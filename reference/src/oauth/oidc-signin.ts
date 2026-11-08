// SPDX-License-Identifier: FSL-1.1-ALv2
// OIDC sign-in plumbing shared by the connector sign-in page (interaction.ts) and the person's web view (web/app.ts):
//
// - Login transactions: one per hand-off to the identity provider, keyed by the `state` sent with it, used once,
//   valid for 10 minutes, and bound to the browser that started it by a random cookie (SameSite=Lax, so the browser
//   sends it back with the provider's redirect; the transaction keeps only the cookie's hash). A callback whose
//   state is unknown, used or from another browser is refused before any code is exchanged.
// - The connector hand-off: after the callback verifies the ID token, the browser returns to the interaction's own
//   path (/interaction/<uid>/oidc), where oidc-provider's interaction cookie proves it is the browser that started
//   the authorization; the verified identity waits there for at most 5 minutes.
// - The provider's refresh token for each connector grant, sealed with AES-256-GCM under a key derived from the
//   authorization server's own secret, so the state file or database never holds it in the clear.
// - The re-check at refresh (spec 5.3 offboarding): whenever an agent's connection refreshes, the broker refreshes
//   at the provider too. The provider refuses for a disabled or deleted account or revoked sessions, and the broker
//   then revokes the connection. A provider that can't be reached, is throttling or busy, or refuses the broker's own
//   request (an expired client secret) fails that refresh only. Overlapping refreshes on one instance share one check;
//   one that succeeded counts for 30 seconds (its time is stored, so on every instance).
//
// Records go through the authorization server's storage adapter (models AlpOidcLogin and AlpIdpSession), so they
// live wherever its state lives (memory, binding.json, or Postgres for a hosted broker), and so do the limits on
// starting sign-ins (`windows`). Those limits come in two pools that never share a count: connector sign-ins, which
// anyone can start from the public sign-in page (per source, an IPv6 /64 counting as one, with no overall total a
// stranger could use up), and the web view's sign-ins and step-ups, which only a person at the broker's machine or
// with a session can start (per person or source, with a total of their own).

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AdapterPayload } from "oidc-provider";
import type { Broker } from "../core/broker.ts";
import { errMessage } from "../core/errors.ts";
import type { PrincipalRecord } from "../core/types.ts";
import { MemoryWindows, windowCount, windowHit } from "../core/windows.ts";
import type { Windows } from "../core/windows.ts";
import { StateAdapter } from "./adapter.ts";
import { OidcSignInError, isOidcSignInError, randomToken, refusesPerson } from "./oidc.ts";
import type { OidcIdentity, OidcRelyingParty } from "./oidc.ts";
import type { BindingStore } from "./state.ts";
import { sourcePrefix } from "./sources.ts";

/** Seconds a login transaction waits for the provider's redirect. */
export const LOGIN_TX_SECONDS = 600;
/** Seconds a verified identity waits for the connector's completion step. */
const HANDOFF_SECONDS = 300;
/** A re-check that succeeded this recently (ms) answers an overlapping refresh. */
const RECHECK_REUSE_MS = 30_000;

export function sha256b64(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

/**
 * AES-256-GCM with keys derived (HKDF-SHA-256) from the authorization server's cookie keys, per purpose. It seals with
 * the first and opens with any of them, so the usual rotation (a new key first, the old ones kept after it) leaves what
 * was sealed before readable until it is sealed again.
 */
export class SecretBox {
  private readonly keys: Buffer[];

  constructor(secrets: string | readonly string[], purpose: string) {
    const list = typeof secrets === "string" ? [secrets] : [...secrets];
    if (list.length === 0 || list.some((x) => x.length < 32)) throw new Error("each sealing secret must be at least 32 characters");
    this.keys = list.map((x) => Buffer.from(hkdfSync("sha256", Buffer.from(x, "utf8"), Buffer.alloc(0), `alp-reference-broker ${purpose}`, 32)));
  }

  seal(plain: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.keys[0] as Buffer, iv);
    const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
    return `v1.${iv.toString("base64url")}.${ct.toString("base64url")}.${c.getAuthTag().toString("base64url")}`;
  }

  /** The plaintext, or null when the value is malformed or was sealed under none of the keys. */
  open(sealed: string | undefined): string | null {
    const [v, iv, ct, tag] = (sealed ?? "").split(".");
    if (v !== "v1" || !iv || ct === undefined || !tag) return null;
    for (const key of this.keys) {
      try {
        const d = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
        d.setAuthTag(Buffer.from(tag, "base64url"));
        return Buffer.concat([d.update(Buffer.from(ct, "base64url")), d.final()]).toString("utf8");
      } catch {
        // sealed under another key: try the next
      }
    }
    return null;
  }
}

// ---------------------------------------------------------------------------------------------
// The browser-binding cookie

const COOKIE_VALUE = /^[A-Za-z0-9_-]{43}$/;

export function readCookie(req: IncomingMessage, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}

/**
 * The browser's binding value for OIDC sign-ins: the one it already has (several sign-ins in one browser share it),
 * or a new one. SameSite=Lax, because it must come back with the provider's cross-site redirect; HttpOnly; Secure
 * on https.
 */
export function bindBrowser(req: IncomingMessage, res: ServerResponse, cookie: { name: string; path: string; secure: boolean }): string {
  const existing = readCookie(req, cookie.name);
  const value = existing && COOKIE_VALUE.test(existing) ? existing : randomToken();
  res.appendHeader("Set-Cookie", `${cookie.name}=${value}; Path=${cookie.path}; HttpOnly; SameSite=Lax; Max-Age=${LOGIN_TX_SECONDS}${cookie.secure ? "; Secure" : ""}`);
  return value;
}

// ---------------------------------------------------------------------------------------------
// Records

export type LoginPurpose = "connector" | "web" | "stepup";

/** A step-up's action: the form the person submitted, held until the provider confirms it's them. */
export interface StepUpAction {
  path: string;
  fields: [string, string][];
  /** sha256 of the path, the fields and the hash of what the action covers (a ratification's terms hash among them): the step-up's nonce commits to it. */
  key: string;
}

export interface LoginTx {
  purpose: LoginPurpose;
  /** sha256 of the browser-binding cookie. */
  browser: string;
  nonce: string;
  /** The PKCE code verifier, sealed. */
  verifier: string;
  redirect_uri: string;
  /** Epoch seconds. */
  created_at: number;
  /** A fresh sign-in was asked for (prompt=login): auth_time, when present, must not be earlier. */
  fresh: boolean;
  /** connector: the authorization's interaction, and its client (for security events). */
  uid?: string;
  client_id?: string;
  /** connector: the agent's name on the broker, as the person confirmed it (unverified clients). */
  label?: string;
  /** web and stepup: sha256 of the web view session id. */
  session?: string;
  /** stepup: the action waiting for it. */
  action?: StepUpAction;
}

export interface ConnectorHandoff {
  purpose: "connector-done";
  uid: string;
  browser: string;
  identity: OidcIdentity;
  nonce: string;
  /** The provider's refresh token, sealed. */
  refresh?: string;
  label?: string;
}

/** The provider session behind one connector grant (keyed by the grant id). */
interface IdpSession {
  grantId: string;
  principal_id: string;
  iss: string;
  sub: string;
  nonce?: string;
  /** The provider's refresh token, sealed. */
  refresh: string;
  /** Epoch seconds of the last successful check. */
  checked_at: number;
  /** Epoch seconds. */
  expires_at: number;
}

/**
 * "refused": the provider refused the person, or there is no provider session to check. "unreadable": the stored provider
 * session can't be opened under any of the broker's cookie keys (they were replaced without keeping the old one).
 */
export type RecheckVerdict = "ok" | "refused" | "unreadable";

/** Which budget a sign-in start counts against: the public connector page, or the web view (loopback, or a session). */
export type StartPool = "connector" | "web";

export interface OidcSignInOptions {
  rp: OidcRelyingParty;
  state: BindingStore;
  /**
   * The authorization server's cookie keys, newest first: sealing uses the first, opening tries each, so a rotation
   * that keeps the old keys after the new one doesn't make sealed values unreadable. A single secret works too.
   */
  secret: string | readonly string[];
  log: (line: string) => void;
  /**
   * Sign-ins started in 10 minutes: per source (an IPv6 /64 is one source) on the connector page, and per key and in
   * all on the web view (defaults 30, 30 and 3000). The connector page has no total, so strangers can't block anyone.
   */
  startLimits?: { perSource: number; total: number };
  /** Where those counts live (default: this process's memory; a hosted broker's Postgres store). */
  windows?: Windows;
}

export class OidcSignIn {
  readonly rp: OidcRelyingParty;
  private readonly txs: StateAdapter;
  private readonly sessions: StateAdapter;
  private readonly box: SecretBox;
  private readonly log: (line: string) => void;
  private readonly checks = new Map<string, Promise<RecheckVerdict>>();
  private readonly windows: Windows;
  private readonly limits: { perSource: number; total: number };

  constructor(opts: OidcSignInOptions) {
    this.rp = opts.rp;
    this.txs = new StateAdapter(opts.state, "AlpOidcLogin");
    this.sessions = new StateAdapter(opts.state, "AlpIdpSession");
    this.box = new SecretBox(opts.secret, "oidc sign-in secrets");
    this.log = opts.log;
    this.limits = opts.startLimits ?? { perSource: 30, total: 3000 };
    this.windows = opts.windows ?? new MemoryWindows();
  }

  /**
   * Limits on starting sign-ins (each one stores a transaction for 10 minutes). `connector`: per source, an IPv6 address
   * counting by its /64, and no overall total, so starts from many addresses can't use up anyone else's budget (a
   * hosted broker's platform rate limits are the second layer). `web`: per key (a person, or the loopback source) and a
   * total of its own, which the public connector page never touches: approvals can't be blocked from outside.
   */
  async allowStart(key: string, pool: StartPool): Promise<boolean> {
    const now = new Date();
    if (pool === "connector") {
      const mine = `oidc-start|${sha256b64(sourcePrefix(key))}`;
      return (await this.windows.hitRateLimit(mine, now, LOGIN_TX_SECONDS, this.limits.perSource)).allowed;
    }
    const mine = `oidc-web-start|${sha256b64(key)}`;
    if ((await windowCount(this.windows, mine, now, LOGIN_TX_SECONDS)) >= this.limits.perSource || (await windowCount(this.windows, "oidc-web-start-all", now, LOGIN_TX_SECONDS)) >= this.limits.total) return false;
    await windowHit(this.windows, mine, now, LOGIN_TX_SECONDS);
    await windowHit(this.windows, "oidc-web-start-all", now, LOGIN_TX_SECONDS);
    return true;
  }

  /**
   * Stores a login transaction and returns the provider's authorization URL. `commitTo` makes the nonce a commitment
   * to an action (a step-up), so the provider's sign-in answers for that action alone.
   */
  async begin(tx: Omit<LoginTx, "nonce" | "verifier" | "created_at">, args: { prompt?: "login"; maxAge?: number; loginHint?: string; commitTo?: string } = {}): Promise<string> {
    const state = randomToken();
    const verifier = randomToken(48);
    const nonce = args.commitTo ? sha256b64(`${randomToken(16)}|${args.commitTo}`) : randomToken();
    const rec: LoginTx = { ...tx, nonce, verifier: this.box.seal(verifier), created_at: Math.floor(Date.now() / 1000) };
    await this.txs.upsert(state, rec as unknown as AdapterPayload, LOGIN_TX_SECONDS);
    return this.rp.authorizationUrl({
      redirectUri: tx.redirect_uri,
      state,
      nonce,
      codeVerifier: verifier,
      ...(args.prompt ? { prompt: args.prompt } : {}),
      ...(args.maxAge !== undefined ? { maxAge: args.maxAge } : {}),
      ...(args.loginHint ? { loginHint: args.loginHint } : {}),
    });
  }

  /** The transaction a provider's redirect names, removed so it can't be used twice; refused unless this browser started it. */
  async take(state: unknown, browserValue: string | undefined, purposes: readonly LoginPurpose[]): Promise<LoginTx> {
    if (typeof state !== "string" || !/^[A-Za-z0-9_-]{20,128}$/.test(state)) throw new OidcSignInError("stale", "no usable state parameter");
    const found = (await this.txs.take(state)) as unknown as LoginTx | undefined;
    if (!found || !purposes.includes(found.purpose)) throw new OidcSignInError("stale", "unknown or used state");
    if (Date.now() / 1000 - found.created_at > LOGIN_TX_SECONDS) throw new OidcSignInError("stale", "the sign-in transaction expired");
    if (!browserValue || !COOKIE_VALUE.test(browserValue) || sha256b64(browserValue) !== found.browser) throw new OidcSignInError("stale", "the callback came to another browser than the one that started the sign-in");
    return found;
  }

  /** RFC 9207 issuer check, then the code exchange and the ID token's checks for this transaction. */
  async finish(tx: LoginTx, query: { code?: unknown; iss?: unknown }, opts: { requireAuthTime?: boolean } = {}): Promise<{ identity: OidcIdentity; refreshToken?: string }> {
    await this.rp.checkResponseIssuer(typeof query.iss === "string" ? query.iss : undefined);
    if (typeof query.code !== "string" || query.code.length === 0 || query.code.length > 4096) throw new OidcSignInError("bad_response", "the provider's redirect has no code");
    const verifier = this.box.open(tx.verifier);
    if (!verifier) throw new OidcSignInError("stale", "the transaction's verifier can't be opened (the broker's keys changed)");
    return this.rp.signIn({ code: query.code, redirectUri: tx.redirect_uri, codeVerifier: verifier, nonce: tx.nonce, ...(tx.fresh ? { freshSince: tx.created_at } : {}), ...(opts.requireAuthTime ? { requireAuthTime: true } : {}) });
  }

  // ---- the connector hand-off

  /** Keeps a verified identity for the connector's completion step; returns the hand-off id. */
  async handOff(h: Omit<ConnectorHandoff, "purpose" | "refresh">, refreshToken: string | undefined): Promise<string> {
    const id = randomToken();
    const rec: ConnectorHandoff = { ...h, purpose: "connector-done", ...(refreshToken ? { refresh: this.box.seal(refreshToken) } : {}) };
    await this.txs.upsert(`handoff:${id}`, rec as unknown as AdapterPayload, HANDOFF_SECONDS);
    return id;
  }

  /** The hand-off for this interaction and browser, removed so it can't be used twice. */
  async takeHandoff(id: unknown, uid: string, browserValue: string | undefined): Promise<ConnectorHandoff> {
    if (typeof id !== "string" || !COOKIE_VALUE.test(id)) throw new OidcSignInError("stale", "no hand-off id");
    const found = (await this.txs.take(`handoff:${id}`)) as unknown as ConnectorHandoff | undefined;
    if (!found || found.purpose !== "connector-done" || found.uid !== uid) throw new OidcSignInError("stale", "unknown, used or mismatched hand-off");
    if (!browserValue || !COOKIE_VALUE.test(browserValue) || sha256b64(browserValue) !== found.browser) throw new OidcSignInError("stale", "the hand-off came to another browser");
    return found;
  }

  // ---- provider sessions and the re-check at refresh

  /** Records the provider session behind a new connector grant, for the re-check at every refresh. */
  async rememberSession(grantId: string, principal: PrincipalRecord, h: ConnectorHandoff, ttlSeconds: number): Promise<void> {
    if (!h.refresh) return;
    const now = Math.floor(Date.now() / 1000);
    const rec: IdpSession = { grantId, principal_id: principal.principal_id, iss: principal.identity.iss, sub: principal.identity.sub, nonce: h.nonce, refresh: h.refresh, checked_at: now, expires_at: now + ttlSeconds };
    await this.sessions.upsert(grantId, rec as unknown as AdapterPayload, ttlSeconds);
  }

  async forgetSession(grantId: string): Promise<void> {
    await this.sessions.destroy(grantId);
  }

  /**
   * The re-check when an agent's connection refreshes: refresh at the provider with the stored refresh token. "ok"
   * keeps the connection (and updates the person's group claims from a new ID token); "refused" means the provider
   * no longer accepts the person, or there is no provider session to check. Throws OidcSignInError when the provider
   * can't be reached or is busy ("idp_unavailable"), or refuses the broker's own request rather than the person
   * ("idp_refused" with an error such as invalid_client), so the refresh fails without ending the connection.
   */
  recheck(grantId: string, principal: PrincipalRecord, broker: Broker): Promise<RecheckVerdict> {
    const running = this.checks.get(grantId);
    if (running) return running;
    const p = this.runRecheck(grantId, principal, broker).finally(() => this.checks.delete(grantId));
    this.checks.set(grantId, p);
    return p;
  }

  private async runRecheck(grantId: string, principal: PrincipalRecord, broker: Broker): Promise<RecheckVerdict> {
    const s = (await this.sessions.find(grantId)) as unknown as IdpSession | undefined;
    if (!s || s.principal_id !== principal.principal_id || s.iss !== principal.identity.iss || s.sub !== principal.identity.sub) {
      this.log("oidc: refused a refresh: no identity-provider session to re-check for this connection");
      return "refused";
    }
    const now = Date.now();
    if (now - s.checked_at * 1000 < RECHECK_REUSE_MS) return "ok";
    const rt = this.box.open(s.refresh);
    if (!rt) {
      this.log("oidc: refused a refresh: the stored identity-provider session can't be opened under any of the broker's cookie keys (ALP_OAUTH_KEYS changed without keeping the old cookie key); the person connects the agent again");
      await this.sessions.destroy(grantId);
      return "unreadable";
    }
    let out: Awaited<ReturnType<OidcRelyingParty["refresh"]>>;
    try {
      out = await this.rp.refresh(rt, { iss: s.iss, sub: s.sub, ...(s.nonce !== undefined ? { nonce: s.nonce } : {}) });
    } catch (err) {
      if (isOidcSignInError(err) && err.reason === "idp_unavailable") {
        this.log(`oidc: couldn't re-check a person at the identity provider (${err.detail}); the refresh fails, the connection stays`);
        throw err;
      }
      // The provider refused the broker's own request (an expired client secret, say), not the person: ending every
      // connection for it would make each person connect their agents again once it is fixed.
      if (isOidcSignInError(err) && err.reason === "idp_refused" && !refusesPerson(err)) {
        this.log(`oidc: the identity provider refused the broker's own request at a re-check (${err.detail}): check ALP_OIDC_CLIENT_SECRET and the broker's registration at the provider; the refresh fails, the connection stays`);
        throw err;
      }
      this.log(`oidc: the identity provider refused the person at refresh (${isOidcSignInError(err) ? `${err.reason}: ${err.detail}` : errMessage(err)})`);
      await this.sessions.destroy(grantId);
      return "refused";
    }
    if (out.groups && JSON.stringify(out.groups) !== JSON.stringify(principal.claims ?? [])) {
      // Roles or groups changed at the provider: the policy sees the new ones from this refresh on.
      await broker.registerPrincipal({ address: principal.address, identity: principal.identity, claims: out.groups });
      this.log("oidc: updated a person's group claims at refresh");
    }
    const nowSec = Math.floor(now / 1000);
    // Sealed again under the first cookie key, whether or not the provider rotated it: after a key rotation, each
    // connection moves to the new key at its next successful re-check.
    const next: IdpSession = { ...s, refresh: this.box.seal(out.refreshToken ?? rt), checked_at: nowSec };
    await this.sessions.upsert(grantId, next as unknown as AdapterPayload, Math.max(1, s.expires_at - nowSec));
    return "ok";
  }
}
