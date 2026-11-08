// SPDX-License-Identifier: FSL-1.1-ALv2
// The client binding's own state, apart from the broker core's Store: the authorization server's artifacts
// (oidc-provider models: grants, sessions, interactions, codes, access and refresh tokens, dynamic registrations,
// replay detection), personal access tokens, connection requests an agent filed that wait for its person (spec 6.2.1,
// `pending_principal`), send idempotency records (spec 10.3), and the person's web view (sessions, step-up challenges,
// invites, passkeys and known devices).
//
// BindingStore is the seam, async like the core's Store, so a hosted broker keeps all of it in Postgres
// (src/storage/postgres-binding.ts) and any instance can answer any request. BindingState is the memory and file
// implementation for a local or demo broker: memory only, or one JSON file (<dataDir>/binding.json, mode 0600) rewritten
// atomically after every change, as the core's FileStore does. The file is read once, when the broker starts, so only
// that process may change it (another process's writes would be lost: `npm run invite` needs Postgres for this reason).
// Web sessions and step-up challenges stay in memory there (a restart signs people out). One conformance suite runs
// on every implementation (binding-store.test.ts).
//
// Tokens are kept only as hashes. oidc-provider artifacts are keyed by the SHA-256 of their id, and an opaque token's
// id is the token itself (an authorization code, a refresh token, a registration access token), as a session's id is
// its cookie. oidc-provider also copies each artifact's id into its payload (`jti`), so for those models the adapter
// (adapter.ts) stores the payload without it and puts it back from the id on lookup (ID_IS_SECRET below). Personal
// access tokens and web sessions are kept as hashes, invite secrets as scrypt hashes, and OIDC sign-in's provider
// refresh tokens sealed (oidc-signin.ts). One credential is kept as issued: a dynamically registered confidential
// client's client_secret, which oidc-provider compares as it is; it authenticates that client, not a person.

import { createHash, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { SealMethod } from "../core/types.ts";

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type JsonRecord = { [key: string]: JsonValue };

export interface OidcEntry {
  payload: JsonRecord;
  /** Epoch milliseconds; absent means no expiry. */
  expiresAt?: number;
}

/** A personal access token (spec 5.7). Only the hash of the token is kept. */
export interface PatRecord {
  id: string;
  hash: string;
  principal_id: string;
  /** The delegate id the token acts as: alp:<address>/<label>. */
  delegate: string;
  /**
   * When that delegate's binding started (spec 5.4): the token acts only for that binding, never for a later agent
   * given the same name. Absent on tokens minted before it was recorded.
   */
  binding?: string;
  label: string;
  scopes: ("read" | "send")[];
  created_at: string;
  expires_at: string;
  revoked_at?: string;
  last_used_at?: string;
}

/** A connection request an agent filed: held for its person, nothing sent yet (spec 6.2.1). */
export interface PendingConnection {
  id: string;
  principal_id: string;
  principal: string;
  delegate: string;
  client_id: string;
  to: string;
  scopes: string[];
  purpose: string;
  note?: string;
  state: "pending_principal" | "sent" | "discarded" | "failed" | "expired";
  /** After approval: the core's connection request id, or why it didn't go. */
  result?: { status: string; request?: string; code?: string };
  created_at: string;
  updated_at: string;
  expires_at: string;
}

export interface IdempotencyRecord {
  at: number;
  result: JsonRecord;
}

/**
 * A web view session. The cookie holds a random id; the store keeps only its SHA-256 (`id_hash`).
 * `stage`: `full` once the person is signed in; on a public origin, `passkey_setup` (the invite secret checked, a
 * passkey must be registered before anything else) or `passkey_check` (the secret checked, the passkey assertion due).
 */
export interface WebSessionRecord {
  id_hash: string;
  principal: string;
  principal_id: string;
  username: string;
  csrf: string;
  stage: "full" | "passkey_setup" | "passkey_check";
  /** When the person last proved who they are (sign-in or a step-up), epoch ms. */
  auth_at: number;
  method: SealMethod;
  created_at: number;
  last_seen: number;
  /** SHA-256 of the browser's device cookie; set when the session started. */
  device_hash?: string;
  /** This sign-in came from a browser the person hadn't used here before. */
  new_device?: boolean;
  /** OIDC sign-ins: the identity the session belongs to (iss + sub; Entra: the tenant's issuer + oid). */
  identity?: { iss: string; sub: string };
}

/**
 * A WebAuthn challenge the web view issued, single use. `binding` is the SHA-256 of what the person is shown and
 * approves (the action, its target and the terms); the challenge sent to the authenticator is 16 random bytes followed
 * by those 32, so the passkey's signature covers the terms (spec 12.5.2).
 *
 * `sso-stepup` is the other kind: a single sign-on step-up the organization's identity provider confirmed for one
 * action of one session (web/app.ts, OIDC mode), waiting until the person confirms that action; `binding` is the
 * action's key, which the provider's nonce committed to, and `auth_at` the provider's fresh sign-in.
 */
export interface StepUpChallenge {
  /** The challenge, base64url (as it comes back in clientDataJSON); for an SSO step-up, `sso.` and an id. */
  challenge: string;
  session_hash: string;
  purpose: "register" | "signin" | "stepup" | "connect" | "sso-stepup";
  action?: string;
  target?: string;
  binding?: string;
  /** sso-stepup: when the identity provider signed the person in again (epoch ms). */
  auth_at?: number;
  expires_at: number;
}

/** An invitation to a hosted broker: one person, a sign-in secret for them alone (kept as a scrypt hash), an expiry. */
export interface InviteRecord {
  id: string;
  /** Lower-case sign-in name. */
  username: string;
  /** The address the person gets (alp:...). */
  address: string;
  display_name?: string;
  /** Where the broker sends the person's notices (connection requests, sign-in from a new device). */
  email?: string;
  /** scrypt$<N>$<r>$<p>$<salt>$<hash>, base64url. */
  secret_hash: string;
  created_at: string;
  expires_at: string;
  revoked_at?: string;
  last_used_at?: string;
}

/** A passkey (WebAuthn credential) a person registered on the web view. */
export interface PasskeyRecord {
  /** base64url credential id. */
  credential_id: string;
  principal_id: string;
  /** base64url COSE public key. */
  public_key: string;
  counter: number;
  transports?: string[];
  device_type?: string;
  backed_up?: boolean;
  created_at: string;
  last_used_at?: string;
}

/** A browser the person has signed in from (the SHA-256 of its device cookie). */
export interface DeviceRecord {
  principal_id: string;
  device_hash: string;
  first_seen: string;
  last_seen: string;
}

export interface BindingStore {
  readonly kind: string;

  // oidc-provider's models. `key` is the SHA-256 (base64url) of the artifact's id, and the adapter stores payloads
  // without a raw id that is a credential (ID_IS_SECRET), so the store holds no usable token. Expired entries are never
  // returned.
  oidcGet(model: string, key: string, nowMs: number): Promise<JsonRecord | null>;
  oidcPut(model: string, key: string, payload: JsonRecord, expiresAtMs?: number): Promise<void>;
  /** Single use: returns the artifact (if unexpired) and deletes it. Atomic, so two instances can't both take it. */
  oidcTake(model: string, key: string, nowMs: number): Promise<JsonRecord | null>;
  oidcFindBy(model: string, field: "uid" | "userCode", value: string, nowMs: number): Promise<JsonRecord | null>;
  /** Mark consumed at `atSeconds` unless it already is: the first consumption time is kept. */
  oidcConsume(model: string, key: string, atSeconds: number): Promise<void>;
  /**
   * The overlapping-refresh allowance (spec 5.6.7): when the artifact was consumed at most `intervalSeconds` ago and
   * its one reuse is unspent, spend it (`alp_reused_at`) and return true. Atomic, so two instances can't both spend it.
   */
  oidcTakeReuse(model: string, key: string, nowSeconds: number, intervalSeconds: number): Promise<boolean>;
  /** Move an artifact's expiry (dynamic registrations that are used are kept; unused ones expire). */
  oidcSetExpiry(model: string, key: string, expiresAtMs: number): Promise<void>;
  oidcDelete(model: string, key: string): Promise<void>;
  oidcDeleteByGrant(model: string, grantId: string): Promise<void>;
  /** The grant ids (`jti`) one account holds for one client. */
  oidcGrantIds(accountId: string, clientId: string, nowMs: number): Promise<string[]>;
  oidcCount(model: string, nowMs: number): Promise<number>;

  putPat(rec: PatRecord): Promise<void>;
  getPat(id: string): Promise<PatRecord | null>;
  findPatByHash(hash: string): Promise<PatRecord | null>;
  /**
   * Note a use: sets `last_used_at` alone, and only while the token isn't revoked. False when it is (or is unknown).
   * A request that read the token before a revocation can't write it back live.
   */
  touchPat(id: string, at: string): Promise<boolean>;
  /** Sets `revoked_at` (the first revocation's time stays) without rewriting anything else; the record, or null. */
  revokePat(id: string, at: string): Promise<PatRecord | null>;
  /** Newest first. */
  listPats(principalId: string): Promise<PatRecord[]>;
  listPatsOfDelegate(delegate: string): Promise<PatRecord[]>;

  putPending(rec: PendingConnection): Promise<void>;
  getPending(id: string): Promise<PendingConnection | null>;
  /** Newest first. */
  listPending(principalId: string): Promise<PendingConnection[]>;

  getIdempotency(key: string): Promise<IdempotencyRecord | null>;
  putIdempotency(key: string, rec: IdempotencyRecord): Promise<void>;
  /**
   * Replaces the key's record with `rec`, or removes it for null, only while it is still the record the caller read:
   * `seen` is that record's `at`, or null when there was none. True when it did. Atomic, so of calls that read the same
   * record at once, one replaces it: alp_send claims a key this way before it sends (spec 10.3).
   */
  swapIdempotency(key: string, seen: number | null, rec: IdempotencyRecord | null): Promise<boolean>;

  getWebSession(idHash: string): Promise<WebSessionRecord | null>;
  putWebSession(rec: WebSessionRecord): Promise<void>;
  deleteWebSession(idHash: string): Promise<void>;
  /** Sign a person out everywhere. */
  deleteWebSessionsOf(principalId: string): Promise<void>;
  putChallenge(rec: StepUpChallenge): Promise<void>;
  /** Single use: returns the challenge (if unexpired and issued to this session) and deletes it. Atomic. */
  takeChallenge(sessionHash: string, challenge: string, nowMs: number): Promise<StepUpChallenge | null>;

  putInvite(rec: InviteRecord): Promise<void>;
  getInvite(id: string): Promise<InviteRecord | null>;
  listInvites(username?: string): Promise<InviteRecord[]>;
  /** Note a sign-in: sets `last_used_at` alone, and only while the invite isn't revoked. False when it is (or is unknown). */
  touchInvite(id: string, at: string): Promise<boolean>;
  /** Sets `revoked_at` (the first revocation's time stays) without rewriting anything else; the record, or null. */
  revokeInvite(id: string, at: string): Promise<InviteRecord | null>;

  putPasskey(rec: PasskeyRecord): Promise<void>;
  /**
   * A person's first passkey: stored only when they have none yet and the credential id is new. Atomic, so of two
   * registrations at once (a leaked invite secret used alongside the person's own), only one is stored.
   */
  addFirstPasskey(rec: PasskeyRecord): Promise<boolean>;
  getPasskey(credentialId: string): Promise<PasskeyRecord | null>;
  listPasskeys(principalId: string): Promise<PasskeyRecord[]>;
  /** Store a newer signature counter. False when `counter` doesn't exceed the stored one (a cloned authenticator) unless both are 0. */
  usePasskey(credentialId: string, counter: number, at: string): Promise<boolean>;

  /** Record a browser for a person; true when it is new for them. */
  noteDevice(principalId: string, deviceHash: string, at: string): Promise<boolean>;
  listDevices(principalId: string): Promise<DeviceRecord[]>;

  close(): Promise<void>;
}

export interface BindingStateData {
  version: 1;
  oidc: Record<string, Record<string, OidcEntry>>;
  pats: Record<string, PatRecord>;
  pending: Record<string, PendingConnection>;
  idempotency: Record<string, IdempotencyRecord>;
  invites?: Record<string, InviteRecord>;
  passkeys?: Record<string, PasskeyRecord>;
  devices?: Record<string, DeviceRecord>;
}

export function sha256b64u(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

/**
 * oidc-provider models whose id is a credential: an opaque token's id is the token (codes, refresh tokens, registration
 * and initial access tokens...), a session's id is its cookie, an interaction's id is its cookie and URL. Their stored
 * payloads carry no `jti`; the adapter restores it from the id on lookup. Not here: Grant (a grant's id is named in its
 * tokens and listed per account and client to revoke them, but grants no access on its own), Client (its id is the
 * client_id), ReplayDetection (its id is a hash) and the broker's own models (oidc-signin.ts), which carry no `jti`.
 */
export const ID_IS_SECRET: ReadonlySet<string> = new Set([
  "AccessToken",
  "AuthorizationCode",
  "RefreshToken",
  "ClientCredentials",
  "DeviceCode",
  "BackchannelAuthenticationRequest",
  "InitialAccessToken",
  "RegistrationAccessToken",
  "PushedAuthorizationRequest",
  "Session",
  "Interaction",
]);

/**
 * A payload as it may be stored: for a model in ID_IS_SECRET, without its raw id (`jti`, when it is the artifact's id:
 * `isId` decides), and an interaction without its copy of the session's cookie (`session.cookie`, which oidc-provider
 * never reads back). Returns the same object when nothing changes.
 */
export function withoutRawIds(model: string, payload: JsonRecord, isId: (jti: string) => boolean): JsonRecord {
  if (!ID_IS_SECRET.has(model)) return payload;
  const jti = payload["jti"];
  const dropId = typeof jti === "string" && isId(jti);
  const session = payload["session"];
  const withCookie = model === "Interaction" && session !== null && typeof session === "object" && !Array.isArray(session) && "cookie" in session ? session : undefined;
  if (!dropId && !withCookie) return payload;
  const out: JsonRecord = { ...payload };
  if (dropId) delete out["jti"];
  if (withCookie) {
    const s: JsonRecord = { ...withCookie };
    delete s["cookie"];
    out["session"] = s;
  }
  return out;
}

function empty(): BindingStateData {
  return { version: 1, oidc: {}, pats: {}, pending: {}, idempotency: {}, invites: {}, passkeys: {}, devices: {} };
}

const clone = <T>(v: T): T => structuredClone(v);

/** Marks a rotated refresh token whose one overlapping reuse has been spent. */
export const REUSED_FIELD = "alp_reused_at";

/** The memory and file BindingStore. Node runs it single-threaded and no method awaits midway, so each is atomic. */
export class BindingState implements BindingStore {
  readonly kind: string;
  readonly data: BindingStateData;
  private readonly path: string | undefined;
  private readonly sessions = new Map<string, WebSessionRecord>();
  private readonly challenges = new Map<string, StepUpChallenge>();

  private constructor(data: BindingStateData, path: string | undefined) {
    this.data = data;
    this.path = path;
    this.kind = path ? "file" : "memory";
  }

  static memory(): BindingState {
    return new BindingState(empty(), undefined);
  }

  /**
   * Loads (or creates) <dir>/binding.json. A file written before raw token ids were dropped (ID_IS_SECRET) is cleaned
   * as it loads: a stored `jti` whose SHA-256 is its key goes, and so does an interaction's copy of its session cookie.
   */
  static file(dir: string): BindingState {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = join(dir, "binding.json");
    let data = empty();
    let cleaned = false;
    if (existsSync(path)) {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as BindingStateData;
      if (parsed?.version !== 1) throw new Error(`unsupported binding state version in ${path}`);
      data = { ...empty(), ...parsed };
      for (const [model, entries] of Object.entries(data.oidc)) {
        for (const [key, e] of Object.entries(entries)) {
          const payload = withoutRawIds(model, e.payload, (jti) => sha256b64u(jti) === key);
          if (payload !== e.payload) {
            e.payload = payload;
            cleaned = true;
          }
        }
      }
    }
    const state = new BindingState(data, path);
    if (cleaned) state.save();
    return state;
  }

  /** Call after every change. Expired authorization-server artifacts and old idempotency records are dropped first. */
  save(now: number = Date.now()): void {
    for (const model of Object.values(this.data.oidc)) {
      for (const [k, e] of Object.entries(model)) if (e.expiresAt !== undefined && e.expiresAt <= now) delete model[k];
    }
    for (const [k, r] of Object.entries(this.data.idempotency)) if (now - r.at > 24 * 3600 * 1000) delete this.data.idempotency[k];
    if (!this.path) return;
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, this.path);
  }

  /** The raw entries of one oidc-provider model (tests age them). */
  model(name: string): Record<string, OidcEntry> {
    let m = this.data.oidc[name];
    if (!m) {
      m = {};
      this.data.oidc[name] = m;
    }
    return m;
  }

  private live(model: string, key: string, nowMs: number): OidcEntry | undefined {
    const m = this.model(model);
    const e = m[key];
    if (!e) return undefined;
    if (e.expiresAt !== undefined && e.expiresAt <= nowMs) {
      delete m[key];
      return undefined;
    }
    return e;
  }

  async oidcGet(model: string, key: string, nowMs: number): Promise<JsonRecord | null> {
    const e = this.live(model, key, nowMs);
    return e ? clone(e.payload) : null;
  }
  async oidcPut(model: string, key: string, payload: JsonRecord, expiresAtMs?: number): Promise<void> {
    this.model(model)[key] = { payload: clone(payload), ...(expiresAtMs !== undefined ? { expiresAt: expiresAtMs } : {}) };
    this.save();
  }
  async oidcTake(model: string, key: string, nowMs: number): Promise<JsonRecord | null> {
    const m = this.model(model);
    const e = m[key];
    if (!e) return null;
    delete m[key];
    this.save();
    return e.expiresAt !== undefined && e.expiresAt <= nowMs ? null : clone(e.payload);
  }
  async oidcFindBy(model: string, field: "uid" | "userCode", value: string, nowMs: number): Promise<JsonRecord | null> {
    for (const key of Object.keys(this.model(model))) {
      const e = this.live(model, key, nowMs);
      if (e && e.payload[field] === value) return clone(e.payload);
    }
    return null;
  }
  async oidcConsume(model: string, key: string, atSeconds: number): Promise<void> {
    const e = this.model(model)[key];
    if (e && e.payload["consumed"] === undefined) {
      e.payload["consumed"] = atSeconds;
      this.save();
    }
  }
  async oidcTakeReuse(model: string, key: string, nowSeconds: number, intervalSeconds: number): Promise<boolean> {
    const e = this.live(model, key, nowSeconds * 1000);
    const consumed = e?.payload["consumed"];
    if (!e || typeof consumed !== "number" || e.payload[REUSED_FIELD] !== undefined || nowSeconds - consumed > intervalSeconds) return false;
    e.payload[REUSED_FIELD] = nowSeconds;
    this.save();
    return true;
  }
  async oidcSetExpiry(model: string, key: string, expiresAtMs: number): Promise<void> {
    const e = this.model(model)[key];
    if (e) {
      e.expiresAt = expiresAtMs;
      this.save();
    }
  }
  async oidcDelete(model: string, key: string): Promise<void> {
    delete this.model(model)[key];
    this.save();
  }
  async oidcDeleteByGrant(model: string, grantId: string): Promise<void> {
    const m = this.model(model);
    for (const [k, e] of Object.entries(m)) if (e.payload["grantId"] === grantId) delete m[k];
    this.save();
  }
  async oidcGrantIds(accountId: string, clientId: string, nowMs: number): Promise<string[]> {
    const out: string[] = [];
    for (const key of Object.keys(this.model("Grant"))) {
      const p = this.live("Grant", key, nowMs)?.payload;
      if (p && p["accountId"] === accountId && p["clientId"] === clientId && typeof p["jti"] === "string") out.push(p["jti"]);
    }
    return out;
  }
  async oidcCount(model: string, nowMs: number): Promise<number> {
    return Object.keys(this.model(model)).filter((k) => this.live(model, k, nowMs)).length;
  }

  async putPat(rec: PatRecord): Promise<void> {
    this.data.pats[rec.id] = clone(rec);
    this.save();
  }
  async getPat(id: string): Promise<PatRecord | null> {
    return clone(this.data.pats[id] ?? null);
  }
  async findPatByHash(hash: string): Promise<PatRecord | null> {
    const want = Buffer.from(hash);
    for (const r of Object.values(this.data.pats)) {
      const h = Buffer.from(r.hash);
      if (h.length === want.length && timingSafeEqual(h, want)) return clone(r);
    }
    return null;
  }
  async listPats(principalId: string): Promise<PatRecord[]> {
    return clone(Object.values(this.data.pats).filter((r) => r.principal_id === principalId).sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id)));
  }
  async listPatsOfDelegate(delegate: string): Promise<PatRecord[]> {
    return clone(Object.values(this.data.pats).filter((r) => r.delegate === delegate).sort((a, b) => a.id.localeCompare(b.id)));
  }
  async touchPat(id: string, at: string): Promise<boolean> {
    const r = this.data.pats[id];
    if (!r || r.revoked_at !== undefined) return false;
    r.last_used_at = at;
    this.save();
    return true;
  }
  async revokePat(id: string, at: string): Promise<PatRecord | null> {
    const r = this.data.pats[id];
    if (!r) return null;
    if (r.revoked_at === undefined) {
      r.revoked_at = at;
      this.save();
    }
    return clone(r);
  }

  async putPending(rec: PendingConnection): Promise<void> {
    this.data.pending[rec.id] = clone(rec);
    this.save();
  }
  async getPending(id: string): Promise<PendingConnection | null> {
    return clone(this.data.pending[id] ?? null);
  }
  async listPending(principalId: string): Promise<PendingConnection[]> {
    return clone(Object.values(this.data.pending).filter((p) => p.principal_id === principalId).sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id)));
  }

  async getIdempotency(key: string): Promise<IdempotencyRecord | null> {
    return clone(this.data.idempotency[key] ?? null);
  }
  async putIdempotency(key: string, rec: IdempotencyRecord): Promise<void> {
    this.data.idempotency[key] = clone(rec);
    this.save();
  }
  async swapIdempotency(key: string, seen: number | null, rec: IdempotencyRecord | null): Promise<boolean> {
    if ((this.data.idempotency[key]?.at ?? null) !== seen) return false;
    if (rec) this.data.idempotency[key] = clone(rec);
    else delete this.data.idempotency[key];
    this.save();
    return true;
  }

  async getWebSession(idHash: string): Promise<WebSessionRecord | null> {
    return clone(this.sessions.get(idHash) ?? null);
  }
  async putWebSession(rec: WebSessionRecord): Promise<void> {
    if (this.sessions.size > 10_000) for (const [k, s] of this.sessions) if (Date.now() - s.last_seen > 24 * 3600_000) this.sessions.delete(k);
    this.sessions.set(rec.id_hash, clone(rec));
  }
  async deleteWebSession(idHash: string): Promise<void> {
    this.sessions.delete(idHash);
    for (const [k, c] of this.challenges) if (c.session_hash === idHash) this.challenges.delete(k);
  }
  async deleteWebSessionsOf(principalId: string): Promise<void> {
    for (const [k, s] of this.sessions) if (s.principal_id === principalId) await this.deleteWebSession(k);
  }
  async putChallenge(rec: StepUpChallenge): Promise<void> {
    const now = Date.now();
    for (const [k, c] of this.challenges) if (c.expires_at <= now) this.challenges.delete(k);
    this.challenges.set(rec.challenge, clone(rec));
  }
  async takeChallenge(sessionHash: string, challenge: string, nowMs: number): Promise<StepUpChallenge | null> {
    const c = this.challenges.get(challenge);
    if (!c || c.session_hash !== sessionHash) return null;
    this.challenges.delete(challenge);
    return c.expires_at > nowMs ? c : null;
  }

  async putInvite(rec: InviteRecord): Promise<void> {
    (this.data.invites ??= {})[rec.id] = clone(rec);
    this.save();
  }
  async getInvite(id: string): Promise<InviteRecord | null> {
    return clone(this.data.invites?.[id] ?? null);
  }
  async listInvites(username?: string): Promise<InviteRecord[]> {
    return clone(Object.values(this.data.invites ?? {}).filter((i) => username === undefined || i.username === username).sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id)));
  }
  async touchInvite(id: string, at: string): Promise<boolean> {
    const i = this.data.invites?.[id];
    if (!i || i.revoked_at !== undefined) return false;
    i.last_used_at = at;
    this.save();
    return true;
  }
  async revokeInvite(id: string, at: string): Promise<InviteRecord | null> {
    const i = this.data.invites?.[id];
    if (!i) return null;
    if (i.revoked_at === undefined) {
      i.revoked_at = at;
      this.save();
    }
    return clone(i);
  }

  async putPasskey(rec: PasskeyRecord): Promise<void> {
    (this.data.passkeys ??= {})[rec.credential_id] = clone(rec);
    this.save();
  }
  async addFirstPasskey(rec: PasskeyRecord): Promise<boolean> {
    const all = (this.data.passkeys ??= {});
    if (all[rec.credential_id] || Object.values(all).some((p) => p.principal_id === rec.principal_id)) return false;
    all[rec.credential_id] = clone(rec);
    this.save();
    return true;
  }
  async getPasskey(credentialId: string): Promise<PasskeyRecord | null> {
    return clone(this.data.passkeys?.[credentialId] ?? null);
  }
  async listPasskeys(principalId: string): Promise<PasskeyRecord[]> {
    return clone(Object.values(this.data.passkeys ?? {}).filter((p) => p.principal_id === principalId).sort((a, b) => a.created_at.localeCompare(b.created_at)));
  }
  async usePasskey(credentialId: string, counter: number, at: string): Promise<boolean> {
    const p = this.data.passkeys?.[credentialId];
    if (!p) return false;
    if (!(counter > p.counter || (counter === 0 && p.counter === 0))) return false;
    p.counter = counter;
    p.last_used_at = at;
    this.save();
    return true;
  }

  async noteDevice(principalId: string, deviceHash: string, at: string): Promise<boolean> {
    const devices = (this.data.devices ??= {});
    const k = `${principalId}|${deviceHash}`;
    const d = devices[k];
    if (d) {
      d.last_seen = at;
      this.save();
      return false;
    }
    devices[k] = { principal_id: principalId, device_hash: deviceHash, first_seen: at, last_seen: at };
    this.save();
    return true;
  }
  async listDevices(principalId: string): Promise<DeviceRecord[]> {
    return clone(Object.values(this.data.devices ?? {}).filter((d) => d.principal_id === principalId).sort((a, b) => a.first_seen.localeCompare(b.first_seen)));
  }

  async close(): Promise<void> {}
}
