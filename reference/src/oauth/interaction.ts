// SPDX-License-Identifier: FSL-1.1-ALv2
// The connector sign-in and consent page (spec 5.6.5): one page, served by the broker at /interaction/:uid while an
// agent platform (Claude, ChatGPT...) runs the OAuth authorization code flow.
//
// It shows the client's name (for a client ID metadata document, the verified host, since the document's own name is
// self-asserted), the host the browser returns to, the attestation the broker will record and the scopes, and warns
// when every redirect URI is on loopback. The person signs in, and approval:
//   1. registers or refreshes the principal, bound to the IdP's iss + sub (never the email);
//   2. binds the client as a delegate of that principal (the label comes from the verified client, or the person
//      confirms it for an unverified one);
//   3. records the OAuth grant (OpenID scopes and the read/send scopes for the requested resource);
//   4. hands the result back to oidc-provider, which redirects to the client with the code and `iss`.
//
// Development mode signs in with the dev IdP's fictional test identities and a per-session secret. A hosted broker
// signs people in by their invite (src/web/invites.ts) and also asks for the passkey they registered on
// their broker page, over a challenge bound to this authorization (the client, the scopes, the person). OIDC mode hands
// the person to the organization's OpenID provider (Entra, Okta...): "allow" redirects to the provider (code flow,
// PKCE, state, nonce); the provider returns the browser to /oidc/callback, which checks the transaction and the ID
// token (oidc.ts, oidc-signin.ts); the browser then comes back to /interaction/<uid>/oidc, where oidc-provider's own
// interaction cookie proves it is the browser that started the authorization, and steps 1 to 4 above run.

import { createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import express from "express";
import type { Request, Response, Router } from "express";
import type Provider from "oidc-provider";
import { delegateIdOf, displayAddress } from "../core/address.ts";
import type { Broker } from "../core/broker.ts";
import { AlpError, errMessage } from "../core/errors.ts";
import type { IdentityVerifier, VerifiedIdentity } from "../core/interfaces.ts";
import { MemoryWindows, windowCount, windowHit } from "../core/windows.ts";
import type { Windows } from "../core/windows.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { domainOf } from "../core/address.ts";
import { clientRule } from "../core/policy/org-policy.ts";
import type { Attestation, ClientRule, DelegateRecord, OrgPolicy, PrincipalRecord } from "../core/types.ts";
import { Html, html, sendPage } from "../web/html.ts";
import { clientAttestation, clientDisplay, isCimdClientId, isLoopbackUri, slugLabel, suggestedLabel } from "./clients.ts";
import { OidcSignInError, isOidcSignInError } from "./oidc.ts";
import { bindBrowser, readCookie, sha256b64 } from "./oidc-signin.ts";
import type { OidcSignIn } from "./oidc-signin.ts";
import { OAUTH_SCOPES } from "./provider.ts";
import type { AuthServer } from "./provider.ts";
import { sha256b64u } from "./state.ts";
import type { BindingStore } from "./state.ts";
import { sourcePrefix } from "./sources.ts";
import { CHALLENGE_TTL_MS, authenticationOptions, challengeOf, newChallenge, parseCredential, stepUpBinding, verifyAssertion } from "../web/passkeys.ts";
import type { RelyingParty } from "../web/passkeys.ts";

/** Where the organization's identity provider returns the browser after a connector sign-in (on the public origin). */
export const CONNECTOR_CALLBACK_PATH = "/oidc/callback";
/** The browser-binding cookie of connector sign-ins (oidc-signin.ts). */
const CONNECTOR_COOKIE = "alp_oidc";

export interface InteractionOptions {
  broker: Broker;
  auth: AuthServer;
  identity: IdentityVerifier;
  /** "dev": test identities on this page. "oidc": hand off to the organization's identity provider (`oidc`). */
  idpMode: "dev" | "oidc";
  /** OIDC mode: the sign-in plumbing, and the callback URL registered at the provider (<PUBLIC_URL>/oidc/callback). */
  oidc?: { signIn: OidcSignIn; callbackUri: string; secureCookies: boolean };
  /** Whether the dev sign-in needs the per-session secret. */
  requireSecret: boolean;
  /** The dev sign-in's secret: one session secret for everyone (`npm run dev`), or each test identity's own (`npm start`). */
  secretKind?: "session" | "personal";
  /** Key for the form's CSRF token. */
  csrfKey: Buffer;
  /** Connector grant caps, shown to the person. */
  grantDays: { organization: number; other: number };
  isOrganizationDomain: (domain: string) => boolean;
  /** The broker's private org policies: a client's pre-registration (label, attestation) lives there. */
  policies: () => readonly OrgPolicy[];
  /** Where a request comes from, for the sign-in limits (see sourceOf). */
  sourceOf?: (req: IncomingMessage) => string;
  /** Where the failed-sign-in counts live (default: this process's memory). */
  windows?: Windows;
  /** A hosted broker: every connector sign-in also needs the person's passkey (registered on their broker page). */
  passkeys?: { rp: RelyingParty; store: BindingStore };
  /**
   * POSTs to the sign-in page per source (an IPv6 /64 counting as one) per minute, before anything else runs: no
   * secret is checked (scrypt for invites) and no sign-in is started past it. Default 120, as on the public web view.
   */
  postsPerMinute?: number;
  log: (line: string) => void;
}

/**
 * Failed test sign-ins are capped (the page is public during a test through a tunnel): 10 per 15 minutes for one source
 * address and identity, then a pause for that pair only; and 100 per 15 minutes in all as a backstop, counting only
 * failures for identities that exist. A stranger who tries made-up names never reaches the backstop, so they can't lock
 * out the person at the keyboard that way. The counts live in `windows`: this process's memory by default, the hosted
 * broker's Postgres store when it passes one (so every instance counts the same failures).
 */
export class SignInLimiter {
  private readonly windows: Windows;
  private readonly name: string;
  private readonly max: number;
  private readonly maxAll: number;
  private readonly windowSeconds: number;
  constructor(opts: { windows?: Windows; name?: string; max?: number; maxAll?: number; windowSeconds?: number } = {}) {
    this.windows = opts.windows ?? new MemoryWindows();
    this.name = opts.name ?? "signin";
    this.max = opts.max ?? 10;
    this.maxAll = opts.maxAll ?? 100;
    this.windowSeconds = opts.windowSeconds ?? 15 * 60;
  }
  private key(key: string): string {
    return `${this.name}|${sha256b64u(key)}`;
  }
  async blocked(key: string, now: number): Promise<boolean> {
    const at = new Date(now);
    return (await windowCount(this.windows, this.key(key), at, this.windowSeconds)) >= this.max || (await windowCount(this.windows, `${this.name}-all`, at, this.windowSeconds)) >= this.maxAll;
  }
  /** A failed sign-in for `key`; `knownIdentity` is false for a username nobody has (it doesn't count toward the backstop). */
  async fail(key: string, now: number, knownIdentity = true): Promise<void> {
    const at = new Date(now);
    if (knownIdentity) await windowHit(this.windows, `${this.name}-all`, at, this.windowSeconds);
    await windowHit(this.windows, this.key(key), at, this.windowSeconds);
  }
}

/** An address as a proxy may write it: `198.51.100.7:51234` and `[2001:db8::1]:51234` lose the port, `[...]` the brackets. */
function bareAddress(value: string): string {
  const v4 = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(value);
  if (v4?.[1]) return v4[1];
  const v6 = /^\[([0-9a-fA-F:.]+)\](?::\d{1,5})?$/.exec(value);
  return v6?.[1] ?? value;
}

/**
 * Where a request comes from, for per-source limits: the socket's address, or a header the platform in front sets
 * itself: Cloudflare's `CF-Connecting-IP` when the operator says the broker is reached only through Cloudflare (a
 * tunnel), or the header the operator names (`clientIpHeader`, for example `x-real-ip` on Vercel or behind nginx). Of a
 * list-valued header (X-Forwarded-For, to which proxies append), the entry `trustedHops` from the right is taken (1, the
 * default, is the right-most): the entries to its left were written by whoever sent the request, so a client could
 * choose them. Anywhere else any client could send such a header, so it is ignored.
 */
export function sourceOf(req: IncomingMessage, behindCloudflare = false, clientIpHeader?: string, trustedHops = 1): string {
  const name = behindCloudflare ? "cf-connecting-ip" : clientIpHeader?.toLowerCase();
  const raw = name ? req.headers[name] : undefined;
  const entries = (Array.isArray(raw) ? raw.join(",") : (raw ?? "")).split(",").map((x) => x.trim()).filter(Boolean);
  const hops = Number.isInteger(trustedHops) && trustedHops >= 1 ? trustedHops : 1;
  // Fewer entries than proxies: the request didn't pass them all; the farthest entry there is is the best guess.
  const picked = behindCloudflare ? entries[0] : entries.length >= hops ? entries[entries.length - hops] : entries[0];
  const value = picked !== undefined ? bareAddress(picked) : undefined;
  return (typeof value === "string" && value.length > 0 && value.length <= 64 ? value : req.socket.remoteAddress ?? "unknown").toLowerCase();
}

/**
 * Spec 5.4: a client recorded above `vendor` or above class `business` must authenticate at the token endpoint. For a
 * public client the authorization code passes through the person's browser, so whoever completes the sign-in could
 * redeem it: its class guards against mistakes, not against the person.
 */
export function needsClientCredential(rule: Pick<ClientRule, "attestation" | "class"> | undefined): boolean {
  if (!rule) return false;
  return rule.attestation === "native" || rule.attestation === "org-client" || rule.attestation === "tenant" || rule.class === "enterprise";
}

/** The rule for a client in the list of the organization that serves `domain` (the signed-in person's), if any. */
function ruleFor(policies: readonly OrgPolicy[], clientId: string, domain: string): ClientRule | undefined {
  for (const p of policies) {
    if (!p.domains.includes(domain)) continue;
    const r = clientRule(p, clientId);
    if (r) return r;
  }
  return undefined;
}

// oidc-provider treats every configured static scope (read and send included, so discovery lists them) as an
// OpenID scope as well as a resource scope; the grant records both.
const OIDC_SCOPES = new Set(["openid", "offline_access", "email", "profile", ...OAUTH_SCOPES]);

function csrfFor(key: Buffer, uid: string): string {
  return createHmac("sha256", key).update(`interaction:${uid}`).digest("base64url");
}

function csrfOk(key: Buffer, uid: string, given: unknown): boolean {
  if (typeof given !== "string") return false;
  const a = Buffer.from(csrfFor(key, uid));
  const b = Buffer.from(given);
  return a.length === b.length && timingSafeEqual(a, b);
}

function asList(v: unknown): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  return [];
}

const SCOPE_TEXT: Record<string, string> = {
  read: "read: see who you are on the broker, your contacts, your inbox and your threads",
  send: "send: send typed messages within your rules, mark messages handled, and ask to connect (which waits for you)",
  offline_access: "stay connected: renew access without asking you again, until the connection ends or you revoke it",
  openid: "your broker identity (an opaque id)",
  email: "your address",
  profile: "your display name",
};

/** Bind the client as the principal's delegate. Re-connecting the same client keeps its label; another client never takes it. */
export async function bindDelegate(broker: Broker, principal: PrincipalRecord, clientId: string, wanted: string, attestation: Attestation): Promise<DelegateRecord> {
  const mine = (await broker.store.listDelegates(principal.address)).filter((d) => d.client_id === clientId).sort((a, b) => (a.status === b.status ? 0 : a.status === "active" ? -1 : 1));
  let label = mine[0]?.label;
  if (!label) {
    const base = slugLabel(wanted);
    for (let i = 1; i < 100 && !label; i++) {
      const candidate = i === 1 ? base : `${base.slice(0, 28)}-${i}`;
      const d = await broker.store.getDelegate(delegateIdOf(principal.address, candidate));
      if (!d || d.client_id === clientId || d.status !== "active") label = candidate;
    }
  }
  if (!label) throw new AlpError("invalid_input", "no free delegate label");
  return broker.registerDelegate({ principal: principal.address, label, kind: "bridged", client_id: clientId, attestation });
}

export function interactionRouter(opts: InteractionOptions): Router {
  const { broker, auth, identity } = opts;
  const provider: Provider = auth.provider;
  const router = express.Router();
  const form = express.urlencoded({ extended: false, limit: "8kb" });
  const windows = opts.windows ?? new MemoryWindows();
  const limiter = new SignInLimiter({ name: "signin-connector", windows });

  const failPage = (res: Response, status: number, message: string, retry?: string): void => {
    sendPage(res, "Sign-in", html`<h1>Sign-in can't continue</h1><div class="card"><p>${message}</p>${retry ? html`<p><a href="${retry}">Back to the sign-in page</a> to try again.</p>` : ""}<p class="muted">Or start again from your agent's connector settings.</p></div>`, { status });
  };

  /** A refused OIDC sign-in: the person sees the reason (never the provider's own text); the operator's log and the security events get the detail. */
  const oidcFail = async (res: Response, err: unknown, ctx: { retry?: string; clientId?: string }): Promise<void> => {
    const e = isOidcSignInError(err) ? err : new OidcSignInError("bad_response", errMessage(err));
    opts.log(`oidc: a connector sign-in was refused (${e.reason}: ${e.detail})`);
    if (e.reason !== "stale" && e.reason !== "rate_limited") {
      await broker.recordSecurityEvent("token_refused", { failed: true, message: `sign-in refused: ${e.reason}`, details: ctx.clientId ? { client_id: ctx.clientId.slice(0, 2048) } : {} });
    }
    failPage(res, e.reason === "idp_unavailable" ? 503 : e.reason === "rate_limited" ? 429 : 401, `${e.personText} (Reason: ${e.reason}.)`, e.reason === "stale" ? undefined : ctx.retry);
  };

  /**
   * After the person is verified (dev IdP or the organization's provider): register or refresh the principal, apply
   * the organization's client rules and kill switches, bind the delegate, record the grant, and hand the result back
   * to oidc-provider, which redirects to the agent's client with the code.
   */
  const completeConnector = async (
    req: Request,
    res: Response,
    params: Record<string, unknown>,
    verified: VerifiedIdentity,
    labelInput: unknown,
    extra: { contact?: { email: string }; amr?: string[]; onGranted?: (grantId: string, principal: PrincipalRecord) => Promise<void> } = {},
  ): Promise<void> => {
    const principal = await broker.registerPrincipal({
      address: verified.address,
      identity: { iss: verified.iss, sub: verified.sub },
      ...(verified.display_name ? { display_name: verified.display_name } : {}),
      ...(verified.claims ? { claims: verified.claims } : {}),
      ...(extra.contact ? { contact: extra.contact } : {}),
    });
    auth.noteAccount(principal.principal_id, principal.address);
    const clientId = String(params["client_id"] ?? "");
    const client = await provider.Client.find(clientId);
    if (!client) {
      failPage(res, 400, "The agent's client is unknown to this broker.");
      return;
    }
    const rule = ruleFor(opts.policies(), clientId, domainOf(principal.address));
    // Spec 6.10: in enforce mode the organization's broker refuses to authorize a client its `clients` list doesn't name.
    const orgPolicy = opts.policies().find((p) => p.domains.includes(domainOf(principal.address)));
    if (orgPolicy?.clients?.mode === "enforce" && !rule) {
      await broker.recordSecurityEvent("client_refused", { failed: true, details: { client_id: clientId.slice(0, 2048), principal_id: principal.principal_id } });
      failPage(res, 403, "Your organization doesn't allow this agent to connect. Ask your administrator to add it to the organization's list of agents.");
      return;
    }
    // Spec 5.4: a client recorded above `vendor` or above class `business` (`org-client`, `tenant`, `native`,
    // `enterprise`) must authenticate at the token endpoint. A public client's code passes through the person's
    // browser, so anyone completing this sign-in could redeem it: it can't be told apart from a script.
    if (needsClientCredential(rule) && (client.tokenEndpointAuthMethod ?? "none") === "none") {
      await broker.recordSecurityEvent("client_refused", { failed: true, details: { client_id: clientId.slice(0, 2048), principal_id: principal.principal_id } });
      failPage(res, 403, "Your organization registered this agent at a level that needs a client credential, but the agent has none. Ask your administrator to check its registration.");
      return;
    }
    // Spec 5.8: a kill switch on the person or on this client also stops new connections.
    const killed = broker.agentBlocked(principal.address, undefined, clientId);
    if (killed) {
      await broker.recordSecurityEvent("kill_switch", { failed: true, message: killed, details: { client_id: clientId.slice(0, 2048), principal_id: principal.principal_id } });
      failPage(res, 403, "Your organization has blocked this agent or this account.");
      return;
    }
    // Spec 5.4: the label comes from the verified client (a metadata document's host, the organization's rule, or the
    // operator's pre-registration); only for a dynamically registered client does the person choose it.
    const verifiedClient = isCimdClientId(clientId) || rule !== undefined || auth.isPreRegistered(clientId);
    const wanted = rule?.label ?? (verifiedClient ? suggestedLabel(clientId, client.clientName) : slugLabel(typeof labelInput === "string" ? labelInput : suggestedLabel(clientId, client.clientName)));
    const delegate = await bindDelegate(broker, principal, clientId, wanted, clientAttestation(clientId));

    // The grant: every OpenID scope asked for, and read/send for each requested resource (exactly as requested,
    // so oidc-provider's consent check matches; the audience is canonicalized when the token is issued).
    const requested = String(params["scope"] ?? "").split(" ").filter(Boolean);
    const grant = new provider.Grant({ accountId: principal.principal_id, clientId });
    const oidc = requested.filter((s) => OIDC_SCOPES.has(s));
    if (oidc.length) grant.addOIDCScope(oidc.join(" "));
    const rs = requested.filter((s) => (OAUTH_SCOPES as readonly string[]).includes(s));
    const resources = asList(params["resource"]).filter((r) => auth.canonicalResource(r) !== null);
    for (const r of resources.length ? resources : [auth.resources.mcp]) grant.addResourceScope(r, (rs.length ? rs : [...OAUTH_SCOPES]).join(" "));
    const grantId = await grant.save();
    await auth.bindGrant(grantId, principal.principal_id, delegate);
    if (extra.onGranted) await extra.onGranted(grantId, principal);
    // "connected" is logged when the authorization actually completes (provider.ts, authorization.success).
    opts.log(`oauth: ${principal.address.replace(/^[a-z]+:/, "")} allowed ${delegate.id} on the sign-in page`);
    await provider.interactionFinished(req, res, { login: { accountId: principal.principal_id, ...(extra.amr?.length ? { amr: extra.amr } : {}) }, consent: { grantId } }, { mergeWithLastSubmission: false });
  };

  const render = async (req: Request, res: Response, error?: string): Promise<void> => {
    let details;
    try {
      details = await provider.interactionDetails(req, res);
    } catch {
      failPage(res, 400, "This sign-in has expired or was opened in another browser.");
      return;
    }
    const { uid, params } = details;
    opts.log(`oauth: sign-in page shown (${details.prompt.name}: ${details.prompt.reasons.join(", ")})`);
    const clientId = String(params["client_id"] ?? "");
    const client = await provider.Client.find(clientId);
    if (!client) {
      failPage(res, 400, "The agent's client is unknown to this broker.");
      return;
    }
    const preRegistered = auth.isPreRegistered(clientId);
    const shown = clientDisplay(clientId, client.clientName, preRegistered);
    const redirectUri = String(params["redirect_uri"] ?? client.redirectUris?.[0] ?? "");
    const returnHost = URL.parse(redirectUri)?.host ?? "(unknown)";
    const allLoopback = (client.redirectUris ?? []).length > 0 && (client.redirectUris ?? []).every((u) => isLoopbackUri(u));
    // Spec 5.6 item 5: the attestation and the name the broker will record. The person signs in on this form, or after
    // it, so their organization isn't known yet, and only their organization's list of agents counts. Organization
    // policy is private (spec 6.4), so the page shows nothing from any list, whoever opens it: only what the client
    // itself gives (a metadata document's host, the operator's registration), and what a list naming it changes.
    const fallback = clientAttestation(clientId);
    const recorded = html`with attestation <code>${fallback}</code>${preRegistered && !shown.verifiedHost ? " (the lowest: the operator's registration doesn't raise it)" : ""}, unless your organization's list of agents names this client: then it has the attestation the list gives it`;
    const scopes = String(params["scope"] ?? "").split(" ").filter((s) => s && SCOPE_TEXT[s]);
    const label = suggestedLabel(clientId, client.clientName);
    const fixedLabel = isCimdClientId(clientId) || preRegistered;
    const people = identity.listTestIdentities?.() ?? [];
    const iat = (details as { iat?: unknown }).iat;
    const minutes = typeof iat === "number" ? Math.max(0, Math.round((Date.now() / 1000 - iat) / 60)) : undefined;
    const startedAgo = minutes === undefined ? undefined : minutes === 0 ? "less than a minute ago" : `${minutes} minute${minutes === 1 ? "" : "s"} ago`;

    const body = html`
      <h1>Connect an agent to your ${PROTOCOL.shortName} broker</h1>
      ${opts.passkeys
        ? html`<div class="warn"><strong>Invite-only evaluation broker.</strong> Don't use it for confidential or production data.</div>`
        : opts.idpMode === "dev" ? html`<div class="warn"><strong>Test identities only.</strong> This is a development broker. The people below are fictional; never enter real personal data.</div>` : ""}
      ${error ? html`<div class="warn bad">${error}</div>` : ""}
      <div class="card">
        <p><strong>${shown.name}</strong> wants to act for you on this broker.</p>
        <p class="muted">${shown.verifiedHost
          ? html`Its identity comes from a client metadata document on <code>${shown.verifiedHost}</code>.`
          : preRegistered
            ? html`Registered with this broker by its operator; its name comes from that registration.`
            : html`Its name is self-declared (dynamic registration), so the broker can't verify which product it is.`}
        After you allow it, your browser returns to <code>${returnHost}</code>. The broker records it ${recorded}.</p>
        <div class="warn">Continue only if you started connecting this agent yourself, in your own account, in the last few minutes${startedAgo !== undefined ? html` (this sign-in started ${startedAgo})` : ""}. A link someone sent you could connect their agent to your broker.</div>
        ${allLoopback ? html`<div class="warn">Every return address of this client is on <code>localhost</code>. Any program on your computer can claim to be it. Allow it only if you started this sign-in yourself.</div>` : ""}
        <p>It asks to:</p>
        <ul>${scopes.map((s) => html`<li>${SCOPE_TEXT[s]}</li>`)}</ul>
        <p class="muted">It can never approve connections, approve commitments or change your rules: those happen only on your broker's page, with a fresh sign-in. A connection lasts at most ${opts.grantDays.organization} days for organization accounts (${opts.grantDays.other} for others).</p>
      </div>
      <form method="post" action="/interaction/${uid}" class="card" ${opts.passkeys ? new Html("data-alp-passkey") : ""}>
        <input type="hidden" name="csrf" value="${csrfFor(opts.csrfKey, uid)}">
        ${opts.idpMode === "dev"
          ? people.length
            ? html`
            <p><strong>Sign in as</strong></p>
            ${people.map((p, i) => html`<label><input type="radio" name="username" value="${p.username}" ${i === 0 ? new Html("checked") : ""}> ${p.display_name ?? p.username} · <code>${p.address.replace(/^[a-z]+:/, "")}</code></label>`)}
            ${opts.requireSecret ? (opts.secretKind === "personal" ? html`<label>Your sign-in secret (from the broker's operator)<br><input type="password" name="secret" autocomplete="off" required></label>` : html`<label>Session secret (printed in the broker operator's terminal)<br><input type="password" name="secret" autocomplete="off" required></label>`) : ""}`
            : html`
            <label>Sign-in name<br><input type="text" name="username" autocomplete="username" maxlength="32" required></label>
            <label>Invitation secret<br><input type="password" name="secret" autocomplete="current-password" maxlength="128" required></label>
            ${opts.passkeys ? html`<p class="muted">Then your passkey: create one on your broker page first if you haven't.</p>` : ""}`
          : html`<p>Next, you sign in with your organization's account${opts.oidc?.signIn.rp.settings.freshSignIn ? " (it asks for your sign-in again, even if you're already signed in)" : ""}. The agent is connected only after that.</p>`}
        ${fixedLabel
          ? html`<p class="muted">This agent will appear as <code>${label}</code> in your broker (a number is added if you already connected another agent with that name), unless your organization's list of agents gives it another name.</p>`
          : html`<label>Name for this agent on your broker (lower case, digits, - and _)<br><input type="text" name="label" value="${label}" maxlength="32" pattern="[a-z0-9][a-z0-9_-]{0,30}[a-z0-9]?" required></label>
            <p class="muted">If your organization's list of agents names this client, the name comes from the list, or from the client's registration, instead.</p>`}
        ${opts.passkeys
          ? html`<input type="hidden" name="action" value="allow"><input type="hidden" name="credential" value=""><button class="primary" type="submit">Sign in and allow</button><span class="muted" data-alp-status></span>`
          : html`<button class="primary" type="submit" name="action" value="allow">${opts.idpMode === "dev" ? "Sign in and allow" : "Allow, then sign in"}</button>
        <button type="submit" name="action" value="deny" formnovalidate>Cancel</button>`}
      </form>
      ${opts.passkeys ? html`<form method="post" action="/interaction/${uid}"><input type="hidden" name="csrf" value="${csrfFor(opts.csrfKey, uid)}"><input type="hidden" name="action" value="deny"><button type="submit">Cancel</button></form>` : ""}`;
    sendPage(res, "Connect an agent", body, opts.passkeys ? { scriptHref: "/web/static/passkey.js" } : {});
  };

  router.get("/interaction/:uid", (req, res, next) => {
    render(req, res).catch(next);
  });

  router.post("/interaction/:uid", form, (req, res, next) => {
    (async () => {
      // Every POST counts per source first, so a flood of sign-in attempts (each would check a secret) or of OIDC
      // starts from one client is turned away before any of that work.
      const source = (opts.sourceOf ?? sourceOf)(req);
      if (!(await windows.hitRateLimit(`connector-post|${sha256b64u(sourcePrefix(source))}`, new Date(), 60, opts.postsPerMinute ?? 120)).allowed) {
        opts.log("oauth: connector sign-in requests paused for one source (too many in a minute)");
        res.setHeader("Retry-After", "60");
        if ((req.body as Record<string, unknown> | undefined)?.["alp_webauthn"] === "options") {
          res.status(429).setHeader("Cache-Control", "no-store");
          res.json({ error: "Too many requests. Wait a minute and try again." });
          return;
        }
        failPage(res, 429, "Too many sign-in requests from your network. Wait a minute and try again.");
        return;
      }
      let details;
      try {
        details = await provider.interactionDetails(req, res);
      } catch {
        failPage(res, 400, "This sign-in has expired or was opened in another browser.");
        return;
      }
      const { uid, params } = details;
      const b = (req.body ?? {}) as Record<string, unknown>;
      if (!csrfOk(opts.csrfKey, uid, b["csrf"])) {
        failPage(res, 403, "The form is stale. Reload the page and try again.");
        return;
      }
      if (b["action"] !== "allow") {
        await provider.interactionFinished(req, res, { error: "access_denied", error_description: "the person did not allow the connection" }, { mergeWithLastSubmission: false });
        return;
      }
      if (opts.idpMode === "oidc") {
        // Hand the person to the organization's identity provider; the callback below picks it up.
        const o = opts.oidc;
        if (!o) {
          failPage(res, 500, "This broker's organization sign-in isn't configured.");
          return;
        }
        const clientId = String(params["client_id"] ?? "");
        if (!(await o.signIn.allowStart(source, "connector"))) {
          await oidcFail(res, new OidcSignInError("rate_limited", "too many sign-ins started from one source"), { retry: `/interaction/${uid}` });
          return;
        }
        const browser = bindBrowser(req, res, { name: CONNECTOR_COOKIE, path: "/", secure: o.secureCookies });
        const fresh = o.signIn.rp.settings.freshSignIn;
        let url: string;
        try {
          url = await o.signIn.begin(
            { purpose: "connector", browser: sha256b64(browser), redirect_uri: o.callbackUri, fresh, uid, ...(clientId ? { client_id: clientId.slice(0, 2048) } : {}), ...(typeof b["label"] === "string" ? { label: b["label"].slice(0, 64) } : {}) },
            fresh ? { prompt: "login" } : {},
          );
        } catch (err) {
          await oidcFail(res, err, { retry: `/interaction/${uid}`, clientId });
          return;
        }
        opts.log("oidc: sent a connector sign-in to the organization's identity provider");
        res.redirect(303, url);
        return;
      }
      const username = typeof b["username"] === "string" ? b["username"] : "";
      // Per source and name, an IPv6 source by its /64, so a client can't spread its tries over its own addresses.
      const limitKey = `${sourcePrefix(source)}|${username.toLowerCase().slice(0, 64)}`;
      const wantsOptions = opts.passkeys !== undefined && b["alp_webauthn"] === "options";
      const refuseJson = (status: number, error: string): void => {
        res.status(status).setHeader("Cache-Control", "no-store");
        res.json({ error });
      };
      if (await limiter.blocked(limitKey, Date.now())) {
        opts.log("oauth: connector sign-ins paused for one source after repeated failures");
        if (wantsOptions) return refuseJson(429, "Too many failed sign-ins. Wait 15 minutes.");
        await render(req, res, "Too many failed sign-ins. Wait 15 minutes, or ask the operator to restart the broker with a new secret.");
        return;
      }
      let verified;
      try {
        verified = await identity.verify({ kind: "dev", username, ...(typeof b["secret"] === "string" ? { secret: b["secret"] } : {}) });
      } catch {
        const known = "known" in identity && typeof identity.known === "function" ? await (identity.known as (u: string) => Promise<boolean>)(username) : (identity.listTestIdentities?.() ?? []).some((p) => p.username.toLowerCase() === username.toLowerCase());
        await limiter.fail(limitKey, Date.now(), known);
        opts.log("oauth: a connector sign-in failed (wrong test identity or session secret)");
        if (wantsOptions) return refuseJson(401, "Sign-in failed: check your sign-in name and secret.");
        await render(req, res, `Sign-in failed: check the test identity and ${opts.secretKind === "personal" ? "your sign-in secret" : "the session secret"}.`);
        return;
      }
      if (opts.passkeys) {
        // A hosted broker also asks for the person's passkey, over a challenge bound to this authorization.
        const { rp, store } = opts.passkeys;
        const known = await broker.store.getPrincipalByIdentity(verified.iss, verified.sub);
        const passkeys = known && known.status === "active" ? await store.listPasskeys(known.principal_id) : [];
        if (!known || passkeys.length === 0) {
          const msg = "Sign in to your broker page first and create a passkey; then connect the agent.";
          if (wantsOptions) return refuseJson(403, msg);
          await render(req, res, msg);
          return;
        }
        const binding = stepUpBinding({ origin: rp.origin, principal_id: known.principal_id, action: `/interaction/${uid}`, terms: { kind: "connect", client_id: String(params["client_id"] ?? ""), scope: String(params["scope"] ?? ""), redirect_uri: String(params["redirect_uri"] ?? "") } });
        const holder = `interaction:${sha256b64u(uid)}`;
        if (wantsOptions) {
          const challenge = newChallenge(binding);
          await store.putChallenge({ challenge, session_hash: holder, purpose: "connect", action: `/interaction/${uid}`, binding, expires_at: Date.now() + CHALLENGE_TTL_MS });
          res.setHeader("Cache-Control", "no-store");
          res.json({ kind: "get", publicKey: await authenticationOptions(rp, passkeys, challenge) });
          return;
        }
        const credential = parseCredential(b["credential"]);
        const challenge = credential ? challengeOf(credential) : null;
        const issued = challenge ? await store.takeChallenge(holder, challenge, Date.now()) : null;
        const id = credential?.["id"];
        const pk = typeof id === "string" && id.length <= 1024 ? await store.getPasskey(id) : null;
        const v = credential && challenge && issued?.purpose === "connect" && issued.binding === binding && pk && pk.principal_id === known.principal_id ? await verifyAssertion(rp, credential, challenge, pk) : null;
        if (!v || !pk || !(await store.usePasskey(pk.credential_id, v.counter, new Date().toISOString()))) {
          await limiter.fail(limitKey, Date.now(), true);
          opts.log("oauth: a connector sign-in's passkey check failed");
          await render(req, res, "The passkey check didn't work. Try again.");
          return;
        }
      }
      await completeConnector(req, res, params as Record<string, unknown>, verified, b["label"], { amr: ["pwd"] });
    })().catch(next);
  });

  // ---- OIDC: the provider's redirect, then the completion step on the interaction's own path

  router.get(CONNECTOR_CALLBACK_PATH, (req, res, next) => {
    (async () => {
      const o = opts.oidc;
      if (opts.idpMode !== "oidc" || !o) {
        res.status(404).type("text").send("Not found");
        return;
      }
      const q = req.query as Record<string, unknown>;
      let tx;
      try {
        tx = await o.signIn.take(q["state"], readCookie(req, CONNECTOR_COOKIE), ["connector"]);
      } catch (err) {
        await oidcFail(res, err, {});
        return;
      }
      const retry = tx.uid ? `/interaction/${tx.uid}` : undefined;
      const ctx = { ...(retry ? { retry } : {}), ...(tx.client_id ? { clientId: tx.client_id } : {}) };
      if (typeof q["error"] === "string") {
        // The provider ended the sign-in itself: the person cancelled, or one of the organization's rules refused them.
        await oidcFail(res, new OidcSignInError("idp_refused", `the provider answered ${q["error"].slice(0, 64)}`, q["error"].slice(0, 64)), ctx);
        return;
      }
      let result;
      try {
        result = await o.signIn.finish(tx, { code: q["code"], iss: q["iss"] });
        if (o.signIn.rp.settings.refreshCheck && !result.refreshToken) throw new OidcSignInError("no_refresh_token", "the provider issued no refresh token (offline_access)");
      } catch (err) {
        await oidcFail(res, err, ctx);
        return;
      }
      if (!tx.uid) {
        failPage(res, 400, "This sign-in has no authorization to finish.");
        return;
      }
      const id = await o.signIn.handOff({ uid: tx.uid, browser: tx.browser, identity: result.identity, nonce: tx.nonce, ...(tx.label !== undefined ? { label: tx.label } : {}) }, result.refreshToken);
      opts.log(`oidc: ${displayAddress(result.identity.address)} signed in at the organization's identity provider`);
      res.redirect(303, `/interaction/${encodeURIComponent(tx.uid)}/oidc?h=${id}`);
    })().catch(next);
  });

  router.get("/interaction/:uid/oidc", (req, res, next) => {
    (async () => {
      const o = opts.oidc;
      if (opts.idpMode !== "oidc" || !o) {
        res.status(404).type("text").send("Not found");
        return;
      }
      let details;
      try {
        details = await provider.interactionDetails(req, res);
      } catch {
        failPage(res, 400, "This sign-in has expired or was opened in another browser.");
        return;
      }
      if (details.uid !== String(req.params["uid"])) {
        failPage(res, 400, "This sign-in has expired or was opened in another browser.");
        return;
      }
      let h;
      try {
        h = await o.signIn.takeHandoff(req.query["h"], details.uid, readCookie(req, CONNECTOR_COOKIE));
      } catch (err) {
        await oidcFail(res, err, {});
        return;
      }
      const params = details.params as Record<string, unknown>;
      await completeConnector(req, res, params, h.identity, h.label, {
        contact: { email: displayAddress(h.identity.address) },
        ...(h.identity.amr ? { amr: h.identity.amr } : {}),
        // Spec 5.3: the provider's refresh token, kept for the re-check at every refresh of this connection.
        onGranted: async (grantId, principal) => {
          if (!o.signIn.rp.settings.refreshCheck) return;
          const days = opts.isOrganizationDomain(domainOf(principal.address)) ? opts.grantDays.organization : opts.grantDays.other;
          await o.signIn.rememberSession(grantId, principal, h, days * 86400);
        },
      });
    })().catch(next);
  });

  return router;
}
