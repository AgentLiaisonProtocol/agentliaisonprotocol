// SPDX-License-Identifier: FSL-1.1-ALv2
// The person's web view (spec 12.5): the only ALP screen a client-mode person has.
// Connection requests (incoming, and the ones their agent filed), ratification, messages held for them, their agents
// and personal access tokens, their relationships and their ledger.
//
// - Actions are POST-only with a CSRF token; GET changes nothing.
// - Every approval, ratification, grant change and settings change needs a fresh sign-in, for exactly what the page
//   showed: with the dev IdP, the session secret on the same form; on a public origin, a passkey (below); with the
//   organization's identity provider (OIDC, loopback only), a single sign-on step-up: a fresh sign-in at the provider
//   (prompt=login, max_age=0, auth_time checked) whose nonce commits to that one action (its form, and the hash of
//   what it covers, read from the broker's state: for a ratification, the terms hash), confirmed once on return.
// - CSP default-src 'self', frame-ancestors 'none'; session cookies as src/web/sessions.ts describes.
// - Counterparty strings render as text only; only the signed-in principal's own items are shown; terms come from
//   server state, never from URL parameters.
//
// Two modes:
// - Loopback (the default; `npm run dev`, `npm start`): the view answers only to loopback host names, and the fresh
//   sign-in for an action is the dev login again (the session secret). During a test through a tunnel it stays on
//   loopback: the tunnel never exposes it.
// - Public (`public`, for a hosted broker): the view answers only to the broker's public origin. A person signs in
//   with their invite (src/web/invites.ts), registers a passkey before anything else, and finishes every later sign-in
//   with it; every action needs a fresh passkey assertion with user verification whose challenge carries the hash of
//   the action and its terms (src/web/passkeys.ts). `__Host-` cookies, Secure, SameSite=Strict; a stricter CSP with
//   one same-origin script; Origin and Sec-Fetch-Site checked on every POST; request and failure limits; a notice when
//   a person signs in from a browser they hadn't used here.

import type { IncomingMessage } from "node:http";
import express from "express";
import type { Request, Response, Router } from "express";
import { delegateIdOf, displayAddress, domainOf, isDelegateLabel, parseAddress } from "../core/address.ts";
import type { Broker } from "../core/broker.ts";
import { isAlpError } from "../core/errors.ts";
import { hashJson } from "../core/hash.ts";
import type { IdentityVerifier, Notifier } from "../core/interfaces.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { defaultScopeTerms } from "../core/relationships.ts";
import { freeTextPatterns } from "../core/scopes/index.ts";
import type { ConnectionPurpose, HeldOutbound, HumanCaller, LedgerEntry, MessageRecord, PrincipalRecord } from "../core/types.ts";
import { MemoryWindows } from "../core/windows.ts";
import type { Windows } from "../core/windows.ts";
import { sanitizeBody, sanitizeFreeText } from "../mcp/render.ts";
import { getPending, pendingFor, settlePending } from "../mcp/pending.ts";
import { OidcSignInError, isOidcSignInError } from "../oauth/oidc.ts";
import { bindBrowser, readCookie, sha256b64 } from "../oauth/oidc-signin.ts";
import type { OidcSignIn, StepUpAction } from "../oauth/oidc-signin.ts";
import { PAT_CLIENT_ID, mintPat, patsOf, revokePat, revokePatsOfDelegate } from "../oauth/pat.ts";
import { sha256b64u } from "../oauth/state.ts";
import { sourcePrefix } from "../oauth/sources.ts";
import type { BindingStore } from "../oauth/state.ts";
import { CSS, Html, PUBLIC_SECURITY_HEADERS, html, sendPage } from "./html.ts";
import { SignInLimiter } from "../oauth/interaction.ts";
import { InviteIdentityVerifier } from "./invites.ts";
import { CHALLENGE_TTL_MS, PASSKEY_JS, authenticationOptions, challengeOf, newChallenge, parseCredential, registrationOptions, relyingParty, stepUpBinding, verifyAssertion, verifyRegistration } from "./passkeys.ts";
import type { RelyingParty } from "./passkeys.ts";
import { WebSessions } from "./sessions.ts";
import type { WebSession } from "./sessions.ts";

/** Where the identity provider returns the browser after a web view sign-in or step-up. */
export const WEB_CALLBACK_PATH = "/web/oidc/callback";
/** The browser-binding cookie of web view sign-ins (oidc-signin.ts). */
const WEB_OIDC_COOKIE = "alp_oidc_web";
/** A confirmed step-up must be used within this long (the broker's own approval window). */
const STEP_UP_USE_MS = 5 * 60 * 1000;

/** Serving the view on the broker's public origin (a hosted broker). */
export interface PublicWebOptions {
  /** The broker's public origin (PUBLIC_URL): the only Host the view answers to, and the passkeys' relying party. */
  origin: string;
  /** Shown by the browser when a passkey is created. */
  rpName: string;
  /** Sends the notice on sign-in from a new device. */
  notifier: Notifier;
  /** Where a request comes from, for per-source limits. */
  sourceOf: (req: IncomingMessage) => string;
  /** POSTs per source address per minute (default 120). */
  postsPerMinute?: number;
}

export interface WebOptions {
  broker: Broker;
  state: BindingStore;
  identity: IdentityVerifier;
  idpMode: "dev" | "oidc";
  /**
   * OIDC mode: the sign-in plumbing, this view's origin (as the person opens it) and its callback URL
   * (<origin>/web/oidc/callback), which is registered at the identity provider.
   */
  oidc?: { signIn: OidcSignIn; origin: string; callbackUri: string };
  requireSecret: boolean;
  /** The dev sign-in's secret: one session secret for everyone (`npm run dev`), or each test identity's own (`npm start`). */
  secretKind?: "session" | "personal";
  /** The web view's origin is HTTPS (enables __Host- cookies). */
  secureCookies: boolean;
  patMaxDays: { organization: number; other: number };
  isOrganizationDomain: (domain: string) => boolean;
  /** Revoke every OAuth grant (and its tokens) the authorization server holds for this person and client. */
  revokeClientGrants: (principalId: string, clientId: string) => Promise<void>;
  now: () => Date;
  log: (line: string) => void;
  /** Where request and failed-sign-in counts live (default: this process's memory). */
  windows?: Windows;
  /** Serve the view on the public origin, as the module comment describes. Default: loopback only. */
  public?: PublicWebOptions;
}

/** What an action covers, read from the broker's state and the form; a passkey approval signs its hash. */
type TermsOf = (req: Request, s: WebSession, f: Form) => Promise<unknown>;

type Form = Record<string, unknown>;

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function list(v: unknown): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string");
  return [];
}

const labelOf = (id: string): string => id.slice(id.lastIndexOf("/") + 1);

/**
 * A message between the person's own agents held under the organization's minimums (spec 6.14) whose receiving agent
 * already got a copy without the withheld fields. A record written before `whole` existed that names `withheld` is of
 * this kind (its copy's id wasn't kept): only those copies set `withheld` then.
 */
function copyWent(h: HeldOutbound): boolean {
  return h.reason === "delivery_minimums" && (h.partial_envelope_id !== undefined || (h.withheld !== undefined && h.whole !== true));
}

/** A held message's state on its page: once the person decided, what left and what didn't. */
function heldState(h: HeldOutbound): Html {
  // A copy without the withheld fields already went: never "nothing was sent" for such a message.
  const copy = copyWent(h)
    ? html`the full message wasn't sent; ${h.to_delegate ? html`your agent <code>${labelOf(h.to_delegate)}</code>` : "that agent"} already had the copy without the fields${h.withheld ? html` labeled <code>${h.withheld.labels.join(", ")}</code>` : ""}${h.partial_envelope_id ? html` (message <code>${h.partial_envelope_id}</code>)` : ""}.`
    : html`nothing was sent.`;
  const code = h.result?.code ?? "not_accepted";
  switch (h.state) {
    case "pending":
      return copyWent(h) ? html`Waiting for you. The rest of it already went to ${h.to_delegate ? html`your agent <code>${labelOf(h.to_delegate)}</code>` : "that agent"}.` : html`Waiting for you. Nothing has been sent.`;
    case "sending":
      return html`<strong>Being sent</strong> since ${h.decided_at ?? h.created_at}. If this doesn't change, the broker stopped before it recorded the outcome: your ledger shows whether it went.`;
    case "sent":
      return html`<strong>Sent</strong>${h.envelope_id ? html` (message <code>${h.envelope_id}</code>)` : ""}.`;
    case "refused":
      // Only what this broker knows: the recipient's broker answered no, or the delivery failed (after which the
      // message may still have arrived), or this broker didn't send it.
      if (h.result?.status === "refused") return html`<strong>Refused by the recipient's broker</strong>: <code>${code}</code>${h.envelope_id ? html` (message <code>${h.envelope_id}</code>)` : ""}.`;
      if (h.result?.status === "undeliverable" && h.envelope_id) return html`<strong>Delivery failed</strong>: <code>${code}</code>; it may still have arrived (message <code>${h.envelope_id}</code>).`;
      if (h.result?.status === "undeliverable") return html`<strong>Not sent</strong>: <code>${code}</code> (no broker for the recipient could be reached).`;
      if (h.result?.status === "needs_ratification") return html`<strong>Not sent</strong>: <code>${code}</code> (both people must ratify the agreed terms first).`;
      return html`<strong>Not sent</strong>: <code>${code}</code> (your broker checked it again when you approved it, and didn't send it).`;
    case "discarded":
      return html`Discarded: ${copy}`;
    case "expired":
      return html`Expired before you decided: ${copy}`;
  }
}

/** Why a pending held message can't be sent any more (spec 5.4), or nothing. */
function heldStale(h: HeldOutbound, changed: "writer" | "target" | null): Html | "" {
  if (changed === "target") return html`It can't be sent now: your agent <strong>${h.to_delegate ? labelOf(h.to_delegate) : "that agent"}</strong> was disconnected after it was written, and it goes only to the agent it was written for. You can discard it.`;
  if (changed === "writer") return html`It can't be sent now: the agent that wrote it was disconnected after it was written. You can discard it.`;
  return "";
}

/** The "Needs you" line for an outbound message held for the person: who wrote it, to whom, and why it waits. */
function heldSummary(h: HeldOutbound, p: PrincipalRecord, changed: "writer" | "target" | null): Html {
  const target = h.to === p.address && h.to_delegate ? labelOf(h.to_delegate) : undefined;
  const writer = h.delegate ? html`Your agent <code>${labelOf(h.delegate)}</code> wrote` : html`Your broker wrote, for you,`;
  const to = target !== undefined ? html`your agent <strong>${target}</strong>` : html`<strong>${displayAddress(h.to)}</strong>`;
  const labels = h.withheld ? html` labeled <code>${h.withheld.labels.join(", ")}</code>` : "";
  const why = h.reason === "review"
    ? html`Your rules hold it for your review. Nothing has been sent.`
    : h.reason === "dlp_justification"
      ? html`A data-loss check asked for your review before it leaves. Nothing has been sent.`
      : copyWent(h)
        ? html`${target ?? "That agent"} got it without the fields${labels}, which your organization's rules keep from it; the full message waits for you.`
        : html`Your organization's rules keep fields${labels} from ${target ?? "that agent"}, and without them it isn't a valid message. Nothing has been sent.`;
  const stale = heldStale(h, changed);
  return html`${writer} a <code>${h.scope}</code> ${h.type} to ${to}. ${why}${stale ? html` ${stale}` : ""}`;
}

/**
 * Why a message to the person waits for them (spec 6.7, 6.11), as it stood when it arrived: quiet hours, an agent
 * `to.delegate` names that couldn't receive it (the label is the sender's text, rendered as text; such an agent may
 * never have existed), or no agent of theirs meeting its delivery rules. The last two stay here for good.
 */
function inboundHeld(m: MessageRecord | null): Html {
  if (m?.held_until !== undefined) return html`arrived during your quiet hours; your agents see it after ${m.held_until}.`;
  const named = m?.held_reason === "to_delegate" ? m.envelope.to.delegate : undefined;
  if (named !== undefined) return html`was addressed to an agent of yours named <code>${labelOf(named)}</code> that wasn't connected or couldn't receive it when it arrived. It stays here and doesn't go to any of your agents.`;
  return html`is held for you: when it arrived, no agent of yours met its sender's delivery rules. It stays here and doesn't go to any of your agents.`;
}

/** How many of the newest ledger entries the ledger page lists. */
export const LEDGER_PAGE_ENTRIES = 1000;

export function webRouter(opts: WebOptions): Router {
  const { broker, state, identity } = opts;
  const pub = opts.public;
  const rp: RelyingParty | undefined = pub ? relyingParty(pub.origin, pub.rpName) : undefined;
  const router = express.Router();
  const sessions = new WebSessions({ secure: opts.secureCookies || pub !== undefined, store: state });
  const form = express.urlencoded({ extended: false, limit: "16kb" });
  const windows = opts.windows ?? new MemoryWindows();
  const limiter = new SignInLimiter({ name: "signin-web", windows });
  const passkeyLimiter = new SignInLimiter({ name: "passkey-web", windows, maxAll: Number.MAX_SAFE_INTEGER });
  const invites = identity instanceof InviteIdentityVerifier ? identity : undefined;

  // The web view answers only to its own host names: loopback ones, or on a public origin that origin's host (no DNS
  // rebinding through another name, no other deployment URL).
  const publicHost = pub ? new URL(pub.origin).host.toLowerCase() : undefined;
  router.use("/web", (req, res, next) => {
    const raw = (req.headers.host ?? "").toLowerCase();
    if (publicHost !== undefined) {
      if (raw !== publicHost) {
        res.status(421).type("text").send("This page answers only on the broker's own address.");
        return;
      }
      next();
      return;
    }
    const host = raw.replace(/:\d+$/, "");
    if (host !== "127.0.0.1" && host !== "localhost" && host !== "[::1]") {
      res.status(421).type("text").send("This page answers only on the loopback address.");
      return;
    }
    next();
  });

  router.get("/web/static/alp.css", (_req, res) => {
    res.type("text/css").setHeader("Cache-Control", "no-store");
    if (pub) res.setHeader("X-Content-Type-Options", "nosniff").setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.send(CSS);
  });
  if (pub) {
    router.get("/web/static/passkey.js", (_req, res) => {
      res.type("text/javascript").setHeader("Cache-Control", "no-store").setHeader("X-Content-Type-Options", "nosniff").setHeader("Cross-Origin-Resource-Policy", "same-origin");
      res.send(PASSKEY_JS);
    });
  }

  // Browsers apply `form-action` to the redirect after a form is posted, so with the organization's identity provider
  // the provider's origins (sign-in and sign-out) are allowed too: sign-in, step-ups and sign-out post here, then
  // redirect there. They come from the configuration, and from the provider's discovery document once it is fetched.
  const formTargets = new Set<string>();
  const noteProviderOrigins = async (): Promise<void> => {
    const oidcRp = opts.oidc?.signIn.rp;
    if (!oidcRp) return;
    formTargets.add(new URL(oidcRp.settings.discoveryUrl).origin);
    try {
      const d = await oidcRp.discovery();
      formTargets.add(new URL(d.authorization_endpoint).origin);
      if (d.end_session_endpoint) formTargets.add(new URL(d.end_session_endpoint).origin);
    } catch {
      // Not reachable yet; a sign-in attempt fetches it again.
    }
  };
  if (opts.idpMode === "oidc") void noteProviderOrigins();
  const formAction = (): string => `form-action 'self'${[...formTargets].map((o) => ` ${o}`).join("")}`;
  const publicHeaders = (): Record<string, string> =>
    pub && new URL(pub.origin).protocol === "https:" ? { ...PUBLIC_SECURITY_HEADERS, "Strict-Transport-Security": "max-age=63072000; includeSubDomains" } : PUBLIC_SECURITY_HEADERS;
  const page = (res: Response, title: string, body: Html, status = 200): void =>
    pub
      ? sendPage(res, title, body, { status, cssHref: "/web/static/alp.css", scriptHref: "/web/static/passkey.js", headers: publicHeaders() })
      : sendPage(res, title, body, { status, cssHref: "/web/static/alp.css", extraCsp: formAction() });

  const people = identity.listTestIdentities?.() ?? [];
  /** The dev sign-in's secret, as the pages name it. */
  const secretName = opts.secretKind === "personal" ? "your sign-in secret" : "the session secret";
  /** On an action form: the session secret again (loopback), or the slot the passkey script fills (public). */
  const stepUpField = (): Html =>
    pub
      ? html`<input type="hidden" name="credential" value=""><span class="muted" data-alp-status>Approving asks for your passkey.</span>`
      : opts.idpMode === "oidc"
        ? html``
        : opts.requireSecret
          ? html`<label>Confirm it's you: ${opts.secretKind === "personal" ? "your sign-in secret" : "session secret"} <input type="password" name="secret" autocomplete="off" required></label>`
          : html`<input type="hidden" name="secret" value="">`;
  /** Marks a form whose submit runs the passkey check first (public origin only). */
  const passkeyForm = (): Html => (pub ? new Html("data-alp-passkey") : new Html(""));

  const loginPage = (res: Response, error?: string, status?: number): void => {
    const body = pub
      ? html`
      <h1>${PROTOCOL.shortName}: your broker page</h1>
      <div class="warn"><strong>Invite-only evaluation broker.</strong> Don't use it for confidential or production data.</div>
      ${error ? html`<div class="warn bad">${error}</div>` : ""}
      <form method="post" action="/web/login" class="card">
        <label>Sign-in name<br><input type="text" name="username" autocomplete="username" maxlength="32" required></label>
        <label>Invitation secret<br><input type="password" name="secret" autocomplete="current-password" maxlength="128" required></label>
        <p class="muted">The secret starts your first sign-in. You'll then create a passkey, and every later sign-in and approval asks for it.</p>
        <button class="primary" type="submit">Sign in</button>
      </form>`
      : html`
      <h1>${PROTOCOL.shortName}: your broker page</h1>
      ${opts.idpMode === "dev" ? html`<div class="warn"><strong>Test identities only.</strong> A development broker with fictional people.</div>` : ""}
      ${error ? html`<div class="warn bad">${error}</div>` : ""}
      ${opts.idpMode === "dev"
        ? html`<form method="post" action="/web/login" class="card">
            ${people.map((p, i) => html`<label><input type="radio" name="username" value="${p.username}" ${i === 0 ? new Html("checked") : ""}> ${p.display_name ?? p.username} · <code>${displayAddress(p.address)}</code></label>`)}
            ${opts.requireSecret ? html`<label>${opts.secretKind === "personal" ? "Your sign-in secret" : "Session secret"}<br><input type="password" name="secret" autocomplete="off" required></label>` : ""}
            <button class="primary" type="submit">Sign in</button>
          </form>`
        : opts.oidc
          ? html`<form method="post" action="/web/login" class="card"><p>Sign in with your organization's account. Every approval asks you to sign in there again.</p><button class="primary" type="submit">Sign in</button></form>`
          : html`<div class="card"><p>This broker's organization sign-in isn't configured.</p></div>`}`;
    page(res, "Sign in", body, status ?? (error ? 401 : 200));
  };

  /** A refused OIDC sign-in or step-up: the reason for the person, the detail for the operator and the security events. */
  const oidcRefused = async (res: Response, err: unknown, s?: WebSession): Promise<void> => {
    const e = isOidcSignInError(err) ? err : new OidcSignInError("bad_response", err instanceof Error ? err.message : String(err));
    opts.log(`oidc: a web view sign-in was refused (${e.reason}: ${e.detail})`);
    if (e.reason !== "stale" && e.reason !== "rate_limited") await broker.recordSecurityEvent("token_refused", { failed: true, message: `web view sign-in refused: ${e.reason}`, ...(s ? { details: { principal_id: s.principal_id } } : {}) });
    if (s) {
      page(res, "Not confirmed", html`<h1>That didn't confirm it's you</h1><div class="card"><p>${e.personText} (Reason: ${e.reason}.)</p><p>Nothing was done. <a href="/web">Back to your page</a></p></div>`, e.reason === "idp_unavailable" ? 503 : 401);
      return;
    }
    loginPage(res, `${e.personText} (Reason: ${e.reason}.)`);
  };

  /**
   * The step-up's action: what was posted (no CSRF token or secret), and the hash of what it covers (`covers`: read
   * from the broker's state by the action's TermsOf, the same value a passkey approval signs; for a ratification it
   * holds the terms hash). A confirmed step-up answers for this key alone, so if the state changes in between, the
   * person is asked again.
   */
  const stepUpAction = (path: string, f: Form, covers: unknown): StepUpAction => {
    const fields: [string, string][] = [];
    for (const [k, v] of Object.entries(f)) {
      if (k === "csrf" || k === "secret") continue;
      for (const x of list(v)) fields.push([k, x.slice(0, 1024)]);
    }
    fields.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));
    const key = sha256b64(JSON.stringify({ path, fields, covers: hashJson(covers ?? null) }));
    return { path, fields, key };
  };

  const ACTION_LABELS: [RegExp, string][] = [
    [/\/connections\/[^/]+\/approve$/, "Approve the connection request"],
    [/\/connections\/[^/]+\/decline$/, "Decline the connection request"],
    [/\/ratifications\/[^/]+\/approve$/, "Approve these terms"],
    [/\/ratifications\/[^/]+\/decline$/, "Decline these terms"],
    [/\/held\/[^/]+\/send$/, "Send the held message"],
    [/\/held\/[^/]+\/discard$/, "Discard the held message"],
    [/\/delegates\/revoke$/, "Disconnect the agent"],
    [/\/tokens\/[^/]+\/revoke$/, "Revoke the personal access token"],
    [/\/tokens$/, "Create the personal access token"],
    [/\/grants\/revoke$/, "Revoke the relationship"],
    [/\/grants\/seal$/, "Seal the relationship"],
  ];

  /** Where a confirmed SSO step-up for one action of one session waits: single use, in the binding store. */
  const ssoStepUpId = (s: WebSession, key: string): string => `sso.${sha256b64(`${s.idHash}|${key}`)}`;

  /**
   * OIDC step-up for one action: a confirmed step-up for exactly this action is taken once (atomically, so two
   * submissions can't both use it); otherwise the person is sent to the provider for a fresh sign-in, and comes back
   * to a page that confirms the action.
   */
  const oidcStepUp = async (req: Request, res: Response, s: WebSession, f: Form, covers: unknown): Promise<HumanCaller | "redirected" | null> => {
    const o = opts.oidc;
    if (!o) return null;
    const action = stepUpAction(req.path, f, covers);
    const now = opts.now().getTime();
    const confirmed = await state.takeChallenge(s.idHash, ssoStepUpId(s, action.key), now);
    if (confirmed && confirmed.purpose === "sso-stepup" && confirmed.binding === action.key && typeof confirmed.auth_at === "number" && now - confirmed.auth_at <= STEP_UP_USE_MS) {
      return { kind: "human", principal: s.principal, principal_id: s.principal_id, auth: { method: "sso-stepup", at: new Date(confirmed.auth_at).toISOString() } };
    }
    if (!(await o.signIn.allowStart(`stepup|${s.principal_id}`, "web"))) return null;
    const browser = bindBrowser(req, res, { name: WEB_OIDC_COOKIE, path: "/web/oidc", secure: opts.secureCookies });
    const url = await o.signIn.begin({ purpose: "stepup", browser: sha256b64(browser), redirect_uri: o.callbackUri, fresh: true, session: s.idHash, action }, { prompt: "login", maxAge: 0, commitTo: action.key });
    await noteProviderOrigins();
    res.redirect(303, url);
    return "redirected";
  };

  /** The signed-in session, or the sign-in page (or, on a public origin, the passkey step that's still due). */
  const session = async (req: Request, res: Response): Promise<WebSession | undefined> => {
    const s = await sessions.current(req, opts.now().getTime());
    if (!s) {
      loginPage(res);
      return undefined;
    }
    if (s.stage !== "full") {
      res.redirect(303, "/web/passkey");
      return undefined;
    }
    return s;
  };

  /** Re-verify the person on an action form (loopback: the dev login again); the HumanCaller then carries a fresh step-up. */
  const stepUp = async (s: WebSession, f: Form): Promise<HumanCaller | null> => {
    const key = `web|${s.username}`;
    if (await limiter.blocked(key, Date.now())) return null;
    try {
      await identity.verify({ kind: "dev", username: s.username, secret: str(f["secret"]) });
    } catch {
      await limiter.fail(key, Date.now());
      return null;
    }
    const now = opts.now();
    s.authAt = now.getTime();
    await sessions.save(s);
    return { kind: "human", principal: s.principal, principal_id: s.principal_id, auth: { method: s.method, at: now.toISOString() } };
  };

  /** A passkey assertion for a challenge this session holds; true when it verifies (and counts a failure when not). */
  const passkeyOk = async (s: WebSession, credential: Record<string, unknown>, check: (c: { purpose: string; action?: string; binding?: string }) => boolean): Promise<boolean> => {
    if (!rp) return false;
    const key = s.principal_id;
    if (await passkeyLimiter.blocked(key, Date.now())) return false;
    const fail = async (): Promise<false> => {
      await passkeyLimiter.fail(key, Date.now());
      return false;
    };
    const challenge = challengeOf(credential);
    if (!challenge) return fail();
    const issued = await state.takeChallenge(s.idHash, challenge, opts.now().getTime());
    if (!issued || !check(issued)) return fail();
    const id = credential["id"];
    const pk = typeof id === "string" && id.length <= 1024 ? await state.getPasskey(id) : null;
    if (!pk || pk.principal_id !== s.principal_id) return fail();
    const v = await verifyAssertion(rp, credential, challenge, pk);
    if (!v || !(await state.usePasskey(pk.credential_id, v.counter, opts.now().toISOString()))) return fail();
    return true;
  };

  /** Public origin: refuse a POST another site started, and too many from one place. */
  const postGuard = async (req: Request, res: Response): Promise<boolean> => {
    if (!pub) return true;
    const origin = req.headers.origin;
    const site = req.headers["sec-fetch-site"];
    if ((origin !== undefined && origin !== new URL(pub.origin).origin) || (site !== undefined && site !== "same-origin")) {
      page(res, "Refused", html`<h1>Refused</h1><p>This form can only be sent from the broker's own page.</p>`, 403);
      return false;
    }
    const at = opts.now();
    if (!(await windows.hitRateLimit(`web-post|${sha256b64u(sourcePrefix(pub.sourceOf(req)))}`, at, 60, pub.postsPerMinute ?? 120)).allowed) {
      res.setHeader("Retry-After", "60");
      page(res, "Slow down", html`<h1>Too many requests</h1><p>Wait a minute and try again.</p>`, 429);
      return false;
    }
    return true;
  };

  // The HumanCaller carries the principal_id the person signed in as: if the address has since passed to someone
  // else, the broker refuses every call from this page (spec 5.2).
  const viewer = (s: WebSession): HumanCaller => ({ kind: "human", principal: s.principal, principal_id: s.principal_id, auth: { method: s.method, at: new Date(s.authAt).toISOString() } });

  const principalOf = async (s: WebSession): Promise<PrincipalRecord | null> => {
    const p = await broker.store.getPrincipalById(s.principal_id);
    return p && p.status === "active" ? p : null;
  };

  /**
   * Runs a POST action: session, CSRF, then the fresh sign-in (loopback: the session secret; public origin: a passkey
   * assertion over the hash of `terms`, which the page's script first asks for with `alp_webauthn=options`). Failures
   * re-render with a message.
   */
  const action = (terms: TermsOf, fn: (req: Request, res: Response, s: WebSession, who: HumanCaller, f: Form) => Promise<void>) => [
    form,
    (req: Request, res: Response, next: express.NextFunction) => {
      (async () => {
        if (!(await postGuard(req, res))) return;
        const s = await session(req, res);
        if (!s) return;
        // The account this page signed in as must still hold the address (spec 5.2).
        if (!(await principalOf(s))) {
          await sessions.end(req, res);
          loginPage(res, "Your account isn't active here.");
          return;
        }
        const f = (req.body ?? {}) as Form;
        if (!sessions.csrfOk(s, f["csrf"])) {
          page(res, "Error", html`<h1>The form is stale</h1><p><a href="/web">Back</a></p>`, 403);
          return;
        }
        let who: HumanCaller | null;
        if (pub && rp) {
          const binding = stepUpBinding({ origin: rp.origin, principal_id: s.principal_id, action: req.path, terms: await terms(req, s, f) });
          if (f["alp_webauthn"] === "options") {
            const challenge = newChallenge(binding);
            await state.putChallenge({ challenge, session_hash: s.idHash, purpose: "stepup", action: req.path, binding, expires_at: opts.now().getTime() + CHALLENGE_TTL_MS });
            res.setHeader("Cache-Control", "no-store");
            res.json({ kind: "get", publicKey: await authenticationOptions(rp, await state.listPasskeys(s.principal_id), challenge) });
            return;
          }
          const credential = parseCredential(f["credential"]);
          const ok = credential !== null && (await passkeyOk(s, credential, (c) => c.purpose === "stepup" && c.action === req.path && c.binding === binding));
          if (ok) {
            const now = opts.now();
            s.authAt = now.getTime();
            s.method = "webauthn-uv";
            await sessions.save(s);
            who = { kind: "human", principal: s.principal, principal_id: s.principal_id, auth: { method: "webauthn-uv", at: now.toISOString() } };
          } else {
            who = null;
          }
        } else if (opts.idpMode === "oidc") {
          let step: HumanCaller | "redirected" | null;
          try {
            step = await oidcStepUp(req, res, s, f, await terms(req, s, f));
          } catch (err) {
            await oidcRefused(res, err, s);
            return;
          }
          if (step === "redirected") return;
          who = step;
        } else {
          who = await stepUp(s, f);
        }
        if (!who) {
          if (!pub && opts.idpMode === "oidc") {
            page(res, "Confirm it's you", html`<h1>Not now</h1><div class="card"><p>Approvals need a fresh sign-in at your organization, and too many were started in the last few minutes. Wait a few minutes and try again.</p><p><a href="/web">Back to your page</a></p></div>`, 429);
            return;
          }
          page(res, "Confirm it's you", pub
            ? html`<h1>That didn't confirm it's you</h1><div class="card"><p>Approvals need a fresh passkey check for exactly what the page showed. If the page changed since you opened it, look again and approve again.</p><p><a href="/web">Back to your page</a></p></div>`
            : html`<h1>That didn't confirm it's you</h1><div class="card"><p>Approvals need a fresh sign-in. Go back and enter ${secretName} again.</p><p><a href="/web">Back to your page</a></p></div>`, 401);
          return;
        }
        try {
          await fn(req, res, s, who, f);
        } catch (err) {
          const msg = isAlpError(err) ? `${err.code}: ${err.message}` : "something went wrong";
          if (!isAlpError(err)) opts.log(`web: action failed: ${err instanceof Error ? err.message : String(err)}`);
          page(res, "Not done", html`<h1>Not done</h1><div class="card"><p>${msg}</p><p><a href="/web">Back to your page</a></p></div>`, 400);
        }
      })().catch(next);
    },
  ];

  const csrfField = (s: WebSession): Html => html`<input type="hidden" name="csrf" value="${s.csrf}">`;

  const header = (s: WebSession, p: PrincipalRecord): Html => html`
    <div class="row"><h1>${PROTOCOL.shortName}: ${p.display_name ?? displayAddress(p.address)}</h1></div>
    <nav class="row"><a href="/web">Your page</a><a href="/web/ledger">Ledger</a>
      <form method="post" action="/web/logout">${csrfField(s)}<button type="submit">Sign out</button></form></nav>
    ${pub ? html`<div class="warn">Invite-only evaluation broker: don't use it for confidential or production data.</div>` : opts.idpMode === "dev" ? html`<div class="warn">Development broker: test identities only.</div>` : ""}
    ${s.newDevice ? html`<div class="warn"><strong>New browser.</strong> This is the first sign-in to your broker page from this browser${p.contact?.email ? "; a notice went to your contact address" : ""}. If it wasn't you, tell the operator.</div>` : ""}`;

  // ---------------------------------------------------------------------------------------------
  // Sign-in

  router.get(["/web", "/web/"], (req, res, next) => {
    (async () => {
      const s = await session(req, res);
      if (!s) return;
      const p = await principalOf(s);
      if (!p) {
        await sessions.end(req, res);
        loginPage(res, "Your account isn't active here.");
        return;
      }
      await dashboard(res, s, p);
    })().catch(next);
  });

  router.post("/web/login", form, (req, res, next) => {
    (async () => {
      if (!(await postGuard(req, res))) return;
      if (opts.idpMode === "oidc") {
        const o = opts.oidc;
        if (!o) {
          loginPage(res, "This broker's organization sign-in isn't configured.");
          return;
        }
        // The provider returns to this view's registered origin; start there, so the binding cookie is on that origin.
        if ((req.headers.host ?? "").toLowerCase() !== new URL(o.origin).host) {
          res.redirect(303, `${o.origin}/web`);
          return;
        }
        if (!(await o.signIn.allowStart(`signin|${(req.socket.remoteAddress ?? "unknown").toLowerCase()}`, "web"))) {
          await oidcRefused(res, new OidcSignInError("rate_limited", "too many web view sign-ins started"));
          return;
        }
        const browser = bindBrowser(req, res, { name: WEB_OIDC_COOKIE, path: "/web/oidc", secure: opts.secureCookies });
        let url: string;
        try {
          url = await o.signIn.begin({ purpose: "web", browser: sha256b64(browser), redirect_uri: o.callbackUri, fresh: false });
        } catch (err) {
          await oidcRefused(res, err);
          return;
        }
        await noteProviderOrigins();
        res.redirect(303, url);
        return;
      }
      if (opts.idpMode !== "dev") {
        loginPage(res, "This broker's sign-in isn't configured.");
        return;
      }
      const f = (req.body ?? {}) as Form;
      const username = str(f["username"]).toLowerCase().slice(0, 64);
      const key = pub ? `${sourcePrefix(pub.sourceOf(req))}|${username}` : `web|${username}`;
      if (await limiter.blocked(key, Date.now())) {
        loginPage(res, "Too many failed sign-ins. Wait 15 minutes.", 429);
        return;
      }
      let verified;
      try {
        verified = await identity.verify({ kind: "dev", username: str(f["username"]), secret: str(f["secret"]) });
      } catch {
        const known = invites ? await invites.known(username) : people.some((x) => x.username.toLowerCase() === username);
        await limiter.fail(key, Date.now(), known);
        opts.log("web: a sign-in failed");
        loginPage(res, "Sign-in failed.");
        return;
      }
      const email = invites ? (await invites.liveInvite(username))?.email : undefined;
      const p = await broker.registerPrincipal({ address: verified.address, identity: { iss: verified.iss, sub: verified.sub }, ...(verified.display_name ? { display_name: verified.display_name } : {}), ...(email ? { contact: { email } } : {}) });
      const now = opts.now().getTime();
      if (pub) {
        // The secret only starts the sign-in: a passkey must be registered (first time) or confirmed (every time after).
        const stage = (await state.listPasskeys(p.principal_id)).length ? "passkey_check" : "passkey_setup";
        const deviceHash = sha256b64u(sessions.device(req, res));
        await sessions.start(res, { principal: p.address, principal_id: p.principal_id, username, stage, authAt: now, method: "webauthn-uv", deviceHash }, now);
        res.redirect(303, "/web/passkey");
        return;
      }
      await sessions.start(res, { principal: p.address, principal_id: p.principal_id, username, stage: "full", authAt: now, method: "reauth-dev" }, now);
      res.redirect(303, "/web");
    })().catch(next);
  });

  // The provider returns here after a web view sign-in or a step-up. The session cookie is SameSite=Strict, so the
  // browser doesn't send it on this cross-site redirect: the transaction (bound to the browser by its own Lax cookie)
  // names the session, and pages continue by a same-site step (a refresh, or the confirm form).
  router.get(WEB_CALLBACK_PATH, (req, res, next) => {
    (async () => {
      const o = opts.oidc;
      if (opts.idpMode !== "oidc" || !o) {
        res.status(404).type("text").send("Not found");
        return;
      }
      const q = req.query as Record<string, unknown>;
      let tx;
      try {
        tx = await o.signIn.take(q["state"], readCookie(req, WEB_OIDC_COOKIE), ["web", "stepup"]);
      } catch (err) {
        await oidcRefused(res, err);
        return;
      }
      const now = opts.now().getTime();
      const s = tx.purpose === "stepup" ? await sessions.findByHash(tx.session ?? "", now) : undefined;
      if (tx.purpose === "stepup" && (!s || !tx.action)) {
        loginPage(res, "Your session ended before you confirmed. Sign in again.");
        return;
      }
      let result;
      try {
        if (typeof q["error"] === "string") throw new OidcSignInError("idp_refused", `the provider answered ${q["error"].slice(0, 64)}`, q["error"].slice(0, 64));
        result = await o.signIn.finish(tx, { code: q["code"], iss: q["iss"] }, { requireAuthTime: tx.purpose === "stepup" });
      } catch (err) {
        await oidcRefused(res, err, s);
        return;
      }
      const id = result.identity;
      if (tx.purpose === "web") {
        const p = await broker.registerPrincipal({
          address: id.address,
          identity: { iss: id.iss, sub: id.sub },
          ...(id.display_name ? { display_name: id.display_name } : {}),
          claims: id.claims,
          contact: { email: displayAddress(id.address) },
        });
        await sessions.start(res, { principal: p.address, principal_id: p.principal_id, username: displayAddress(p.address), stage: "full", authAt: (id.auth_time ?? Math.floor(now / 1000)) * 1000, method: "sso-stepup", identity: { iss: id.iss, sub: id.sub } }, now);
        opts.log(`oidc: ${displayAddress(p.address)} signed in to the web view`);
        res.setHeader("Refresh", "0; url=/web");
        page(res, "Signed in", html`<h1>Signed in</h1><div class="card"><p>You're signed in as <strong>${displayAddress(p.address)}</strong>.</p><p><a href="/web">Continue to your page</a></p></div>`);
        return;
      }
      // A step-up: the provider must have signed in the same person again, for this action.
      const session = s as WebSession;
      const action = tx.action as StepUpAction;
      if (!session.identity || session.identity.iss !== id.iss || session.identity.sub !== id.sub) {
        await oidcRefused(res, new OidcSignInError("wrong_subject", "the step-up signed in another identity"), session);
        return;
      }
      const at = (id.auth_time ?? 0) * 1000;
      // The confirmed step-up waits, for this session and this action only, until the person confirms (single use).
      const stepUpId = ssoStepUpId(session, action.key);
      await state.takeChallenge(session.idHash, stepUpId, now);
      await state.putChallenge({ challenge: stepUpId, session_hash: session.idHash, purpose: "sso-stepup", action: action.path, binding: action.key, auth_at: at, expires_at: at + STEP_UP_USE_MS });
      session.authAt = at;
      session.method = "sso-stepup";
      await sessions.save(session);
      const label = ACTION_LABELS.find(([re]) => re.test(action.path))?.[1] ?? "Continue";
      page(res, "Confirm", html`<h1>${label}</h1>
        <div class="card"><p>Your organization confirmed it's you, <strong>${displayAddress(session.principal)}</strong>. Nothing has been done yet.</p>
        <form method="post" action="${action.path}">${csrfField(session)}${action.fields.map(([k, v]) => html`<input type="hidden" name="${k}" value="${v}">`)}<button class="primary" type="submit">${label}</button></form>
        <p><a href="/web">Cancel</a></p></div>`);
    })().catch(next);
  });

  router.post("/web/logout", form, (req, res, next) => {
    (async () => {
      if (!(await postGuard(req, res))) return;
      const s = await sessions.current(req, opts.now().getTime());
      // Signing out needs the page's CSRF token, so another site can't sign a person out.
      if (s && !sessions.csrfOk(s, ((req.body ?? {}) as Form)["csrf"])) {
        page(res, "Error", html`<h1>The form is stale</h1><p><a href="/web">Back</a></p>`, 403);
        return;
      }
      await sessions.end(req, res);
      // With the organization's identity provider, also end the provider's session (RP-initiated logout), when the
      // provider offers it (the form came from this page: the CSRF token was checked above).
      if (opts.idpMode === "oidc" && opts.oidc && s) {
        const url = await opts.oidc.signIn.rp.endSessionUrl(`${opts.oidc.origin}/web`);
        if (url) {
          res.redirect(303, url);
          return;
        }
      }
      res.redirect(303, "/web");
    })().catch(next);
  });

  // ---------------------------------------------------------------------------------------------
  // Passkeys (public origin): registered after the first sign-in, confirmed to finish every later one

  if (pub && rp) {
    const pending = async (req: Request, res: Response): Promise<WebSession | undefined> => {
      const s = await sessions.current(req, opts.now().getTime());
      if (!s) {
        loginPage(res);
        return undefined;
      }
      if (s.stage === "full") {
        res.redirect(303, "/web");
        return undefined;
      }
      return s;
    };

    router.get("/web/passkey", (req, res, next) => {
      (async () => {
        const s = await pending(req, res);
        if (!s) return;
        const setup = s.stage === "passkey_setup";
        const body = html`
          <h1>${PROTOCOL.shortName}: ${setup ? "create your passkey" : "confirm it's you"}</h1>
          <div class="card">
            <p>${setup
              ? "Your invitation got you this far. Create a passkey for this broker now (your device asks for your fingerprint, face or PIN). Every later sign-in and every approval asks for it; the invitation secret alone won't sign you in again."
              : "Confirm with your passkey to finish signing in."}</p>
            <form method="post" action="/web/passkey" data-alp-passkey>
              <input type="hidden" name="csrf" value="${s.csrf}">
              <input type="hidden" name="credential" value="">
              <button class="primary" type="submit">${setup ? "Create a passkey" : "Use my passkey"}</button>
              <span class="muted" data-alp-status></span>
            </form>
          </div>
          <form method="post" action="/web/logout"><input type="hidden" name="csrf" value="${s.csrf}"><button type="submit">Cancel and sign out</button></form>`;
        page(res, setup ? "Create a passkey" : "Confirm it's you", body);
      })().catch(next);
    });

    router.post("/web/passkey", form, (req, res, next) => {
      (async () => {
        if (!(await postGuard(req, res))) return;
        const s = await pending(req, res);
        if (!s) return;
        const f = (req.body ?? {}) as Form;
        if (!sessions.csrfOk(s, f["csrf"])) {
          page(res, "Error", html`<h1>The form is stale</h1><p><a href="/web">Back</a></p>`, 403);
          return;
        }
        const p = await principalOf(s);
        if (!p) {
          await sessions.end(req, res);
          loginPage(res, "Your account isn't active here.");
          return;
        }
        const setup = s.stage === "passkey_setup";
        const purpose = setup ? "register" : "signin";
        if (f["alp_webauthn"] === "options") {
          const challenge = newChallenge();
          await state.putChallenge({ challenge, session_hash: s.idHash, purpose, expires_at: opts.now().getTime() + CHALLENGE_TTL_MS });
          const mine = await state.listPasskeys(s.principal_id);
          res.setHeader("Cache-Control", "no-store");
          res.json(setup
            ? { kind: "create", publicKey: await registrationOptions(rp, { principal_id: s.principal_id, name: displayAddress(p.address), display: p.display_name ?? displayAddress(p.address) }, mine, challenge) }
            : { kind: "get", publicKey: await authenticationOptions(rp, mine, challenge) });
          return;
        }
        const credential = parseCredential(f["credential"]);
        let ok = false;
        if (credential && setup) {
          const challenge = challengeOf(credential);
          const issued = challenge && !(await passkeyLimiter.blocked(s.principal_id, Date.now())) ? await state.takeChallenge(s.idHash, challenge, opts.now().getTime()) : null;
          const rec = issued && issued.purpose === "register" && challenge ? await verifyRegistration(rp, credential, challenge, s.principal_id, opts.now().toISOString()) : null;
          // The first registration wins: a second session that also got this far with the invite secret (a secret
          // that leaked before its first use) can't add its own passkey next to the person's, even at the same moment.
          if (rec && (await state.addFirstPasskey(rec))) {
            ok = true;
          } else {
            await passkeyLimiter.fail(s.principal_id, Date.now());
          }
        } else if (credential) {
          ok = await passkeyOk(s, credential, (c) => c.purpose === "signin");
        }
        if (!ok) {
          opts.log(`web: a passkey ${setup ? "registration" : "sign-in"} failed`);
          page(res, "Not done", html`<h1>The passkey check didn't work</h1><div class="card"><p>Try again from <a href="/web/passkey">the passkey page</a>.</p></div>`, 401);
          return;
        }
        // Signed in: a new session id, and the notice if this browser is new for this person.
        const now = opts.now();
        const deviceHash = s.deviceHash ?? sha256b64u(sessions.device(req, res));
        const isNew = await state.noteDevice(s.principal_id, deviceHash, now.toISOString());
        await sessions.rotate(res, s, now.getTime(), { stage: "full", authAt: now.getTime(), method: "webauthn-uv", deviceHash, ...(isNew ? { newDevice: true } : {}) });
        opts.log(`web: ${displayAddress(p.address)} signed in with a passkey${setup ? " (registered now)" : ""}${isNew ? " from a new browser" : ""}`);
        if (isNew && p.contact?.email) {
          try {
            await pub.notifier.notify({
              principal: p.address,
              kind: "new_device",
              channel: "email",
              to: p.contact.email,
              subject: "A new browser signed in to your broker page",
              text: `Someone signed in to your ${PROTOCOL.shortName} broker page from a browser that hadn't been used for your account before, at ${now.toISOString()} (UTC). If it was you, there's nothing to do. If it wasn't, tell the broker's operator. This message can't approve or change anything.`,
              link: `${rp.origin}/web`,
              at: now.toISOString(),
            });
          } catch {
            // the page shows the notice either way
          }
        }
        res.redirect(303, "/web");
      })().catch(next);
    });
  }

  // ---------------------------------------------------------------------------------------------
  // The person's page

  const dashboard = async (res: Response, s: WebSession, p: PrincipalRecord): Promise<void> => {
    const me = viewer(s);
    const now = opts.now();
    const agentRequests = (await pendingFor(state, p.principal_id, now)).filter((x) => x.state === "pending_principal");
    const connections = await broker.listConnections(me);
    const incoming = connections.filter((c) => c.direction === "incoming" && c.state === "pending");
    const ratifications = (await broker.listRatifications(me)).filter((r) => r.state === "pending");
    const inbox = await broker.messagesForPerson(me, { limit: 50, include_acked: true });
    const held = await Promise.all(inbox.items.filter((m) => m.status === "held").map(async (m) => ({ m, rec: await broker.store.getMessage(p.address, "in", m.envelope.id) })));
    const mineHeld = await Promise.all((await broker.listHeld(me)).filter((h) => h.state === "pending").map(async (h) => ({ h, changed: await broker.heldBindingChanged(h) })));
    // Only this person's agents: an earlier holder of the address had their own (spec 5.2).
    const delegates = (await broker.store.listDelegates(p.address)).filter((d) => d.principal_id === p.principal_id);
    const grants = await broker.listGrants(me);
    const pats = await patsOf(state, p.principal_id);
    const patsOff = broker.clientRefused(p.address, PAT_CLIENT_ID);
    const passkeys = pub ? await state.listPasskeys(p.principal_id) : [];

    const body = html`
      ${header(s, p)}
      <h2>Needs you</h2>
      ${agentRequests.length + incoming.length + ratifications.length + held.length + mineHeld.length === 0 ? html`<p class="muted">Nothing waiting.</p>` : ""}
      ${mineHeld.map(({ h, changed }) => html`<div class="card">${heldSummary(h, p, changed)} <a href="/web/held/${h.id}">Review</a></div>`)}
      ${agentRequests.map((r) => html`<div class="card">Your agent <code>${r.delegate.slice(r.delegate.lastIndexOf("/") + 1)}</code> asked to connect with <strong>${displayAddress(r.to)}</strong> for ${r.scopes.join(", ")}. Nothing has been sent. <a href="/web/connections/${r.id}">Review</a></div>`)}
      ${incoming.map((c) => html`<div class="card"><strong>${displayAddress(c.counterparty)}</strong> asks to connect for ${c.scopes.join(", ")}${c.origin === "stranger_message" ? " (they sent a message without a relationship; it was not delivered)" : ""}. <a href="/web/connections/${c.id}">Review</a></div>`)}
      ${ratifications.map((r) => html`<div class="card">Agreed terms with <strong>${displayAddress(r.counterparty)}</strong> (${r.scope}) need your approval. <a href="/web/ratifications/${r.id}">Review</a></div>`)}
      ${held.map(({ m, rec }) => html`<div class="card">A message from <strong>${m.verified.sender.display}</strong> (${m.verified.scope} ${m.verified.type}) ${inboundHeld(rec)} <a href="/web/messages/${m.envelope.id}">Read</a></div>`)}

      <h2>Messages to you</h2>
      ${inbox.items.length === 0 ? html`<p class="muted">None yet.</p>` : html`<table><tr><th>Received</th><th>From (verified)</th><th>Scope</th><th>Type</th><th>Status</th><th></th></tr>
        ${inbox.items.slice(-20).reverse().map((m) => html`<tr><td>${m.received_at}</td><td>${m.verified.sender.display}</td><td>${m.verified.scope}</td><td>${m.verified.type}</td><td>${m.status}</td><td><a href="/web/messages/${m.envelope.id}">Read</a></td></tr>`)}</table>`}

      <h2>Your agents</h2>
      ${delegates.length === 0 ? html`<p class="muted">No agent is connected. Add this broker as a custom connector in your agent, or create a personal access token below.</p>` : html`<table><tr><th>Agent</th><th>Client</th><th>Attestation</th><th>Class</th><th>Status</th><th></th></tr>
        ${delegates.map((d) => html`<tr><td><code>${d.label}</code></td><td>${d.client_id === PAT_CLIENT_ID ? "personal access token" : d.client_id}</td><td>${d.attestation}</td><td>${d.class}</td><td>${d.status}</td><td>${d.status === "active" ? html`<form method="post" action="/web/delegates/revoke" ${passkeyForm()}>${csrfField(s)}<input type="hidden" name="delegate" value="${d.id}">${stepUpField()}<button type="submit">Disconnect</button></form>` : ""}</td></tr>`)}</table>`}

      <h2>Your relationships</h2>
      <p class="muted">Organization defaults also apply (your organization's policy). Grants here are yours: they can narrow what your organization allows, never widen it.</p>
      ${grants.length === 0 ? html`<p class="muted">No individual grants.</p>` : html`<table><tr><th>With</th><th>Basis</th><th>Status</th><th>Scopes</th><th></th></tr>
        ${grants.map((g) => html`<tr><td>${displayAddress(g.counterparty)}</td><td>${g.basis}</td><td>${g.status}</td><td>${Object.keys(g.scopes).join(", ")}</td><td>
          ${g.status === "pending" ? html`<form method="post" action="/web/grants/seal" ${passkeyForm()}>${csrfField(s)}<input type="hidden" name="counterparty" value="${g.counterparty}">${stepUpField()}<button type="submit">Seal</button></form>` : ""}
          ${g.status !== "revoked" ? html`<form method="post" action="/web/grants/revoke" ${passkeyForm()}>${csrfField(s)}<input type="hidden" name="counterparty" value="${g.counterparty}">${stepUpField()}<button type="submit">Revoke</button></form>` : ""}</td></tr>`)}</table>`}

      <h2>Personal access tokens</h2>
      <p class="muted">${patsOff ? "Your organization's list of agents doesn't allow personal access tokens." : "For agents that can only send a fixed header (an API key setting, or an agent that writes its own connector). A token acts as one agent of yours. It is shown once."}</p>
      ${pats.length ? html`<table><tr><th>Agent</th><th>Scopes</th><th>Created</th><th>Expires</th><th>Last used</th><th></th></tr>
        ${pats.map((t) => html`<tr><td><code>${t.label}</code></td><td>${t.scopes.join(" ")}</td><td>${t.created_at}</td><td>${t.expires_at}</td><td>${t.last_used_at ?? "never"}</td><td>${t.revoked_at ? "revoked" : html`<form method="post" action="/web/tokens/${t.id}/revoke" ${passkeyForm()}>${csrfField(s)}${stepUpField()}<button type="submit">Revoke</button></form>`}</td></tr>`)}</table>` : ""}
      ${patsOff ? "" : html`<form method="post" action="/web/tokens" class="card" ${passkeyForm()}>
        ${csrfField(s)}
        <label>Agent name (lower case, digits, - and _) <input type="text" name="label" maxlength="32" required></label>
        <p class="muted">The name of an agent you disconnected starts a new agent, which doesn't see what was addressed to, or sent by, the earlier one. The name of an agent that has a token adds a second token for it.</p>
        <label><input type="checkbox" name="scopes" value="read" checked> read (whoami, contacts, inbox, thread)</label>
        <label><input type="checkbox" name="scopes" value="send" checked> send (send, mark handled, ask to connect)</label>
        <label>Days until it expires (at most ${opts.isOrganizationDomain(domainOf(p.address)) ? opts.patMaxDays.organization : opts.patMaxDays.other}) <input type="number" name="days" min="1" value="7"></label>
        ${stepUpField()}
        <button class="primary" type="submit">Create token</button>
      </form>`}
      ${pub
        ? html`<h2>Your passkeys</h2>
      <p class="muted">Sign-in and every approval here ask for one of these. If you don't recognize one, tell the operator.</p>
      <table><tr><th>Created</th><th>Last used</th><th>Kind</th></tr>
        ${passkeys.map((k) => html`<tr><td>${k.created_at}</td><td>${k.last_used_at ?? "never"}</td><td>${k.device_type === "multiDevice" ? "synced" : "this device only"}</td></tr>`)}</table>`
        : ""}`;
    page(res, "Your page", body);
  };

  // ---------------------------------------------------------------------------------------------
  // Connection requests: incoming ones (the core's), and ones the person's agent filed (held here)

  // The default terms include `commit` in scopes that end in a commitment (spec 9.4): say plainly what it takes.
  const commitLine = (scopeIds: readonly string[], other: string): Html | "" => {
    const committing = scopeIds.filter((sid) => broker.scopes.get(sid)?.types.has("commit"));
    return committing.length ? html`<p>Commit (${committing.join(", ")}): an agent can send one only after you and ${other} have each approved the agreed terms on your own broker pages.</p>` : "";
  };

  router.get("/web/connections/:id", (req, res, next) => {
    (async () => {
      const s = await session(req, res);
      if (!s) return;
      const p = await principalOf(s);
      if (!p) return loginPage(res);
      const id = String(req.params["id"]);
      const mine = await getPending(state, p.principal_id, id);
      if (mine) {
        const scopeTerms = mine.scopes.map((sid) => {
          const sc = broker.scopes.get(sid);
          return sc ? { sid, terms: defaultScopeTerms(sc) } : null;
        });
        const body = html`${header(s, p)}
          <h2>Your agent asked to connect</h2>
          <div class="card">
            <p>Agent <code>${mine.delegate.slice(mine.delegate.lastIndexOf("/") + 1)}</code> asked to connect with <strong>${displayAddress(mine.to)}</strong>. Purpose: ${mine.purpose}. State: ${mine.state}${mine.result ? html` (${mine.result.status}${mine.result.code ? `: ${mine.result.code}` : ""})` : ""}.</p>
            ${mine.note ? html`<p>Its note (it goes to ${displayAddress(mine.to)} as unverified text): <pre>${mine.note}</pre></p>` : ""}
            <p>If you approve, the request goes to ${displayAddress(mine.to)} (the person, not their agent). Your own terms for each scope are sealed now and apply when they accept:</p>
            ${scopeTerms.map((x) => (x ? html`<p><code>${x.sid}</code>: your agent may send ${x.terms.may.join(", ")}; fields it may share: ${x.terms.disclose.join(" ") || "none"}; fields you accept: ${x.terms.receive.join(" ") || "none"}; commitments: ask me.</p>` : ""))}
            ${commitLine(mine.scopes, displayAddress(mine.to))}
          </div>
          ${mine.state === "pending_principal"
            ? html`<form method="post" action="/web/connections/${mine.id}/approve" class="card" ${passkeyForm()}>${csrfField(s)}
                ${mine.scopes.map((sid) => html`<label><input type="checkbox" name="scopes" value="${sid}" checked> ${sid}</label>`)}
                ${stepUpField()}<button class="primary" type="submit">Approve and send</button></form>
              <form method="post" action="/web/connections/${mine.id}/decline" class="card" ${passkeyForm()}>${csrfField(s)}${stepUpField()}<button type="submit">Discard</button></form>`
            : ""}`;
        page(res, "Connection request", body);
        return;
      }
      const c = (await broker.listConnections(viewer(s))).find((x) => x.id === id);
      if (!c) {
        page(res, "Not found", html`${header(s, p)}<p>No such request.</p>`, 404);
        return;
      }
      const body = html`${header(s, p)}
        <h2>${c.direction === "incoming" ? "A connection request" : "Your connection request"}</h2>
        <div class="card">
          <p>${c.direction === "incoming" ? "From" : "To"} <strong>${displayAddress(c.counterparty)}</strong> <span class="pill">address verified by their home broker</span></p>
          ${c.display_name ? html`<p>Name they give (unverified): ${c.display_name}</p>` : ""}
          <p>Scopes: ${c.scopes.join(", ")}. Purpose: ${c.purpose}. State: ${c.state}.</p>
          ${c.origin === "stranger_message" ? html`<p class="muted">This came from a message sent to you without a relationship. The message itself was not delivered to your agent.</p>` : ""}
          ${c.note ? html`<p>Their note (unverified text): <pre>${sanitizeFreeText(c.note)}</pre></p>` : ""}
          ${c.direction === "incoming" ? html`<p>If you approve, their agent may send you the scopes you tick, and your own terms (each scope's suggested fields) are sealed now.</p>${commitLine(c.scopes, displayAddress(c.counterparty))}` : ""}
        </div>
        ${c.direction === "incoming" && c.state === "pending"
          ? html`<form method="post" action="/web/connections/${c.id}/approve" class="card" ${passkeyForm()}>${csrfField(s)}
              ${c.scopes.map((sid) => html`<label><input type="checkbox" name="scopes" value="${sid}" checked> ${sid}</label>`)}
              ${stepUpField()}<button class="primary" type="submit">Approve</button></form>
            <form method="post" action="/web/connections/${c.id}/decline" class="card" ${passkeyForm()}>${csrfField(s)}${stepUpField()}<button type="submit">Decline</button></form>`
          : ""}`;
      page(res, "Connection request", body);
    })().catch(next);
  });

  // What approving or declining a connection request covers: the request, the scopes ticked, and for a request the
  // person's agent filed, the person's own terms per scope (each scope's suggested fields).
  const connectionTerms = (decision: "approve" | "decline"): TermsOf => async (req, s, f) => {
    const id = String(req.params["id"]);
    const chosen = list(f["scopes"]).sort();
    const mine = await getPending(state, s.principal_id, id);
    if (mine) {
      const scopes = decision === "approve" ? mine.scopes.filter((x) => chosen.includes(x)).sort() : [];
      return { kind: "agent_request", decision, id, to: mine.to, purpose: mine.purpose, note: mine.note ?? null, state: mine.state, scopes, terms: scopes.map((sid) => { const sc = broker.scopes.get(sid); return sc ? defaultScopeTerms(sc) : null; }) };
    }
    const c = (await broker.listConnections(viewer(s))).find((x) => x.id === id);
    return { kind: "connection_request", decision, id, counterparty: c?.counterparty ?? null, purpose: c?.purpose ?? null, state: c?.state ?? null, scopes: decision === "approve" ? chosen : [] };
  };

  router.post("/web/connections/:id/approve", ...action(connectionTerms("approve"), async (req, res, s, who, f) => {
    const id = String(req.params["id"]);
    const mine = await getPending(state, s.principal_id, id);
    const chosen = list(f["scopes"]);
    if (mine) {
      if (mine.state !== "pending_principal") throw new Error("this request was already handled");
      const scopes = mine.scopes.filter((x) => chosen.includes(x));
      if (!scopes.length) {
        page(res, "Not done", html`<h1>Choose at least one scope</h1><p><a href="/web/connections/${id}">Back</a></p>`, 400);
        return;
      }
      const r = await broker.requestConnection(who, { to: mine.to, scopes, purpose: mine.purpose as ConnectionPurpose, ...(mine.note ? { note: mine.note } : {}) });
      const now = opts.now();
      if (r.status === "requested" || r.status === "already_pending") await settlePending(state, id, "sent", { status: r.status, request: r.request.id }, now);
      else await settlePending(state, id, "failed", { status: r.status, code: r.code }, now);
      res.redirect(303, `/web/connections/${id}`);
      return;
    }
    await broker.respondToConnection(who, { request: id, decision: "approve", ...(chosen.length ? { scopes: chosen } : {}) });
    res.redirect(303, `/web/connections/${id}`);
  }));

  router.post("/web/connections/:id/decline", ...action(connectionTerms("decline"), async (req, res, s, who) => {
    const id = String(req.params["id"]);
    const mine = await getPending(state, s.principal_id, id);
    if (mine) {
      if (mine.state === "pending_principal") await settlePending(state, id, "discarded", undefined, opts.now());
      res.redirect(303, `/web/connections/${id}`);
      return;
    }
    await broker.respondToConnection(who, { request: id, decision: "decline" });
    res.redirect(303, `/web/connections/${id}`);
  }));

  // ---------------------------------------------------------------------------------------------
  // Ratification

  router.get("/web/ratifications/:id", (req, res, next) => {
    (async () => {
      const s = await session(req, res);
      if (!s) return;
      const p = await principalOf(s);
      if (!p) return loginPage(res);
      const r = (await broker.listRatifications(viewer(s))).find((x) => x.id === String(req.params["id"]));
      if (!r) {
        page(res, "Not found", html`${header(s, p)}<p>No such request.</p>`, 404);
        return;
      }
      const body = html`${header(s, p)}
        <h2>Approve agreed terms</h2>
        <div class="card">
          <p>With <strong>${displayAddress(r.counterparty)}</strong>, scope <code>${r.scope}</code>, thread <code>${r.thread}</code>. State: ${r.state}.</p>
          <p>The terms (from your broker's records; terms hash <code>${r.terms_hash}</code>):</p>
          <pre>${JSON.stringify(r.terms, null, 2)}</pre>
          <p class="muted">Approving signs a ratification record for you. A commit needs both people's records; any change to the terms voids them.</p>
        </div>
        ${r.state === "pending"
          ? html`<form method="post" action="/web/ratifications/${r.id}/approve" class="card" ${passkeyForm()}>${csrfField(s)}${stepUpField()}<button class="primary" type="submit">Approve these terms</button></form>
            <form method="post" action="/web/ratifications/${r.id}/decline" class="card" ${passkeyForm()}>${csrfField(s)}${stepUpField()}<button type="submit">Decline</button></form>`
          : ""}`;
      page(res, "Ratification", body);
    })().catch(next);
  });

  // Ratifying covers the agreed terms by their hash (spec 9.4): the passkey signs over it.
  const ratificationTerms = (decision: "approve" | "decline"): TermsOf => async (req, s) => {
    const r = (await broker.listRatifications(viewer(s))).find((x) => x.id === String(req.params["id"]));
    return { kind: "ratification", decision, id: String(req.params["id"]), terms_hash: r?.terms_hash ?? null, counterparty: r?.counterparty ?? null, scope: r?.scope ?? null, thread: r?.thread ?? null, state: r?.state ?? null };
  };

  for (const decision of ["approve", "decline"] as const) {
    router.post(`/web/ratifications/:id/${decision}`, ...action(ratificationTerms(decision), async (req, res, _s, who) => {
      const id = String(req.params["id"]);
      await broker.ratify(who, { request: id, decision });
      res.redirect(303, `/web/ratifications/${id}`);
    }));
  }

  // ---------------------------------------------------------------------------------------------
  // Outbound messages held for the person's review (spec 6.12)

  router.get("/web/held/:id", (req, res, next) => {
    (async () => {
      const s = await session(req, res);
      if (!s) return;
      const p = await principalOf(s);
      if (!p) return loginPage(res);
      const h = (await broker.listHeld(viewer(s))).find((x) => x.id === String(req.params["id"]));
      if (!h) {
        page(res, "Not found", html`${header(s, p)}<p>No such message.</p>`, 404);
        return;
      }
      // Spec 5.4: a message goes only as the agent that wrote it, and (between the person's own agents) only to the
      // agent it was written for; if either was disconnected since, it can only be discarded.
      const changed = h.state === "pending" ? await broker.heldBindingChanged(h) : null;
      const stale = heldStale(h, changed);
      // A reply or follow-up goes only while its thread is open (spec 9.2): by when to decide, if before the message expires.
      const ends = h.state === "pending" && !h.opens_thread ? await broker.threadDeadline(p, h.thread) : undefined;
      const decideBy = ends !== undefined && Date.parse(ends) < Date.parse(h.expires_at) ? ends : undefined;
      const body = html`${header(s, p)}
        <h2>A message waiting for your review</h2>
        <div class="card">
          <p>To ${h.to === p.address && h.to_delegate ? html`your own agent <strong>${labelOf(h.to_delegate)}</strong>` : html`<strong>${displayAddress(h.to)}</strong>`}, scope <code>${h.scope}</code>, type <code>${h.type}</code>${h.delegate ? html`, written by your agent <code>${labelOf(h.delegate)}</code>` : ""}. ${heldState(h)}</p>
          ${stale ? html`<div class="warn">${stale}</div>` : ""}
          ${decideBy && !stale ? html`<p>Decide before <strong>${decideBy}</strong>: its thread expires then, unless a later message in it extends it.</p>` : ""}
          <p class="muted">${h.reason === "review"
            ? "Your rules ask you to review messages in this scope before they leave."
            : h.reason === "delivery_minimums"
              ? html`Your organization's rules keep fields${h.withheld ? html` labeled <code>${h.withheld.labels.join(", ")}</code>` : ""} from that agent unless you approve${copyWent(h) && h.withheld ? html`: it already received this message without <code>${h.withheld.pointers.join(", ")}</code>${h.partial_envelope_id ? html` (message <code>${h.partial_envelope_id}</code>)` : ""}` : ": without them what is left isn't a valid message, so it was held whole"}. Sending it gives that agent the full message.`
              : "A data-loss check asked for your review before it leaves."} If you send it, the broker checks it again in full first.</p>
        </div>
        <div class="card"><p><strong>Content</strong> (your agent's draft):</p><pre>${JSON.stringify(h.body, null, 2)}</pre>${h.note !== undefined ? html`<p>Note:</p><pre>${h.note}</pre>` : ""}</div>
        ${h.state === "pending" && !stale
          ? html`<form method="post" action="/web/held/${h.id}/send" class="card" ${passkeyForm()}>${csrfField(s)}${stepUpField()}<button class="primary" type="submit">Send it</button></form>`
          : ""}
        ${h.state === "pending"
          ? html`<form method="post" action="/web/held/${h.id}/discard" class="card" ${passkeyForm()}>${csrfField(s)}${stepUpField()}<button type="submit">Discard</button></form>`
          : ""}`;
      page(res, "Held message", body);
    })().catch(next);
  });

  // Sending a held message covers exactly the draft the page showed.
  const heldTerms = (decision: "send" | "discard"): TermsOf => async (req, s) => {
    const h = (await broker.listHeld(viewer(s))).find((x) => x.id === String(req.params["id"]));
    return { kind: "held", decision, id: String(req.params["id"]), to: h?.to ?? null, to_delegate: h?.to_delegate ?? null, scope: h?.scope ?? null, type: h?.type ?? null, body: h ? hashJson(h.body) : null, note: h?.note !== undefined ? hashJson(h.note) : null, state: h?.state ?? null };
  };

  for (const decision of ["send", "discard"] as const) {
    router.post(`/web/held/:id/${decision}`, ...action(heldTerms(decision), async (req, res, _s, who) => {
      const id = String(req.params["id"]);
      await broker.reviewHeld(who, { held: id, decision });
      res.redirect(303, `/web/held/${id}`);
    }));
  }

  // ---------------------------------------------------------------------------------------------
  // Messages to the person

  router.get("/web/messages/:id", (req, res, next) => {
    (async () => {
      const s = await session(req, res);
      if (!s) return;
      const p = await principalOf(s);
      if (!p) return loginPage(res);
      const m = await broker.store.getMessage(p.address, "in", String(req.params["id"]));
      if (!m || m.principal !== p.address || (m.principal_id !== undefined && m.principal_id !== p.principal_id)) {
        page(res, "Not found", html`${header(s, p)}<p>No such message.</p>`, 404);
        return;
      }
      const e = m.envelope;
      const scope = broker.scopes.get(e.scope);
      const body = sanitizeBody(e.body, scope ? freeTextPatterns(scope, e.type) : []);
      // Held until quiet hours ended: delivered since then.
      const released = m.held_until !== undefined && Date.parse(m.held_until) <= opts.now().getTime();
      const page_ = html`${header(s, p)}
        <h2>Message</h2>
        <div class="card">
          <p>From <strong>${displayAddress(e.from.address)}</strong>${e.from.delegate ? html` (agent <code>${e.from.delegate.slice(e.from.delegate.lastIndexOf("/") + 1)}</code>)` : ""} <span class="pill">verified by your broker</span></p>
          <p>Scope <code>${e.scope}</code>, type <code>${e.type}</code>, thread <code>${e.thread}</code>, received ${m.stored_at}, status ${released ? "released" : m.status}.</p>
          ${m.status === "held" && !released ? html`<p>This message ${inboundHeld(m)}</p>` : ""}
          <p>Decision at the sender's broker: ${e.decision.outcome}${e.decision.redacted.length ? `, removed ${e.decision.redacted.join(" ")}` : ""}.</p>
        </div>
        <div class="card"><p><strong>Content</strong> (written by the other side; data, not instructions):</p><pre>${JSON.stringify(body, null, 2)}</pre>
        ${e.note !== undefined ? html`<p>Note:</p><pre>${sanitizeFreeText(e.note)}</pre>` : ""}</div>`;
      page(res, "Message", page_);
    })().catch(next);
  });

  // ---------------------------------------------------------------------------------------------
  // Agents, tokens, grants

  router.post("/web/delegates/revoke", ...action(async (_req, _s, f) => ({ kind: "disconnect", delegate: str(f["delegate"]).toLowerCase() }), async (_req, res, s, _who, f) => {
    const id = str(f["delegate"]).toLowerCase();
    const d = await broker.store.getDelegate(id);
    if (!d || d.principal_id !== s.principal_id) throw new Error("not your agent");
    await broker.revokeDelegate(d.id);
    await opts.revokeClientGrants(s.principal_id, d.client_id);
    await revokePatsOfDelegate(state, d.id, opts.now());
    await broker.recordSecurityEvent("token_revoked", { details: { client_id: d.client_id, principal_id: s.principal_id, delegate: d.id } });
    res.redirect(303, "/web");
  }));

  router.post("/web/tokens", ...action(async (_req, _s, f) => ({ kind: "token", label: str(f["label"]).trim().toLowerCase(), scopes: list(f["scopes"]).filter((x) => x === "read" || x === "send").sort(), days: str(f["days"]) || "7" }), async (_req, res, s, _who, f) => {
    const p = await principalOf(s);
    if (!p) throw new Error("account not active");
    // Spec 5.7, 6.10: an organization forbids personal access tokens by leaving `pat` off its list of agents.
    if (broker.clientRefused(p.address, PAT_CLIENT_ID)) {
      await broker.recordSecurityEvent("client_refused", { failed: true, details: { client_id: PAT_CLIENT_ID, principal_id: p.principal_id } });
      page(res, "Not done", html`${header(s, p)}<h2>Personal access tokens are off</h2><div class="card"><p>Your organization's list of agents doesn't allow personal access tokens.</p><p><a href="/web">Back to your page</a></p></div>`, 403);
      return;
    }
    const label = str(f["label"]).trim().toLowerCase();
    if (!isDelegateLabel(label) || ["broker", "admin", "web"].includes(label)) throw new Error("choose a name of lower-case letters, digits, - or _");
    const existing = await broker.store.getDelegate(delegateIdOf(p.address, label));
    if (existing && existing.status === "active" && existing.client_id !== PAT_CLIENT_ID) throw new Error(`the name ${label} is already used by a connected agent`);
    const scopes = list(f["scopes"]).filter((x): x is "read" | "send" => x === "read" || x === "send");
    const maxDays = opts.isOrganizationDomain(domainOf(p.address)) ? opts.patMaxDays.organization : opts.patMaxDays.other;
    const now = opts.now();
    // Spec 5.4, 5.7: the name of an agent the person disconnected starts a new agent; a token for an agent that already
    // has one is a second token, and the first keeps working until it is revoked.
    const restarted = existing !== null && existing.principal_id === p.principal_id && existing.status === "revoked";
    const live = existing?.status === "active" ? (await patsOf(state, p.principal_id)).filter((x) => x.delegate === existing.id && !x.revoked_at && Date.parse(x.expires_at) > now.getTime()).length : 0;
    const { token, record } = await mintPat({ broker, state, principal: p, label, scopes, days: Number(str(f["days"]) || "7"), maxDays, now });
    await broker.recordSecurityEvent("token_issued", { details: { client_id: PAT_CLIENT_ID, principal_id: p.principal_id, delegate: record.delegate } });
    page(res, "Token created", html`${header(s, p)}<h2>Personal access token for <code>${record.label}</code></h2>
      <div class="card"><p>Copy it now into your agent's secure credential setting. It won't be shown again.</p><pre>${token}</pre>
      ${restarted ? html`<p>The name <code>${record.label}</code> belonged to an agent you disconnected. This token starts a new agent: it won't see what was addressed to, or sent by, the earlier one.</p>` : ""}
      ${live > 0 ? html`<p>Your agent <code>${record.label}</code> already had ${live === 1 ? "a token" : `${live} tokens`}: this adds one, and ${live === 1 ? "the earlier one still works" : "the earlier ones still work"}. Revoke ${live === 1 ? "it" : "them"} on your page if you're replacing ${live === 1 ? "it" : "them"}.</p>` : ""}
      <p class="muted">Scopes ${record.scopes.join(" ")}; expires ${record.expires_at}. Use it as <code>Authorization: Bearer &lt;token&gt;</code> on the connector URL or the REST API.</p>
      <p><a href="/web">Back to your page</a></p></div>`);
  }));

  router.post("/web/tokens/:id/revoke", ...action(async (req) => ({ kind: "token_revoke", id: String(req.params["id"]) }), async (req, res, s) => {
    const r = await revokePat(state, s.principal_id, String(req.params["id"]), opts.now());
    if (!r) throw new Error("no such token");
    await broker.recordSecurityEvent("token_revoked", { details: { client_id: PAT_CLIENT_ID, principal_id: s.principal_id, delegate: r.delegate } });
    res.redirect(303, "/web");
  }));

  router.post("/web/grants/revoke", ...action(async (_req, _s, f) => ({ kind: "revoke", counterparty: str(f["counterparty"]) }), async (_req, res, _s, who, f) => {
    await broker.revoke(who, { counterparty: parseAddress(str(f["counterparty"])) });
    res.redirect(303, "/web");
  }));

  // Sealing covers the pending grant's terms as the page listed them.
  const sealTerms: TermsOf = async (_req, s, f) => {
    const g = (await broker.listGrants(viewer(s))).find((x) => x.counterparty === str(f["counterparty"]));
    return { kind: "seal", counterparty: str(f["counterparty"]), status: g?.status ?? null, scopes: g ? hashJson(g.scopes) : null };
  };

  router.post("/web/grants/seal", ...action(sealTerms, async (_req, res, _s, who, f) => {
    await broker.sealGrant(who, { counterparty: parseAddress(str(f["counterparty"])) });
    res.redirect(303, "/web");
  }));

  // ---------------------------------------------------------------------------------------------
  // The ledger

  // Where a received message waits, as its `received` entry (or, in a ledger written before, its `held` entry) says.
  const waits = (e: LedgerEntry): Html | "" => {
    if ((e.kind !== "received" && e.kind !== "held") || e.ref === undefined) return "";
    if (e.ref === "web_view") return html`<br><span class="muted">waits for you on this page</span>`;
    if (e.ref.startsWith("until:")) return html`<br><span class="muted">arrived during your quiet hours; your agents see it after ${e.ref.slice("until:".length)}</span>`;
    return "";
  };
  const ledgerRow = (e: LedgerEntry): Html => html`<tr><td>${e.seq}</td><td>${e.at}</td><td>${e.kind}</td><td>${e.counterparty ? displayAddress(e.counterparty) : ""}</td><td>${e.scope ?? ""} ${e.type ?? ""}</td><td>${e.outcome}${e.code ? ` (${e.code})` : ""}${waits(e)}</td><td>${(e.disclosed ?? []).join(" ")}${e.redacted?.length ? html`<br><span class="muted">removed ${e.redacted.join(" ")}</span>` : ""}</td><td>${e.delegate ? e.delegate.slice(e.delegate.lastIndexOf("/") + 1) : ""}</td><td>${e.receipt_hash ? html`<code>${e.receipt_hash.slice(0, 18)}…</code>` : ""}</td></tr>`;

  router.get("/web/ledger", (req, res, next) => {
    (async () => {
      const s = await session(req, res);
      if (!s) return;
      const p = await principalOf(s);
      if (!p) return loginPage(res);
      const me = viewer(s);
      // The newest entries, so that refusals piling up (a looping or hostile agent) never push the person's own out of
      // view; the count is the whole ledger's, and the export has every entry.
      const all = await broker.ledger(me);
      const entries = all.slice(-LEDGER_PAGE_ENTRIES);
      const check = await broker.verifyLedger(me);
      const count = (n: number): string => n.toLocaleString("en-US");
      const body = html`${header(s, p)}
        <h2>Your ledger</h2>
        <p>${count(all.length)} ${all.length === 1 ? "entry" : "entries"}${all.length > entries.length ? `, showing the newest ${count(entries.length)}; the export has all of them` : ""}. Chain: ${check.ok ? html`<strong>intact</strong>` : html`<strong class="bad">broken</strong>`}. <a href="/web/ledger.json">Export (JSON)</a></p>
        <table><tr><th>#</th><th>At</th><th>Kind</th><th>Counterparty</th><th>Scope / type</th><th>Outcome</th><th>Fields that crossed</th><th>Agent</th><th>Receipt</th></tr>
        ${entries.slice().reverse().map(ledgerRow)}</table>`;
      page(res, "Ledger", body);
    })().catch(next);
  });

  router.get("/web/ledger.json", (req, res, next) => {
    (async () => {
      const s = await session(req, res);
      if (!s) return;
      if (!(await principalOf(s))) {
        await sessions.end(req, res);
        loginPage(res, "Your account isn't active here.");
        return;
      }
      const me = viewer(s);
      // Every entry, however many.
      const entries = await broker.ledger(me);
      res.setHeader("Content-Disposition", `attachment; filename="ledger.json"`);
      res.setHeader("Cache-Control", "no-store");
      res.json({ principal: s.principal, exported_at: opts.now().toISOString(), entries });
    })().catch(next);
  });

  return router;
}

