// SPDX-License-Identifier: FSL-1.1-ALv2
// The client binding's OAuth 2.1 authorization server: oidc-provider (MIT, pinned 9.13.3) inside the broker,
// configured to the MCP authorization specification and spec 5.6:
//
// - RFC 8414 metadata and OpenID discovery (served by oidc-provider; src/oauth/metadata.ts adds the RFC 8414 path);
// - client registration: client ID metadata documents first (draft-ietf-oauth-client-id-metadata-document, oidc-provider's
//   experimental `clientIdMetadataDocument` feature, draft-02), dynamic client registration (RFC 7591) as the fallback
//   with `application_type` required, and pre-registered clients;
// - PKCE S256 only, for every client; RFC 9207 `iss` in every authorization response (oidc-provider always sends it);
// - RFC 8707 resource indicators: JWT access tokens (RFC 9068, `typ: at+jwt`) whose `aud` is the canonical MCP or REST
//   URI, 10 minutes by default; rotating refresh tokens with reuse detection (a reused one revokes the whole grant);
// - a connector grant ends after at most 30 days for organization principals and 90 days for others (spec 5.6.7).
//
// Sign-in is the broker's own interaction (src/oauth/interaction.ts): the dev IdP's test identities, or in production a
// hand-off to the organization's OpenID provider (oidc.ts). Every authorization asks the person to sign in again, so a
// browser that already signed in as Ana can't silently authorize a second agent as Ana. With the organization's
// provider, every refresh also re-checks the person there (`refreshCheck`, oidc-signin.ts).

import type { IncomingMessage } from "node:http";
import Provider, { errors, interactionPolicy } from "oidc-provider";
import type { ClientMetadata, Configuration, KoaContextWithOIDC } from "oidc-provider";
import { displayAddress, domainOf } from "../core/address.ts";
import { isJsonContentType } from "../federation/fetcher.ts";
import type { Broker } from "../core/broker.ts";
import type { SecurityEventName } from "../core/security-events.ts";
import type { DelegateRecord, PrincipalRecord } from "../core/types.ts";
import { sourcePrefix } from "./sources.ts";
import { StateAdapter } from "./adapter.ts";
import { dcrRedirectAllowed, isCimdClientId, isLoopbackUri, loopbackMatch, redirectUriPermitted } from "./clients.ts";
import type { RedirectPolicy } from "./clients.ts";
import type { AuthServerKeys } from "./keys.ts";
import { sha256b64u } from "./state.ts";
import type { BindingStore } from "./state.ts";
import { MemoryWindows, windowCount, windowHit } from "../core/windows.ts";
import type { Windows } from "../core/windows.ts";

export const OAUTH_SCOPES = ["read", "send"] as const;
export type OAuthScope = (typeof OAUTH_SCOPES)[number];

export const ROUTES = {
  authorization: "/oauth/authorize",
  token: "/oauth/token",
  registration: "/oauth/register",
  jwks: "/oauth/jwks",
  userinfo: "/oauth/userinfo",
  revocation: "/oauth/revoke",
  end_session: "/oauth/logout",
  introspection: "/oauth/introspect",
  pushed_authorization_request: "/oauth/par",
  code_verification: "/oauth/device",
  device_authorization: "/oauth/device/auth",
  backchannel_authentication: "/oauth/backchannel",
  challenge: "/oauth/challenge",
} as const;

export interface AuthServerOptions {
  broker: Broker;
  state: BindingStore;
  keys: AuthServerKeys;
  /** The public origin, exactly as clients see it (no trailing slash). It is the issuer. */
  issuer: string;
  /** Canonical resource URIs (RFC 8707 audiences). */
  resources: { mcp: string; rest: string };
  redirectPolicy: RedirectPolicy;
  /** Spec 5.6.4: dynamic registrations must state application_type. */
  requireApplicationType: boolean;
  /** Dynamic registrations may use only the platforms' published callbacks or loopback (default true). */
  dcrExactCallbacks?: boolean;
  /** Is this principal an organization principal (its domain has an org policy here)? */
  isOrganizationDomain: (domain: string) => boolean;
  accessTokenTtlSeconds: number;
  /** Connector grant caps in days. */
  grantDays: { organization: number; other: number };
  /** Pre-registered clients (spec 5.6.4): an operator registers a client id (and secret, or keys) for a platform
   *  that needs one, such as Microsoft 365 Copilot or Gemini Enterprise. Same redirect rules as every client. */
  staticClients?: ClientMetadata[];
  /** Replaces the outbound fetch under the rules below (client ID metadata documents, client JWKS). Tests use it;
   *  production keeps oidc-provider's SSRF-protected fetch, which refuses special-use addresses. */
  fetch?: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  /** Who is asking, for the per-requester budget on fetching client ID metadata documents (spec 4.3 rule 6). */
  sourceOf?: (req: IncomingMessage) => string;
  /** Client ID metadata documents fetched per requester and in all, per minute, and seconds a failed one isn't fetched again. */
  cimdLimits?: { perSourcePerMinute: number; totalPerMinute: number; failureCacheSeconds: number };
  /**
   * Whether an installed policy's list of agents names this client id. A listed client's metadata document is fetched
   * outside the per-source and total budgets (which limit discovery of URLs the broker hasn't seen, spec 4.3 rule 6),
   * so strangers spending them can't stop a listed client from signing in or refreshing. The failure cache still applies.
   */
  isListedClient?: (clientId: string) => boolean;
  /**
   * Re-checks the person at the organization's identity provider whenever a connection refreshes (spec 5.3,
   * offboarding). "refused" ends the connection; a thrown error fails this refresh only (the provider was unreachable).
   */
  refreshCheck?: (grantId: string, principal: PrincipalRecord, clientId: string) => Promise<"ok" | "refused" | "unreadable">;
  /** Called when oidc-provider revokes a grant (refresh-token reuse, code replay). */
  onGrantRevoked?: (grantId: string) => void;
  /** Where the fetch budgets and the failure cache live (default: this process's memory). */
  windows?: Windows;
  log: (line: string) => void;
}

/** Defaults for fetching client ID metadata documents (spec 4.3 rule 6). */
export const CIMD_LIMITS = { perSourcePerMinute: 20, totalPerMinute: 200, failureCacheSeconds: 120 } as const;

/** Size caps for what the authorization server fetches (spec 4.3 rule 4; oidc-provider's own cap for metadata documents). */
export const AUTH_FETCH_LIMITS = { "client_id metadata document": 5 * 1024, jwks_uri: 64 * 1024, sector_identifier_uri: 64 * 1024 } as const;

/** How long one fetch may take, its body included: oidc-provider's own timeout (2.5 s), enforced on the whole fetch. */
export const AUTH_FETCH_DEADLINE_MS = 2500;

/** The largest body any fetch here may have; oidc-provider then applies each purpose's own cap, to the body in memory. */
const AUTH_FETCH_MAX_BYTES = Math.max(...Object.values(AUTH_FETCH_LIMITS));

/** Statuses whose responses can't carry a body. */
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

/** Store model of the agent binding each connection (oidc-provider grant) was authorized for (spec 5.4). */
const GRANT_BINDING = "AlpGrantBinding";

/** What an interaction needs from the provider, typed. */
export interface AuthServer {
  provider: Provider;
  /**
   * Records the agent binding a connection was authorized for (spec 5.4): its tokens act for that binding only, and
   * it stops refreshing once that agent is disconnected, even if the same client connects again under the same name.
   */
  bindGrant(grantId: string, accountId: string, delegate: DelegateRecord): Promise<void>;
  /** Remember whether an account is an organization principal (TTL functions are synchronous). */
  noteAccount(principalId: string, address: string): void;
  /** RFC 8707: is this one of our resources? Returns the canonical form. */
  canonicalResource(value: string | undefined): string | null;
  /** Canonical resource URIs. */
  resources: { mcp: string; rest: string };
  /** Whether the operator pre-registered this client (`staticClients`), the source of its name and label (spec 5.4). */
  isPreRegistered(clientId: string): boolean;
}

function securityEvent(broker: Broker, event: SecurityEventName, details: { client_id?: string; principal_id?: string }, failed?: boolean, message?: string): void {
  const clean: { client_id?: string; principal_id?: string } = {};
  if (details.client_id) clean.client_id = details.client_id.slice(0, 2048);
  if (details.principal_id && /^[A-Za-z0-9_-]{16,64}$/.test(details.principal_id)) clean.principal_id = details.principal_id;
  void broker.recordSecurityEvent(event, { ...(failed !== undefined ? { failed } : {}), ...(message ? { message } : {}), details: clean });
}

/** A CIMD URL the broker will fetch: https on the default port, a DNS name (not an IP literal), no credentials. */
export function cimdUrlAllowed(id: string): boolean {
  const u = URL.parse(id);
  if (!u || u.protocol !== "https:" || u.port !== "" || u.username || u.password || u.hash) return false;
  const host = u.hostname;
  if (host === "localhost" || host.endsWith(".localhost") || /^[0-9.]+$/.test(host) || host.startsWith("[")) return false;
  return host.includes(".");
}

/** Reads at most `max` bytes of a response body; more is an error. */
async function readCapped(res: Response, max: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  if (res.body) {
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > max) {
        await res.body.cancel().catch(() => undefined);
        throw new Error("response over the size cap");
      }
      chunks.push(Buffer.from(chunk));
    }
  }
  return Buffer.concat(chunks);
}

/**
 * Runs `work` with a signal that aborts when `outer` does or after `ms`, and settles by then whatever `work` does. An
 * aborted fetch doesn't always end: Node's fetch can leave a response body pending forever, with neither data nor an
 * error, when its signal fires after the body's last bytes arrived but before a compressed body was decoded (decoding
 * runs on the libuv threadpool, so a busy threadpool or a stalled event loop can put the signal there). oidc-provider
 * makes every later request for a client wait on the first fetch of its metadata document (or key set), so one such
 * fetch would hold that client out until a restart.
 */
async function withDeadline<T>(ms: number, outer: AbortSignal | null | undefined, work: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const ac = new AbortController();
  const expired = new Promise<never>((_, reject) => {
    ac.signal.addEventListener("abort", () => reject(ac.signal.reason), { once: true });
  });
  const fromOuter = (): void => ac.abort(outer?.reason);
  const timer = setTimeout(() => ac.abort(new Error(`no complete response within ${ms} ms`)), ms);
  timer.unref();
  if (outer?.aborted) fromOuter();
  else outer?.addEventListener("abort", fromOuter, { once: true });
  try {
    return await Promise.race([work(ac.signal), expired]);
  } finally {
    clearTimeout(timer);
    outer?.removeEventListener("abort", fromOuter);
  }
}

/** Whether a fetched client ID metadata document is one oidc-provider can use: a JSON object naming its own URL. */
function cimdLooksValid(url: string, body: Buffer): boolean {
  try {
    const v = JSON.parse(body.toString("utf8")) as unknown;
    return typeof v === "object" && v !== null && !Array.isArray(v) && (v as Record<string, unknown>)["client_id"] === url;
  } catch {
    return false;
  }
}

export function createAuthServer(opts: AuthServerOptions): AuthServer {
  const { broker, state, keys, issuer, resources, redirectPolicy } = opts;
  const orgByAccount = new Map<string, boolean>();
  const noteAccount = (principalId: string, address: string): void => {
    orgByAccount.set(principalId, opts.isOrganizationDomain(domainOf(address)));
  };
  const capSeconds = (accountId: string | undefined): number =>
    (accountId !== undefined && orgByAccount.get(accountId) === false ? opts.grantDays.other : opts.grantDays.organization) * 86400;
  const bindGrant = async (grantId: string, accountId: string, delegate: DelegateRecord): Promise<void> => {
    await state.oidcPut(GRANT_BINDING, sha256b64u(grantId), { delegate: delegate.id, binding: delegate.created_at }, Date.now() + capSeconds(accountId) * 1000);
  };
  /** The binding a connection was authorized for; null for one authorized before bindings were recorded. */
  const grantBinding = async (grantId: string): Promise<{ delegate: string; binding: string } | null> => {
    const r = await state.oidcGet(GRANT_BINDING, sha256b64u(grantId), Date.now());
    const delegate = r?.["delegate"];
    const binding = r?.["binding"];
    return typeof delegate === "string" && typeof binding === "string" ? { delegate, binding } : null;
  };
  /** The client's newest active agent of this person: the agent a connection acted for before bindings were recorded. */
  const newestAgent = async (p: PrincipalRecord, clientId: string): Promise<DelegateRecord | undefined> =>
    (await broker.store.listDelegates(p.address)).filter((x) => x.client_id === clientId && x.status === "active" && x.principal_id === p.principal_id).sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
  /**
   * The agent a connection authorized before bindings were recorded acts for: the client's newest active agent, as
   * before, but only if its binding had started when the connection was authorized (the grant's `iat`, in whole
   * seconds). One that started later is another agent (spec 5.4), even with the same name and client: null.
   */
  const agentOfUnboundGrant = async (grantId: string, p: PrincipalRecord, clientId: string): Promise<DelegateRecord | null> => {
    const d = await newestAgent(p, clientId);
    if (!d) return null;
    const iat = (await new StateAdapter(state, "Grant").find(grantId))?.iat;
    return typeof iat === "number" && Math.floor(Date.parse(d.created_at) / 1000) <= iat ? d : null;
  };
  /** Ends a connection: its grant and every token and code issued under it. */
  const revokeConnection = async (grantId: string): Promise<void> => {
    for (const model of ["AccessToken", "RefreshToken", "AuthorizationCode"]) await new StateAdapter(state, model).revokeByGrantId(grantId);
    await new StateAdapter(state, "Grant").destroy(grantId);
  };

  const canonicalResource = (value: string | undefined): string | null => {
    if (value === undefined) return null;
    const v = value.replace(/\/+$/, "");
    if (v === resources.mcp) return resources.mcp;
    if (v === resources.rest) return resources.rest;
    return null;
  };

  // Spec 4.3: a client ID metadata document, and the JWKS it names, are URLs chosen by whoever sent the request. They
  // are fetched over https on port 443 only, to a host name, with no redirects, `Cache-Control: no-cache`,
  // `Accept-Encoding: identity`, a JSON content type and size caps (AUTH_FETCH_LIMITS). oidc-provider adds a 2.5-second
  // timeout and, in production, refuses special-use addresses (it checks once connected, not before). The whole fetch,
  // its body included, settles within that time whatever the fetch does (withDeadline); the body is read here, or
  // cancelled where oidc-provider wouldn't read it, so oidc-provider only ever reads one in memory and no response is
  // still being received after the deadline. Metadata documents are also budgeted per requester and in all, and one
  // that failed (or timed out) isn't fetched again for a while; oidc-provider caches only the ones that worked.
  const baseFetch = opts.fetch ?? ((input: string | URL | Request, init?: RequestInit) => globalThis.fetch(input, init));
  const cimd = { ...CIMD_LIMITS, ...opts.cimdLimits };
  const windows = opts.windows ?? new MemoryWindows();
  // Marks the next fetch of a URL as a metadata document fetch that allowFetch approved (same request, same process).
  const cimdApproved = new Set<string>();
  const sourceOf = opts.sourceOf ?? ((req: IncomingMessage) => (req.socket.remoteAddress ?? "unknown").toLowerCase());
  const failedKey = (url: string): string => `cimd-failed|${sha256b64u(url)}`;
  const noteCimdFailure = async (url: string): Promise<void> => {
    await windowHit(windows, failedKey(url), new Date(), cimd.failureCacheSeconds);
  };
  const guardedFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const isCimd = cimdApproved.delete(url);
    try {
      if (!cimdUrlAllowed(url)) throw new Error("only https URLs on port 443 with a host name are fetched");
      const headers = new Headers(init?.headers);
      headers.set("cache-control", "no-cache");
      // An uncompressed body: Node's fetch decodes a compressed one off the event loop, which is where an abort can
      // leave it pending forever (withDeadline). A server may compress anyway, so the deadline stays.
      headers.set("accept-encoding", "identity");
      return await withDeadline(AUTH_FETCH_DEADLINE_MS, init?.signal, async (signal) => {
        const res = await baseFetch(url, { ...init, headers, redirect: "manual", signal });
        if (res.status === 200 && !isJsonContentType(res.headers.get("content-type") ?? undefined)) {
          await res.body?.cancel().catch(() => undefined);
          throw new Error("not a JSON content type");
        }
        if (isCimd && res.status !== 200) {
          // oidc-provider refuses any other status without reading the body. Cancelling it here closes the connection
          // now, however long the server would go on sending, and oidc-provider gets the status and headers only.
          await res.body?.cancel().catch(() => undefined);
          await noteCimdFailure(url);
          return new Response(null, { status: res.status, headers: res.headers });
        }
        const body = await readCapped(res, isCimd ? AUTH_FETCH_LIMITS["client_id metadata document"] : AUTH_FETCH_MAX_BYTES);
        if (isCimd && !cimdLooksValid(url, body)) await noteCimdFailure(url);
        return new Response(NULL_BODY_STATUSES.has(res.status) ? null : body, { status: res.status, headers: res.headers });
      });
    } catch (err) {
      if (isCimd) await noteCimdFailure(url);
      throw err;
    }
  };
  const allowCimdFetch = async (req: IncomingMessage, clientId: string): Promise<boolean> => {
    const now = new Date();
    if ((await windowCount(windows, failedKey(clientId), now, cimd.failureCacheSeconds)) > 0) {
      opts.log("oauth: did not fetch a client metadata document that failed recently");
      return false;
    }
    if (opts.isListedClient?.(clientId) !== true) {
      // Per source, an IPv6 /64 counting as one, and in all.
      const mineKey = `cimd|${sha256b64u(sourcePrefix(sourceOf(req)))}`;
      if ((await windowCount(windows, mineKey, now, 60)) >= cimd.perSourcePerMinute || (await windowCount(windows, "cimd-all", now, 60)) >= cimd.totalPerMinute) {
        opts.log("oauth: paused fetching client metadata documents (rate limit)");
        return false;
      }
      await windowHit(windows, mineKey, now, 60);
      await windowHit(windows, "cimd-all", now, 60);
    }
    if (cimdApproved.size > 1000) cimdApproved.clear();
    cimdApproved.add(clientId);
    return true;
  };

  const policy = interactionPolicy.base();
  policy.get("login")?.checks.add(
    new interactionPolicy.Check("alp_fresh_signin", "each connector authorization needs the person to sign in", "login_required", (ctx) =>
      ctx.oidc.result?.["login"] ? interactionPolicy.Check.NO_NEED_TO_PROMPT : interactionPolicy.Check.REQUEST_PROMPT,
    ),
  );

  const configuration: Configuration = {
    adapter: (name: string) => new StateAdapter(state, name),
    ...(opts.staticClients?.length ? { clients: opts.staticClients.map((c) => ({ ...c })) } : {}),
    jwks: { keys: keys.signing.map((k) => ({ ...k })) as NonNullable<Configuration["jwks"]>["keys"] },
    cookies: { keys: keys.cookieKeys },
    claims: { openid: ["sub"], email: ["email", "email_verified"], profile: ["name"] },
    scopes: ["openid", "offline_access", ...OAUTH_SCOPES],
    responseTypes: ["code"],
    clientAuthMethods: ["none", "private_key_jwt", "client_secret_basic", "client_secret_post"],
    clientDefaults: {
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      id_token_signed_response_alg: "RS256",
    },
    pkce: { required: () => true },
    routes: { ...ROUTES },
    interactions: {
      policy,
      url: (_ctx: KoaContextWithOIDC, interaction) => `/interaction/${interaction.uid}`,
    },
    features: {
      devInteractions: { enabled: false },
      registration: { enabled: true, initialAccessToken: false },
      revocation: { enabled: true },
      // Every access token is audience-bound to the MCP endpoint or the REST mirror (RFC 8707), so none could call a
      // UserInfo endpoint; identity is in the ID token. Not advertising one keeps clients from calling it in vain.
      userinfo: { enabled: false },
      rpInitiatedLogout: { enabled: false },
      // Client mode uses bearer tokens (MCP authorization has no DPoP); DPoP is future work (spec 19). No PAR either.
      dPoP: { enabled: false },
      pushedAuthorizationRequests: { enabled: false },
      clientIdMetadataDocument: {
        enabled: true,
        ack: "draft-02",
        allowFetch: async (ctx: KoaContextWithOIDC, clientId: string) => {
          if (!cimdUrlAllowed(clientId)) {
            opts.log(`oauth: refused to fetch client metadata from a disallowed URL`);
            return false;
          }
          return allowCimdFetch(ctx.req, clientId);
        },
        allowClient: async () => true,
        cacheDuration: { min: 60, max: 3600 },
      },
      resourceIndicators: {
        enabled: true,
        defaultResource: async (_ctx: KoaContextWithOIDC, _client, oneOf?: readonly string[]) => oneOf ?? resources.mcp,
        useGrantedResource: async () => true,
        getResourceServerInfo: async (_ctx: KoaContextWithOIDC, resourceIndicator: string) => {
          const canonical = canonicalResource(resourceIndicator);
          if (!canonical) throw new errors.InvalidTarget();
          return {
            scope: OAUTH_SCOPES.join(" "),
            audience: canonical,
            accessTokenTTL: opts.accessTokenTtlSeconds,
            accessTokenFormat: "jwt",
            jwt: { sign: { alg: "ES256" } },
          };
        },
      },
    },
    extraClientMetadata: {
      // A marker property, so the validator below runs for every client: registered, CIMD or static.
      properties: ["x_alp_checked"],
      validator(ctx, key, _value, metadata) {
        if (key !== "x_alp_checked") return;
        const route = (ctx as KoaContextWithOIDC | undefined)?.oidc?.route;
        if (route === "registration" && opts.requireApplicationType) {
          const body = (ctx as KoaContextWithOIDC).oidc.body;
          if (!body || body["application_type"] === undefined) throw new errors.InvalidClientMetadata("application_type is required (MCP 2026-07-28 registration rule; spec 5.6)");
        }
        const uris = Array.isArray(metadata.redirect_uris) ? metadata.redirect_uris : [];
        const clientId = typeof metadata.client_id === "string" ? metadata.client_id : "";
        const cimdHost = isCimdClientId(clientId) ? URL.parse(clientId)?.hostname : undefined;
        for (const uri of uris) {
          if (!redirectUriPermitted(uri, redirectPolicy)) throw new errors.InvalidRedirectUri(`redirect_uri host is not allowed at this broker`);
          if (cimdHost && !isLoopbackUri(uri) && URL.parse(uri)?.hostname !== cimdHost) throw new errors.InvalidClientMetadata("a client ID metadata document may only list redirect URIs on its own host, or loopback");
          // A dynamically registered client may use only the agent platforms' published callbacks (or loopback), not
          // any page on their hosts, which might leak the code.
          if (route === "registration" && opts.dcrExactCallbacks !== false && !dcrRedirectAllowed(uri)) throw new errors.InvalidRedirectUri("a dynamically registered client may use only a platform's published callback URL, or loopback");
        }
      },
    },
    findAccount: async (ctx: KoaContextWithOIDC, sub: string, token?: { clientId?: string; grantId?: string }) => {
      const p = await broker.store.getPrincipalById(sub);
      if (!p || p.status !== "active") return undefined;
      // Spec 5.8: a kill switch on the person, the client or its agent also stops code exchange and refresh; so does
      // the client leaving the organization's list of agents in enforce mode (spec 6.10).
      const clientId = token?.clientId;
      if (clientId) {
        const d = (await broker.store.listDelegates(p.address)).find((x) => x.client_id === clientId && x.status === "active" && x.principal_id === p.principal_id);
        if (broker.agentBlocked(p.address, d?.id, clientId) || broker.clientRefused(p.address, clientId)) return undefined;
      } else if (broker.agentBlocked(p.address, undefined, undefined)) {
        return undefined;
      }
      // Spec 5.4: a connection acts only for the agent it was authorized for. Once that agent is disconnected (and its
      // name perhaps given to a later agent, even of the same client), the connection can't refresh.
      if (typeof token?.grantId === "string") {
        const bound = await grantBinding(token.grantId);
        const d = bound ? await broker.store.getDelegate(bound.delegate) : null;
        if (bound && (!d || d.status !== "active" || d.created_at !== bound.binding)) return undefined;
        // A connection authorized before bindings were recorded gets its binding at its next token (extraTokenClaims),
        // but never one that started after it was authorized: then it is ended, as disconnecting its agent would.
        if (!bound && clientId && !(await agentOfUnboundGrant(token.grantId, p, clientId))) {
          await revokeConnection(token.grantId);
          securityEvent(broker, "token_refused", { client_id: clientId, principal_id: p.principal_id }, true, "refresh refused: the connection was authorized before the agent it would act for; the connection was revoked");
          securityEvent(broker, "token_revoked", { client_id: clientId, principal_id: p.principal_id });
          return undefined;
        }
      }
      // Spec 5.3: a refresh re-checks the person at the organization's identity provider. When the provider refuses
      // (a disabled or deleted account, revoked sessions), the whole connection is revoked, its live access tokens too.
      const params = ctx?.oidc?.params as Record<string, unknown> | undefined;
      if (opts.refreshCheck && ctx?.oidc?.route === "token" && params?.["grant_type"] === "refresh_token" && clientId && typeof token?.grantId === "string") {
        const grantId = token.grantId;
        const verdict = await opts.refreshCheck(grantId, p, clientId);
        if (verdict !== "ok") {
          await revokeConnection(grantId);
          // Only a refusal at the provider says the provider no longer accepts the person.
          securityEvent(broker, "token_refused", { client_id: clientId, principal_id: p.principal_id }, true, verdict === "refused"
            ? "refresh refused: the identity provider no longer accepts this person; the connection was revoked"
            : "refresh refused: the stored identity-provider session can't be opened under the broker's cookie keys; the connection was revoked");
          securityEvent(broker, "token_revoked", { client_id: clientId, principal_id: p.principal_id });
          return undefined;
        }
      }
      noteAccount(p.principal_id, p.address);
      return {
        accountId: p.principal_id,
        claims: async () => ({
          sub: p.principal_id,
          email: displayAddress(p.address),
          // Test identities and addresses are not verified mailboxes.
          email_verified: false,
          ...(p.display_name ? { name: p.display_name } : {}),
        }),
      };
    },
    extraTokenClaims: async (_ctx: KoaContextWithOIDC, token) => {
      const accountId = "accountId" in token ? token.accountId : undefined;
      const clientId = token.clientId;
      if (!accountId || !clientId) return undefined;
      const p = await broker.store.getPrincipalById(accountId);
      if (!p) return undefined;
      // The grant id, so the resource server can refuse a token whose grant was revoked (refresh reuse, the person
      // disconnecting the agent) before the token expires.
      const grantId = "grantId" in token && typeof token.grantId === "string" ? token.grantId : undefined;
      // The agent the connection was authorized for, and when its binding started (spec 5.4): the resource server
      // refuses the token once that binding has ended, whoever has the name now.
      const bound = grantId ? await grantBinding(grantId) : null;
      if (bound) return { alp_delegate: bound.delegate, alp_binding: bound.binding, ...(grantId ? { alp_grant: grantId } : {}) };
      if (!grantId) {
        const d = await newestAgent(p, clientId);
        return d ? { alp_delegate: d.id } : undefined;
      }
      // A connection authorized before bindings were recorded: the client's newest active agent, as before, if its
      // binding had started when the connection was authorized (findAccount ends the connection otherwise). That is
      // from now on the binding it acts for, so it stops once that agent is disconnected, as one authorized since does.
      const d = await agentOfUnboundGrant(grantId, p, clientId);
      if (!d) return undefined;
      await bindGrant(grantId, accountId, d);
      return { alp_delegate: d.id, alp_binding: d.created_at, alp_grant: grantId };
    },
    issueRefreshToken: async (_ctx: KoaContextWithOIDC, client) => client.grantTypeAllowed("refresh_token"),
    expiresWithSession: async () => false,
    rotateRefreshToken: true,
    ttl: {
      AccessToken: opts.accessTokenTtlSeconds,
      AuthorizationCode: 60,
      IdToken: 600,
      Interaction: 900,
      Session: 900,
      Grant: (_ctx: KoaContextWithOIDC, grant) => capSeconds(grant.accountId),
      RefreshToken: (_ctx: KoaContextWithOIDC, token) => {
        const iiat = typeof token.iiat === "number" ? token.iiat : Math.floor(Date.now() / 1000);
        return Math.max(1, capSeconds(token.accountId) - (Math.floor(Date.now() / 1000) - iiat));
      },
    },
    renderError: async (ctx: KoaContextWithOIDC, out) => {
      ctx.type = "html";
      const esc = (s: unknown): string => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
      ctx.body = `<!doctype html><meta charset="utf-8"><title>Sign-in error</title><h1>Sign-in error</h1><p>${esc(out["error"])}: ${esc(out["error_description"])}</p>`;
    },
    fetch: guardedFetch,
    fetchResponseBodyLimits: { ...AUTH_FETCH_LIMITS },
  };

  const provider = new Provider(issuer, configuration);
  // The broker listens on loopback only; X-Forwarded-Proto and X-Forwarded-Host are set from PUBLIC_URL by the app.
  provider.proxy = true;
  // RFC 8252 7.3: a loopback redirect matches a registered one whatever its port, for 127.0.0.1 and for localhost (as
  // Claude Code's client metadata document lists them). oidc-provider ignores the port only for native clients.
  const clientProto = provider.Client.prototype as unknown as { redirectUriAllowed(this: { redirectUris?: string[] }, uri: string): boolean };
  const exactRedirect = clientProto.redirectUriAllowed;
  clientProto.redirectUriAllowed = function (this: { redirectUris?: string[] }, uri: string): boolean {
    return exactRedirect.call(this, uri) || (this.redirectUris ?? []).some((r) => loopbackMatch(uri, r));
  };

  provider.on("grant.success", (ctx: KoaContextWithOIDC) => {
    const at = ctx.oidc.entities.AccessToken;
    securityEvent(broker, "token_issued", { client_id: ctx.oidc.client?.clientId ?? "", principal_id: at?.accountId ?? ctx.oidc.entities.Account?.accountId ?? "" }, false);
  });
  provider.on("grant.error", (ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => {
    // oidc-provider keeps the specific reason in error_detail (error_description is generic).
    const why = err.error_detail ?? err.error_description ?? "";
    const reuse = why === "refresh token already used";
    securityEvent(broker, reuse ? "refresh_reuse" : "token_refused", { client_id: ctx.oidc?.client?.clientId ?? "" }, true, `${err.error}${why ? `: ${why}` : ""}`);
    opts.log(`oauth: token request refused (${err.error}${why ? `: ${why}` : ""})${reuse ? "; the whole connection was revoked" : ""}`);
  });
  provider.on("grant.revoked", (ctx: KoaContextWithOIDC, grantId?: string) => {
    securityEvent(broker, "token_revoked", { client_id: ctx.oidc?.client?.clientId ?? "" });
    if (typeof grantId === "string") opts.onGrantRevoked?.(grantId);
  });
  provider.on("authorization.success", (ctx: KoaContextWithOIDC) => {
    // Logged only now, when the client gets its code: a sign-in that oidc-provider then refuses never says "connected".
    const clientId = ctx.oidc.client?.clientId ?? "";
    const accountId = ctx.oidc.session?.accountId ?? ctx.oidc.entities.Account?.accountId;
    void (async () => {
      const p = accountId ? await broker.store.getPrincipalById(accountId) : null;
      if (!p) return;
      const d = (await broker.store.listDelegates(p.address)).filter((x) => x.client_id === clientId && x.status === "active").sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
      opts.log(`oauth: ${displayAddress(p.address)} connected ${d?.id ?? "an agent"} (${isCimdClientId(clientId) ? URL.parse(clientId)?.hostname ?? "cimd" : "registered client"})`);
    })().catch(() => undefined);
  });
  provider.on("authorization.error", (_ctx: KoaContextWithOIDC, err: errors.OIDCProviderError) => {
    const why = err.error_detail ?? err.error_description ?? "";
    opts.log(`oauth: authorization refused (${err.error}${why ? `: ${why}` : ""})`);
  });
  provider.on("registration_create.success", (_ctx: KoaContextWithOIDC, client) => {
    opts.log(`oauth: registered a client dynamically (${client.clientName ? JSON.stringify(String(client.clientName).slice(0, 64)) : "no name"})`);
  });
  provider.on("server_error", (_ctx: KoaContextWithOIDC, err: Error) => {
    opts.log(`oauth: server error: ${err.message}`);
  });

  const preRegistered = new Set((opts.staticClients ?? []).map((c) => c.client_id));
  const isPreRegistered = (clientId: string): boolean => preRegistered.has(clientId);

  return { provider, bindGrant, noteAccount, canonicalResource, resources, isPreRegistered };
}
