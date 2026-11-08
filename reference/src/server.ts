// SPDX-License-Identifier: FSL-1.1-ALv2
// The HTTP broker: the core (src/core) with the client binding (src/oauth, src/mcp, src/web).
//
// Two listeners, both on loopback by default:
// - the public app (PORT): what a tunnel or reverse proxy exposes. The MCP endpoint (/mcp), the REST mirror (/rest),
//   the authorization server (/oauth/*, /.well-known/*) and the connector sign-in page (/interaction/*). Nothing else.
// - the web view (WEB_PORT): the person's page (/web). During a test through a tunnel it stays on loopback.
// The federation inbox can be mounted on either app through `extraPublicRoutes`.
//
// For a hosted broker (`publicWeb`), the web view moves onto the public app instead, behind invites and passkeys
// (src/web/app.ts), and `bindingStore` and `windows` put the client binding's state and its rate and replay windows in
// Postgres, so several instances given the same `authKeys` can serve it. (The federation inbox keeps its per-address
// limit and request-signature nonces per instance: src/federation/inbox.ts.)

import { createHmac } from "node:crypto";
import type { IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import express from "express";
import type { Express, NextFunction, Request, Response, Router } from "express";
import type { Broker } from "./core/broker.ts";
import type { IdentityVerifier, Notifier } from "./core/interfaces.ts";
import { PROTOCOL } from "./core/protocol.ts";
import type { OrgPolicy } from "./core/types.ts";
import { toolCatalog } from "./mcp/tools.ts";
import type { ToolContext } from "./mcp/handlers.ts";
import { mcpRouter } from "./mcp/server.ts";
import { restRouter } from "./mcp/rest.ts";
import { revokeClientGrants } from "./oauth/adapter.ts";
import { DEFAULT_REDIRECT_HOSTS } from "./oauth/clients.ts";
import { CONNECTOR_CALLBACK_PATH, interactionRouter, sourceOf } from "./oauth/interaction.ts";
import { loadAuthServerKeys, publicJwks } from "./oauth/keys.ts";
import { metadataRouter } from "./oauth/metadata.ts";
import type { OidcRelyingParty } from "./oauth/oidc.ts";
import { OidcSignIn } from "./oauth/oidc-signin.ts";
import { OAUTH_SCOPES, ROUTES, createAuthServer } from "./oauth/provider.ts";
import type { AuthServer, AuthServerOptions } from "./oauth/provider.ts";
import { ResourceGuard } from "./oauth/resource.ts";
import { BindingState, sha256b64u } from "./oauth/state.ts";
import { sourcePrefix } from "./oauth/sources.ts";
import type { BindingStore } from "./oauth/state.ts";
import { MemoryWindows } from "./core/windows.ts";
import { EventFolder } from "./core/security-events.ts";
import type { Windows } from "./core/windows.ts";
import { WEB_CALLBACK_PATH, webRouter } from "./web/app.ts";
import { relyingParty } from "./web/passkeys.ts";
import { CSS, html, sendPage } from "./web/html.ts";

export interface BrokerServerOptions {
  broker: Broker;
  /** The public origin clients use (a tunnel URL in a test with real agents), no trailing slash. It is the OAuth issuer. */
  publicUrl: string;
  /** Bind address for both listeners. Default 127.0.0.1. */
  host?: string;
  port: number;
  /** Loopback port of the person's web view. Omit to run without it. */
  webPort?: number;
  /**
   * Bind address of the web view. Default 127.0.0.1. Inside a container, 0.0.0.0 with the port published only on the
   * host's loopback (`-p 127.0.0.1:8081:8081`); the view still answers only to loopback host names.
   */
  webHost?: string;
  /** Binding state and authorization-server keys go here; omit for memory only. */
  dataDir?: string;
  /** The client binding's state (authorization server, tokens, web sessions, invites, passkeys). Default: binding.json in dataDir, or memory. */
  bindingStore?: BindingStore;
  /** The authorization server's keys (a hosted broker reads them from its environment). Default: dataDir, or generated. */
  authKeys?: Awaited<ReturnType<typeof loadAuthServerKeys>>;
  /** Rate and replay windows (failed sign-ins, registrations, metadata fetches, web requests). Default: this process's memory. */
  windows?: Windows;
  /**
   * Serve the person's web view on the public origin, behind invites and passkeys, instead of on a loopback port (a
   * hosted broker). `identity` should then be an InviteIdentityVerifier. Default: off.
   */
  publicWeb?: { rpName?: string; postsPerMinute?: number };
  identity: IdentityVerifier;
  /** "dev" (the default): the dev IdP's test identities. "oidc": the organization's identity provider (`oidc`). */
  idpMode?: "dev" | "oidc";
  /** OIDC mode: the relying party for the organization's identity provider (src/oauth/oidc.ts). */
  oidc?: OidcRelyingParty;
  /** The dev sign-in requires the per-session secret (the identity verifier holds it). */
  requireSecret?: boolean;
  /**
   * What the dev sign-in's secret is, for the pages' words: one session secret for every test identity (`npm run dev`,
   * the default), or each test identity's own sign-in secret (`npm start`).
   */
  secretKind?: "session" | "personal";
  /** The broker's private org policies (the same objects the Broker was given). */
  policies: () => readonly OrgPolicy[];
  notifier: Notifier;
  /** Hosts allowed in OAuth redirect URIs besides loopback. Default claude.ai, chatgpt.com. `*` allows any https host. */
  redirectHosts?: string[];
  requireApplicationType?: boolean;
  /** Pre-registered OAuth clients (client metadata as RFC 7591 names it, with client_id and, for confidential ones, client_secret). */
  staticClients?: AuthServerOptions["staticClients"];
  accessTokenTtlSeconds?: number;
  grantDays?: { organization: number; other: number };
  patMaxDays?: { organization: number; other: number };
  /** Origins a browser-based MCP client may send (the public origin is always allowed). */
  allowedOrigins?: string[];
  /** Dynamic registrations may use only the platforms' published callbacks or loopback (default true). */
  dcrExactCallbacks?: boolean;
  /** Dynamic registrations per source address per hour, and dynamically registered clients kept in all (defaults 20 and 500). */
  dcrLimits?: { perSourcePerHour: number; total: number };
  /** POSTs to the connector sign-in page per source per minute (default 120; an IPv6 /64 counts as one source). */
  connectorPostsPerMinute?: number;
  /** Replaces the authorization server's outbound fetch (tests serve client metadata documents with it). */
  fetch?: AuthServerOptions["fetch"];
  /** Client ID metadata document fetch limits (defaults in CIMD_LIMITS). */
  cimdLimits?: AuthServerOptions["cimdLimits"];
  /**
   * The public listener is reached only through Cloudflare (a tunnel), so per-source limits may use Cloudflare's
   * `CF-Connecting-IP`. Leave it off anywhere else: any client could send that header.
   */
  behindCloudflare?: boolean;
  /**
   * The request header a hosting platform sets to the client's address (for example `x-real-ip` on Vercel), for
   * per-source limits. Set it only when every request reaches the broker through that platform.
   */
  clientIpHeader?: string;
  /**
   * Of a list-valued `clientIpHeader` (X-Forwarded-For), the entry this many from the right is the client's (default 1,
   * the right-most): the number of proxies in front that append to it.
   */
  trustedProxyHops?: number;
  extraPublicRoutes?: Router[];
  /**
   * Plain Node handlers mounted on the public app before everything else (no body parser has run), by exact path:
   * the federation inbox and JWKS (`FederationServer.handler()`).
   */
  rawRoutes?: { paths: string[]; handle: (req: IncomingMessage, res: ServerResponse) => void }[];
  log?: (line: string) => void;
  now?: () => Date;
}

export interface RunningBrokerServer {
  publicUrl: string;
  /** http://127.0.0.1:<webPort>/web when the web view runs. */
  webUrl?: string;
  mcpUrl: string;
  restUrl: string;
  /** OIDC mode: the redirect URIs to register at the identity provider (the connector's, and the web view's). */
  oidcRedirectUris?: { connector: string; web?: string };
  auth: AuthServer;
  state: BindingStore;
  publicApp: Express;
  close(): Promise<void>;
}

function listen(app: Express, port: number, host: string): Promise<HttpServer> {
  return new Promise((resolve, reject) => {
    const s = app.listen(port, host);
    s.once("listening", () => resolve(s));
    s.once("error", reject);
  });
}

function closeServer(s: HttpServer): Promise<void> {
  return new Promise((resolve) => {
    s.close(() => resolve());
    s.closeAllConnections();
  });
}

/**
 * Stops a broker process (SIGINT, SIGTERM) in order: its listeners first, so no new call starts; then the work the
 * broker handed out after answering (`Broker.settled`: the person's notices, those that waited for quiet hours to end
 * included, and the pushes to agents), for at most `graceMs`; then its stores. Closing the stores or exiting before
 * that work ends would drop it.
 */
export async function stopBroker(parts: { running: { close(): Promise<void> }; broker: { settled(): Promise<void> }; stores?: { close(): Promise<void> }[]; graceMs?: number }): Promise<void> {
  await parts.running.close();
  let timer: NodeJS.Timeout | undefined;
  const grace = new Promise<void>((done) => {
    timer = setTimeout(done, parts.graceMs ?? 10_000);
  });
  await Promise.race([parts.broker.settled(), grace]);
  clearTimeout(timer);
  for (const s of parts.stores ?? []) await s.close();
}

/**
 * The broker's public origin, checked: https, or http on loopback (for tests and `npm run dev`); an origin, with no
 * path, query or fragment. `name` says where the value came from, for the error (`PUBLIC_URL`, the configuration's `id`).
 */
export function normalizePublicUrl(raw: string, name = "the public URL"): string {
  const u = URL.parse(raw);
  if (!u) throw new Error(`${name} isn't a URL`);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname))) {
    throw new Error(`${name} must be https:// (or http:// on loopback for local tests)`);
  }
  if (u.pathname !== "/" || u.search || u.hash) throw new Error(`${name} is an origin: no path, query or fragment`);
  return u.origin;
}

export async function startBrokerServer(opts: BrokerServerOptions): Promise<RunningBrokerServer> {
  const log = opts.log ?? (() => undefined);
  const now = opts.now ?? (() => new Date());
  const publicUrl = normalizePublicUrl(opts.publicUrl, "publicUrl");
  const host = opts.host ?? "127.0.0.1";
  const state: BindingStore = opts.bindingStore ?? (opts.dataDir ? BindingState.file(opts.dataDir) : BindingState.memory());
  const keys = opts.authKeys ?? (await loadAuthServerKeys(opts.dataDir));
  const windows = opts.windows ?? new MemoryWindows();
  if (opts.publicWeb && new URL(publicUrl).protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(new URL(publicUrl).hostname)) {
    throw new Error("the public web view needs an https PUBLIC_URL");
  }
  const resources = { mcp: `${publicUrl}/mcp`, rest: `${publicUrl}/rest` };
  const grantDays = opts.grantDays ?? { organization: 30, other: 90 };
  const isOrganizationDomain = (domain: string): boolean => opts.policies().some((p) => p.domains.includes(domain));
  const idpMode = opts.idpMode ?? "dev";
  const source = (req: IncomingMessage): string => sourceOf(req, opts.behindCloudflare === true, opts.clientIpHeader, opts.trustedProxyHops ?? 1);
  if (idpMode === "oidc" && !opts.oidc) throw new Error("idpMode \"oidc\" needs the OIDC relying party (oidc)");
  // The public web view signs people in by invite and passkey; signing in there through the organization's identity
  // provider isn't built, so the two can't be combined yet.
  if (idpMode === "oidc" && opts.publicWeb) throw new Error("the public web view signs people in by invite and passkey: it can't be combined with OIDC sign-in yet");
  // OIDC: login transactions and provider sessions live in the binding state; their secrets are sealed under a key
  // derived from the authorization server's first cookie key, and opened with any of its cookie keys (a rotation keeps
  // the old ones after the new one).
  const oidcSignIn = idpMode === "oidc" && opts.oidc ? new OidcSignIn({ rp: opts.oidc, state, secret: keys.cookieKeys, windows, log }) : undefined;
  const webOrigin = opts.webPort !== undefined ? `http://127.0.0.1:${opts.webPort}` : undefined;
  const oidcRedirectUris = oidcSignIn ? { connector: `${publicUrl}${CONNECTOR_CALLBACK_PATH}`, ...(webOrigin ? { web: `${webOrigin}${WEB_CALLBACK_PATH}` } : {}) } : undefined;

  const auth = createAuthServer({
    broker: opts.broker,
    state,
    keys,
    issuer: publicUrl,
    resources,
    redirectPolicy: { hosts: opts.redirectHosts ?? DEFAULT_REDIRECT_HOSTS },
    requireApplicationType: opts.requireApplicationType ?? true,
    ...(opts.dcrExactCallbacks !== undefined ? { dcrExactCallbacks: opts.dcrExactCallbacks } : {}),
    ...(opts.staticClients ? { staticClients: opts.staticClients } : {}),
    isOrganizationDomain,
    accessTokenTtlSeconds: opts.accessTokenTtlSeconds ?? 600,
    grantDays,
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
    ...(opts.cimdLimits ? { cimdLimits: opts.cimdLimits } : {}),
    isListedClient: (clientId: string) => opts.policies().some((p) => p.clients?.allowed.some((c) => c.client_id === clientId) === true),
    sourceOf: source,
    ...(oidcSignIn && opts.oidc?.settings.refreshCheck ? { refreshCheck: (grantId: string, principal: Parameters<OidcSignIn["recheck"]>[1]) => oidcSignIn.recheck(grantId, principal, opts.broker) } : {}),
    ...(oidcSignIn ? { onGrantRevoked: (grantId: string) => void oidcSignIn.forgetSession(grantId) } : {}),
    windows,
    log,
  });
  // A refused bearer token is one event per reason and client per minute, plus one with the count of the rest: a client
  // sending many bad tokens would otherwise write one synchronous event per request.
  const refusals = new EventFolder();
  const guard = new ResourceGuard({
    broker: opts.broker,
    state,
    issuer: publicUrl,
    resources,
    jwks: publicJwks(keys),
    onRefused: (reason, clientId) => {
      refusals.note(`${reason}|${clientId ?? ""}`, (count) => {
        void opts.broker.recordSecurityEvent("token_refused", { failed: true, message: reason, details: { ...(clientId ? { client_id: clientId.slice(0, 2048) } : {}), ...(count ? { count } : {}) } });
      });
    },
  });
  const tools: ToolContext = { broker: opts.broker, state, catalog: toolCatalog(), policies: opts.policies, notifier: opts.notifier, now, log };
  // Browser Origins the MCP endpoint accepts (requests without Origin pass): its own, and the web origins of the agent
  // platforms whose callback hosts are allowed (in case a platform's own requests carry one).
  const redirectHosts = opts.redirectHosts ?? DEFAULT_REDIRECT_HOSTS;
  const allowedOrigins = [publicUrl, ...redirectHosts.filter((h) => h !== "*").map((h) => `https://${h}`), ...(opts.allowedOrigins ?? [])];
  const mcp = mcpRouter({ tools, guard, resource: resources.mcp, allowedOrigins, log });

  // ---- the public app
  const app = express();
  app.disable("x-powered-by");
  const pub = new URL(publicUrl);
  // Health checks, before the request log (a container or load balancer asks every few seconds). /healthz: the process
  // serves; /readyz: a cheap read of the broker's store answers. Nothing else in either body.
  app.get("/healthz", (_req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    res.status(200).json({ status: "ok", security_events_dropped: opts.broker.securityEventsDropped() });
  });
  app.get("/readyz", (_req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    opts.broker.store.getPrincipalById("readiness-probe").then(
      () => res.status(200).json({ status: "ready" }),
      () => res.status(503).json({ status: "unavailable" }),
    );
  });
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Absolute URLs come from PUBLIC_URL, whatever the tunnel or a local client put in Host.
    req.headers["x-forwarded-proto"] = pub.protocol.slice(0, -1);
    req.headers["x-forwarded-host"] = pub.host;
    const started = Date.now();
    res.on("finish", () => log(`${req.method} ${req.path} ${res.statusCode} ${Date.now() - started}ms`));
    next();
  });
  for (const raw of opts.rawRoutes ?? []) {
    app.use((req: Request, res: Response, next: NextFunction) => {
      if (raw.paths.includes(req.path)) raw.handle(req, res);
      else next();
    });
  }
  app.get("/static/alp.css", (_req, res) => {
    res.type("text/css").setHeader("Cache-Control", "no-store");
    res.send(CSS);
  });
  app.get("/", (_req, res) => {
    sendPage(res, "Broker", html`<h1>${PROTOCOL.shortName} broker</h1><div class="card"><p>Connector URL for agents: <code>${resources.mcp}</code></p><p class="muted">REST mirror: <code>${resources.rest}</code> (OpenAPI at <code>${resources.rest}/openapi.json</code>).</p></div>`);
  });
  app.use(metadataRouter({ issuer: publicUrl, resources, provider: auth.provider }));
  app.use(interactionRouter({
    broker: opts.broker,
    auth,
    identity: opts.identity,
    idpMode,
    ...(oidcSignIn && oidcRedirectUris ? { oidc: { signIn: oidcSignIn, callbackUri: oidcRedirectUris.connector, secureCookies: pub.protocol === "https:" } } : {}),
    requireSecret: opts.requireSecret ?? false,
    secretKind: opts.secretKind ?? "session",
    // Derived from the authorization server's cookie keys, so every instance of a hosted broker accepts the form any
    // instance rendered.
    csrfKey: createHmac("sha256", keys.cookieKeys[0] ?? "").update("alp-interaction-csrf").digest(),
    grantDays,
    isOrganizationDomain,
    policies: opts.policies,
    sourceOf: source,
    windows,
    ...(opts.publicWeb ? { passkeys: { rp: relyingParty(publicUrl, opts.publicWeb.rpName ?? `${PROTOCOL.shortName} broker`), store: state } } : {}),
    ...(opts.connectorPostsPerMinute !== undefined ? { postsPerMinute: opts.connectorPostsPerMinute } : {}),
    log,
  }));
  app.use(mcp.router);
  app.use(restRouter({ tools, guard, resource: resources.rest }));
  for (const r of opts.extraPublicRoutes ?? []) app.use(r);
  const webOptions = {
    broker: opts.broker,
    state,
    identity: opts.identity,
    idpMode,
    requireSecret: opts.requireSecret ?? false,
    secretKind: opts.secretKind ?? "session",
    patMaxDays: opts.patMaxDays ?? grantDays,
    isOrganizationDomain,
    // Disconnecting an agent revokes its OAuth grants, and forgets the identity-provider session kept for each (OIDC).
    revokeClientGrants: async (principalId: string, clientId: string) => {
      for (const grantId of await revokeClientGrants(state, principalId, clientId)) await oidcSignIn?.forgetSession(grantId);
    },
    now,
    log,
    windows,
  };
  if (opts.publicWeb) {
    // A hosted broker: the person's page on the public origin, behind invites and passkeys.
    app.use(webRouter({
      ...webOptions,
      secureCookies: true,
      public: { origin: publicUrl, rpName: opts.publicWeb.rpName ?? `${PROTOCOL.shortName} broker`, notifier: opts.notifier, sourceOf: source, ...(opts.publicWeb.postsPerMinute ? { postsPerMinute: opts.publicWeb.postsPerMinute } : {}) },
    }));
  } else {
    app.use("/web", (_req, res) => {
      res.status(404).type("text").send("Not found");
    });
  }
  // A client that asks for no resource scope (none, OpenID scopes only, or its own words such as `claudeai`) gets
  // `read send` by default (RFC 6749 3.3): the consent page lists them, and the token can call the tools.
  app.get(ROUTES.authorization, (req: Request, _res: Response, next: NextFunction) => {
    const u = new URL(req.url, publicUrl);
    const asked = (u.searchParams.get("scope") ?? "").split(" ").filter(Boolean);
    if (!asked.includes("read") && !asked.includes("send")) {
      u.searchParams.set("scope", [...asked, ...OAUTH_SCOPES].join(" "));
      req.url = `${u.pathname}${u.search}`;
    }
    next();
  });
  // Dynamic registration (spec 5.6.4): limited per source address and in total, and scope values this server doesn't
  // support are dropped rather than failing the registration.
  const dcr = opts.dcrLimits ?? { perSourcePerHour: 20, total: 500 };
  app.post(ROUTES.registration, express.json({ limit: "16kb" }), (req: Request, res: Response, next: NextFunction) => {
    (async () => {
      const now = new Date();
      const refuse = (): void => {
        log("oauth: refused a dynamic registration (rate or total limit)");
        res.status(429).setHeader("Retry-After", "3600").json({ error: "invalid_client_metadata", error_description: "too many registrations; try again later" });
      };
      // Unused registrations expire (oauth/adapter.ts), so the total counts live ones.
      if ((await state.oidcCount("Client", now.getTime())) >= dcr.total) return refuse();
      // Per source, an IPv6 /64 counting as one.
      if (!(await windows.hitRateLimit(`dcr|${sha256b64u(sourcePrefix(source(req)))}`, now, 3600, dcr.perSourcePerHour)).allowed) return refuse();
      const body = req.body as Record<string, unknown> | undefined;
      if (body && typeof body["scope"] === "string") {
        const supported = new Set(["openid", "offline_access", "email", "profile", ...OAUTH_SCOPES]);
        const kept = body["scope"].split(" ").filter((x) => supported.has(x));
        if (kept.length) body["scope"] = kept.join(" ");
        else delete body["scope"];
      }
      next();
    })().catch(next);
  });
  app.use(auth.provider.callback());
  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    log(`http: ${err instanceof Error ? err.message : String(err)}`);
    if (!res.headersSent) res.status(500).json({ error: "internal" });
  });

  const servers: HttpServer[] = [await listen(app, opts.port, host)];

  // ---- the person's web view (loopback), unless it is on the public origin
  let webUrl: string | undefined;
  if (opts.webPort !== undefined && !opts.publicWeb) {
    const web = express();
    web.disable("x-powered-by");
    web.use((req: Request, res: Response, next: NextFunction) => {
      const started = Date.now();
      res.on("finish", () => log(`web ${req.method} ${req.path} ${res.statusCode} ${Date.now() - started}ms`));
      next();
    });
    web.get("/", (_req, res) => res.redirect(302, "/web"));
    web.use(webRouter({
      ...webOptions,
      ...(oidcSignIn && webOrigin && oidcRedirectUris?.web ? { oidc: { signIn: oidcSignIn, origin: webOrigin, callbackUri: oidcRedirectUris.web } } : {}),
      secureCookies: false,
    }));
    web.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
      log(`web: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.headersSent) res.status(500).type("text").send("Something went wrong.");
    });
    try {
      servers.push(await listen(web, opts.webPort, opts.webHost ?? "127.0.0.1"));
    } catch (err) {
      await closeServer(servers[0] as HttpServer);
      throw err;
    }
    webUrl = `http://127.0.0.1:${opts.webPort}/web`;
  }
  if (opts.publicWeb) webUrl = `${publicUrl}/web`;
  // Notifications that waited for a grant's quiet hours to end go out within a minute of it (spec 6.7).
  const stopNotices = opts.broker.startNoticeTimer();

  return {
    publicUrl,
    ...(webUrl ? { webUrl } : {}),
    mcpUrl: resources.mcp,
    restUrl: resources.rest,
    ...(oidcRedirectUris ? { oidcRedirectUris } : {}),
    auth,
    state,
    publicApp: app,
    close: async () => {
      stopNotices();
      await mcp.close();
      await Promise.all(servers.map(closeServer));
      refusals.flush();
    },
  };
}

