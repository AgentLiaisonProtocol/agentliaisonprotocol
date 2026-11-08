// SPDX-License-Identifier: FSL-1.1-ALv2
// Test support for the client binding: a running dev broker on loopback ports from the tests' pool (47120-47149,
// checked free first; the federation tests own 47150-47165, the demos 47166-47176 and 47180-47185, the dev broker
// 47110-47111; ALP_TEST_PORT_BASE moves the pool and the federation tests' ports together, src/test-ports.ts), a small
// browser that signs in on the connector page, and an OAuth client provider for the MCP SDKs. Not a test file itself.

import { join } from "node:path";
import { createPrivateKeyJwtAuth } from "@modelcontextprotocol/client";
import type { AddClientAuthentication, OAuthClientInformationMixed, OAuthClientMetadata, OAuthClientProvider, OAuthDiscoveryState, OAuthTokens } from "@modelcontextprotocol/client";
import { MemorySecurityEvents } from "../core/security-events.ts";
import { createDevBroker } from "../dev-world.ts";
import type { DevBroker } from "../dev-world.ts";
import { startBrokerServer } from "../server.ts";
import type { BrokerServerOptions, RunningBrokerServer } from "../server.ts";
import { freePorts } from "../test-ports.ts";
import { ConsoleOutboxNotifier } from "../web/notifier.ts";

export { freePorts };

export const TEST_SECRET = "test-session-secret";

export interface TestBroker {
  dev: DevBroker;
  server: RunningBrokerServer;
  events: MemorySecurityEvents;
  notifier: ConsoleOutboxNotifier;
  base: string;
  web: string;
  close(): Promise<void>;
}

/** `world.dataDir`: the file store and the binding state go there (a restart reads them back); default memory only. */
export async function startTestBroker(extra: Partial<BrokerServerOptions> = {}, world: { dataDir?: string } = {}): Promise<TestBroker> {
  // Another test process may take a port between the check and the listen: try again with the next ones.
  for (let attempt = 0; ; attempt++) {
    const [port, webPort] = extra.port !== undefined && extra.webPort !== undefined ? [extra.port, extra.webPort] : await freePorts(2);
    if (port === undefined || webPort === undefined) throw new Error("ports");
    const base = `http://127.0.0.1:${port}`;
    const events = new MemorySecurityEvents();
    const notifier = new ConsoleOutboxNotifier();
    const dev = await createDevBroker({ ...(world.dataDir ? { dataDir: world.dataDir } : {}), webBaseUrl: `http://127.0.0.1:${webPort}/web`, notifier, securityEvents: events, secret: TEST_SECRET });
    try {
      const server = await startBrokerServer({
        broker: dev.broker,
        publicUrl: base,
        port,
        webPort,
        identity: dev.identity,
        idpMode: "dev",
        requireSecret: true,
        policies: () => dev.policies,
        notifier,
        ...(world.dataDir ? { dataDir: join(world.dataDir, "binding") } : {}),
        ...extra,
      });
      return { dev, server, events, notifier, base, web: `http://127.0.0.1:${webPort}`, close: async () => {
        await server.close();
        await dev.store.close();
      } };
    } catch (err) {
      if (attempt >= 4 || !(err instanceof Error) || !/EADDRINUSE/.test(err.message)) throw err;
    }
  }
}

/** A cookie jar good enough for the broker's own pages (path-scoped cookies, no domains). */
export class Browser {
  private readonly cookies = new Map<string, { value: string; path: string }>();

  /** A cookie's current value (tests check that the server never stores it). */
  cookieValue(name: string): string | undefined {
    return this.cookies.get(name)?.value;
  }

  private cookieHeader(url: URL): string {
    return [...this.cookies.entries()].filter(([, c]) => url.pathname.startsWith(c.path)).map(([k, c]) => `${k}=${c.value}`).join("; ");
  }

  private remember(res: Response): void {
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(";");
      if (!pair) continue;
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const path = attrs.map((a) => a.trim()).find((a) => a.toLowerCase().startsWith("path="))?.slice(5) ?? "/";
      const expired = attrs.some((a) => /max-age=0/i.test(a.trim())) || attrs.some((a) => /expires=thu, 01 jan 1970/i.test(a.trim()));
      if (expired) this.cookies.delete(name);
      else this.cookies.set(name, { value, path });
    }
  }

  async request(url: string, init: { method?: string; form?: Record<string, string | string[]>; headers?: Record<string, string> } = {}): Promise<Response> {
    const u = new URL(url);
    const headers: Record<string, string> = { ...(init.headers ?? {}) };
    const cookie = this.cookieHeader(u);
    if (cookie) headers["cookie"] = cookie;
    let body: string | undefined;
    if (init.form) {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(init.form)) for (const x of Array.isArray(v) ? v : [v]) p.append(k, x);
      body = p.toString();
      headers["content-type"] = "application/x-www-form-urlencoded";
    }
    const res = await fetch(u, { method: init.method ?? (init.form ? "POST" : "GET"), headers, redirect: "manual", ...(body !== undefined ? { body } : {}) });
    this.remember(res);
    return res;
  }

  /** Follow redirects on the broker's own origin; stop at the first redirect elsewhere (the client's callback). */
  async follow(start: Response, origin: string, max = 10): Promise<{ res: Response; location?: string }> {
    let res = start;
    for (let i = 0; i < max; i++) {
      if (res.status < 300 || res.status >= 400) return { res };
      const loc = res.headers.get("location");
      if (!loc) return { res };
      const next = new URL(loc, res.url || origin);
      if (next.origin !== new URL(origin).origin) return { res, location: next.href };
      res = await this.request(next.href);
    }
    throw new Error("too many redirects");
  }
}

export function csrfFrom(page: string): string {
  const m = /name="csrf" value="([^"]+)"/.exec(page);
  if (!m?.[1]) throw new Error("no csrf token on the page");
  return m[1];
}

/** Drive the connector sign-in page: open the authorization URL, sign in as `username`, return the client callback URL. */
export async function signInAndAllow(authorizationUrl: string, username: string, opts: { secret?: string; label?: string; browser?: Browser } = {}): Promise<URL> {
  const b = opts.browser ?? new Browser();
  const origin = new URL(authorizationUrl).origin;
  const first = await b.follow(await b.request(authorizationUrl), origin);
  if (first.location) return new URL(first.location);
  const pageUrl = first.res.url || "";
  const html = await first.res.text();
  if (first.res.status !== 200) throw new Error(`sign-in page answered ${first.res.status}: ${html.slice(0, 300)}`);
  const action = /<form method="post" action="([^"]+)"/.exec(html)?.[1];
  if (!action) throw new Error(`no sign-in form at ${pageUrl}`);
  const form: Record<string, string> = { csrf: csrfFrom(html), username, secret: opts.secret ?? TEST_SECRET, action: "allow" };
  if (html.includes('name="label"')) form["label"] = opts.label ?? "agent";
  const posted = await b.request(new URL(action, origin).href, { form });
  const done = await b.follow(posted, origin);
  if (!done.location) throw new Error(`sign-in didn't return to the client (status ${done.res.status}): ${(await done.res.text()).slice(0, 300)}`);
  return new URL(done.location);
}

/** An OAuthClientProvider for the MCP SDK (v2 and v1 share the shape) that records the authorization URL. */
export class TestOAuthClient implements OAuthClientProvider {
  readonly redirect: string;
  private info: OAuthClientInformationMixed | undefined;
  private saved: OAuthTokens | undefined;
  private verifier = "";
  private discovery: OAuthDiscoveryState | undefined;
  lastAuthorizationUrl: URL | undefined;
  readonly metadata: OAuthClientMetadata;
  readonly clientMetadataUrl: string | undefined;
  /** Set for a client that authenticates at the token endpoint with private_key_jwt (its metadata document says so). */
  readonly addClientAuthentication?: AddClientAuthentication;

  /**
   * `preRegistered`: a confidential client the broker's operator registered (client_secret_basic), so the SDK neither
   * registers nor uses a metadata document. `issuer` is the authorization server it was issued by (the SDK checks it).
   * `privateKeyJwt`: a client ID metadata document client that signs a client assertion with this key (private_key_jwt).
   */
  constructor(opts: { name: string; redirect?: string; clientMetadataUrl?: string; applicationType?: string; preRegistered?: { client_id: string; client_secret: string; issuer: string }; privateKeyJwt?: { jwk: Record<string, unknown>; alg: string } }) {
    this.redirect = opts.redirect ?? "http://127.0.0.1:47199/callback";
    this.clientMetadataUrl = opts.preRegistered ? undefined : opts.clientMetadataUrl;
    if (opts.preRegistered) this.info = { client_id: opts.preRegistered.client_id, client_secret: opts.preRegistered.client_secret, issuer: opts.preRegistered.issuer } as OAuthClientInformationMixed;
    if (opts.privateKeyJwt && opts.clientMetadataUrl) {
      this.addClientAuthentication = createPrivateKeyJwtAuth({ issuer: opts.clientMetadataUrl, subject: opts.clientMetadataUrl, privateKey: opts.privateKeyJwt.jwk, alg: opts.privateKeyJwt.alg });
    }
    this.metadata = {
      client_name: opts.name,
      redirect_uris: [this.redirect],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: opts.preRegistered ? "client_secret_basic" : opts.privateKeyJwt ? "private_key_jwt" : "none",
      ...(opts.applicationType !== undefined ? { application_type: opts.applicationType } : { application_type: "native" }),
    } as OAuthClientMetadata;
  }

  get redirectUrl(): string {
    return this.redirect;
  }
  get clientMetadata(): OAuthClientMetadata {
    return this.metadata;
  }
  clientInformation(): OAuthClientInformationMixed | undefined {
    return this.info;
  }
  saveClientInformation(info: OAuthClientInformationMixed): void {
    this.info = info;
  }
  tokens(): OAuthTokens | undefined {
    return this.saved;
  }
  saveTokens(tokens: OAuthTokens): void {
    this.saved = tokens;
  }
  redirectToAuthorization(url: URL): void {
    this.lastAuthorizationUrl = url;
  }
  saveCodeVerifier(v: string): void {
    this.verifier = v;
  }
  codeVerifier(): string {
    return this.verifier;
  }
  saveDiscoveryState(state: OAuthDiscoveryState): void {
    this.discovery = state;
  }
  discoveryState(): OAuthDiscoveryState | undefined {
    return this.discovery;
  }
}
