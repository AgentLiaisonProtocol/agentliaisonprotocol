// SPDX-License-Identifier: FSL-1.1-ALv2
// Test support for OIDC sign-in. Not a test file itself.
//
// - A stand-in for the organization's identity provider: a standard OpenID provider (oidc-provider itself, configured
//   as an issuer) running in this process on a loopback port from the test pool. Its issuer is a fictional https
//   name (RFC 2606), which the broker reaches through the hardened fetcher's development host map, exactly as it
//   reaches any provider in production but over loopback. An Entra-shaped issuer (https://<host>/<tenant-id>/v2.0)
//   is served under its path, like Entra's per-tenant endpoints. Users sign in on a plain login form.
// - Hooks a test needs: a token-response hook that rewrites the ID token's claims and re-signs it with the provider's
//   own key (a wrong issuer, audience, nonce or tenant, an expired token, a groups overage), extra documents (Entra's
//   multi-tenant discovery document), the authorization requests it saw, the scope each token request named (and,
//   as Entra's token endpoint may, a refusal of one that names none), a refresh's ID token unsigned or left out, a
//   canned answer from the token endpoint (a throttle, a busy provider, a rejected client secret), and disabling a
//   user.
// - A browser that keeps cookies per host and path and applies SameSite as browsers do (Strict only when the whole
//   navigation stayed on one site; Lax also on cross-site top-level GETs), so the tests exercise the same cookie rules
//   a person's browser applies on the provider's redirects.

import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import Provider from "oidc-provider";
import type { Configuration, KoaContextWithOIDC } from "oidc-provider";
import { SignJWT, decodeJwt, exportJWK, generateKeyPair, importJWK } from "jose";
import type { JWK, JWTPayload } from "jose";
import { onFreePorts } from "../test-ports.ts";
import { StateAdapter } from "./adapter.ts";
import { BindingState } from "./state.ts";

export interface IdpUser {
  /** The provider's subject for this user. */
  sub: string;
  /** Claims the provider asserts (email, email_verified, name, preferred_username, tid, oid, roles, groups...). */
  claims: Record<string, unknown>;
  disabled?: boolean;
}

export interface StandInIdpOptions {
  /** https://idp.example, or an Entra-shaped https://login.idp.example/<tenant-id>/v2.0. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Loopback redirect URIs match whatever their port (RFC 8252; the client is registered as a native one). */
  redirectUris: string[];
  postLogoutRedirectUris?: string[];
  tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post";
  /**
   * Refuse a token request that names no `scope` (400 invalid_request, AADSTS900144), as Microsoft Entra's v2.0 token
   * endpoint has been reported to, on the code exchange and on a refresh alike.
   */
  requireTokenScope?: boolean;
  /** Users by login name. */
  users: Record<string, IdpUser>;
}

export interface StandInIdp {
  issuer: string;
  /** The issuer's origin (https://...), and the loopback base that serves it. */
  origin: string;
  base: string;
  /** For the broker's hardened fetcher. */
  devHosts: Record<string, string>;
  users: Record<string, IdpUser>;
  /** Rewrites the ID token of token responses (re-signed with the provider's key) while set. */
  tamper: ((claims: JWTPayload) => JWTPayload) | null;
  /** Query parameters of the authorization requests the provider received. */
  authorizations: URLSearchParams[];
  /** Token requests the provider answered, by grant type. */
  tokenRequests: Record<string, number>;
  /** The `scope` each token request named (undefined: none), in order, refused ones included. */
  tokenScopes: { grant_type: string; scope: string | undefined }[];
  /** While set, the token endpoint's only answer (Entra's shape: `error`, `error_description`, `error_codes`). */
  tokenFailure: { status: number; body: Record<string, unknown> } | null;
  /**
   * The ID token of refresh responses: as issued (the default), unsigned (`alg: none`, as Microsoft's documentation
   * describes Entra's refreshed ID token), or left out.
   */
  refreshIdToken: "signed" | "unsigned" | "omitted";
  /** Documents served at extra paths (Entra's multi-tenant discovery document). */
  extraDocs: Record<string, unknown>;
  /** Signs claims with the provider's own key, or another key (an attacker's). */
  sign(claims: JWTPayload, key?: { jwk: JWK; kid: string; alg?: string }): Promise<string>;
  /** Fetches one of the provider's own documents, as the broker sees it. */
  document(path: string): Promise<Record<string, unknown>>;
  close(): Promise<void>;
}

export async function startStandInIdp(opts: StandInIdpOptions): Promise<StandInIdp> {
  const issuerUrl = new URL(opts.issuer);
  const mount = issuerUrl.pathname.replace(/\/$/, "");
  // The loopback base, set once the server listens on a port from the tests' pool (below).
  let base = "http://127.0.0.1";
  const { privateKey } = await generateKeyPair("RS256", { extractable: true, modulusLength: 2048 });
  const privateJwk: JWK = { ...(await exportJWK(privateKey)), kid: "stand-in-idp-1", alg: "RS256", use: "sig" };
  const signingKey = await importJWK(privateJwk, "RS256");

  const idp: StandInIdp = {
    issuer: opts.issuer,
    origin: issuerUrl.origin,
    base,
    devHosts: {},
    users: opts.users,
    tamper: null,
    authorizations: [],
    tokenRequests: {},
    tokenScopes: [],
    tokenFailure: null,
    refreshIdToken: "signed",
    extraDocs: {},
    sign: async (claims, key) => {
      const k = key ? await importJWK(key.jwk, key.alg ?? "RS256") : signingKey;
      return new SignJWT(claims).setProtectedHeader({ alg: key?.alg ?? "RS256", kid: key?.kid ?? "stand-in-idp-1" }).sign(k);
    },
    document: async (path) => (await (await fetch(`${idp.base}${path}`)).json()) as Record<string, unknown>,
    close: async () => undefined,
  };

  const userBySub = (sub: string): IdpUser | undefined => Object.values(idp.users).find((u) => u.sub === sub);
  const store = BindingState.memory();
  const configuration: Configuration = {
    clients: [
      {
        client_id: opts.clientId,
        client_secret: opts.clientSecret,
        redirect_uris: opts.redirectUris,
        post_logout_redirect_uris: opts.postLogoutRedirectUris ?? [],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: opts.tokenEndpointAuthMethod ?? "client_secret_basic",
        // Loopback callbacks on any port: the broker under test listens on whatever ports the test pool gives it.
        application_type: "native",
        // As Entra does with the auth_time optional claim: every ID token says when the person signed in.
        require_auth_time: true,
      },
    ],
    adapter: (name: string) => new StateAdapter(store, name),
    jwks: { keys: [privateJwk] as NonNullable<Configuration["jwks"]>["keys"] },
    cookies: { keys: ["stand-in-idp-cookie-key-test-only"] },
    // Scope claims go in the ID token (as Entra puts them there), not only in UserInfo.
    conformIdTokenClaims: false,
    claims: { openid: ["sub", "tid", "oid", "roles", "groups"], profile: ["name", "preferred_username"], email: ["email", "email_verified"] },
    scopes: ["openid", "profile", "email", "offline_access"],
    pkce: { required: () => true },
    features: { devInteractions: { enabled: false }, rpInitiatedLogout: { enabled: true } },
    interactions: { url: (_ctx: KoaContextWithOIDC, interaction) => `/idp-interaction/${interaction.uid}` },
    findAccount: async (_ctx: KoaContextWithOIDC, sub: string) => {
      const user = userBySub(sub);
      if (!user || user.disabled) return undefined;
      return { accountId: sub, claims: async () => ({ ...user.claims, sub }) };
    },
    issueRefreshToken: async (_ctx: KoaContextWithOIDC, client) => client.grantTypeAllowed("refresh_token"),
    rotateRefreshToken: true,
    ttl: { AccessToken: 600, AuthorizationCode: 60, IdToken: 3600, RefreshToken: 86400, Interaction: 600, Session: 3600, Grant: 86400 },
  };
  const provider = new Provider(opts.issuer, configuration);
  provider.proxy = true;
  provider.use(async (ctx, next) => {
    await next();
    if (ctx.oidc?.route !== "token") return;
    const body = ctx.body as Record<string, unknown> | undefined;
    const grantType = String((ctx.oidc.params as Record<string, unknown> | undefined)?.["grant_type"] ?? "");
    idp.tokenRequests[grantType] = (idp.tokenRequests[grantType] ?? 0) + 1;
    if (ctx.status === 200 && idp.tamper && body && typeof body["id_token"] === "string") {
      ctx.body = { ...body, id_token: await idp.sign(idp.tamper(decodeJwt(body["id_token"]))) };
    }
    if (ctx.status === 200 && grantType === "refresh_token" && idp.refreshIdToken !== "signed" && ctx.body) {
      const { id_token: issued, ...rest } = ctx.body as Record<string, unknown>;
      ctx.body = idp.refreshIdToken === "unsigned" && typeof issued === "string" ? { ...rest, id_token: unsignedJwt(decodeJwt(issued)) } : rest;
    }
  });

  const app = express();
  app.disable("x-powered-by");
  app.use((req, _res, next) => {
    req.headers["x-forwarded-proto"] = "https";
    req.headers["x-forwarded-host"] = issuerUrl.host;
    const u = new URL(req.url, base);
    if (u.pathname === `${mount}/auth`) idp.authorizations.push(u.searchParams);
    next();
  });
  app.get(/.*/, (req, res, next) => {
    const doc = idp.extraDocs[new URL(req.url, base).pathname];
    if (doc === undefined) return next();
    res.json(doc);
  });
  const form = express.urlencoded({ extended: false });
  // The token endpoint, before oidc-provider sees the request (it reads the body this parser leaves).
  app.post(`${mount}/token`, form, (req, res, next) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const scope = typeof body["scope"] === "string" ? body["scope"] : undefined;
    idp.tokenScopes.push({ grant_type: String(body["grant_type"] ?? ""), scope });
    if (idp.tokenFailure) {
      res.status(idp.tokenFailure.status).json(idp.tokenFailure.body);
      return;
    }
    if (opts.requireTokenScope) {
      if (scope === undefined) {
        res.status(400).json({ error: "invalid_request", error_description: "AADSTS900144: The request body must contain the following parameter: 'scope'.", error_codes: [900144] });
        return;
      }
      // The scopes then come from the grant: oidc-provider dropped offline_access at the authorization (no
      // prompt=consent), so it would refuse a refresh that names it, where Entra accepts one.
      delete body["scope"];
    }
    next();
  });
  app.get("/idp-interaction/:uid", (req, res, next) => {
    (async () => {
      const details = await provider.interactionDetails(req, res);
      res.type("html").send(`<!doctype html><title>Stand-in identity provider</title><form method="post" action="/idp-interaction/${details.uid}"><input name="login"><button>Sign in</button></form>`);
    })().catch(next);
  });
  app.post("/idp-interaction/:uid", form, (req, res, next) => {
    (async () => {
      const details = await provider.interactionDetails(req, res);
      const login = String((req.body as Record<string, unknown>)["login"] ?? "");
      const user = idp.users[login];
      if (!user || user.disabled) {
        res.status(403).type("text").send("unknown or disabled user");
        return;
      }
      const grant = new provider.Grant({ accountId: user.sub, clientId: String(details.params["client_id"]) });
      grant.addOIDCScope(String(details.params["scope"] ?? "openid"));
      const grantId = await grant.save();
      await provider.interactionFinished(req, res, { login: { accountId: user.sub }, consent: { grantId } }, { mergeWithLastSubmission: false });
    })().catch(next);
  });
  app.use(mount || "/", provider.callback());

  // Another test process may take a pooled port between the check and the listen: onFreePorts tries new ones.
  const server = await onFreePorts(1, ([port]) =>
    new Promise<Server>((resolve, reject) => {
      const s = app.listen(port ?? 0, "127.0.0.1");
      s.once("listening", () => resolve(s));
      s.once("error", reject);
    }),
  );
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  idp.base = base;
  idp.devHosts = { [issuerUrl.origin]: base };
  idp.close = () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  return idp;
}

/** An unsigned JWT (`alg: none`) carrying these claims. */
function unsignedJwt(claims: JWTPayload): string {
  const part = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString("base64url");
  return `${part({ typ: "JWT", alg: "none" })}.${part(claims)}.`;
}

// ---------------------------------------------------------------------------------------------
// A browser with per-host cookies and SameSite rules

interface Cookie {
  name: string;
  value: string;
  host: string;
  path: string;
  sameSite: "strict" | "lax" | "none";
  expires?: number;
}

export interface Visit {
  status: number;
  /** The URL that answered (after redirects on the way). */
  url: string;
  html: string;
  headers: Headers;
  /** Set when a redirect was stopped before it was followed (the agent's own callback). */
  stoppedAt?: string;
}

export class SiteBrowser {
  private cookies: Cookie[] = [];
  private readonly hostMap: Map<string, string>;
  /** The Set-Cookie lines the browser received, for assertions. */
  readonly setCookies: string[] = [];

  /** `hostMap`: published https origins (the stand-in provider's) to the loopback bases that serve them. */
  constructor(hostMap: Record<string, string> = {}) {
    this.hostMap = new Map(Object.entries(hostMap));
  }

  private transport(url: URL): string {
    const mapped = this.hostMap.get(url.origin);
    return mapped ? `${mapped}${url.pathname}${url.search}` : url.href;
  }

  private cookieHeader(url: URL, method: string, crossSite: boolean): string {
    const now = Date.now();
    this.cookies = this.cookies.filter((c) => c.expires === undefined || c.expires > now);
    return this.cookies
      .filter((c) => c.host === url.hostname)
      .filter((c) => url.pathname === c.path || url.pathname.startsWith(c.path.endsWith("/") ? c.path : `${c.path}/`))
      .filter((c) => c.sameSite === "none" || !crossSite || (c.sameSite === "lax" && method === "GET"))
      .map((c) => `${c.name}=${c.value}`)
      .join("; ");
  }

  private remember(url: URL, res: Response): void {
    for (const line of res.headers.getSetCookie()) {
      this.setCookies.push(line);
      const [pair, ...attrs] = line.split(";");
      if (!pair) continue;
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      let path = "/";
      let sameSite: Cookie["sameSite"] = "lax";
      let expires: number | undefined;
      for (const a of attrs.map((x) => x.trim())) {
        const [k, ...v] = a.split("=");
        const key = (k ?? "").toLowerCase();
        const val = v.join("=");
        if (key === "path") path = val || "/";
        else if (key === "samesite") sameSite = val.toLowerCase() === "strict" ? "strict" : val.toLowerCase() === "none" ? "none" : "lax";
        else if (key === "max-age") expires = Date.now() + Number(val) * 1000;
        else if (key === "expires" && expires === undefined) expires = Date.parse(val);
      }
      this.cookies = this.cookies.filter((c) => !(c.name === name && c.host === url.hostname && c.path === path));
      if (value !== "" && (expires === undefined || expires > Date.now())) this.cookies.push({ name, value, host: url.hostname, path, sameSite, ...(expires !== undefined ? { expires } : {}) });
    }
  }

  /**
   * A top-level navigation: the request, then its redirects, until a page answers or a redirect matches `stopAt`.
   * `from` is the page that started it (undefined: another app, such as the agent's platform, opened it).
   */
  async navigate(url: string, init: { method?: "GET" | "POST"; form?: Record<string, string | string[]>; from?: string; stopAt?: (u: URL) => boolean; autoSubmits?: number } = {}): Promise<Visit> {
    let target = new URL(url);
    let method = init.method ?? (init.form ? "POST" : "GET");
    let body: string | undefined;
    if (init.form) {
      const p = new URLSearchParams();
      for (const [k, v] of Object.entries(init.form)) for (const x of Array.isArray(v) ? v : [v]) p.append(k, x);
      body = p.toString();
    }
    // Sites seen in this navigation: the initiator's, then every URL it passed through.
    const sites = [init.from ? new URL(init.from).hostname : "elsewhere.invalid"];
    for (let hop = 0; hop < 20; hop++) {
      sites.push(target.hostname);
      const crossSite = sites.some((s) => s !== target.hostname);
      const headers: Record<string, string> = {};
      const cookie = this.cookieHeader(target, method, crossSite);
      if (cookie) headers["cookie"] = cookie;
      if (body !== undefined) headers["content-type"] = "application/x-www-form-urlencoded";
      const res = await fetch(this.transport(target), { method, headers, redirect: "manual", ...(body !== undefined ? { body } : {}) });
      this.remember(target, res);
      const loc = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && loc) {
        const next = new URL(loc, target);
        await res.arrayBuffer().catch(() => undefined);
        if (init.stopAt?.(next)) return { status: res.status, url: target.href, html: "", headers: res.headers, stoppedAt: next.href };
        // 303 (and 302 after a POST) become GETs.
        if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST")) {
          method = "GET";
          body = undefined;
        }
        target = next;
        continue;
      }
      const html = await res.text();
      // A page whose only job is to post a form by script (oidc-provider's session-change and form-post pages): a
      // browser runs the script, so this one submits the form.
      if (res.status === 200 && /document\.forms\[0\]\.submit\(\)/.test(html) && (init.autoSubmits ?? 0) < 3) {
        return this.submit({ status: res.status, url: target.href, html, headers: res.headers }, {}, { ...(init.stopAt ? { stopAt: init.stopAt } : {}), autoSubmits: (init.autoSubmits ?? 0) + 1 });
      }
      return { status: res.status, url: target.href, html, headers: res.headers };
    }
    throw new Error("too many redirects");
  }

  /** Submits the page's first form whose action matches, with its hidden fields and `fields` on top. */
  async submit(page: Visit, fields: Record<string, string | string[]>, opts: { action?: RegExp; stopAt?: (u: URL) => boolean; autoSubmits?: number } = {}): Promise<Visit> {
    const forms = [...page.html.matchAll(/<form method="post" action="([^"]+)"[^>]*>([\s\S]*?)<\/form>/g)];
    const f = forms.find((m) => (opts.action ? opts.action.test(m[1] ?? "") : true));
    if (!f || !f[1]) throw new Error(`no form on ${page.url}: ${page.html.slice(0, 300)}`);
    const hidden: Record<string, string | string[]> = {};
    for (const m of (f[2] ?? "").matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"\s*\/?>/g)) {
      const k = m[1] ?? "";
      const v = decodeEntities(m[2] ?? "");
      const prev = hidden[k];
      hidden[k] = prev === undefined ? v : Array.isArray(prev) ? [...prev, v] : [prev, v];
    }
    return this.navigate(new URL(decodeEntities(f[1]), page.url).href, { form: { ...hidden, ...fields }, from: page.url, ...(opts.stopAt ? { stopAt: opts.stopAt } : {}), ...(opts.autoSubmits !== undefined ? { autoSubmits: opts.autoSubmits } : {}) });
  }
}

function decodeEntities(s: string): string {
  return s.replace(/&#(\d+);/g, (_m, n: string) => String.fromCharCode(Number(n)));
}
