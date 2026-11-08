// SPDX-License-Identifier: FSL-1.1-ALv2
// OIDC sign-in against a standard OpenID provider run in-process as the stand-in for the organization's identity
// provider (oidc-provider itself, configured as an issuer: oidc-testkit.ts). The broker reaches it only through the
// hardened fetcher's development host map; the person's browser (SiteBrowser) applies SameSite as browsers do.
//
// Covered: the full code flow for an agent and for the web view (PKCE, state, nonce); a wrong issuer, wrong audience,
// bad nonce, expired token and wrong tenant, each refused; the callback is single-use and bound to its browser;
// Entra's per-tenant issuer and tid + oid binding (single- and multi-tenant), and its token requests naming the scopes
// (the Entra-shaped stand-in refuses one that doesn't, as Entra's v2.0 endpoint may); an address change keeping the
// principal_id and a recycled address getting a new one; app roles and groups as policy groups, and the groups
// overage refused; the re-check at refresh (a refreshed ID token that isn't signed, as Microsoft documents Entra's, is
// left unused, and a signed one naming another person refuses; only a refusal of the person ends the connection, not a
// throttled or busy provider or a refusal of the broker's own request); the SSO step-up for each approval; sign-out at
// the provider; the binding and the provider session surviving a restart on the file store; the configuration
// examples. Not tested here: a live Microsoft Entra tenant; SELF-HOST.md ("Tested against a live Entra tenant")
// records one test against one, on November 8, 2026, with test users.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import type { JWK, JWTPayload } from "jose";
import { inGroup } from "../core/policy/org-policy.ts";
import { DEV_DOMAINS } from "../dev-world.ts";
import { HardenedFetcher } from "../federation/fetcher.ts";
import { TestOAuthClient, startTestBroker } from "../mcp/testkit.ts";
import type { TestBroker } from "../mcp/testkit.ts";
import { RESTART_TEST_PORTS } from "../test-ports.ts";
import { OidcRelyingParty, OidcSignInError, parseOidcConfig } from "./oidc.ts";
import type { OidcRefusal } from "./oidc.ts";
import { generateAuthServerKeys } from "./keys.ts";
import type { AuthServerKeys } from "./keys.ts";
import { SecretBox } from "./oidc-signin.ts";
import { SiteBrowser, startStandInIdp } from "./oidc-testkit.ts";
import type { IdpUser, StandInIdp, Visit } from "./oidc-testkit.ts";
import { patsOf } from "./pat.ts";
import type { BindingState } from "./state.ts";

const CLIENT_ID = "alp-broker-test";
const CLIENT_SECRET = "stand-in-idp-client-secret-test-only";
const TENANT_A = "aaaaaaaa-0000-4000-8000-000000000001";
const TENANT_B = "bbbbbbbb-0000-4000-8000-000000000002";
const TENANT_C = "cccccccc-0000-4000-8000-000000000003";
const AUTHORITY = "https://login.idp.example";
const ISS_A = `${AUTHORITY}/${TENANT_A}/v2.0`;
const ISS_B = `${AUTHORITY}/${TENANT_B}/v2.0`;
const OID_KIM = "0a0a0a0a-1111-4111-8111-000000000001";
const OID_NEW = "0b0b0b0b-2222-4222-8222-000000000002";
const OID_SAM = "0c0c0c0c-3333-4333-8333-000000000003";
const OID_RIO = "0d0d0d0d-4444-4444-8444-000000000004";
const OID_TAO = "0e0e0e0e-5555-4555-8555-000000000005";

/** The agent: a client ID metadata document client (as Claude and ChatGPT connect), with a loopback callback nothing listens on. */
const AGENT = "https://agent.vendor.example/oauth/client.json";
const AGENT_CALLBACK = "http://127.0.0.1/agent-callback";
const isAgentCallback = (u: URL): boolean => u.href.startsWith(AGENT_CALLBACK);
const testFetch = async (input: string | URL | Request): Promise<Response> => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  if (url !== AGENT) return new Response("no such test document", { status: 404 });
  const doc = { client_id: AGENT, client_name: "Vendor Agent", redirect_uris: [AGENT_CALLBACK], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" };
  return new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } });
};

const nowSec = (): number => Math.floor(Date.now() / 1000);

async function refusedWith(p: Promise<unknown>, reason: OidcRefusal): Promise<void> {
  await assert.rejects(p, (err: unknown) => {
    assert.ok(err instanceof OidcSignInError, `expected an OidcSignInError, got ${String(err)}`);
    assert.equal(err.reason, reason, err.detail);
    return true;
  });
}

function rpFor(idp: StandInIdp, raw: Record<string, unknown>, domains: readonly string[] = ["example.org"], log?: (line: string) => void): OidcRelyingParty {
  return new OidcRelyingParty({ settings: parseOidcConfig(raw, domains), clientSecret: CLIENT_SECRET, fetcher: new HardenedFetcher({ devHosts: idp.devHosts }), ...(log ? { log } : {}) });
}

// ---------------------------------------------------------------------------------------------
// A broker in OIDC mode with its stand-in identity provider

interface World {
  idp: StandInIdp;
  rp: OidcRelyingParty;
  t: TestBroker;
  base: string;
  web: string;
  ports: [number, number];
  /** The operator's log lines (the broker's and the relying party's). */
  logs: string[];
}

const genericUsers = (): Record<string, IdpUser> => ({
  kim: { sub: "idp-sub-kim", claims: { email: "kim@example.org", email_verified: true, name: "Kim (test)", groups: ["staff"] } },
  sam: { sub: "idp-sub-sam", claims: { email: "sam@example.org", email_verified: true, name: "Sam (test)" } },
});

const entraUsers = (): Record<string, IdpUser> => ({
  kim: { sub: "pairwise-sub-kim", claims: { tid: TENANT_A, oid: OID_KIM, preferred_username: "kim@example.org", email: "kim.personal@mail.example", name: "Kim (test)", roles: ["Finance"] } },
  newhire: { sub: "pairwise-sub-newhire", claims: { tid: TENANT_A, oid: OID_NEW, preferred_username: "newhire@example.org", name: "New hire (test)" } },
  sam: { sub: "pairwise-sub-sam", claims: { tid: TENANT_A, oid: OID_SAM, preferred_username: "sam@example.org", name: "Sam (test)" } },
  rio: { sub: "pairwise-sub-rio", claims: { tid: TENANT_A, oid: OID_RIO, preferred_username: "rio@example.org", name: "Rio (test)", roles: ["Finance"] } },
  tao: { sub: "pairwise-sub-tao", claims: { tid: TENANT_A, oid: OID_TAO, preferred_username: "tao@example.org", name: "Tao (test)" } },
});

async function startWorld(opts: { entra?: boolean; users: Record<string, IdpUser>; idp?: StandInIdp; ports?: [number, number]; dataDir?: string; settings?: Record<string, unknown> }): Promise<World> {
  const idp =
    opts.idp ??
    (await startStandInIdp({
      issuer: opts.entra ? ISS_A : "https://idp.example",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUris: ["http://127.0.0.1/oidc/callback", "http://127.0.0.1/web/oidc/callback"],
      postLogoutRedirectUris: ["http://127.0.0.1/web"],
      tokenEndpointAuthMethod: opts.entra ? "client_secret_post" : "client_secret_basic",
      ...(opts.entra ? { requireTokenScope: true } : {}),
      users: opts.users,
    }));
  const raw = opts.entra
    ? { kind: "oidc", provider: "entra", tenant: TENANT_A, authority: AUTHORITY, client_id: CLIENT_ID, group_claims: ["roles", "groups"], ...opts.settings }
    : { kind: "oidc", issuer: "https://idp.example", client_id: CLIENT_ID, ...opts.settings };
  const logs: string[] = [];
  const log = (line: string): void => void logs.push(line);
  const rp = rpFor(idp, raw, DEV_DOMAINS, log);
  const fixed = opts.ports ? { port: opts.ports[0], webPort: opts.ports[1], publicUrl: `http://127.0.0.1:${opts.ports[0]}` } : {};
  let t: TestBroker | undefined;
  // A restart reuses its ports; another test process may hold one for a moment.
  for (let attempt = 0; !t; attempt++) {
    try {
      t = await startTestBroker({ idpMode: "oidc", identity: rp, oidc: rp, requireSecret: false, fetch: testFetch, log, ...fixed }, opts.dataDir ? { dataDir: opts.dataDir } : {});
    } catch (err) {
      if (attempt >= 20 || !/EADDRINUSE/.test(String(err))) throw err;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  const ports: [number, number] = [Number(new URL(t.base).port), Number(new URL(t.web).port)];
  return { idp, rp, t, base: t.base, web: t.web, ports, logs };
}

/** An MCP client connects as an agent; the person allows it and signs in at the provider as `login`. */
async function connectAgent(w: World, login: string, browser = new SiteBrowser(w.idp.devHosts)): Promise<{ client?: Client; oauth: TestOAuthClient; visit: Visit; browser: SiteBrowser }> {
  const oauth = new TestOAuthClient({ name: "unused", clientMetadataUrl: AGENT, redirect: AGENT_CALLBACK });
  const url = new URL(`${w.base}/mcp`);
  const first = new StreamableHTTPClientTransport(url, { authProvider: oauth });
  await assert.rejects(new Client({ name: "x", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } }).connect(first));
  assert.ok(oauth.lastAuthorizationUrl, "the agent got an authorization URL");
  // The agent's platform opens the authorization URL in the person's browser (a navigation from another site).
  const consent = await browser.navigate(oauth.lastAuthorizationUrl.href, { stopAt: isAgentCallback });
  assert.equal(consent.status, 200, consent.html.slice(0, 300));
  assert.match(consent.html, /Allow, then sign in/);
  const atIdp = await browser.submit(consent, { action: "allow" }, { action: /^\/interaction\//, stopAt: isAgentCallback });
  assert.equal(atIdp.status, 200, `the provider's sign-in page: ${atIdp.html.slice(0, 300)}`);
  const visit = await browser.submit(atIdp, { login }, { stopAt: isAgentCallback });
  if (!visit.stoppedAt) return { oauth, visit, browser };
  await first.finishAuth(new URL(visit.stoppedAt).searchParams);
  const client = new Client({ name: "x", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  await client.connect(new StreamableHTTPClientTransport(url, { authProvider: oauth }));
  return { client, oauth, visit, browser };
}

/** The person signs in on the web view at the provider as `login`; returns the page after sign-in (same-site). */
async function webSignIn(w: World, login: string, browser = new SiteBrowser(w.idp.devHosts)): Promise<{ page: Visit; browser: SiteBrowser }> {
  const loginPage = await browser.navigate(`${w.web}/web`);
  const atIdp = await browser.submit(loginPage, {}, { action: /^\/web\/login$/ });
  assert.equal(atIdp.status, 200, atIdp.html.slice(0, 300));
  const signedIn = await browser.submit(atIdp, { login });
  if (signedIn.status !== 200 || !/Signed in/.test(signedIn.html)) return { page: signedIn, browser };
  // The session cookie is SameSite=Strict: the page continues with a same-site navigation (its Refresh header).
  assert.equal(signedIn.headers.get("refresh"), "0; url=/web");
  const page = await browser.navigate(`${w.web}/web`, { from: signedIn.url });
  return { page, browser };
}

function sc(r: unknown): Record<string, unknown> {
  return (r as CallToolResult).structuredContent as Record<string, unknown>;
}

/** Makes every stored provider session due for its re-check (a successful check counts for 30 seconds). */
function ageProviderSessions(t: TestBroker): void {
  for (const e of Object.values((t.server.state as BindingState).model("AlpIdpSession"))) e.payload["checked_at"] = 0;
}

async function refreshAgent(w: World, oauth: TestOAuthClient): Promise<Response> {
  const rt = oauth.tokens()?.refresh_token;
  assert.ok(rt, "the agent holds a refresh token");
  const res = await fetch(`${w.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: AGENT }).toString() });
  if (res.status === 200) {
    const tokens = (await res.clone().json()) as { access_token: string; refresh_token?: string; token_type: string };
    oauth.saveTokens({ ...oauth.tokens(), ...tokens } as Parameters<TestOAuthClient["saveTokens"]>[0]);
  }
  return res;
}

// ---------------------------------------------------------------------------------------------

describe("ID token checks (a generic OpenID provider)", () => {
  let idp: StandInIdp;
  let rp: OidcRelyingParty;
  const good = (over: JWTPayload = {}): JWTPayload => ({ iss: "https://idp.example", sub: "idp-sub-kim", aud: CLIENT_ID, iat: nowSec(), exp: nowSec() + 600, nonce: "nonce-1", email: "kim@example.org", email_verified: true, groups: ["staff", "finance"], ...over });
  before(async () => {
    idp = await startStandInIdp({ issuer: "https://idp.example", clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, redirectUris: ["http://127.0.0.1/unused"], users: genericUsers() });
    rp = rpFor(idp, { kind: "oidc", issuer: "https://idp.example", client_id: CLIENT_ID });
  });
  after(async () => {
    await idp?.close();
  });

  test("a valid token: the binding is iss + sub, the address is an alias from the email claim, groups become claims", async () => {
    const id = rp.identityFrom(await rp.validateIdToken(await idp.sign(good()), { nonce: "nonce-1", checkAge: true }));
    assert.equal(id.iss, "https://idp.example");
    assert.equal(id.sub, "idp-sub-kim");
    assert.equal(id.address, "alp:kim@example.org");
    assert.deepEqual(id.claims, [
      { issuer: "https://idp.example", name: "groups", value: "staff" },
      { issuer: "https://idp.example", name: "groups", value: "finance" },
    ]);
  });

  test("refused: a wrong issuer, a wrong audience, a bad nonce, an expired token", async () => {
    await refusedWith(rp.validateIdToken(await idp.sign(good({ iss: "https://other-idp.example" })), { nonce: "nonce-1" }), "wrong_issuer");
    await refusedWith(rp.validateIdToken(await idp.sign(good({ aud: "another-app" })), { nonce: "nonce-1" }), "wrong_audience");
    await refusedWith(rp.validateIdToken(await idp.sign(good({ aud: [CLIENT_ID, "another-app"] })), { nonce: "nonce-1" }), "wrong_audience");
    await refusedWith(rp.validateIdToken(await idp.sign(good({ azp: "another-app" })), { nonce: "nonce-1" }), "wrong_audience");
    await refusedWith(rp.validateIdToken(await idp.sign(good({ nonce: "nonce-2" })), { nonce: "nonce-1" }), "bad_nonce");
    await refusedWith(rp.validateIdToken(await idp.sign(good({ nonce: undefined })), { nonce: "nonce-1" }), "bad_nonce");
    await refusedWith(rp.validateIdToken(await idp.sign(good({ iat: nowSec() - 7200, exp: nowSec() - 3600 })), { nonce: "nonce-1" }), "expired");
    // Within the clock skew (60 s) it still passes; a code exchange's token older than 10 minutes doesn't.
    await rp.validateIdToken(await idp.sign(good({ exp: nowSec() - 30 })), { nonce: "nonce-1" });
    await refusedWith(rp.validateIdToken(await idp.sign(good({ iat: nowSec() - 1200, exp: nowSec() + 600 })), { nonce: "nonce-1", checkAge: true }), "expired");
    await refusedWith(rp.validateIdToken(await idp.sign(good({ iat: nowSec() + 3600, exp: nowSec() + 7200 })), { nonce: "nonce-1" }), "bad_token");
  });

  test("refused: a signature by another key, an unknown key, alg none and HMAC with the client secret", async () => {
    const other = await generateKeyPair("RS256", { extractable: true });
    const otherJwk: JWK = await exportJWK(other.privateKey);
    await refusedWith(rp.validateIdToken(await idp.sign(good(), { jwk: otherJwk, kid: "stand-in-idp-1" }), { nonce: "nonce-1" }), "bad_signature");
    await refusedWith(rp.validateIdToken(await idp.sign(good(), { jwk: otherJwk, kid: "attacker-key" }), { nonce: "nonce-1" }), "bad_signature");
    const b64 = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString("base64url");
    await refusedWith(rp.validateIdToken(`${b64({ alg: "none" })}.${b64(good())}.`, { nonce: "nonce-1" }), "bad_signature");
    const hmac = await new SignJWT(good()).setProtectedHeader({ alg: "HS256" }).sign(new TextEncoder().encode(CLIENT_SECRET));
    await refusedWith(rp.validateIdToken(hmac, { nonce: "nonce-1" }), "bad_signature");
  });

  test("the address: a verified email on a served domain only; never the binding", async () => {
    await assert.throws(() => rp.identityFrom(good({ email_verified: false })), (e: unknown) => e instanceof OidcSignInError && e.reason === "email_not_verified");
    await assert.throws(() => rp.identityFrom(good({ email: "kim@elsewhere.example" })), (e: unknown) => e instanceof OidcSignInError && e.reason === "address_not_allowed");
    await assert.throws(() => rp.identityFrom(good({ email: undefined })), (e: unknown) => e instanceof OidcSignInError && e.reason === "no_address");
    // The same subject with another email is the same person (only the alias differs).
    const a = rp.identityFrom(good());
    const b = rp.identityFrom(good({ email: "kim.renamed@example.org" }));
    assert.deepEqual([a.iss, a.sub], [b.iss, b.sub]);
    assert.notEqual(a.address, b.address);
  });

  test("groups overage: a distributed groups claim (a link instead of the list) refuses the sign-in", async () => {
    const overage = good({ groups: undefined, _claim_names: { groups: "src1" }, _claim_sources: { src1: { endpoint: "https://graph.microsoft.example/v1.0/users/x/getMemberObjects" } } });
    await assert.throws(() => rp.identityFrom(overage), (e: unknown) => {
      assert.ok(e instanceof OidcSignInError && e.reason === "groups_overage");
      assert.match(e.personText, /app roles/);
      return true;
    });
    await assert.throws(() => rp.identityFrom(good({ groups: undefined, hasgroups: true })), (e: unknown) => e instanceof OidcSignInError && e.reason === "groups_overage");
  });
});

describe("Microsoft Entra ID rules (Entra-shaped issuers)", () => {
  let idp: StandInIdp;
  const entraToken = (over: JWTPayload = {}): JWTPayload => ({ iss: ISS_A, tid: TENANT_A, oid: OID_KIM, sub: "pairwise-sub-kim", aud: CLIENT_ID, iat: nowSec(), exp: nowSec() + 600, nonce: "nonce-1", preferred_username: "kim@example.org", roles: ["Finance"], ...over });
  before(async () => {
    idp = await startStandInIdp({ issuer: ISS_A, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, redirectUris: ["http://127.0.0.1/unused"], users: entraUsers() });
  });
  after(async () => {
    await idp?.close();
  });

  test("single tenant: the per-tenant issuer, tid + oid binding, roles as claims; other tenants refused", async () => {
    const rp = rpFor(idp, { kind: "oidc", provider: "entra", tenant: TENANT_A, authority: AUTHORITY, client_id: CLIENT_ID });
    assert.equal(rp.settings.issuer, ISS_A);
    assert.equal(rp.settings.discoveryUrl, `${ISS_A}/.well-known/openid-configuration`);
    const id = rp.identityFrom(await rp.validateIdToken(await idp.sign(entraToken()), { nonce: "nonce-1" }));
    assert.deepEqual({ iss: id.iss, sub: id.sub, tenant: id.tenant, address: id.address }, { iss: ISS_A, sub: OID_KIM, tenant: TENANT_A, address: "alp:kim@example.org" });
    assert.deepEqual(id.claims, [{ issuer: ISS_A, name: "roles", value: "Finance" }]);
    // The binding is tid + oid: a renamed UPN or a changed email is the same person; `sub` (pairwise) isn't used.
    const renamed = rp.identityFrom(await rp.validateIdToken(await idp.sign(entraToken({ preferred_username: "kim.lee@example.org", email: "x@mail.example", sub: "another-pairwise-sub" })), { nonce: "nonce-1" }));
    assert.deepEqual([renamed.iss, renamed.sub], [ISS_A, OID_KIM]);
    await refusedWith(rp.validateIdToken(await idp.sign(entraToken({ iss: ISS_B, tid: TENANT_B })), { nonce: "nonce-1" }), "wrong_tenant");
    await refusedWith(rp.validateIdToken(await idp.sign(entraToken({ tid: TENANT_B })), { nonce: "nonce-1" }), "wrong_issuer");
    await refusedWith(rp.validateIdToken(await idp.sign(entraToken({ iss: `https://sts.windows.example/${TENANT_A}/` })), { nonce: "nonce-1" }), "wrong_issuer");
    await refusedWith(rp.validateIdToken(await idp.sign(entraToken({ tid: undefined })), { nonce: "nonce-1" }), "missing_claim");
    assert.throws(() => rp.identityFrom(entraToken({ oid: undefined })), (e: unknown) => e instanceof OidcSignInError && e.reason === "missing_claim");
    // A guest (its idp is another directory, a personal account or a one-time passcode) is refused, even with an
    // address on a served domain; a member's idp, when present, is its own issuer.
    assert.throws(() => rp.identityFrom(entraToken({ idp: `https://sts.windows.example/${TENANT_B}/`, preferred_username: "ceo@example.org" })), (e: unknown) => e instanceof OidcSignInError && e.reason === "guest_account");
    assert.throws(() => rp.identityFrom(entraToken({ idp: "mail" })), (e: unknown) => e instanceof OidcSignInError && e.reason === "guest_account");
    assert.equal(rp.identityFrom(entraToken({ idp: ISS_A })).sub, OID_KIM);
    const guestsAllowed = rpFor(idp, { kind: "oidc", provider: "entra", tenant: TENANT_A, authority: AUTHORITY, client_id: CLIENT_ID, allow_guests: true });
    assert.equal(guestsAllowed.identityFrom(entraToken({ idp: "mail" })).sub, OID_KIM);
    // A guest's UPN from another directory isn't an address on a served domain.
    assert.throws(() => rp.identityFrom(entraToken({ preferred_username: "kim_mail.example#EXT#@tenant.onmicrosoft.example" })), (e: unknown) => e instanceof OidcSignInError && (e.reason === "no_address" || e.reason === "address_not_allowed"));
  });

  test("multi-tenant (\"organizations\"): only listed tenants, each only for its own domains", async () => {
    const doc = await idp.document(`/${TENANT_A}/v2.0/.well-known/openid-configuration`);
    idp.extraDocs["/organizations/v2.0/.well-known/openid-configuration"] = { ...doc, issuer: `${AUTHORITY}/{tenantid}/v2.0` };
    const rp = rpFor(idp, { kind: "oidc", provider: "entra", tenant: "organizations", tenants: { [TENANT_A]: ["example.org"], [TENANT_B]: ["partner.example"] }, authority: AUTHORITY, client_id: CLIENT_ID }, ["example.org", "partner.example"]);
    const a = rp.identityFrom(await rp.validateIdToken(await idp.sign(entraToken()), { nonce: "nonce-1" }));
    assert.equal(a.tenant, TENANT_A);
    const b = rp.identityFrom(await rp.validateIdToken(await idp.sign(entraToken({ iss: ISS_B, tid: TENANT_B, preferred_username: "rio@partner.example" })), { nonce: "nonce-1" }));
    assert.deepEqual([b.iss, b.address], [ISS_B, "alp:rio@partner.example"]);
    assert.throws(() => rp.identityFrom(entraToken({ iss: ISS_B, tid: TENANT_B, preferred_username: "ceo@example.org" })), (e: unknown) => e instanceof OidcSignInError && e.reason === "address_not_allowed");
    await refusedWith(rp.validateIdToken(await idp.sign(entraToken({ iss: `${AUTHORITY}/${TENANT_C}/v2.0`, tid: TENANT_C })), { nonce: "nonce-1" }), "wrong_tenant");
    // RFC 9207: the authorization response's iss must be a listed tenant's issuer.
    await rp.checkResponseIssuer(ISS_B);
    await refusedWith(rp.checkResponseIssuer("https://evil.example"), "wrong_issuer");
    await refusedWith(rp.checkResponseIssuer(undefined), "wrong_issuer");
  });
});

describe("an agent connects through the organization's identity provider (generic)", () => {
  let w: World;
  before(async () => {
    w = await startWorld({ users: genericUsers() });
  });
  after(async () => {
    await w?.t.close();
    await w?.idp.close();
  });

  test("the full code flow: PKCE, state and nonce at the provider; the agent acts for the principal bound to iss + sub", async () => {
    const { client, browser } = await connectAgent(w, "kim");
    assert.ok(client, "the agent connected");
    const req = w.idp.authorizations.at(-1);
    assert.ok(req);
    assert.equal(req.get("response_type"), "code");
    assert.equal(req.get("client_id"), CLIENT_ID);
    assert.equal(req.get("redirect_uri"), `${w.base}/oidc/callback`);
    assert.equal(req.get("code_challenge_method"), "S256");
    assert.match(req.get("code_challenge") ?? "", /^[A-Za-z0-9_-]{43}$/);
    assert.match(req.get("state") ?? "", /^[A-Za-z0-9_-]{43}$/);
    assert.match(req.get("nonce") ?? "", /^[A-Za-z0-9_-]{43}$/);
    assert.equal(req.get("prompt"), "login", "a connector authorization asks for a fresh sign-in");
    assert.deepEqual((req.get("scope") ?? "").split(" ").sort(), ["email", "offline_access", "openid", "profile"]);
    assert.deepEqual(w.idp.tokenScopes.at(-1), { grant_type: "authorization_code", scope: undefined }, "a generic provider's code exchange names no scope (Entra's names them: below)");
    const me = sc(await client.callTool({ name: "alp_whoami", arguments: {} }));
    assert.equal(me["address"], "alp:kim@example.org");
    const p = await w.t.dev.store.getPrincipal("alp:kim@example.org");
    assert.ok(p);
    assert.deepEqual(p.identity, { iss: "https://idp.example", sub: "idp-sub-kim" });
    assert.equal(me["id"], p.principal_id);
    // The browser-binding cookie is SameSite=Lax (it must come back with the provider's cross-site redirect).
    assert.ok(browser.setCookies.some((c) => /^alp_oidc=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Lax/.test(c)));
    await client.close();
  });

  test("refused before the agent gets a code: a wrong issuer, a wrong audience, a bad nonce, an expired token", async () => {
    const cases: [OidcRefusal, (c: JWTPayload) => JWTPayload][] = [
      ["wrong_issuer", (c) => ({ ...c, iss: "https://other-idp.example" })],
      ["wrong_audience", (c) => ({ ...c, aud: "another-app" })],
      ["bad_nonce", (c) => ({ ...c, nonce: "not-this-sign-in" })],
      ["expired", (c) => ({ ...c, iat: nowSec() - 7200, exp: nowSec() - 3600 })],
    ];
    try {
      for (const [reason, tamper] of cases) {
        const before = w.t.events.events.length;
        w.idp.tamper = tamper;
        const { client, visit } = await connectAgent(w, "sam");
        assert.equal(client, undefined, `${reason}: the agent got no code`);
        assert.equal(visit.status, 401, `${reason}: ${visit.html.slice(0, 200)}`);
        assert.match(visit.html, /Sign-in can.t continue/);
        assert.match(visit.html, new RegExp(`Reason: ${reason}`));
        assert.ok(w.t.events.events.slice(before).some((e) => e.detail.event === "token_refused" && e.message === `sign-in refused: ${reason}`), `${reason}: a security event`);
      }
    } finally {
      w.idp.tamper = null;
    }
    assert.equal(await w.t.dev.store.getPrincipal("alp:sam@example.org"), null, "no principal was registered by a refused sign-in");
  });

  test("the provider's redirect is used once, and only in the browser that started the sign-in", async () => {
    const browser = new SiteBrowser(w.idp.devHosts);
    const oauth = new TestOAuthClient({ name: "unused", clientMetadataUrl: AGENT, redirect: AGENT_CALLBACK });
    await assert.rejects(new Client({ name: "x", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } }).connect(new StreamableHTTPClientTransport(new URL(`${w.base}/mcp`), { authProvider: oauth })));
    assert.ok(oauth.lastAuthorizationUrl);
    const consent = await browser.navigate(oauth.lastAuthorizationUrl.href);
    const atIdp = await browser.submit(consent, { action: "allow" }, { action: /^\/interaction\// });
    const isCallback = (u: URL): boolean => u.pathname === "/oidc/callback";
    const stopped = await browser.submit(atIdp, { login: "kim" }, { stopAt: isCallback });
    assert.ok(stopped.stoppedAt, "stopped at the broker's callback");
    // Another browser (say, one the link was sent to) can't use it.
    const elsewhere = await new SiteBrowser(w.idp.devHosts).navigate(stopped.stoppedAt);
    assert.equal(elsewhere.status, 401);
    assert.match(elsewhere.html, /Reason: stale/);
    // The state was spent by that attempt: even the right browser can't use it now.
    const late = await browser.navigate(stopped.stoppedAt, { stopAt: isAgentCallback });
    assert.equal(late.status, 401);
    assert.match(late.html, /Reason: stale/);
    const made_up = await browser.navigate(`${w.base}/oidc/callback?code=x&state=${"A".repeat(43)}`);
    assert.equal(made_up.status, 401);
  });
});

describe("Microsoft Entra ID, end to end (an Entra-shaped stand-in)", () => {
  let w: World;
  before(async () => {
    w = await startWorld({ entra: true, users: entraUsers() });
  });
  after(async () => {
    await w?.t.close();
    await w?.idp.close();
  });

  test("tid + oid binding; app roles become the policy's claim-based groups; another tenant's token is refused", async () => {
    const { client } = await connectAgent(w, "kim");
    assert.ok(client);
    // The stand-in refuses a token request without `scope`, as Entra's v2.0 endpoint may: the code exchange names the
    // scopes the authorization asked for.
    assert.deepEqual(w.idp.tokenScopes.at(-1), { grant_type: "authorization_code", scope: "openid profile email offline_access" });
    const p = await w.t.dev.store.getPrincipal("alp:kim@example.org");
    assert.ok(p);
    assert.deepEqual(p.identity, { iss: ISS_A, sub: OID_KIM });
    assert.deepEqual(p.claims, [{ issuer: ISS_A, name: "roles", value: "Finance" }]);
    // The organization's policy names the group by the claim (spec 6.4), as in deploy/policy.example.json.
    const policy = w.t.dev.policies[0];
    assert.ok(policy);
    const next = { ...structuredClone(policy), serial: policy.serial + 1, groups: { ...policy.groups, finance: { claim: { issuer: ISS_A, name: "roles", value: "Finance" } } } };
    await w.t.dev.broker.setOrgPolicy({ kind: "admin", operator: "test" }, next);
    const claimsOf = (a: string) => (a === p.address ? p.claims ?? [] : []);
    assert.equal(inGroup(next, "finance", p.address, claimsOf), true, "Kim is in group:finance through her app role");
    assert.equal(inGroup(next, "finance", "alp:sam@example.org", claimsOf), false);
    await client.close();

    const before = w.t.events.events.length;
    w.idp.tamper = (c) => ({ ...c, iss: ISS_B, tid: TENANT_B });
    try {
      const { client: other, visit } = await connectAgent(w, "sam");
      assert.equal(other, undefined);
      assert.equal(visit.status, 401);
      assert.match(visit.html, /Reason: wrong_tenant/);
      assert.match(visit.html, /organization this broker doesn(&#39;|')t serve/);
    } finally {
      w.idp.tamper = null;
    }
    assert.ok(w.t.events.events.slice(before).some((e) => e.message === "sign-in refused: wrong_tenant"));
  });

  test("groups overage: the sign-in is refused with a clear reason, not signed in without groups", async () => {
    w.idp.tamper = (c) => ({ ...c, _claim_names: { groups: "src1" }, _claim_sources: { src1: { endpoint: `https://graph.microsoft.example/v1.0/users/${OID_SAM}/getMemberObjects` } } });
    try {
      const { client, visit } = await connectAgent(w, "sam");
      assert.equal(client, undefined);
      assert.equal(visit.status, 401);
      assert.match(visit.html, /Reason: groups_overage/);
      assert.match(visit.html, /app roles/);
    } finally {
      w.idp.tamper = null;
    }
    assert.equal(await w.t.dev.store.getPrincipal("alp:sam@example.org"), null);
  });

  test("an address change keeps the principal_id; a recycled address gets a new principal", async () => {
    const first = await webSignIn(w, "kim");
    assert.match(first.page.html, /Your agents/);
    const p1 = await w.t.dev.store.getPrincipal("alp:kim@example.org");
    assert.ok(p1);
    // The organization renames Kim's account (same tenant, same oid): same principal, new address.
    const kim = w.idp.users["kim"];
    assert.ok(kim);
    kim.claims["preferred_username"] = "kim.lee@example.org";
    const renamed = await webSignIn(w, "kim");
    assert.match(renamed.page.html, /Your agents/);
    const p1b = await w.t.dev.store.getPrincipal("alp:kim.lee@example.org");
    assert.equal(p1b?.principal_id, p1.principal_id, "the same principal_id after the address change");
    assert.equal(await w.t.dev.store.getPrincipal("alp:kim@example.org"), null, "the old address no longer resolves");
    // The old address goes to a new hire (another oid): a new principal; Kim's stays active at her new address.
    const newhire = w.idp.users["newhire"];
    assert.ok(newhire);
    newhire.claims["preferred_username"] = "kim@example.org";
    await webSignIn(w, "newhire");
    const p2 = await w.t.dev.store.getPrincipal("alp:kim@example.org");
    assert.ok(p2);
    assert.notEqual(p2.principal_id, p1.principal_id, "a recycled address gets a new principal_id");
    assert.deepEqual(p2.identity, { iss: ISS_A, sub: OID_NEW });
    assert.equal((await w.t.dev.store.getPrincipalById(p1.principal_id))?.status, "active");
    kim.claims["preferred_username"] = "kim@example.org";
    newhire.claims["preferred_username"] = "newhire@example.org";
  });

  test("the re-check at refresh: roles follow the provider; a disabled account ends the connection", async () => {
    const sam = w.idp.users["sam"];
    assert.ok(sam);
    const { client, oauth } = await connectAgent(w, "sam");
    assert.ok(client);
    const atStart = w.idp.tokenRequests["refresh_token"] ?? 0;
    ageProviderSessions(w.t);
    assert.equal((await refreshAgent(w, oauth)).status, 200, "an active person's agent refreshes");
    assert.equal(w.idp.tokenRequests["refresh_token"], atStart + 1, "the broker re-checked the person at the provider");
    assert.deepEqual(w.idp.tokenScopes.at(-1), { grant_type: "refresh_token", scope: "openid profile email offline_access" }, "the refresh names the scopes too (and so gets an ID token)");
    // A role assigned at the provider reaches the policy at the next refresh.
    sam.claims["roles"] = ["Leads"];
    ageProviderSessions(w.t);
    assert.equal((await refreshAgent(w, oauth)).status, 200);
    assert.deepEqual((await w.t.dev.store.getPrincipal("alp:sam@example.org"))?.claims, [{ issuer: ISS_A, name: "roles", value: "Leads" }]);
    // Two overlapping refreshes inside 30 seconds of a check: one provider call.
    const calls = w.idp.tokenRequests["refresh_token"] ?? 0;
    assert.equal((await refreshAgent(w, oauth)).status, 200);
    assert.equal(w.idp.tokenRequests["refresh_token"], calls, "a check from the last 30 seconds counts");
    assert.equal(sc(await client.callTool({ name: "alp_whoami", arguments: {} }))["address"], "alp:sam@example.org");
    // The account is disabled at the provider: the next refresh is refused and the connection revoked at once.
    sam.disabled = true;
    ageProviderSessions(w.t);
    const before = w.t.events.events.length;
    const refused = await refreshAgent(w, oauth);
    assert.equal(refused.status, 400);
    assert.equal(((await refused.json()) as Record<string, unknown>)["error"], "invalid_grant");
    assert.ok(w.t.events.events.slice(before).some((e) => e.detail.event === "token_refused" && /identity provider no longer accepts/.test(e.message ?? "")));
    await assert.rejects(client.callTool({ name: "alp_whoami", arguments: {} }), "the agent's live access token stopped working too");
    sam.disabled = false;
    sam.claims["roles"] = [];
  });

  test("a refresh whose ID token isn't signed (as Microsoft documents Entra's) or is left out keeps the connection and the roles from the last sign-in", async () => {
    const rio = w.idp.users["rio"];
    assert.ok(rio);
    const { client, oauth } = await connectAgent(w, "rio");
    assert.ok(client);
    const finance = [{ issuer: ISS_A, name: "roles", value: "Finance" }];
    assert.deepEqual((await w.t.dev.store.getPrincipal("alp:rio@example.org"))?.claims, finance);
    try {
      // A role changed at the provider isn't taken from an ID token the broker can't verify, nor from none.
      rio.claims["roles"] = ["Leads"];
      for (const mode of ["unsigned", "omitted"] as const) {
        w.idp.refreshIdToken = mode;
        const calls = w.idp.tokenRequests["refresh_token"] ?? 0;
        ageProviderSessions(w.t);
        assert.equal((await refreshAgent(w, oauth)).status, 200, `${mode}: the connection refreshes`);
        assert.equal(w.idp.tokenRequests["refresh_token"], calls + 1, `${mode}: the person was re-checked at the provider`);
        assert.deepEqual((await w.t.dev.store.getPrincipal("alp:rio@example.org"))?.claims, finance, `${mode}: the roles from the last sign-in stay`);
      }
      assert.equal(sc(await client.callTool({ name: "alp_whoami", arguments: {} }))["address"], "alp:rio@example.org");
      // A signed one again: the new role arrives.
      w.idp.refreshIdToken = "signed";
      ageProviderSessions(w.t);
      assert.equal((await refreshAgent(w, oauth)).status, 200);
      assert.deepEqual((await w.t.dev.store.getPrincipal("alp:rio@example.org"))?.claims, [{ issuer: ISS_A, name: "roles", value: "Leads" }]);
    } finally {
      w.idp.refreshIdToken = "signed";
      rio.claims["roles"] = ["Finance"];
    }
    // A signed one that names another person still ends the connection.
    w.idp.tamper = (c) => ({ ...c, oid: OID_SAM });
    try {
      ageProviderSessions(w.t);
      assert.equal((await refreshAgent(w, oauth)).status, 400);
    } finally {
      w.idp.tamper = null;
    }
    await assert.rejects(client.callTool({ name: "alp_whoami", arguments: {} }));
  });

  test("at a refresh, only a refusal of the person ends the connection: a throttled or busy provider, or one refusing the broker's own request, fails that refresh only", async () => {
    const entraError = (error: string, code: number): Record<string, unknown> => ({ error, error_description: `AADSTS${code}: (test)`, error_codes: [code] });
    // At a sign-in, a busy provider is "couldn't be reached, try again", not a refusal.
    w.idp.tokenFailure = { status: 400, body: { error: "temporarily_unavailable" } };
    try {
      const { page } = await webSignIn(w, "tao");
      assert.match(page.html, /Reason: idp_unavailable/);
    } finally {
      w.idp.tokenFailure = null;
    }
    const { client, oauth } = await connectAgent(w, "tao");
    assert.ok(client);
    const notThePerson: [number, Record<string, unknown>][] = [
      [429, { error: "temporarily_unavailable" }],
      [400, { error: "temporarily_unavailable" }],
      // The broker's client secret expired, and a request the provider can't take: the broker's problem, not the
      // person's.
      [401, entraError("invalid_client", 7000222)],
      [400, entraError("invalid_request", 900144)],
    ];
    for (const [status, body] of notThePerson) {
      const what = `${status} ${String(body["error"])}`;
      const before = w.t.events.events.length;
      w.idp.tokenFailure = { status, body };
      try {
        ageProviderSessions(w.t);
        assert.notEqual((await refreshAgent(w, oauth)).status, 200, `${what}: that refresh fails`);
      } finally {
        w.idp.tokenFailure = null;
      }
      assert.ok(!w.t.events.events.slice(before).some((e) => e.detail.event === "token_revoked"), `${what}: the connection wasn't revoked`);
      ageProviderSessions(w.t);
      assert.equal((await refreshAgent(w, oauth)).status, 200, `${what}: the next refresh works`);
    }
    assert.ok(w.logs.some((l) => /AADSTS7000222/.test(l) && /ALP_OIDC_CLIENT_SECRET/.test(l)), "the operator's log names Entra's code and what to check");
    assert.equal(sc(await client.callTool({ name: "alp_whoami", arguments: {} }))["address"], "alp:tao@example.org");
    // A refusal of the person ends it: Entra's interaction_required (multi-factor authentication or a Conditional
    // Access policy wants a new sign-in), as invalid_grant does (a disabled account: above).
    w.idp.tokenFailure = { status: 400, body: entraError("interaction_required", 50076) };
    try {
      ageProviderSessions(w.t);
      assert.equal((await refreshAgent(w, oauth)).status, 400);
    } finally {
      w.idp.tokenFailure = null;
    }
    assert.ok(w.logs.some((l) => /refused the person at refresh/.test(l) && /AADSTS50076/.test(l)), "the log names Entra's code for a refusal too");
    await assert.rejects(client.callTool({ name: "alp_whoami", arguments: {} }));
  });
});

describe("the web view through the identity provider: sign-in, SSO step-up, sign-out", () => {
  let w: World;
  before(async () => {
    w = await startWorld({ users: genericUsers() });
  });
  after(async () => {
    await w?.t.close();
    await w?.idp.close();
  });

  test("sign-in: the provider's origin is allowed as a form target; the Strict session cookie needs the same-site step", async () => {
    const browser = new SiteBrowser(w.idp.devHosts);
    const login = await browser.navigate(`${w.web}/web`);
    assert.match(login.headers.get("content-security-policy") ?? "", /form-action 'self' https:\/\/idp\.example/);
    const { page } = await webSignIn(w, "kim", browser);
    assert.equal(page.status, 200);
    assert.match(page.html, /Your agents/);
    assert.match(page.html, /kim@example\.org|Kim \(test\)/);
    // A navigation that arrives from another site doesn't carry the Strict session cookie (why the page continues same-site).
    const crossSite = await browser.navigate(`${w.web}/web`, { from: "https://elsewhere.example/" });
    assert.match(crossSite.html, /Sign in with your organization/);
  });

  test("each approval needs a fresh sign-in at the provider, committed to that action, and only the same person passes", async () => {
    const { page, browser } = await webSignIn(w, "kim");
    const p = await w.t.dev.store.getPrincipal("alp:kim@example.org");
    assert.ok(p);
    const toIdp = await browser.submit(page, { label: "script", scopes: ["read"], days: "7" }, { action: /^\/web\/tokens$/ });
    assert.equal(toIdp.status, 200, "at the provider's sign-in page");
    const req = w.idp.authorizations.at(-1);
    assert.ok(req);
    assert.equal(req.get("prompt"), "login");
    assert.equal(req.get("max_age"), "0");
    assert.equal(req.get("redirect_uri"), `${w.web}/web/oidc/callback`);
    assert.equal((await patsOf(w.t.server.state, p.principal_id)).length, 0, "nothing is done before the step-up");
    const confirm = await browser.submit(toIdp, { login: "kim" });
    assert.equal(confirm.status, 200, confirm.html.slice(0, 300));
    assert.match(confirm.html, /Create the personal access token/);
    assert.equal((await patsOf(w.t.server.state, p.principal_id)).length, 0, "nothing is done until the person confirms");
    const done = await browser.submit(confirm, {}, { action: /^\/web\/tokens$/ });
    assert.match(done.html, /Personal access token for/);
    assert.equal((await patsOf(w.t.server.state, p.principal_id)).length, 1);
    // A confirmed step-up is used once: posting the same form again starts a new one.
    const again = await browser.submit(confirm, {}, { action: /^\/web\/tokens$/ });
    assert.equal(again.status, 200);
    assert.equal(new URL(again.url).hostname, "idp.example", "back to the provider for the second approval");
    // A step-up where someone else signs in at the provider is refused, and nothing is done.
    const dashboard = await browser.navigate(`${w.web}/web`, { from: done.url });
    const tokenId = /action="\/web\/tokens\/([^/"]+)\/revoke"/.exec(dashboard.html)?.[1];
    assert.ok(tokenId);
    const atIdp = await browser.submit(dashboard, {}, { action: /\/web\/tokens\/[^/]+\/revoke$/ });
    const wrong = await browser.submit(atIdp, { login: "sam" });
    assert.equal(wrong.status, 401);
    assert.match(wrong.html, /Reason: wrong_subject/);
    assert.equal((await patsOf(w.t.server.state, p.principal_id)).filter((x) => !x.revoked_at).length, 1, "the token is still active");
  });

  test("sign-out ends the broker session and sends the browser to the provider's end-session endpoint", async () => {
    const { page, browser } = await webSignIn(w, "kim");
    const out = await browser.submit(page, {}, { action: /^\/web\/logout$/, stopAt: (u) => u.hostname === "idp.example" });
    assert.ok(out.stoppedAt);
    const end = new URL(out.stoppedAt);
    assert.equal(end.pathname, "/session/end");
    assert.equal(end.searchParams.get("client_id"), CLIENT_ID);
    assert.equal(end.searchParams.get("post_logout_redirect_uri"), `${w.web}/web`);
    assert.equal(end.searchParams.get("id_token_hint"), null, "no ID token in the URL");
    const after = await browser.navigate(`${w.web}/web`, { from: page.url });
    assert.match(after.html, /Sign in with your organization/);
  });
});

describe("a restart on the file store", () => {
  let dir = "";
  let idp: StandInIdp | undefined;
  after(async () => {
    await idp?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  test("the binding (iss + sub) and the provider session behind a connection survive a restart", async () => {
    dir = mkdtempSync(join(tmpdir(), "alp-oidc-"));
    // The restart keeps its ports (the issuer and the agent's resource URL name them), so both starts use the two
    // reserved for restarts: a pooled port could go to another test process while the broker is down.
    const w1 = await startWorld({ users: genericUsers(), dataDir: dir, ports: RESTART_TEST_PORTS });
    idp = w1.idp;
    const { client, oauth } = await connectAgent(w1, "kim");
    assert.ok(client);
    const p1 = await w1.t.dev.store.getPrincipal("alp:kim@example.org");
    assert.ok(p1);
    await client.close();
    await w1.t.close();

    const w2 = await startWorld({ users: genericUsers(), dataDir: dir, idp: w1.idp, ports: w1.ports });
    try {
      const again = await w2.t.dev.store.getPrincipalByIdentity("https://idp.example", "idp-sub-kim");
      assert.equal(again?.principal_id, p1.principal_id);
      // The person signs in again after the restart: the same principal.
      await webSignIn(w2, "kim");
      assert.equal((await w2.t.dev.store.getPrincipal("alp:kim@example.org"))?.principal_id, p1.principal_id);
      // The agent's connection refreshes after the restart, and the broker re-checks the person with the stored
      // (sealed) provider refresh token.
      const calls = w2.idp.tokenRequests["refresh_token"] ?? 0;
      ageProviderSessions(w2.t);
      assert.equal((await refreshAgent(w2, oauth)).status, 200);
      assert.equal(w2.idp.tokenRequests["refresh_token"], calls + 1);
      // The provider's refresh token is stored sealed (AES-256-GCM), never in the clear.
      const state = JSON.parse(readFileSync(join(dir, "binding", "binding.json"), "utf8")) as { oidc: Record<string, Record<string, { payload: Record<string, unknown> }>> };
      const sessions = Object.values(state.oidc["AlpIdpSession"] ?? {});
      assert.equal(sessions.length, 1);
      assert.match(String(sessions[0]?.payload["refresh"]), /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    } finally {
      await w2.t.close();
    }
  });
});

describe("a cookie-key rotation on the file store", () => {
  let dir = "";
  let idp: StandInIdp | undefined;
  after(async () => {
    await idp?.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  test("new keys first and the old ones kept: the next refresh re-checks the person at the provider and succeeds, and re-seals the session under the new key; with the old cookie key gone, the refusal says why", async () => {
    dir = mkdtempSync(join(tmpdir(), "alp-oidc-rotate-"));
    const w1 = await startWorld({ users: genericUsers(), dataDir: dir, ports: RESTART_TEST_PORTS });
    idp = w1.idp;
    const { client, oauth } = await connectAgent(w1, "kim");
    assert.ok(client);
    await client.close();
    await w1.t.close();

    // The usual rollover: new signing keys and a new cookie key first, every old key kept after them.
    const keysPath = join(dir, "binding", "oauth-keys.json");
    const old = JSON.parse(readFileSync(keysPath, "utf8")) as AuthServerKeys;
    const fresh = await generateAuthServerKeys();
    writeFileSync(keysPath, JSON.stringify({ version: 1, signing: [...fresh.signing, ...old.signing], cookieKeys: [fresh.cookieKeys[0], ...old.cookieKeys] }), { mode: 0o600 });
    const w2 = await startWorld({ users: genericUsers(), dataDir: dir, idp: w1.idp, ports: w1.ports });
    try {
      const calls = w2.idp.tokenRequests["refresh_token"] ?? 0;
      ageProviderSessions(w2.t);
      assert.equal((await refreshAgent(w2, oauth)).status, 200, "the connection survives the rotation");
      assert.equal(w2.idp.tokenRequests["refresh_token"], calls + 1, "the person was re-checked at the provider");
      const sealed = Object.values((w2.t.server.state as BindingState).model("AlpIdpSession"))[0]?.payload["refresh"];
      assert.notEqual(new SecretBox([fresh.cookieKeys[0] ?? ""], "oidc sign-in secrets").open(String(sealed)), null, "re-sealed under the new first key");
    } finally {
      await w2.t.close();
    }

    // Replacing the cookie keys without keeping the old ones: the next refresh is refused, and the event says the stored
    // session can't be opened, not that the provider refused the person.
    const now = JSON.parse(readFileSync(keysPath, "utf8")) as AuthServerKeys;
    writeFileSync(keysPath, JSON.stringify({ ...now, cookieKeys: (await generateAuthServerKeys()).cookieKeys }), { mode: 0o600 });
    const w3 = await startWorld({ users: genericUsers(), dataDir: dir, idp: w1.idp, ports: w1.ports });
    try {
      ageProviderSessions(w3.t);
      const calls = w3.idp.tokenRequests["refresh_token"] ?? 0;
      assert.equal((await refreshAgent(w3, oauth)).status, 400);
      assert.equal(w3.idp.tokenRequests["refresh_token"] ?? 0, calls, "nothing was asked of the provider");
      const refused = w3.t.events.events.filter((e) => e.detail.event === "token_refused").map((e) => e.message ?? "");
      assert.ok(refused.some((m) => /stored identity-provider session can't be opened/.test(m)), refused.join(" | "));
      assert.ok(!refused.some((m) => /no longer accepts/.test(m)), "not blamed on the provider");
    } finally {
      await w3.t.close();
    }
  });
});

describe("configuration", () => {
  test("the examples in deploy/config.example.json parse", () => {
    const config = JSON.parse(readFileSync(new URL("../../deploy/config.example.json", import.meta.url), "utf8")) as { domains: string[]; identity_examples: Record<string, unknown> };
    const generic = parseOidcConfig(config.identity_examples["oidc"], config.domains);
    assert.equal(generic.discoveryUrl, "https://idp.example.org/.well-known/openid-configuration");
    const entra = parseOidcConfig(config.identity_examples["entra"], config.domains);
    assert.equal(entra.issuer, "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0");
    assert.deepEqual(entra.tenants, { "00000000-0000-0000-0000-000000000000": ["example.org"] });
    assert.deepEqual([entra.addressClaim, entra.groupClaims, entra.refreshCheck], ["preferred_username", ["roles"], true]);
    assert.ok(entra.scopes.includes("offline_access"));
    const multi = parseOidcConfig(config.identity_examples["entra_multi_tenant"], config.domains);
    assert.equal(multi.issuer, "https://login.microsoftonline.com/{tenantid}/v2.0");
    assert.equal(multi.discoveryUrl, "https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration");
  });

  test("mistakes are refused when the broker starts", () => {
    const d = ["example.org"];
    const base = { kind: "oidc", issuer: "https://idp.example.org", client_id: "x" };
    assert.throws(() => parseOidcConfig({ ...base, client_secret: "s" }, d), /ALP_OIDC_CLIENT_SECRET/);
    assert.throws(() => parseOidcConfig({ ...base, isser: "typo" }, d), /isser/);
    assert.throws(() => parseOidcConfig({ ...base, issuer: "http://idp.example.org" }, d), /issuer/);
    assert.throws(() => parseOidcConfig({ ...base, address_claim: "sub" }, d), /alias/);
    assert.throws(() => parseOidcConfig({ ...base, domains: ["other.example"] }, d), /not one of the broker's domains/);
    assert.throws(() => parseOidcConfig({ ...base, scopes: ["profile"] }, d), /openid/);
    assert.throws(() => parseOidcConfig({ kind: "oidc", provider: "entra", tenant: "organizations", client_id: "x" }, d), /tenants/);
    assert.throws(() => parseOidcConfig({ kind: "oidc", provider: "entra", tenant: "contoso", client_id: "x" }, d), /tenant/);
    assert.throws(() => parseOidcConfig({ kind: "oidc", provider: "entra", tenant: TENANT_A, tenants: { [TENANT_B]: ["example.org"] }, client_id: "x" }, d), /single-tenant/);
    // Entra sends oid (the binding) and preferred_username only with the profile scope.
    assert.throws(() => parseOidcConfig({ kind: "oidc", provider: "entra", tenant: TENANT_A, client_id: "x", scopes: ["openid", "email"] }, d), /"profile"/);
    assert.deepEqual(parseOidcConfig({ kind: "oidc", provider: "entra", tenant: TENANT_A, client_id: "x", scopes: ["openid", "profile"] }, d).scopes, ["openid", "profile", "offline_access"]);
  });
});

describe("the dev sign-in stays the default", () => {
  test("a dev broker serves no OIDC callback", async () => {
    const t = await startTestBroker();
    try {
      assert.equal((await fetch(`${t.base}/oidc/callback?code=x&state=y`)).status, 404);
      assert.equal((await fetch(`${t.web}/web/oidc/callback?code=x&state=y`)).status, 404);
      const login = await (await fetch(`${t.web}/web`)).text();
      assert.match(login, /Test identities only/);
    } finally {
      await t.close();
    }
  });
});
