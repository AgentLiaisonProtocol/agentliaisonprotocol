// SPDX-License-Identifier: FSL-1.1-ALv2
// The authorization server's client rules: client ID metadata documents (how Claude and ChatGPT connect), dynamic
// registration rules, redirect hosts, a fresh sign-in for every authorization, and the access token's shape.

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair } from "jose";
import type { JWK } from "jose";
import { Browser, TEST_SECRET, TestOAuthClient, csrfFrom, signInAndAllow, startTestBroker } from "../mcp/testkit.ts";
import { onFreePorts } from "../test-ports.ts";
import { StateAdapter } from "./adapter.ts";
import { SignInLimiter, sourceOf } from "./interaction.ts";
import { AUTH_FETCH_DEADLINE_MS } from "./provider.ts";
import { sourcePrefix } from "./sources.ts";
import { sha256b64u } from "./state.ts";
import type { BindingState } from "./state.ts";
import type { TestBroker } from "../mcp/testkit.ts";

const REDIRECT = "http://127.0.0.1:47199/callback";

/** Client ID metadata documents the test "vendors" publish (served through the authorization server's fetch hook). */
const DOCS: Record<string, Record<string, unknown>> = {
  "https://agent.vendor.example/oauth/client.json": {
    client_id: "https://agent.vendor.example/oauth/client.json",
    client_name: "Vendor Agent",
    redirect_uris: [REDIRECT],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  },
  // Shaped like Claude's published document, including a grant type this broker doesn't offer.
  "https://claude.example/oauth/mcp-oauth-client-metadata": {
    client_id: "https://claude.example/oauth/mcp-oauth-client-metadata",
    client_name: "Claude-shaped client",
    client_uri: "https://claude.example",
    redirect_uris: [REDIRECT],
    grant_types: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  },
  // A vendor-wide public client (shared by every account of the product).
  "https://public.vendor.example/oauth/client.json": {
    client_id: "https://public.vendor.example/oauth/client.json",
    client_name: "Company agent (self-declared)",
    redirect_uris: [REDIRECT],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  },
  "https://phish.example/client.json": {
    client_id: "https://phish.example/client.json",
    client_name: "Claude",
    redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  },
};

// Shaped like Claude Code's published document: loopback callbacks with no port, and no application_type.
DOCS["https://cli.vendor.example/oauth/client.json"] = {
  client_id: "https://cli.vendor.example/oauth/client.json",
  client_name: "CLI agent",
  redirect_uris: ["http://localhost/callback", "http://127.0.0.1/callback"],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
};

// A ChatGPT-shaped confidential client: private_key_jwt with RS256 and a published JWKS.
const GPT_ID = "https://gpt.example/oauth/client.json";
const gptKeys = await generateKeyPair("RS256", { extractable: true });
const gptJwk: JWK = { ...(await exportJWK(gptKeys.publicKey)), kid: "gpt-test-1", alg: "RS256", use: "sig" };
DOCS[GPT_ID] = {
  client_id: GPT_ID,
  client_name: "GPT-shaped client",
  client_uri: "https://gpt.example/",
  redirect_uris: [REDIRECT],
  token_endpoint_auth_method: "private_key_jwt",
  token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
  token_endpoint_auth_signing_alg: "RS256",
  jwks_uri: "https://gpt.example/oauth/jwks.json",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
};
DOCS["https://gpt.example/oauth/jwks.json"] = { keys: [gptJwk] };

// Clients whose key sets break spec 4.3's fetch rules (each is refused before any key is used).
const attacker = await generateKeyPair("RS256", { extractable: true });
const attackerJwk: JWK = { ...(await exportJWK(attacker.publicKey)), kid: "attacker-1", alg: "RS256", use: "sig" };
for (const [name, jwksUri] of [["bigkeys", "https://bigkeys.vendor.example/jwks.json"], ["smallkeys", "https://smallkeys.vendor.example/jwks.json"], ["htmlkeys", "https://htmlkeys.vendor.example/jwks.json"], ["bounce", "https://bounce.vendor.example/jwks.json"], ["port", "https://port.vendor.example:8443/jwks.json"]] as const) {
  DOCS[`https://${name}.vendor.example/client.json`] = { client_id: `https://${name}.vendor.example/client.json`, client_name: name, redirect_uris: [REDIRECT], token_endpoint_auth_method: "private_key_jwt", token_endpoint_auth_signing_alg: "RS256", jwks_uri: jwksUri, grant_types: ["authorization_code"], response_types: ["code"] };
}

/** Every outbound fetch the authorization server made, with the redirect mode it asked for. */
const fetched: { url: string; redirect: string | undefined }[] = [];

const testFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  fetched.push({ url, redirect: init?.redirect });
  // The same usable key, once in a 70 KiB key set and once in a small one.
  if (url === "https://bigkeys.vendor.example/jwks.json") return new Response(JSON.stringify({ keys: [{ ...attackerJwk, x_padding: "x".repeat(70 * 1024) }] }), { status: 200, headers: { "content-type": "application/json" } });
  if (url === "https://smallkeys.vendor.example/jwks.json") return new Response(JSON.stringify({ keys: [attackerJwk] }), { status: 200, headers: { "content-type": "application/json" } });
  if (url === "https://htmlkeys.vendor.example/jwks.json") return new Response(JSON.stringify({ keys: [attackerJwk] }), { status: 200, headers: { "content-type": "text/html" } });
  if (url === "https://bounce.vendor.example/jwks.json") return new Response(null, { status: 302, headers: { location: "https://elsewhere.example/jwks.json" } });
  if (/^https:\/\/fail[0-9]*\.vendor\.example\//.test(url)) return new Response("not here", { status: 404 });
  const doc = DOCS[url];
  if (doc) return new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json", "cache-control": "max-age=60" } });
  return new Response("no such test document", { status: 404 });
};

async function cimdConnect(t: TestBroker, clientId: string, username: string): Promise<{ client: Client; oauth: TestOAuthClient }> {
  const oauth = new TestOAuthClient({ name: "unused", clientMetadataUrl: clientId });
  const url = new URL(`${t.base}/mcp`);
  const first = new StreamableHTTPClientTransport(url, { authProvider: oauth });
  await assert.rejects(new Client({ name: "x", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } }).connect(first));
  assert.ok(oauth.lastAuthorizationUrl);
  assert.equal(oauth.lastAuthorizationUrl.searchParams.get("client_id"), clientId, "the SDK used the metadata document URL as its client_id");
  const cb = await signInAndAllow(oauth.lastAuthorizationUrl.href, username);
  await first.finishAuth(cb.searchParams);
  const client = new Client({ name: "x", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  await client.connect(new StreamableHTTPClientTransport(url, { authProvider: oauth }));
  return { client, oauth };
}

describe("authorization server", () => {
  let t: TestBroker;
  before(async () => {
    t = await startTestBroker({
      fetch: testFetch,
      staticClients: [
        { client_id: "copilot-preregistered", client_secret: "preregistered-test-secret-0123456789", client_name: "Pre-registered agent", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "client_secret_basic" },
        { client_id: "company-preregistered", client_secret: "company-test-secret-0123456789abcdef", client_name: "Company workspace agent", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "client_secret_basic" },
      ],
    });
  });
  after(async () => {
    await t?.close();
  });

  test("a client ID metadata document client connects without registering; its label comes from the verified host", async () => {
    const { client, oauth } = await cimdConnect(t, "https://agent.vendor.example/oauth/client.json", "ana");
    const w = (await client.callTool({ name: "alp_whoami", arguments: {} })) as CallToolResult;
    const s = w.structuredContent as Record<string, unknown>;
    assert.equal(s["delegate"], "alp:ana@example.org/vendor");
    assert.equal(s["attestation"], "vendor");
    const at = oauth.tokens()?.access_token ?? "";
    const claims = decodeJwt(at);
    assert.equal(decodeProtectedHeader(at).typ, "at+jwt");
    assert.equal(claims.aud, `${t.base}/mcp`, "RFC 8707: the audience is the canonical MCP URL");
    assert.equal(claims.client_id, "https://agent.vendor.example/oauth/client.json");
    assert.equal(claims["alp_delegate"], "alp:ana@example.org/vendor");
    assert.ok((claims.exp ?? 0) - (claims.iat ?? 0) <= 900);
    assert.deepEqual(String(claims["scope"]).split(" ").sort(), ["read", "send"]);
    await client.close();
  });

  test("a document shaped like Claude's (with a jwt-bearer grant type) is accepted; unsupported grant types are dropped", async () => {
    const { client } = await cimdConnect(t, "https://claude.example/oauth/mcp-oauth-client-metadata", "lee");
    const s = ((await client.callTool({ name: "alp_whoami", arguments: {} })) as CallToolResult).structuredContent as Record<string, unknown>;
    assert.equal(s["delegate"], "alp:lee@example.org/claude");
    await client.close();
  });


  /** A hand-driven authorization code flow, the way a hosted platform runs it (no SDK). */
  async function codeFlow(clientId: string, scope: string, extra: Record<string, string> = {}): Promise<{ code: string; verifier: string; callback: URL }> {
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope, resource: `${t.base}/mcp`, state: "s-123", ...extra });
    const callback = await signInAndAllow(`${t.base}/oauth/authorize?${q}`, "lee");
    assert.equal(callback.searchParams.get("state"), "s-123");
    assert.equal(callback.searchParams.get("iss"), t.base);
    return { code: callback.searchParams.get("code") ?? "", verifier, callback };
  }

  async function token(params: Record<string, string>): Promise<Record<string, unknown>> {
    const res = await fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(params).toString() });
    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(res.status, 200, JSON.stringify(body));
    return body;
  }

  test("a public client that doesn't send prompt=consent still gets a rotating refresh token", async () => {
    const { code, verifier } = await codeFlow("https://claude.example/oauth/mcp-oauth-client-metadata", "read send offline_access");
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: "https://claude.example/oauth/mcp-oauth-client-metadata", resource: `${t.base}/mcp` });
    assert.ok(typeof tok["refresh_token"] === "string", "refresh token issued");
    assert.equal(tok["token_type"], "Bearer");
    const next = await token({ grant_type: "refresh_token", refresh_token: String(tok["refresh_token"]), client_id: "https://claude.example/oauth/mcp-oauth-client-metadata", resource: `${t.base}/mcp` });
    assert.notEqual(next["refresh_token"], tok["refresh_token"]);
  });

  test("the binding state holds no usable token: no code, refresh token or session cookie, though each still works", async () => {
    const id = "https://claude.example/oauth/mcp-oauth-client-metadata";
    const browser = new Browser();
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: id, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send offline_access", resource: `${t.base}/mcp`, state: "s-raw" });
    const cb = await signInAndAllow(`${t.base}/oauth/authorize?${q}`, "lee", { browser });
    const code = cb.searchParams.get("code") ?? "";
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
    const next = await token({ grant_type: "refresh_token", refresh_token: String(tok["refresh_token"]), client_id: id, resource: `${t.base}/mcp` });
    const session = browser.cookieValue("_session");
    assert.ok(session, "the browser holds the authorization server's session cookie");
    const stored = JSON.stringify((t.server.state as BindingState).data.oidc);
    for (const [what, v] of [["code", code], ["refresh token", String(tok["refresh_token"])], ["rotated refresh token", String(next["refresh_token"])], ["session cookie", session ?? ""]] as const) {
      assert.ok(v.length >= 20 && !stored.includes(v), `no ${what} in the stored state`);
    }
    // Looked up by its hash, the newest refresh token still refreshes.
    await token({ grant_type: "refresh_token", refresh_token: String(next["refresh_token"]), client_id: id, resource: `${t.base}/mcp` });
  });

  test("a confidential client ID metadata document client (private_key_jwt, RS256, like ChatGPT's) completes the flow and refreshes", async () => {
    const { code, verifier } = await codeFlow(GPT_ID, "openid email profile read send offline_access", { prompt: "consent" });
    const assertion = async (): Promise<string> =>
      new SignJWT({}).setProtectedHeader({ alg: "RS256", kid: "gpt-test-1" }).setIssuer(GPT_ID).setSubject(GPT_ID).setAudience(`${t.base}/oauth/token`).setJti(randomUUID()).setIssuedAt().setExpirationTime("2m").sign(gptKeys.privateKey);
    const auth = async (): Promise<Record<string, string>> => ({ client_id: GPT_ID, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await assertion() });
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, resource: `${t.base}/mcp`, ...(await auth()) });
    assert.ok(tok["id_token"], "an ID token for the openid scope");
    assert.equal(decodeJwt(String(tok["access_token"])).aud, `${t.base}/mcp`);
    const r = await fetch(`${t.base}/rest/alp_whoami`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${String(tok["access_token"])}` }, body: "{}" });
    assert.equal(r.status, 401, "an MCP-audience token is not a REST token");
    const viaSdk = new Client({ name: "gpt", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await viaSdk.connect(new StreamableHTTPClientTransport(new URL(`${t.base}/mcp`), { authProvider: { token: async () => String(tok["access_token"]) } }));
    const who = ((await viaSdk.callTool({ name: "alp_whoami", arguments: {} })) as CallToolResult).structuredContent as Record<string, unknown>;
    assert.equal(who["delegate"], "alp:lee@example.org/gpt");
    await viaSdk.close();
    const next = await token({ grant_type: "refresh_token", refresh_token: String(tok["refresh_token"]), resource: `${t.base}/mcp`, ...(await auth()) });
    assert.ok(next["access_token"] && next["refresh_token"] !== tok["refresh_token"]);
    const noAssertion = await fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: String(next["refresh_token"]), client_id: GPT_ID }).toString() });
    assert.equal(noAssertion.status, 401, "a confidential client must authenticate");
  });

  test("a pre-registered confidential client (client_secret_basic) completes the flow", async () => {
    const { code, verifier } = await codeFlow("copilot-preregistered", "read send");
    const res = await fetch(`${t.base}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from("copilot-preregistered:preregistered-test-secret-0123456789").toString("base64")}` },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, resource: `${t.base}/mcp` }).toString(),
    });
    const tok = (await res.json()) as Record<string, unknown>;
    assert.equal(res.status, 200, JSON.stringify(tok));
    assert.equal(decodeJwt(String(tok["access_token"]))["alp_delegate"], "alp:lee@example.org/pre-registered-agent", "spec 5.4: a pre-registered client's label comes from its registration");
  });

  /** The connector sign-in page a client's authorization request opens. */
  async function consentPage(clientId: string): Promise<string> {
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    const b = new Browser();
    const first = await b.follow(await b.request(`${t.base}/oauth/authorize?${q}`), t.base);
    assert.equal(first.res.status, 200);
    return first.res.text();
  }

  test("spec 5.6 item 5: the consent page says where the client's name comes from: a metadata document, the operator's registration, or the client itself", async () => {
    const pre = await consentPage("copilot-preregistered");
    assert.match(pre, /<strong>Pre-registered agent<\/strong> wants to act for you/);
    assert.match(pre, /Registered with this broker by its operator; its name comes from that registration\./);
    assert.match(pre, /attestation <code>self<\/code> \(the lowest: the operator(?:'|&#39;)s registration doesn(?:'|&#39;)t raise it\)/, "spec 5.4: why a registered client is self");
    assert.doesNotMatch(pre, /unverified name|dynamic registration/);
    assert.match(pre, /This agent will appear as <code>pre-registered-agent<\/code>/, "the label comes from the registration");
    assert.doesNotMatch(pre, /name="label"/, "the person isn't asked for one");

    const reg = await fetch(`${t.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Some agent", application_type: "native", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }) });
    assert.equal(reg.status, 201);
    const dynamic = await consentPage(String(((await reg.json()) as Record<string, unknown>)["client_id"]));
    assert.match(dynamic, /<strong>Some agent \(unverified name\)<\/strong>/);
    assert.match(dynamic, /Its name is self-declared \(dynamic registration\)/);
    assert.match(dynamic, /name="label"/, "the person names it");
    assert.doesNotMatch(dynamic, /the lowest/);

    const cimd = await consentPage("https://agent.vendor.example/oauth/client.json");
    assert.match(cimd, /Its identity comes from a client metadata document on <code>agent\.vendor\.example<\/code>/);
    assert.doesNotMatch(cimd, /Registered with this broker|dynamic registration/);
  });

  test("spec 5.6 item 5: on a broker that serves several organizations, the consent page shows nothing of another organization's list of agents", async () => {
    const original = t.dev.policies[0];
    assert.ok(original?.clients);
    const reg = await fetch(`${t.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Some agent", application_type: "native", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }) });
    assert.equal(reg.status, 201);
    const dynamicId = String(((await reg.json()) as Record<string, unknown>)["client_id"]);
    // Another organization on this broker lists the pre-registered client as tenant, and the dynamically registered one
    // under a name of its own; example.org's list names neither.
    const other = { ...structuredClone(original), id: "other-org", domains: ["other.example"], clients: { mode: "enforce" as const, allowed: [
      { client_id: "copilot-preregistered", scopes: ["alp.briefing/1"], attestation: "tenant" as const, class: "enterprise" as const, no_training: true },
      { client_id: dynamicId, label: "other-orgs-label", scopes: ["alp.briefing/1"], attestation: "org-client" as const, class: "business" as const, no_training: true },
    ] } };
    t.dev.policies.push(other);
    try {
      const pre = await consentPage("copilot-preregistered");
      assert.doesNotMatch(pre, /tenant|registration of this client\)/, "neither the attestation the other list gives it nor that a list names it");
      assert.match(pre, /attestation <code>self<\/code> \(the lowest: the operator(?:'|&#39;)s registration doesn(?:'|&#39;)t raise it\), unless your organization(?:'|&#39;)s list of agents names this client/);
      const dynamic = await consentPage(dynamicId);
      assert.doesNotMatch(dynamic, /other-orgs-label|org-client/, "nor the name or attestation the other list gives a dynamically registered client");
      assert.match(dynamic, /name="label"/, "the person names it, as any dynamically registered client");
      // Lee (example.org) gets the name he gives it, which the page asked him for.
      const verifier = randomBytes(32).toString("base64url");
      const q = new URLSearchParams({ response_type: "code", client_id: dynamicId, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
      await signInAndAllow(`${t.base}/oauth/authorize?${q}`, "lee", { label: "lees-name" });
      assert.equal((await t.dev.broker.store.listDelegates("alp:lee@example.org")).find((d) => d.client_id === dynamicId)?.label, "lees-name");
    } finally {
      t.dev.policies.splice(t.dev.policies.indexOf(other), 1);
    }
  });

  /** A dynamically registered client connected through the MCP SDK, signed in as `username` with the agent name `label`. */
  async function dcrConnect(username: string, label: string): Promise<Client> {
    const oauth = new TestOAuthClient({ name: "Some agent" });
    const url = new URL(`${t.base}/mcp`);
    const first = new StreamableHTTPClientTransport(url, { authProvider: oauth });
    await assert.rejects(new Client({ name: "x", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } }).connect(first));
    assert.ok(oauth.lastAuthorizationUrl);
    const cb = await signInAndAllow(oauth.lastAuthorizationUrl.href, username, { label });
    await first.finishAuth(cb.searchParams);
    const client = new Client({ name: "x", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await client.connect(new StreamableHTTPClientTransport(url, { authProvider: oauth }));
    return client;
  }

  test("spec 5.4: a client that takes a disconnected client's agent name is a new agent: it sees none of the earlier one's messages", async () => {
    const earlier = await dcrConnect("ana", "relay");
    const sender = await t.dev.broker.registerDelegate({ principal: "alp:ana@example.org", label: "relay-sender", client_id: "pat" });
    const sent = await t.dev.broker.send({ kind: "delegate", principal: "alp:ana@example.org", delegate: sender.id, client_id: "pat" }, { to: "alp:ana@example.org", to_delegate: "alp:ana@example.org/relay", scope: "alp.availability/1", type: "request", body: { window: { start: "2026-11-11T14:00:00Z", end: "2026-11-11T18:00:00Z" }, duration_minutes: 15 } });
    assert.equal(sent.status, "delivered", JSON.stringify(sent));
    const id = sent.status === "delivered" ? sent.envelope.id : "";
    const items = async (c: Client): Promise<unknown[]> => (((await c.callTool({ name: "alp_inbox", arguments: { include_acked: true } })) as CallToolResult).structuredContent as { items: { id: string }[] }).items.map((i) => i.id);
    assert.ok((await items(earlier)).includes(id));
    await earlier.close();
    await t.dev.broker.revokeDelegate("alp:ana@example.org/relay");

    const later = await dcrConnect("ana", "relay");
    const who = ((await later.callTool({ name: "alp_whoami", arguments: {} })) as CallToolResult).structuredContent as Record<string, unknown>;
    assert.equal(who["delegate"], "alp:ana@example.org/relay", "the other client took the name");
    assert.equal((await items(later)).includes(id), false);
    const th = ((await later.callTool({ name: "alp_thread", arguments: { thread: sent.status === "delivered" ? sent.thread : "" } })) as CallToolResult).structuredContent as { messages: unknown[] };
    assert.deepEqual(th.messages, [], "nor in the thread view");
    await later.close();
  });

  test("org-client (spec 5.4): a pre-registered client with a credential gets it; a public client listed that way is refused", async () => {
    const original = t.dev.policies[0];
    assert.ok(original?.clients);
    const scopes = ["alp.briefing/1", "alp.status/1"];
    const admin = { kind: "admin" as const, operator: "test" };
    // The broker and the sign-in page read the same configured policy; install the change in both.
    const install = async (p: typeof original): Promise<void> => {
      await t.dev.broker.setOrgPolicy(admin, p);
      t.dev.policies[0] = p;
    };
    await install({
      ...structuredClone(original),
      serial: original.serial + 1,
      clients: {
        ...original.clients,
        allowed: [
          ...original.clients.allowed,
          { client_id: "company-preregistered", label: "company", scopes, attestation: "org-client", class: "enterprise", no_training: true },
          { client_id: "https://public.vendor.example/oauth/client.json", scopes, attestation: "org-client", class: "enterprise", no_training: true },
        ],
      },
    });
    try {
      const { code, verifier } = await codeFlow("company-preregistered", "read send");
      const res = await fetch(`${t.base}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from("company-preregistered:company-test-secret-0123456789abcdef").toString("base64")}` },
        body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, resource: `${t.base}/mcp` }).toString(),
      });
      assert.equal(res.status, 200);
      const company = await t.dev.broker.store.getDelegate("alp:lee@example.org/company");
      assert.equal(company?.attestation, "org-client");
      assert.equal(company?.class, "enterprise");
      const oauth = new TestOAuthClient({ name: "unused", clientMetadataUrl: "https://public.vendor.example/oauth/client.json" });
      const first = new StreamableHTTPClientTransport(new URL(`${t.base}/mcp`), { authProvider: oauth });
      await assert.rejects(new Client({ name: "x", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } }).connect(first));
      assert.ok(oauth.lastAuthorizationUrl);
      await assert.rejects(signInAndAllow(oauth.lastAuthorizationUrl.href, "ana"), /status 403/, "a public client can't stand for a credential the broker issued");
    } finally {
      await install({ ...structuredClone(original), serial: original.serial + 2 });
    }
  });

  test("a metadata document can't send codes to another host", async () => {
    const b = new Browser();
    const q = new URLSearchParams({ response_type: "code", client_id: "https://phish.example/client.json", redirect_uri: "https://claude.ai/api/mcp/auth_callback", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    const res = await b.request(`${t.base}/oauth/authorize?${q}`);
    assert.equal(res.status, 400);
    assert.equal(res.headers.get("location"), null, "nothing is redirected");
  });

  test("dynamic registration: application_type is required and redirect hosts are limited", async () => {
    const reg = (body: Record<string, unknown>): Promise<Response> => fetch(`${t.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const noType = await reg({ client_name: "x", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" });
    assert.equal(noType.status, 400);
    assert.equal(((await noType.json()) as Record<string, unknown>)["error"], "invalid_client_metadata");
    const evil = await reg({ client_name: "x", application_type: "web", redirect_uris: ["https://evil.example/cb"], token_endpoint_auth_method: "none" });
    assert.equal(evil.status, 400);
    assert.equal(((await evil.json()) as Record<string, unknown>)["error"], "invalid_redirect_uri");
    const ok = await reg({ client_name: "x", application_type: "web", redirect_uris: ["https://claude.ai/api/mcp/auth_callback"], token_endpoint_auth_method: "none" });
    assert.equal(ok.status, 201);
    const okBody = (await ok.json()) as Record<string, unknown>;
    assert.deepEqual(okBody["grant_types"], ["authorization_code", "refresh_token"]);
  });

  test("every authorization asks the person to sign in again, even in a browser that just signed in", async () => {
    const b = new Browser();
    const one = new TestOAuthClient({ name: "first" });
    const t1 = new StreamableHTTPClientTransport(new URL(`${t.base}/mcp`), { authProvider: one });
    await assert.rejects(new Client({ name: "a", version: "1" }).connect(t1));
    await signInAndAllow(one.lastAuthorizationUrl?.href ?? "", "ana", { browser: b });
    const two = new TestOAuthClient({ name: "second" });
    const t2 = new StreamableHTTPClientTransport(new URL(`${t.base}/mcp`), { authProvider: two });
    await assert.rejects(new Client({ name: "b", version: "1" }).connect(t2));
    const first = await b.follow(await b.request(two.lastAuthorizationUrl?.href ?? ""), t.base);
    assert.equal(first.location, undefined, "no silent redirect back to the client");
    assert.equal(first.res.status, 200);
    assert.match(await first.res.text(), /Sign in as/);
  });

  test("cancelling on the sign-in page returns access_denied with iss", async () => {
    const oauth = new TestOAuthClient({ name: "cancel" });
    const tr = new StreamableHTTPClientTransport(new URL(`${t.base}/mcp`), { authProvider: oauth });
    await assert.rejects(new Client({ name: "c", version: "1" }).connect(tr));
    const b = new Browser();
    const first = await b.follow(await b.request(oauth.lastAuthorizationUrl?.href ?? ""), t.base);
    const html = await first.res.text();
    const action = /<form method="post" action="([^"]+)"/.exec(html)?.[1] ?? "";
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? "";
    const done = await b.follow(await b.request(new URL(action, t.base).href, { form: { csrf, action: "deny" } }), t.base);
    const cb = new URL(done.location ?? "");
    assert.equal(cb.searchParams.get("error"), "access_denied");
    assert.equal(cb.searchParams.get("iss"), t.base, "RFC 9207: iss on errors too");
  });

  test("a wrong session secret signs nobody in", async () => {
    const oauth = new TestOAuthClient({ name: "wrong" });
    const tr = new StreamableHTTPClientTransport(new URL(`${t.base}/mcp`), { authProvider: oauth });
    await assert.rejects(new Client({ name: "w", version: "1" }).connect(tr));
    await assert.rejects(signInAndAllow(oauth.lastAuthorizationUrl?.href ?? "", "ana", { secret: "nope" }), /didn't return to the client/);
  });

  test("protected resource metadata follows the URL a person typed, trailing slash included", async () => {
    const res = await fetch(`${t.base}/mcp/`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(res.status, 401);
    assert.match(res.headers.get("www-authenticate") ?? "", /oauth-protected-resource\/mcp\/"/);
    const prm = (await (await fetch(`${t.base}/.well-known/oauth-protected-resource/mcp/`)).json()) as Record<string, unknown>;
    assert.equal(prm["resource"], `${t.base}/mcp/`);
  });

  // ---- review fixes: scopes, refresh races, loopback ports, registration, attestation levels, revocation

  async function install(change: (p: NonNullable<TestBroker["dev"]["policies"][0]>) => void): Promise<void> {
    const current = t.dev.policies[0];
    assert.ok(current);
    const next = structuredClone(current);
    next.serial = current.serial + 1;
    change(next);
    await t.dev.broker.setOrgPolicy({ kind: "admin", operator: "test" }, next);
    t.dev.policies[0] = next;
  }

  test("a client that asks for no resource scope gets read and send by default, and its token works", async () => {
    const id = "https://agent.vendor.example/oauth/client.json";
    for (const scope of ["openid email profile offline_access", "claudeai"]) {
      const { code, verifier } = await codeFlow(id, scope);
      const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
      assert.deepEqual(String(decodeJwt(String(tok["access_token"]))["scope"]).split(" ").filter((x) => x === "read" || x === "send").sort(), ["read", "send"], scope);
    }
  });

  test("a third use of a rotated refresh token, even within the reuse interval, revokes the connection", async () => {
    const id = "https://agent.vendor.example/oauth/client.json";
    const { code, verifier } = await codeFlow(id, "read send offline_access");
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
    const refresh = (rt: string): Promise<Response> => fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: id, resource: `${t.base}/mcp` }).toString() });
    const first = await refresh(String(tok["refresh_token"]));
    assert.equal(first.status, 200);
    const fresh = (await first.json()) as Record<string, unknown>;
    assert.equal((await refresh(String(tok["refresh_token"]))).status, 200, "one overlapping reuse is allowed");
    assert.equal((await refresh(String(tok["refresh_token"]))).status, 400, "a second reuse is theft, even inside 30 seconds");
    assert.equal((await refresh(String(fresh["refresh_token"]))).status, 400, "the whole connection was revoked");
  });

  test("two overlapping refreshes both succeed; reusing a rotated token later revokes the connection and its access token", async () => {
    const id = "https://agent.vendor.example/oauth/client.json";
    const { code, verifier } = await codeFlow(id, "read send offline_access");
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
    const refresh = (rt: string): Promise<Response> => fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: id, resource: `${t.base}/mcp` }).toString() });
    const [a, b] = await Promise.all([refresh(String(tok["refresh_token"])), refresh(String(tok["refresh_token"]))]);
    assert.equal(a.status, 200);
    assert.equal(b.status, 200, "a refresh that overlaps another isn't treated as theft");
    const fresh = (await a.json()) as Record<string, unknown>;
    // Past the reuse interval, presenting the rotated token again is theft: the whole connection ends.
    for (const e of Object.values((t.server.state as BindingState).model("RefreshToken"))) if (typeof e.payload["consumed"] === "number") e.payload["consumed"] = Math.floor(Date.now() / 1000) - 120;
    assert.equal((await refresh(String(tok["refresh_token"]))).status, 400);
    const call = await fetch(`${t.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${String(fresh["access_token"])}`, "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
    assert.equal(call.status, 401, "an access token of a revoked connection stops working at once");
  });

  test("a loopback redirect matches a registered one whatever its port (Claude Code's metadata lists none)", async () => {
    const id = "https://cli.vendor.example/oauth/client.json";
    const verifier = randomBytes(32).toString("base64url");
    const redirect = "http://localhost:54321/callback";
    const q = new URLSearchParams({ response_type: "code", client_id: id, redirect_uri: redirect, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    const cb = await signInAndAllow(`${t.base}/oauth/authorize?${q}`, "mallory");
    assert.equal(`${cb.origin}${cb.pathname}`, redirect);
    const tok = await token({ grant_type: "authorization_code", code: cb.searchParams.get("code") ?? "", redirect_uri: redirect, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
    assert.ok(tok["access_token"]);
  });

  test("dynamic registration: only the platforms' published callbacks, and unsupported scope values are dropped", async () => {
    const reg = (body: Record<string, unknown>): Promise<Response> => fetch(`${t.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const other = await reg({ client_name: "x", application_type: "web", redirect_uris: ["https://claude.ai/some/page"], token_endpoint_auth_method: "none" });
    assert.equal(other.status, 400, "any page on the platform's host could leak the code");
    const ok = await reg({ client_name: "x", application_type: "web", scope: "claudeai read", redirect_uris: ["https://chatgpt.com/connector_platform_oauth_redirect"], token_endpoint_auth_method: "none" });
    assert.equal(ok.status, 201, await ok.clone().text());
  });

  test("discovery advertises no UserInfo endpoint (every token is for the MCP or REST resource)", async () => {
    const oidc = (await (await fetch(`${t.base}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    assert.equal(oidc["userinfo_endpoint"], undefined);
  });

  test("the sign-in page always asks whether the person started the connection", async () => {
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: "https://agent.vendor.example/oauth/client.json", redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    const b = new Browser();
    const first = await b.follow(await b.request(`${t.base}/oauth/authorize?${q}`), t.base);
    assert.match(await first.res.text(), /Continue only if you started connecting this agent yourself/);
  });

  test("spec 5.4: a public client recorded as tenant, or as enterprise class, is refused at sign-in", async () => {
    const id = "https://public.vendor.example/oauth/client.json";
    for (const rule of [{ attestation: "tenant" as const, class: "business" as const }, { attestation: "vendor" as const, class: "enterprise" as const }]) {
      await install((p) => {
        if (!p.clients) return;
        p.clients.allowed = [...p.clients.allowed.filter((c) => c.client_id !== id), { client_id: id, scopes: ["alp.briefing/1"], ...rule, no_training: true }];
      });
      const verifier = randomBytes(32).toString("base64url");
      const q = new URLSearchParams({ response_type: "code", client_id: id, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
      await assert.rejects(signInAndAllow(`${t.base}/oauth/authorize?${q}`, "ana"), /status 403/, JSON.stringify(rule));
    }
    await install((p) => {
      if (p.clients) p.clients.allowed = p.clients.allowed.filter((c) => c.client_id !== id);
    });
  });

  test("spec 4.3: a client's key set is fetched on port 443 only, with no redirects, as JSON and at most 64 KiB", async () => {
    const assertion = async (clientId: string): Promise<string> =>
      new SignJWT({}).setProtectedHeader({ alg: "RS256", kid: "attacker-1" }).setIssuer(clientId).setSubject(clientId).setAudience(`${t.base}/oauth/token`).setJti(randomUUID()).setIssuedAt().setExpirationTime("2m").sign(attacker.privateKey);
    const tokenRequest = async (name: string): Promise<Response> => {
      const clientId = `https://${name}.vendor.example/client.json`;
      return fetch(`${t.base}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code: "not-a-code", redirect_uri: REDIRECT, code_verifier: "v".repeat(43), client_id: clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await assertion(clientId) }).toString(),
      });
    };
    const small = await tokenRequest("smallkeys");
    assert.equal(small.status, 400, "with a small key set the client authenticates; only the code is wrong");
    assert.match(await small.text(), /invalid_grant/);
    for (const name of ["bigkeys", "htmlkeys", "bounce", "port"]) {
      const res = await tokenRequest(name);
      assert.equal(res.status, 401, `${name}: the client's keys are never used: ${await res.clone().text()}`);
      assert.match(await res.text(), /invalid_client/);
    }
    assert.ok(!fetched.some((f) => f.url.startsWith("https://port.vendor.example:8443/")), "a key set on another port is never fetched");
    assert.ok(!fetched.some((f) => f.url.startsWith("https://elsewhere.example/")), "a redirect is never followed");
    assert.ok(fetched.filter((f) => f.url.includes(".vendor.example/")).every((f) => f.redirect === "manual"), "every fetch asks for no redirects");
  });

  test("spec 5.8: a blocked client can't refresh, and its tokens stop working", async () => {
    const id = "https://agent.vendor.example/oauth/client.json";
    const { code, verifier } = await codeFlow(id, "read send offline_access");
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
    await install((p) => {
      p.blocked = { client_ids: [id] };
    });
    try {
      const r = await fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: String(tok["refresh_token"]), client_id: id, resource: `${t.base}/mcp` }).toString() });
      assert.equal(r.status, 400);
      const call = await fetch(`${t.base}/rest/alp_inbox`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${String(tok["access_token"])}` }, body: "{}" });
      assert.equal(call.status, 401);
    } finally {
      await install((p) => {
        delete p.blocked;
      });
    }
  });

  test("spec 5.4: a connection acts only for the agent it was authorized for, also after that agent was disconnected some other way than the web view and the same client connected again", async () => {
    const id = "https://agent.vendor.example/oauth/client.json";
    const connect = async (): Promise<Record<string, unknown>> => {
      const { code, verifier } = await codeFlow(id, "read send offline_access");
      return token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
    };
    const inbox = (access: unknown): Promise<Response> => fetch(`${t.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${String(access)}`, "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "alp_inbox", arguments: {} } }) });
    const refresh = (rt: unknown): Promise<Response> => fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: String(rt), client_id: id, resource: `${t.base}/mcp` }).toString() });
    const earlier = await connect();
    assert.equal((await inbox(earlier["access_token"])).status, 200);
    const agent = (await t.dev.broker.store.listDelegates("alp:lee@example.org")).find((d) => d.client_id === id && d.status === "active");
    assert.ok(agent);
    // Disconnected through the broker's API (an operator's tool, say), which leaves the connection's grant in place.
    await t.dev.broker.revokeDelegate(agent.id);
    await new Promise((done) => setTimeout(done, 5));
    const later = await connect();
    const now = await t.dev.broker.store.getDelegate(agent.id);
    assert.equal(now?.status, "active");
    assert.notEqual(now?.created_at, agent.created_at, "the same client connecting again under that name is a new agent");
    assert.equal((await inbox(later["access_token"])).status, 200, "the new connection works");
    assert.equal((await inbox(earlier["access_token"])).status, 401, "the earlier connection's token doesn't act for the new agent");
    assert.equal((await refresh(earlier["refresh_token"])).status, 400, "nor can it refresh");
    assert.equal((await refresh(later["refresh_token"])).status, 200);
  });

  test("spec 5.4: a connection authorized before bindings were recorded is bound to its agent when it next gets a token", async () => {
    const id = "https://agent.vendor.example/oauth/client.json";
    const connect = async (): Promise<Record<string, unknown>> => {
      const { code, verifier } = await codeFlow(id, "read send offline_access");
      return token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
    };
    const inbox = (access: unknown): Promise<Response> => fetch(`${t.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${String(access)}`, "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "alp_inbox", arguments: {} } }) });
    const refresh = (rt: unknown): Promise<Response> => fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: String(rt), client_id: id, resource: `${t.base}/mcp` }).toString() });
    const earlier = await connect();
    // As a connection authorized before the broker recorded bindings: its grant has no binding record.
    const grantId = decodeJwt(String(earlier["access_token"]))["alp_grant"];
    assert.equal(typeof grantId, "string");
    await t.server.state.oidcDelete("AlpGrantBinding", sha256b64u(String(grantId)));
    const agent = (await t.dev.broker.store.listDelegates("alp:lee@example.org")).find((d) => d.client_id === id && d.status === "active");
    assert.ok(agent);
    // Its next token names the agent it acts for then (the client's newest active agent, as before), and binds it.
    const next = await token({ grant_type: "refresh_token", refresh_token: String(earlier["refresh_token"]), client_id: id, resource: `${t.base}/mcp` });
    const claims = decodeJwt(String(next["access_token"]));
    assert.equal(claims["alp_delegate"], agent.id);
    assert.equal(claims["alp_binding"], agent.created_at);
    // So once that agent is disconnected some other way than the web view and the same client connects again under the
    // name, the connection acts for neither.
    await t.dev.broker.revokeDelegate(agent.id);
    await new Promise((done) => setTimeout(done, 5));
    const later = await connect();
    assert.equal((await inbox(later["access_token"])).status, 200, "the new connection works");
    assert.equal((await inbox(next["access_token"])).status, 401, "the earlier connection's token doesn't act for the new agent");
    assert.equal((await refresh(next["refresh_token"])).status, 400, "nor can it refresh");
  });

  test("spec 5.4: a connection from before bindings is never bound to an agent that started after it was authorized; it is ended instead", async () => {
    const id = "https://agent.vendor.example/oauth/client.json";
    const connect = async (): Promise<Record<string, unknown>> => {
      const { code, verifier } = await codeFlow(id, "read send offline_access");
      return token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: id, resource: `${t.base}/mcp` });
    };
    const inbox = (access: unknown): Promise<Response> => fetch(`${t.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${String(access)}`, "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "alp_inbox", arguments: {} } }) });
    const refresh = (rt: unknown): Promise<Response> => fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: String(rt), client_id: id, resource: `${t.base}/mcp` }).toString() });
    const active = async () => (await t.dev.broker.store.listDelegates("alp:lee@example.org")).find((d) => d.client_id === id && d.status === "active");
    // As a connection authorized before the broker recorded bindings: its grant has no binding record.
    const earlier = await connect();
    const claims = decodeJwt(String(earlier["access_token"]));
    const grantId = String(claims["alp_grant"]);
    await t.server.state.oidcDelete("AlpGrantBinding", sha256b64u(grantId));
    const agent = await active();
    assert.ok(agent);
    // Before its next token, its agent is disconnected some other way than the web view, and the same client connects
    // again under the name, in a later second than the one the earlier connection was authorized in.
    await t.dev.broker.revokeDelegate(agent.id);
    while (Math.floor(Date.now() / 1000) <= Number(claims.iat)) await new Promise((done) => setTimeout(done, 20));
    const later = await connect();
    const newAgent = await active();
    assert.ok(newAgent && newAgent.id === agent.id && newAgent.created_at !== agent.created_at, "the same name, a new agent");
    assert.equal((await inbox(later["access_token"])).status, 200, "the new connection works");
    // The earlier connection would now act for the client's newest agent, which started after it was authorized: its
    // refresh is refused and the connection ended.
    assert.equal((await refresh(earlier["refresh_token"])).status, 400);
    assert.equal(await new StateAdapter(t.server.state, "Grant").find(grantId), undefined, "its grant is gone");
    assert.equal((await inbox(later["access_token"])).status, 200, "the new connection still works");
    assert.ok(t.events.events.some((e) => e.message?.includes("authorized before the agent it would act for")), "and the security events say why");
  });
});

describe("authorization server: fetching client metadata documents (spec 4.3 rule 6)", () => {
  let t: TestBroker;
  before(async () => {
    t = await startTestBroker({ fetch: testFetch, cimdLimits: { perSourcePerMinute: 3, totalPerMinute: 100, failureCacheSeconds: 120 } });
  });
  after(async () => {
    await t?.close();
  });

  const authorize = async (clientId: string): Promise<number> => {
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    const res = await fetch(`${t.base}/oauth/authorize?${q}`, { redirect: "manual" });
    await res.text();
    return res.status;
  };
  const failFetches = (): number => fetched.filter((f) => /^https:\/\/fail[0-9]*\.vendor\.example\//.test(f.url)).length;

  test("a document that failed isn't fetched again for a while, and one requester can't make the broker fetch without limit", async () => {
    const before = failFetches();
    for (let i = 0; i < 5; i++) assert.equal(await authorize("https://fail.vendor.example/client.json"), 400);
    assert.equal(failFetches() - before, 1, "the same failing document is fetched once, then the failure is cached");
    for (let i = 1; i <= 5; i++) assert.equal(await authorize(`https://fail${i}.vendor.example/client.json`), 400);
    assert.equal(failFetches() - before, 3, "three fetches a minute from one requester, then none");
  });
});

describe("authorization server: a fetch whose body never ends holds up no one", () => {
  // Node's fetch can leave a response body pending forever, with neither data nor an error: when its signal fires after
  // the body's last bytes arrived but before a compressed body was decoded (decoding runs on the libuv threadpool, so a
  // busy threadpool or a stalled event loop can put the signal there). oidc-provider makes every later authorization of
  // a client wait on the first fetch of its metadata document, so one such fetch kept that client from signing in until
  // a restart, while others still could. Nor may a body that never ends keep its connection open.
  const STALLED = "https://stalled.vendor.example/client.json";
  const OTHER = "https://other.vendor.example/client.json";
  const KEYS = "https://keys.vendor.example/client.json";
  /** Fetched with Node's own fetch, from the loopback server below. */
  const DRIPPING = "https://drip.vendor.example/client.json";
  const docs: Record<string, Record<string, unknown>> = {
    [STALLED]: { client_id: STALLED, client_name: "Stalled", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" },
    [OTHER]: { client_id: OTHER, client_name: "Other", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" },
    [KEYS]: { client_id: KEYS, client_name: "Keys", redirect_uris: [REDIRECT], token_endpoint_auth_method: "private_key_jwt", token_endpoint_auth_signing_alg: "RS256", jwks_uri: "https://keys.vendor.example/jwks.json", grant_types: ["authorization_code"], response_types: ["code"] },
  };
  const stalledUrls = new Set([STALLED, "https://keys.vendor.example/jwks.json"]);
  const served: string[] = [];
  /** What each request to the loopback server asked for, when it came and when its connection closed. */
  const drips: { acceptEncoding: string | undefined; at: number; closedAt?: number }[] = [];
  let dripServer: Server | undefined;
  let dripBase = "";
  const stallingFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    served.push(url);
    // The request as the broker made it (headers, signal, no redirects), without oidc-provider's dispatcher, which
    // refuses loopback addresses.
    if (url === DRIPPING) return fetch(`${dripBase}/client.json`, { headers: init?.headers ?? {}, redirect: init?.redirect ?? "manual", signal: init?.signal ?? null });
    const json = { "content-type": "application/json" };
    if (stalledUrls.has(url)) {
      // The headers and a first chunk, then nothing more: no data, no end and no error, whatever the signal says.
      const first = new TextEncoder().encode('{"client_id":');
      return new Response(new ReadableStream({ start: (c) => c.enqueue(first) }), { status: 200, headers: json });
    }
    const doc = docs[url];
    return doc ? new Response(JSON.stringify(doc), { status: 200, headers: json }) : new Response("no", { status: 404 });
  };
  let t: TestBroker;
  before(async () => {
    // Answers 404 and goes on sending the body, a few bytes every 100 ms, for as long as the connection stays open.
    // Another test process may take a pooled port between the check and the listen: onFreePorts tries new ones.
    dripServer = await onFreePorts(1, ([port]) =>
      new Promise<Server>((resolve, reject) => {
        const s = createServer((req, res) => {
          const drip: (typeof drips)[number] = { acceptEncoding: req.headers["accept-encoding"], at: Date.now() };
          drips.push(drip);
          res.writeHead(404, { "content-type": "text/plain" });
          res.write("not here");
          const timer = setInterval(() => res.write(", not here"), 100);
          res.on("close", () => {
            clearInterval(timer);
            drip.closedAt = Date.now();
          });
        });
        s.once("listening", () => resolve(s));
        s.once("error", reject);
        s.listen(port ?? 0, "127.0.0.1");
      }),
    );
    dripBase = `http://127.0.0.1:${(dripServer.address() as AddressInfo).port}`;
    t = await startTestBroker({ fetch: stallingFetch });
  });
  after(async () => {
    await t?.close();
    dripServer?.closeAllConnections();
    await new Promise<void>((done) => (dripServer ? dripServer.close(() => done()) : done()));
  });

  /** The status, or "no answer" when none came within `waitMs`. */
  const answer = async (url: string, init: RequestInit = {}, waitMs = 10_000): Promise<number | "no answer"> => {
    try {
      const res = await fetch(url, { ...init, redirect: "manual", signal: AbortSignal.timeout(waitMs) });
      await res.text();
      return res.status;
    } catch {
      return "no answer";
    }
  };
  const authorize = (clientId: string): Promise<number | "no answer"> => {
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    return answer(`${t.base}/oauth/authorize?${q}`);
  };
  const fetchesOf = (url: string): number => served.filter((u) => u === url).length;

  test("the authorizations waiting on a stalled metadata document fail by the fetch deadline; other clients sign in meanwhile", { timeout: 60_000 }, async () => {
    const started = Date.now();
    const first = authorize(STALLED);
    await new Promise((r) => setTimeout(r, 300));
    const later = authorize(STALLED);
    assert.equal(await authorize(OTHER), 303, "an unrelated client signs in while the fetch is stuck");
    assert.equal(await authorize("not-a-url-client"), 400, "an unknown client is refused at once");
    assert.deepEqual([await first, await later], [400, 400], "both authorizations answer: the fetch was given up");
    const took = Date.now() - started;
    assert.ok(took < AUTH_FETCH_DEADLINE_MS + 3000, `answered after ${took} ms`);
    assert.equal(fetchesOf(STALLED), 1, "the later authorization waited on the same fetch");
    assert.equal(await authorize(STALLED), 400, "for a while after, the client is refused at once");
    assert.equal(fetchesOf(STALLED), 1, "without fetching the document again");
  });

  test("a token request whose client key set stalls fails by the fetch deadline", { timeout: 60_000 }, async () => {
    const key = await generateKeyPair("RS256");
    const assertion = await new SignJWT({}).setProtectedHeader({ alg: "RS256" }).setIssuer(KEYS).setSubject(KEYS).setAudience(`${t.base}/oauth/token`).setJti(randomUUID()).setIssuedAt().setExpirationTime("2m").sign(key.privateKey);
    const body = new URLSearchParams({ grant_type: "authorization_code", code: "not-a-code", redirect_uri: REDIRECT, code_verifier: "v".repeat(43), client_id: KEYS, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion }).toString();
    const started = Date.now();
    const status = await answer(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
    assert.equal(status, 401, "the client can't authenticate: its keys never arrived");
    assert.ok(Date.now() - started < AUTH_FETCH_DEADLINE_MS + 3000, `answered after ${Date.now() - started} ms`);
    assert.equal(fetchesOf("https://keys.vendor.example/jwks.json"), 1);
  });

  test("a metadata document URL that answers 404 with a body that never ends: the authorization fails, and the broker closes the connection by the fetch deadline", { timeout: 60_000 }, async () => {
    const started = Date.now();
    assert.equal(await authorize(DRIPPING), 400, "the client is refused: its document isn't there");
    assert.ok(Date.now() - started < AUTH_FETCH_DEADLINE_MS + 3000, `answered after ${Date.now() - started} ms`);
    assert.equal(fetchesOf(DRIPPING), 1);
    const drip = drips[0];
    assert.ok(drip && drips.length === 1, "the loopback server got the one request");
    assert.equal(drip.acceptEncoding, "identity", "asking for an uncompressed body");
    // The server would go on sending forever: only the broker can end the connection. oidc-provider never reads the
    // body of a status other than 200, so the broker cancels it.
    while (drip.closedAt === undefined && Date.now() - drip.at < AUTH_FETCH_DEADLINE_MS + 3000) await new Promise((done) => setTimeout(done, 50));
    assert.ok(drip.closedAt !== undefined, `the connection was still open ${Date.now() - drip.at} ms after the request`);
    assert.ok(drip.closedAt - drip.at < AUTH_FETCH_DEADLINE_MS + 3000, `closed after ${drip.closedAt - drip.at} ms`);
  });
});

describe("authorization server: strangers spending the fetch budgets don't stop a listed client", () => {
  // The development policy lists Claude's published client id (report mode): a listed client.
  const LISTED = "https://claude.ai/oauth/mcp-oauth-client-metadata";
  const listedDoc = { client_id: LISTED, client_name: "Claude", redirect_uris: [REDIRECT], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none" };
  const served: string[] = [];
  const budgetFetch = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    served.push(url);
    const doc = url === LISTED ? listedDoc : /^https:\/\/unlisted-[0-9]+\.example\/client\.json$/.test(url) ? { ...listedDoc, client_id: url, client_name: "Unlisted" } : undefined;
    return doc ? new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } }) : new Response("no", { status: 404 });
  };
  let t: TestBroker;
  before(async () => {
    // Requests carry their source in X-Real-IP, as behind a proxy that sets it.
    t = await startTestBroker({ fetch: budgetFetch, clientIpHeader: "x-real-ip" });
  });
  after(async () => {
    await t?.close();
  });
  const authorize = async (clientId: string, source: string): Promise<number> => {
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    const res = await fetch(`${t.base}/oauth/authorize?${q}`, { redirect: "manual", headers: { "x-real-ip": source } });
    await res.text();
    return res.status;
  };

  test("after 200 unlisted client ids from 10 sources, a listed client's refresh and a new authorization both succeed", async () => {
    const { client, oauth } = await cimdConnect(t, LISTED, "ana");
    await client.close();
    // 20 unlisted documents from each of 10 sources: the whole total budget (200 a minute), and more than the 100
    // documents oidc-provider keeps cached, so the listed client's document has to be fetched again.
    const statuses: number[] = [];
    for (let i = 0; i < 200; i++) statuses.push(await authorize(`https://unlisted-${i}.example/client.json`, `203.0.113.${i % 10}`));
    assert.equal(statuses.filter((x) => x === 303).length, 200, "each source within its 20, and the listed client's own fetch counted toward no budget");
    assert.equal(await authorize("https://unlisted-200.example/client.json", "198.51.100.200"), 400, "the total budget is spent for unlisted clients");
    const fetchedBefore = served.filter((u) => u === LISTED).length;
    const rt = oauth.tokens()?.refresh_token ?? "";
    const refresh = await fetch(`${t.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-real-ip": "198.51.100.201" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: LISTED }).toString() });
    assert.equal(refresh.status, 200, await refresh.clone().text());
    assert.equal(served.filter((u) => u === LISTED).length, fetchedBefore + 1, "the listed client's document was fetched again, outside the budget");
    assert.equal(await authorize(LISTED, "198.51.100.202"), 303, "a new authorization of the listed client");
  });

  test("dynamic registrations count per /64: the 21st from one /64 is refused", async () => {
    const register = async (source: string): Promise<number> => {
      const res = await fetch(`${t.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json", "x-real-ip": source }, body: JSON.stringify({ client_name: "Script", application_type: "native", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }) });
      await res.text();
      return res.status;
    };
    for (let i = 1; i <= 20; i++) assert.equal(await register(`2001:db8:5:6::${i.toString(16)}`), 201, `registration ${i}`);
    assert.equal(await register("2001:db8:5:6:ffff:ffff:ffff:ffff"), 429, "another address in the same /64");
    assert.equal(await register("2001:db8:5:7::1"), 201, "another /64 has its own budget");
  });

  test("failed connector sign-ins count an IPv6 source by its /64: ten from one /64 pause that name from every address in it", async () => {
    const b = new Browser();
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: LISTED, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    const page = await b.follow(await b.request(`${t.base}/oauth/authorize?${q}`), t.base);
    const html = await page.res.text();
    const action = new URL(/<form method="post" action="([^"]+)"/.exec(html)?.[1] ?? "", t.base).href;
    const form = (secret: string): Record<string, string> => ({ csrf: csrfFrom(html), username: "lee", secret, action: "allow", ...(html.includes('name="label"') ? { label: "agent" } : {}) });
    const from = async (source: string, secret: string): Promise<{ status: number; text: string }> => {
      const res = await b.request(action, { form: form(secret), headers: { "x-real-ip": source } });
      return { status: res.status, text: await res.text() };
    };
    for (let i = 1; i <= 10; i++) assert.match((await from(`2001:db8:9:1::${i.toString(16)}`, `wrong-${i}`)).text, /Sign-in failed/, `failure ${i}`);
    assert.match((await from("2001:db8:9:1:ffff:ffff:ffff:ffff", TEST_SECRET)).text, /Too many failed sign-ins/, "another address in the same /64, with the right secret");
    const other = await from("2001:db8:9:2::1", TEST_SECRET);
    assert.doesNotMatch(other.text, /Too many failed sign-ins|Sign-in failed/, "another /64 isn't paused");
  });
});

test("an IPv6 source counts by its /64 for the limits a stranger could otherwise multiply", () => {
  assert.equal(sourcePrefix("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2::/64");
  assert.equal(sourcePrefix("2001:0DB8:0001:0002::1"), "2001:db8:1:2::/64", "the same /64, written another way");
  assert.equal(sourcePrefix("[2001:db8:1:3::1]"), "2001:db8:1:3::/64", "another /64");
  assert.equal(sourcePrefix("::ffff:198.51.100.7"), "198.51.100.7", "an IPv4-mapped address is its IPv4 address");
  assert.equal(sourcePrefix("198.51.100.7"), "198.51.100.7");
  assert.equal(sourcePrefix("unknown"), "unknown");
});

describe("the connector sign-in page: requests per source", () => {
  let t: TestBroker;
  before(async () => {
    t = await startTestBroker({ connectorPostsPerMinute: 3 });
  });
  after(async () => {
    await t?.close();
  });
  test("past the cap a POST is refused before any secret is checked or sign-in started (429, Retry-After)", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await fetch(`${t.base}/interaction/no-such-interaction`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: "ana", secret: "wrong", action: "allow" }).toString() });
      statuses.push(res.status);
      if (res.status === 429) assert.equal(res.headers.get("retry-after"), "60");
      await res.text();
    }
    assert.deepEqual(statuses, [400, 400, 400, 429], "three are looked at (no such sign-in), the fourth isn't");
  });
});

test("the sign-in limiter's backstop counts only failures for identities that exist", async () => {
  const limiter = new SignInLimiter({ max: 10, maxAll: 100 });
  const now = Date.now();
  for (let i = 0; i < 300; i++) await limiter.fail(`203.0.113.9|nobody${i}`, now, false);
  assert.equal(await limiter.blocked("198.51.100.7|ana", now), false, "made-up names never lock out the person at the keyboard");
  for (let i = 0; i < 100; i++) await limiter.fail(`203.0.113.${i % 50}|ana`, now, true);
  assert.equal(await limiter.blocked("198.51.100.7|lee", now), true, "the backstop still holds against failures on real identities");
});

test("per-source limits trust a client-address header only when the operator names the platform that sets it", () => {
  const req = (headers: Record<string, string>) => ({ headers, socket: { remoteAddress: "10.0.0.9" } }) as unknown as Parameters<typeof sourceOf>[0];
  assert.equal(sourceOf(req({ "x-real-ip": "198.51.100.7" })), "10.0.0.9", "not configured: the socket's address");
  assert.equal(sourceOf(req({ "x-real-ip": "198.51.100.7" }), false, "x-real-ip"), "198.51.100.7");
  assert.equal(sourceOf(req({ "x-forwarded-for": "203.0.113.5, 10.1.1.1" }), false, "x-forwarded-for"), "10.1.1.1", "the right-most address of a list: the one the proxy in front appended");
  assert.equal(sourceOf(req({ "x-forwarded-for": "203.0.113.5, 10.1.1.1" }), false, "x-forwarded-for", 2), "203.0.113.5", "two proxies append: the second from the right");
  assert.equal(sourceOf(req({ "cf-connecting-ip": "192.0.2.1", "x-real-ip": "198.51.100.7" }), true, "x-real-ip"), "192.0.2.1", "behind Cloudflare, its header");
  assert.equal(sourceOf(req({}), false, "x-real-ip"), "10.0.0.9", "a missing header falls back to the socket");
});

test("per-source limits can't be dodged by a client that writes its own X-Forwarded-For entries", () => {
  const req = (headers: Record<string, string | string[]>) => ({ headers, socket: { remoteAddress: "10.0.0.9" } }) as unknown as Parameters<typeof sourceOf>[0];
  // nginx with $proxy_add_x_forwarded_for, Azure Application Gateway, Front Door: the client's own header comes first,
  // and the proxy appends the address it saw. A new made-up first entry on every request no longer counts as a new source.
  for (const spoof of ["1.2.3.4", "5.6.7.8, 9.9.9.9", "unknown"]) {
    assert.equal(sourceOf(req({ "x-forwarded-for": `${spoof}, 198.51.100.7` }), false, "x-forwarded-for"), "198.51.100.7", spoof);
    assert.equal(sourceOf(req({ "x-forwarded-for": `${spoof}, 198.51.100.7, 10.2.2.2` }), false, "x-forwarded-for", 2), "198.51.100.7", `${spoof}, behind two proxies`);
  }
  assert.equal(sourceOf(req({ "x-forwarded-for": ["1.2.3.4", "198.51.100.7"] }), false, "x-forwarded-for"), "198.51.100.7", "repeated header lines read as one list");
  assert.equal(sourceOf(req({ "x-forwarded-for": "1.2.3.4, 198.51.100.7:51234" }), false, "x-forwarded-for"), "198.51.100.7", "a port an Application Gateway adds is dropped");
  assert.equal(sourceOf(req({ "x-forwarded-for": "1.2.3.4, [2001:db8::7]:51234" }), false, "x-forwarded-for"), "2001:db8::7");
  assert.equal(sourceOf(req({ "x-forwarded-for": "198.51.100.7" }), false, "x-forwarded-for", 3), "198.51.100.7", "fewer entries than proxies: the farthest there is");
  assert.equal(sourceOf(req({ "cf-connecting-ip": "192.0.2.1" }), true, undefined, 3), "192.0.2.1", "Cloudflare's header is one address, whatever the hops");
});
