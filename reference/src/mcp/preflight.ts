// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run preflight`: scripted checks against a running dev broker through its public URL (the tunnel), before
// anyone adds a real connector. Test identities and test data only. It never prints tokens or the
// session secret.
//
//   PUBLIC_URL=https://<name>.trycloudflare.com ALP_DEV_LOGIN_SECRET=<the broker's secret> npm run preflight
//   (WEB_URL, default http://127.0.0.1:47111, is the broker's loopback web view, for the personal access token check)
//
// Checks: discovery documents (and no UserInfo endpoint); the 401 challenge; that the broker can fetch Claude's two
// and ChatGPT's published client metadata documents and accepts their callback URLs (an authorization request that
// stops at the sign-in page); dynamic registration + PKCE + code exchange with both MCP eras (2026-07-28 as Ana,
// 2025-11-25 as Lee); a client that asks only for OpenID scopes (as ChatGPT does by default) still gets a token that
// can call the tools; a alp.availability/1 request from Ana's agent to Lee's, the reply, acks; refresh token rotation,
// including two overlapping refreshes; and a personal access token minted on the web view, used through the tunnel on
// both the MCP endpoint and the REST mirror, then revoked.

import { createHash, randomBytes } from "node:crypto";
import { Client, StreamableHTTPClientTransport, refreshAuthorization } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";
import { Client as V1Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport as V1Transport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { KNOWN_CLIENTS } from "../dev-world.ts";
import { Browser, TestOAuthClient, signInAndAllow } from "./testkit.ts";

const base = (process.env["PUBLIC_URL"] ?? "").replace(/\/+$/, "");
const secret = process.env["ALP_DEV_LOGIN_SECRET"] ?? "";
const webUrl = (process.env["WEB_URL"] ?? "http://127.0.0.1:47111").replace(/\/+$/, "");
let failures = 0;

function ok(name: string): void {
  console.log(`  ok    ${name}`);
}
function bad(name: string, why: string): void {
  failures++;
  console.log(`  FAIL  ${name}: ${why}`);
}
async function check(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    ok(name);
  } catch (err) {
    bad(name, err instanceof Error ? err.message.split("\n")[0] ?? "" : String(err));
  }
}
function must(cond: unknown, why: string): asserts cond {
  if (!cond) throw new Error(why);
}
function sc(r: unknown): Record<string, unknown> {
  const s = (r as CallToolResult).structuredContent;
  must(s && typeof s === "object", `no structured result: ${JSON.stringify(r).slice(0, 200)}`);
  return s as Record<string, unknown>;
}

async function main(): Promise<void> {
  if (!/^https:\/\//.test(base) && !/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(base)) {
    console.error("Set PUBLIC_URL to the broker's public origin (the tunnel's https URL).");
    process.exit(2);
  }
  if (!secret) {
    console.error("Set ALP_DEV_LOGIN_SECRET to the session secret the broker printed.");
    process.exit(2);
  }
  console.log(`Preflight against ${base}\n`);
  const mcp = `${base}/mcp`;

  await check("protected resource metadata names this URL and issuer", async () => {
    const prm = (await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json()) as Record<string, unknown>;
    must(prm["resource"] === mcp, `resource is ${String(prm["resource"])}, expected ${mcp} (is PUBLIC_URL the same in the broker?)`);
    must(JSON.stringify(prm["authorization_servers"]) === JSON.stringify([base]), "authorization_servers must be exactly the public origin");
  });
  await check("authorization server metadata (RFC 8414) is complete", async () => {
    const as = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    must(as["issuer"] === base, `issuer is ${String(as["issuer"])}`);
    must(JSON.stringify(as["code_challenge_methods_supported"]) === '["S256"]', "S256 only");
    must(as["authorization_response_iss_parameter_supported"] === true, "RFC 9207 iss");
    must(as["client_id_metadata_document_supported"] === true, "CIMD");
    must((as["token_endpoint_auth_methods_supported"] as string[]).includes("none"), "none (Claude needs it for CIMD)");
    must(String(as["token_endpoint"]).startsWith(`${base}/`), `token_endpoint is ${String(as["token_endpoint"])}`);
    const oidc = (await (await fetch(`${base}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    must(oidc["userinfo_endpoint"] === undefined, "no UserInfo endpoint is advertised (connector tokens can't call one)");
  });
  await check("an unauthenticated MCP request gets 401 with the resource_metadata challenge", async () => {
    const r = await fetch(mcp, { method: "POST", headers: { "content-type": "application/json" }, body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' });
    must(r.status === 401, `status ${r.status}`);
    must((r.headers.get("www-authenticate") ?? "").includes(`resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`), "challenge");
  });

  const vendors: [string, string, string][] = [
    ["Claude", KNOWN_CLIENTS.claude, "https://claude.ai/api/mcp/auth_callback"],
    ["Claude (confidential)", KNOWN_CLIENTS.claudeConfidential, "https://claude.ai/api/mcp/auth_callback"],
    ["ChatGPT", KNOWN_CLIENTS.chatgpt, "https://chatgpt.com/connector_platform_oauth_redirect"],
  ];
  for (const [name, clientId, redirect] of vendors) {
    await check(`the broker fetches ${name}'s client metadata document and shows the sign-in page`, async () => {
      const verifier = randomBytes(32).toString("base64url");
      const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: redirect, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send offline_access", resource: mcp, state: "preflight" });
      const b = new Browser();
      const r = await b.request(`${base}/oauth/authorize?${q}`);
      must(r.status === 303 || r.status === 302, `the authorization endpoint answered ${r.status}: ${(await r.text()).slice(0, 160)}`);
      const loc = new URL(r.headers.get("location") ?? "", base);
      must(loc.pathname.startsWith("/interaction/"), `redirected to ${loc.origin === new URL(base).origin ? loc.pathname : loc.origin} instead of the sign-in page`);
      const page = await (await b.request(loc.href)).text();
      must(page.includes(new URL(clientId).hostname), "the sign-in page names the client's verified host");
    });
  }

  let anaClient: Client | undefined;
  let anaOauth: TestOAuthClient | undefined;
  let leeClient: V1Client | undefined;
  await check("Ana: dynamic registration, PKCE, code exchange and tools (MCP 2026-07-28)", async () => {
    anaOauth = new TestOAuthClient({ name: "Preflight agent (Ana)" });
    const t1 = new StreamableHTTPClientTransport(new URL(mcp), { authProvider: anaOauth });
    await new Client({ name: "preflight", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } }).connect(t1).then(() => undefined, () => undefined);
    must(anaOauth.lastAuthorizationUrl, "the SDK didn't start sign-in");
    const cb = await signInAndAllow(anaOauth.lastAuthorizationUrl.href, "ana", { secret, label: "preflight" });
    must(cb.searchParams.get("iss") === base, "iss missing or wrong in the authorization response");
    await t1.finishAuth(cb.searchParams);
    anaClient = new Client({ name: "preflight", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await anaClient.connect(new StreamableHTTPClientTransport(new URL(mcp), { authProvider: anaOauth }));
    const w = sc(await anaClient.callTool({ name: "alp_whoami", arguments: {} }));
    must(w["address"] === "alp:ana@example.org", `whoami says ${String(w["address"])}`);
  });
  await check("Lee: dynamic registration and tools (MCP 2025-11-25, initialize)", async () => {
    const oauth = new TestOAuthClient({ name: "Preflight agent (Lee)" });
    const t1 = new V1Transport(new URL(mcp), { authProvider: oauth });
    await new V1Client({ name: "preflight", version: "1" }).connect(t1).then(() => undefined, () => undefined);
    must(oauth.lastAuthorizationUrl, "the SDK didn't start sign-in");
    const cb = await signInAndAllow(oauth.lastAuthorizationUrl.href, "lee", { secret, label: "preflight" });
    await t1.finishAuth(cb.searchParams.get("code") ?? "");
    leeClient = new V1Client({ name: "preflight", version: "1" });
    await leeClient.connect(new V1Transport(new URL(mcp), { authProvider: oauth }));
    const w = sc(await leeClient.callTool({ name: "alp_whoami", arguments: {} }));
    must(w["address"] === "alp:lee@example.org", `whoami says ${String(w["address"])}`);
  });
  await check("a client asking only for OpenID scopes (ChatGPT's default) still gets read and send, and its token calls a tool", async () => {
    const reg = await fetch(`${base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Preflight scopes check", application_type: "native", redirect_uris: ["http://127.0.0.1:47199/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }) });
    must(reg.status === 201, `registration answered ${reg.status}`);
    const clientId = String(((await reg.json()) as Record<string, unknown>)["client_id"]);
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: "http://127.0.0.1:47199/callback", code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "openid email profile offline_access", resource: mcp, state: "preflight" });
    const cb = await signInAndAllow(`${base}/oauth/authorize?${q}`, "lee", { secret, label: "preflight-scopes" });
    must(!cb.searchParams.get("error"), `authorization refused: ${cb.searchParams.get("error_description") ?? cb.searchParams.get("error")}`);
    const tr = await fetch(`${base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: cb.searchParams.get("code") ?? "", redirect_uri: "http://127.0.0.1:47199/callback", code_verifier: verifier, client_id: clientId, resource: mcp }).toString() });
    const tok = (await tr.json()) as Record<string, unknown>;
    must(tr.status === 200 && typeof tok["access_token"] === "string", `token request answered ${tr.status}`);
    const c = new Client({ name: "preflight", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await c.connect(new StreamableHTTPClientTransport(new URL(mcp), { authProvider: { token: async () => String(tok["access_token"]) } }));
    const w = sc(await c.callTool({ name: "alp_whoami", arguments: {} }));
    must(w["address"] === "alp:lee@example.org", `whoami says ${String(w["address"])}`);
    await c.close();
  });
  await check("Ana's agent → Lee's agent: request, inbox, reply, ack", async () => {
    must(anaClient && leeClient, "the two agents didn't connect");
    // Addressed to the other preflight agent only, so the agents people connect afterwards start with empty inboxes.
    const sent = sc(await anaClient.callTool({ name: "alp_send", arguments: { to: "lee@example.org", to_delegate: "preflight", scope: "alp.availability/1", type: "request", body: { window: { start: "2026-11-10T14:00:00Z", end: "2026-11-10T18:00:00Z" }, duration_minutes: 30, timezone: "America/New_York", purpose: "meeting" } } }));
    must(sent["status"] === "delivered", `send: ${JSON.stringify(sent).slice(0, 200)}`);
    const inbox = sc(await leeClient.callTool({ name: "alp_inbox", arguments: { thread: String(sent["thread"]) } }));
    const item = (inbox["items"] as Record<string, unknown>[])[0];
    must(item && item["id"] === sent["id"], "Lee's inbox doesn't show the request");
    const reply = sc(await leeClient.callTool({ name: "alp_send", arguments: { to: "ana@example.org", to_delegate: "preflight", scope: "alp.availability/1", type: "inform", thread: sent["thread"], in_reply_to: sent["id"], body: { free: [{ start: "2026-11-10T15:00:00Z", end: "2026-11-10T15:30:00Z" }], as_of: new Date().toISOString().replace(/\.\d+Z$/, "Z") } } }));
    must(reply["status"] === "delivered", `reply: ${JSON.stringify(reply).slice(0, 200)}`);
    await leeClient.callTool({ name: "alp_ack", arguments: { ids: [String(sent["id"])] } });
    const back = sc(await anaClient.callTool({ name: "alp_inbox", arguments: { thread: String(sent["thread"]) } }));
    const r = (back["items"] as Record<string, unknown>[])[0];
    must(r && r["id"] === reply["id"], "Ana's inbox doesn't show the reply");
    await anaClient.callTool({ name: "alp_ack", arguments: { ids: [String(reply["id"])] } });
  });
  await check("refresh tokens rotate", async () => {
    must(anaOauth, "no connection");
    const tokens = anaOauth.tokens();
    const info = anaOauth.clientInformation();
    must(tokens?.refresh_token && info, "no refresh token was issued");
    const metadata = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as Parameters<typeof refreshAuthorization>[1]["metadata"];
    const [fresh, overlap] = await Promise.all([
      refreshAuthorization(base, { metadata, clientInformation: info, refreshToken: tokens.refresh_token, resource: new URL(mcp) }),
      refreshAuthorization(base, { metadata, clientInformation: info, refreshToken: tokens.refresh_token, resource: new URL(mcp) }),
    ]);
    must(fresh.refresh_token && fresh.refresh_token !== tokens.refresh_token, "the refresh token didn't rotate");
    must(overlap.access_token, "an overlapping refresh (two parallel tool calls) was refused");
    anaOauth.saveTokens({ ...fresh });
  });
  await check("a personal access token (web view on loopback) works through the tunnel on MCP and REST, then is revoked", async () => {
    const b = new Browser();
    const login = await b.request(`${webUrl}/web/login`, { form: { username: "ana", secret } });
    must(login.status === 303, `the web view sign-in answered ${login.status} (is WEB_URL the broker's loopback web view?)`);
    const home = await (await b.request(`${webUrl}/web`)).text();
    const csrf = /name="csrf" value="([^"]+)"/.exec(home)?.[1] ?? "";
    const minted = await (await b.request(`${webUrl}/web/tokens`, { form: { csrf, label: "preflight-pat", scopes: ["read"], days: "1", secret } })).text();
    const pat = /<pre>(alpat_[A-Za-z0-9_-]{43})<\/pre>/.exec(minted)?.[1];
    must(pat, "the web view didn't mint a token");
    const rest = await fetch(`${base}/rest/alp_whoami`, { method: "POST", headers: { authorization: `Bearer ${pat}`, "content-type": "application/json" }, body: "{}" });
    must(rest.status === 200, `REST answered ${rest.status}`);
    const c = new Client({ name: "preflight", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await c.connect(new StreamableHTTPClientTransport(new URL(mcp), { authProvider: { token: async () => pat } }));
    const w = sc(await c.callTool({ name: "alp_whoami", arguments: {} }));
    must(w["address"] === "alp:ana@example.org", `whoami says ${String(w["address"])}`);
    await c.close();
    const page = await (await b.request(`${webUrl}/web`)).text();
    const id = /action="\/web\/tokens\/([^"/]+)\/revoke"/.exec(page)?.[1];
    must(id, "no revoke button for the token");
    const csrf2 = /name="csrf" value="([^"]+)"/.exec(page)?.[1] ?? "";
    await b.request(`${webUrl}/web/tokens/${id}/revoke`, { form: { csrf: csrf2, secret } });
    const after = await fetch(`${base}/rest/alp_whoami`, { method: "POST", headers: { authorization: `Bearer ${pat}`, "content-type": "application/json" }, body: "{}" });
    must(after.status === 401, `a revoked token answered ${after.status}`);
  });
  await anaClient?.close().catch(() => undefined);
  await leeClient?.close().catch(() => undefined);

  console.log(failures ? `\n${failures} check(s) failed.` : "\nAll checks passed. The preflight's test messages went only to its own agents (preflight, preflight-scopes); disconnect them on the web view if you like.");
  process.exit(failures ? 1 : 0);
}

main().catch((err: unknown) => {
  console.error(`preflight crashed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
