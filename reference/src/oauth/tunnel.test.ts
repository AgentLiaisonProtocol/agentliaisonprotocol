// SPDX-License-Identifier: FSL-1.1-ALv2
// Behind a tunnel: PUBLIC_URL is https://<tunnel host> while requests reach the broker over loopback HTTP (that is
// what cloudflared does). Every URL the broker hands out, the issuer, the token audience and the iss parameter must
// use the public origin, whatever arrives in Host.

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { after, before, test } from "node:test";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { decodeJwt } from "jose";
import { Browser, TEST_SECRET, csrfFrom, startTestBroker } from "../mcp/testkit.ts";
import type { TestBroker } from "../mcp/testkit.ts";
import { onFreePorts } from "../test-ports.ts";

const PUBLIC = "https://tunnel-name.trycloudflare.example";
const REDIRECT = "http://127.0.0.1:47199/callback";
let t: TestBroker;
let local = "";

before(async () => {
  // Another test process may take a pooled port between the check and the listen: onFreePorts tries new ones.
  t = await onFreePorts(2, ([port, webPort]) => startTestBroker({ publicUrl: PUBLIC, ...(port !== undefined ? { port } : {}), ...(webPort !== undefined ? { webPort } : {}) }));
  local = t.base;
});
after(async () => {
  await t?.close();
});

/** Map the public origin to the loopback listener, as the tunnel does. */
function viaTunnel(url: string): string {
  return url.startsWith(PUBLIC) ? `${local}${url.slice(PUBLIC.length)}` : url;
}

test("behind a tunnel, discovery, the sign-in, the code exchange and the token all use the public origin", async () => {
  const prm = (await (await fetch(`${local}/.well-known/oauth-protected-resource/mcp`)).json()) as Record<string, unknown>;
  assert.equal(prm["resource"], `${PUBLIC}/mcp`);
  assert.deepEqual(prm["authorization_servers"], [PUBLIC]);
  const as = (await (await fetch(`${local}/.well-known/oauth-authorization-server`)).json()) as Record<string, string>;
  assert.equal(as["issuer"], PUBLIC);
  for (const k of ["authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri"]) assert.ok(String(as[k]).startsWith(`${PUBLIC}/oauth/`), `${k} is public`);
  const challenge = await fetch(`${local}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  assert.match(challenge.headers.get("www-authenticate") ?? "", new RegExp(`resource_metadata="${PUBLIC}/\\.well-known/oauth-protected-resource/mcp"`));

  const regRes = await fetch(viaTunnel(as["registration_endpoint"] ?? ""), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Tunnel test", application_type: "native", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }) });
  const reg = (await regRes.json()) as Record<string, string>;
  const clientId = reg["client_id"] ?? "";
  const verifier = randomBytes(32).toString("base64url");
  const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${PUBLIC}/mcp`, state: "t1" });
  const b = new Browser();
  let res = await b.request(`${viaTunnel(as["authorization_endpoint"] ?? "")}?${q}`);
  let callback: URL | undefined;
  for (let i = 0; i < 8 && !callback; i++) {
    if (res.status >= 300 && res.status < 400) {
      const loc = new URL(res.headers.get("location") ?? "", local);
      if (loc.href.startsWith(REDIRECT)) callback = loc;
      else res = await b.request(viaTunnel(loc.href));
      continue;
    }
    const page = await res.text();
    assert.equal(res.status, 200, page.slice(0, 200));
    const action = /<form method="post" action="([^"]+)"/.exec(page)?.[1] ?? "";
    res = await b.request(new URL(action, local).href, { form: { csrf: csrfFrom(page), username: "ana", secret: TEST_SECRET, label: "tunnel", action: "allow" } });
  }
  assert.ok(callback, "the browser came back to the client");
  assert.equal(callback.searchParams.get("iss"), PUBLIC);
  const tok = (await (await fetch(viaTunnel(as["token_endpoint"] ?? ""), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", code: callback.searchParams.get("code") ?? "", redirect_uri: REDIRECT, code_verifier: verifier, client_id: clientId, resource: `${PUBLIC}/mcp` }).toString() })).json()) as Record<string, string>;
  const claims = decodeJwt(tok["access_token"] ?? "");
  assert.equal(claims.iss, PUBLIC);
  assert.equal(claims.aud, `${PUBLIC}/mcp`);
  const client = new Client({ name: "tunnel", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${local}/mcp`), { authProvider: { token: async () => tok["access_token"] } }));
  const who = (await client.callTool({ name: "alp_whoami", arguments: {} })).structuredContent as Record<string, unknown>;
  assert.equal(who["delegate"], "alp:ana@example.org/tunnel");
  await client.close();
});
