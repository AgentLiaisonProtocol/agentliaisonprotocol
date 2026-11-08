// SPDX-License-Identifier: FSL-1.1-ALv2
// The REST mirror's plumbing (spec 12.1.9, 18.3): a refusal's message carries the advice an MCP client gets in its
// text; a body that isn't JSON is told where it stops being JSON (and about curly quotes), a leading byte order mark is
// dropped, and JSON that isn't an object is refused; GET on a tool is 405; a token
// problem keeps the code identity_mismatch but says what to do; and between one person's own agents, an unknown agent
// name lists the person's connected agents.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { mintPat, revokePat } from "../oauth/pat.ts";
import { startTestBroker } from "./testkit.ts";
import type { TestBroker } from "./testkit.ts";
import { devPolicy } from "../dev-world.ts";

let t: TestBroker;
const tokens: Record<string, string> = {};

before(async () => {
  t = await startTestBroker();
  const now = new Date();
  for (const [who, label, scopes] of [["ana", "script", ["read", "send"]], ["lee", "script", ["read", "send"]], ["ana", "reader", ["read"]]] as const) {
    const p = (await t.dev.broker.store.getPrincipal(`alp:${who}@example.org`))!;
    const { token } = await mintPat({ broker: t.dev.broker, state: t.server.state, principal: p, label, scopes: [...scopes], days: 7, maxDays: 30, now });
    tokens[`${who}/${label}`] = token;
  }
});
after(async () => {
  await t?.close();
});

type ErrorBody = { error: { code: string; message: string; pointers?: string[]; retry_after?: number } };

/** `token` null: no Authorization header; omitted: Ana's read+send token. */
async function call(tool: string, body: unknown, token?: string | null, raw?: string): Promise<{ status: number; headers: Headers; json: ErrorBody & Record<string, unknown> }> {
  const bearer = token === undefined ? tokens["ana/script"] : token;
  const res = await fetch(`${t.base}/rest/${tool}`, { method: "POST", headers: { "content-type": "application/json", ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) }, body: raw ?? JSON.stringify(body) });
  return { status: res.status, headers: res.headers, json: (await res.json()) as ErrorBody & Record<string, unknown> };
}

const WINDOW = { start: "2026-11-10T09:00:00Z", end: "2026-11-10T17:00:00Z" };

test("the advice an MCP client gets in its text is in the REST error's message: not_disclosed, schema_invalid, type_not_allowed", async () => {
  const notDisclosed = await call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Q4", depth: "summary", context: { project: "Atlas" } } });
  assert.equal(notDisclosed.status, 403);
  assert.equal(notDisclosed.json.error.code, "not_disclosed");
  assert.match(notDisclosed.json.error.message, /don't name the free-text field \/body\/context\/project: send without it/);
  assert.match(notDisclosed.json.error.message, /Leave it out; don't move it into another field\.$/);

  const schema = await call("alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Q4", depth: "verbose" } });
  assert.equal(schema.status, 422);
  assert.match(schema.json.error.message, /^\/body\/depth must be one of "headline", "summary", "detailed"\. The body doesn't match the scope's schema \(see pointers\)\. alp_whoami with include_scopes returns the schemas\. Send the corrected draft with a new idempotency_key if you set one \(the same key returns this answer for 24 hours\)\.$/);

  const ask = await call("alp_send", { to: "lee@example.org", scope: "alp.availability/1", type: "request", body: { window: WINDOW, duration_minutes: 30 } });
  assert.equal(ask.status, 200, JSON.stringify(ask.json));
  const type = await call("alp_send", { to: "lee@example.org", scope: "alp.availability/1", type: "ask_human", thread: ask.json["thread"], body: { urgency: "normal", reason: "needs_decision" } });
  assert.equal(type.status, 403);
  assert.equal(type.json.error.code, "type_not_allowed");
  assert.match(type.json.error.message, /don't allow ask_human messages\. alp_contacts lists the types you may send each contact\.$/);
});

test("rate_limited on REST: the advice in the message, retry_after in the body and a Retry-After header", async () => {
  const lee = (await t.dev.broker.store.getPrincipal("alp:lee@example.org"))!;
  // Fill Lee's window toward Ana (the default limit between two people: 120 an hour).
  for (let i = 0; i < 120; i++) await t.dev.broker.store.hitRateLimit(`out|${lee.principal_id}|alp:ana@example.org`, new Date(), 3600, 1_000_000);
  const r = await call("alp_send", { to: "ana@example.org", scope: "alp.availability/1", type: "request", body: { window: WINDOW, duration_minutes: 30 } }, tokens["lee/script"]);
  assert.equal(r.status, 429);
  assert.equal(r.json.error.code, "rate_limited");
  assert.ok(typeof r.json.error.retry_after === "number" && r.json.error.retry_after >= 3590 && r.json.error.retry_after <= 3600, JSON.stringify(r.json));
  assert.equal(r.headers.get("retry-after"), String(r.json.error.retry_after));
  assert.match(r.json.error.message, /^too many messages to ana@example\.org; retry after \d+ seconds\. Wait at least retry_after seconds, then send it again, with a new idempotency_key if you set one/);
});

test("a body that isn't JSON: where it stops being JSON, and curly quotes named; never a piece of the body", async () => {
  const curly = await call("alp_whoami", undefined, undefined, "{“include_scopes”: true}");
  assert.equal(curly.status, 400);
  assert.equal(curly.json.error.code, "invalid_input");
  assert.match(curly.json.error.message, /at line 1, column 2 \(character 2\), where a member name in double quotes was expected\./);
  assert.match(curly.json.error.message, /It contains curly quotes: use straight quotes/);
  assert.doesNotMatch(curly.json.error.message, /include_scopes/);
  const cut = await call("alp_whoami", undefined, undefined, '{"include_scopes": true');
  assert.match(cut.json.error.message, /at the end of the body, where ',' or '\}' was expected\./);
  assert.doesNotMatch(cut.json.error.message, /curly/);
  const second = await call("alp_whoami", undefined, undefined, '{\n  "include_scopes": tru\n}');
  assert.match(second.json.error.message, /at line 2, column 21 \(character 23\)/);
});

test("a byte order mark before the JSON is dropped; a body that is JSON but not an object is refused", async () => {
  const bom = await call("alp_whoami", undefined, undefined, '\ufeff{"include_scopes": false}');
  assert.equal(bom.status, 200, JSON.stringify(bom.json));
  assert.equal(bom.json["address"], "alp:ana@example.org");
  const bomBroken = await call("alp_whoami", undefined, undefined, '\ufeff{"include_scopes": tru}');
  assert.match(bomBroken.json.error.message, /at line 1, column 20 \(character 20\)/, "positions count from after the byte order mark");
  for (const raw of ["null", '"x"', "42", "true", "[]", '[{"include_scopes": true}]']) {
    const r = await call("alp_whoami", undefined, undefined, raw);
    assert.equal(r.status, 400, raw);
    assert.deepEqual(r.json, { error: { code: "invalid_input", message: "The request body must be a JSON object." } }, raw);
  }
  assert.equal((await call("alp_whoami", undefined, undefined, "")).status, 200, "an empty body is {}");
});

test("GET on a tool is 405 with Allow: POST and a JSON error; an unknown tool is 404", async () => {
  const res = await fetch(`${t.base}/rest/alp_send`);
  assert.equal(res.status, 405);
  assert.equal(res.headers.get("allow"), "POST");
  const body = (await res.json()) as ErrorBody;
  assert.equal(body.error.code, "invalid_input");
  assert.match(body.error.message, /^Use POST: http:\/\/127\.0\.0\.1:\d+\/rest\/alp_send takes the tool's input as a JSON object/);
  const unknown = await fetch(`${t.base}/rest/alp_nothing`);
  assert.equal(unknown.status, 404);
  assert.match(((await unknown.json()) as ErrorBody).error.message, /unknown tool: the tools are alp_whoami, /);
  assert.equal((await fetch(`${t.base}/rest/openapi.json`)).status, 200, "the OpenAPI document is still served");
});

test("token problems keep identity_mismatch and say what to do: sign in, renew, add the send scope, or ask the administrator", async () => {
  const none = await call("alp_whoami", {}, null);
  assert.equal(none.status, 401);
  assert.equal(none.json.error.code, "identity_mismatch");
  assert.match(none.json.error.message, /^sign-in required\. Send Authorization: Bearer with an OAuth access token issued for http:\/\/127\.0\.0\.1:\d+\/rest, or a personal access token/);

  const unknown = await call("alp_whoami", {}, `alpat_${"A".repeat(43)}`);
  assert.equal(unknown.status, 401);
  assert.match(unknown.headers.get("www-authenticate") ?? "", /error="invalid_token"/);
  assert.match(unknown.json.error.message, /^unknown personal access token\. Refresh the access token .*or create a new personal access token on your person's broker page\.$/);

  const ana = (await t.dev.broker.store.getPrincipal("alp:ana@example.org"))!;
  const { token, record } = await mintPat({ broker: t.dev.broker, state: t.server.state, principal: ana, label: "short-lived", scopes: ["read"], days: 1, maxDays: 30, now: new Date() });
  await revokePat(t.server.state, ana.principal_id, record.id, new Date());
  const revoked = await call("alp_whoami", {}, token);
  assert.match(revoked.json.error.message, /^the personal access token was revoked or has expired\. Refresh the access token/);

  const readOnly = await call("alp_send", { to: "lee@example.org", scope: "alp.availability/1", type: "request", body: { window: WINDOW, duration_minutes: 30 } }, tokens["ana/reader"]);
  assert.equal(readOnly.status, 403);
  assert.equal(readOnly.json.error.code, "identity_mismatch");
  assert.match(readOnly.json.error.message, /^This token lacks the send scope\. Create a personal access token with send on your person's broker page/);

  // The organization blocks Ana's reader agent: only an administrator can change that.
  const policy = devPolicy(new Date());
  await t.dev.broker.setOrgPolicy({ kind: "admin", operator: "test" }, { ...policy, serial: 2, blocked: { delegates: ["alp:ana@example.org/reader"] } });
  const blocked = await call("alp_whoami", {}, tokens["ana/reader"]);
  assert.equal(blocked.status, 401);
  assert.match(blocked.json.error.message, /^the organization blocked this agent\. .*ask the organization's administrator\.$/);
  await t.dev.broker.setOrgPolicy({ kind: "admin", operator: "test" }, { ...policy, serial: 3 });
});

test("unknown_recipient between one person's own agents lists the person's other connected agents", async () => {
  const r = await call("alp_send", { to: "ana@example.org", to_delegate: "nobody", scope: "alp.availability/1", type: "request", body: { window: WINDOW, duration_minutes: 30 } });
  assert.equal(r.status, 404);
  assert.equal(r.json.error.code, "unknown_recipient");
  assert.match(r.json.error.message, /^No agent of your person's is connected under that name\. Your person's other connected agents: [a-z0-9_, -]*reader[a-z0-9_, -]*\. Check the address, and the agent's name in to_delegate\. Send the corrected draft with a new idempotency_key if you set one \(the same key returns this answer for 24 hours\)\.$/);
  assert.doesNotMatch(r.json.error.message, /nobody/, "the name it was given isn't echoed");
});
