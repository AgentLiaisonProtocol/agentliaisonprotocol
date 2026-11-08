// SPDX-License-Identifier: FSL-1.1-ALv2
// The person's web view over HTTP: sign-in, CSRF, headers, a fresh sign-in for every approval, personal access
// tokens (REST and MCP), ratification of agreed terms, disconnecting an agent, and the ledger.

import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/client";
import type { ScopeTerms } from "../core/types.ts";
import { Browser, TestOAuthClient, csrfFrom, signInAndAllow, startTestBroker, TEST_SECRET } from "../mcp/testkit.ts";
import type { TestBroker } from "../mcp/testkit.ts";

type J = Record<string, unknown>;

async function signIn(t: TestBroker, username: string): Promise<Browser> {
  const b = new Browser();
  const res = await b.request(`${t.web}/web/login`, { form: { username, secret: TEST_SECRET } });
  assert.equal(res.status, 303);
  return b;
}

async function mintPat(t: TestBroker, b: Browser, label: string, scopes: string[]): Promise<string> {
  const page = await (await b.request(`${t.web}/web`)).text();
  const res = await b.request(`${t.web}/web/tokens`, { form: { csrf: csrfFrom(page), label, scopes, days: "3", secret: TEST_SECRET } });
  assert.equal(res.status, 200);
  const token = /<pre>(alpat_[A-Za-z0-9_-]{43})<\/pre>/.exec(await res.text())?.[1];
  assert.ok(token, "the token is shown once");
  return token;
}

async function rest(t: TestBroker, token: string, tool: string, body: J): Promise<{ status: number; json: J; challenge: string | null }> {
  const res = await fetch(`${t.base}/rest/${tool}`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body) });
  return { status: res.status, json: (await res.json()) as J, challenge: res.headers.get("www-authenticate") };
}

describe("web view", () => {
  let t: TestBroker;
  before(async () => {
    t = await startTestBroker();
  });
  after(async () => {
    await t?.close();
  });

  test("sign-in, security headers, CSRF, and GET changes nothing", async () => {
    const anon = await fetch(`${t.web}/web`);
    assert.equal(anon.status, 200);
    assert.match(anon.headers.get("content-security-policy") ?? "", /default-src 'self'; frame-ancestors 'none'/);
    assert.match(await anon.text(), /Test identities only/);
    const bad = await new Browser().request(`${t.web}/web/login`, { form: { username: "ana", secret: "wrong" } });
    assert.equal(bad.status, 401);
    const b = await signIn(t, "ana");
    const page = await (await b.request(`${t.web}/web`)).text();
    assert.match(page, /Ana \(test analyst\)/);
    const noCsrf = await b.request(`${t.web}/web/tokens`, { form: { label: "x", scopes: "read", days: "1", secret: TEST_SECRET } });
    assert.equal(noCsrf.status, 403);
    const get = await b.request(`${t.web}/web/tokens`);
    assert.equal(get.status, 404, "actions are POST-only");
    assert.equal((await fetch(`${t.base}/web`)).status, 404, "the public listener never serves the web view");
    void csrfFrom(page);
  });

  test("personal access tokens: REST and MCP, scope limits, revocation", async () => {
    const b = await signIn(t, "ana");
    const pat = await mintPat(t, b, "muse", ["read", "send"]);
    const who = await rest(t, pat, "alp_whoami", {});
    assert.equal(who.status, 200);
    assert.equal(who.json["delegate"], "alp:ana@example.org/muse");
    assert.equal(who.json["attestation"], "self");
    const openapi = (await (await fetch(`${t.base}/rest/openapi.json`)).json()) as { servers: { url: string }[] };
    assert.deepEqual(openapi.servers, [{ url: `${t.base}/rest` }]);

    const client = new Client({ name: "pat", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${t.base}/mcp`), { authProvider: { token: async () => pat } }));
    const sent = (await client.callTool({ name: "alp_send", arguments: { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Read <b>this</b> https://evil.example/x", depth: "summary" } } })) as CallToolResult;
    assert.equal((sent.structuredContent as J)["status"], "delivered");
    await client.close();

    const readOnly = await mintPat(t, b, "reader", ["read"]);
    const denied = await rest(t, readOnly, "alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "x", depth: "summary" } });
    assert.equal(denied.status, 403);
    assert.match(denied.challenge ?? "", /error="insufficient_scope"/);
    const mcpDenied = await fetch(`${t.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${readOnly}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "alp_send", arguments: {} } }) });
    assert.equal(mcpDenied.status, 403);
    assert.match(mcpDenied.headers.get("www-authenticate") ?? "", /^Bearer error="insufficient_scope"/);

    const page = await (await b.request(`${t.web}/web`)).text();
    const id = /action="\/web\/tokens\/([0-9A-Z]{26})\/revoke"/.exec(page)?.[1];
    assert.ok(id);
    const rv = await b.request(`${t.web}/web/tokens/${id}/revoke`, { form: { csrf: csrfFrom(page), secret: TEST_SECRET } });
    assert.equal(rv.status, 303);
    const statuses = await Promise.all([pat, readOnly].map(async (x) => (await rest(t, x, "alp_whoami", {})).status));
    assert.ok(statuses.includes(401), "a revoked token stops working");
  });

  test("Lee reads the briefing request on his page as text, sanitized", async () => {
    const b = await signIn(t, "lee");
    const page = await (await b.request(`${t.web}/web`)).text();
    const id = /href="\/web\/messages\/([0-9A-Z]{26})"/.exec(page)?.[1];
    assert.ok(id);
    const msg = await (await b.request(`${t.web}/web/messages/${id}`)).text();
    assert.match(msg, /Read this hxxps:\/\/evil\[\.\]example\/x/);
    assert.doesNotMatch(msg, /<b>this<\/b>/);
  });

  test("ratification: both people approve agreed terms on their pages with a fresh sign-in; then the commit goes through", async () => {
    const meeting: ScopeTerms = {
      may: ["request", "propose", "counter", "accept", "commit", "inform", "decline", "ack"],
      disclose: ["/body/title", "/body/window", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms", "/body/event", "/body/as_of"],
      receive: ["/body/title", "/body/window", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms", "/body/event", "/body/as_of"],
      commit: "ask_me",
      redaction: "reject",
    };
    const fresh = (p: string) => ({ kind: "human" as const, principal: p, auth: { method: "reauth-dev" as const, at: new Date().toISOString() } });
    await t.dev.broker.setGrant(fresh("alp:ana@example.org"), { counterparty: "alp:lee@example.org", scopes: { "alp.meeting/1": meeting } });
    await t.dev.broker.setGrant(fresh("alp:lee@example.org"), { counterparty: "alp:ana@example.org", scopes: { "alp.meeting/1": meeting } });
    const ab = await signIn(t, "ana");
    const lb = await signIn(t, "lee");
    const anaPat = await mintPat(t, ab, "planner", ["read", "send"]);
    const leePat = await mintPat(t, lb, "assistant", ["read", "send"]);
    const slot = { start: "2026-11-10T15:00:00Z", end: "2026-11-10T15:30:00Z" };
    const req = await rest(t, anaPat, "alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "request", body: { title: "Launch sync", duration_minutes: 30, window: { start: "2026-11-10T14:00:00Z", end: "2026-11-10T18:00:00Z" } } });
    assert.equal(req.status, 200, JSON.stringify(req.json));
    const thread = String(req.json["thread"]);
    const prop = await rest(t, leePat, "alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "propose", thread, in_reply_to: req.json["id"], body: { title: "Launch sync", duration_minutes: 30, slots: [slot], location: { kind: "video" } } });
    assert.equal(prop.status, 200, JSON.stringify(prop.json));
    const terms = { title: "Launch sync", duration_minutes: 30, start: slot.start, end: slot.end, location: { kind: "video" } };
    const acc = await rest(t, anaPat, "alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "accept", thread, in_reply_to: prop.json["id"], body: { terms } });
    assert.equal(acc.status, 200, JSON.stringify(acc.json));
    const early = await rest(t, leePat, "alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "commit", thread, in_reply_to: acc.json["id"], body: { terms } });
    assert.equal(early.status, 409);
    assert.equal((early.json["error"] as J)["code"], "needs_ratification");
    for (const b of [ab, lb]) {
      const home = await (await b.request(`${t.web}/web`)).text();
      const rid = /href="\/web\/ratifications\/([^"]+)"/.exec(home)?.[1];
      assert.ok(rid, "the ratification request is on the person's page");
      const page = await (await b.request(`${t.web}/web/ratifications/${rid}`)).text();
      assert.match(page, /Launch sync/);
      const no = await b.request(`${t.web}/web/ratifications/${rid}/approve`, { form: { csrf: csrfFrom(page), secret: "wrong" } });
      assert.equal(no.status, 401, "ratification needs a fresh sign-in");
      const yes = await b.request(`${t.web}/web/ratifications/${rid}/approve`, { form: { csrf: csrfFrom(page), secret: TEST_SECRET } });
      assert.equal(yes.status, 303);
    }
    const th = await rest(t, leePat, "alp_thread", { thread });
    assert.deepEqual((th.json["ratification"] as J)["mine"], "ratified");
    assert.ok((th.json["next_types"] as string[]).includes("commit"));
    const commit = await rest(t, leePat, "alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "commit", thread, in_reply_to: acc.json["id"], body: { terms } });
    assert.equal(commit.status, 200, JSON.stringify(commit.json));
    const after = await rest(t, anaPat, "alp_thread", { thread });
    assert.equal(after.json["state"], "committed");
  });

  test("disconnecting an agent on the web view stops its tokens at once", async () => {
    const oauth = new TestOAuthClient({ name: "Doomed agent" });
    const url = new URL(`${t.base}/mcp`);
    const first = new StreamableHTTPClientTransport(url, { authProvider: oauth });
    await assert.rejects(new Client({ name: "d", version: "1" }).connect(first));
    const cb = await signInAndAllow(oauth.lastAuthorizationUrl?.href ?? "", "ana", { label: "doomed" });
    await first.finishAuth(cb.searchParams);
    const token = oauth.tokens()?.access_token ?? "";
    const live = new Client({ name: "d", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await live.connect(new StreamableHTTPClientTransport(url, { authProvider: { token: async () => token } }));
    assert.equal((await live.listTools()).tools.length, 7);
    await live.close();
    const b = await signIn(t, "ana");
    const page = await (await b.request(`${t.web}/web`)).text();
    const rv = await b.request(`${t.web}/web/delegates/revoke`, { form: { csrf: csrfFrom(page), delegate: "alp:ana@example.org/doomed", secret: TEST_SECRET } });
    assert.equal(rv.status, 303);
    const gone = await fetch(`${t.base}/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: "{}" });
    assert.equal(gone.status, 401);
    assert.match(gone.headers.get("www-authenticate") ?? "", /error="invalid_token"/);
  });

  test("the ledger page and export", async () => {
    // A message for Ana that waits for her on this page: it names an agent of hers that doesn't exist.
    const sender = await t.dev.broker.registerDelegate({ principal: "alp:lee@example.org", label: "ledger-sender", client_id: "pat" });
    const waiting = await t.dev.broker.send({ kind: "delegate", principal: "alp:lee@example.org", delegate: sender.id, client_id: "pat" }, { to: "alp:ana@example.org", to_delegate: "alp:ana@example.org/nobody", scope: "alp.availability/1", type: "request", body: { window: { start: "2026-11-11T14:00:00Z", end: "2026-11-11T18:00:00Z" }, duration_minutes: 15 } });
    assert.equal(waiting.status, "delivered", JSON.stringify(waiting));
    const b = await signIn(t, "ana");
    const page = await (await b.request(`${t.web}/web/ledger`)).text();
    assert.match(page, /Chain: <strong>intact<\/strong>/);
    assert.match(page, /sent/);
    assert.match(page, /<td>received<\/td><td>lee@example\.org<\/td><td>alp\.availability\/1 request<\/td><td>accepted<br><span class="muted">waits for you on this page<\/span><\/td>/, "the ledger page says it waits, as the entry records");
    const exp = await b.request(`${t.web}/web/ledger.json`);
    const body = (await exp.json()) as { entries: unknown[] };
    assert.ok(body.entries.length > 0);
  });
});

describe("web view: the organization's list of agents, and an address that changes hands", () => {
  let t: TestBroker;
  before(async () => {
    t = await startTestBroker();
  });
  after(async () => {
    await t?.close();
  });

  async function install(change: (p: NonNullable<TestBroker["dev"]["policies"][0]>) => void): Promise<void> {
    const current = t.dev.policies[0];
    assert.ok(current);
    const next = structuredClone(current);
    next.serial = current.serial + 1;
    change(next);
    await t.dev.broker.setOrgPolicy({ kind: "admin", operator: "test" }, next);
    t.dev.policies[0] = next;
  }

  test("spec 5.7, 6.10: leaving pat off the list in enforce mode forbids personal access tokens, those already issued too", async () => {
    const b = await signIn(t, "ana");
    const pat = await mintPat(t, b, "muse", ["read", "send"]);
    assert.equal((await rest(t, pat, "alp_whoami", {})).status, 200);
    await install((p) => {
      if (!p.clients) return;
      p.clients.mode = "enforce";
      p.clients.allowed = p.clients.allowed.filter((c) => c.client_id !== "pat");
    });
    try {
      const page = await (await b.request(`${t.web}/web`)).text();
      assert.match(page, /doesn(?:'|&#39;)t allow personal access tokens/);
      assert.doesNotMatch(page, /action="\/web\/tokens"/, "no form to create one");
      const res = await b.request(`${t.web}/web/tokens`, { form: { csrf: csrfFrom(page), label: "muse2", scopes: ["read"], days: "3", secret: TEST_SECRET } });
      assert.equal(res.status, 403);
      assert.doesNotMatch(await res.text(), /alpat_/, "no token is minted");
      for (const tool of ["alp_whoami", "alp_inbox", "alp_send"]) {
        const r = await rest(t, pat, tool, tool === "alp_send" ? { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "x", depth: "headline" } } : {});
        assert.equal(r.status, 401, `${tool}: a token issued before the list changed stops working`);
      }
    } finally {
      await install((p) => {
        if (!p.clients) return;
        p.clients.mode = "report";
        p.clients.allowed.push({ client_id: "pat", scopes: ["alp.availability/1", "alp.briefing/1", "alp.meeting/1", "alp.status/1", "alp.document_request/1"], attestation: "self", class: "consumer", no_training: false });
      });
    }
    assert.equal((await rest(t, pat, "alp_whoami", {})).status, 200, "allowed again once the list names pat");
  });

  test("spec 5.2: a page left open by an earlier holder of the address can't act for the new holder", async () => {
    // Two pages the earlier holder left open.
    const oldForms = await signIn(t, "lee");
    const csrf = csrfFrom(await (await oldForms.request(`${t.web}/web`)).text());
    const oldExport = await signIn(t, "lee");
    const before = await t.dev.broker.getPrincipal("lee@example.org");
    assert.ok(before);
    // The address passes to someone else: a different identity at the organization's identity provider.
    const now = await t.dev.broker.registerPrincipal({ address: "alp:lee@example.org", identity: { iss: "https://dev-idp.invalid", sub: "dev-lee-successor" } });
    assert.notEqual(now.principal_id, before.principal_id);
    // A form on the old page, with a valid CSRF token and a fresh sign-in, is refused.
    const act = await oldForms.request(`${t.web}/web/tokens`, { form: { csrf, label: "x", scopes: ["read"], days: "1", secret: TEST_SECRET } });
    assert.equal(act.status, 401);
    assert.doesNotMatch(await act.text(), /alpat_/, "nothing is minted for anyone");
    const ledger = await oldExport.request(`${t.web}/web/ledger.json`);
    assert.equal(ledger.status, 401, "the export doesn't show the new holder's ledger");
    assert.doesNotMatch(await ledger.text(), /"entries"/);
    // And the broker itself refuses a HumanCaller that carries the earlier holder's principal_id.
    await assert.rejects(t.dev.broker.listGrants({ kind: "human", principal: "alp:lee@example.org", principal_id: before.principal_id, auth: { method: "reauth-dev", at: new Date().toISOString() } }), /earlier holder/);
    assert.ok(Array.isArray(await t.dev.broker.listGrants({ kind: "human", principal: "alp:lee@example.org", principal_id: now.principal_id, auth: { method: "reauth-dev", at: new Date().toISOString() } })));
  });
});

describe("web view: messages that wait for the person", () => {
  let t: TestBroker;
  before(async () => {
    t = await startTestBroker();
  });
  after(async () => {
    await t?.close();
  });

  const fresh = (p: string) => ({ kind: "human" as const, principal: p, auth: { method: "reauth-dev" as const, at: new Date().toISOString() } });
  const brief: ScopeTerms = { may: ["request", "inform", "ask_human"], disclose: ["/body/topic", "/body/questions/*", "/body/depth"], receive: ["/body/points/*", "/body/as_of"], commit: "ask_me", redaction: "reject" };

  async function approve(b: Browser, id: string): Promise<string> {
    const page = await (await b.request(`${t.web}/web/held/${id}`)).text();
    const sent = await b.request(`${t.web}/web/held/${id}/send`, { form: { csrf: csrfFrom(page), secret: TEST_SECRET } });
    assert.equal(sent.status, 303);
    return (await b.request(`${t.web}/web/held/${id}`)).text();
  }

  test("spec 6.12: the page says whether an approved message was sent, or the code it wasn't sent with", async () => {
    await t.dev.broker.setGrant(fresh("alp:ana@example.org"), { counterparty: "alp:lee@example.org", scopes: { "alp.briefing/1": { ...brief, hold_for_review: true } } });
    const b = await signIn(t, "ana");
    const pat = await mintPat(t, b, "planner", ["read", "send"]);
    const ask = { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Q4 plan", depth: "summary" } };
    const first = await rest(t, pat, "alp_send", ask);
    assert.equal(first.json["status"], "held_for_review", JSON.stringify(first.json));
    const home = await (await b.request(`${t.web}/web`)).text();
    assert.match(home, new RegExp(`href="/web/held/${String(first.json["id"])}"`));
    const sent = await approve(b, String(first.json["id"]));
    assert.match(sent, /<strong>Sent<\/strong> \(message <code>[0-9A-Z]{26}<\/code>\)/);

    const second = await rest(t, pat, "alp_send", ask);
    assert.equal(second.json["status"], "held_for_review");
    await t.dev.broker.revoke(fresh("alp:ana@example.org"), { counterparty: "alp:lee@example.org" });
    const refused = await approve(b, String(second.json["id"]));
    assert.match(refused, /<strong>Not sent<\/strong>: <code>no_relationship<\/code>/);
    assert.doesNotMatch(refused, /<strong>Sent<\/strong>/);
  });

  /** The "Needs you" card that links to this held message. */
  function card(home: string, id: string): string {
    const found = home.split('<div class="card">').find((c) => c.includes(`href="/web/held/${id}"`));
    assert.ok(found, `a card for ${id}`);
    return found;
  }

  test("spec 6.14: a message between one person's agents that waits for them names the agents, the labels and whether anything went", async () => {
    const b = await signIn(t, "lee");
    const writer = await mintPat(t, b, "assistant", ["read", "send"]);
    await mintPat(t, b, "muse", ["read", "send"]);
    // Labeled confidential as a whole: muse (a personal access token, consumer class) gets nothing of it.
    const whole = await rest(t, writer, "alp_send", { to: "lee@example.org", to_delegate: "muse", scope: "alp.briefing/1", type: "request", labels: ["confidential"], body: { topic: "Board pack", depth: "summary" } });
    assert.equal(whole.json["status"], "held_for_review", JSON.stringify(whole.json));
    // Only its confidential field is kept from muse: the rest went.
    const split = await rest(t, writer, "alp_send", { to: "lee@example.org", to_delegate: "muse", scope: "alp.briefing/1", type: "request", body: { topic: "Board pack", depth: "summary", context: { project: "Atlas" } } });
    assert.equal(split.json["status"], "delivered", JSON.stringify(split.json));

    const home = await (await b.request(`${t.web}/web`)).text();
    const wholeId = String(whole.json["id"]);
    const wholeCard = card(home, wholeId);
    assert.match(wholeCard, /Your agent <code>assistant<\/code> wrote a <code>alp\.briefing\/1<\/code> request to your agent <strong>muse<\/strong>/);
    assert.match(wholeCard, /labeled <code>confidential<\/code>/);
    assert.match(wholeCard, /Nothing has been sent/);
    const splitId = (await t.dev.broker.listHeld(fresh("alp:lee@example.org"))).find((h) => h.state === "pending" && h.partial_envelope_id === split.json["id"])?.id;
    assert.ok(splitId, "the full message waits for Lee");
    const splitCard = card(home, splitId);
    assert.match(splitCard, /muse got it without the fields labeled <code>confidential<\/code>/);
    assert.doesNotMatch(splitCard, /Nothing has been sent/, "a copy did go");

    const page = await (await b.request(`${t.web}/web/held/${wholeId}`)).text();
    assert.match(page, /keep fields labeled <code>confidential<\/code> from that agent/);
    assert.match(page, /Waiting for you\. Nothing has been sent\./);
    assert.doesNotMatch(page, /<code><\/code>/, "no empty label");
    const partial = await (await b.request(`${t.web}/web/held/${splitId}`)).text();
    assert.match(partial, /Waiting for you\. The rest of it already went to your agent <code>muse<\/code>\./);
    assert.doesNotMatch(partial, /Nothing has been sent/);
    assert.match(partial, new RegExp(`it already received this message without <code>/body/context/project</code> \\(message <code>${String(split.json["id"])}</code>\\)`));
  });

  test("spec 6.7: a message to an agent of Lee's that doesn't exist is shown on Lee's page with why, the label as text", async () => {
    await t.dev.broker.setGrant(fresh("alp:ana@example.org"), { counterparty: "alp:lee@example.org", scopes: { "alp.briefing/1": brief } });
    const pat = await mintPat(t, await signIn(t, "ana"), "courier", ["read", "send"]);
    const r = await rest(t, pat, "alp_send", { to: "lee@example.org", to_delegate: "no-such_agent-2", scope: "alp.briefing/1", type: "request", body: { topic: "Q4 plan", depth: "summary" } });
    assert.equal(r.json["status"], "delivered", JSON.stringify(r.json));
    const id = String(r.json["id"]);
    const b = await signIn(t, "lee");
    const home = await (await b.request(`${t.web}/web`)).text();
    const reason = /was addressed to an agent of yours named <code>no-such_agent-2<\/code> that wasn(?:'|&#39;)t connected or couldn(?:'|&#39;)t receive it when it arrived\. It stays here and doesn(?:'|&#39;)t go to any of your agents\./;
    const card = home.split('<div class="card">').find((c) => c.includes(`href="/web/messages/${id}"`));
    assert.ok(card, "a card under Needs you");
    assert.match(card, /A message from <strong>ana@example\.org<\/strong> \(alp\.briefing\/1 request\)/);
    assert.match(card, reason);
    const page = await (await b.request(`${t.web}/web/messages/${id}`)).text();
    assert.match(page, /status held\./);
    assert.match(page, new RegExp(`This message ${reason.source}`));
  });

  /** Mint a personal access token on the person's page; the token and the page that shows it. */
  async function mintWithPage(b: Browser, label: string): Promise<{ token: string; page: string }> {
    const home = await (await b.request(`${t.web}/web`)).text();
    const res = await b.request(`${t.web}/web/tokens`, { form: { csrf: csrfFrom(home), label, scopes: ["read", "send"], days: "3", secret: TEST_SECRET } });
    assert.equal(res.status, 200);
    const page = await res.text();
    const token = /<pre>(alpat_[A-Za-z0-9_-]{43})<\/pre>/.exec(page)?.[1];
    assert.ok(token);
    return { token, page };
  }

  async function disconnect(b: Browser, delegate: string): Promise<void> {
    const home = await (await b.request(`${t.web}/web`)).text();
    assert.equal((await b.request(`${t.web}/web/delegates/revoke`, { form: { csrf: csrfFrom(home), delegate, secret: TEST_SECRET } })).status, 303);
  }

  test("spec 5.4, 5.7: a token minted with a disconnected agent's name starts a new agent; a second token for a connected one adds a token", async () => {
    const b = await signIn(t, "ana");
    const first = await mintWithPage(b, "scout");
    assert.doesNotMatch(first.page, /belonged to an agent you disconnected|already had/);
    const sender = await mintPat(t, b, "sender", ["read", "send"]);
    const sent = await rest(t, sender, "alp_send", { to: "ana@example.org", to_delegate: "scout", scope: "alp.availability/1", type: "request", body: { window: { start: "2026-11-11T14:00:00Z", end: "2026-11-11T18:00:00Z" }, duration_minutes: 15 } });
    assert.equal(sent.json["status"], "delivered", JSON.stringify(sent.json));
    const ids = async (token: string): Promise<unknown[]> => ((await rest(t, token, "alp_inbox", { include_acked: true })).json["items"] as J[]).map((i) => i["id"]);
    assert.ok((await ids(first.token)).includes(sent.json["id"]));

    await disconnect(b, "alp:ana@example.org/scout");
    assert.equal((await rest(t, first.token, "alp_whoami", {})).status, 401, "the disconnected agent's token stays refused");
    const again = await mintWithPage(b, "scout");
    assert.match(again.page, /The name <code>scout<\/code> belonged to an agent you disconnected\. This token starts a new agent: it won(?:'|&#39;)t see what was addressed to, or sent by, the earlier one\./);
    assert.equal((await rest(t, again.token, "alp_whoami", {})).json["delegate"], "alp:ana@example.org/scout");
    assert.equal((await ids(again.token)).includes(sent.json["id"]), false, "the new agent doesn't see what was addressed to the earlier one");
    assert.equal((await rest(t, first.token, "alp_whoami", {})).status, 401, "and the earlier token doesn't come back with the name");

    const second = await mintWithPage(b, "scout");
    assert.match(second.page, /Your agent <code>scout<\/code> already had a token: this adds one, and the earlier one still works\./);
    // Disconnected other than through this page (its tokens aren't revoked), then the name taken again: the earlier
    // agent's tokens don't act for the new one.
    const kept = await mintWithPage(b, "keeper");
    await t.dev.broker.revokeDelegate("alp:ana@example.org/keeper");
    const renewed = await mintWithPage(b, "keeper");
    assert.equal((await rest(t, kept.token, "alp_whoami", {})).status, 401, "a token of the earlier agent");
    assert.equal((await rest(t, renewed.token, "alp_whoami", {})).status, 200);
    for (const token of [again.token, second.token]) assert.equal((await rest(t, token, "alp_whoami", {})).status, 200, "both tokens work");
    await disconnect(b, "alp:ana@example.org/scout");
    for (const token of [again.token, second.token]) assert.equal((await rest(t, token, "alp_whoami", {})).status, 401, "one disconnection revokes both");
  });

  /** A message from Lee's agent `writer` to his agent `to`, whose confidential field `to` doesn't qualify for: it got the rest. */
  async function split(writer: string, to: string): Promise<{ held: string; copy: string }> {
    const r = await rest(t, writer, "alp_send", { to: "lee@example.org", to_delegate: to, scope: "alp.briefing/1", type: "request", body: { topic: "Board pack", depth: "summary", context: { project: "Atlas" } } });
    assert.equal(r.json["status"], "delivered", JSON.stringify(r.json));
    const copy = String(r.json["id"]);
    const held = (await t.dev.broker.listHeld(fresh("alp:lee@example.org"))).find((h) => h.partial_envelope_id === copy)?.id;
    assert.ok(held);
    return { held, copy };
  }

  test("spec 6.14: when a message whose rest already went is discarded, expires, or was recorded without the copy's id, the page never says nothing was sent", async () => {
    const b = await signIn(t, "lee");
    const writer = await mintPat(t, b, "planner", ["read", "send"]);
    await mintPat(t, b, "pal", ["read", "send"]);
    const went = (id?: string) => new RegExp(`the full message wasn(?:'|&#39;)t sent; your agent <code>pal</code> already had the copy without the fields labeled <code>confidential</code>${id ? ` \\(message <code>${id}</code>\\)` : ""}\\.`);

    const discarded = await split(writer, "pal");
    const page = await (await b.request(`${t.web}/web/held/${discarded.held}`)).text();
    assert.equal((await b.request(`${t.web}/web/held/${discarded.held}/discard`, { form: { csrf: csrfFrom(page), secret: TEST_SECRET } })).status, 303);
    const afterDiscard = await (await b.request(`${t.web}/web/held/${discarded.held}`)).text();
    assert.match(afterDiscard, /Discarded: /);
    assert.match(afterDiscard, went(discarded.copy));
    assert.doesNotMatch(afterDiscard, /nothing was sent/);

    const expired = await split(writer, "pal");
    const rec = await t.dev.broker.store.getHeldOutbound("alp:lee@example.org", expired.held);
    assert.ok(rec);
    await t.dev.broker.store.putHeldOutbound({ ...rec, expires_at: new Date(Date.now() - 1000).toISOString() });
    const afterExpiry = await (await b.request(`${t.web}/web/held/${expired.held}`)).text();
    assert.match(afterExpiry, /Expired before you decided: /);
    assert.match(afterExpiry, went(expired.copy));
    assert.doesNotMatch(afterExpiry, /nothing was sent/);

    // A record written before the copy's id was kept: only such copies named `withheld` then, so a copy went.
    const older = await split(writer, "pal");
    const stored = await t.dev.broker.store.getHeldOutbound("alp:lee@example.org", older.held);
    assert.ok(stored);
    delete stored.partial_envelope_id;
    await t.dev.broker.store.putHeldOutbound(stored);
    const home = await (await b.request(`${t.web}/web`)).text();
    const oldCard = card(home, older.held);
    assert.match(oldCard, /pal got it without the fields labeled <code>confidential<\/code>/);
    assert.doesNotMatch(oldCard, /Nothing has been sent/);
    const oldPage = await (await b.request(`${t.web}/web/held/${older.held}`)).text();
    assert.match(oldPage, /it already received this message without <code>\/body\/context\/project<\/code>\./);
    assert.doesNotMatch(oldPage, /nothing has been sent|held whole/);
    await t.dev.broker.store.putHeldOutbound({ ...stored, state: "discarded" });
    assert.match(await (await b.request(`${t.web}/web/held/${older.held}`)).text(), went());
  });

  test("spec 6.12: after the person approved a message, the page says only what this broker knows of where it went", async () => {
    await t.dev.broker.setGrant(fresh("alp:ana@example.org"), { counterparty: "alp:lee@example.org", scopes: { "alp.briefing/1": { ...brief, hold_for_review: true } } });
    const b = await signIn(t, "ana");
    const pat = await mintPat(t, b, "drafter", ["read", "send"]);
    const r = await rest(t, pat, "alp_send", { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Q4 plan", depth: "summary" } });
    assert.equal(r.json["status"], "held_for_review", JSON.stringify(r.json));
    const id = String(r.json["id"]);
    const rec = await t.dev.broker.store.getHeldOutbound("alp:ana@example.org", id);
    assert.ok(rec);
    const envelope = "01M7090000000000000000ENV1";
    const show = async (change: Partial<typeof rec>): Promise<string> => {
      await t.dev.broker.store.putHeldOutbound({ ...rec, decided_at: rec.created_at, ...change });
      return (await b.request(`${t.web}/web/held/${id}`)).text();
    };
    assert.match(await show({ state: "refused", result: { status: "refused", code: "not_accepted" }, envelope_id: envelope }), new RegExp(`<strong>Refused by the recipient(?:'|&#39;)s broker</strong>: <code>not_accepted</code> \\(message <code>${envelope}</code>\\)\\.`));
    assert.match(await show({ state: "refused", result: { status: "undeliverable", code: "unreachable" }, envelope_id: envelope }), new RegExp(`<strong>Delivery failed</strong>: <code>unreachable</code>; it may still have arrived \\(message <code>${envelope}</code>\\)\\.`));
    assert.match(await show({ state: "refused", result: { status: "undeliverable", code: "unknown_recipient" } }), /<strong>Not sent<\/strong>: <code>unknown_recipient<\/code> \(no broker for the recipient could be reached\)\./);
    assert.match(await show({ state: "refused", result: { status: "rejected", code: "no_relationship" } }), /<strong>Not sent<\/strong>: <code>no_relationship<\/code>/);
    const sending = await show({ state: "sending" });
    assert.match(sending, /<strong>Being sent<\/strong> since /);
    assert.doesNotMatch(sending, /action="\/web\/held\/[0-9A-Z]+\/(send|discard)"/, "nothing to decide any more");
    await t.dev.broker.store.putHeldOutbound({ ...rec, state: "discarded" });
  });

  test("spec 5.4: a held message for an agent the person disconnected can't be sent, even to a new agent with its name; it can be discarded", async () => {
    const b = await signIn(t, "lee");
    const writer = await mintPat(t, b, "editor", ["read", "send"]);
    await mintPat(t, b, "buddy", ["read", "send"]);
    const whole = await rest(t, writer, "alp_send", { to: "lee@example.org", to_delegate: "buddy", scope: "alp.briefing/1", type: "request", labels: ["confidential"], body: { topic: "Board pack", depth: "summary" } });
    assert.equal(whole.json["status"], "held_for_review", JSON.stringify(whole.json));
    const id = String(whole.json["id"]);
    assert.match(await (await b.request(`${t.web}/web/held/${id}`)).text(), new RegExp(`action="/web/held/${id}/send"`));
    await disconnect(b, "alp:lee@example.org/buddy");
    await mintPat(t, b, "buddy", ["read", "send"]);
    const page = await (await b.request(`${t.web}/web/held/${id}`)).text();
    assert.match(page, /It can(?:'|&#39;)t be sent now: your agent <strong>buddy<\/strong> was disconnected after it was written, and it goes only to the agent it was written for\./);
    assert.doesNotMatch(page, new RegExp(`action="/web/held/${id}/send"`), "no Send button");
    assert.match(page, new RegExp(`action="/web/held/${id}/discard"`));
    assert.match(card(await (await b.request(`${t.web}/web`)).text(), id), /It can(?:'|&#39;)t be sent now/);
    const sent = await b.request(`${t.web}/web/held/${id}/send`, { form: { csrf: csrfFrom(page), secret: TEST_SECRET } });
    assert.notEqual(sent.status, 303, "a send posted anyway is refused");
    assert.equal((await t.dev.broker.listHeld(fresh("alp:lee@example.org"))).find((h) => h.id === id)?.state, "pending");
    assert.equal((await b.request(`${t.web}/web/held/${id}/discard`, { form: { csrf: csrfFrom(page), secret: TEST_SECRET } })).status, 303);
    assert.match(await (await b.request(`${t.web}/web/held/${id}`)).text(), /Discarded: nothing was sent\./);
  });
});
