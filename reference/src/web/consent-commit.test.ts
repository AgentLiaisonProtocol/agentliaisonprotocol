// SPDX-License-Identifier: FSL-1.1-ALv2
// Both consent pages of the web view say what a commit takes, for the scopes that end in a commitment (spec 6.2, 9.4):
// the default terms a person seals by approving include `commit` there, and an agent can send one only after both
// people have approved the agreed terms on their own broker pages. The requester's page (a request their agent filed,
// held for them) and the recipient's page (the incoming request) both say so; a scope without commit gets no such line.

import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { mintPat } from "../oauth/pat.ts";
import { Browser, TEST_SECRET, csrfFrom, startTestBroker } from "../mcp/testkit.ts";
import type { TestBroker } from "../mcp/testkit.ts";

let t: TestBroker;
before(async () => {
  t = await startTestBroker();
});
after(async () => {
  await t?.close();
});

async function signIn(username: string): Promise<Browser> {
  const b = new Browser();
  const res = await b.request(`${t.web}/web/login`, { form: { username, secret: TEST_SECRET } });
  assert.equal(res.status, 303, `${username} signs in`);
  return b;
}

const commitLine = (other: string): RegExp => new RegExp(`<p>Commit \\(alp\\.meeting/1\\): an agent can send one only after you and ${other.replace(/\./g, "\\.")} have each approved the agreed terms on your own broker pages\\.</p>`);

test("the requester's and the recipient's consent pages both say what a commit takes, only for the scopes with commit", async () => {
  const mallory = (await t.dev.broker.store.getPrincipal("alp:mallory@outside.example"))!;
  const { token } = await mintPat({ broker: t.dev.broker, state: t.server.state, principal: mallory, label: "script", scopes: ["read", "send"], days: 7, maxDays: 30, now: new Date() });
  const filed = await fetch(`${t.base}/rest/alp_request_connection`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ to: "lee@example.org", scopes: ["alp.meeting/1", "alp.briefing/1"], purpose: "scheduling" }) });
  const held = (await filed.json()) as { status: string; request_id: string };
  assert.equal(held.status, "pending_principal");

  // Mallory's own page: the request her agent filed, waiting for her approval.
  const mb = await signIn("mallory");
  const mine = await (await mb.request(`${t.web}/web/connections/${held.request_id}`)).text();
  assert.match(mine, commitLine("lee@example.org"));
  assert.doesNotMatch(mine, /Commit \([^)]*alp\.briefing\/1/, "alp.briefing/1 has no commit");
  const approved = await mb.request(`${t.web}/web/connections/${held.request_id}/approve`, { form: { csrf: csrfFrom(mine), scopes: ["alp.meeting/1", "alp.briefing/1"], secret: TEST_SECRET } });
  assert.equal(approved.status, 303);

  // Lee's page: the incoming request.
  const lb = await signIn("lee");
  const home = await (await lb.request(`${t.web}/web`)).text();
  const id = /href="\/web\/connections\/([^"]+)"/.exec(home)?.[1];
  assert.ok(id, "Lee's page links to the incoming request");
  const theirs = await (await lb.request(`${t.web}/web/connections/${id}`)).text();
  assert.match(theirs, /mallory@outside\.example/);
  assert.match(theirs, commitLine("mallory@outside.example"));
  assert.doesNotMatch(theirs, /Commit \([^)]*alp\.briefing\/1/);
});
