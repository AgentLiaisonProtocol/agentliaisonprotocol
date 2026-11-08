// SPDX-License-Identifier: FSL-1.1-ALv2
// Binding commitments on the consent path (spec 6.2, 9.4): a relationship set up through a connection request, with the
// default terms both people seal when they approve it (each scope's suggested fields, `commit: ask_me`), reaches
// commit once both people ratify the agreed terms. Before, the default terms left `commit` out, so such a thread
// reached `agreed` and every commit was refused with type_not_allowed. Driven through the client binding's handlers,
// as an agent sees it: alp_request_connection, alp_send, alp_thread.

import assert from "node:assert/strict";
import { test } from "node:test";
import { ANA, LEE, buildWorld } from "../demo/world.ts";
import type { World } from "../demo/world.ts";
import type { DelegateCaller } from "../core/types.ts";
import { BindingState } from "../oauth/state.ts";
import type { AuthContext } from "../oauth/resource.ts";
import { runTool } from "./handlers.ts";
import type { ToolContext, ToolOutcome } from "./handlers.ts";
import { SERVER_INSTRUCTIONS } from "./server.ts";
import { toolCatalog } from "./tools.ts";

function ok(o: ToolOutcome): Extract<ToolOutcome, { ok: true }> {
  assert.equal(o.ok, true, JSON.stringify(o));
  return o as Extract<ToolOutcome, { ok: true }>;
}

interface Side {
  call(tool: string, args: Record<string, unknown>): Promise<ToolOutcome>;
}

async function sides(w: World): Promise<{ ctx: ToolContext; ana: Side; lee: Side }> {
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const side = async (address: string, caller: DelegateCaller): Promise<Side> => {
    const p = (await w.example.getPrincipal(address))!;
    const auth: AuthContext = { caller, principal_id: p.principal_id, scopes: ["read", "send"], via: "oauth", resource: "mcp" };
    return { call: (tool, args) => runTool(ctx, auth, tool, args) };
  };
  return { ctx, ana: await side(ANA, w.ana.agent), lee: await side(LEE, w.lee.agent) };
}

/**
 * Ana's agent asks to connect; Ana approves it on her page and Lee approves it on his, both without choosing terms, as
 * the web view's two approve buttons do: each side's terms are the scopes' defaults.
 */
async function connectOnConsentPath(w: World, ana: Side, scopes: string[], purpose: "scheduling" | "document_exchange"): Promise<void> {
  const asked = ok(await ana.call("alp_request_connection", { to: "lee@example.org", scopes, purpose }));
  assert.equal(asked.structured["status"], "pending_principal");
  const sent = await w.example.requestConnection(w.ana.human(), { to: LEE, scopes, purpose });
  assert.equal(sent.status, "requested");
  const incoming = (await w.example.listConnections(w.lee.human())).find((c) => c.direction === "incoming" && c.state === "pending");
  assert.ok(incoming);
  await w.example.respondToConnection(w.lee.human(), { request: incoming.id, decision: "approve" });
  for (const [who, other] of [[w.ana, LEE], [w.lee, ANA]] as const) {
    const g = (await w.example.listGrants(who.human())).find((x) => x.counterparty === other);
    assert.equal(g?.status, "active");
    for (const s of scopes) assert.ok(g?.scopes[s]?.may.includes("commit"), `${who.address}'s default terms for ${s} list commit`);
  }
}

async function ratifyBoth(w: World): Promise<void> {
  for (const who of [w.ana, w.lee]) {
    const req = (await w.example.listRatifications(who.human())).find((r) => r.state === "pending");
    assert.ok(req, `${who.address} is asked to ratify`);
    const r = await w.example.ratify(who.human(), { request: req.id, decision: "approve" });
    assert.equal(r.record?.method, "reauth-dev");
  }
}

function nextTypes(o: ToolOutcome): string[] {
  return ok(o).structured["next_types"] as string[];
}

test("spec 9.4: a meeting set up through a connection request with the default terms reaches commit once both people ratify", async () => {
  const w = await buildWorld({ domainDocs: false });
  const { ana, lee } = await sides(w);
  await connectOnConsentPath(w, ana, ["alp.meeting/1"], "scheduling");

  const window = { start: "2026-11-10T15:00:00Z", end: "2026-11-10T18:00:00Z" };
  const slot = { start: "2026-11-10T16:00:00Z", end: "2026-11-10T16:30:00Z" };
  const request = ok(await ana.call("alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "request", body: { title: "Launch sync", window, duration_minutes: 30 } }));
  const thread = String(request.structured["thread"]);
  const proposal = ok(await lee.call("alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "propose", thread, in_reply_to: request.structured["id"], body: { title: "Launch sync", duration_minutes: 30, slots: [slot], location: { kind: "video" } } }));
  const terms = { title: "Launch sync", duration_minutes: 30, start: slot.start, end: slot.end, location: { kind: "video" } };
  const accept = ok(await ana.call("alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "accept", thread, in_reply_to: proposal.structured["id"], body: { terms } }));

  // Agreed, not ratified: no side is offered commit, and a commit is refused for the missing records, not the type.
  assert.ok(!nextTypes(await lee.call("alp_thread", { thread })).includes("commit"));
  const early = await lee.call("alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "commit", thread, in_reply_to: accept.structured["id"], body: { terms } });
  assert.equal(early.ok, false);
  assert.equal(early.ok === false && early.code, "needs_ratification");

  await ratifyBoth(w);
  // Both records held: either side may commit a meeting (its committer is "either").
  assert.ok(nextTypes(await lee.call("alp_thread", { thread })).includes("commit"));
  assert.ok(nextTypes(await ana.call("alp_thread", { thread })).includes("commit"));

  // The commit replies to the accept and carries the accepted terms unchanged.
  const commit = ok(await lee.call("alp_send", { to: "ana@example.org", scope: "alp.meeting/1", type: "commit", thread, in_reply_to: accept.structured["id"], body: { terms } }));
  assert.equal(commit.structured["status"], "delivered");
  const booked = ok(await ana.call("alp_send", { to: "lee@example.org", scope: "alp.meeting/1", type: "inform", thread, in_reply_to: commit.structured["id"], body: { event: "booked", as_of: "2026-11-09T14:05:00Z" } }));
  assert.equal(booked.structured["status"], "delivered");
  const view = ok(await lee.call("alp_thread", { thread }));
  assert.equal(view.structured["state"], "committed");
  assert.deepEqual((await w.example.thread(w.ana.agent, thread)).thread.state, "committed");
});

test("spec 9.4: in alp.document_request/1 only the proposer is offered commit, and only the proposer's commit is accepted", async () => {
  const w = await buildWorld({ domainDocs: false });
  const { ana, lee } = await sides(w);
  await connectOnConsentPath(w, ana, ["alp.document_request/1"], "document_exchange");

  const request = ok(await ana.call("alp_send", { to: "lee@example.org", scope: "alp.document_request/1", type: "request", body: { description: "The launch plan", purpose: "review" } }));
  const thread = String(request.structured["thread"]);
  const terms = { resource: { kind: "link", url: "https://docs.example.org/launch-plan", title: "Launch plan", requires_sign_in: true }, access: "view" };
  const proposal = ok(await lee.call("alp_send", { to: "ana@example.org", scope: "alp.document_request/1", type: "propose", thread, in_reply_to: request.structured["id"], body: { terms } }));
  const accept = ok(await ana.call("alp_send", { to: "lee@example.org", scope: "alp.document_request/1", type: "accept", thread, in_reply_to: proposal.structured["id"], body: { terms } }));
  await ratifyBoth(w);

  assert.ok(nextTypes(await lee.call("alp_thread", { thread })).includes("commit"), "Lee proposed: he is offered commit");
  assert.ok(!nextTypes(await ana.call("alp_thread", { thread })).includes("commit"), "Ana accepted: she isn't");
  const notProposer = await ana.call("alp_send", { to: "lee@example.org", scope: "alp.document_request/1", type: "commit", thread, in_reply_to: accept.structured["id"], body: { terms } });
  assert.equal(notProposer.ok === false && notProposer.code, "thread_state");
  const commit = ok(await lee.call("alp_send", { to: "ana@example.org", scope: "alp.document_request/1", type: "commit", thread, in_reply_to: accept.structured["id"], body: { terms } }));
  assert.equal(commit.structured["status"], "delivered");
  // The proposer then tells the requester the link is shared: an inform in the thread.
  ok(await lee.call("alp_send", { to: "ana@example.org", scope: "alp.document_request/1", type: "inform", thread, body: { event: "shared", as_of: "2026-11-09T14:05:00Z" } }));
  assert.equal(ok(await ana.call("alp_thread", { thread })).structured["state"], "committed");
});

test("the MCP server's instructions say the agent sends the commit with alp_send once both people have ratified, and keep approvals and ratification on the person's page", () => {
  assert.doesNotMatch(SERVER_INSTRUCTIONS, /commitments happen only on your person's broker page/, "a commit is an alp_send, as alp_thread's next_types and the bridge kit say");
  assert.match(SERVER_INSTRUCTIONS, /Approving connections and ratifying agreed terms happen only on your person's broker page, never through these tools; once both people have ratified, alp_thread lists commit, and you send it with alp_send\./);
});
