// SPDX-License-Identifier: FSL-1.1-ALv2
// One person, several agents of different trust (spec 6.14): the person's own agents write to each
// other through the home broker with no connection, but the organization's policy still applies, and its delivery
// minimums decide per field and per receiving agent.

import { test } from "node:test";
import assert from "node:assert/strict";
import { ANA, CLIENTS, LEE, buildWorld, examplePolicy } from "../demo/world.ts";
import type { World } from "../demo/world.ts";
import type { SendResult } from "./api.ts";
import { meetsConstraints } from "./policy/org-policy.ts";
import type { DelegateCaller, OrgPolicy, ScopeTerms } from "./types.ts";

const DOT = "example-org-dot";
const CLAUDE = "https://assistant.example/orgs/example-org/client.json";
const MUSE = "pat";
const PERSONAL = "https://chat.example/oauth/client.json";
const ALL = ["alp.briefing/1", "alp.availability/1", "alp.status/1"];

function policy(now: Date): OrgPolicy {
  const p = examplePolicy(now);
  return {
    ...p,
    classification: { ...(p.classification ?? {}), overrides: { "alp.status/1": { "/body/blockers": ["confidential"] } } },
    clients: {
      mode: "enforce",
      allowed: [
        { client_id: CLIENTS.connector, scopes: ALL, attestation: "vendor", class: "business", no_training: true },
        { client_id: DOT, label: "dot", scopes: ALL, attestation: "org-client", class: "enterprise", no_training: true },
        { client_id: CLAUDE, label: "claude", scopes: ALL, attestation: "tenant", class: "enterprise", no_training: true },
        { client_id: MUSE, scopes: ALL, attestation: "self", class: "consumer", no_training: false },
        { client_id: PERSONAL, scopes: ALL, attestation: "vendor", class: "consumer", no_training: false },
      ],
    },
    delivery_minimums: [
      { labels: ["confidential.financial"], min_class: "enterprise", min_attestation: "org-client", otherwise: "block" },
      { labels: ["confidential", "confidential.*"], min_class: "enterprise", min_attestation: "org-client" },
    ],
  };
}

async function agents(w: World): Promise<Record<"dot" | "claude" | "muse" | "personal", DelegateCaller>> {
  const out: Partial<Record<"dot" | "claude" | "muse" | "personal", DelegateCaller>> = {};
  for (const [name, client] of [["dot", DOT], ["claude", CLAUDE], ["muse", MUSE], ["personal", PERSONAL]] as const) {
    const d = await w.example.registerDelegate({ principal: LEE, label: name, kind: "bridged", client_id: client });
    out[name] = { kind: "delegate", principal: LEE, delegate: d.id, client_id: client };
  }
  return out as Record<"dot" | "claude" | "muse" | "personal", DelegateCaller>;
}

const update = { subject: "Board pack", state: "in_progress", eta: "2026-11-20", blockers: ["Atlas budget sign-off from the CFO"], updated_at: "2026-11-09T13:00:00Z" };

function expect<S extends SendResult["status"]>(r: SendResult, s: S): Extract<SendResult, { status: S }> {
  assert.equal(r.status, s, JSON.stringify(r));
  return r as Extract<SendResult, { status: S }>;
}

test("the broker records each agent's class from the organization's list, never from the agent", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  await agents(w);
  const recorded = Object.fromEntries((await w.example.store.listDelegates(LEE)).map((d) => [d.label, `${d.attestation}/${d.class}`]));
  assert.equal(recorded["dot"], "org-client/enterprise");
  assert.equal(recorded["claude"], "tenant/enterprise");
  assert.equal(recorded["muse"], "self/consumer");
  assert.equal(recorded["personal"], "vendor/consumer");
});

test("org-client ranks between native and tenant", () => {
  const need = { deliver_to: { min_attestation: "org-client" as const, min_class: "enterprise" as const } };
  assert.equal(meetsConstraints(need, { attestation: "org-client", class: "enterprise" }, undefined), true);
  assert.equal(meetsConstraints(need, { attestation: "tenant", class: "enterprise" }, undefined), true);
  assert.equal(meetsConstraints(need, { attestation: "native", class: "enterprise" }, undefined), false);
  assert.equal(meetsConstraints(need, { attestation: "tenant", class: "business" }, undefined), false);
});

test("one person's agents write to each other with no connection; a message names the agent it is for", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  const a = await agents(w);
  const noName = await w.example.send(a.dot, { to: "lee@example.org", scope: "alp.status/1", type: "inform", body: update });
  assert.equal(noName.status === "rejected" && noName.code, "invalid_input", "writing to oneself needs to_delegate");
  const self = await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/dot`, scope: "alp.status/1", type: "inform", body: update });
  assert.equal(self.status === "rejected" && self.code, "invalid_input", "an agent can't write to itself");
  const nobody = await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/nobody`, scope: "alp.status/1", type: "inform", body: update });
  assert.equal(nobody.status === "rejected" && nobody.code, "unknown_recipient");

  const sent = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/claude`, scope: "alp.status/1", type: "inform", body: update }), "delivered");
  assert.equal(sent.envelope.grant, "self");
  assert.equal(sent.envelope.constraints, undefined, "the minimums were applied per field already");
  assert.deepEqual(sent.envelope.body, update, "the company Claude (enterprise, tenant) gets the confidential blockers");
  assert.equal(w.fed.wire.length, 0);
  const claudeInbox = await w.example.inbox(a.claude);
  assert.equal(claudeInbox.items.length, 1);
  assert.equal(claudeInbox.items[0]?.verified.sender.delegate, `${LEE}/dot`);
  assert.equal(claudeInbox.items[0]?.verified.sender.attestation, "org-client");
  assert.equal(claudeInbox.items[0]?.verified.sender.class, "enterprise");
  assert.equal((await w.example.inbox(a.muse)).items.length, 0, "only the named agent sees it");
  assert.equal((await w.example.inbox(a.dot)).items.length, 0, "the sender doesn't receive its own message");
  const ledger = await w.example.ledger(w.lee.human());
  assert.deepEqual(ledger.filter((e) => e.envelope_id === sent.envelope.id).map((e) => e.kind), ["sent", "received", "receipt"]);
  assert.equal((await w.example.verifyLedger(w.lee.human())).ok, true);
});

test("toward a consumer agent the confidential fields wait for the person; the rest is delivered; the person can send the rest", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  const a = await agents(w);
  const before = w.notifier.sent.length;
  const sent = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/muse`, scope: "alp.status/1", type: "inform", body: update }), "delivered");
  assert.deepEqual(sent.envelope.body, { subject: "Board pack", state: "in_progress", eta: "2026-11-20", updated_at: "2026-11-09T13:00:00Z" });
  assert.equal(sent.envelope.decision.outcome, "redacted");
  assert.deepEqual(sent.envelope.decision.redacted, ["/body/blockers/0"]);
  assert.deepEqual(sent.held?.labels, ["confidential"]);
  const museInbox = await w.example.inbox(a.muse);
  assert.equal(museInbox.items.length, 1);
  assert.equal(JSON.stringify(museInbox.items[0]?.content.body).includes("Atlas"), false, "the blocker never reaches muse");

  const held = await w.example.listHeld(w.lee.human());
  assert.equal(held.length, 1);
  assert.equal(held[0]?.reason, "delivery_minimums");
  assert.deepEqual(held[0]?.withheld, { pointers: ["/body/blockers/0"], labels: ["confidential"] });
  assert.equal(held[0]?.partial_envelope_id, sent.envelope.id, "the copy muse already got");
  const note = w.notifier.sent.slice(before).find((n) => n.kind === "message_held");
  assert.ok(note, "the person is told");
  assert.equal(note.text.includes("Atlas"), false, "the notification names labels, never values");
  assert.match(note.text, /labeled confidential/);

  const released = await w.example.reviewHeld(w.lee.human(), { held: held[0]?.id ?? "", decision: "send" });
  assert.equal(released.status, "delivered");
  const after = await w.example.inbox(a.muse);
  assert.equal(after.items.length, 2);
  assert.equal(JSON.stringify(after.items.map((i) => i.content.body)).includes("Atlas"), true, "with the person's approval, muse gets the full message");
});

test("a label whose minimum says block refuses the message, naming only the label", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  const a = await agents(w);
  const ask = expect(await w.example.send(a.muse, { to: "lee@example.org", to_delegate: `${LEE}/dot`, scope: "alp.briefing/1", type: "request", body: { topic: "Atlas budget", questions: ["What is the approved figure?"], depth: "headline" } }), "delivered");
  const answer = await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/muse`, scope: "alp.briefing/1", type: "inform", thread: ask.thread, in_reply_to: ask.envelope.id, labels: ["confidential.financial"], body: { points: ["Approved: 4.2M"], as_of: "2026-11-09T13:00:00Z" } });
  assert.equal(answer.status, "rejected");
  if (answer.status !== "rejected") return;
  assert.equal(answer.code, "org_policy");
  assert.equal(answer.reasons[0]?.rule, "delivery_minimums");
  assert.match(answer.reasons[0]?.detail ?? "", /confidential\.financial/);
  assert.equal(JSON.stringify(answer.reasons).includes("4.2M"), false);
  assert.equal((await w.example.inbox(a.muse)).items.length, 0, "nothing reaches muse");
  const toClaude = await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/claude`, scope: "alp.status/1", type: "inform", labels: ["confidential.financial"], body: update });
  assert.equal(toClaude.status, "delivered", "the company Claude meets that minimum");
});

test("an agent of the same product on a personal account is treated as consumer", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  const a = await agents(w);
  const sent = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/personal`, scope: "alp.status/1", type: "inform", body: update }), "delivered");
  assert.deepEqual(sent.envelope.decision.redacted, ["/body/blockers/0"], "a personal account doesn't meet the minimum the company client meets");
  const fromPersonal = expect(await w.example.send(a.personal, { to: "lee@example.org", to_delegate: `${LEE}/claude`, scope: "alp.status/1", type: "inform", body: { subject: "Weekend", state: "done", updated_at: "2026-11-09T13:00:00Z" } }), "delivered");
  assert.equal(fromPersonal.envelope.from.class, "consumer");
  assert.equal(fromPersonal.envelope.from.attestation, "vendor");
});

test("when what is left isn't a valid message, the whole message waits for the person; approving it opens the thread it was given", async () => {
  const strict = (now: Date): OrgPolicy => {
    const p = policy(now);
    return { ...p, classification: { ...(p.classification ?? {}), overrides: { "alp.status/1": { "/body/state": ["confidential"] } } } };
  };
  const w = await buildWorld({ domainDocs: false, policy: strict });
  const a = await agents(w);
  const before = w.notifier.sent.length;
  const r = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/muse`, scope: "alp.status/1", type: "inform", body: update }), "held_for_review");
  assert.equal(r.reason, "delivery_minimums");
  assert.equal((await w.example.inbox(a.muse)).items.length, 0);
  const rec = await w.example.store.getHeldOutbound(LEE, r.held);
  assert.deepEqual(rec?.withheld, { pointers: ["/body/state"], labels: ["confidential"] }, "the page can name what waits");
  assert.equal(rec?.partial_envelope_id, undefined, "nothing was sent");
  const note = w.notifier.sent.slice(before).find((n) => n.kind === "message_held");
  assert.ok(note, "the person is told");
  assert.match(note.text, /labeled confidential/);
  assert.match(note.text, /muse is consumer class and self-attested/);
  assert.match(note.text, /nothing has been sent/);
  for (const value of ["in_progress", "Atlas", "Board pack"]) assert.equal(note.text.includes(value), false, "labels, never values");
  await assert.rejects(w.example.thread(a.dot, r.thread), /no such thread/, "the thread starts only when the message is sent");

  // Spec 6.14 item 4: the person approves; the broker evaluates the full message again and delivers it to muse.
  const released = await w.example.reviewHeld(w.lee.human(), { held: r.held, decision: "send" });
  assert.equal(released.status, "delivered", JSON.stringify(released));
  if (released.status !== "delivered") return;
  assert.equal(released.thread, r.thread, "in the thread alp_send returned when it held the message");
  assert.equal(released.envelope.thread, r.thread);
  const inbox = await w.example.inbox(a.muse);
  assert.equal(inbox.items.length, 1);
  assert.match(JSON.stringify(inbox.items[0]?.content.body), /Atlas/, "with the person's approval, muse gets the full message");
  const held = (await w.example.listHeld(w.lee.human())).find((h) => h.id === r.held);
  assert.equal(held?.state, "sent");
  assert.equal(held?.envelope_id, released.envelope.id);
  const ledger = await w.example.ledger(w.lee.human());
  assert.deepEqual(ledger.filter((e) => e.ref === r.held || e.envelope_id === released.envelope.id).map((e) => `${e.kind}:${e.outcome}`), ["held:held", "sent:allowed", "received:accepted", "receipt:accepted", "released:accepted"]);
  assert.equal((await w.example.verifyLedger(w.lee.human())).ok, true);
  for (const agent of [a.dot, a.muse]) assert.equal((await w.example.thread(agent, r.thread)).thread.id, r.thread);
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: r.held, decision: "send" }), /already sent/);
});

test("approving the held remainder of a decline that already closed the thread sends nothing, and says why", async () => {
  // The note of a decline is the one field muse doesn't qualify for: the decline goes without it and closes the thread.
  const noteOnly = (now: Date): OrgPolicy => {
    const p = policy(now);
    return {
      ...p,
      classification: { ...(p.classification ?? {}), overrides: { "alp.briefing/1": { "/body/of": ["public"], "/body/reason": ["public"] } } },
      delivery_minimums: [{ labels: ["internal"], min_class: "enterprise", min_attestation: "org-client" }],
    };
  };
  const w = await buildWorld({ domainDocs: false, policy: noteOnly });
  const a = await agents(w);
  const ask = expect(await w.example.send(a.muse, { to: "lee@example.org", to_delegate: `${LEE}/dot`, scope: "alp.briefing/1", type: "request", body: { topic: "Board pack", depth: "headline" } }), "delivered");
  const no = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/muse`, scope: "alp.briefing/1", type: "decline", thread: ask.thread, in_reply_to: ask.envelope.id, note: "Waiting on the CFO", body: { of: ask.envelope.id, reason: "not_available" } }), "delivered");
  assert.deepEqual(no.envelope.decision.redacted, ["/note"]);
  assert.equal((await w.example.thread(a.dot, ask.thread)).thread.state, "done");
  const id = no.held?.id ?? "";
  const r = await w.example.reviewHeld(w.lee.human(), { held: id, decision: "send" });
  assert.equal(r.status === "rejected" && r.code, "thread_state", JSON.stringify(r));
  const held = (await w.example.listHeld(w.lee.human())).find((h) => h.id === id);
  assert.equal(held?.state, "refused");
  assert.deepEqual(held?.result, { status: "rejected", code: "thread_state" });
  const released = (await w.example.ledger(w.lee.human())).find((e) => e.kind === "released" && e.ref === id);
  assert.equal(released?.outcome, "refused");
  assert.equal(released?.code, "thread_state");
  assert.equal(JSON.stringify((await w.example.inbox(a.muse, { include_acked: true })).items).includes("CFO"), false, "the note never reached muse");
});

test("one person's agents don't negotiate with each other", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  const a = await agents(w);
  const r = await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/claude`, scope: "alp.meeting/1", type: "propose", body: { title: "1:1", duration_minutes: 30, timezone: "UTC", slots: [{ start: "2026-11-10T15:00:00Z", end: "2026-11-10T15:30:00Z" }] } });
  assert.equal(r.status, "rejected");
  assert.equal(r.status === "rejected" && ["type_not_allowed", "client_not_allowed"].includes(r.code), true, JSON.stringify(r));
});

test("spec 5.4: an agent that takes a disconnected agent's name is a new agent, and reads nothing addressed to or sent by the earlier one", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  const a = await agents(w);
  const briefing: ScopeTerms = { may: ["request", "inform", "ask_human"], disclose: ["/body/topic", "/body/depth"], receive: ["/body/topic", "/body/depth"], commit: "ask_me", redaction: "reject" };
  // Lee asks to review what his agents send Ana.
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefing, hold_for_review: true } } });
  // The company Claude (tenant, enterprise) gets the confidential blocker, writes to dot, and drafts a request to Ana.
  const toClaude = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/claude`, scope: "alp.status/1", type: "inform", body: update }), "delivered");
  assert.deepEqual(toClaude.envelope.body, update);
  const fromClaude = expect(await w.example.send(a.claude, { to: "lee@example.org", to_delegate: `${LEE}/dot`, scope: "alp.status/1", type: "inform", body: { subject: "Board pack", state: "done", updated_at: "2026-11-09T13:30:00Z" } }), "delivered");
  const draft = expect(await w.example.send(a.claude, { to: ANA, scope: "alp.briefing/1", type: "request", body: { topic: "Board pack", depth: "headline" } }), "held_for_review");
  // A message to Lee himself, which any agent of his may read; the earlier claude marks it handled.
  const toLee = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: { topic: "Offsite", depth: "headline" } }), "delivered");
  assert.equal((await w.example.ack(a.claude, { envelope_ids: [toLee.envelope.id] })).acked, 1);
  assert.deepEqual((await w.example.inbox(a.claude)).items.map((i) => i.envelope.id).includes(toLee.envelope.id), false);

  w.clock.advance(60);
  await w.example.revokeDelegate(`${LEE}/claude`);
  // Addressed to claude while it is disconnected: it waits for Lee (spec 6.7).
  const whileGone = expect(await w.example.send(w.ana.agent, { to: LEE, to_delegate: `${LEE}/claude`, scope: "alp.briefing/1", type: "request", body: { topic: "Q4", depth: "headline" } }), "delivered");
  assert.equal((await w.example.store.getMessage(LEE, "in", whileGone.envelope.id))?.status, "held");

  // A personal access token named claude: a new agent, recorded as self and consumer.
  w.clock.advance(60);
  const fresh = await w.example.registerDelegate({ principal: LEE, label: "claude", kind: "bridged", client_id: MUSE });
  assert.equal(`${fresh.attestation}/${fresh.class}`, "self/consumer");
  assert.equal(fresh.created_at, w.clock.now().toISOString(), "a new binding starts now");
  const claude: DelegateCaller = { kind: "delegate", principal: LEE, delegate: fresh.id, client_id: MUSE };
  const earlier = [toClaude.envelope.id, fromClaude.envelope.id, whileGone.envelope.id];
  const inbox = (await w.example.inbox(claude, { include_acked: true })).items.map((i) => i.envelope.id);
  assert.deepEqual(inbox, [toLee.envelope.id], "only what any newly connected agent of Lee's may read");
  for (const thread of [toClaude.thread, fromClaude.thread, whileGone.thread]) {
    const seen = (await w.example.thread(claude, thread)).messages.map((m) => m.envelope.id);
    assert.deepEqual(seen.filter((id) => earlier.includes(id)), [], "nor in a thread view");
  }
  assert.deepEqual(await w.example.visibleInbound(claude, earlier), []);
  assert.equal((await w.example.ack(claude, { envelope_ids: earlier })).acked, 0);
  // Acknowledgements are per binding too: what the earlier claude marked handled is new to this one.
  assert.deepEqual((await w.example.inbox(claude)).items.map((i) => i.envelope.id), [toLee.envelope.id], "not marked handled by the earlier claude's acknowledgement");
  assert.equal((await w.example.ack(claude, { envelope_ids: [toLee.envelope.id] })).acked, 1);
  assert.deepEqual((await w.example.inbox(claude)).items.length, 0);
  assert.equal(JSON.stringify(await w.example.inbox(claude, { include_acked: true })).includes("Atlas"), false, "the confidential blocker the earlier claude was cleared for");
  const forLee = (await w.example.messagesForPerson(w.lee.human(), { include_acked: true })).items.map((i) => i.envelope.id);
  for (const id of [toClaude.envelope.id, fromClaude.envelope.id, whileGone.envelope.id]) assert.ok(forLee.includes(id), "Lee's page keeps everything");
  // What the earlier claude drafted can't be released under the new one.
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: draft.held, decision: "send" }), /disconnected/);

  // From now on, the new claude gets what its own class allows: the blocker waits for Lee.
  const now = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/claude`, scope: "alp.status/1", type: "inform", body: update }), "delivered");
  assert.deepEqual(now.held?.labels, ["confidential"]);
  assert.ok((await w.example.inbox(claude)).items.some((i) => i.envelope.id === now.envelope.id));
});

test("spec 5.4: a message held for muse goes only to that muse; once muse is disconnected and the name taken again, it can only be discarded", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  const a = await agents(w);
  w.clock.advance(60);
  // Held whole (labeled confidential as a whole: nothing is left for muse), and held in part (muse got the rest).
  const whole = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/muse`, scope: "alp.status/1", type: "inform", labels: ["confidential"], body: update }), "held_for_review");
  const part = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/muse`, scope: "alp.status/1", type: "inform", body: update }), "delivered");
  const partId = part.held?.id ?? "";
  const recs = await w.example.listHeld(w.lee.human());
  const museSince = (await w.example.store.getDelegate(`${LEE}/muse`))?.created_at;
  for (const id of [whole.held, partId]) {
    const rec = recs.find((h) => h.id === id);
    assert.ok(rec);
    assert.equal(rec.to_delegate_since, museSince, "the record names the binding it is for");
    assert.equal(await w.example.heldBindingChanged(rec), null);
  }
  assert.equal(recs.find((h) => h.id === whole.held)?.whole, true);

  // Disconnected, and the name taken again by a personal access token: a new agent.
  w.clock.advance(60);
  await w.example.revokeDelegate(`${LEE}/muse`);
  w.clock.advance(60);
  const fresh = await w.example.registerDelegate({ principal: LEE, label: "muse", kind: "bridged", client_id: MUSE });
  const muse: DelegateCaller = { kind: "delegate", principal: LEE, delegate: fresh.id, client_id: MUSE };
  for (const id of [whole.held, partId]) {
    const rec = (await w.example.listHeld(w.lee.human())).find((h) => h.id === id);
    assert.ok(rec);
    assert.equal(await w.example.heldBindingChanged(rec), "target");
    await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: id, decision: "send" }), /agent this message is for was disconnected/);
    assert.equal((await w.example.listHeld(w.lee.human())).find((h) => h.id === id)?.state, "pending", "still the person's to discard");
  }
  const seen = JSON.stringify(await w.example.inbox(muse, { include_acked: true }));
  assert.equal(seen.includes("Atlas") || seen.includes(part.envelope.id), false, "the new muse never gets the full message, nor the copy the earlier one got");
  assert.equal((await w.example.thread(muse, part.thread)).messages.length, 0);
  assert.equal((await w.example.ack(muse, { envelope_ids: [part.envelope.id] })).acked, 0);
  // A record written before it named the binding: one that started after the message was held is another agent.
  const older = await w.example.store.getHeldOutbound(LEE, partId);
  assert.ok(older);
  delete older.to_delegate_since;
  await w.example.store.putHeldOutbound(older);
  assert.equal(await w.example.heldBindingChanged(older), "target");
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: partId, decision: "send" }), /agent this message is for was disconnected/);
  assert.deepEqual(await w.example.reviewHeld(w.lee.human(), { held: whole.held, decision: "discard" }), { status: "discarded", held: whole.held });
});

test("spec 5.4: another client given an active agent's name is a new binding, not the same agent", async () => {
  const w = await buildWorld({ domainDocs: false, policy });
  const a = await agents(w);
  const before = expect(await w.example.send(a.dot, { to: "lee@example.org", to_delegate: `${LEE}/personal`, scope: "alp.briefing/1", type: "request", body: { topic: "Board pack", depth: "headline" } }), "delivered");
  const was = await w.example.store.getDelegate(`${LEE}/personal`);
  // The same client signing in again keeps the binding.
  const again = await w.example.registerDelegate({ principal: LEE, label: "personal", kind: "bridged", client_id: PERSONAL });
  assert.equal(again.created_at, was?.created_at);
  // Another client (an embedder calling registerDelegate directly) gets a new one, which can't read the earlier's.
  w.clock.advance(60);
  const other = await w.example.registerDelegate({ principal: LEE, label: "personal", kind: "bridged", client_id: CLIENTS.connector });
  assert.notEqual(other.created_at, was?.created_at);
  const reader: DelegateCaller = { kind: "delegate", principal: LEE, delegate: other.id, client_id: CLIENTS.connector };
  assert.equal((await w.example.inbox(reader, { include_acked: true })).items.some((i) => i.envelope.id === before.envelope.id), false);
  await assert.rejects(w.example.inbox(a.personal), /not an active delegate/, "the earlier client's credentials no longer act for the name");
});
