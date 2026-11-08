// SPDX-License-Identifier: FSL-1.1-ALv2
// Threads are conversations (spec 9): either side keeps a thread going with follow-up questions, answers,
// clarifications and updates until one side closes it or it expires. Every turn is a full message: both brokers
// evaluate it (each direction needs its own relationship's may-list), both ledgers record it, and it is delivered like
// any other. Negotiation keeps its own states, so nothing said around it moves the terms or stands in for a commit.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ANA, CLIENTS, LEE, PAT, buildWorld, examplePolicy } from "../demo/world.ts";
import type { World } from "../demo/world.ts";
import type { SendInput, SendResult } from "./api.ts";
import { schemaErrors } from "./spec-schemas.ts";
import type { DelegateCaller, JsonObject, LedgerEntry, OrgPolicy, ScopeTerms } from "./types.ts";

function expect<S extends SendResult["status"]>(r: SendResult, s: S): Extract<SendResult, { status: S }> {
  assert.equal(r.status, s, JSON.stringify(r));
  return r as Extract<SendResult, { status: S }>;
}

const kinds = (ledger: LedgerEntry[], envelopeId: string): string[] => ledger.filter((e) => e.envelope_id === envelopeId).map((e) => e.kind);
const ASK = ["/body/topic", "/body/questions/*", "/body/depth", "/body/due_by"];
const ANSWER = ["/body/points/*", "/body/as_of", "/body/confidence", "/body/follow_up"];
const asOf = "2026-11-09T13:00:00Z";

test("one person's own agents hold a status conversation in one thread, closed by an ack; the person's ledger records every turn", async () => {
  const w = await buildWorld({ domainDocs: false });
  const d = await w.example.registerDelegate({ principal: LEE, label: "desk", kind: "bridged", client_id: CLIENTS.connector });
  const desk: DelegateCaller = { kind: "delegate", principal: LEE, delegate: d.id, client_id: CLIENTS.connector };
  const dot = w.lee.agent;
  const toDesk = { to: "lee@example.org", to_delegate: `${LEE}/desk`, scope: "alp.status/1" } as const;
  const toDot = { to: "lee@example.org", to_delegate: `${LEE}/dot`, scope: "alp.status/1" } as const;
  const update = (state: string, extra: Record<string, unknown> = {}) => ({ subject: "Board pack", state, updated_at: asOf, ...extra });

  const u1 = expect(await w.example.send(dot, { ...toDesk, type: "inform", body: update("in_progress", { percent_complete: 40 }) }), "delivered");
  const thread = u1.thread;
  // The other agent answers the update with its own, in the same thread (an inform answering an inform)...
  const u2 = expect(await w.example.send(desk, { ...toDot, type: "inform", thread, in_reply_to: u1.envelope.id, body: update("blocked", { blockers: ["Waiting on the venue contract"] }) }), "delivered");
  // ...and adds to it before anyone answers (a follow-up names no message).
  const u3 = expect(await w.example.send(desk, { ...toDot, type: "inform", thread, body: update("in_progress", { eta: "2026-11-20" }) }), "delivered");
  // A follow-up question about the earlier update, and its answer.
  const q = expect(await w.example.send(dot, { ...toDesk, type: "request", thread, in_reply_to: u2.envelope.id, body: { subject: "Board pack", ref: "venue contract" } }), "delivered");
  const a = expect(await w.example.send(desk, { ...toDot, type: "inform", thread, in_reply_to: q.envelope.id, body: update("in_progress", { percent_complete: 70 }) }), "delivered");
  const turns = [u1, u2, u3, q, a];
  assert.ok(turns.every((r) => r.thread === thread && r.envelope.thread === thread), "every turn is in the one thread");
  assert.ok(turns.every((r) => r.envelope.grant === "self"));
  for (const agent of [dot, desk]) {
    // Each agent reads the whole conversation: what it sent and what was addressed to it.
    const view = await w.example.thread(agent, thread);
    assert.equal(view.thread.state, "open");
    assert.deepEqual(view.messages.map((m) => m.envelope.id), turns.map((r) => r.envelope.id));
  }
  // Either side closes it; then nothing more goes in it.
  const done = expect(await w.example.send(dot, { ...toDesk, type: "ack", thread, in_reply_to: a.envelope.id, body: { of: a.envelope.id, status: "completed" } }), "delivered");
  assert.equal((await w.example.thread(desk, thread)).thread.state, "done");
  const late = expect(await w.example.send(desk, { ...toDot, type: "inform", thread, body: update("done") }), "rejected");
  assert.equal(late.code, "thread_state");
  assert.match(late.reasons[0]?.detail ?? "", /the thread is done; anything more needs a new thread/);

  const ledger = await w.example.ledger(w.lee.human());
  for (const r of [...turns, done]) assert.deepEqual(kinds(ledger, r.envelope.id), ["sent", "received", "receipt"], r.envelope.type);
  assert.ok(ledger.some((e) => e.kind === "refused_outbound" && e.thread === thread && e.code === "thread_state"), "the refused turn is recorded too");
  assert.equal((await w.example.verifyLedger(w.lee.human())).ok, true);
});

/** Ana ↔ Pat across two organizations' brokers, each side sealing its own grant through its own person. */
async function connectAnaPat(w: World, ana: ScopeTerms, pat: ScopeTerms): Promise<void> {
  await w.example.setGrant(w.ana.human(), { counterparty: PAT, scopes: { "alp.briefing/1": ana } });
  await w.partner.setGrant(w.pat.human(), { counterparty: ANA, scopes: { "alp.briefing/1": pat } });
}

const talk = (may: ScopeTerms["may"]): ScopeTerms => ({ may, disclose: [...ASK, ...ANSWER], receive: [...ASK, ...ANSWER], commit: "ask_me", redaction: "reject" });

test("two people's agents hold a briefing conversation across two brokers; every turn is checked by both and recorded in both ledgers", async () => {
  const w = await buildWorld();
  // Ana's grant lets ask_human cross and Pat's doesn't: Pat's broker decides for Pat. Ana discloses no due date.
  const anaTerms = { ...talk(["request", "inform", "ask_human"]), disclose: [...ASK.filter((p) => p !== "/body/due_by"), ...ANSWER] };
  await connectAnaPat(w, anaTerms, talk(["request", "inform"]));
  const toPat = { to: "pat@partner.example", scope: "alp.briefing/1" } as const;
  const toAna = { to: "ana@example.org", scope: "alp.briefing/1" } as const;
  const sendAna = (i: Omit<SendInput, "to" | "scope">) => w.example.send(w.ana.agent, { ...toPat, ...i });
  const sendPat = (i: Omit<SendInput, "to" | "scope">) => w.partner.send(w.pat.agent, { ...toAna, ...i });

  const r1 = expect(await sendAna({ type: "request", body: { topic: "Partner launch readiness", questions: ["What is still open?"], depth: "summary" } }), "delivered");
  const thread = r1.thread;
  const i1 = expect(await sendPat({ type: "inform", thread, in_reply_to: r1.envelope.id, body: { points: ["Two integrations are still in review."], as_of: asOf } }), "delivered");
  const i2 = expect(await sendPat({ type: "inform", thread, body: { points: ["One of them passed review this morning."], as_of: asOf } }), "delivered");
  const r2 = expect(await sendAna({ type: "request", thread, in_reply_to: i1.envelope.id, body: { topic: "Partner launch readiness", questions: ["Which integration is still in review?"], depth: "headline" } }), "delivered");
  const r3 = expect(await sendPat({ type: "request", thread, in_reply_to: r2.envelope.id, body: { topic: "Partner launch readiness", questions: ["Do you mean the payments or the reporting work?"], depth: "headline" } }), "delivered");
  const i3 = expect(await sendAna({ type: "inform", thread, in_reply_to: r3.envelope.id, body: { points: ["The reporting work."], as_of: asOf } }), "delivered");
  const i4 = expect(await sendPat({ type: "inform", thread, in_reply_to: r2.envelope.id, body: { points: ["Reporting is in review until Thursday."], as_of: asOf, confidence: "medium" } }), "delivered");
  // Every turn is checked in full, as a first message would be. Nothing below leaves Ana's broker.
  const wire = w.fed.wire.length;
  // A confidential field stays inside example.org (its classification rule), however far the conversation got...
  const inside = expect(await sendAna({ type: "request", thread, in_reply_to: i4.envelope.id, body: { topic: "Partner launch readiness", depth: "headline", context: { project: "Project Lantern" } } }), "rejected");
  assert.equal(inside.code, "org_policy");
  // ...a field outside Ana's own list isn't disclosed (she left /body/due_by out)...
  const notListed = expect(await sendAna({ type: "request", thread, in_reply_to: i4.envelope.id, body: { topic: "Partner launch readiness", depth: "headline", due_by: "2026-11-12T17:00:00Z" } }), "rejected");
  assert.equal(notListed.code, "not_disclosed");
  // ...and DLP reads every free-text field: a card number in a follow-up question is blocked.
  const leak = expect(await sendAna({ type: "request", thread, in_reply_to: i4.envelope.id, body: { topic: "Expenses", questions: ["Was card 4111 1111 1111 1111 charged twice?"], depth: "headline" } }), "rejected");
  assert.equal(leak.code, "dlp_blocked");
  assert.equal(w.fed.wire.length, wire, "nothing crossed");
  // Pat's own terms leave ask_human out, so Pat's broker refuses it, whatever Ana's terms allow.
  const ask = expect(await sendAna({ type: "ask_human", thread, in_reply_to: i4.envelope.id, body: { urgency: "low", reason: "needs_information" } }), "refused");
  assert.equal(ask.code, "not_accepted");
  // Ana's agent closes the thread; both brokers' copies are done.
  const done = expect(await sendAna({ type: "ack", thread, in_reply_to: i4.envelope.id, body: { of: i4.envelope.id, status: "completed" } }), "delivered");
  assert.equal((await w.example.thread(w.ana.agent, thread)).thread.state, "done");
  assert.equal((await w.partner.thread(w.pat.agent, thread)).thread.state, "done");
  const late = expect(await sendPat({ type: "inform", thread, body: { points: ["One more thing."], as_of: asOf } }), "rejected");
  assert.equal(late.code, "thread_state");

  const delivered = [r1, i1, i2, r2, r3, i3, i4, done];
  const fromAna = new Set([r1, r2, i3, done].map((r) => r.envelope.id));
  const anaView = await w.example.thread(w.ana.agent, thread);
  const patView = await w.partner.thread(w.pat.agent, thread);
  assert.deepEqual(anaView.messages.map((m) => m.envelope.id), delivered.map((r) => r.envelope.id), "Ana's agent reads the whole conversation");
  assert.deepEqual(patView.messages.filter((m) => m.status !== "held").map((m) => m.envelope.id), delivered.map((r) => r.envelope.id), "and so does Pat's");
  const anaLedger = await w.example.ledger(w.ana.human());
  const patLedger = await w.partner.ledger(w.pat.human());
  for (const r of delivered) {
    const id = r.envelope.id;
    assert.deepEqual(kinds(anaLedger, id), fromAna.has(id) ? ["sent", "receipt"] : ["received"], `Ana's ledger, ${r.envelope.type}`);
    assert.deepEqual(kinds(patLedger, id), fromAna.has(id) ? ["received"] : ["sent", "receipt"], `Pat's ledger, ${r.envelope.type}`);
    assert.deepEqual(schemaErrors("envelope", r.envelope), []);
  }
  assert.equal((await w.example.verifyLedger(w.ana.human())).ok, true);
  assert.equal((await w.partner.verifyLedger(w.pat.human())).ok, true);
});

/** example.org with a one-way default: analysts may ask leaders for briefings, and leaders may answer. */
function oneWay(now: Date): OrgPolicy {
  return examplePolicy(now, {
    groups: { finance: { members: [] }, analysts: { members: [ANA] }, leaders: { members: [LEE] } },
    default_relationships: [{
      id: "analysts-leaders",
      from: ["group:analysts"],
      to: ["group:leaders"],
      scopes: { "alp.briefing/1": { forward: { may: ["request", "ask_human"], fields: ASK }, reverse: { may: ["inform", "ask_human"], fields: ANSWER } } },
    }],
  });
}

test("each turn needs the relationship's may-list for its own direction: a one-way default refuses the leader's question back; the example policy's two-way default allows it", async () => {
  const w = await buildWorld({ domainDocs: false, policy: oneWay });
  const toLee = { to: "lee@example.org", scope: "alp.briefing/1" } as const;
  const toAna = { to: "ana@example.org", scope: "alp.briefing/1" } as const;
  const ask = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", body: { topic: "Q4 staffing", questions: ["Which teams are short?"], depth: "summary" } }), "delivered");
  const thread = ask.thread;
  const answer = expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread, in_reply_to: ask.envelope.id, body: { points: ["Support is two people short."], as_of: asOf } }), "delivered");
  expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread, body: { points: ["Hiring closes Friday."], as_of: asOf } }), "delivered");
  const followUp = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", thread, in_reply_to: answer.envelope.id, body: { topic: "Q4 staffing", questions: ["Until when?"], depth: "headline" } }), "delivered");
  // The thread would take a question back, but the relationship doesn't let it go from Lee to Ana.
  const back = expect(await w.example.send(w.lee.agent, { ...toAna, type: "request", thread, in_reply_to: followUp.envelope.id, body: { topic: "Q4 staffing", questions: ["Support or sales?"], depth: "headline" } }), "rejected");
  assert.equal(back.code, "type_not_allowed");
  const informBack = expect(await w.example.send(w.ana.agent, { ...toLee, type: "inform", thread, in_reply_to: answer.envelope.id, body: { points: ["Support."], as_of: asOf } }), "rejected");
  assert.equal(informBack.code, "type_not_allowed");
  assert.equal((await w.example.thread(w.ana.agent, thread)).thread.state, "open", "a refused turn leaves the thread as it was");
  expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread, in_reply_to: followUp.envelope.id, body: { points: ["Until January."], as_of: asOf } }), "delivered");
  const refusals = (await w.example.ledger(w.lee.human())).filter((e) => e.kind === "refused_outbound" && e.thread === thread);
  assert.deepEqual(refusals.map((e) => e.code), ["type_not_allowed"]);

  // The example policy (reference/deploy/policy.example.json) makes the same briefing default two-way.
  const file = JSON.parse(readFileSync(new URL("../../deploy/policy.example.json", import.meta.url), "utf8")) as OrgPolicy;
  assert.deepEqual(schemaErrors("orgPolicy", file), []);
  const twoWay = (now: Date): OrgPolicy => ({ ...file, updated_at: now.toISOString(), clients: { mode: "enforce", allowed: [...(file.clients?.allowed ?? []), { client_id: CLIENTS.connector, scopes: ["alp.briefing/1", "alp.availability/1"], attestation: "vendor", class: "business", no_training: true }] } });
  const v = await buildWorld({ domainDocs: false, policy: twoWay });
  const ask2 = expect(await v.example.send(v.ana.agent, { ...toLee, type: "request", body: { topic: "Q4 staffing", questions: ["Which teams are short?"], depth: "summary" } }), "delivered");
  const back2 = expect(await v.example.send(v.lee.agent, { ...toAna, type: "request", thread: ask2.thread, in_reply_to: ask2.envelope.id, body: { topic: "Q4 staffing", questions: ["Support or sales?"], depth: "headline" } }), "delivered");
  expect(await v.example.send(v.ana.agent, { ...toLee, type: "inform", thread: ask2.thread, in_reply_to: back2.envelope.id, body: { points: ["Support."], as_of: asOf } }), "delivered");
  expect(await v.example.send(v.lee.agent, { ...toAna, type: "inform", thread: ask2.thread, in_reply_to: ask2.envelope.id, body: { points: ["Support is two people short."], as_of: asOf, confidence: "high" } }), "delivered");
  expect(await v.example.send(v.ana.agent, { ...toLee, type: "ack", thread: ask2.thread, in_reply_to: back2.envelope.id, body: { of: back2.envelope.id, status: "completed" } }), "delivered");
  assert.equal((await v.example.thread(v.lee.agent, ask2.thread)).thread.state, "done");
});

test("how a thread ends: a decline of its first message, an ack completed, or expiry; a decline of a later question doesn't end it; every message keeps the thread open for its own lifetime", async () => {
  const w = await buildWorld({ domainDocs: false });
  const toLee = { to: "lee@example.org", scope: "alp.briefing/1" } as const;
  const toAna = { to: "ana@example.org", scope: "alp.briefing/1" } as const;
  // Expiry: the request lives an hour; the answer two; the thread lasts as long as the latest of them.
  const ask = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", expires_in_seconds: 3600, body: { topic: "Q4", depth: "headline" } }), "delivered");
  const answer = expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread: ask.thread, in_reply_to: ask.envelope.id, expires_in_seconds: 7200, body: { points: ["On track."], as_of: asOf } }), "delivered");
  w.clock.advance(3700);
  assert.equal((await w.example.thread(w.ana.agent, ask.thread)).thread.state, "open", "the answer kept it open");
  w.clock.advance(3600);
  assert.equal((await w.example.thread(w.ana.agent, ask.thread)).thread.state, "expired");
  const late = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", thread: ask.thread, in_reply_to: answer.envelope.id, body: { topic: "Q4", depth: "headline" } }), "rejected");
  assert.equal(late.code, "thread_state");
  assert.match(late.reasons[0]?.detail ?? "", /the thread is expired/);

  // A decline of a later question turns down that question only: the conversation goes on.
  const ask5 = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", body: { topic: "Q4 hiring", depth: "headline" } }), "delivered");
  const back = expect(await w.example.send(w.lee.agent, { ...toAna, type: "request", thread: ask5.thread, in_reply_to: ask5.envelope.id, body: { topic: "Q4 hiring", questions: ["Which office?"], depth: "headline" } }), "delivered");
  expect(await w.example.send(w.ana.agent, { ...toLee, type: "decline", thread: ask5.thread, in_reply_to: back.envelope.id, body: { of: back.envelope.id, reason: "not_available" } }), "delivered");
  assert.equal((await w.example.thread(w.lee.agent, ask5.thread)).thread.state, "open", "declining the question back left the thread open");
  expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread: ask5.thread, in_reply_to: ask5.envelope.id, body: { points: ["Hiring closes Friday."], as_of: asOf } }), "delivered");

  // A decline of the thread's first message closes it before agreement.
  const ask2 = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", body: { topic: "Q1", depth: "headline" } }), "delivered");
  expect(await w.example.send(w.lee.agent, { ...toAna, type: "decline", thread: ask2.thread, in_reply_to: ask2.envelope.id, body: { of: ask2.envelope.id, reason: "not_available" } }), "delivered");
  assert.equal((await w.example.thread(w.ana.agent, ask2.thread)).thread.state, "done");
  assert.equal(expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread: ask2.thread, body: { points: ["Actually, here it is."], as_of: asOf } }), "rejected").code, "thread_state");

  // The asker may withdraw its own question: a decline names either side's message.
  const ask3 = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", body: { topic: "Q2", depth: "headline" } }), "delivered");
  expect(await w.example.send(w.ana.agent, { ...toLee, type: "decline", thread: ask3.thread, in_reply_to: ask3.envelope.id, body: { of: ask3.envelope.id, reason: "withdrawn" } }), "delivered");
  assert.equal((await w.example.thread(w.lee.agent, ask3.thread)).thread.state, "done");

  // An ack that only says received leaves the thread open; one that says completed closes it.
  const ask4 = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", body: { topic: "Q3", depth: "headline" } }), "delivered");
  expect(await w.example.send(w.lee.agent, { ...toAna, type: "ack", thread: ask4.thread, in_reply_to: ask4.envelope.id, body: { of: ask4.envelope.id, status: "received" } }), "delivered");
  assert.equal((await w.example.thread(w.ana.agent, ask4.thread)).thread.state, "open");
  const a4 = expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread: ask4.thread, in_reply_to: ask4.envelope.id, body: { points: ["Done."], as_of: asOf } }), "delivered");
  expect(await w.example.send(w.lee.agent, { ...toAna, type: "ack", thread: ask4.thread, in_reply_to: a4.envelope.id, body: { of: a4.envelope.id, status: "completed" } }), "delivered");
  assert.equal((await w.example.thread(w.ana.agent, ask4.thread)).thread.state, "done", "the side that spoke last can close it too");
});

test("around a meeting negotiation: a request answered by a request first, nothing conversational while the terms are open or await ratification, updates both ways after the commit", async () => {
  const w = await buildWorld({ domainDocs: false });
  const fields = ["/body/title", "/body/window", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms", "/body/event", "/body/as_of"];
  const meeting: ScopeTerms = { may: ["request", "propose", "counter", "accept", "commit", "inform", "decline", "ack"], disclose: fields, receive: fields, commit: "ask_me", redaction: "reject" };
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.meeting/1": meeting } });
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.meeting/1": meeting } });
  const toLee = { to: LEE, scope: "alp.meeting/1" } as const;
  const toAna = { to: ANA, scope: "alp.meeting/1" } as const;
  const req = expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", body: { title: "Launch sync", duration_minutes: 30, window: { start: "2026-11-10T15:00:00Z", end: "2026-11-10T18:00:00Z" } } }), "delivered");
  const thread = req.thread;
  // Before any proposal, Lee's agent asks Ana's to propose in another window.
  const redirect = expect(await w.example.send(w.lee.agent, { ...toAna, type: "request", thread, in_reply_to: req.envelope.id, body: { title: "Launch sync", duration_minutes: 30, window: { start: "2026-11-11T15:00:00Z", end: "2026-11-11T18:00:00Z" } } }), "delivered");
  const early = expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread, body: { event: "booked", as_of: asOf } }), "rejected");
  assert.equal(early.code, "thread_state", "nothing reports a booking before the commit");
  const slot = { start: "2026-11-11T16:00:00Z", end: "2026-11-11T16:30:00Z" };
  const prop = expect(await w.example.send(w.ana.agent, { ...toLee, type: "propose", thread, in_reply_to: redirect.envelope.id, body: { title: "Launch sync", duration_minutes: 30, slots: [slot], location: { kind: "video" } } }), "delivered");
  for (const type of ["request", "inform"] as const) {
    const body: JsonObject = type === "request" ? { title: "Launch sync", duration_minutes: 30, window: { start: "2026-11-12T15:00:00Z", end: "2026-11-12T18:00:00Z" } } : { event: "booked", as_of: asOf };
    assert.equal(expect(await w.example.send(w.lee.agent, { ...toAna, type, thread, body }), "rejected").code, "thread_state", `${type} while a proposal is on the table`);
  }
  const terms = { title: "Launch sync", duration_minutes: 30, start: slot.start, end: slot.end, location: { kind: "video" } };
  const acc = expect(await w.example.send(w.lee.agent, { ...toAna, type: "accept", thread, in_reply_to: prop.envelope.id, body: { terms } }), "delivered");
  await w.example.settled();
  const moved = expect(await w.example.send(w.ana.agent, { ...toLee, type: "counter", thread, in_reply_to: acc.envelope.id, body: { title: "Launch sync", duration_minutes: 30, slots: [slot], location: { kind: "phone" } } }), "rejected");
  assert.equal(moved.code, "thread_state", "agreed terms don't change");
  assert.equal(expect(await w.example.send(w.ana.agent, { ...toLee, type: "request", thread, body: { title: "Launch sync", duration_minutes: 30, window: { start: "2026-11-12T15:00:00Z", end: "2026-11-12T18:00:00Z" } } }), "rejected").code, "thread_state");
  assert.equal(expect(await w.example.send(w.ana.agent, { ...toLee, type: "commit", thread, in_reply_to: acc.envelope.id, body: { terms } }), "needs_ratification").status, "needs_ratification");
  for (const person of [w.ana, w.lee]) {
    const pending = (await w.example.listRatifications(person.human())).find((r) => r.state === "pending");
    assert.ok(pending);
    await w.example.ratify(person.human(), { request: pending.id, decision: "approve" });
  }
  const commit = expect(await w.example.send(w.ana.agent, { ...toLee, type: "commit", thread, in_reply_to: acc.envelope.id, body: { terms } }), "delivered");
  // After the commit, both sides report what happened, in the same thread.
  const booked = expect(await w.example.send(w.ana.agent, { ...toLee, type: "inform", thread, in_reply_to: commit.envelope.id, body: { event: "booked", as_of: asOf } }), "delivered");
  const changed = expect(await w.example.send(w.lee.agent, { ...toAna, type: "inform", thread, in_reply_to: booked.envelope.id, body: { event: "changed", as_of: asOf } }), "delivered");
  assert.equal(expect(await w.example.send(w.lee.agent, { ...toAna, type: "request", thread, body: { title: "Launch sync", duration_minutes: 30, window: { start: "2026-11-12T15:00:00Z", end: "2026-11-12T18:00:00Z" } } }), "rejected").code, "thread_state", "new times need a new thread");
  expect(await w.example.send(w.ana.agent, { ...toLee, type: "ack", thread, in_reply_to: changed.envelope.id, body: { of: changed.envelope.id, status: "completed" } }), "delivered");
  for (const agent of [w.ana.agent, w.lee.agent]) assert.equal((await w.example.thread(agent, thread)).thread.state, "done");
});
