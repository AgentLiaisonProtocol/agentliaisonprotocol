// SPDX-License-Identifier: FSL-1.1-ALv2
// The rules that keep a conversation from widening what was agreed (spec 7.8, 9.2, 9.4): an availability answer keeps
// to the window its recipient asked about, however the conversation goes on; an accept or a counter answers only the
// other party's latest proposal; agreed terms end with a commit, a decline or expiry, and a commit needs both
// ratifications still valid; a thread holds a bounded number of messages; and the side that receives an accept
// ratifies by standing grant once its answer is out. Each rule is checked by both brokers.

import { test } from "node:test";
import assert from "node:assert/strict";
import { ulid } from "ulid";
import { ANA, CLIENTS, LEE, PAT, buildWorld } from "../demo/world.ts";
import type { World } from "../demo/world.ts";
import type { SendInput, SendResult } from "./api.ts";
import { objectHash, signEnvelope } from "./envelope.ts";
import { termsHash } from "./ratification.ts";
import { MAX_THREAD_MESSAGES } from "./threads.ts";
import type { DelegateCaller, Envelope, JsonObject, ScopeTerms, UnsignedEnvelope } from "./types.ts";

function expect<S extends SendResult["status"]>(r: SendResult, s: S): Extract<SendResult, { status: S }> {
  assert.equal(r.status, s, JSON.stringify(r));
  return r as Extract<SendResult, { status: S }>;
}

/** A copy of an envelope a broker sent, changed and signed again by that broker: what a broker that skipped its own checks would send. */
async function forged(w: World, from: "example" | "partner", env: Envelope, change: Partial<UnsignedEnvelope>, drop: ("in_reply_to" | "in_reply_to_hash")[] = []): Promise<Envelope> {
  const { broker_sig: _sig, ...unsigned } = env;
  const next: UnsignedEnvelope = { ...unsigned, id: ulid(w.clock.now().getTime()), ...change };
  for (const k of drop) delete next[k];
  return signEnvelope(next, w[from].keys);
}

const AVAILABILITY = ["/body/window", "/body/duration_minutes", "/body/timezone", "/body/free", "/body/as_of"];
const availability: ScopeTerms = { may: ["request", "inform"], disclose: AVAILABILITY, receive: AVAILABILITY, commit: "ask_me", redaction: "reject" };
const window = (day: string, from: string, to: string): JsonObject => ({ window: { start: `2026-11-${day}T${from}:00:00Z`, end: `2026-11-${day}T${to}:00:00Z` }, duration_minutes: 30 });
const free = (day: string, hh: string): JsonObject => ({ free: [{ start: `2026-11-${day}T${hh}:00:00Z`, end: `2026-11-${day}T${hh}:30:00Z` }], as_of: "2026-11-09T13:00:00Z" });

test("spec 7.8: an availability answer keeps to the window its recipient asked about, as a reply, an update or a follow-up, at both brokers", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.ana.human(), { counterparty: PAT, scopes: { "alp.availability/1": availability } });
  await w.partner.setGrant(w.pat.human(), { counterparty: ANA, scopes: { "alp.availability/1": availability } });
  const toAna = { to: ANA, scope: "alp.availability/1" } as const;
  const sendPat = (i: Omit<SendInput, "to" | "scope">) => w.partner.send(w.pat.agent, { ...toAna, ...i });
  const ask = expect(await w.example.send(w.ana.agent, { to: PAT, scope: "alp.availability/1", type: "request", body: window("10", "15", "18") }), "delivered");
  const thread = ask.thread;
  const answer = expect(await sendPat({ type: "inform", thread, in_reply_to: ask.envelope.id, body: free("10", "15") }), "delivered");
  // Pat's broker refuses free intervals nobody asked for, however the message is framed.
  for (const [how, extra] of [["answering the request", { in_reply_to: ask.envelope.id }], ["updating its own answer", { in_reply_to: answer.envelope.id }], ["following up", {}]] as const) {
    const r = expect(await sendPat({ type: "inform", thread, ...extra, body: free("11", "15") }), "rejected");
    assert.equal(r.code, "schema_invalid", how);
    assert.match(r.reasons[0]?.detail ?? "", /outside the window its recipient asked about/, how);
  }
  // A question back with a wider window doesn't widen what Pat may tell: an inform answering Pat's own request is refused.
  const back = expect(await sendPat({ type: "request", thread, in_reply_to: ask.envelope.id, body: window("10", "08", "20") }), "delivered");
  const own = expect(await sendPat({ type: "inform", thread, in_reply_to: back.envelope.id, body: free("10", "09") }), "rejected");
  assert.match(own.reasons[0]?.detail ?? "", /answer a request from their recipient/);
  // Inside the window, an update and a follow-up go; and Ana's agent may answer Pat's question within Pat's window.
  expect(await sendPat({ type: "inform", thread, in_reply_to: answer.envelope.id, body: free("10", "16") }), "delivered");
  expect(await sendPat({ type: "inform", thread, body: free("10", "17") }), "delivered");
  expect(await w.example.send(w.ana.agent, { to: PAT, scope: "alp.availability/1", type: "inform", thread, in_reply_to: back.envelope.id, body: free("10", "09") }), "delivered");

  // Ana's broker checks it too: what a broker that skipped the rule would send is refused there (step 9).
  for (const [how, change, drop] of [
    ["answering the request", { body: free("12", "15") }, []],
    ["following up", { body: free("12", "15") }, ["in_reply_to", "in_reply_to_hash"]],
  ] as const) {
    const env = await forged(w, "partner", answer.envelope, change, [...drop]);
    const r = await w.example.acceptInbound(structuredClone(env));
    assert.equal(r.kind === "receipt" && r.receipt.status, "refused", how);
    assert.equal(r.kind === "receipt" && r.receipt.code, "schema_invalid", how);
  }
  const fine = await w.example.acceptInbound(structuredClone(await forged(w, "partner", answer.envelope, { body: free("10", "17") })));
  assert.equal(fine.kind === "receipt" && fine.receipt.status, "accepted", "inside the window it is accepted");
  const anaView = await w.example.thread(w.ana.agent, thread);
  assert.ok(anaView.messages.every((m) => m.envelope.type !== "inform" || m.direction === "out" || JSON.stringify(m.envelope.body).includes("2026-11-10T")), "Ana's agent never saw an interval outside what she asked about");
});

const MEETING_FIELDS = ["/body/title", "/body/window", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms", "/body/event", "/body/as_of"];
const meeting = (commit: ScopeTerms["commit"] = "ask_me"): ScopeTerms => ({
  may: ["request", "propose", "counter", "accept", "commit", "inform"],
  disclose: MEETING_FIELDS,
  receive: MEETING_FIELDS,
  commit,
  ...(commit === "within_limits" ? { limits: { max_duration_minutes: 60, timezone: "UTC", weekdays: [1, 2, 3, 4, 5], earliest_minute: 480, latest_minute: 1080 } } : {}),
  redaction: "reject",
});
const slot = (h: string) => ({ start: `2026-11-10T${h}:00:00Z`, end: `2026-11-10T${h}:30:00Z` });
const proposal = (h: string): JsonObject => ({ title: "Launch sync", duration_minutes: 30, slots: [slot(h)], location: { kind: "video" } });
const terms = (h: string): JsonObject => ({ title: "Launch sync", duration_minutes: 30, start: slot(h).start, end: slot(h).end, location: { kind: "video" } });

async function meetingWorld(anaCommit: ScopeTerms["commit"] = "ask_me", leeCommit: ScopeTerms["commit"] = "ask_me"): Promise<World> {
  const w = await buildWorld();
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.meeting/1": meeting(anaCommit) } });
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.meeting/1": meeting(leeCommit) } });
  return w;
}

test("spec 9.2: an agent can't accept its own proposal, or one a later counter replaced; the other person is never told their agent agreed", async () => {
  const w = await meetingWorld("ask_me", "within_limits");
  const toLee = { to: LEE, scope: "alp.meeting/1" } as const;
  const prop = expect(await w.example.send(w.ana.agent, { ...toLee, type: "propose", body: proposal("16") }), "delivered");
  const thread = prop.thread;
  const counter = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.meeting/1", type: "counter", thread, in_reply_to: prop.envelope.id, body: proposal("17") }), "delivered");
  const self = expect(await w.example.send(w.ana.agent, { ...toLee, type: "accept", thread, in_reply_to: prop.envelope.id, body: { terms: terms("16") } }), "rejected");
  assert.equal(self.code, "thread_state");
  assert.match(self.reasons[0]?.detail ?? "", /accept answers the other party's proposal, never your own/);
  // Lee's broker refuses it too, from a broker that skipped the check.
  const env = await forged(w, "example", prop.envelope, { type: "accept", in_reply_to: prop.envelope.id, in_reply_to_hash: objectHash(prop.envelope), body: { terms: terms("16") }, terms_hash: termsHash(terms("16")) });
  const r = await w.example.acceptInbound(structuredClone(env));
  assert.equal(r.kind === "receipt" && r.receipt.code, "thread_state");
  await w.example.settled();
  assert.equal((await w.example.thread(w.lee.agent, thread)).thread.state, "negotiating", "Lee's copy is unchanged");
  assert.equal((await w.example.listRatifications(w.lee.human())).length, 0, "Lee's broker neither asked Lee nor ratified");
  assert.ok(!w.notifier.sent.some((n) => n.principal === LEE && n.kind === "ratification_needed"));
  // Accepting the counter, the latest proposal, works.
  expect(await w.example.send(w.ana.agent, { ...toLee, type: "accept", thread, in_reply_to: counter.envelope.id, body: { terms: terms("17") } }), "delivered");
});

test("spec 9.2, 9.4: agreed terms end with a commit, a decline or expiry: acks don't prolong them, an ack can't close them, and a commit needs both ratifications still valid", async () => {
  const w = await meetingWorld();
  const toLee = { to: LEE, scope: "alp.meeting/1" } as const;
  const toAna = { to: ANA, scope: "alp.meeting/1" } as const;
  const prop = expect(await w.example.send(w.ana.agent, { ...toLee, type: "propose", expires_in_seconds: 86400, body: proposal("16") }), "delivered");
  const thread = prop.thread;
  const acc = expect(await w.example.send(w.lee.agent, { ...toAna, type: "accept", thread, in_reply_to: prop.envelope.id, expires_in_seconds: 86400, body: { terms: terms("16") } }), "delivered");
  await w.example.settled();
  const agreedUntil = (await w.example.thread(w.ana.agent, thread)).thread.expires_at;
  // An ack that would close agreed terms is refused; one that acknowledges goes, but doesn't keep them waiting.
  const close = expect(await w.example.send(w.ana.agent, { ...toLee, type: "ack", thread, in_reply_to: acc.envelope.id, body: { of: acc.envelope.id, status: "completed" } }), "rejected");
  assert.match(close.reasons[0]?.detail ?? "", /agreed terms end with a commit, or with a decline that cancels them/);
  expect(await w.example.send(w.ana.agent, { ...toLee, type: "ack", thread, in_reply_to: acc.envelope.id, expires_in_seconds: 7 * 86400, body: { of: acc.envelope.id, status: "received" } }), "delivered");
  for (const agent of [w.ana.agent, w.lee.agent]) assert.equal((await w.example.thread(agent, thread)).thread.expires_at, agreedUntil, "both copies keep the accept's expiry");

  // Both ratify; their records last 3 days. A commit after they lapse is refused, by the sender and the recipient.
  for (const person of [w.ana, w.lee]) {
    const pending = (await w.example.listRatifications(person.human())).find((r) => r.state === "pending");
    assert.ok(pending);
    await w.example.ratify(person.human(), { request: pending.id, decision: "approve" });
  }
  const w2 = await meetingWorld();
  const p2 = expect(await w2.example.send(w2.ana.agent, { ...toLee, type: "propose", expires_in_seconds: 7 * 86400, body: proposal("16") }), "delivered");
  const a2 = expect(await w2.example.send(w2.lee.agent, { ...toAna, type: "accept", thread: p2.thread, in_reply_to: p2.envelope.id, expires_in_seconds: 7 * 86400, body: { terms: terms("16") } }), "delivered");
  await w2.example.settled();
  for (const person of [w2.ana, w2.lee]) {
    const pending = (await w2.example.listRatifications(person.human())).find((r) => r.state === "pending");
    assert.ok(pending);
    await w2.example.ratify(person.human(), { request: pending.id, decision: "approve" });
  }
  w2.clock.advance(4 * 86400);
  const late = expect(await w2.example.send(w2.lee.agent, { ...toAna, type: "commit", thread: p2.thread, in_reply_to: a2.envelope.id, body: { terms: terms("16") } }), "rejected");
  assert.equal(late.code, "thread_state");
  assert.match(late.reasons[0]?.detail ?? "", /a ratification of the agreed terms has expired; new terms need a new thread/);
  const view = await w2.example.thread(w2.lee.agent, p2.thread);
  assert.equal(view.thread.state, "agreed");
  // A decline ends them.
  expect(await w2.example.send(w2.lee.agent, { ...toAna, type: "decline", thread: p2.thread, in_reply_to: a2.envelope.id, body: { of: a2.envelope.id, reason: "not_available" } }), "delivered");
  assert.equal((await w2.example.thread(w2.ana.agent, p2.thread)).thread.state, "cancelled");
});

test("spec 9.2: a decline of agreed terms voids what still waits for ratification, and says the thread was closed", async () => {
  const w = await meetingWorld();
  const prop = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "propose", body: proposal("16") }), "delivered");
  const acc = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.meeting/1", type: "accept", thread: prop.thread, in_reply_to: prop.envelope.id, body: { terms: terms("16") } }), "delivered");
  await w.example.settled();
  const leeReq = (await w.example.listRatifications(w.lee.human())).find((r) => r.state === "pending");
  assert.ok(leeReq);
  expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "decline", thread: prop.thread, in_reply_to: acc.envelope.id, body: { of: acc.envelope.id, reason: "not_available" } }), "delivered");
  await w.example.settled();
  for (const person of [w.ana, w.lee]) assert.deepEqual((await w.example.listRatifications(person.human())).map((r) => r.state), ["voided"], "nothing is left pending");
  const fresh = (await w.example.store.getRatificationRequest(leeReq.id))!;
  await w.example.store.putRatificationRequest({ ...fresh, state: "pending" });
  await assert.rejects(w.example.ratify(w.lee.human(), { request: leeReq.id, decision: "approve" }), /the thread is cancelled; this ratification request no longer applies/);
});

test("spec 9.4: the side that receives an accept ratifies by standing grant once its answer is out, so the accepting side holds the record and the commit goes (one broker and two)", async () => {
  // One broker: Lee proposes, Ana accepts; Lee's grant ratifies within its limits.
  const w = await meetingWorld("ask_me", "within_limits");
  const prop = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.meeting/1", type: "propose", body: proposal("16") }), "delivered");
  const acc = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "accept", thread: prop.thread, in_reply_to: prop.envelope.id, body: { terms: terms("16") } }), "delivered");
  await w.example.settled();
  const anaCopy = (await w.example.thread(w.ana.agent, prop.thread)).thread;
  assert.match(String(anaCopy.ratifications?.theirs?.record.method), /^standing-grant:/, "Ana's broker holds Lee's standing ratification");
  const anaReq = (await w.example.listRatifications(w.ana.human())).find((r) => r.state === "pending");
  assert.ok(anaReq);
  await w.example.ratify(w.ana.human(), { request: anaReq.id, decision: "approve" });
  expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "commit", thread: prop.thread, in_reply_to: acc.envelope.id, body: { terms: terms("16") } }), "delivered");
  const ledger = await w.example.ledger(w.lee.human());
  assert.ok(!ledger.some((e) => e.kind === "receipt" && e.outcome === "refused"), "no ratification ack was refused");

  // Two brokers: Pat proposes, Ana accepts; Pat's grant ratifies within its limits.
  const v = await buildWorld();
  await v.example.setGrant(v.ana.human(), { counterparty: PAT, scopes: { "alp.meeting/1": meeting() } });
  await v.partner.setGrant(v.pat.human(), { counterparty: ANA, scopes: { "alp.meeting/1": meeting("within_limits") } });
  const p = expect(await v.partner.send(v.pat.agent, { to: ANA, scope: "alp.meeting/1", type: "propose", body: proposal("16") }), "delivered");
  const a = expect(await v.example.send(v.ana.agent, { to: PAT, scope: "alp.meeting/1", type: "accept", thread: p.thread, in_reply_to: p.envelope.id, body: { terms: terms("16") } }), "delivered");
  await v.partner.settled();
  await v.example.settled();
  assert.ok((await v.example.thread(v.ana.agent, p.thread)).thread.ratifications?.theirs, "Ana's broker holds Pat's record");
  const req = (await v.example.listRatifications(v.ana.human())).find((r) => r.state === "pending");
  assert.ok(req);
  await v.example.ratify(v.ana.human(), { request: req.id, decision: "approve" });
  await v.example.settled();
  expect(await v.partner.send(v.pat.agent, { to: ANA, scope: "alp.meeting/1", type: "commit", thread: p.thread, in_reply_to: a.envelope.id, body: { terms: terms("16") } }), "delivered");
});

test(`spec 9.2: a thread takes at most ${MAX_THREAD_MESSAGES} messages, then only one that ends it; a new thread carries on`, async () => {
  const w = await buildWorld({ domainDocs: false, brokerOptions: { limits: { defaultRateLimit: { count: 10_000, per_seconds: 3600 } } } });
  const d = await w.example.registerDelegate({ principal: LEE, label: "desk", kind: "bridged", client_id: CLIENTS.connector });
  const desk: DelegateCaller = { kind: "delegate", principal: LEE, delegate: d.id, client_id: CLIENTS.connector };
  const update = (n: number): JsonObject => ({ subject: "Board pack", state: "in_progress", percent_complete: n % 100, updated_at: "2026-11-09T13:00:00Z" });
  const first = expect(await w.example.send(w.lee.agent, { to: LEE, to_delegate: d.id, scope: "alp.status/1", type: "inform", body: update(0) }), "delivered");
  const thread = first.thread;
  let last = first.envelope.id;
  for (let i = 1; i < MAX_THREAD_MESSAGES; i++) {
    const [from, to] = i % 2 ? [desk, `${LEE}/dot`] : [w.lee.agent, d.id];
    last = expect(await w.example.send(from, { to: LEE, to_delegate: to, scope: "alp.status/1", type: "inform", thread, body: update(i) }), "delivered").envelope.id;
  }
  const full = expect(await w.example.send(w.lee.agent, { to: LEE, to_delegate: d.id, scope: "alp.status/1", type: "request", thread, in_reply_to: last, body: { subject: "Board pack" } }), "rejected");
  assert.equal(full.code, "thread_state");
  assert.match(full.reasons[0]?.detail ?? "", /continue in a new thread/);
  expect(await w.example.send(w.lee.agent, { to: LEE, to_delegate: d.id, scope: "alp.status/1", type: "ack", thread, in_reply_to: last, body: { of: last, status: "completed" } }), "delivered");
  assert.equal((await w.example.thread(desk, thread)).thread.state, "done");
  const view = await w.example.thread(desk, thread);
  assert.equal(new Set(view.thread.history.map((h) => h.envelope_id)).size, MAX_THREAD_MESSAGES + 1, "the thread record stays bounded");
  expect(await w.example.send(w.lee.agent, { to: LEE, to_delegate: d.id, scope: "alp.status/1", type: "request", body: { subject: "Board pack" } }), "delivered");
});

test("spec 9.3, 10.2: a reply that overtook the message it answers is refused as retryable", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.ana.human(), { counterparty: PAT, scopes: { "alp.availability/1": availability } });
  await w.partner.setGrant(w.pat.human(), { counterparty: ANA, scopes: { "alp.availability/1": availability } });
  const ask = expect(await w.example.send(w.ana.agent, { to: PAT, scope: "alp.availability/1", type: "request", body: window("10", "15", "18") }), "delivered");
  const answer = expect(await w.partner.send(w.pat.agent, { to: ANA, scope: "alp.availability/1", type: "inform", thread: ask.thread, in_reply_to: ask.envelope.id, body: free("10", "15") }), "delivered");
  const early = await forged(w, "partner", answer.envelope, { in_reply_to: ulid(w.clock.now().getTime()) });
  const r = await w.example.acceptInbound(structuredClone(early));
  assert.equal(r.kind, "receipt");
  assert.equal(r.kind === "receipt" && r.receipt.code, "thread_state");
  assert.equal(r.kind === "receipt" && r.retry_after, 2, "the sender may try again shortly");
  const wrongHash = await w.example.acceptInbound(structuredClone(await forged(w, "partner", answer.envelope, { in_reply_to_hash: "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" })));
  assert.equal(wrongHash.kind === "receipt" && wrongHash.receipt.code, "thread_state");
  assert.equal(wrongHash.kind === "receipt" && wrongHash.retry_after, undefined, "a reply that names the wrong hash never becomes right: not retryable");
});
