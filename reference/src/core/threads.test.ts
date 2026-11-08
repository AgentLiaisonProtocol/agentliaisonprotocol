// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { ScopeRegistry } from "./scopes/index.ts";
import { MAX_THREAD_MESSAGES, acceptedTypes, applyToThread, expireIfDue } from "./threads.ts";
import type { ThreadMessage } from "./threads.ts";
import type { MessageType, Ratification, ThreadRecord } from "./types.ts";

const reg = ScopeRegistry.load();
const meeting = reg.require("alp.meeting/1");
const briefing = reg.require("alp.briefing/1");
const status = reg.require("alp.status/1");
const availability = reg.require("alp.availability/1");
const documents = reg.require("alp.document_request/1");
const now = new Date("2026-11-09T14:00:00.000Z");
let n = 0;
function msg(type: MessageType, extra: Partial<ThreadMessage> = {}): ThreadMessage {
  n++;
  return { thread: "01JCT00000000000000000000T", principal: "alp:ana@example.org", counterparty: "alp:lee@example.org", scope: "alp.meeting/1", envelope_id: `01JCM0000000000000000000${String(n).padStart(2, "0")}`, type, direction: "out", at: now.toISOString(), expires_at: "2026-11-12T14:00:00.000Z", ...extra };
}
function step(t: ThreadRecord | null, m: ThreadMessage, scope = meeting): ThreadRecord {
  const r = applyToThread(scope, t, m, now);
  assert.ok(r.ok, r.ok ? "" : r.detail);
  return r.thread;
}
function refused(t: ThreadRecord | null, m: ThreadMessage, scope = meeting, at = now): string {
  const r = applyToThread(scope, t, m, at);
  assert.equal(r.ok, false, `${m.type} should be refused`);
  return r.ok ? "" : r.detail;
}
/** Both people's ratification records, valid until `until`. */
function ratified(t: ThreadRecord, until = "2026-11-12T14:00:00.000Z"): ThreadRecord {
  const record = { expires_at: until } as Ratification;
  return { ...t, ratifications: { mine: { id: "m", hash: "sha256:M", record }, theirs: { id: "t", hash: "sha256:H", record } } };
}
/** A reply to the last message of `t` (its envelope id and type, seen from this side). */
function replyTo(t: ThreadRecord, extra: Partial<ThreadMessage> = {}): Partial<ThreadMessage> {
  const last = t.history[t.history.length - 1];
  assert.ok(last);
  return { in_reply_to: last.envelope_id, reply_to: { type: last.type, direction: last.direction }, ...extra };
}

test("negotiation: request → propose → counter → accept → ratified commit → done", () => {
  let t = step(null, msg("request"));
  assert.equal(t.state, "open");
  t = step(t, msg("propose", { ...replyTo(t), direction: "in" }));
  t = step(t, msg("counter", replyTo(t)));
  assert.equal(t.state, "negotiating");
  t = step(t, msg("accept", { ...replyTo(t), direction: "in", terms_hash: "sha256:T" }));
  assert.equal(t.state, "agreed");
  assert.equal(t.proposer, "me");
  const noRat = applyToThread(meeting, t, msg("commit", { in_reply_to: "a", reply_to: { type: "accept", direction: "in" }, terms_hash: "sha256:T" }), now);
  assert.equal(!noRat.ok && noRat.code, "needs_ratification");
  t = ratified(t);
  const wrongTerms = applyToThread(meeting, t, msg("commit", { in_reply_to: "a", reply_to: { type: "accept", direction: "in" }, terms_hash: "sha256:X", ratifications: ["sha256:M", "sha256:H"] }), now);
  assert.equal(wrongTerms.ok, false);
  t = step(t, msg("commit", { in_reply_to: "a", reply_to: { type: "accept", direction: "in" }, terms_hash: "sha256:T", ratifications: ["sha256:H", "sha256:M"] }));
  assert.equal(t.state, "committed");
  const twice = applyToThread(meeting, t, msg("commit", { in_reply_to: "a", reply_to: { type: "accept", direction: "in" }, terms_hash: "sha256:T", ratifications: ["sha256:H", "sha256:M"] }), now);
  assert.equal(twice.ok, false, "single use");
  t = step(t, msg("ack", { in_reply_to: "c", reply_to: { type: "commit", direction: "out" }, direction: "in", ack_status: "completed" }));
  assert.equal(t.state, "done");
  assert.equal(applyToThread(meeting, t, msg("inform"), now).ok, false, "terminal");
});

test("scope rules: starts, replies, negotiable; in agreed the terms can't change, so a new proposal is refused (spec 9.4)", () => {
  assert.equal(applyToThread(meeting, null, msg("accept", { terms_hash: "sha256:T" }), now).ok, false);
  assert.equal(applyToThread(briefing, null, msg("propose", { scope: "alp.briefing/1" }), now).ok, false);
  const t = step(null, msg("request", { scope: "alp.briefing/1" }), briefing);
  assert.equal(applyToThread(briefing, t, msg("counter", { scope: "alp.briefing/1", in_reply_to: "r", reply_to: { type: "request", direction: "out" } }), now).ok, false);
  let m = step(null, msg("propose"));
  const proposal = m.history[0]?.envelope_id;
  m = step(m, msg("accept", { ...replyTo(m), direction: "in", terms_hash: "sha256:T" }));
  m = { ...m, ratifications: { mine: { id: "m", hash: "sha256:M", record: {} as never } } };
  assert.match(refused(m, msg("propose", { direction: "in" })), /new terms need a new thread/);
  assert.match(refused(m, msg("counter", { direction: "in", in_reply_to: proposal, reply_to: { type: "propose", direction: "out" } })), /new terms need a new thread/);
  assert.equal(m.state, "agreed");
  assert.equal(m.terms_hash, "sha256:T", "the agreed terms stand");
  assert.equal(m.ratifications?.mine?.hash, "sha256:M", "and so does the ratification already made");
});

test("threads expire before commitment, not after", () => {
  const t = step(null, msg("request"));
  assert.equal(expireIfDue(t, new Date("2026-11-13T00:00:00Z")).state, "expired");
  assert.equal(expireIfDue({ ...t, state: "committed" }, new Date("2026-11-13T00:00:00Z")).state, "committed");
});

test("a conversation: either side keeps an open thread going with replies and follow-ups (alp.status/1)", () => {
  const s = { scope: "alp.status/1" as const };
  // Lee's side of a status thread that Ana's agent opened with an unsolicited update.
  const lee = (type: MessageType, extra: Partial<ThreadMessage> = {}): ThreadMessage => msg(type, { ...s, principal: "alp:lee@example.org", counterparty: "alp:ana@example.org", ...extra });
  let t = step(null, lee("inform", { direction: "in" }), status);
  // Lee's agent answers the update with its own, in the same thread (an inform answering an inform).
  t = step(t, lee("inform", replyTo(t)), status);
  // Then adds to it before Ana's agent says anything (a follow-up names no message).
  t = step(t, lee("inform"), status);
  // Ana's agent asks a follow-up question about the first update, which Lee's agent answers.
  t = step(t, lee("request", { direction: "in", in_reply_to: t.history[0]?.envelope_id, reply_to: { type: "inform", direction: "in" } }), status);
  t = step(t, lee("inform", replyTo(t)), status);
  // Lee's agent asks back; Ana's agent answers with a question of its own; Lee's agent answers that.
  t = step(t, lee("request", replyTo(t)), status);
  t = step(t, lee("request", replyTo(t, { direction: "in" })), status);
  t = step(t, lee("inform", replyTo(t)), status);
  assert.equal(t.state, "open");
  assert.deepEqual(t.history.map((h) => `${h.direction} ${h.type}`), ["in inform", "out inform", "out inform", "in request", "out inform", "out request", "in request", "out inform"], "every turn is recorded, in order");
  // Ana's agent closes it.
  t = step(t, lee("ack", replyTo(t, { direction: "in", ack_status: "completed" })), status);
  assert.equal(t.state, "done");
  assert.match(refused(t, lee("inform"), status), /the thread is done; anything more needs a new thread/);
});

test("conversations in alp.briefing/1 and alp.availability/1: follow-up questions, clarifications and updates", () => {
  const b = { scope: "alp.briefing/1" as const };
  let t = step(null, msg("request", b), briefing);
  // A clarifying question in answer to the request, then the answer to it, then the briefing, then a follow-up.
  t = step(t, msg("request", { ...b, ...replyTo(t), direction: "in" }), briefing);
  t = step(t, msg("inform", { ...b, ...replyTo(t) }), briefing);
  t = step(t, msg("inform", { ...b, direction: "in", in_reply_to: t.history[0]?.envelope_id, reply_to: { type: "request", direction: "out" } }), briefing);
  t = step(t, msg("request", { ...b, ...replyTo(t) }), briefing);
  t = step(t, msg("inform", { ...b, ...replyTo(t), direction: "in" }), briefing);
  t = step(t, msg("inform", { ...b, direction: "in" }), briefing);
  assert.equal(t.state, "open");
  // The replies map still decides: a decline answers a request, not an inform.
  assert.match(refused(t, msg("decline", { ...b, ...replyTo(t) }), briefing), /decline cannot reply to inform/);

  const a = { scope: "alp.availability/1" as const };
  let v = step(null, msg("request", a), availability);
  v = step(v, msg("inform", { ...a, ...replyTo(v), direction: "in" }), availability);
  v = step(v, msg("request", { ...a, ...replyTo(v) }), availability);
  v = step(v, msg("inform", { ...a, ...replyTo(v), direction: "in" }), availability);
  v = step(v, msg("decline", { ...a, direction: "in", in_reply_to: v.history[2]?.envelope_id, reply_to: { type: "request", direction: "out" } }), availability);
  assert.equal(v.state, "open", "a decline of a later request turns down that request only");
  v = step(v, msg("decline", { ...a, direction: "in", in_reply_to: v.history[0]?.envelope_id, reply_to: { type: "request", direction: "out" } }), availability);
  assert.equal(v.state, "done", "a decline of the thread's first message closes it");
});

test("a follow-up names no message, so it can't be a type that must reply; a new thread starts only with a type in starts", () => {
  const b = { scope: "alp.briefing/1" as const };
  const t = step(null, msg("request", b), briefing);
  for (const type of ["ack", "decline"] as const) assert.match(refused(t, msg(type, { ...b, direction: "in" }), briefing), new RegExp(`${type} must reply to a message`));
  assert.match(refused(null, msg("inform", b), briefing), /inform cannot start a alp\.briefing\/1 thread/);
  assert.match(refused(null, msg("request", { ...b, in_reply_to: "x", reply_to: { type: "request", direction: "in" } }), briefing), /a new thread cannot reply to anything/);
  assert.match(refused(t, msg("inform", { ...b, in_reply_to: "x" }), briefing), /in_reply_to names no message in this thread/);
});

test("how a thread ends: ack completed from either side, a decline, or expiry; every message extends the thread's life", () => {
  const s = { scope: "alp.status/1" as const };
  let t = step(null, msg("request", { ...s, expires_at: "2026-11-10T14:00:00.000Z" }), status);
  assert.equal(t.expires_at, "2026-11-10T14:00:00.000Z");
  t = step(t, msg("inform", { ...s, ...replyTo(t), direction: "in", expires_at: "2026-11-11T14:00:00.000Z" }), status);
  assert.equal(t.expires_at, "2026-11-11T14:00:00.000Z", "the answer keeps the thread open as long as it lives");
  t = step(t, msg("inform", { ...s, expires_at: "2026-11-09T15:00:00.000Z" }), status);
  assert.equal(t.expires_at, "2026-11-11T14:00:00.000Z", "a shorter-lived message never shortens it");
  const later = new Date("2026-11-11T14:00:00.000Z");
  assert.equal(expireIfDue(t, new Date("2026-11-11T13:59:59.999Z")).state, "open");
  assert.equal(expireIfDue(t, later).state, "expired");
  assert.match(refused(t, msg("inform", s), status, later), /the thread is expired/);
  // The sender of the last message can close the thread too, by acknowledging the other side's.
  const closed = step(t, msg("ack", { ...s, in_reply_to: t.history[1]?.envelope_id, reply_to: { type: "inform", direction: "in" }, ack_status: "completed" }), status);
  assert.equal(closed.state, "done");
  const received = step(t, msg("ack", { ...s, ...replyTo(t), direction: "in", ack_status: "received" }), status);
  assert.equal(received.state, "open", "an ack that only says received leaves the thread open");
});

test("around a negotiation: requests before it, informs after the commit, and nothing conversational in between (alp.meeting/1)", () => {
  let t = step(null, msg("request"));
  // Before any proposal: a request answered by a request (propose times in another window, or you propose).
  t = step(t, msg("request", { ...replyTo(t), direction: "in" }));
  assert.match(refused(t, msg("inform", { direction: "in" })), /inform reports what happened after the commit, so an open thread doesn't take it/);
  t = step(t, msg("propose", replyTo(t)));
  assert.equal(t.state, "negotiating");
  for (const type of ["request", "inform", "propose"] as const) assert.match(refused(t, msg(type, { direction: "in" })), /a negotiating alp\.meeting\/1 thread doesn't take|inform reports/);
  t = step(t, msg("accept", { ...replyTo(t), direction: "in", terms_hash: "sha256:T" }));
  assert.equal(t.state, "agreed");
  for (const type of ["request", "inform"] as const) assert.equal(applyToThread(meeting, t, msg(type, { direction: "in" }), now).ok, false, `${type} while the terms wait for ratification`);
  const acceptId = t.history[t.history.length - 1]?.envelope_id;
  t = ratified(t);
  t = step(t, msg("commit", { in_reply_to: acceptId, reply_to: { type: "accept", direction: "in" }, terms_hash: "sha256:T", ratifications: ["sha256:H", "sha256:M"] }));
  assert.equal(t.state, "committed");
  // After the commit, either side reports what happened, as often as needed; nobody asks for new times here.
  t = step(t, msg("inform", replyTo(t, { direction: "in" })));
  t = step(t, msg("inform", replyTo(t)));
  t = step(t, msg("inform"));
  assert.match(refused(t, msg("request", { direction: "in" })), /a committed alp\.meeting\/1 thread doesn't take request/);
  assert.match(refused(t, msg("decline", replyTo(t, { direction: "in" }))), /doesn't take decline/);
  assert.equal(expireIfDue(t, new Date("2026-12-31T00:00:00Z")).state, "committed", "a committed thread doesn't expire");
  t = step(t, msg("ack", replyTo(t, { direction: "in", ack_status: "completed" })));
  assert.equal(t.state, "done");
});

test("alp.document_request/1: no inform before the commit, the request can be clarified, only the proposer commits", () => {
  const d = { scope: "alp.document_request/1" as const };
  let t = step(null, msg("request", d), documents);
  t = step(t, msg("request", { ...d, ...replyTo(t), direction: "in" }), documents);
  t = step(t, msg("request", { ...d, ...replyTo(t) }), documents);
  assert.equal(applyToThread(documents, t, msg("inform", { ...d, direction: "in" }), now).ok, false);
  assert.match(refused(t, msg("propose", { ...d, direction: "in" }), documents), /propose must reply to a message/, "propose doesn't start this scope's threads, so it answers a request");
  t = step(t, msg("propose", { ...d, ...replyTo(t), direction: "in" }), documents);
  t = step(t, msg("accept", { ...d, ...replyTo(t), terms_hash: "sha256:D" }), documents);
  assert.equal(t.proposer, "counterparty");
  const acceptId = t.history[t.history.length - 1]?.envelope_id;
  t = ratified(t);
  assert.match(refused(t, msg("commit", { ...d, in_reply_to: acceptId, reply_to: { type: "accept", direction: "out" }, terms_hash: "sha256:D", ratifications: ["sha256:H", "sha256:M"] }), documents), /only the proposer may commit/);
  t = step(t, msg("commit", { ...d, direction: "in", in_reply_to: acceptId, reply_to: { type: "accept", direction: "out" }, terms_hash: "sha256:D", ratifications: ["sha256:H", "sha256:M"] }), documents);
  t = step(t, msg("inform", { ...d, direction: "in" }), documents);
  t = step(t, msg("inform", { ...d, ...replyTo(t) }), documents);
  assert.equal(t.state, "committed");
});

test("the types each state accepts (spec 9.2)", () => {
  assert.deepEqual(acceptedTypes(status, "open"), ["request", "inform", "decline", "ack", "ask_human", "error"]);
  assert.deepEqual(acceptedTypes(meeting, "open"), ["request", "propose", "decline", "ack", "ask_human", "error"]);
  assert.deepEqual(acceptedTypes(meeting, "negotiating"), ["counter", "accept", "decline", "ack", "ask_human", "error"]);
  assert.deepEqual(acceptedTypes(meeting, "agreed"), ["commit", "decline", "ack", "ask_human", "error"]);
  assert.deepEqual(acceptedTypes(meeting, "committed"), ["inform", "ack", "ask_human", "error"]);
  for (const s of ["done", "expired", "cancelled"] as const) assert.deepEqual(acceptedTypes(meeting, s), []);
});

test("an accept or a counter answers the other party's latest proposal: never the sender's own, nor one a later proposal replaced (spec 9.2)", () => {
  let t = step(null, msg("propose"));
  const own = t.history[0]?.envelope_id;
  // Ana's agent can't accept, or counter, its own proposal.
  assert.match(refused(t, msg("accept", { ...replyTo(t), terms_hash: "sha256:A" })), /accept answers the other party's proposal, never your own/);
  assert.match(refused(t, msg("counter", replyTo(t))), /counter answers the other party's proposal, never your own/);
  // Lee's agent counters; Ana's agent may now accept or counter that, but not go back to its own proposal.
  t = step(t, msg("counter", { ...replyTo(t), direction: "in" }));
  const leeCounter = t.history[1]?.envelope_id;
  assert.match(refused(t, msg("accept", { in_reply_to: own, reply_to: { type: "propose", direction: "out" }, terms_hash: "sha256:A" })), /never your own/);
  t = step(t, msg("counter", replyTo(t)));
  // Ana's counter replaced Lee's: Lee's agent accepts Ana's latest, and Ana's agent can no longer accept Lee's counter.
  assert.match(refused(t, msg("accept", { in_reply_to: leeCounter, reply_to: { type: "counter", direction: "in" }, terms_hash: "sha256:D" })), /a later one replaced this one/);
  assert.match(refused(t, msg("accept", { in_reply_to: own, reply_to: { type: "propose", direction: "out" }, direction: "in", terms_hash: "sha256:A" })), /a later one replaced this one/);
  t = step(t, msg("accept", { ...replyTo(t), direction: "in", terms_hash: "sha256:C" }));
  assert.equal(t.state, "agreed");
  assert.equal(t.proposer, "me");
});

test("agreed terms: an ack can't close them, only acknowledge; a decline cancels them; acks and questions don't keep them waiting (spec 9.2)", () => {
  let t = step(null, msg("propose", { expires_at: "2026-11-10T14:00:00.000Z" }));
  t = step(t, msg("accept", { ...replyTo(t), direction: "in", terms_hash: "sha256:T", expires_at: "2026-11-11T14:00:00.000Z" }));
  assert.equal(t.expires_at, "2026-11-11T14:00:00.000Z", "an accept extends the thread");
  const acceptId = t.history[1]?.envelope_id;
  const toAccept = { in_reply_to: acceptId, reply_to: { type: "accept" as const, direction: "in" as const } };
  assert.match(refused(t, msg("ack", { ...toAccept, ack_status: "completed" })), /agreed terms end with a commit, or with a decline that cancels them/);
  // Acknowledgements and errors are accepted, but don't extend agreed terms.
  t = step(t, msg("ack", { ...toAccept, ack_status: "received", expires_at: "2026-11-16T14:00:00.000Z" }));
  t = step(t, msg("error", { expires_at: "2026-11-16T14:00:00.000Z" }));
  assert.equal(t.state, "agreed");
  assert.equal(t.expires_at, "2026-11-11T14:00:00.000Z", "nothing but a proposal or an accept prolongs agreed terms");
  assert.equal(expireIfDue(t, new Date("2026-11-11T14:00:00.000Z")).state, "expired");
  assert.equal(step(t, msg("decline", toAccept)).state, "cancelled");
});

test("while terms are on the table, only a proposal or an accept extends the thread (spec 9.2)", () => {
  let t = step(null, msg("propose", { expires_at: "2026-11-10T14:00:00.000Z" }));
  t = step(t, msg("ack", { ...replyTo(t), direction: "in", ack_status: "received", expires_at: "2026-11-16T14:00:00.000Z" }));
  t = step(t, msg("ask_human", { direction: "in", expires_at: "2026-11-16T14:00:00.000Z" }));
  assert.equal(t.expires_at, "2026-11-10T14:00:00.000Z");
  t = step(t, msg("counter", { in_reply_to: t.history[0]?.envelope_id, reply_to: { type: "propose", direction: "out" }, direction: "in", expires_at: "2026-11-12T14:00:00.000Z" }));
  assert.equal(t.expires_at, "2026-11-12T14:00:00.000Z", "a counter does");
});

test("a commit needs both ratification records valid when it is sent and when it is received (spec 9.4)", () => {
  let t = step(null, msg("propose"));
  t = step(t, msg("accept", { ...replyTo(t), direction: "in", terms_hash: "sha256:T", expires_at: "2026-11-20T14:00:00.000Z" }));
  const acceptId = t.history[1]?.envelope_id;
  t = ratified(t, "2026-11-12T14:00:00.000Z");
  const commit = msg("commit", { in_reply_to: acceptId, reply_to: { type: "accept", direction: "in" }, terms_hash: "sha256:T", ratifications: ["sha256:H", "sha256:M"] });
  assert.equal(applyToThread(meeting, t, commit, new Date("2026-11-12T13:59:59.000Z")).ok, true);
  assert.match(refused(t, commit, meeting, new Date("2026-11-12T14:00:00.000Z")), /a ratification of the agreed terms has expired; new terms need a new thread/);
  const theirsLapsed: ThreadRecord = { ...t, ratifications: { mine: { id: "m", hash: "sha256:M", record: { expires_at: "2026-11-15T14:00:00.000Z" } as Ratification }, theirs: { id: "t", hash: "sha256:H", record: { expires_at: "2026-11-09T13:00:00.000Z" } as Ratification } } };
  assert.match(refused(theirsLapsed, commit), /has expired/);
});

test(`a thread takes at most ${MAX_THREAD_MESSAGES} messages, then only one that ends it (spec 9.2); one person's own agents' copy counts each message once`, () => {
  const s = { scope: "alp.status/1" as const };
  let t = step(null, msg("inform", s), status);
  for (let i = 1; i < MAX_THREAD_MESSAGES; i++) t = step(t, msg("inform", { ...s, direction: i % 2 ? "in" : "out" }), status);
  assert.equal(t.history.length, MAX_THREAD_MESSAGES);
  assert.match(refused(t, msg("request", { ...s, direction: "in" }), status), new RegExp(`the thread holds ${MAX_THREAD_MESSAGES} messages, the most one thread takes, so it takes only a message that ends it; continue in a new thread`));
  const closed = step(t, msg("ack", { ...s, ...replyTo(t), direction: "in", ack_status: "completed" }), status);
  assert.equal(closed.state, "done");
  assert.match(refused(t, msg("ack", { ...s, ...replyTo(t), direction: "in", ack_status: "received" }), status), /takes only a message that ends it/);
  // Between one person's own agents each message is applied twice (as received, then as sent): the second time isn't another message.
  const self = { scope: "alp.status/1" as const, principal: "alp:lee@example.org", counterparty: "alp:lee@example.org" };
  let o = step(null, msg("inform", { ...self, direction: "in" }), status);
  o = step(o, { ...msg("inform", self), envelope_id: o.history[0]?.envelope_id ?? "" }, status);
  for (let i = 1; i < MAX_THREAD_MESSAGES; i++) {
    const m = msg("inform", { ...self, direction: "in" });
    o = step(o, m, status);
    o = step(o, { ...m, direction: "out" }, status);
  }
  assert.equal(o.history.length, 2 * MAX_THREAD_MESSAGES);
  assert.match(refused(o, msg("inform", { ...self, direction: "in" }), status), /takes only a message that ends it/);
});
