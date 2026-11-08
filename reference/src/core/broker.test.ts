// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { isDeepStrictEqual } from "node:util";
import { ANA, CLIENTS, FRAN, IDS, LEE, MALLORY, PAT, buildWorld, examplePolicy } from "../demo/world.ts";
import type { World } from "../demo/world.ts";
import { MemoryStore } from "../storage/memory.ts";
import type { SendResult } from "./api.ts";
import { homeBroker, pinnedFederationKeys } from "./domain.ts";
import { objectHash, signEnvelope, verifyAnyEnvelope, verifyReceipt } from "./envelope.ts";
import { hashJson } from "./hash.ts";
import { DEV_ISSUER } from "./identity.ts";
import { KeyRing } from "./keys.ts";
import { crossCheckEntries } from "./ledger.ts";
import { schemaErrors } from "./spec-schemas.ts";
import type { DelegateCaller, Envelope, HumanCaller, JsonObject, LedgerEntry, MessageRecord, ScopeTerms, UnsignedEnvelope } from "./types.ts";

const brief = { topic: "Q4 launch readiness", questions: ["What is still blocked?"], depth: "summary" };

function expect<S extends SendResult["status"]>(r: SendResult, s: S): Extract<SendResult, { status: S }> {
  assert.equal(r.status, s, JSON.stringify(r));
  return r as Extract<SendResult, { status: S }>;
}

function sendBrief(w: World, body: JsonObject = brief, extra: { note?: string; to?: string } = {}): Promise<SendResult> {
  return w.example.send(w.ana.agent, { to: extra.to ?? "lee@example.org", scope: "alp.briefing/1", type: "request", body, ...(extra.note ? { note: extra.note } : {}) });
}

/** Ana ↔ Pat across organizations, each side sealing its own grant through its own person. */
async function connectAnaPat(w: World, scopes: Record<string, ScopeTerms>): Promise<void> {
  await w.example.setGrant(w.ana.human(), { counterparty: PAT, scopes });
  await w.partner.setGrant(w.pat.human(), { counterparty: ANA, scopes });
}

const briefTerms: ScopeTerms = {
  may: ["request", "inform", "ask_human"],
  disclose: ["/body/topic", "/body/questions/*", "/body/depth", "/body/points/*", "/body/as_of"],
  receive: ["/body/topic", "/body/questions/*", "/body/depth", "/body/points/*", "/body/as_of"],
  commit: "ask_me",
  redaction: "reject",
};

// ---------------------------------------------------------------------------------------------
// Act 1: in one organization (Local profile)

test("Act 1.1 Ana's connector agent sends Lee a briefing request on the Local broker; Lee's agent reads and verifies it", async () => {
  const w = await buildWorld({ domainDocs: false });
  const sent = expect(await sendBrief(w), "delivered");
  assert.equal(sent.envelope.aud, IDS.example);
  assert.equal(sent.envelope.from.principal_id.length >= 16, true);
  assert.deepEqual(schemaErrors("envelope", sent.envelope), [], "the envelope validates against the spec schema");
  assert.deepEqual(schemaErrors("receipt", sent.receipt), []);
  assert.equal(w.fed.wire.length, 0, "no federation hop and no domain document needed");
  // The broker asks whether example.org publishes a document (spec 4.5); in the Local profile none exists, so local
  // configuration decides and no keys are fetched.
  assert.ok(w.resolver.lookups.every((l) => l === "domain:example.org"), JSON.stringify(w.resolver.lookups));

  const page = await w.example.inbox(w.lee.agent);
  assert.equal(page.items.length, 1);
  const item = page.items[0]!;
  assert.equal(item.verified.sender.address, ANA);
  assert.equal(item.verified.sender.attestation, "vendor");
  assert.equal(item.verified.signature, "verified");
  assert.deepEqual(item.content.body, brief);
  assert.equal((await verifyAnyEnvelope(item.envelope, w.example.jwks())).ok, true, "anyone with the broker's JWKS can verify it");
  assert.equal((await verifyReceipt(item.receipt!, w.example.jwks())).ok, true);

  const anaLedger = await w.example.ledger(w.ana.human());
  const leeLedger = await w.example.ledger(w.lee.human());
  const s = anaLedger.find((e) => e.kind === "sent")!;
  const rc = anaLedger.find((e) => e.kind === "receipt" && e.envelope_id === s.envelope_id)!;
  const r = leeLedger.find((e) => e.kind === "received")!;
  assert.deepEqual(crossCheckEntries(s, rc, r), []);
  for (const e of [...anaLedger, ...leeLedger]) assert.deepEqual(schemaErrors("ledgerEntry", e), [], `ledger entry ${e.kind}`);
  assert.equal((await w.example.verifyLedger(w.ana.human())).ok, true);
  assert.equal(s.client_id, CLIENTS.connector);
});

test("Act 1.2 a confidential.financial field is blocked at Ana's side; Fran (finance) may receive it", async () => {
  const w = await buildWorld();
  const body = { topic: "Budget", depth: "headline", context: { amount: { value: 1200000, currency: "USD" } } };
  const r = expect(await sendBrief(w, body), "rejected");
  assert.equal(r.code, "org_policy");
  assert.ok(r.reasons.every((x) => x.rule === "financial-stays-in-finance"));
  assert.equal((await w.example.inbox(w.lee.agent)).items.length, 0);
  expect(await sendBrief(w, body, { to: FRAN }), "delivered");
});

test("Act 1.3 free text: named explicitly to cross, and DLP-checked (a card number is blocked)", async () => {
  const w = await buildWorld();
  // /body/context/project is free text the default relationship doesn't name (it names /body/context only).
  const project = expect(await sendBrief(w, { topic: "T", depth: "headline", context: { project: "Atlas" } }), "rejected");
  assert.equal(project.reasons[0]?.pointer, "/body/context/project");
  assert.equal(project.reasons[0]?.detail, "Your person's terms for alp.briefing/1 with lee@example.org don't name the free-text field /body/context/project: send without it, or ask your person to allow it on their broker page.");
  const card = expect(await sendBrief(w, { topic: "pay with 4111 1111 1111 1111", depth: "headline" }), "rejected");
  assert.equal(card.code, "dlp_blocked");
  assert.ok(w.events.events.some((e) => e.detail.event === "dlp_blocked"));
  // The note is free text too: no grant names /note, so it never crosses.
  const note = expect(await sendBrief(w, brief, { note: "fyi" }), "rejected");
  assert.equal(note.reasons[0]?.pointer, "/note");
});

test("Act 1.4 another employee's token claiming Ana is refused, and so is a forged delegate", async () => {
  const w = await buildWorld();
  const r = expect(await w.example.send(w.fran.agent, { from: "ana@example.org", to: LEE, scope: "alp.briefing/1", type: "request", body: brief }), "rejected");
  assert.equal(r.code, "identity_mismatch");
  // Spec 5.1: logged as a security event naming the caller, never the claimed address or the message.
  const fran = (await w.example.getPrincipal(FRAN))!;
  const ev = w.events.events.find((e) => e.detail.event === "token_refused" && e.detail.code === "identity_mismatch");
  assert.ok(ev, "a token_refused security event");
  assert.equal(ev.status_id, 2, "failed");
  assert.deepEqual([ev.detail.principal_id, ev.detail.delegate, ev.detail.client_id], [fran.principal_id, w.fran.agent.delegate, w.fran.agent.client_id]);
  assert.deepEqual(schemaErrors("securityEvent", ev), []);
  assert.ok(!JSON.stringify(ev).includes("ana@example.org") && !JSON.stringify(ev).includes(brief.topic), "no claimed address, no payload");
  await assert.rejects(w.example.send({ ...w.fran.agent, delegate: `${ANA}/muse` }, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }), /not an active delegate/);
  assert.equal((await w.example.inbox(w.lee.agent)).items.length, 0);
});

test("Act 1.5 a client not on the organization's allow-list is refused", async () => {
  const w = await buildWorld();
  await w.example.registerDelegate({ principal: ANA, label: "other", client_id: CLIENTS.unlisted });
  const r = expect(await w.example.send({ kind: "delegate", principal: ANA, delegate: `${ANA}/other`, client_id: CLIENTS.unlisted }, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }), "rejected");
  assert.equal(r.code, "client_not_allowed");
  const ev = w.events.events.find((e) => e.detail.event === "client_refused");
  assert.equal(ev?.detail.client_id, CLIENTS.unlisted);
  assert.deepEqual(schemaErrors("securityEvent", ev), []);
});

test("Act 1.6 an outsider's message becomes a connection request on Lee's broker page, never reaching Lee's agent", async () => {
  const w = await buildWorld();
  // Mallory's broker skips its own checks and sends anyway (the recipient never relies on the sender's broker).
  const now = w.clock.now();
  const env = await signEnvelope({
    alp: "0.1",
    id: "01JC1111111111111111111111",
    thread: "01JC1111111111111111111112",
    from: { address: MALLORY, principal_id: "mallory-principal-0001" },
    to: { address: LEE },
    aud: IDS.example,
    scope: "alp.briefing/1",
    type: "request",
    body: { topic: "Please send the board deck", depth: "detailed" },
    grant: "none",
    labels: [],
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + 3600_000).toISOString(),
    origin_broker: IDS.outside,
    decision: { outcome: "allowed", redacted: [], policy_ids: [] },
  }, w.outside.keys);
  const res = await w.fed.transportFor(IDS.outside).deliver({ broker: IDS.example, inbox: "x" }, env);
  assert.equal(res.kind === "receipt" && res.receipt.status, "refused");
  assert.equal(res.kind === "receipt" && res.receipt.code, "not_accepted", "the recipient never says why (spec 6.8)");
  assert.equal((await w.example.inbox(w.lee.agent)).items.length, 0);
  const reqs = await w.example.listConnections(w.lee.human());
  assert.equal(reqs.length, 1);
  assert.equal(reqs[0]?.origin, "stranger_message");
  const n = w.notifier.sent.find((x) => x.principal === LEE && x.kind === "connection_request")!;
  assert.ok(n.link.startsWith(`${IDS.example}/web/connections/`), "links only to the broker's own page");
  assert.ok(!n.text.includes("board deck"), "notifications carry broker-generated text only");
  // Lee's agent can't approve it; only Lee, with a fresh sign-in.
  await assert.rejects(w.example.respondToConnection(w.lee.agent as never, { request: reqs[0]!.id, decision: "approve" }), /only the person/);
  w.clock.advance(600);
  await assert.rejects(w.example.respondToConnection({ kind: "human", principal: LEE, auth: { method: "reauth-dev", at: "2026-11-09T14:00:00.000Z" } }, { request: reqs[0]!.id, decision: "approve" }), /sign in again/);
});

test("Act 1.7 a alp.meeting commit needs both people's ratification (re-authentication on the web view) and is single-use", async () => {
  const w = await buildWorld();
  const meeting: ScopeTerms = {
    may: ["request", "propose", "counter", "accept", "commit", "inform", "decline", "ack"],
    disclose: ["/body/title", "/body/window", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms", "/body/event", "/body/as_of"],
    receive: ["/body/title", "/body/window", "/body/duration_minutes", "/body/timezone", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms", "/body/event", "/body/as_of"],
    commit: "ask_me",
    redaction: "reject",
  };
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.meeting/1": meeting } });
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.meeting/1": meeting } });
  const window = { start: "2026-11-10T15:00:00Z", end: "2026-11-10T18:00:00Z" };
  const slot = { start: "2026-11-10T16:00:00Z", end: "2026-11-10T16:30:00Z" };
  const req = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "request", body: { title: "Launch sync", duration_minutes: 30, window } }), "delivered");
  const thread = req.thread;
  const prop = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.meeting/1", type: "propose", thread, in_reply_to: req.envelope.id, body: { title: "Launch sync", duration_minutes: 30, slots: [slot], location: { kind: "video" } } }), "delivered");
  const terms = { title: "Launch sync", duration_minutes: 30, start: slot.start, end: slot.end, location: { kind: "video" } };
  const acc = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "accept", thread, in_reply_to: prop.envelope.id, body: { terms } }), "delivered");
  assert.ok(acc.envelope.terms_hash);
  // The side that received the accept asks its person once its answer is out.
  await w.example.settled();
  // The commit waits for both ratifications.
  const early = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.meeting/1", type: "commit", thread, in_reply_to: acc.envelope.id, body: { terms } }), "needs_ratification");
  assert.match(early.detail, /not ratified/);
  const anaReq = (await w.example.listRatifications(w.ana.human())).find((r) => r.state === "pending")!;
  const leeReq = (await w.example.listRatifications(w.lee.human())).find((r) => r.state === "pending")!;
  await assert.rejects(w.example.ratify(w.ana.agent as never, { request: anaReq.id, decision: "approve" }), /only the person/);
  const a = await w.example.ratify(w.ana.human(), { request: anaReq.id, decision: "approve" });
  assert.deepEqual(schemaErrors("ratification", a.record), []);
  assert.equal(a.record?.method, "reauth-dev");
  await w.example.ratify(w.lee.human(), { request: leeReq.id, decision: "approve" });
  const commit = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.meeting/1", type: "commit", thread, in_reply_to: acc.envelope.id, body: { terms } }), "delivered");
  assert.equal(commit.envelope.ratifications?.length, 2);
  assert.equal((await w.example.thread(w.ana.agent, thread)).thread.state, "committed");
  assert.equal((await w.example.thread(w.lee.agent, thread)).thread.state, "committed");
  const again = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "commit", thread, in_reply_to: acc.envelope.id, body: { terms } }), "rejected");
  assert.equal(again.code, "thread_state");
  // Changed terms don't match the agreed terms_hash.
  const ledger = await w.example.ledger(w.ana.human());
  assert.ok(ledger.some((e) => e.kind === "ratification"));
});

test("Act 1.8 a standing grant within limits ratifies on its own; outside the limits it asks the person", async () => {
  const w = await buildWorld();
  const base: ScopeTerms = {
    may: ["request", "propose", "accept", "commit", "ack", "decline"],
    disclose: ["/body/title", "/body/window", "/body/duration_minutes", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms"],
    receive: ["/body/title", "/body/window", "/body/duration_minutes", "/body/slots", "/body/location/kind", "/body/terms/title", "/body/terms"],
    commit: "within_limits",
    limits: { max_duration_minutes: 30, timezone: "UTC", weekdays: [1, 2, 3, 4, 5], earliest_minute: 540, latest_minute: 1080 },
    redaction: "reject",
  };
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.meeting/1": base } });
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.meeting/1": { ...base, commit: "ask_me" } } });
  const slot = { start: "2026-11-10T16:00:00Z", end: "2026-11-10T16:30:00Z" };
  const req = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "request", body: { title: "Sync", duration_minutes: 30, window: { start: "2026-11-10T15:00:00Z", end: "2026-11-10T18:00:00Z" } } }), "delivered");
  const prop = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.meeting/1", type: "propose", thread: req.thread, in_reply_to: req.envelope.id, body: { title: "Sync", duration_minutes: 30, slots: [slot], location: { kind: "video" } } }), "delivered");
  const terms = { title: "Sync", duration_minutes: 30, start: slot.start, end: slot.end, location: { kind: "video" } };
  expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.meeting/1", type: "accept", thread: req.thread, in_reply_to: prop.envelope.id, body: { terms } }), "delivered");
  await w.example.settled();
  assert.equal((await w.example.listRatifications(w.ana.human())).length, 0, "Ana's standing grant ratified for her");
  const anaThread = (await w.example.thread(w.ana.agent, req.thread)).thread;
  assert.match(String(anaThread.ratifications?.mine?.record.method), /^standing-grant:/);
  const leeView = (await w.example.thread(w.lee.agent, req.thread)).thread;
  assert.ok(leeView.ratifications?.theirs, "Lee's broker holds Ana's ratification");
  assert.equal((await w.example.listRatifications(w.lee.human())).filter((r) => r.state === "pending").length, 1, "Lee is asked");
  // Declining cancels the thread on both sides.
  const leeReq = (await w.example.listRatifications(w.lee.human()))[0]!;
  await w.example.ratify(w.lee.human(), { request: leeReq.id, decision: "decline" });
  assert.equal((await w.example.thread(w.ana.agent, req.thread)).thread.state, "cancelled");
  assert.equal((await w.example.thread(w.lee.agent, req.thread)).thread.state, "cancelled");
});

test("Act 1.9 ledgers and security events: chained, payloads apart, values never in events", async () => {
  const w = await buildWorld({ policy: (now) => examplePolicy(now, { retention: { store_values: "all", ledger_days: 30 } }) });
  expect(await sendBrief(w), "delivered");
  const entries = await w.example.ledger(w.ana.human());
  const sent = entries.find((e) => e.kind === "sent")!;
  assert.ok(sent.payload_hash);
  // The payload maps envelope-relative pointers to values (spec 11.4); `all` keeps typed values too.
  assert.deepEqual(await w.example.ledgerPayload(w.ana.human(), sent.seq), { "/body/topic": brief.topic, "/body/questions/0": brief.questions[0], "/body/depth": brief.depth });
  // Erasing a payload (crypto-shredding stand-in) keeps the chain valid.
  const anaId = (await w.example.getPrincipal(ANA))!.principal_id;
  await w.example.store.eraseLedgerPayload(anaId, sent.seq);
  assert.equal((await w.example.verifyLedger(w.ana.human())).ok, true);
  expect(await sendBrief(w, { topic: "4111 1111 1111 1111", depth: "headline" }), "rejected");
  for (const e of w.events.events) {
    assert.deepEqual(schemaErrors("securityEvent", e), []);
    assert.ok(!JSON.stringify(e).includes("4111"), "no values in security events");
  }
});

// ---------------------------------------------------------------------------------------------
// Act 2: across organizations (federation)

test("Act 2.1 Ana (example.org) and Pat (partner.example) connect through their people, then exchange a briefing with receipts", async () => {
  const w = await buildWorld();
  const direct = expect(await sendBrief(w, brief, { to: PAT }), "rejected");
  assert.equal(direct.code, "no_relationship");
  const req = await w.example.requestConnection(w.ana.agent, { to: PAT, scopes: ["alp.briefing/1"], purpose: "briefing" });
  assert.equal(req.status, "requested");
  const incoming = (await w.partner.listConnections(w.pat.human()))[0]!;
  assert.equal(incoming.state, "pending");
  await w.partner.respondToConnection(w.pat.human(), { request: incoming.id, decision: "approve", terms: { "alp.briefing/1": briefTerms } });
  // The agent filed the request, so Ana's grant is pending until Ana seals it herself.
  const pending = (await w.example.listGrants(w.ana.human())).find((g) => g.counterparty === PAT)!;
  assert.equal(pending.status, "pending");
  expect(await sendBrief(w, brief, { to: PAT }), "rejected");
  await w.example.setGrant(w.ana.human(), { counterparty: PAT, scopes: { "alp.briefing/1": briefTerms } });
  const sent = expect(await sendBrief(w, brief, { to: PAT }), "delivered");
  assert.equal(sent.envelope.aud, IDS.partner);
  const doc = await w.resolver.domainDocument("partner.example");
  const keys = await pinnedFederationKeys(await w.resolver.jwks(homeBroker(doc, PAT)!.jwks_uri), homeBroker(doc, PAT)!);
  assert.equal((await verifyReceipt(sent.receipt, keys)).ok, true);
  const item = (await w.partner.inbox(w.pat.agent)).items[0]!;
  assert.equal(item.verified.sender_broker, IDS.example);
  const anaEntries = await w.example.ledger(w.ana.human());
  const s = anaEntries.filter((e) => e.kind === "sent").at(-1)!;
  const rc = anaEntries.find((e) => e.kind === "receipt" && e.envelope_id === s.envelope_id)!;
  const r = (await w.partner.ledger(w.pat.human())).find((e) => e.kind === "received")!;
  assert.deepEqual(crossCheckEntries(s, rc, r, objectHash(sent.receipt)), []);
  assert.equal(s.counterparty_broker, IDS.partner);
  assert.equal(r.counterparty_broker, IDS.example);
});

test("Act 2.1b a connection request the person files with a fresh sign-in activates on approval", async () => {
  const w = await buildWorld();
  const req = await w.example.requestConnection(w.ana.human(), { to: PAT, scopes: ["alp.briefing/1"], purpose: "briefing", terms: { "alp.briefing/1": briefTerms } });
  assert.equal(req.status, "requested");
  const incoming = (await w.partner.listConnections(w.pat.human()))[0]!;
  await w.partner.respondToConnection(w.pat.human(), { request: incoming.id, decision: "approve", terms: { "alp.briefing/1": briefTerms } });
  assert.equal((await w.example.listGrants(w.ana.human())).find((g) => g.counterparty === PAT)?.status, "active");
  expect(await sendBrief(w, brief, { to: PAT }), "delivered");
});

test("Act 2.2 a rogue broker claiming ana@example.org is refused: it is not Ana's home broker", async () => {
  const w = await buildWorld();
  await connectAnaPat(w, { "alp.briefing/1": briefTerms });
  // The rogue broker's own "Ana" has a grant for Pat on the rogue broker, so it signs and sends.
  await w.rogue.setGrant({ kind: "human", principal: ANA, auth: { method: "reauth-dev", at: w.clock.now().toISOString() } }, { counterparty: PAT, scopes: { "alp.briefing/1": briefTerms } });
  const r = expect(await w.rogue.send({ kind: "delegate", principal: ANA, delegate: `${ANA}/muse`, client_id: CLIENTS.connector }, { to: PAT, scope: "alp.briefing/1", type: "request", body: brief }), "undeliverable");
  assert.equal(r.code, "broker_not_authorized");
  assert.equal((await w.partner.inbox(w.pat.agent)).items.length, 0);
  assert.ok(w.events.events.some((e) => e.detail.event === "broker_not_authorized"));
  // Claiming to be example.org's broker while signing with another key fails the pinned-key check.
  const forgedKeys = await KeyRing.generate(w.clock.now());
  const now = w.clock.now();
  const u: UnsignedEnvelope = {
    alp: "0.1", id: "01JC2222222222222222222222", thread: "01JC2222222222222222222223",
    from: { address: ANA, principal_id: "forged-principal-0001" }, to: { address: PAT }, aud: IDS.partner,
    scope: "alp.briefing/1", type: "request", body: brief, grant: "x", labels: [],
    created_at: now.toISOString(), expires_at: new Date(now.getTime() + 3600_000).toISOString(),
    origin_broker: IDS.example, decision: { outcome: "allowed", redacted: [], policy_ids: [] },
  };
  const res = await w.fed.transportFor(IDS.rogue).deliver({ broker: IDS.partner, inbox: "x" }, await signEnvelope(u, forgedKeys));
  assert.equal(res.kind === "refused" && res.code, "bad_signature");
});

test("Act 2.3 a replayed envelope is refused, as are expired, misaddressed and tampered ones", async () => {
  const w = await buildWorld();
  await connectAnaPat(w, { "alp.briefing/1": briefTerms });
  const sent = expect(await sendBrief(w, brief, { to: PAT }), "delivered");
  const target = { broker: IDS.partner, inbox: "x" };
  const t = w.fed.transportFor(IDS.example);
  // A duplicate of an accepted envelope (an honest retry, or a captured copy) gets the original receipt and changes nothing (spec 10.3).
  const duplicate = await t.deliver(target, sent.envelope);
  assert.equal(duplicate.kind === "receipt" && duplicate.receipt.id, sent.receipt.id);
  assert.equal((await w.partner.inbox(w.pat.agent)).items.length, 1);
  // The same id with other content is a replay, and its refusal does not replace the original receipt.
  const replay = await t.deliver(target, await signEnvelope({ ...sent.envelope, body: { ...brief, depth: "detailed" } }, w.example.keys));
  assert.equal(replay.kind === "receipt" && replay.receipt.code, "replay");
  assert.equal((await w.partner.inbox(w.pat.agent)).items.length, 1);
  const again = await t.deliver(target, sent.envelope);
  assert.equal(again.kind === "receipt" && again.receipt.id, sent.receipt.id);
  const tampered: Envelope = { ...sent.envelope, id: "01JC3333333333333333333333", body: { ...brief, depth: "detailed" } };
  const r1 = await t.deliver(target, tampered);
  assert.equal(r1.kind === "refused" && r1.code, "bad_signature");
  const misaddressed = await signEnvelope({ ...sent.envelope, id: "01JC4444444444444444444444", aud: IDS.outside }, w.example.keys);
  const r2 = await t.deliver(target, misaddressed);
  // After the signature verifies, refusals are signed receipts (spec 12.2.3); step 3 is the audience.
  assert.equal(r2.kind === "receipt" && r2.receipt.code, "wrong_audience");
  w.clock.advance(4 * 24 * 3600);
  const r3 = await t.deliver(target, await signEnvelope({ ...sent.envelope, id: "01JC5555555555555555555555" }, w.example.keys));
  assert.equal(r3.kind === "receipt" && r3.receipt.code, "expired");
});

test("Act 2.4 a broker removed from its domain document is refused after the refresh", async () => {
  const w = await buildWorld();
  await connectAnaPat(w, { "alp.briefing/1": briefTerms });
  expect(await sendBrief(w, brief, { to: PAT }), "delivered");
  // example.org moves its people to another broker: broker.example.org is no longer the home broker.
  const other = await KeyRing.generate(w.clock.now());
  w.publish("example.org", w.example, {
    brokers: [{ id: "https://new-broker.example.org", inbox: "https://new-broker.example.org/federation/inbox", jwks_uri: "https://new-broker.example.org/.well-known/jwks.json", jkt: other.jkts(), principals: "*" }],
  });
  const r = expect(await sendBrief(w, brief, { to: PAT }), "undeliverable");
  assert.equal(r.code, "broker_not_authorized");
});

test("Act 2.5 revocation takes effect at once at the revoking broker and stops the other side's sends", async () => {
  const w = await buildWorld();
  await connectAnaPat(w, { "alp.briefing/1": briefTerms });
  expect(await sendBrief(w, brief, { to: PAT }), "delivered");
  await w.partner.revoke(w.pat.human(), { counterparty: ANA });
  const r = expect(await sendBrief(w, brief, { to: PAT }), "rejected");
  assert.equal(r.code, "no_relationship");
  assert.match(r.reasons[0]?.detail ?? "", /revoked/);
});

test("Act 2.6 key rotation: the next key is pinned ahead of time, so the other side keeps verifying", async () => {
  const w = await buildWorld();
  await connectAnaPat(w, { "alp.briefing/1": briefTerms });
  const pinsBefore = w.example.keys.jkts();
  await w.example.rotateKeys({ kind: "admin", operator: "test" });
  assert.ok(pinsBefore.includes(w.example.keys.kid), "the new active key was pinned before rotation");
  w.publish("example.org", w.example);
  expect(await sendBrief(w, brief, { to: PAT }), "delivered");
  assert.ok(w.events.events.some((e) => e.detail.event === "key_rotated"));
});

// ---------------------------------------------------------------------------------------------
// Act 3: delivery constraints; Act 4: human fallback

test("Act 3 a reply carrying confidential fields is held when the recipient's only agent is consumer-class", async () => {
  // A grant can only narrow an organization default (spec 6.6.1), so the default names the free-text field here.
  const w = await buildWorld({ policy: (now) => {
    const p = examplePolicy(now);
    p.default_relationships![0]!.scopes["alp.briefing/1"]!.forward.fields.push("/body/context/project");
    return p;
  } });
  // Lee's only agent is a consumer-class client; the org requires business class for confidential.*.
  await w.example.revokeDelegate(`${LEE}/dot`);
  await w.example.registerDelegate({ principal: LEE, label: "phone", client_id: CLIENTS.consumer });
  const leePhone = { kind: "delegate" as const, principal: LEE, delegate: `${LEE}/phone`, client_id: CLIENTS.consumer };
  const terms: ScopeTerms = { may: ["request"], disclose: ["/body/topic", "/body/depth", "/body/context/project"], receive: ["/body/topic", "/body/depth", "/body/context/project"], commit: "ask_me", redaction: "reject" };
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.briefing/1": terms } });
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.briefing/1": terms } });
  const sent = expect(await sendBrief(w, { topic: "Atlas", depth: "headline", context: { project: "Atlas" } }), "delivered");
  assert.equal(sent.envelope.constraints?.deliver_to?.min_class, "business");
  assert.equal((await w.example.inbox(leePhone)).items.length, 0, "the consumer agent never sees it");
  const forPerson = await w.example.messagesForPerson(w.lee.human());
  assert.equal(forPerson.items[0]?.status, "held");
  // The person is told after Ana's broker has its answer (spec 6.7).
  await w.example.settled();
  assert.ok(w.notifier.sent.some((n) => n.principal === LEE && n.kind === "message_held"));
});

test("Act 4 human fallback: the notification only notifies; the person acts on the broker's page", async () => {
  const w = await buildWorld();
  await w.example.registerPrincipal({ address: LEE, identity: { iss: "https://dev-idp.invalid", sub: "dev-lee" }, human_fallback: true });
  expect(await sendBrief(w), "delivered");
  await w.example.settled();
  const n = w.notifier.sent.find((x) => x.principal === LEE && x.kind === "message_waiting")!;
  assert.equal(n.channel, "email");
  assert.ok(n.link.startsWith(`${IDS.example}/web/messages/`));
  assert.ok(!/approve|decline|reply/i.test(n.link));
  assert.equal((await w.example.messagesForPerson(w.lee.human())).items.length, 1);
});

// ---------------------------------------------------------------------------------------------
// More rules

test("narrowing an org default: Lee limits Ana to availability; refusals never name Lee's rules", async () => {
  const w = await buildWorld();
  const avail: ScopeTerms = { may: ["request", "inform"], disclose: ["/body/free", "/body/as_of"], receive: ["/body/window", "/body/duration_minutes"], commit: "ask_me", redaction: "reject" };
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.availability/1": avail } });
  const refused = expect(await sendBrief(w), "refused");
  assert.equal(refused.code, "not_accepted", "a narrowed-away scope looks like any refusal");
  expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.availability/1", type: "request", body: { window: { start: "2026-11-10T15:00:00Z", end: "2026-11-10T18:00:00Z" }, duration_minutes: 30 } }), "delivered");
  const tz = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.availability/1", type: "request", body: { window: { start: "2026-11-10T15:00:00Z", end: "2026-11-10T18:00:00Z" }, duration_minutes: 30, timezone: "UTC" } }), "refused");
  assert.equal(tz.code, "not_accepted", "only a generic code crosses back");
});

test("spec 6.4: claim-based groups (an identity provider's app roles) match both people a broker signed in, in default relationships and classification rules; claims recorded elsewhere don't count", async () => {
  const IDP = "https://login.microsoftonline.com/dddddddd-0000-4000-8000-000000000004/v2.0";
  const OTHER_IDP = "https://idp.other.example";
  const roles = (issuer: string, ...values: string[]) => values.map((value) => ({ issuer, name: "roles", value }));
  const role = (value: string) => ({ claim: { issuer: IDP, name: "roles", value } });
  const w = await buildWorld({
    policy: (now) =>
      examplePolicy(now, {
        // The example policy's financial-stays-in-finance rule allows group:finance, here an app role.
        groups: { finance: role("Finance"), analysts: role("Analyst"), leaders: role("Leader") },
        default_relationships: [
          {
            id: "analysts-leaders",
            from: ["group:analysts"],
            to: ["group:leaders"],
            scopes: {
              "alp.briefing/1": {
                forward: { may: ["request"], fields: ["/body/topic", "/body/questions/*", "/body/depth", "/body/context"] },
                reverse: { may: ["inform"], fields: ["/body/points/*", "/body/as_of"] },
              },
            },
          },
        ],
      }),
  });
  // People the broker signed in through the identity provider: their roles are recorded under its issuer (oidc.ts).
  const person = async (local: string, iss: string, claims: { issuer: string; name: string; value: string }[]) => {
    const address = `alp:${local}@example.org`;
    const p = await w.example.registerPrincipal({ address, identity: { iss, sub: `${local}-object-id` }, claims, contact: { email: `${local}@example.org` } });
    const d = await w.example.registerDelegate({ principal: address, label: "claude", kind: "bridged", client_id: CLIENTS.connector });
    return { address, principal_id: p.principal_id, agent: { kind: "delegate" as const, principal: address, delegate: d.id, client_id: CLIENTS.connector } };
  };
  const kim = await person("kim", IDP, roles(IDP, "Analyst"));
  const lou = await person("lou", IDP, roles(IDP, "Leader"));
  const rio = await person("rio", IDP, roles(IDP, "Leader", "Finance"));
  const sam = await person("sam", IDP, []);
  const max = await person("max", OTHER_IDP, roles(OTHER_IDP, "Leader"));
  const ask = (from: { agent: DelegateCaller }, to: { address: string }, body: JsonObject = brief) => w.example.send(from.agent, { to: to.address, scope: "alp.briefing/1", type: "request", body });

  // The analyst's agent reaches a leader under the default: the sender's role at the sender's side, and both roles
  // again at the recipient's side.
  const sent = expect(await ask(kim, lou), "delivered");
  assert.equal(sent.envelope.grant, "default:analysts-leaders");
  assert.equal((await w.example.inbox(lou.agent)).items.length, 1);
  // The leader's agent answers under the reverse terms.
  const reply = expect(await w.example.send(lou.agent, { to: kim.address, scope: "alp.briefing/1", type: "inform", thread: sent.thread, in_reply_to: sent.envelope.id, body: { points: ["Nothing is blocked."], as_of: "2026-11-09T14:00:00Z" } }), "delivered");
  assert.equal(reply.envelope.grant, "default:analysts-leaders");
  // Without the role, or with a role of that name from another issuer, there is no relationship.
  assert.equal(expect(await ask(sam, lou), "rejected").code, "no_relationship");
  assert.equal(expect(await ask(kim, sam), "rejected").code, "no_relationship");
  assert.equal(expect(await ask(kim, max), "rejected").code, "no_relationship");
  // A classification rule's allow list by app role: the financial figure goes only to the leader in finance.
  const budget = { topic: "Budget", depth: "headline", context: { amount: { value: 1200000, currency: "USD" } } };
  const toLou = expect(await ask(kim, lou, budget), "rejected");
  assert.equal(toLou.code, "org_policy");
  assert.ok(toLou.reasons.every((x) => x.rule === "financial-stays-in-finance"));
  expect(await ask(kim, rio, budget), "delivered");

  // Roles another broker records count for nothing here (fail closed): Pat's broker lists him as an analyst of the same
  // issuer, and his message to Lou is a stranger's.
  await w.partner.registerPrincipal({ address: PAT, identity: { iss: DEV_ISSUER, sub: "dev-pat" }, claims: roles(IDP, "Analyst") });
  await w.partner.setGrant(w.pat.human(), { counterparty: lou.address, scopes: { "alp.briefing/1": briefTerms } });
  const fromPat = expect(await w.partner.send(w.pat.agent, { to: lou.address, scope: "alp.briefing/1", type: "request", body: brief }), "refused");
  assert.equal(fromPat.code, "not_accepted");
  assert.equal((await w.example.inbox(lou.agent)).items.length, 1, "only Kim's request reached Lou's agent");
  const louHuman: HumanCaller = { kind: "human", principal: lou.address, auth: { method: "reauth-dev", at: w.clock.now().toISOString() } };
  assert.deepEqual((await w.example.listConnections(louHuman)).map((c) => [c.counterparty, c.origin]), [[PAT, "stranger_message"]]);
});

test("redaction before signing: a grant in redact mode drops fields and the decision says so", async () => {
  const w = await buildWorld();
  const terms: ScopeTerms = { ...briefTerms, disclose: ["/body/topic", "/body/depth"], redaction: "redact" };
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.briefing/1": terms } });
  const r = expect(await sendBrief(w, { topic: "T", depth: "summary", due_by: "2026-11-12T00:00:00Z" }), "delivered");
  assert.equal(r.envelope.decision.outcome, "redacted");
  assert.deepEqual(r.envelope.decision.redacted, ["/body/due_by"]);
  assert.deepEqual(r.envelope.body, { topic: "T", depth: "summary" });
});

test("kill switches in the private org policy take effect at once", async () => {
  const w = await buildWorld();
  expect(await sendBrief(w), "delivered");
  await w.example.setOrgPolicy({ kind: "admin", operator: "it" }, examplePolicy(w.clock.now(), { serial: 2, blocked: { scopes: ["alp.briefing/1"] } }));
  const r = expect(await sendBrief(w), "rejected");
  assert.equal(r.code, "blocked");
  await assert.rejects(w.example.setOrgPolicy({ kind: "admin", operator: "it" }, examplePolicy(w.clock.now(), { serial: 2 })), /higher serial/);
  assert.ok(w.events.events.some((e) => e.detail.event === "policy_changed"));
});

test("rate limits are enforced by the recipient's broker on its own", async () => {
  const w = await buildWorld();
  // Ana's own terms allow 100 an hour; Lee's narrowing grant allows 2 (a grant takes the stricter of its own and the default's).
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.briefing/1": briefTerms }, rate_limit: { count: 100, per_seconds: 3600 } });
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefTerms, receive: briefTerms.disclose } }, rate_limit: { count: 2, per_seconds: 3600 } });
  expect(await sendBrief(w), "delivered");
  expect(await sendBrief(w), "delivered");
  assert.equal(expect(await sendBrief(w), "refused").code, "rate_limited");
});

test("reply rules come from the scope: an inform must answer a request, and a reply must name a message in its thread", async () => {
  const w = await buildWorld();
  const sent = expect(await sendBrief(w), "delivered");
  const bad = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "decline", thread: sent.thread, in_reply_to: "01JC9999999999999999999999", body: { of: sent.envelope.id, reason: "not_available" } }), "rejected");
  assert.equal(bad.code, "thread_state");
  const answer = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "inform", thread: sent.thread, in_reply_to: sent.envelope.id, body: { points: ["Two blockers left."], as_of: "2026-11-09T14:00:00Z" } }), "delivered");
  assert.ok(answer.envelope.in_reply_to_hash);
  const done = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "ack", thread: sent.thread, in_reply_to: answer.envelope.id, body: { of: answer.envelope.id, status: "completed" } }), "delivered");
  assert.equal(done.envelope.type, "ack");
  assert.equal((await w.example.thread(w.ana.agent, sent.thread)).thread.state, "done");
});

test("inbound content is shaped for agents: markup stripped, URLs defanged, verified fields apart", async () => {
  const w = await buildWorld();
  const sent = expect(await sendBrief(w), "delivered");
  expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "inform", thread: sent.thread, in_reply_to: sent.envelope.id, body: { points: ["<b>See</b> https://evil.example/x and [docs](https://docs.example)"], as_of: "2026-11-09T14:00:00Z" } }), "delivered");
  const item = (await w.example.inbox(w.ana.agent)).items[0]!;
  const text = String((item.content.body["points"] as string[])[0]);
  assert.ok(!text.includes("<b>"));
  assert.ok(!text.includes("https://"));
  assert.match(text, /evil\[\.\]example/);
  assert.equal(item.verified.type, "inform");
  assert.equal((await verifyAnyEnvelope(item.envelope, w.example.jwks())).ok, true, "the signed original is kept for verification");
  assert.equal(objectHash(item.envelope), item.receipt?.envelope_hash);
});

test("address reassignment creates a new principal; the old one is retired", async () => {
  const w = await buildWorld();
  const old = (await w.example.getPrincipal(LEE))!;
  const fresh = await w.example.registerPrincipal({ address: LEE, identity: { iss: "https://dev-idp.invalid", sub: "dev-someone-else" }, display_name: "New Lee" });
  assert.notEqual(fresh.principal_id, old.principal_id);
  assert.equal((await w.example.store.getPrincipalById(old.principal_id))?.status, "retired");
  await assert.rejects(w.example.inbox(w.lee.agent), /not an active delegate/);
});

test("hold for review (spec 6.12): the message waits for the person; on approval it is evaluated again and sent", async () => {
  const w = await buildWorld();
  // Lee narrows the default for Ana and asks to review every briefing reply before it leaves.
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefTerms, hold_for_review: true } } });
  const req = expect(await sendBrief(w), "delivered");
  const reply = { points: ["Two contracts are unsigned."], as_of: "2026-11-09T13:00:00Z" };
  const held = await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "inform", thread: req.thread, in_reply_to: req.envelope.id, body: reply });
  assert.equal(held.status, "held_for_review");
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 0, "nothing left");
  assert.ok(w.notifier.sent.some((n) => n.principal === LEE && n.kind === "message_held" && n.link.includes("/web/held/")));
  const pending = (await w.example.listHeld(w.lee.human())).filter((h) => h.state === "pending");
  assert.equal(pending.length, 1);
  await assert.rejects(w.example.reviewHeld({ kind: "human", principal: LEE }, { held: pending[0]!.id, decision: "send" }), /sign in again/);
  const sent = await w.example.reviewHeld(w.lee.human(), { held: pending[0]!.id, decision: "send" });
  assert.equal(sent.status, "delivered");
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 1);
  assert.equal((await w.example.listHeld(w.lee.human()))[0]?.state, "sent");
  // A second held message, discarded: nothing leaves.
  const again = await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "inform", thread: req.thread, in_reply_to: req.envelope.id, body: reply });
  assert.equal(again.status, "held_for_review");
  const id = again.status === "held_for_review" ? again.held : "";
  assert.deepEqual(await w.example.reviewHeld(w.lee.human(), { held: id, decision: "discard" }), { status: "discarded", held: id });
  assert.equal((await w.example.inbox(w.ana.agent, { include_acked: true })).items.length, 1);
});

test("hold for review: a held request opens the thread it was given when the person approves it (spec 6.12, 9.2)", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefTerms, hold_for_review: true } } });
  const held = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review");
  assert.equal((await w.example.store.getHeldOutbound(LEE, held.held))?.opens_thread, true);
  await assert.rejects(w.example.thread(w.lee.agent, held.thread), /no such thread/, "the thread id is only reserved until the message is sent");
  const sent = await w.example.reviewHeld(w.lee.human(), { held: held.held, decision: "send" });
  assert.equal(sent.status, "delivered", JSON.stringify(sent));
  if (sent.status !== "delivered") return;
  assert.equal(sent.thread, held.thread);
  const item = (await w.example.inbox(w.ana.agent)).items[0];
  assert.ok(item, "Ana's agent receives it");
  assert.equal(item.verified.thread, held.thread, "in the thread Lee's agent was given");
  assert.deepEqual(item.content.body, brief);
  const rec = (await w.example.listHeld(w.lee.human())).find((h) => h.id === held.held);
  assert.equal(rec?.state, "sent");
  assert.equal(rec?.envelope_id, sent.envelope.id);
  const ledger = await w.example.ledger(w.lee.human());
  assert.deepEqual(ledger.filter((e) => e.ref === held.held || e.envelope_id === sent.envelope.id).map((e) => `${e.kind}:${e.outcome}`), ["held:held", "sent:allowed", "receipt:accepted", "released:accepted"]);
  // Both agents go on in that thread.
  expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "inform", thread: held.thread, in_reply_to: item.envelope.id, body: { points: ["On track."], as_of: "2026-11-09T13:00:00Z" } }), "delivered");
  assert.equal((await w.example.thread(w.lee.agent, held.thread)).messages.length, 2);

  // A record written before `opens_thread` existed releases the same way.
  const older = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review");
  const stored = await w.example.store.getHeldOutbound(LEE, older.held);
  assert.ok(stored);
  delete stored.opens_thread;
  await w.example.store.putHeldOutbound(stored);
  const again = await w.example.reviewHeld(w.lee.human(), { held: older.held, decision: "send" });
  assert.equal(again.status === "delivered" && again.thread, older.thread, JSON.stringify(again));
});

test("hold for review: approving a message the rules no longer allow sends nothing, and the page and ledger say so", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefTerms, hold_for_review: true } } });
  const held = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review");
  await w.example.revoke(w.lee.human(), { counterparty: ANA });
  const r = await w.example.reviewHeld(w.lee.human(), { held: held.held, decision: "send" });
  assert.equal(r.status === "rejected" && r.code, "no_relationship", JSON.stringify(r));
  const rec = (await w.example.listHeld(w.lee.human())).find((h) => h.id === held.held);
  assert.equal(rec?.state, "refused", "never reported as sent");
  assert.deepEqual(rec?.result, { status: "rejected", code: "no_relationship" });
  const ledger = await w.example.ledger(w.lee.human());
  assert.ok(ledger.some((e) => e.kind === "refused_outbound" && e.code === "no_relationship" && e.thread === held.thread));
  const released = ledger.find((e) => e.kind === "released" && e.ref === held.held);
  assert.equal(released?.outcome, "refused");
  assert.equal(released?.code, "no_relationship");
  for (const e of ledger) assert.deepEqual(schemaErrors("ledgerEntry", e), [], `ledger entry ${e.kind}`);
  assert.equal((await w.example.inbox(w.ana.agent, { include_acked: true })).items.length, 0, "nothing reached Ana");
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: held.held, decision: "send" }), /already refused/);

  // An address no broker serves: nothing is signed, so neither the record nor the ledger names an envelope.
  const kim = "alp:kim@nowhere.example";
  await w.example.setGrant(w.lee.human(), { counterparty: kim, scopes: { "alp.briefing/1": { ...briefTerms, hold_for_review: true } } });
  const nowhere = expect(await w.example.send(w.lee.agent, { to: kim, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review");
  const lost = await w.example.reviewHeld(w.lee.human(), { held: nowhere.held, decision: "send" });
  assert.equal(lost.status, "undeliverable", JSON.stringify(lost));
  assert.equal(lost.status === "undeliverable" && lost.envelope_id, undefined, "no envelope was signed");
  const lostRec = (await w.example.listHeld(w.lee.human())).find((h) => h.id === nowhere.held);
  assert.equal(lostRec?.state, "refused");
  assert.deepEqual(lostRec?.result, { status: "undeliverable", code: "unknown_recipient" });
  assert.equal(lostRec?.envelope_id, undefined);
  const after = await w.example.ledger(w.lee.human());
  const lostEntry = after.find((e) => e.kind === "released" && e.ref === nowhere.held);
  assert.equal(lostEntry?.outcome, "refused");
  assert.equal(lostEntry?.envelope_id, undefined, "a released entry names only an envelope a sent entry names");
  assert.equal(after.some((e) => e.kind === "sent" && e.counterparty === kim), false);
});

test("hold for review: of two decisions on one held message at once, exactly one acts", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefTerms, hold_for_review: true } } });
  const hold = async () => expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review").held;
  // Two approvals (a double submit): one sends it; the other is refused, and never overwrites what the first recorded.
  const first = await hold();
  const both = await Promise.allSettled([w.example.reviewHeld(w.lee.human(), { held: first, decision: "send" }), w.example.reviewHeld(w.lee.human(), { held: first, decision: "send" })]);
  assert.equal(both.filter((r) => r.status === "fulfilled" && r.value.status === "delivered").length, 1, JSON.stringify(both));
  const refused = both.find((r) => r.status === "rejected");
  assert.match(String(refused?.status === "rejected" ? refused.reason : ""), /already decided|being sent/);
  assert.equal((await w.example.listHeld(w.lee.human())).find((h) => h.id === first)?.state, "sent");
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 1, "Ana's agent got it once");
  assert.equal((await w.example.ledger(w.lee.human())).filter((e) => e.kind === "released" && e.ref === first).length, 1);
  // An approval and a discard at once: one of them.
  const second = await hold();
  const mixed = await Promise.allSettled([w.example.reviewHeld(w.lee.human(), { held: second, decision: "send" }), w.example.reviewHeld(w.lee.human(), { held: second, decision: "discard" })]);
  assert.equal(mixed.filter((r) => r.status === "fulfilled").length, 1, JSON.stringify(mixed));
  const state = (await w.example.listHeld(w.lee.human())).find((h) => h.id === second)?.state;
  assert.equal((await w.example.inbox(w.ana.agent, { include_acked: true })).items.length, state === "sent" ? 2 : 1);
  assert.equal((await w.example.ledger(w.lee.human())).filter((e) => e.kind === "released" && e.ref === second).length, 1);
});

test("hold for review: an approval that fails on the way never leaves the message stuck being sent", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefTerms, hold_for_review: true } } });
  // The store drops its connection once, while it writes the next ledger entry of this kind (as a database can).
  const store = w.example.store;
  const append = store.appendLedger.bind(store);
  let failOn: string | undefined;
  store.appendLedger = (principalId, build) => append(principalId, (head) => {
    const out = build(head);
    if (out.entry.kind === failOn) {
      failOn = undefined;
      throw new Error("connection reset");
    }
    return out;
  });
  const stateOf = async (id: string) => (await w.example.listHeld(w.lee.human())).find((h) => h.id === id);
  const lee = () => w.example.ledger(w.lee.human());

  // Before the envelope's `sent` entry is written nothing has left: the message waits for Lee again, and he can send it.
  const first = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review").held;
  failOn = "sent";
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: first, decision: "send" }), /connection reset/);
  assert.equal((await stateOf(first))?.state, "pending");
  assert.equal((await stateOf(first))?.decided_at, undefined);
  assert.equal((await lee()).some((e) => e.kind === "sent" || (e.kind === "released" && e.ref === first)), false);
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 0, "nothing reached Ana");
  assert.equal((await w.example.reviewHeld(w.lee.human(), { held: first, decision: "send" })).status, "delivered");
  assert.equal((await stateOf(first))?.state, "sent");
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 1);

  // After it the envelope may have arrived (here it did): delivery failed, may still have arrived; never sent twice.
  const second = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review").held;
  failOn = "receipt";
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: second, decision: "send" }), /connection reset/);
  const rec = await stateOf(second);
  const sent = (await lee()).filter((e) => e.kind === "sent").at(-1);
  assert.equal(rec?.state, "refused");
  assert.deepEqual(rec?.result, { status: "undeliverable", code: "internal" });
  assert.ok(sent?.envelope_id);
  assert.equal(rec?.envelope_id, sent.envelope_id, "the envelope its `sent` entry names");
  const released = (await lee()).filter((e) => e.kind === "released" && e.ref === second);
  assert.deepEqual(released.map((e) => [e.outcome, e.code, e.envelope_id]), [["refused", "internal", sent.envelope_id]]);
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 2, "it did reach Ana");
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: second, decision: "send" }), /already refused/);
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: second, decision: "discard" }), /already refused/);
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 2, "and only once");
});

test("hold for review: when only recording what sending answered fails, the held message still ends with that answer", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefTerms, hold_for_review: true } } });
  // The store drops its connection once: while it writes the held record's outcome, or the next ledger entry of a kind.
  const store = w.example.store;
  const putHeld = store.putHeldOutbound.bind(store);
  let failPut = false;
  store.putHeldOutbound = async (rec) => {
    if (failPut && rec.state !== "pending") {
      failPut = false;
      throw new Error("connection reset");
    }
    return putHeld(rec);
  };
  const append = store.appendLedger.bind(store);
  let failOn: string | undefined;
  store.appendLedger = (principalId, build) => append(principalId, (head) => {
    const out = build(head);
    if (out.entry.kind === failOn) {
      failOn = undefined;
      throw new Error("connection reset");
    }
    return out;
  });
  const hold = async () => expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review").held;
  const stateOf = async (id: string) => (await w.example.listHeld(w.lee.human())).find((h) => h.id === id);
  const released = async (id: string) => (await w.example.ledger(w.lee.human())).filter((e) => e.kind === "released" && e.ref === id).map((e) => [e.outcome, e.code, e.envelope_id]);
  const lastSent = async () => (await w.example.ledger(w.lee.human())).filter((e) => e.kind === "sent").at(-1)?.envelope_id;

  // Delivered, and the record's write fails: the record says sent, as the receipt does, never "delivery failed".
  const first = await hold();
  failPut = true;
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: first, decision: "send" }), /connection reset/);
  const delivered = await lastSent();
  assert.ok(delivered);
  assert.equal((await stateOf(first))?.state, "sent");
  assert.equal((await stateOf(first))?.result, undefined);
  assert.equal((await stateOf(first))?.envelope_id, delivered);
  assert.deepEqual(await released(first), [["accepted", undefined, delivered]]);
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 1);

  // Delivered and recorded, and the `released` entry fails: it is written all the same.
  const second = await hold();
  failOn = "released";
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: second, decision: "send" }), /connection reset/);
  assert.equal((await stateOf(second))?.state, "sent");
  assert.deepEqual(await released(second), [["accepted", undefined, await lastSent()]]);

  // Refused before anything was signed (the rules changed), and the record's write fails: refused with that code, not
  // waiting for Lee again.
  const third = await hold();
  await w.example.revoke(w.lee.human(), { counterparty: ANA });
  failPut = true;
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: third, decision: "send" }), /connection reset/);
  assert.equal((await stateOf(third))?.state, "refused");
  assert.deepEqual((await stateOf(third))?.result, { status: "rejected", code: "no_relationship" });
  assert.deepEqual(await released(third), [["refused", "no_relationship", undefined]]);
  assert.equal((await w.example.inbox(w.ana.agent, { include_acked: true })).items.length, 2, "each was sent at most once");
});

test("hold for review: a write that lands but reports a failure still leaves one released entry, with what sending answered", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": { ...briefTerms, hold_for_review: true } } });
  // The database commits a write, then the connection drops before it says so: the store reports a failure once, for
  // the held record's outcome or for the next ledger entry of a kind, after writing it.
  const store = w.example.store;
  const putHeld = store.putHeldOutbound.bind(store);
  let landPut = false;
  store.putHeldOutbound = async (rec) => {
    await putHeld(rec);
    if (landPut && rec.state !== "pending") {
      landPut = false;
      throw new Error("connection reset");
    }
  };
  const append = store.appendLedger.bind(store);
  let landOn: string | undefined;
  store.appendLedger = async (principalId, build) => {
    const entry = await append(principalId, build);
    if (entry.kind === landOn) {
      landOn = undefined;
      throw new Error("connection reset");
    }
    return entry;
  };
  const hold = async () => expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "held_for_review").held;
  const stateOf = async (id: string) => (await w.example.listHeld(w.lee.human())).find((h) => h.id === id);
  const released = async (id: string) => (await w.example.ledger(w.lee.human())).filter((e) => e.kind === "released" && e.ref === id).map((e) => [e.outcome, e.code, e.envelope_id]);
  const lastSent = async () => (await w.example.ledger(w.lee.human())).filter((e) => e.kind === "sent").at(-1)?.envelope_id;

  // The `released` entry is written, and its append reports a failure: it isn't written again.
  const first = await hold();
  landOn = "released";
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: first, decision: "send" }), /connection reset/);
  assert.equal((await stateOf(first))?.state, "sent");
  assert.deepEqual(await released(first), [["accepted", undefined, await lastSent()]]);

  // The record's outcome is written, and its write reports a failure: the `released` entry is still written, once.
  const second = await hold();
  landPut = true;
  await assert.rejects(w.example.reviewHeld(w.lee.human(), { held: second, decision: "send" }), /connection reset/);
  assert.equal((await stateOf(second))?.state, "sent");
  assert.equal((await stateOf(second))?.envelope_id, await lastSent());
  assert.deepEqual(await released(second), [["accepted", undefined, await lastSent()]]);
  assert.equal((await w.example.inbox(w.ana.agent, { include_acked: true })).items.length, 2, "each was sent once");
});

test("spec 6.7: a message whose to_delegate names no agent of Lee's that can receive it waits for Lee, and Ana can't tell", async () => {
  // What Ana's agent sees of a send: the same whether or not the named agent exists and can receive it.
  const seen = (r: SendResult) => (r.status === "delivered" ? { status: r.status, receipt: Object.keys(r.receipt).sort(), outcome: r.receipt.status, ledger_hash: typeof r.receipt.ledger_hash } : { status: r.status });
  const control = await buildWorld();
  const toDot = expect(await control.example.send(control.ana.agent, { to: LEE, to_delegate: `${LEE}/dot`, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
  assert.equal((await control.example.inbox(control.lee.agent)).items.length, 1, "an agent that exists gets it");
  const cases: [string, (w: World) => Promise<void>][] = [
    ["no agent has that name", async () => {}],
    ["that agent was disconnected", async (w) => {
      await w.example.registerDelegate({ principal: LEE, label: "phone", client_id: CLIENTS.connector });
      await w.example.revokeDelegate(`${LEE}/phone`);
    }],
    ["the organization blocked that agent", async (w) => {
      await w.example.registerDelegate({ principal: LEE, label: "phone", client_id: CLIENTS.connector });
      await w.example.setOrgPolicy({ kind: "admin", operator: "it" }, examplePolicy(w.clock.now(), { serial: 2, blocked: { delegates: [`${LEE}/phone`] } }));
    }],
  ];
  for (const [name, setup] of cases) {
    const w = await buildWorld();
    await setup(w);
    const before = w.notifier.sent.length;
    const r = expect(await w.example.send(w.ana.agent, { to: LEE, to_delegate: `${LEE}/phone`, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
    assert.deepEqual(seen(r), seen(toDot), `${name}: an accepted receipt with a ledger hash, as for an agent that exists`);
    const stored = await w.example.store.getMessage(LEE, "in", r.envelope.id);
    assert.equal(stored?.status, "held", name);
    assert.equal(stored?.held_reason, "to_delegate", name);
    // Lee's ledger says it waits for him, in the `received` entry written before the answer; his notification comes
    // after Ana's broker has its answer.
    assert.equal((await w.example.ledger(w.lee.human())).find((e) => e.kind === "received" && e.envelope_id === r.envelope.id)?.ref, "web_view", name);
    await w.example.settled();
    const notes = w.notifier.sent.slice(before).filter((n) => n.principal === LEE);
    assert.deepEqual(notes.map((n) => n.kind), ["message_held"], `${name}: Lee is told once`);
    assert.equal(/phone|Q4|blocked/.test(notes[0]?.text ?? ""), false, `${name}: neither the label the sender chose nor the message's text`);
    // Never delivered to Lee's other agent instead: not in its inbox, its thread view or its acknowledgements.
    assert.equal((await w.example.inbox(w.lee.agent, { include_acked: true })).items.length, 0, name);
    assert.equal((await w.example.thread(w.lee.agent, r.thread)).messages.length, 0, name);
    assert.deepEqual(await w.example.visibleInbound(w.lee.agent, [r.envelope.id]), [], name);
    assert.equal((await w.example.ack(w.lee.agent, { envelope_ids: [r.envelope.id] })).acked, 0, name);
    assert.equal((await w.example.messagesForPerson(w.lee.human())).items.find((i) => i.envelope.id === r.envelope.id)?.status, "held", `${name}: on Lee's page`);
  }
});

test("spec 6.7, 11.4: a receipt's ledger_hash lets Ana confirm no guess of Lee's entry, so she can't tell whether a message waits for him", async () => {
  const w = await buildWorld();
  const lee = await w.example.getPrincipal(LEE);
  assert.ok(lee);
  let previous: string | undefined;
  for (const [name, to_delegate, waits] of [["to an agent that can receive it", `${LEE}/dot`, false], ["to no agent of Lee's", `${LEE}/nobody`, true], ["to that agent again", `${LEE}/dot`, false]] as const) {
    const r = expect(await w.example.send(w.ana.agent, { to: LEE, to_delegate, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
    const sent = (await w.example.ledger(w.ana.human())).find((e) => e.kind === "sent" && e.envelope_id === r.envelope.id);
    assert.ok(sent);
    // Lee's `received` entry as Ana's side can rebuild it: the envelope, the receipt and her own `sent` entry give every
    // member; the entry before it is her previous message's (its ledger_hash), and seq is small. With and without the hold.
    const guesses: Record<string, unknown>[] = [undefined, "web_view"].flatMap((ref) => Array.from({ length: 16 }, (_, seq) => ({
      alp: r.envelope.alp, principal: LEE, principal_id: lee.principal_id, seq, at: r.receipt.created_at, kind: "received", outcome: "accepted",
      counterparty: ANA, counterparty_broker: r.envelope.origin_broker, envelope_id: r.envelope.id, thread: r.envelope.thread, scope: r.envelope.scope, type: r.envelope.type, envelope_hash: sent.envelope_hash,
      ...(ref ? { ref } : {}), disclosed: sent.disclosed, labels: sent.labels, policy_ids: sent.policy_ids, ...(sent.payload_hash ? { payload_hash: sent.payload_hash } : {}), prev_hash: previous ?? null,
    })));
    const entry = (await w.example.ledger(w.lee.human())).find((e) => e.kind === "received" && e.envelope_id === r.envelope.id);
    assert.ok(entry);
    assert.equal(entry.ref, waits ? "web_view" : undefined, `${name}: Lee's entry records whether it waits`);
    const { hash, salt, ...known } = entry;
    assert.equal(hash, r.receipt.ledger_hash);
    assert.ok(guesses.some((g) => isDeepStrictEqual(g, known)), `${name}: Ana's side guesses every member but the salt`);
    assert.equal(guesses.some((g) => hashJson(g) === r.receipt.ledger_hash), false, `${name}: and can confirm none of her guesses`);
    assert.match(salt ?? "", /^[A-Za-z0-9_-]{22,86}$/, `${name}: a salt of at least 128 bits`);
    previous = r.receipt.ledger_hash;
  }
});

test("spec 6.7, 11: Lee's ledger says a message waits for him before his broker answers, so a broker that stops right after the answer loses only the notice", async () => {
  // The work after the answer never runs, as when the process stops (or a serverless instance freezes) right then.
  const dropped: (() => Promise<void>)[] = [];
  const w = await buildWorld({ policy: enterpriseOnly, brokerOptions: { background: (task) => void dropped.push(task) } });
  const quiet = { tz: "UTC", start: "13:00", end: "15:00" };
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, basis: "narrowing", scopes: { "alp.briefing/1": briefTerms }, quiet_hours: quiet });
  const cases: [string, { to_delegate?: string; labels?: string[] }, string][] = [
    ["no agent of Lee's has that name", { to_delegate: `${LEE}/nobody` }, "web_view"],
    ["no agent of Lee's meets its delivery rules", { labels: ["confidential"] }, "web_view"],
    ["Lee's quiet hours", { to_delegate: `${LEE}/dot` }, "until:2026-11-09T15:00:00.000Z"],
  ];
  for (const [name, extra, ref] of cases) {
    const r = expect(await w.example.send(w.ana.agent, { to: LEE, ...extra, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
    assert.equal((await w.example.store.getMessage(LEE, "in", r.envelope.id))?.status, "held", name);
    const entries = (await w.example.ledger(w.lee.human())).filter((e) => e.envelope_id === r.envelope.id);
    assert.deepEqual(entries.map((e) => [e.kind, e.ref]), [["received", ref]], `${name}: one entry, written before the answer, says where it waits`);
    assert.equal(r.receipt.ledger_hash, entries[0]?.hash, `${name}: the receipt names that entry`);
  }
  assert.equal(dropped.length, 3);
  assert.equal(w.notifier.sent.some((n) => n.principal === LEE), false, "only the notices were lost");
  assert.equal((await w.example.verifyLedger(w.lee.human())).ok, true);
});

test("spec 6.7: between two people of one broker, Lee's notice waits until Ana's send has returned, also when every store write takes a turn of the event loop", async () => {
  /** A store whose writes each take a turn of the event loop, as a database's do. */
  class YieldingStore extends MemoryStore {
    override async appendLedger(...args: Parameters<MemoryStore["appendLedger"]>): Promise<LedgerEntry> {
      await new Promise((done) => setTimeout(done, 1));
      return super.appendLedger(...args);
    }
    override async putMessage(...args: Parameters<MemoryStore["putMessage"]>): Promise<void> {
      await new Promise((done) => setTimeout(done, 1));
      return super.putMessage(...args);
    }
  }
  const w = await buildWorld({ storeFor: () => new YieldingStore() });
  const told = (): number => w.notifier.sent.filter((n) => n.principal === LEE).length;
  // Lee's broker accepts it inside Ana's call, and Ana's side still writes its message and receipt entry after that.
  expect(await w.example.send(w.ana.agent, { to: LEE, to_delegate: `${LEE}/nobody`, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
  assert.equal(told(), 0, "not while Ana's call runs");
  await w.example.settled();
  assert.equal(told(), 1, "once it has returned");
});

test("spec 5.4, 6.7: the agent to_delegate names counts only if its binding had started when Lee's broker received the message", async () => {
  const w = await buildWorld();
  const lee = await w.example.getPrincipal(LEE);
  assert.ok(lee);
  // The binding of `phone` starts a second after the message arrives (it was being set up meanwhile): it is another
  // agent than the one Ana's agent named, and can't read what arrived before it (spec 5.4).
  await w.example.store.putDelegate({ id: `${LEE}/phone`, principal: LEE, principal_id: lee.principal_id, label: "phone", kind: "bridged", client_id: CLIENTS.connector, attestation: "vendor", class: "business", status: "active", created_at: new Date(w.clock.now().getTime() + 1000).toISOString() });
  const r = expect(await w.example.send(w.ana.agent, { to: LEE, to_delegate: `${LEE}/phone`, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
  const stored = await w.example.store.getMessage(LEE, "in", r.envelope.id);
  assert.equal(stored?.status, "held", "never stored as delivered to an agent that can't read it");
  assert.equal(stored?.held_reason, "to_delegate");
  w.clock.advance(5);
  const phone = { kind: "delegate" as const, principal: LEE, delegate: `${LEE}/phone`, client_id: CLIENTS.connector };
  assert.equal((await w.example.inbox(phone, { include_acked: true })).items.length, 0);
  assert.equal((await w.example.inbox(w.lee.agent, { include_acked: true })).items.length, 0, "nor Lee's other agent");
  await w.example.settled();
  assert.deepEqual(w.notifier.sent.filter((n) => n.principal === LEE).map((n) => n.kind), ["message_held"], "Lee is told it waits for him");
});

test("a sender that keeps naming agents that don't exist sets off at most one notification an hour", async () => {
  const w = await buildWorld();
  const send = () => w.example.send(w.ana.agent, { to: LEE, to_delegate: `${LEE}/nobody`, scope: "alp.briefing/1", type: "request", body: brief });
  const count = async (): Promise<number> => {
    await w.example.settled();
    return w.notifier.sent.filter((n) => n.principal === LEE && n.kind === "message_held").length;
  };
  expect(await send(), "delivered");
  expect(await send(), "delivered");
  assert.equal(await count(), 1);
  assert.equal((await w.example.messagesForPerson(w.lee.human())).items.filter((i) => i.status === "held").length, 2, "the page lists both");
  w.clock.advance(3601);
  expect(await send(), "delivered");
  assert.equal(await count(), 2);
});

/** Lee's organization asks for an enterprise agent for anything labeled confidential; Lee's agent dot is business. */
const enterpriseOnly = (now: Date) => examplePolicy(now, { delivery_minimums: [{ labels: ["confidential"], min_class: "enterprise" }] });

test("messages that wait for Lee because of his agents share one notification an hour per sender, whatever the reason", async () => {
  const w = await buildWorld({ policy: enterpriseOnly });
  const send = (extra: { labels?: string[]; to_delegate?: string }) => w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief, ...extra });
  const constrained = expect(await send({ labels: ["confidential"] }), "delivered");
  assert.equal((await w.example.store.getMessage(LEE, "in", constrained.envelope.id))?.held_reason, "constraints");
  expect(await send({ labels: ["confidential"] }), "delivered");
  expect(await send({ to_delegate: `${LEE}/nobody` }), "delivered");
  await w.example.settled();
  assert.equal(w.notifier.sent.filter((n) => n.principal === LEE && n.kind === "message_held").length, 1);
  assert.equal((await w.example.messagesForPerson(w.lee.human())).items.filter((i) => i.status === "held").length, 3, "the page lists all three");
});

test("spec 6.7: an ask_human that waits for Lee because of his agents (one it names can't receive it, or none meets its delivery rules) is notified each time", async () => {
  const cases: [NonNullable<MessageRecord["held_reason"]>, { to_delegate?: string; labels?: string[] }][] = [["to_delegate", { to_delegate: `${LEE}/nobody` }], ["constraints", { labels: ["confidential"] }]];
  for (const [reason, extra] of cases) {
    const w = await buildWorld({ policy: enterpriseOnly });
    await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.briefing/1": briefTerms } });
    await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.briefing/1": briefTerms } });
    const before = w.notifier.sent.length;
    const ids: string[] = [];
    for (let i = 0; i < 2; i++) {
      const req = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
      const ask = expect(await w.example.send(w.ana.agent, { to: LEE, ...extra, scope: "alp.briefing/1", type: "ask_human", thread: req.thread, in_reply_to: req.envelope.id, body: { of: req.envelope.id, urgency: "normal", reason: "needs_decision" } }), "delivered");
      ids.push(ask.envelope.id);
    }
    await w.example.settled();
    for (const id of ids) assert.equal((await w.example.store.getMessage(LEE, "in", id))?.held_reason, reason);
    assert.equal((await w.example.inbox(w.lee.agent, { include_acked: true })).items.some((i) => ids.includes(i.envelope.id)), false, `${reason}: not handed to Lee's agent`);
    const kinds = w.notifier.sent.slice(before).filter((n) => n.principal === LEE).map((n) => n.kind);
    assert.deepEqual(kinds, ["ask_human", "ask_human"], `${reason}: outside the hourly limit on notices of held messages`);
  }
});

test("spec 6.7: during the grant's quiet hours Lee is told of none of Ana's messages, whether they wait for the hours to end or because of his agents; once they end he is told what he would have been", async () => {
  const w = await buildWorld({ policy: enterpriseOnly });
  await w.example.setGrant(w.ana.human(), { counterparty: LEE, scopes: { "alp.briefing/1": briefTerms } });
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.briefing/1": briefTerms }, quiet_hours: { tz: "UTC", start: "13:00", end: "15:00" } });
  const ask = async (extra: { to_delegate?: string; labels?: string[] }): Promise<string> => {
    const req = expect(await w.example.send(w.lee.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
    return expect(await w.example.send(w.ana.agent, { to: LEE, ...extra, scope: "alp.briefing/1", type: "ask_human", thread: req.thread, in_reply_to: req.envelope.id, body: { of: req.envelope.id, urgency: "normal", reason: "needs_decision" } }), "delivered").envelope.id;
  };
  const request = async (extra: { to_delegate?: string; labels?: string[] }): Promise<string> =>
    expect(await w.example.send(w.ana.agent, { to: LEE, ...extra, scope: "alp.briefing/1", type: "request", body: brief }), "delivered").envelope.id;
  const told = async (): Promise<string[]> => {
    await w.example.settled();
    return w.notifier.sent.filter((n) => n.principal === LEE).map((n) => n.kind);
  };
  const cases: [string, { to_delegate?: string; labels?: string[] }, MessageRecord["held_reason"]][] = [
    ["to an agent that can receive it", { to_delegate: `${LEE}/dot` }, undefined],
    ["to no agent of Lee's", { to_delegate: `${LEE}/nobody` }, "to_delegate"],
    ["with delivery rules none of Lee's agents meets", { labels: ["confidential"] }, "constraints"],
  ];
  // 14:00, inside the quiet hours: each case twice, as an ask_human and as a request.
  for (const [name, extra, reason] of cases) {
    for (const id of [await ask(extra), await ask(extra), await request(extra), await request(extra)]) {
      const stored = await w.example.store.getMessage(LEE, "in", id);
      assert.equal(stored?.status, "held", name);
      assert.equal(stored?.held_reason, reason, name);
    }
  }
  assert.equal(await w.example.sendDueNotices(), 0, "none is due yet");
  assert.deepEqual(await told(), [], "nothing while the quiet hours last, whatever the message waits for");
  w.clock.advance(3599);
  assert.equal(await w.example.sendDueNotices(), 0, "still nothing a second before they end");
  assert.deepEqual(await told(), []);
  // 15:00, when they end: what Lee would have been told as each arrived. Each ask_human, the ones his agent can read
  // too, and one notice an hour of the messages that wait for him because of his agents (the first of four); nothing
  // for a request his agent can read.
  w.clock.advance(1);
  assert.equal(await w.example.sendDueNotices(), 10, "six ask_human and four held requests");
  assert.deepEqual(await told(), ["ask_human", "ask_human", "ask_human", "ask_human", "message_held", "ask_human", "ask_human"]);
  const held = w.notifier.sent.filter((n) => n.principal === LEE && n.kind === "message_held");
  assert.match(held[0]?.text ?? "", /names one of your agents that isn't connected/);
  assert.equal(held[0]?.at, "2026-11-09T15:00:00.000Z");
  assert.equal(await w.example.sendDueNotices(), 0, "each is sent once");
  // After them: each ask_human that waits for Lee because of his agents, as at any time; the hour's one notice of the
  // rest has gone. An hour later the next one goes.
  for (const [, extra, reason] of cases) {
    if (reason === undefined) continue;
    await ask(extra);
    await request(extra);
  }
  assert.deepEqual((await told()).slice(7), ["ask_human", "ask_human"]);
  w.clock.advance(3600);
  await request({ to_delegate: `${LEE}/nobody` });
  assert.deepEqual((await told()).slice(9), ["message_held"]);
});

test("spec 6.7: a notice that waited for the quiet hours to end says what is true when it goes, and never reaches a later holder of the address", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.briefing/1": briefTerms }, quiet_hours: { tz: "UTC", start: "13:00", end: "15:00" } });
  const told = async (): Promise<string[]> => {
    await w.example.settled();
    return w.notifier.sent.filter((n) => n.principal === LEE).map((n) => n.kind);
  };
  const lee = (extra: { sub?: string; human_fallback: boolean }) => w.example.registerPrincipal({ address: LEE, identity: { iss: "https://dev-idp.invalid", sub: extra.sub ?? "dev-lee" }, contact: { email: "lee@example.org" }, human_fallback: extra.human_fallback });
  // Lee's agent has no connector, so each message he gets brings a notice: at 14:00, once the quiet hours end.
  await lee({ human_fallback: true });
  expect(await sendBrief(w), "delivered");
  assert.deepEqual(await told(), []);
  w.clock.advance(3600);
  assert.equal(await w.example.sendDueNotices(), 1);
  assert.deepEqual(await told(), ["message_waiting"]);

  // The next day: he connects his agent before they end, so the message no longer needs a notice.
  w.clock.advance(23 * 3600);
  expect(await sendBrief(w), "delivered");
  assert.deepEqual(await told(), ["message_waiting"]);
  await lee({ human_fallback: false });
  w.clock.advance(3600);
  assert.equal(await w.example.sendDueNotices(), 1);
  assert.deepEqual(await told(), ["message_waiting"], "nothing more");

  // The day after: the address passes to someone else before they end, who isn't told of the earlier holder's message.
  w.clock.advance(23 * 3600);
  await lee({ human_fallback: true });
  expect(await sendBrief(w), "delivered");
  assert.deepEqual(await told(), ["message_waiting"]);
  await lee({ sub: "dev-someone-else", human_fallback: true });
  w.clock.advance(3600);
  assert.equal(await w.example.sendDueNotices(), 1);
  assert.deepEqual(await told(), ["message_waiting"], "nothing for the new holder");
});

test("spec 6.7: the servers' notice timer sends a notice that waited for the quiet hours once it is due, and stops when told", async () => {
  const w = await buildWorld();
  await w.example.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.briefing/1": briefTerms }, quiet_hours: { tz: "UTC", start: "13:00", end: "15:00" } });
  await w.example.registerPrincipal({ address: LEE, identity: { iss: "https://dev-idp.invalid", sub: "dev-lee" }, human_fallback: true });
  const told = (): string[] => w.notifier.sent.filter((n) => n.principal === LEE).map((n) => n.kind);
  const tick = (): Promise<void> => new Promise((done) => setTimeout(done, 20));
  expect(await sendBrief(w), "delivered");
  await w.example.settled();
  const stop = w.example.startNoticeTimer(5);
  try {
    await tick();
    await w.example.settled();
    assert.deepEqual(told(), [], "not due yet");
    w.clock.advance(3600);
    for (let i = 0; i < 50 && told().length === 0; i++) await tick();
    await w.example.settled();
    assert.deepEqual(told(), ["message_waiting"]);
  } finally {
    stop();
  }
  // Stopped: a notice due later stays in the store until something sends it.
  w.clock.advance(23 * 3600);
  expect(await sendBrief(w), "delivered");
  await w.example.settled();
  w.clock.advance(3600);
  await tick();
  await w.example.settled();
  assert.deepEqual(told(), ["message_waiting"]);
  assert.equal(await w.example.sendDueNotices(), 1);
  assert.deepEqual(told(), ["message_waiting", "message_waiting"]);
});

test("spec 6.7: Lee's broker answers with the same store writes whether a message is delivered or waits for Lee; what a hold adds comes after the answer", async () => {
  class CountingStore extends MemoryStore {
    writes = 0;
    protected override changed(): void {
      this.writes++;
    }
  }
  const stores = new Map<string, CountingStore>();
  const w = await buildWorld({ policy: enterpriseOnly, storeFor: (id) => {
    const s = new CountingStore();
    stores.set(id, s);
    return s;
  } });
  const store = stores.get(IDS.example);
  assert.ok(store);
  // What Lee's side writes before it answers (the inbound call), and what Ana's call writes in all, before it returns.
  const accept = w.example.acceptInbound.bind(w.example);
  let answering = 0;
  w.example.acceptInbound = async (raw, ctx) => {
    const before = store.writes;
    const r = await accept(raw, ctx);
    answering = store.writes - before;
    return r;
  };
  const measure = async (extra: { to_delegate?: string; labels?: string[] }) => {
    await w.example.settled();
    // A new hour: each hold sets off its notice (and the write of its limit).
    w.clock.advance(3601);
    const before = store.writes;
    const r = expect(await w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief, ...extra }), "delivered");
    const sending = store.writes - before;
    const accepting = answering;
    await w.example.settled();
    const stored = await w.example.store.getMessage(LEE, "in", r.envelope.id);
    return { accepting, sending, after: store.writes - before - sending, held: stored?.held_reason ?? stored?.status };
  };
  await measure({});
  const delivered = await measure({ to_delegate: `${LEE}/dot` });
  const noAgent = await measure({ to_delegate: `${LEE}/nobody` });
  const constrained = await measure({ labels: ["confidential"] });
  assert.deepEqual([delivered.held, noAgent.held, constrained.held], ["delivered", "to_delegate", "constraints"]);
  assert.ok(delivered.accepting > 0);
  for (const [name, m] of [["to_delegate", noAgent], ["constraints", constrained]] as const) {
    assert.equal(m.accepting, delivered.accepting, `${name}: Lee's broker writes as much before it answers`);
    assert.equal(m.sending, delivered.sending, `${name}: Ana's call writes as much before it returns`);
    assert.ok(m.after > delivered.after, `${name}: the limit on notices of held messages is written after`);
  }
});

/** Records Lee's broker stored before, made up for paging tests: `n` received messages, each with `extra`. */
async function stored(w: World, n: number, extra: (i: number) => { status?: "held"; to_delegate?: string; stored_at?: string }): Promise<void> {
  const lee = await w.example.getPrincipal(LEE);
  for (let i = 0; i < n; i++) {
    const id = `0000000000000000000${String(i).padStart(7, "0")}`;
    const x = extra(i);
    await w.example.store.putMessage({
      local_id: id,
      principal: LEE,
      ...(lee ? { principal_id: lee.principal_id } : {}),
      direction: "in",
      envelope: { id, thread: id, from: { address: ANA }, to: { address: LEE, ...(x.to_delegate ? { delegate: x.to_delegate } : {}) }, created_at: "2026-11-01T00:00:00.000Z" } as Envelope,
      envelope_hash: "sha256:x",
      status: x.status ?? "delivered",
      acked_by: {},
      stored_at: x.stored_at ?? "2026-11-01T00:00:00.000Z",
    });
  }
}

test("inbox paging: a page of only records the agent may not see says there is more, and the cursor moves past them", async () => {
  const w = await buildWorld();
  // 250 messages held for Lee (no agent of his may read them), then one his agent may.
  await stored(w, 250, () => ({ status: "held" }));
  const visible = expect(await sendBrief(w), "delivered");
  const first = await w.example.inbox(w.lee.agent, { limit: 1 });
  assert.deepEqual(first.items, []);
  assert.equal(first.has_more, true, "not \"no messages\" while unread records remain");
  assert.ok(first.next_cursor);
  const next = await w.example.inbox(w.lee.agent, { limit: 1, cursor: first.next_cursor });
  assert.deepEqual(next.items.map((i) => i.envelope.id), [visible.envelope.id]);
});

test("spec 5.4: an agent that took a disconnected agent's name pages straight past what was addressed to the earlier one", async () => {
  const w = await buildWorld();
  await w.example.registerDelegate({ principal: LEE, label: "phone", client_id: CLIENTS.connector });
  await stored(w, 300, () => ({ to_delegate: `${LEE}/phone`, stored_at: w.clock.now().toISOString() }));
  w.clock.advance(60);
  await w.example.revokeDelegate(`${LEE}/phone`);
  w.clock.advance(60);
  const fresh = await w.example.registerDelegate({ principal: LEE, label: "phone", client_id: CLIENTS.connector });
  const phone = { kind: "delegate" as const, principal: LEE, delegate: fresh.id, client_id: CLIENTS.connector };
  const toLee = expect(await sendBrief(w), "delivered");
  const page = await w.example.inbox(phone, { limit: 1 });
  assert.deepEqual(page.items.map((i) => i.envelope.id), [toLee.envelope.id], "the store leaves the earlier agent's out of the query");
});

test("spec 12.2.4 step 0: an envelope whose from.delegate or to.delegate is an agent of another address is refused, whoever's agents exist", async () => {
  const w = await buildWorld();
  const now = w.clock.now();
  const pat = (await w.partner.getPrincipal(PAT))?.principal_id ?? "";
  const cases: [string, string, Pick<UnsignedEnvelope, "from" | "to">][] = [
    ["to.delegate is another person's agent", "01M7090000000000000000TD01", { from: { address: PAT, principal_id: pat, delegate: `${PAT}/agent`, attestation: "vendor", class: "business" }, to: { address: LEE, delegate: `${ANA}/muse` } }],
    ["from.delegate is another person's agent", "01M7090000000000000000FD01", { from: { address: PAT, principal_id: pat, delegate: `${ANA}/muse`, attestation: "vendor", class: "business" }, to: { address: LEE } }],
  ];
  for (const [name, id, parties] of cases) {
    const unsigned: UnsignedEnvelope = {
      alp: "0.1",
      id,
      thread: id,
      ...parties,
      aud: IDS.example,
      scope: "alp.briefing/1",
      type: "request",
      body: brief,
      grant: "g",
      labels: ["internal"],
      created_at: now.toISOString(),
      expires_at: new Date(now.getTime() + 3600_000).toISOString(),
      origin_broker: IDS.partner,
      decision: { outcome: "allowed", redacted: [], policy_ids: [] },
    };
    const r = await w.example.acceptInbound(await signEnvelope(unsigned, w.partner.keys));
    assert.equal(r.kind === "refused" && `${r.code}@${r.step}`, "bad_envelope@0", `${name}: ${JSON.stringify(r)}`);
  }
});
