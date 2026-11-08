// SPDX-License-Identifier: FSL-1.1-ALv2
// What one agent may read, labels, uniform answers to connection requests, duplicates in flight, home checks for a
// broker's own principals, address reassignment and kill switches on reads (spec 5.2, 5.8, 6.2.2, 6.5, 6.11, 10.3,
// 12.1.4, 12.2.4).

import assert from "node:assert/strict";
import { test } from "node:test";
import { ANA, CLIENTS, LEE, PAT, buildWorld, examplePolicy } from "../demo/world.ts";
import type { World } from "../demo/world.ts";
import type { SendResult } from "./api.ts";
import { registrableDomain } from "./broker.ts";
import { signEnvelope } from "./envelope.ts";
import { DEV_ISSUER } from "./identity.ts";
import type { DelegateCaller, Envelope, OrgPolicy, ScopeTerms } from "./types.ts";
import { ulid } from "ulid";
import { MemoryStore } from "../storage/memory.ts";

function expect<S extends SendResult["status"]>(r: SendResult, s: S): Extract<SendResult, { status: S }> {
  assert.equal(r.status, s, JSON.stringify(r));
  return r as Extract<SendResult, { status: S }>;
}

const briefTerms: ScopeTerms = {
  may: ["request", "inform", "ask_human"],
  disclose: ["/body/topic", "/body/questions/*", "/body/depth", "/body/points/*", "/body/as_of"],
  receive: ["/body/topic", "/body/questions/*", "/body/depth", "/body/points/*", "/body/as_of"],
  commit: "ask_me",
  redaction: "reject",
};

async function connectAnaPat(w: World): Promise<void> {
  await w.example.setGrant(w.ana.human(), { counterparty: PAT, scopes: { "alp.briefing/1": briefTerms } });
  await w.partner.setGrant(w.pat.human(), { counterparty: ANA, scopes: { "alp.briefing/1": briefTerms } });
}

/** Ana's second agent: a consumer-class one (example.org's list records CLIENTS.consumer as self / consumer). */
async function consumerAgent(w: World): Promise<DelegateCaller> {
  const d = await w.example.registerDelegate({ principal: ANA, label: "personal", kind: "bridged", client_id: CLIENTS.consumer });
  assert.equal(`${d.attestation}/${d.class}`, "self/consumer");
  return { kind: "delegate", principal: ANA, delegate: d.id, client_id: CLIENTS.consumer };
}

// ---------------------------------------------------------------------------------------------
// What one agent may read (spec 6.11, 12.1.4)

test("alp_thread applies delivery constraints: a consumer agent never reads a reply its person's rules kept from it", async () => {
  const w = await buildWorld({ domainDocs: false });
  const personal = await consumerAgent(w);
  const ask = expect(await w.example.send(personal, { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Q3 tracking", depth: "summary" } }), "delivered");
  const reply = expect(
    await w.example.send(w.lee.agent, { to: "ana@example.org", scope: "alp.briefing/1", type: "inform", thread: ask.thread, in_reply_to: ask.envelope.id, labels: ["confidential"], body: { points: ["CONFIDENTIAL: Q3 revenue tracking 12% below plan"], as_of: "2026-11-09T13:00:00Z" } }),
    "delivered",
  );
  assert.deepEqual(reply.envelope.constraints, { deliver_to: { min_class: "business" } });

  assert.equal((await w.example.inbox(personal)).items.length, 0, "the inbox keeps it from the consumer agent");
  const seen = await w.example.thread(personal, ask.thread);
  assert.deepEqual(seen.messages.map((m) => `${m.direction}:${m.envelope.type}`), ["out:request"], "and so does the thread: only the agent's own request");
  assert.ok(!JSON.stringify(seen).includes("12% below plan"));
  assert.deepEqual(await w.example.visibleInbound(personal, [reply.envelope.id]), []);
  assert.equal((await w.example.ack(personal, { envelope_ids: [reply.envelope.id] })).acked, 0, "nor can it acknowledge it");

  // Ana's business agent meets the constraint: it reads the reply, but not what her other agent sent.
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 1);
  const business = await w.example.thread(w.ana.agent, ask.thread);
  assert.deepEqual(business.messages.map((m) => `${m.direction}:${m.envelope.type}`), ["in:inform"], "another agent's sent messages are never shown");
});

// ---------------------------------------------------------------------------------------------
// Labels (spec 6.5)

test("a delegate may add only labels the rules name exactly, and only a few", async () => {
  const w = await buildWorld({ domainDocs: false });
  const send = (labels: string[]): Promise<SendResult> => w.example.send(w.ana.agent, { to: "lee@example.org", scope: "alp.availability/1", type: "request", labels, body: { window: { start: "2026-11-10T14:00:00Z", end: "2026-11-10T18:00:00Z" }, duration_minutes: 30, timezone: "UTC" } });
  // example.org's rules name confidential.* as a pattern: a pattern names no new labels, so nothing can be smuggled
  // below it either.
  for (const smuggle of [["card.n4111111111111111"], ["x.merger_contoso_42_per_share"], ["confidential.n4111111111111111"], ["confidential.merger_contoso_42_per_share", "internal"]]) {
    const r = expect(await send(smuggle), "rejected");
    assert.equal(r.code, "invalid_input", `${smuggle.join(",")}: a label the rules don't name exactly is refused, so labels can't carry data`);
  }
  expect(await send(["confidential.financial", "internal"]), "delivered");
  assert.equal(expect(await send(["internal", "public", "confidential", "restricted", "confidential.financial"]), "rejected").code, "invalid_input", "at most four");
  const added = w.example.labelVocabulary(ANA, "alp.briefing/1", "added");
  assert.equal(added.has("confidential.financial"), true);
  assert.equal(added.has("confidential"), true);
  assert.equal(added.has("confidential.hr"), false, "below a pattern, but not named");
  assert.equal(added.has("card.n4111"), false);
  const known = w.example.labelVocabulary(ANA, "alp.briefing/1", "known");
  assert.equal(known.has("confidential.hr"), true, "a recipient keeps a sender's label below a pattern its rules name");
  assert.equal(known.has("card.n4111"), false);
});

test("the recipient drops sender-added labels its own rules don't know", async () => {
  const policy = (now: Date): OrgPolicy => {
    const p = examplePolicy(now);
    return { ...p, classification: { ...(p.classification ?? {}), overrides: { "alp.briefing/1": { "/body/depth": ["project.atlas"] } } } };
  };
  const w = await buildWorld({ policy });
  await connectAnaPat(w);
  const sent = expect(await w.example.send(w.ana.agent, { to: PAT, scope: "alp.briefing/1", type: "request", labels: ["project.atlas"], body: { topic: "Launch", depth: "headline" } }), "delivered");
  assert.ok(sent.envelope.labels.includes("project.atlas"), "known at example.org, so it is signed");
  const item = (await w.partner.inbox(w.pat.agent)).items[0];
  assert.ok(item);
  assert.ok(!item.verified.labels.includes("project.atlas"), "partner.example's rules don't know it: dropped");
});

// ---------------------------------------------------------------------------------------------
// Connection requests answer the same whatever happens (spec 6.2.2)

test("connection requests get the same accepted receipt, with no ledger hash, for real, unknown, declined and dropped addresses", async () => {
  const w = await buildWorld();
  const mallory = w.mallory.human();
  const lee = await w.outside.requestConnection(mallory, { to: "lee@example.org", scopes: ["alp.briefing/1"], purpose: "briefing" });
  const ghost = await w.outside.requestConnection(mallory, { to: "ghost@example.org", scopes: ["alp.briefing/1"], purpose: "briefing" });
  for (const r of [lee, ghost]) {
    assert.equal(r.status, "requested", JSON.stringify(r));
    if (r.status === "requested") {
      assert.equal(r.receipt.status, "accepted");
      assert.equal(r.receipt.ledger_hash, undefined, "no ledger hash: it would tell a real address from an unknown one");
    }
  }
  // Lee declines; Mallory asks again: the same answer, and nothing new reaches Lee for 90 days.
  const pending = (await w.example.listConnections(w.lee.human())).filter((c) => c.state === "pending");
  assert.equal(pending.length, 1);
  await w.example.respondToConnection(w.lee.human(), { request: pending[0]!.id, decision: "decline" });
  const again = await w.outside.requestConnection(mallory, { to: "lee@example.org", scopes: ["alp.briefing/1"], purpose: "briefing" });
  assert.equal(again.status, "requested", JSON.stringify(again));
  assert.equal((await w.example.listConnections(w.lee.human())).filter((c) => c.state === "pending").length, 0, "dropped: Lee declined Mallory within 90 days");
});

test("an organization that refuses outside requests still answers accepted", async () => {
  const w = await buildWorld({ policy: (now) => examplePolicy(now, { connection_requests: { inbound: "deny" } }) });
  const r = await w.outside.requestConnection(w.mallory.human(), { to: "lee@example.org", scopes: ["alp.briefing/1"], purpose: "briefing" });
  assert.equal(r.status, "requested");
  assert.equal((await w.example.listConnections(w.lee.human())).length, 0);
});

test("on a shared broker a requester can't tell which local addresses exist", async () => {
  const w = await buildWorld({ domainDocs: false });
  for (const to of ["lee@example.org", "nobody-here@example.org"]) {
    const r = await w.example.requestConnection(w.ana.human(), { to, scopes: ["alp.availability/1"], purpose: "scheduling" });
    assert.equal(r.status, "requested", `${to}: ${JSON.stringify(r)}`);
  }
});

test("connection-request notifications are a digest: one email a day, the page lists the rest", async () => {
  const w = await buildWorld();
  await w.outside.registerPrincipal({ address: "alp:eve@outside.example", identity: { iss: DEV_ISSUER, sub: "dev-eve" } });
  await w.outside.requestConnection(w.mallory.human(), { to: "lee@example.org", scopes: ["alp.briefing/1"], purpose: "briefing" });
  await w.outside.requestConnection({ kind: "human", principal: "alp:eve@outside.example", auth: { method: "reauth-dev", at: w.clock.now().toISOString() } }, { to: "lee@example.org", scopes: ["alp.briefing/1"], purpose: "briefing" });
  assert.equal((await w.example.listConnections(w.lee.human())).filter((c) => c.state === "pending").length, 2);
  assert.equal(w.notifier.sent.filter((n) => n.principal === LEE && n.kind === "connection_request").length, 1);
});

test("connection-request quotas group a registrable domain's names", () => {
  assert.equal(registrableDomain("a1.evil.example"), "evil.example");
  assert.equal(registrableDomain("x.y.evil.co.uk"), "evil.co.uk");
  assert.equal(registrableDomain("partner.example"), "partner.example");
});

// ---------------------------------------------------------------------------------------------
// Duplicates in flight (spec 10.3)

test("concurrent copies of one envelope are evaluated once", async () => {
  const w = await buildWorld();
  await connectAnaPat(w);
  const first = expect(await w.example.send(w.ana.agent, { to: PAT, scope: "alp.briefing/1", type: "request", body: { topic: "Launch", depth: "headline" } }), "delivered");
  // A fresh envelope from the same broker, posted four times at once (a sender retrying after a timeout).
  const { broker_sig: _sig, ...unsigned } = first.envelope;
  const env = (await signEnvelope({ ...unsigned, id: ulid(), thread: ulid() }, w.example.keys)) as Envelope;
  const results = await Promise.all([1, 2, 3, 4].map(() => w.partner.acceptInbound(structuredClone(env))));
  const receipts = new Set(results.flatMap((r) => (r.kind === "receipt" ? [r.receipt.id] : [])));
  assert.equal(receipts.size, 1, `one evaluation, one receipt: ${JSON.stringify(results.map((r) => r.kind === "receipt" ? r.receipt.status : `${r.status} ${r.code}`))}`);
  for (const r of results) if (r.kind === "refused") assert.equal(r.status, 503, "a copy in flight is told to retry shortly");
  const received = (await w.partner.ledger(w.pat.human())).filter((e) => e.kind === "received" && e.envelope_id === env.id);
  assert.equal(received.length, 1, "Pat's ledger records it once");
  const later = await w.partner.acceptInbound(structuredClone(env));
  assert.equal(later.kind === "receipt" && later.duplicate, true, "a copy after it was answered gets the original receipt");
});

test("a copy that takes the in-flight mark first is the only one evaluated, even when the store answers out of order", async () => {
  /** A store whose first write of each in-flight mark lands 40 ms late, as a database round trip under load might. */
  class SlowInflightStore extends MemoryStore {
    private readonly slowed = new Set<string>();
    override async recordOnce(key: string, expiresAt: string, now: Date): Promise<boolean> {
      if (key.startsWith("inflight|") && !this.slowed.has(key)) {
        this.slowed.add(key);
        await new Promise((r) => setTimeout(r, 40));
      }
      return super.recordOnce(key, expiresAt, now);
    }
  }
  const w = await buildWorld({ storeFor: () => new SlowInflightStore() });
  await connectAnaPat(w);
  const first = expect(await w.example.send(w.ana.agent, { to: PAT, scope: "alp.briefing/1", type: "request", body: { topic: "Launch", depth: "headline" } }), "delivered");
  const { broker_sig: _sig, ...unsigned } = first.envelope;
  const env = (await signEnvelope({ ...unsigned, id: ulid(), thread: ulid() }, w.example.keys)) as Envelope;
  // The first copy, and a sender's retry 5 ms later, while the first copy's in-flight write is still on its way.
  const a = w.partner.acceptInbound(structuredClone(env));
  await new Promise((r) => setTimeout(r, 5));
  const b = w.partner.acceptInbound(structuredClone(env));
  const results = await Promise.all([a, b]);
  assert.equal(results.filter((r) => r.kind === "receipt").length, 1, JSON.stringify(results.map((r) => (r.kind === "receipt" ? r.receipt.status : `${r.status} ${r.code}`))));
  const received = (await w.partner.ledger(w.pat.human())).filter((e) => e.kind === "received" && e.envelope_id === env.id);
  assert.equal(received.length, 1, "Pat's ledger records it once");
});

// ---------------------------------------------------------------------------------------------
// The domain document decides for a broker's own principals too (spec 4.5, 12.2.4 steps 3 and 6)

test("a broker the domain document doesn't name can't deliver between its stale local principals", async () => {
  const w = await buildWorld();
  // The rogue broker hosts example.org in its own configuration and holds its own "ana" and "lee".
  await w.rogue.registerPrincipal({ address: LEE, identity: { iss: "https://rogue.example", sub: "lee" } });
  const human = { kind: "human" as const, principal: ANA, auth: { method: "reauth-dev" as const, at: w.clock.now().toISOString() } };
  await w.rogue.setGrant(human, { counterparty: LEE, scopes: { "alp.briefing/1": briefTerms } });
  await w.rogue.setGrant({ ...human, principal: LEE }, { counterparty: ANA, scopes: { "alp.briefing/1": briefTerms } });
  const r = await w.rogue.send({ kind: "delegate", principal: ANA, delegate: `${ANA}/muse`, client_id: CLIENTS.connector }, { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Wire the funds", depth: "headline" } });
  assert.notEqual(r.status, "delivered", JSON.stringify(r));
  // The rogue's own "lee" record is ignored: example.org's document names the real broker for lee, which refuses a
  // broker the document doesn't name for ana.
  assert.equal(r.status === "undeliverable" && r.code, "broker_not_authorized");
  assert.equal((await w.rogue.store.listMessages(LEE, { direction: "in", limit: 10 })).length, 0, "nothing was delivered locally on the rogue broker");
  assert.equal((await w.example.inbox(w.lee.agent)).items.length, 0);
});

test("a broker stops delivering for its local principals once their domain's document names another broker", async () => {
  const w = await buildWorld();
  expect(await w.example.send(w.ana.agent, { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Before", depth: "headline" } }), "delivered");
  // example.org moves everyone to another broker; this broker still holds Ana's and Lee's records.
  w.publish("example.org", w.example, { brokers: [{ id: "https://new-broker.example.org", inbox: "https://new-broker.example.org/federation/inbox", jwks_uri: "https://new-broker.example.org/.well-known/jwks.json", jkt: w.partner.keys.jkts(), principals: "*" }] });
  const r = await w.example.send(w.ana.agent, { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "After", depth: "headline" } });
  assert.notEqual(r.status, "delivered", JSON.stringify(r));
  assert.equal((await w.example.inbox(w.lee.agent)).items.length, 1, "only the message from before the move");
});

// ---------------------------------------------------------------------------------------------
// Address reassignment (spec 5.2)

test("a new holder of an address inherits nothing: inbox, threads, grants and the counterparty's consent", async () => {
  const w = await buildWorld();
  await connectAnaPat(w);
  const toPat = expect(await w.example.send(w.ana.agent, { to: PAT, scope: "alp.briefing/1", type: "request", body: { topic: "Board pack", depth: "summary" } }), "delivered");
  const fromLee = expect(await w.example.send(w.lee.agent, { to: "ana@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Old Ana: what is left?", depth: "summary" } }), "delivered");
  const oldId = toPat.envelope.from.principal_id;
  assert.equal((await w.partner.store.getGrant(PAT, ANA))?.counterparty_principal_id, oldId, "Pat's grant is bound, on first contact, to the Ana who wrote");
  // Pat answers once, so example.org's side binds its grant to Pat too.
  expect(await w.partner.send(w.pat.agent, { to: ANA, scope: "alp.briefing/1", type: "inform", thread: toPat.thread, in_reply_to: toPat.envelope.id, body: { points: ["On track"], as_of: "2026-11-09T13:00:00Z" } }), "delivered");

  // The address goes to someone else.
  const fresh = await w.example.registerPrincipal({ address: ANA, identity: { iss: DEV_ISSUER, sub: "dev-ana-new" }, display_name: "Another Ana" });
  assert.notEqual(fresh.principal_id, oldId);
  const d = await w.example.registerDelegate({ principal: ANA, label: "agent", kind: "bridged", client_id: CLIENTS.connector });
  const agent: DelegateCaller = { kind: "delegate", principal: ANA, delegate: d.id, client_id: CLIENTS.connector };

  assert.equal((await w.example.inbox(agent)).items.length, 0, "the old holder's inbox stays hers");
  await assert.rejects(w.example.thread(agent, fromLee.thread), /no such thread/);
  assert.ok(!(await w.example.contacts(agent)).some((c) => c.basis === "grant" && c.address === PAT), "her grants stay hers");
  assert.equal(expect(await w.example.send(agent, { to: PAT, scope: "alp.briefing/1", type: "request", body: { topic: "Status?", depth: "headline" } }), "rejected").code, "no_relationship");
  assert.equal((await w.example.listGrants(w.ana.human())).length, 0);

  // Pat's broker was told (revoke, address_reassigned): its grant stays bound to the old Ana, and is over.
  const after = await w.partner.store.getGrant(PAT, ANA);
  assert.equal(after?.status, "revoked");
  assert.equal(after?.counterparty_principal_id, oldId);
  assert.equal(await w.partner.store.getRevocation(PAT, ANA), null, "nothing is recorded against the address itself");
  assert.equal(expect(await w.partner.send(w.pat.agent, { to: ANA, scope: "alp.briefing/1", type: "request", body: { topic: "Hello?", depth: "headline" } }), "rejected").code, "no_relationship");
  // The old holder's agents are disconnected; her ledger is kept.
  await assert.rejects(w.example.inbox(w.ana.agent));
  assert.ok((await w.example.store.listLedger(oldId)).some((e) => e.kind === "grant_revoked"));
});

test("a recipient refuses a sender whose principal_id differs from the one its grant holds", async () => {
  const w = await buildWorld();
  await connectAnaPat(w);
  expect(await w.example.send(w.ana.agent, { to: PAT, scope: "alp.briefing/1", type: "request", body: { topic: "Board pack", depth: "summary" } }), "delivered");
  const bound = await w.partner.store.getGrant(PAT, ANA);
  assert.ok(bound?.counterparty_principal_id, "bound on first contact");
  // The same address, another principal_id: the grant is void for this sender, who is a stranger to Pat.
  const g = await w.partner.grantOf((await w.partner.getPrincipal(PAT))!, ANA, "someone-else-0123456789");
  assert.equal(g, null);
  assert.ok(await w.partner.grantOf((await w.partner.getPrincipal(PAT))!, ANA, bound.counterparty_principal_id));
});

// ---------------------------------------------------------------------------------------------
// Kill switches stop reads too (spec 5.8)

test("a kill switch on a principal, a client or a delegate stops reads, not only sends", async () => {
  for (const blocked of [{ principals: [ANA] }, { client_ids: [CLIENTS.connector] }, { delegates: [`${ANA}/muse`] }] as OrgPolicy["blocked"][]) {
    const w = await buildWorld({ domainDocs: false });
    const sent = expect(await w.example.send(w.lee.agent, { to: "ana@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Confidential reorg", depth: "summary" } }), "delivered");
    await w.example.setOrgPolicy({ kind: "admin", operator: "test" }, examplePolicy(w.clock.now(), { serial: 2, blocked }));
    await assert.rejects(w.example.inbox(w.ana.agent), /blocked/, JSON.stringify(blocked));
    await assert.rejects(w.example.thread(w.ana.agent, sent.thread), /blocked/);
    await assert.rejects(w.example.whoami(w.ana.agent), /blocked/);
    assert.equal(w.example.agentBlocked(ANA, `${ANA}/muse`, CLIENTS.connector) !== null, true);
    // The person still sees it on the web view.
    assert.equal((await w.example.messagesForPerson(w.ana.human())).items.length, 1);
  }
});

test("spec 6.10: a client the organization's list leaves out (enforce mode) stops reading at once, not only sending", async () => {
  const w = await buildWorld({ domainDocs: false });
  expect(await w.example.send(w.lee.agent, { to: "ana@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Reorg", depth: "summary" } }), "delivered");
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 1);
  const p = examplePolicy(w.clock.now(), { serial: 2 });
  if (p.clients) p.clients.allowed = p.clients.allowed.filter((c) => c.client_id !== CLIENTS.connector);
  await w.example.setOrgPolicy({ kind: "admin", operator: "test" }, p);
  assert.equal(w.example.clientRefused(ANA, CLIENTS.connector), true);
  await assert.rejects(w.example.inbox(w.ana.agent), /client_not_allowed|list of agents/);
  await assert.rejects(w.example.whoami(w.ana.agent), /client_not_allowed|list of agents/);
  assert.equal((await w.example.messagesForPerson(w.ana.human())).items.length, 1, "the person still sees it on the web view");
  // Report mode only records it.
  await w.example.setOrgPolicy({ kind: "admin", operator: "test" }, { ...p, serial: 3, clients: { mode: "report", allowed: p.clients?.allowed ?? [] } });
  assert.equal(w.example.clientRefused(ANA, CLIENTS.connector), false);
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 1);
});

test("spec 5.4: a lower class or attestation in the current list applies at once to connected agents; a higher one waits for the next sign-in", async () => {
  const w = await buildWorld({ domainDocs: false });
  // A reply only business-class agents may read (the confidential label's delivery minimum).
  expect(await w.example.send(w.lee.agent, { to: "ana@example.org", scope: "alp.briefing/1", type: "request", labels: ["confidential"], body: { topic: "Reorg", depth: "summary" } }), "delivered");
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 1);
  const lowered = examplePolicy(w.clock.now(), { serial: 2 });
  for (const c of lowered.clients?.allowed ?? []) if (c.client_id === CLIENTS.connector) Object.assign(c, { attestation: "self", class: "consumer" });
  await w.example.setOrgPolicy({ kind: "admin", operator: "test" }, lowered);
  const who = await w.example.whoami(w.ana.agent);
  assert.equal(`${who.attestation}/${who.class}`, "self/consumer", "the agent signed in under business class; the list now says consumer");
  assert.equal((await w.example.inbox(w.ana.agent)).items.length, 0, "it no longer reads what only business-class agents may read");
  // Raised again: the agent's own record (registered while the list said consumer) caps it until it signs in again.
  const fresh = await w.example.registerDelegate({ principal: ANA, label: "later", kind: "bridged", client_id: CLIENTS.connector });
  assert.equal(`${fresh.attestation}/${fresh.class}`, "self/consumer");
  await w.example.setOrgPolicy({ kind: "admin", operator: "test" }, examplePolicy(w.clock.now(), { serial: 3 }));
  const later = await w.example.whoami({ kind: "delegate", principal: ANA, delegate: fresh.id, client_id: CLIENTS.connector });
  assert.equal(`${later.attestation}/${later.class}`, "self/consumer", "a raise waits for the next sign-in, when the client's credential is checked");
  const resigned = await w.example.registerDelegate({ principal: ANA, label: "later", kind: "bridged", client_id: CLIENTS.connector });
  assert.equal(`${resigned.attestation}/${resigned.class}`, "vendor/business");
});

test("spec 5.7: a personal access token is never recorded or ranked above self and business, whatever the list says", async () => {
  const w = await buildWorld({ domainDocs: false, policy: (now) => {
    const p = examplePolicy(now);
    p.clients?.allowed.push({ client_id: "pat", scopes: ["alp.briefing/1"], attestation: "tenant", class: "enterprise", no_training: true });
    return p;
  } });
  const d = await w.example.registerDelegate({ principal: ANA, label: "script", kind: "bridged", client_id: "pat", attestation: "self", class: "consumer" });
  assert.equal(`${d.attestation}/${d.class}`, "self/business");
  const who = await w.example.whoami({ kind: "delegate", principal: ANA, delegate: d.id, client_id: "pat" });
  assert.equal(`${who.attestation}/${who.class}`, "self/business");
});

test("blocked agents don't count as able to receive: a constrained message waits for the person", async () => {
  // example.org blocks the connector client: Ana's only business-class agent can't receive.
  const w = await buildWorld({ domainDocs: false, policy: (now) => examplePolicy(now, { blocked: { client_ids: [CLIENTS.connector] } }) });
  const leeOther = await w.example.registerDelegate({ principal: LEE, label: "other", kind: "bridged", client_id: CLIENTS.consumer });
  const sent = expect(await w.example.send({ kind: "delegate", principal: LEE, delegate: leeOther.id, client_id: CLIENTS.consumer }, { to: "ana@example.org", scope: "alp.briefing/1", type: "request", labels: ["confidential"], body: { topic: "Reorg", depth: "headline" } }), "delivered");
  const rec = await w.example.store.getMessage(ANA, "in", sent.envelope.id);
  assert.equal(rec?.status, "held", "no agent that may receive it meets its constraints: it waits on the person's page");
  await w.example.settled();
  assert.ok(w.notifier.sent.some((n) => n.principal === ANA && n.kind === "message_held"));
});
