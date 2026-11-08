// SPDX-License-Identifier: FSL-1.1-ALv2
// Federation over real localhost HTTP: three brokers for example.org's addresses (broker-a and broker-b, which the
// domain authority lists, and the rogue broker-c, which it doesn't) plus outside.example's own broker. Every request
// goes through the hardened fetcher and the dev host map; every answer comes from a real HTTP server.
// Ports 47160 to 47165 (one world at a time; each test starts and stops its own).

import { test } from "node:test";
import assert from "node:assert/strict";
import type { SendResult } from "../core/api.ts";
import { homeBroker, pinnedFederationKeys } from "../core/domain.ts";
import { objectHash, signEnvelope, verifyAnyEnvelope, verifyReceipt } from "../core/envelope.ts";
import { KeyRing } from "../core/keys.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { crossCheckEntries } from "../core/ledger.ts";
import type { Envelope, JsonObject } from "../core/types.ts";
import { ANA, LEE, MALLORY } from "../demo/world.ts";
import { FEDERATION_PATHS } from "./domain-authority.ts";
import { contentDigest, signRequest } from "./http-signatures.ts";
import { FED_IDS, startHttpWorld } from "./http-world.ts";
import type { HttpWorld, HttpWorldOptions } from "./http-world.ts";
import { HttpsDomainResolver } from "./resolver.ts";
import { FEDERATION_TEST_PORT_BASE } from "../test-ports.ts";
import { postRaw } from "./testing.ts";

const BASE = FEDERATION_TEST_PORT_BASE + 10;
const INBOX_B = `${FED_IDS.b}${FEDERATION_PATHS.inbox}`;
const brief = { topic: "Q4 launch readiness", questions: ["What is still blocked?"], depth: "summary" };

async function withWorld(fn: (w: HttpWorld) => Promise<void>, opts: Partial<HttpWorldOptions> = {}): Promise<void> {
  const w = await startHttpWorld({ basePort: BASE, sleep: async () => {}, ...opts });
  try {
    await fn(w);
  } finally {
    await w.close();
  }
}

function expectStatus<S extends SendResult["status"]>(r: SendResult, s: S): Extract<SendResult, { status: S }> {
  assert.equal(r.status, s, JSON.stringify(r));
  return r as Extract<SendResult, { status: S }>;
}

function sendBrief(w: HttpWorld, body: JsonObject = brief): Promise<SendResult> {
  return w.a.broker.send(w.ana.agent, { to: "lee@example.org", scope: "alp.briefing/1", type: "request", body });
}

test("cross-broker delivery: Ana's agent at broker-a reaches Lee's agent at broker-b over HTTP, and anyone can verify it from what example.org publishes", async () => {
  await withWorld(async (w) => {
    const sent = expectStatus(await sendBrief(w), "delivered");
    assert.equal(sent.envelope.origin_broker, FED_IDS.a);
    assert.equal(sent.envelope.aud, FED_IDS.b, "addressed to Lee's home broker, found in example.org's document");
    const posts = w.b.server.inboxRequests();
    assert.equal(posts.length, 1);
    assert.equal(posts[0]?.status, 200);
    assert.equal(posts[0]?.inbox?.request_signature, "verified", "the optional RFC 9421 request signature verified too");
    assert.ok(w.exampleAuthority.requests.some((r) => r.path === `/.well-known/${PROTOCOL.wellKnownFile}` && r.status === 200), "real discovery over HTTP");

    const item = (await w.b.broker.inbox(w.lee.agent)).items[0];
    assert.ok(item);
    assert.equal(item.verified.sender.address, ANA);
    assert.equal(item.verified.sender_broker, FED_IDS.a);
    assert.deepEqual(item.content.body, brief);

    // An independent verifier needs only example.org's document and the brokers' published keys.
    const verifier = new HttpsDomainResolver({ fetcher: w.fetcher, clock: w.clock });
    const doc = await verifier.domainDocument("example.org");
    const anaHome = homeBroker(doc, ANA);
    const leeHome = homeBroker(doc, LEE);
    assert.equal(anaHome?.id, FED_IDS.a);
    assert.equal(leeHome?.id, FED_IDS.b);
    assert.ok(anaHome && leeHome);
    assert.equal((await verifyAnyEnvelope(item.envelope, await pinnedFederationKeys(await verifier.jwks(anaHome.jwks_uri), anaHome))).ok, true);
    assert.equal((await verifyReceipt(sent.receipt, await pinnedFederationKeys(await verifier.jwks(leeHome.jwks_uri), leeHome))).ok, true);
  });
});

test("spec 6.7: a to_delegate that names no agent of Lee's waits for Lee at broker-b; broker-a gets the same receipt as for one that exists", async () => {
  await withWorld(async (w) => {
    const send = (label: string) => w.a.broker.send(w.ana.agent, { to: "lee@example.org", to_delegate: `${LEE}/${label}`, scope: "alp.briefing/1", type: "request", body: brief });
    const seen = (r: SendResult) => (r.status === "delivered" ? { status: r.status, receipt: Object.keys(r.receipt).sort(), outcome: r.receipt.status, ledger_hash: typeof r.receipt.ledger_hash } : { status: r.status });
    const toDot = expectStatus(await send("dot"), "delivered");
    const before = w.notifier.sent.length;
    const toNobody = expectStatus(await send("nobody"), "delivered");
    assert.deepEqual(seen(toNobody), seen(toDot));
    const statuses = w.b.server.inboxRequests().map((x) => x.status);
    assert.deepEqual(statuses, [200, 200], "the same HTTP answer");
    const stored = await w.b.broker.store.getMessage(LEE, "in", toNobody.envelope.id);
    assert.equal(stored?.status, "held");
    assert.equal(stored?.held_reason, "to_delegate");
    const ids = (await w.b.broker.inbox(w.lee.agent)).items.map((i) => i.envelope.id);
    assert.deepEqual(ids, [toDot.envelope.id], "Lee's agent gets only the message addressed to it");
    await w.b.broker.settled();
    const notes = w.notifier.sent.slice(before).filter((n) => n.principal === LEE);
    assert.deepEqual(notes.map((n) => n.kind), ["message_held"]);
    assert.equal(/nobody|Q4/.test(notes[0]?.text ?? ""), false, "neither the label nor the message's text");
  });
});

test("a sensitive field is stopped at the sender's broker, and no request of any kind is made", async () => {
  await withWorld(async (w) => {
    const financial = expectStatus(await sendBrief(w, { topic: "Budget", depth: "headline", context: { amount: { value: 1200000, currency: "USD" } } }), "rejected");
    assert.equal(financial.code, "org_policy");
    assert.equal(financial.reasons[0]?.rule, "financial-stays-in-finance");
    const card = expectStatus(await sendBrief(w, { topic: "use 4111 1111 1111 1111", depth: "headline" }), "rejected");
    assert.equal(card.code, "dlp_blocked");
    assert.equal(w.wire().length, 0, "no discovery, no inbox POST: nothing left broker-a");
    assert.equal(w.attempts().length, 0);
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 0);
  });
});

test("a rogue broker claiming ana@example.org is refused at broker-b; Lee's agent and Lee never see it", async () => {
  await withWorld(async (w) => {
    const r = expectStatus(await w.c.broker.send(w.rogueAna, { to: LEE, scope: "alp.briefing/1", type: "request", body: { topic: "Approve the transfer today", depth: "headline" } }), "undeliverable");
    assert.equal(r.code, "broker_not_authorized");
    const post = w.b.server.inboxRequests().at(-1);
    assert.equal(post?.status, 403);
    assert.equal(post?.inbox?.code, "broker_not_authorized");
    assert.equal(post?.inbox?.request_signature, "skipped", "broker-c is not Ana's home broker, so its request key is never looked up");
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 0);
    assert.equal((await w.b.broker.listConnections(w.lee.human())).length, 0, "not even a connection request");
    assert.ok(w.events.events.some((e) => e.detail.event === "broker_not_authorized" && e.detail.broker === FED_IDS.b));

    // Claiming broker-a as the origin while signing with another key fails the pinned-key check (401, unsigned answer).
    const good = expectStatus(await sendBrief(w), "delivered");
    const forged = await signEnvelope({ ...good.envelope, id: "01JC2222222222222222222222", body: { topic: "Approve the transfer today", depth: "headline" } }, await KeyRing.generate(w.clock.now()));
    const res = await postRaw(w.fetcher, INBOX_B, forged);
    assert.equal(res.status, 401);
    assert.equal(res.json.error?.code, "bad_signature");
    assert.equal(res.json.receipt, undefined, "an envelope that fails authentication gets no signed receipt");
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 1);
  });
});

test("a replayed envelope changes nothing (the original receipt comes back); the same id with other content is refused as a replay", async () => {
  await withWorld(async (w) => {
    const sent = expectStatus(await sendBrief(w), "delivered");
    const again = await postRaw(w.fetcher, INBOX_B, sent.envelope);
    assert.equal(again.status, 200);
    assert.equal(again.json.receipt?.id, sent.receipt.id, "a duplicate gets the original receipt (spec 10.3)");
    assert.equal(objectHash(again.json.receipt as never), objectHash(sent.receipt), "byte for byte");

    const altered = await signEnvelope({ ...sent.envelope, body: { ...brief, depth: "detailed" } }, w.a.broker.keys);
    const replay = await postRaw(w.fetcher, INBOX_B, altered);
    assert.equal(replay.status, 409);
    assert.equal(replay.json.error?.code, "replay");
    assert.equal(replay.json.receipt?.code, "replay");
    assert.ok(w.events.events.some((e) => e.detail.event === "replay_refused"));

    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 1, "Lee's agent has exactly one copy");
    const third = await postRaw(w.fetcher, INBOX_B, sent.envelope);
    assert.equal(third.json.receipt?.id, sent.receipt.id, "the replay did not overwrite the original receipt");
  });
});

test("a de-listed broker is refused once the recipient's cached document expires and is refreshed", async () => {
  await withWorld(async (w) => {
    expectStatus(await sendBrief(w), "delivered");
    assert.equal(w.b.resolver.cachedSerial("example.org"), 1);
    // example.org moves Ana to broker-b: broker-a no longer speaks for anyone at example.org (serial 2).
    w.publishExample({ brokers: [w.entry("b", "*")] });
    // Within max_age a peer may still use its cached copy: the spec bounds revocation elsewhere by max_age.
    expectStatus(await sendBrief(w), "delivered");
    w.clock.advance(3601);
    const r = expectStatus(await sendBrief(w), "undeliverable");
    assert.equal(r.code, "broker_not_authorized");
    assert.equal(w.b.resolver.cachedSerial("example.org"), 2);
    assert.equal(w.b.server.inboxRequests().at(-1)?.status, 403);
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 2);
  });
});

test("a domain that publishes no document authorizes no broker: its senders are refused for good, and its addresses can't receive", async () => {
  await withWorld(async (w) => {
    const KIM = "alp:kim@nowhere.example";
    const terms = { may: ["request" as const], disclose: ["/body/topic", "/body/questions/*", "/body/depth"], receive: ["/body/topic", "/body/questions/*", "/body/depth"], commit: "ask_me" as const, redaction: "reject" as const };
    // Sending: Ana has a grant for Kim, but nowhere.example names no home broker for anyone (spec 4.5).
    await w.a.broker.setGrant(w.ana.human(), { counterparty: KIM, scopes: { "alp.briefing/1": terms } });
    const out = expectStatus(await w.a.broker.send(w.ana.agent, { to: "kim@nowhere.example", scope: "alp.briefing/1", type: "request", body: brief }), "undeliverable");
    assert.equal(out.code, "unknown_recipient", "permanent, not the retryable discovery_failed");
    // Receiving: broker-c signs for kim@nowhere.example; broker-b refuses it permanently (vector "sender's domain publishes no document").
    await w.c.broker.registerPrincipal({ address: KIM, identity: { iss: FED_IDS.c, sub: "kim" } });
    const d = await w.c.broker.registerDelegate({ principal: KIM, label: "agent", client_id: w.ana.agent.client_id });
    await w.c.broker.setGrant({ kind: "human", principal: KIM, auth: { method: "reauth-dev", at: w.clock.now().toISOString() } }, { counterparty: LEE, scopes: { "alp.briefing/1": terms } });
    const r = expectStatus(await w.c.broker.send({ kind: "delegate", principal: KIM, delegate: d.id, client_id: w.ana.agent.client_id }, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }), "undeliverable");
    assert.equal(r.code, "broker_not_authorized");
    assert.equal(w.b.server.inboxRequests().at(-1)?.status, 403);
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 0);
  });
});

test("the TXT hint ends the cache early: a higher id makes the recipient refresh before max_age", async () => {
  await withWorld(async (w) => {
    expectStatus(await sendBrief(w), "delivered");
    w.publishExample({ brokers: [w.entry("b", "*")] });
    w.txt.set(`${PROTOCOL.txtLabel}.example.org`, [`v=${PROTOCOL.txtVersion}; id=2`]);
    w.clock.advance(301); // past the 300-second TXT check interval, well inside max_age (3600)
    const r = expectStatus(await sendBrief(w), "undeliverable");
    assert.equal(r.code, "broker_not_authorized");
    assert.ok(w.b.resolver.diagnostics.some((d) => d.event === "txt_hint"));
  });
});

test("a stranger's message becomes a connection request on Lee's broker page; Lee's agent never sees it", async () => {
  await withWorld(async (w) => {
    // Mallory's own broker lets her agent try (her side has a grant); Lee has no relationship with her.
    await w.outside.broker.setGrant(w.mallory.human(), {
      counterparty: LEE,
      scopes: { "alp.briefing/1": { may: ["request"], disclose: ["/body/topic", "/body/questions/*", "/body/depth"], receive: [], commit: "ask_me", redaction: "reject" } },
    });
    const r = expectStatus(await w.outside.broker.send(w.mallory.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }), "refused");
    assert.equal(r.code, "not_accepted", "the recipient never says why (spec 6.8)");
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 0, "Lee's agent sees nothing");
    const incoming = await w.b.broker.listConnections(w.lee.human());
    assert.equal(incoming.length, 1);
    assert.equal(incoming[0]?.counterparty, MALLORY);
    assert.equal(incoming[0]?.origin, "stranger_message");
    assert.equal(incoming[0]?.remote_broker, FED_IDS.outside);
    const n = w.notifier.sent.find((x) => x.principal === LEE && x.kind === "connection_request");
    assert.ok(n, "Lee is told");
    assert.ok(n.link.startsWith(`${FED_IDS.b}/web/connections/`), "the link opens Lee's own broker page");
    assert.doesNotMatch(n.text, /https?:\/\//, "the text holds no link that acts");
  });
});

test("connection_request, connection_response and revoke cross brokers; the revocation stops the other side at its own broker", async () => {
  await withWorld(async (w) => {
    const req = await w.outside.broker.requestConnection(w.mallory.agent, { to: LEE, scopes: ["alp.briefing/1"], purpose: "briefing" });
    assert.equal(req.status, "requested");
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 0);
    const incoming = await w.b.broker.listConnections(w.lee.human());
    assert.equal(incoming[0]?.origin, "explicit");
    assert.ok(incoming[0]);

    await w.b.broker.respondToConnection(w.lee.human(), { request: incoming[0].id, decision: "approve" });
    const mine = req.status === "requested" ? (await w.outside.broker.listConnections(w.mallory.human())).find((c) => c.id === req.request.id) : undefined;
    assert.equal(mine?.state, "approved", "the answer reached Mallory's broker");
    assert.equal((await w.outside.broker.listGrants(w.mallory.human())).find((g) => g.counterparty === LEE)?.status, "pending", "her agent filed it, so she seals it herself");
    await w.outside.broker.sealGrant(w.mallory.human(), { counterparty: LEE });
    expectStatus(await w.outside.broker.send(w.mallory.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }), "delivered");
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 1);

    await w.b.broker.revoke(w.lee.human(), { counterparty: MALLORY });
    assert.deepEqual(w.outside.server.inboxRequests().map((x) => [x.inbox?.type, x.status]), [["connection_response", 200], ["revoke", 200]]);
    const before = w.wire().length;
    const after = expectStatus(await w.outside.broker.send(w.mallory.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: brief }), "rejected");
    assert.equal(after.code, "no_relationship");
    assert.equal(w.wire().length, before, "stopped at Mallory's own broker: nothing on the wire");
  });
});

test("ledgers match: Ana's sent entry carries the hash of the receipt that crossed the wire and points at Lee's entry", async () => {
  await withWorld(async (w) => {
    const sent = expectStatus(await sendBrief(w), "delivered");
    const anaEntries = await w.a.broker.ledger(w.ana.human());
    const s = anaEntries.filter((e) => e.kind === "sent").at(-1);
    const rc = anaEntries.find((e) => e.kind === "receipt" && e.envelope_id === s?.envelope_id);
    const r = (await w.b.broker.ledger(w.lee.human())).find((e) => e.kind === "received");
    assert.ok(s && rc && r);
    assert.deepEqual(crossCheckEntries(s, rc, r, objectHash(sent.receipt)), []);
    assert.equal(rc.receipt_hash, objectHash(sent.receipt));
    assert.equal(sent.receipt.ledger_hash, r.hash);
    assert.equal(rc.counterparty_ledger_hash, r.hash);
    assert.equal(s.envelope_hash, r.envelope_hash);
    assert.equal(s.counterparty_broker, FED_IDS.b);
    assert.equal(r.counterparty_broker, FED_IDS.a);
    assert.equal((await w.a.broker.verifyLedger(w.ana.human())).ok, true);
    assert.equal((await w.b.broker.verifyLedger(w.lee.human())).ok, true);
    // The receipt broker-b serves for this envelope hashes to the value in Ana's ledger.
    const again = await postRaw(w.fetcher, INBOX_B, sent.envelope);
    assert.equal(objectHash(again.json.receipt as never), rc.receipt_hash);
  });
});

test("retries: a 503 with Retry-After is retried, Retry-After is honored, and the message is delivered once", async () => {
  let posts = 0;
  const delays: number[] = [];
  await withWorld(
    async (w) => {
      const sent = expectStatus(await sendBrief(w), "delivered");
      assert.deepEqual(w.a.transport.attempts.map((a) => a.status), [503, 200]);
      assert.ok((delays[0] ?? 0) >= 1000, "waited at least the Retry-After");
      assert.equal(w.b.server.inboxRequests().length, 2);
      assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 1);
      assert.equal(sent.receipt.status, "accepted");
    },
    {
      sleep: async (ms) => {
        delays.push(ms);
      },
      intercept: {
        b: (req) => (req.method === "POST" && posts++ === 0 ? { status: 503, headers: { "retry-after": "1" }, body: { error: { code: "internal", message: "busy" } } } : null),
      },
    },
  );
});

test("the recipient's rate_limited receipt comes over HTTP with its Retry-After, and the refusal carries that wait", async () => {
  await withWorld(async (w) => {
    // Lee's broker takes one briefing request an hour from Ana; the second is refused with a signed receipt (HTTP 429).
    const fields = ["/body/topic", "/body/questions/*", "/body/depth"];
    await w.b.broker.setGrant(w.lee.human(), { counterparty: ANA, scopes: { "alp.briefing/1": { may: ["request", "inform", "ask_human"], disclose: fields, receive: fields, commit: "ask_me", redaction: "reject" } }, rate_limit: { count: 1, per_seconds: 3600 } });
    expectStatus(await sendBrief(w), "delivered");
    const refused = expectStatus(await sendBrief(w), "refused");
    assert.equal(refused.code, "rate_limited");
    const post = w.b.server.inboxRequests().at(-1);
    assert.equal(post?.status, 429);
    assert.equal(refused.retry_after, 60, "the Retry-After Lee's federation inbox sent with the receipt");
  });
});

test("idempotency and TTL: the same envelope is one delivery; an expired envelope is never sent", async () => {
  await withWorld(async (w) => {
    const sent = expectStatus(await sendBrief(w), "delivered");
    const target = { broker: FED_IDS.b, inbox: INBOX_B };
    const before = w.b.server.inboxRequests().length;
    const again = await w.a.transport.deliver(target, sent.envelope);
    assert.equal(again.kind === "receipt" && again.receipt.id, sent.receipt.id);
    assert.equal(w.b.server.inboxRequests().length, before, "the transport reused its receipt");

    // Two concurrent deliveries of a new envelope share one request.
    const now = w.clock.now();
    const fresh = await signEnvelope({ ...sent.envelope, id: "01JC7777777777777777777777", created_at: now.toISOString(), expires_at: new Date(now.getTime() + 3600_000).toISOString() }, w.a.broker.keys);
    const [x, y] = await Promise.all([w.a.transport.deliver(target, fresh), w.a.transport.deliver(target, fresh)]);
    assert.equal(w.b.server.inboxRequests().length, before + 1);
    assert.equal(x.kind === "receipt" && y.kind === "receipt" && x.receipt.id === y.receipt.id, true);

    w.clock.advance(2 * 3600);
    const late: Envelope = await signEnvelope({ ...fresh, id: "01JC8888888888888888888888" }, w.a.broker.keys);
    const res = await w.a.transport.deliver(target, late);
    assert.equal(res.kind === "refused" && res.code, "expired");
    assert.equal(w.b.server.inboxRequests().length, before + 1, "nothing sent past expires_at");
  });
});

test("request signatures at the inbox: a signed request whose body changed is refused before the envelope is read; a reused nonce is refused", async () => {
  await withWorld(async (w) => {
    const sent = expectStatus(await sendBrief(w), "delivered");
    const ring = w.a.httpKeys;
    assert.ok(ring);
    const now = w.clock.now();
    const fresh = await signEnvelope({ ...sent.envelope, id: "01JC6666666666666666666666", created_at: now.toISOString(), expires_at: new Date(now.getTime() + 3600_000).toISOString() }, w.a.broker.keys);
    const body = Buffer.from(JSON.stringify(fresh));
    const headers: Record<string, string> = { "content-type": "application/json", "content-digest": contentDigest(body) };
    const created = Math.floor(now.getTime() / 1000);
    Object.assign(headers, signRequest({ method: "POST", targetUri: INBOX_B, headers }, { kid: ring.kid, privateKey: ring.privateKey(ring.kid) }, { created, expires: created + 300, nonce: "nonce-1" }));

    const changed = await postRaw(w.fetcher, INBOX_B, { ...fresh, note: "added in transit" }, headers);
    assert.equal(changed.status, 401);
    assert.equal(changed.json.error?.code, "bad_signature");
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 1);

    const ok = await postRaw(w.fetcher, INBOX_B, body.toString("utf8"), headers);
    assert.equal(ok.status, 200);
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 2);
    const reused = await postRaw(w.fetcher, INBOX_B, body.toString("utf8"), headers);
    assert.equal(reused.status, 401, "the same signed request twice: the nonce is spent");
    assert.ok(w.events.events.some((e) => e.detail.event === "signature_failure" && e.detail.broker === FED_IDS.b));
  });
});

test("an inbox that requires request signatures refuses an unsigned POST, and still accepts its peers' signed ones", async () => {
  await withWorld(
    async (w) => {
      const sent = expectStatus(await sendBrief(w), "delivered");
      const unsigned = await postRaw(w.fetcher, INBOX_B, await signEnvelope({ ...sent.envelope, id: "01JC9999999999999999999999" }, w.a.broker.keys));
      assert.equal(unsigned.status, 401);
      assert.equal(unsigned.json.error?.code, "bad_signature");
    },
    { requestSignatures: "require" },
  );
});

test("the inbox refuses what isn't one strict JSON envelope: duplicate member names, the wrong content type, an oversize body", async () => {
  await withWorld(async (w) => {
    const dup = await postRaw(w.fetcher, INBOX_B, '{"alp":"0.1","alp":"0.1"}');
    assert.equal(dup.status, 400);
    assert.equal(dup.json.error?.code, "bad_envelope");
    const text = await w.fetcher.request(INBOX_B, { method: "POST", headers: { "content-type": "text/plain" }, body: Buffer.from("{}") });
    assert.equal(text.status, 415);
    const big = await w.fetcher.request(INBOX_B, { method: "POST", headers: { "content-type": "application/json" }, body: Buffer.alloc(1024 * 1024 + 1, 0x20) });
    assert.equal(big.status, 413);
    const get = await w.fetcher.request(INBOX_B, { method: "GET" });
    assert.equal(get.status, 405);
    const jwks = await w.fetcher.getJson(`${FED_IDS.b}${FEDERATION_PATHS.jwks}`);
    assert.equal(Array.isArray((jwks as { keys?: unknown }).keys), true);
    assert.equal((await w.b.broker.inbox(w.lee.agent)).items.length, 0);
  });
});
