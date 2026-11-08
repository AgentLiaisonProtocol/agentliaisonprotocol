// SPDX-License-Identifier: FSL-1.1-ALv2
// Every conformance vector in <repo>/vectors, run through the reference broker's own code paths (spec Appendix B,
// conformance requirement BC-25). A failure here is a bug in the reference or in the vector.

import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { sep } from "node:path";
import { describe, test } from "node:test";
import type { SendInput } from "../core/api.ts";
import { sanitizeText } from "../core/content.ts";
import { checkDomainDocument, homeBroker, jwkThumbprint, parseTxtRecord, pinnedFederationKeys } from "../core/domain.ts";
import { checkEnvelopeStructure, objectHash, verifyAnyEnvelope, verifyRatification, verifyReceipt } from "../core/envelope.ts";
import { hashJson } from "../core/hash.ts";
import { canonicalize } from "../core/jcs.ts";
import { signDetached, verifyDetached } from "../core/jws.ts";
import type { JwsTyp } from "../core/jws.ts";
import { crossCheckEntries, payloadFor, verifyLedger } from "../core/ledger.ts";
import { termsHash } from "../core/ratification.ts";
import { ScopeRegistry, freeTextPatterns, validateBody } from "../core/scopes/index.ts";
import { scopeSemantics, windowRequestId } from "../core/scopes/semantics.ts";
import { MAX_THREAD_MESSAGES, applyToThread, expireIfDue } from "../core/threads.ts";
import type { ThreadMessage } from "../core/threads.ts";
import type { Attestation, Constraints, DelegateCaller, DelegateClass, Envelope, Jwk, JsonObject, LedgerEntry, MessageType, Ratification, Receipt, RelationshipGrant, ThreadRecord } from "../core/types.ts";
import { agentMayRead } from "../core/visibility.ts";
import { parseStrictJson } from "../federation/strict-json.ts";
import { CURRENT_DOCS, VECTOR_DIR, readVector, seedSeen, testKeyRing, vectorBroker, world } from "./vector-world.ts";

const registry = ScopeRegistry.load();
const ORG = "https://broker.example.org";

/** The keys example.org pins for its broker (example.org@42), from the published JWKS. */
async function exampleOrgKeys() {
  const doc = checkDomainDocument(structuredClone(world.domain_documents["example.org@42"]), "example.org");
  const entry = doc.brokers.find((b) => b.id === ORG);
  assert.ok(entry);
  return pinnedFederationKeys(world.jwks[entry.jwks_uri], entry, []);
}

describe("vectors/jcs", () => {
  const v = readVector<{ cases: { name: string; input_text: string; expected?: string; expected_error?: string }[] }>("jcs/jcs.json");
  for (const c of v.cases) {
    test(c.name, () => {
      if (c.expected_error !== undefined) assert.throws(() => canonicalize(parseStrictJson(c.input_text)));
      else assert.equal(canonicalize(parseStrictJson(c.input_text)), c.expected);
    });
  }
});

describe("vectors/signatures", () => {
  const jkt = readVector<{ cases: { name: string; jwk: Jwk; expected_jkt: string }[] }>("signatures/jkt.json");
  for (const c of jkt.cases) test(`jkt: ${c.name}`, async () => assert.equal(await jwkThumbprint(c.jwk), c.expected_jkt));

  const jws = readVector<{ cases: { name: string; key: string; typ: JwsTyp; object: JsonObject; verify_only?: boolean; broker_sig?: string; expected?: { jcs: string; protected_header: JsonObject; broker_sig: string; envelope_hash?: string } }[] }>("signatures/detached-jws.json");
  for (const c of jws.cases) {
    test(`detached JWS: ${c.name}`, async () => {
      if (c.verify_only) {
        const owner = Object.entries(world.jwks).flatMap(([, set]) => set.keys).filter((k) => k.kid !== undefined);
        const r = await verifyDetached(c.object, String(c.broker_sig), c.typ, { keys: owner });
        assert.equal(r.ok, true, JSON.stringify(r));
        return;
      }
      assert.ok(c.expected);
      assert.equal(canonicalize(c.object), c.expected.jcs);
      const sig = await signDetached(c.object, c.typ, testKeyRing(c.key));
      assert.equal(sig, c.expected.broker_sig, "Ed25519 is deterministic: the exact broker_sig");
      assert.deepEqual(JSON.parse(Buffer.from(sig.split(".")[0] ?? "", "base64url").toString("utf8")), c.expected.protected_header);
      if (c.expected.envelope_hash) assert.equal(objectHash({ ...c.object, broker_sig: sig } as unknown as Envelope), c.expected.envelope_hash);
      assert.equal((await verifyDetached(c.object, sig, c.typ, testKeyRing(c.key).jwks())).ok, true);
    });
  }
});

describe("vectors/envelope/validity", () => {
  const v = readVector<{ cases: { name: string; object?: unknown; raw_text?: string; expected: { valid: boolean; code?: string } }[] }>("envelope/validity.json");
  for (const c of v.cases) {
    test(c.name, () => {
      let value: unknown;
      try {
        value = c.raw_text !== undefined ? parseStrictJson(c.raw_text) : c.object;
      } catch {
        assert.equal(c.expected.valid, false);
        assert.equal(c.expected.code, "bad_envelope", "a strict-parse failure is bad_envelope");
        return;
      }
      const r = checkEnvelopeStructure(value);
      assert.equal(r.ok, c.expected.valid, r.ok ? "valid" : `${r.code}: ${r.detail}`);
      if (!r.ok) assert.equal(r.code, c.expected.code);
    });
  }
});

describe("vectors/scopes/bodies", () => {
  const v = readVector<{ cases: { scope: string; type: MessageType; body: unknown; valid: boolean }[] }>("scopes/bodies.json");
  v.cases.forEach((c, i) => {
    test(`${i}: ${c.scope} ${c.type} ${c.valid ? "valid" : "invalid"}`, () => {
      const scope = registry.require(c.scope);
      const errors = validateBody(scope, c.type, c.body);
      assert.equal(errors.length === 0, c.valid, JSON.stringify(errors));
    });
  });
});

describe("vectors/domain/resolution", () => {
  const v = readVector<{
    documents: { name: string; document: unknown; expected: { valid: boolean } }[];
    resolution: { document: string | JsonObject; address: string; expected_home: string | null }[];
    txt: { record: string; valid: boolean; id?: string }[];
  }>("domain/resolution.json");
  for (const c of v.documents) {
    test(`document: ${c.name}`, () => {
      const domain = (c.document as { domain?: string }).domain ?? "";
      let valid = true;
      try {
        checkDomainDocument(structuredClone(c.document), domain);
      } catch {
        valid = false;
      }
      assert.equal(valid, c.expected.valid);
    });
  }
  for (const c of v.resolution) {
    const doc = typeof c.document === "string" ? world.domain_documents[c.document] : c.document;
    test(`home broker of ${c.address} in ${typeof c.document === "string" ? c.document : "an inline document"}`, () => {
      const checked = checkDomainDocument(structuredClone(doc), String((doc as { domain: string }).domain));
      assert.equal(homeBroker(checked, c.address)?.id ?? null, c.expected_home);
    });
  }
  for (const c of v.txt) {
    test(`TXT ${c.record}`, () => {
      const r = parseTxtRecord(c.record);
      assert.equal(r !== null, c.valid);
      if (c.valid) assert.equal(r?.id, c.id);
    });
  }
});

describe("vectors/federation/acceptance (steps 0 to 6)", () => {
  const v = readVector<{
    now: string;
    cases: {
      name: string;
      context: { receiving_broker: string; served_domains: Record<string, string>; domain_documents: Record<string, string>; last_seen_serial?: Record<string, number>; seen?: { origin_broker: string; id: string; envelope_hash: string; expires_at: string }[]; now?: string };
      request_body: string;
      expected: { result: string; code?: string; step?: number; typ?: string; home_broker?: string };
    }[];
  }>("federation/acceptance.json");
  for (const c of v.cases) {
    test(c.name, async () => {
      const vb = await vectorBroker({ id: c.context.receiving_broker, domains: Object.keys(c.context.served_domains), now: c.context.now ?? v.now, docs: c.context.domain_documents, lastSeen: c.context.last_seen_serial ?? {} });
      for (const s of c.context.seen ?? []) await seedSeen(vb, s);
      // The federation inbox parses the request body once, strictly (spec 8.3), before acceptance.
      let parsed: unknown;
      try {
        parsed = parseStrictJson(c.request_body);
      } catch {
        assert.deepEqual({ result: "refused", code: "bad_envelope", step: 0 }, c.expected);
        return;
      }
      const a = await vb.broker.authenticateInbound(parsed);
      let got: Record<string, unknown>;
      if (a.kind === "authenticated") got = { result: "authenticated", typ: a.typ, home_broker: a.home_broker };
      else if (a.result.kind === "receipt" && a.result.duplicate) got = { result: "duplicate" };
      else got = { result: "refused", code: a.result.kind === "receipt" ? a.result.receipt.code : a.result.code, step: a.result.step };
      assert.deepEqual(got, c.expected);
    });
  }
});

describe("vectors/policy/sender (spec 6.6)", () => {
  const v = readVector<{
    now: string;
    cases: { name: string; caller: { principal: string; principal_id: string; delegate: string; client_id: string; attestation: "self" | "vendor" | "native" | "tenant"; class: "consumer" | "business" | "enterprise" }; draft: SendInput; grants: RelationshipGrant[]; expected: Record<string, unknown> }[];
  }>("policy/sender.json");
  for (const c of v.cases) {
    test(c.name, async () => {
      const vb = await vectorBroker({ id: ORG, domains: ["example.org"], now: v.now, grants: c.grants });
      // The caller's delegate binding, with the client it signed in with.
      await vb.store.putDelegate({ id: c.caller.delegate, principal: c.caller.principal, principal_id: c.caller.principal_id, label: c.caller.delegate.slice(c.caller.delegate.lastIndexOf("/") + 1), kind: "bridged", client_id: c.caller.client_id, attestation: c.caller.attestation, class: c.caller.class, status: "active", created_at: v.now });
      const caller: DelegateCaller = { kind: "delegate", principal: c.caller.principal, delegate: c.caller.delegate, client_id: c.caller.client_id };
      const got = await vb.broker.evaluateSend(caller, c.draft, { skipThreadChecks: true });
      assert.deepEqual(got, c.expected);
    });
  }
});

describe("vectors/policy/recipient (spec 6.7)", () => {
  const v = readVector<{
    now: string;
    cases: { name: string; recipient: string; broker_capabilities?: { deliver_to?: boolean; no_training?: boolean; retention_max?: boolean }; envelope: Envelope; grants: RelationshipGrant[]; state: { recent?: number }; now?: string; expected: { outcome: string; code?: string; contact_attempt?: boolean; delivery?: string; hold_until?: string } }[];
  }>("policy/recipient.json");
  for (const c of v.cases) {
    test(c.name, async () => {
      const vb = await vectorBroker({ id: ORG, domains: ["example.org"], now: c.now ?? v.now, grants: c.grants, ...(c.broker_capabilities ? { extra: { constraintSupport: c.broker_capabilities } } : {}) });
      const recipient = await vb.store.getPrincipal(c.recipient);
      assert.ok(recipient);
      const e = c.envelope;
      // Messages already accepted in the rate-limit window.
      for (let i = 0; i < (c.state.recent ?? 0); i++) await vb.store.hitRateLimit(`in|${recipient.principal_id}|${e.from.address}`, vb.clock.now(), 3600, 1_000_000);
      // A reply needs the message it answers: the recipient's broker holds it with the hash the reply names.
      if (e.in_reply_to && e.in_reply_to_hash) {
        const at = vb.clock.now().toISOString();
        const original: Envelope = { ...e, id: e.in_reply_to, from: { address: e.to.address, principal_id: recipient.principal_id }, to: { address: e.from.address }, type: "request", body: {}, broker_sig: "" };
        delete (original as Partial<Envelope>).in_reply_to;
        delete (original as Partial<Envelope>).in_reply_to_hash;
        await vb.store.putMessage({ local_id: "01M7090000000000000000000A", principal: c.recipient, direction: "out", envelope: original, envelope_hash: e.in_reply_to_hash, status: "delivered", acked_by: {}, stored_at: at });
        const thread: ThreadRecord = { id: e.thread, principal: c.recipient, counterparty: e.from.address, scope: e.scope, state: "open", created_at: at, updated_at: at, expires_at: e.expires_at, history: [] };
        await vb.store.putThread(thread);
      }
      const r = await vb.broker.acceptInbound(structuredClone(e));
      assert.equal(r.kind, "receipt", JSON.stringify(r));
      if (r.kind !== "receipt") return;
      const got: Record<string, unknown> = { outcome: r.receipt.status === "accepted" ? "accepted" : "refused" };
      if (r.receipt.status === "refused") {
        got["code"] = r.receipt.code;
        const attempts = (await vb.store.listConnections(c.recipient)).filter((x) => x.origin === "stranger_message" && x.direction === "incoming");
        if (attempts.length) got["contact_attempt"] = true;
      } else {
        const m = await vb.store.getMessage(c.recipient, "in", e.id);
        got["delivery"] = m?.status === "held" ? (m.held_until ? "hold_until" : "hold_for_web_view") : "deliver";
        if (m?.held_until) got["hold_until"] = m.held_until.replace(/\.000Z$/, "Z");
      }
      assert.deepEqual(got, c.expected);
    });
  }
});

describe("vectors/federation/connection-requests (spec 6.2.2)", () => {
  const v = readVector<{ now: string; cases: { name: string; request_body: string; expected: { status: "accepted" | "refused"; code?: string; ledger_hash?: false } }[] }>("federation/connection-requests.json");
  for (const c of v.cases) {
    test(c.name, async () => {
      const vb = await vectorBroker({ id: ORG, domains: ["example.org"], now: v.now });
      const r = await vb.broker.acceptInbound(parseStrictJson(c.request_body));
      assert.equal(r.kind, "receipt", JSON.stringify(r));
      if (r.kind !== "receipt") return;
      assert.equal(r.receipt.status, c.expected.status);
      if (c.expected.code !== undefined) assert.equal(r.receipt.code, c.expected.code);
      if (c.expected.ledger_hash === false) assert.equal(r.receipt.ledger_hash, undefined, "no ledger hash: it would tell a real address from an unknown one");
    });
  }
});

describe("vectors/delivery/visibility (spec 5.4, 6.11, 12.1.4)", () => {
  type Msg = { id: string; direction: "in" | "out"; status: "delivered" | "held"; held_until?: string; stored_at?: string; created_at?: string; to_delegate?: string; from_delegate?: string; constraints?: Constraints };
  const v = readVector<{ now: string; cases: { name: string; reader: { delegate: string; attestation: Attestation; class: DelegateClass; client: { no_training?: boolean; retention_days?: number }; since?: string }; messages: Msg[]; expected: { visible: string[] } }[] }>("delivery/visibility.json");
  for (const c of v.cases) {
    test(c.name, () => {
      const reader = { id: c.reader.delegate, attestation: c.reader.attestation, class: c.reader.class, ...(c.reader.since ? { since: c.reader.since } : {}) };
      const visible = c.messages
        .filter((m) => agentMayRead({ direction: m.direction, status: m.status, ...(m.held_until ? { held_until: m.held_until } : {}), ...(m.stored_at ? { stored_at: m.stored_at } : {}), envelope: { from: m.from_delegate ? { delegate: m.from_delegate } : {}, to: m.to_delegate ? { delegate: m.to_delegate } : {}, ...(m.constraints ? { constraints: m.constraints } : {}), ...(m.created_at ? { created_at: m.created_at } : {}) } }, reader, c.reader.client, new Date(v.now)))
        .map((m) => m.id);
      assert.deepEqual(visible, c.expected.visible);
    });
  }
});

describe("vectors/threads/meeting-commit (spec 9)", () => {
  const v = readVector<{ now: string; objects: { propose: Envelope; accept: Envelope; ratification_ana: Ratification; ack_ratified_lee: Envelope; commit: Envelope }; expected: { terms_hash: string; states: string[]; ratifications: string[] } }>("threads/meeting-commit.json");
  const o = v.objects;
  test("every object verifies with the keys example.org pins", async () => {
    const keys = await exampleOrgKeys();
    for (const e of [o.propose, o.accept, o.ack_ratified_lee, o.commit]) assert.equal((await verifyAnyEnvelope(e, keys)).ok, true, e.type);
    assert.equal((await verifyRatification(o.ratification_ana, keys)).ok, true);
    const lee = o.ack_ratified_lee.body["ratification"] as unknown as Ratification;
    assert.equal((await verifyRatification(lee, keys)).ok, true);
  });
  test("replies chain by hash, terms_hash covers body.terms, the accept fixes a proposed slot", () => {
    assert.equal(o.accept.in_reply_to_hash, objectHash(o.propose));
    assert.equal(o.ack_ratified_lee.in_reply_to_hash, objectHash(o.accept));
    assert.equal(termsHash(o.accept.body["terms"] as JsonObject), v.expected.terms_hash);
    assert.equal(o.accept.terms_hash, v.expected.terms_hash);
    assert.equal(o.commit.terms_hash, v.expected.terms_hash);
    assert.equal(scopeSemantics("alp.meeting/1", "accept", o.accept.body, { type: "propose", body: o.propose.body }), null);
  });
  test("both ratification records bind the thread and the terms; the commit references both", () => {
    const lee = o.ack_ratified_lee.body["ratification"] as unknown as Ratification;
    for (const r of [o.ratification_ana, lee]) {
      assert.equal(r.thread, o.propose.thread);
      assert.equal(r.terms_hash, v.expected.terms_hash);
      assert.equal(r.iat, Math.floor(Date.parse(r.created_at) / 1000));
    }
    assert.deepEqual([objectHash(o.ratification_ana), objectHash(lee)].sort(), v.expected.ratifications);
    assert.deepEqual(o.commit.ratifications, v.expected.ratifications);
  });
  test("the thread states follow the reference's state machine", () => {
    const scope = registry.require("alp.meeting/1");
    const ana = o.propose.from.address;
    const lee = o.propose.to.address;
    const lr = o.ack_ratified_lee.body["ratification"] as unknown as Ratification;
    const msg = (e: Envelope, dir: "in" | "out", replyTo?: Envelope): ThreadMessage => ({
      thread: e.thread,
      principal: ana,
      counterparty: lee,
      scope: e.scope,
      envelope_id: e.id,
      type: e.type,
      direction: dir,
      at: e.created_at,
      expires_at: e.expires_at,
      ...(e.in_reply_to ? { in_reply_to: e.in_reply_to } : {}),
      ...(replyTo ? { reply_to: { type: replyTo.type, direction: replyTo.from.address === ana ? ("out" as const) : ("in" as const) } } : {}),
      ...(e.terms_hash ? { terms_hash: e.terms_hash } : {}),
      ...(e.ratifications ? { ratifications: e.ratifications } : {}),
      ...(e.type === "ack" ? { ack_status: e.body["status"] as "ratified" } : {}),
    });
    const now = new Date(v.now);
    const states: string[] = [];
    let t: ThreadRecord | null = null;
    for (const [e, dir, replyTo] of [[o.propose, "out", undefined], [o.accept, "in", o.propose], [o.ack_ratified_lee, "in", o.accept]] as const) {
      const r = applyToThread(scope, t, msg(e, dir, replyTo), now);
      assert.ok(r.ok, r.ok ? "" : r.detail);
      t = r.thread;
      states.push(t.state);
    }
    // Ana's broker holds both records (hers, and Lee's from the ack) before her agent commits.
    t = { ...(t as ThreadRecord), ratifications: { mine: { id: o.ratification_ana.id, hash: objectHash(o.ratification_ana), record: o.ratification_ana }, theirs: { id: lr.id, hash: objectHash(lr), record: lr } } };
    const r = applyToThread(scope, t, msg(o.commit, "out", o.accept), now);
    assert.ok(r.ok, r.ok ? "" : r.detail);
    states.push(r.thread.state);
    assert.deepEqual(states, v.expected.states);
  });
});

describe("vectors/threads/conversations (spec 9.2, 9.3)", () => {
  type Turn = { id: string; by: "ana" | "lee"; type: MessageType; in_reply_to?: string; status?: "received" | "completed" | "ratified"; terms?: string; ratified?: ("ana" | "lee")[]; ratified_until?: string; body?: JsonObject; at: string; expires_at: string; expected: { outcome: "accepted" | "refused"; code?: string; state: string | null } };
  const v = readVector<{ principals: { ana: string; lee: string }; max_thread_messages: number; cases: { name: string; scope: string; turns: Turn[] }[] }>("threads/conversations.json");
  test("the vectors' thread limit is the reference's", () => assert.equal(v.max_thread_messages, MAX_THREAD_MESSAGES));
  // Ana's broker's copy of each thread: Ana's turns go out, Lee's come in. Each turn gets an envelope id of its own.
  const envelopeId = (caseIndex: number, turnIndex: number): string => `01M709C${String(caseIndex).padStart(2, "0")}T${String(turnIndex).padStart(3, "0")}0000000000000`;
  const hash = (who: "ana" | "lee"): string => `sha256:ratification-of-${who}`;
  v.cases.forEach((c, ci) => {
    test(c.name, () => {
      const scope = registry.require(c.scope);
      const ids = new Map<string, { envelope_id: string; type: MessageType; direction: "in" | "out"; body?: JsonObject }>();
      let t: ThreadRecord | null = null;
      c.turns.forEach((turn, ti) => {
        const at = new Date(turn.at);
        const direction = turn.by === "ana" ? ("out" as const) : ("in" as const);
        const answered = turn.in_reply_to !== undefined ? ids.get(turn.in_reply_to) : undefined;
        // The ratification records the broker holds when it evaluates a commit, and the commit references them.
        if (t && turn.type === "commit") {
          const held = turn.ratified ?? [];
          const record = { expires_at: turn.ratified_until ?? "2027-01-01T00:00:00.000Z" } as Ratification;
          t = { ...t, ratifications: { ...(held.includes("ana") ? { mine: { id: "mine", hash: hash("ana"), record } } : {}), ...(held.includes("lee") ? { theirs: { id: "theirs", hash: hash("lee"), record } } : {}) } };
        }
        const msg: ThreadMessage = {
          thread: "01M709C00THREAD0000000000T",
          principal: v.principals.ana,
          counterparty: v.principals.lee,
          scope: c.scope,
          envelope_id: envelopeId(ci, ti),
          type: turn.type,
          direction,
          at: at.toISOString(),
          expires_at: new Date(turn.expires_at).toISOString(),
          // A reply to a message the broker doesn't hold names an id it can't find.
          ...(turn.in_reply_to !== undefined ? { in_reply_to: answered?.envelope_id ?? "01M709C9900000000000000000" } : {}),
          ...(answered ? { reply_to: { type: answered.type, direction: answered.direction } } : {}),
          ...(turn.terms !== undefined ? { terms_hash: `sha256:terms-${turn.terms}` } : {}),
          ...(turn.type === "commit" ? { ratifications: (turn.ratified ?? []).map(hash).sort() as [string, string] } : {}),
          ...(turn.status !== undefined ? { ack_status: turn.status } : {}),
        };
        const r = applyToThread(scope, t, msg, at);
        let refusal: { code: string; detail: string } | null = r.ok ? null : { code: r.code, detail: r.detail };
        if (r.ok && turn.body) {
          // Step 9's semantic rules, as the broker runs them: the message answered, and the request an availability
          // inform keeps to, looked up in this copy of the thread.
          const windowId = c.scope === "alp.availability/1" && turn.type === "inform" ? windowRequestId(t?.history ?? [], msg) : undefined;
          const window = windowId === undefined ? undefined : windowId === null ? null : ([...ids.values()].find((x) => x.envelope_id === windowId)?.body ?? null);
          const semantic = scopeSemantics(c.scope, turn.type, turn.body, answered?.body ? { type: answered.type, body: answered.body } : undefined, window);
          if (semantic) refusal = { code: "schema_invalid", detail: semantic };
        }
        if (r.ok && !refusal) {
          t = r.thread;
          ids.set(turn.id, { envelope_id: msg.envelope_id, type: turn.type, direction, ...(turn.body ? { body: turn.body } : {}) });
        }
        const state = t ? expireIfDue(t, at).state : null;
        const got = refusal ? { outcome: "refused", code: refusal.code, state } : { outcome: "accepted", state };
        assert.deepEqual(got, turn.expected, `turn ${ti + 1} (${turn.by} ${turn.type}): ${refusal ? refusal.detail : "accepted"}`);
      });
    });
  });
});

describe("vectors/ledger/matching-ledgers (spec 11.5)", () => {
  const v = readVector<{ envelope: Envelope; receipt: Receipt; ledgers: Record<string, LedgerEntry[]> }>("ledger/matching-ledgers.json");
  const pat = v.ledgers["alp:pat@partner.example"] ?? [];
  const lee = v.ledgers["alp:lee@example.org"] ?? [];
  test("both chains verify", () => {
    assert.deepEqual(verifyLedger(String(pat[0]?.principal_id), pat).ok, true);
    assert.deepEqual(verifyLedger(String(lee[0]?.principal_id), lee).ok, true);
  });
  test("the sent, receipt and received entries cross-check through the signed receipt", async () => {
    const sent = pat.find((e) => e.kind === "sent");
    const rc = pat.find((e) => e.kind === "receipt");
    const recv = lee.find((e) => e.kind === "received");
    assert.ok(sent && rc && recv);
    assert.deepEqual(crossCheckEntries(sent, rc, recv, objectHash(v.receipt)), []);
    assert.equal(v.receipt.ledger_hash, recv.hash);
    assert.equal(sent.envelope_hash, objectHash(v.envelope));
    assert.equal((await verifyReceipt(v.receipt, await exampleOrgKeys())).ok, true);
  });
  test("both sides compute the same payload, and its hash is the one in both entries", () => {
    const scope = registry.require(v.envelope.scope);
    const payload = payloadFor(v.envelope.body, v.envelope.note, freeTextPatterns(scope, v.envelope.type));
    for (const e of [...pat, ...lee].filter((x) => x.kind === "sent" || x.kind === "received")) assert.equal(hashJson(payload), e.payload_hash);
  });
});

describe("vectors/delivery/sanitize (spec 12.1.6)", () => {
  const v = readVector<{ cases: { name: string; input: string; expected: string }[] }>("delivery/sanitize.json");
  for (const c of v.cases) test(c.name, () => assert.equal(sanitizeText(c.input), c.expected));
});

test("every vector file is exercised here", () => {
  const covered = new Set(["jcs/jcs.json", "signatures/detached-jws.json", "signatures/jkt.json", "envelope/validity.json", "scopes/bodies.json", "domain/resolution.json", "policy/sender.json", "policy/recipient.json", "federation/acceptance.json", "federation/connection-requests.json", "threads/meeting-commit.json", "threads/conversations.json", "ledger/matching-ledgers.json", "delivery/sanitize.json", "delivery/visibility.json", "world.json", "keys/TEST-ONLY-private-keys.json"]);
  const files = readdirSync(VECTOR_DIR, { recursive: true }).map(String).filter((f) => f.endsWith(".json")).map((f) => f.split(sep).join("/"));
  assert.deepEqual(files.filter((f) => !covered.has(f)), [], "a new vector file needs a runner here");
  assert.ok(CURRENT_DOCS["example.org"]);
});
