// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildLedgerEntry, crossCheckEntries, verifyLedger } from "./ledger.ts";
import { schemaErrors } from "./spec-schemas.ts";
import type { LedgerEntry, LedgerPayload } from "./types.ts";

const who = { address: "alp:ana@example.org", principal_id: "ana-principal-00001" };

function chain(): { entries: LedgerEntry[]; payloads: Map<number, LedgerPayload> } {
  const entries: LedgerEntry[] = [];
  const payloads = new Map<number, LedgerPayload>();
  let head = null;
  for (let i = 0; i < 3; i++) {
    const { entry, payload } = buildLedgerEntry(who, head, `2026-11-09T14:00:0${i}.000Z`, { kind: "sent", outcome: "allowed", counterparty: "alp:lee@example.org" }, i === 1 ? { note: "hello" } : undefined);
    entries.push(entry);
    if (payload) payloads.set(entry.seq, payload);
    head = { seq: entry.seq, hash: entry.hash };
  }
  return { entries, payloads };
}

test("entries chain over digests, validate against the spec schema, and payloads sit apart", () => {
  const { entries, payloads } = chain();
  for (const e of entries) assert.deepEqual(schemaErrors("ledgerEntry", e), []);
  assert.ok(entries[1]!.payload_hash);
  assert.equal(JSON.stringify(entries[1]).includes("hello"), false);
  assert.deepEqual(verifyLedger(who.principal_id, entries, payloads), { ok: true, count: 3, head: { seq: 2, hash: entries[2]!.hash } });
  // An erased payload keeps the chain valid; an altered one does not.
  assert.equal(verifyLedger(who.principal_id, entries, new Map()).ok, true);
  assert.equal(verifyLedger(who.principal_id, entries, new Map([[1, { note: "changed" }]])).ok, false);
});

test("tampering, reordering and gaps are caught", () => {
  const { entries } = chain();
  const altered = structuredClone(entries);
  altered[1]!.counterparty = "alp:mallory@outside.example";
  assert.deepEqual(verifyLedger(who.principal_id, altered), { ok: false, seq: 1, problem: "entry was altered (hash)" });
  assert.equal(verifyLedger(who.principal_id, [entries[0]!, entries[2]!]).ok, false);
  assert.equal(verifyLedger("someone-else-00001", entries).ok, false);
});

test("cross-check: the sender's sent and receipt entries against the recipient's received entry (spec 11.5)", () => {
  const sent = buildLedgerEntry(who, null, "2026-11-09T14:00:00.000Z", { kind: "sent", outcome: "allowed", counterparty: "alp:lee@example.org", envelope_id: "01JC0000000000000000000000", envelope_hash: `sha256:${"a".repeat(43)}` }).entry;
  const recv = buildLedgerEntry({ address: "alp:lee@example.org", principal_id: "lee-principal-00001" }, null, "2026-11-09T14:00:00.000Z", { kind: "received", outcome: "accepted", counterparty: who.address, envelope_id: "01JC0000000000000000000000", envelope_hash: `sha256:${"a".repeat(43)}` }).entry;
  const head = { seq: sent.seq, hash: sent.hash };
  const fields = { kind: "receipt" as const, outcome: "accepted" as const, counterparty: "alp:lee@example.org", envelope_id: "01JC0000000000000000000000", envelope_hash: `sha256:${"a".repeat(43)}`, receipt_hash: `sha256:${"b".repeat(43)}` };
  const lost = buildLedgerEntry(who, head, "2026-11-09T14:00:01.000Z", fields).entry;
  assert.ok(crossCheckEntries(sent, lost, recv).includes("the receipt does not point at the recipient's entry"));
  const rc = buildLedgerEntry(who, head, "2026-11-09T14:00:01.000Z", { ...fields, counterparty_ledger_hash: recv.hash }).entry;
  assert.deepEqual(crossCheckEntries(sent, rc, recv, `sha256:${"b".repeat(43)}`), []);
  assert.equal(sent.seq, 0, "seq starts at 0 (spec 11.2)");
});
