// SPDX-License-Identifier: FSL-1.1-ALv2
// Per-principal, append-only ledger, chained over entry digests (spec 11). `seq` starts at 0.
// Values, notes and free text live in a separate payload, a JSON object mapping envelope-relative pointers to their
// values; the entry carries only its digest (payload_hash), so a payload can be erased (crypto-shredding) without
// breaking the chain. Matching ledgers (spec 11.5): the sender's `sent` entry and the recipient's `received` entry
// carry the same envelope hash; the receipt carries the recipient entry's hash as `ledger_hash`; the sender's
// `receipt` entry carries the receipt's hash and the recipient's entry hash. Each entry carries a random `salt` (spec
// 11.4): the sender knows or can guess every other member of the recipient's entry, and without it could confirm from
// `ledger_hash` what the entry records (whether the message waits for the person, say) or what came before it.

import { randomBytes } from "node:crypto";
import { hashJson } from "./hash.ts";
import { getAt, leafPointers, matchPattern } from "./pointers.ts";
import { ALP_VERSION } from "./protocol.ts";
import type { Address, JsonObject, LedgerEntry, LedgerHead, LedgerPayload, PrincipalId } from "./types.ts";

export type LedgerFields = Omit<LedgerEntry, "alp" | "principal" | "principal_id" | "seq" | "at" | "salt" | "prev_hash" | "hash" | "payload_hash">;

/** A new entry's salt: 16 bytes (128 bits) from the system's secure random source, unpadded base64url (spec 11.4). */
export function newSalt(): string {
  return randomBytes(16).toString("base64url");
}

function dropUndefined<T extends object>(o: T): T {
  return JSON.parse(JSON.stringify(o)) as T;
}

function isEmpty(p: LedgerPayload | undefined): boolean {
  return !p || Object.keys(p).length === 0;
}

export function buildLedgerEntry(
  who: { address: Address; principal_id: PrincipalId },
  head: LedgerHead | null,
  at: string,
  fields: LedgerFields,
  payload?: LedgerPayload,
): { entry: LedgerEntry; payload?: LedgerPayload } {
  const keep = isEmpty(payload) ? undefined : dropUndefined(payload as LedgerPayload);
  const base = dropUndefined({
    alp: ALP_VERSION,
    principal: who.address,
    principal_id: who.principal_id,
    seq: head ? head.seq + 1 : 0,
    at,
    ...fields,
    ...(keep ? { payload_hash: hashJson(keep) } : {}),
    salt: newSalt(),
    prev_hash: head ? head.hash : null,
  });
  const entry = { ...base, hash: hashJson(base) } as LedgerEntry;
  return keep ? { entry, payload: keep } : { entry };
}

export type LedgerCheck = { ok: true; count: number; head: LedgerHead | null } | { ok: false; seq: number; problem: string };

/** Walk the chain. Payloads, when given, must match their digests; missing (erased) payloads are fine. */
export function verifyLedger(principalId: PrincipalId, entries: LedgerEntry[], payloads?: Map<number, LedgerPayload>): LedgerCheck {
  let prev: LedgerHead | null = null;
  for (const e of entries) {
    const { hash, ...rest } = e;
    if (e.principal_id !== principalId) return { ok: false, seq: e.seq, problem: "entry belongs to another principal" };
    if (e.seq !== (prev ? prev.seq + 1 : 0)) return { ok: false, seq: e.seq, problem: "sequence gap" };
    if (e.prev_hash !== (prev ? prev.hash : null)) return { ok: false, seq: e.seq, problem: "chain broken (prev_hash)" };
    if (hashJson(rest) !== hash) return { ok: false, seq: e.seq, problem: "entry was altered (hash)" };
    const p = payloads?.get(e.seq);
    if (p && hashJson(p) !== e.payload_hash) return { ok: false, seq: e.seq, problem: "payload does not match payload_hash" };
    prev = { seq: e.seq, hash };
  }
  return { ok: true, count: entries.length, head: prev };
}

/**
 * Problems found matching two ledgers for one envelope ([] = they match): the sender's `sent` entry, the sender's
 * `receipt` entry and the recipient's `received` entry (spec 11.5). `receiptHash` is the hash of the receipt itself
 * when the caller holds it, so the receipt entry can be checked against it too.
 */
export function crossCheckEntries(sent: LedgerEntry, receiptEntry: LedgerEntry, received: LedgerEntry, receiptHash?: string): string[] {
  const problems: string[] = [];
  if (sent.kind !== "sent") problems.push("the first entry is not a sent entry");
  if (receiptEntry.kind !== "receipt") problems.push("the second entry is not a receipt entry");
  if (received.kind !== "received") problems.push("the third entry is not a received entry");
  if (sent.envelope_id !== received.envelope_id || receiptEntry.envelope_id !== sent.envelope_id) problems.push("different envelopes");
  if (!sent.envelope_hash || sent.envelope_hash !== received.envelope_hash) problems.push("envelope hashes differ");
  if (receiptEntry.counterparty_ledger_hash !== received.hash) problems.push("the receipt does not point at the recipient's entry");
  if (receiptHash !== undefined && receiptEntry.receipt_hash !== receiptHash) problems.push("the receipt entry does not carry the receipt's hash");
  if (sent.counterparty !== received.principal || received.counterparty !== sent.principal) problems.push("parties differ");
  return problems;
}

/**
 * A message's ledger payload (spec 11.4): envelope-relative pointers mapped to their values. `free_text` (the
 * default) keeps the free-text leaves (`freeText` patterns) and the note; `all` keeps every leaf; `never` nothing.
 * Both sides compute it from the same envelope, so the two ledgers' payload hashes match.
 */
export function payloadFor(body: JsonObject, note: string | undefined, freeText: readonly string[], storeValues: "never" | "free_text" | "all" = "free_text"): LedgerPayload | undefined {
  if (storeValues === "never") return undefined;
  const out: LedgerPayload = {};
  for (const p of Object.keys(body).length ? leafPointers(body, ["body"]) : []) {
    const isText = freeText.some((ft) => matchPattern(ft, p) && ft.split("/").length === p.split("/").length);
    if (storeValues === "all" || isText) {
      const v = getAt(body, p.slice("/body".length));
      if (v !== undefined) out[p] = v;
    }
  }
  if (note !== undefined) out["/note"] = note;
  return Object.keys(out).length ? out : undefined;
}
