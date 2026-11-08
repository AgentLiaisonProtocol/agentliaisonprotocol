// SPDX-License-Identifier: FSL-1.1-ALv2
// One conformance suite, run against every Store implementation: memory, file, and Postgres (PGlite, Postgres compiled
// to WebAssembly and run in this process behind the wire-protocol bridge on a loopback port from the tests' pool, or a
// real database with ALP_TEST_POSTGRES_URL).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildLedgerEntry } from "../core/ledger.ts";
import type { Store } from "../core/interfaces.ts";
import type { DeferredNotice, HeldOutbound, MessageRecord, PrincipalRecord } from "../core/types.ts";
import { FileStore } from "./file.ts";
import { MemoryStore } from "./memory.ts";
import { startPgliteBridge } from "./pglite-bridge.ts";

const now = new Date("2026-11-09T14:00:00.000Z");
const ana: PrincipalRecord = { principal_id: "ana-principal-00001", address: "alp:ana@example.org", identity: { iss: "https://idp.example", sub: "a1" }, status: "active", created_at: now.toISOString() };

function msg(local: string, id: string, extra: Partial<MessageRecord> = {}): MessageRecord {
  return {
    local_id: local,
    principal: ana.address,
    direction: "in",
    envelope: { id, thread: "01JCT00000000000000000000T", to: { address: ana.address } } as MessageRecord["envelope"],
    envelope_hash: "sha256:x",
    status: "delivered",
    acked_by: {},
    stored_at: now.toISOString(),
    ...extra,
  };
}

async function conformance(name: string, make: () => Store | Promise<Store>): Promise<void> {
  await test(`${name}: principals by address, id and identity; retired aliases are skipped`, async () => {
    const s = await make();
    await s.putPrincipal(ana);
    assert.equal((await s.getPrincipal(ana.address))?.principal_id, ana.principal_id);
    assert.equal((await s.getPrincipalByIdentity("https://idp.example", "a1"))?.address, ana.address);
    await s.putPrincipal({ ...ana, status: "retired" });
    assert.equal(await s.getPrincipal(ana.address), null);
    assert.equal((await s.getPrincipalById(ana.principal_id))?.status, "retired");
  });
  await test(`${name}: records are copies`, async () => {
    const s = await make();
    await s.putPrincipal(ana);
    const got = (await s.getPrincipal(ana.address))!;
    got.display_name = "changed";
    assert.equal((await s.getPrincipal(ana.address))?.display_name, undefined);
  });
  await test(`${name}: a thread's messages newest first, with a before cursor (alp_thread reads the newest first)`, async () => {
    const s = await make();
    for (const k of ["A", "B", "C", "D", "E"]) await s.putMessage(msg(`01JCL00000000000000000000${k}`, `01JCE00000000000000000000${k}`));
    await s.putMessage(msg("01JCL00000000000000000000F", "01JCE00000000000000000000F", { envelope: { id: "01JCE00000000000000000000F", thread: "01JCT0000000000000000OTHER", to: { address: ana.address } } as MessageRecord["envelope"] }));
    const thread = "01JCT00000000000000000000T";
    const newest = await s.listMessages(ana.address, { thread, order: "desc", limit: 2 });
    assert.deepEqual(newest.map((m) => m.local_id.slice(-1)), ["E", "D"]);
    const older = await s.listMessages(ana.address, { thread, order: "desc", limit: 2, before: "01JCL00000000000000000000D" });
    assert.deepEqual(older.map((m) => m.local_id.slice(-1)), ["C", "B"]);
    const oldest = await s.listMessages(ana.address, { thread, limit: 10, before: "01JCL00000000000000000000C" });
    assert.deepEqual(oldest.map((m) => m.local_id.slice(-1)), ["A", "B"], "before works in ascending order too");
  });
  await test(`${name}: message paging, cursors, acks and delegate addressing`, async () => {
    const s = await make();
    await s.putMessage(msg("01JCL00000000000000000000A", "01JCE00000000000000000000A"));
    await s.putMessage(msg("01JCL00000000000000000000B", "01JCE00000000000000000000B", { acked_by: { "alp:ana@example.org/muse": now.toISOString() } }));
    await s.putMessage(msg("01JCL00000000000000000000C", "01JCE00000000000000000000C", { envelope: { id: "01JCE00000000000000000000C", thread: "t", to: { address: ana.address, delegate: "alp:ana@example.org/other" } } as MessageRecord["envelope"] }));
    const all = await s.listMessages(ana.address, { direction: "in", limit: 10 });
    assert.deepEqual(all.map((m) => m.local_id.slice(-1)), ["A", "B", "C"]);
    const after = await s.listMessages(ana.address, { direction: "in", limit: 10, after: "01JCL00000000000000000000A" });
    assert.deepEqual(after.map((m) => m.local_id.slice(-1)), ["B", "C"]);
    const muse = await s.listMessages(ana.address, { direction: "in", limit: 10, unackedBy: "alp:ana@example.org/muse", forDelegate: "alp:ana@example.org/muse" });
    assert.deepEqual(muse.map((m) => m.local_id.slice(-1)), ["A"]);
  });
  await test(`${name}: a binding's start hides what an earlier binding with the label received or acknowledged (spec 5.4)`, async () => {
    const s = await make();
    const muse = "alp:ana@example.org/muse";
    const at = (m: number): string => new Date(now.getTime() + m * 60_000).toISOString();
    const to = (id: string): MessageRecord["envelope"] => ({ id, thread: "t", to: { address: ana.address, delegate: muse } }) as MessageRecord["envelope"];
    await s.putMessage(msg("01JCL00000000000000000000D", "01JCE00000000000000000000D", { envelope: to("01JCE00000000000000000000D"), stored_at: at(-10) }));
    await s.putMessage(msg("01JCL00000000000000000000E", "01JCE00000000000000000000E", { envelope: to("01JCE00000000000000000000E"), stored_at: at(10) }));
    await s.putMessage(msg("01JCL00000000000000000000F", "01JCE00000000000000000000F", { acked_by: { [muse]: at(-5) } }));
    await s.putMessage(msg("01JCL00000000000000000000G", "01JCE00000000000000000000G", { acked_by: { [muse]: at(5) } }));
    const page = await s.listMessages(ana.address, { direction: "in", limit: 10, forDelegate: muse, unackedBy: muse, bindingSince: now.toISOString() });
    assert.deepEqual(page.map((m) => m.local_id.slice(-1)), ["E", "F"], "D was the earlier binding's; G this binding acknowledged; F only the earlier one");
    const all = await s.listMessages(ana.address, { direction: "in", limit: 10, forDelegate: muse });
    assert.deepEqual(all.map((m) => m.local_id.slice(-1)), ["D", "E", "F", "G"]);
  });
  await test(`${name}: a held message leaves pending once: of two claims at once, one wins`, async () => {
    const s = await make();
    const held: HeldOutbound = { id: "01JCH00000000000000000000A", principal: ana.address, to: "alp:lee@example.org", scope: "alp.briefing/1", type: "request", body: {}, thread: "01JCT00000000000000000000T", reason: "review", state: "pending", created_at: now.toISOString(), expires_at: now.toISOString() };
    await s.putHeldOutbound(held);
    const claims = await Promise.all([s.claimHeldOutbound({ ...held, state: "sending" }), s.claimHeldOutbound({ ...held, state: "discarded" })]);
    assert.deepEqual(claims.filter(Boolean).length, 1);
    const stored = await s.getHeldOutbound(ana.address, held.id);
    assert.equal(stored?.state, claims[0] ? "sending" : "discarded");
    assert.equal(await s.claimHeldOutbound({ ...held, state: "expired" }), false, "only a pending record is replaced");
    assert.equal(await s.claimHeldOutbound({ ...held, id: "01JCH00000000000000000000B" }), false, "nor one that doesn't exist");
    // An approval that failed leaves `sending` the same way, and only from `sending`.
    const from = claims[0] ? "sending" : "discarded";
    assert.equal(await s.claimHeldOutbound(held, from === "sending" ? "discarded" : "sending"), false);
    assert.equal(await s.claimHeldOutbound(held, from), true);
    assert.equal((await s.getHeldOutbound(ana.address, held.id))?.state, "pending");
  });
  await test(`${name}: notifications deferred to the end of quiet hours are taken once due, earliest first, each by one caller`, async () => {
    const s = await make();
    const at = (m: number): string => new Date(now.getTime() + m * 60_000).toISOString();
    const notice = (id: string, due: string): DeferredNotice => ({ id, principal: ana.address, principal_id: ana.principal_id, envelope_id: `01JCE0000000000000000000${id.slice(-2)}`, due_at: due });
    await s.putDeferredNotice(notice("01JCN000000000000000000N0C", at(60)));
    await s.putDeferredNotice(notice("01JCN000000000000000000N0B", at(0)));
    await s.putDeferredNotice(notice("01JCN000000000000000000N0A", at(0)));
    await s.putDeferredNotice(notice("01JCN000000000000000000N0D", at(-30)));
    assert.deepEqual((await s.takeDueNotices(now, 2)).map((n) => n.id.slice(-1)), ["D", "A"], "the earliest due first, then by id, at most the limit");
    const [one, other] = await Promise.all([s.takeDueNotices(now, 10), s.takeDueNotices(now, 10)]);
    assert.deepEqual([...one, ...other].map((n) => n.id.slice(-1)), ["B"], "of two takes at once, one gets it");
    assert.deepEqual(await s.takeDueNotices(now, 10), [], "C isn't due yet");
    assert.deepEqual(await s.takeDueNotices(new Date(now.getTime() + 60 * 60_000), 10), [notice("01JCN000000000000000000N0C", at(60))], "due at its time, and returned whole");
    assert.deepEqual(await s.takeDueNotices(new Date(now.getTime() + 120 * 60_000), 10), [], "and taken once");
  });
  await test(`${name}: the ledger appends atomically and keeps payloads apart`, async () => {
    const s = await make();
    const e1 = await s.appendLedger(ana.principal_id, (h) => buildLedgerEntry(ana, h, now.toISOString(), { kind: "sent", outcome: "allowed" }, { note: "n" }));
    const e2 = await s.appendLedger(ana.principal_id, (h) => buildLedgerEntry(ana, h, now.toISOString(), { kind: "received", outcome: "accepted" }));
    assert.equal(e2.prev_hash, e1.hash);
    assert.equal(e1.seq, 0, "seq starts at 0 (spec 11.2)");
    assert.deepEqual(await s.getLedgerPayload(ana.principal_id, e1.seq), { note: "n" });
    await s.eraseLedgerPayload(ana.principal_id, e1.seq);
    assert.equal(await s.getLedgerPayload(ana.principal_id, e1.seq), null);
    assert.equal((await s.listLedger(ana.principal_id, { afterSeq: e1.seq })).length, 1);
    await assert.rejects(s.appendLedger(ana.principal_id, () => ({ entry: { ...e2, seq: 7 } })));
  });
  await test(`${name}: concurrent appends still form one chain`, async () => {
    const s = await make();
    const at = now.toISOString();
    await Promise.all(Array.from({ length: 12 }, () => s.appendLedger(ana.principal_id, (h) => buildLedgerEntry(ana, h, at, { kind: "grant_set", outcome: "info" }))));
    const entries = await s.listLedger(ana.principal_id);
    assert.deepEqual(entries.map((e) => e.seq), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    for (let i = 1; i < entries.length; i++) assert.equal(entries[i]?.prev_hash, entries[i - 1]?.hash);
  });
  await test(`${name}: replay window and rate limits`, async () => {
    const s = await make();
    assert.equal(await s.recordOnce("k", "2026-11-09T15:00:00.000Z", now), true);
    assert.equal(await s.recordOnce("k", "2026-11-09T15:00:00.000Z", now), false);
    assert.equal(await s.recordOnce("k", "2026-11-09T17:00:00.000Z", new Date("2026-11-09T16:00:00.000Z")), true, "an expired entry can be reused");
    assert.equal((await s.hitRateLimit("r", now, 60, 2)).allowed, true);
    assert.equal((await s.hitRateLimit("r", now, 60, 2)).allowed, true);
    assert.equal((await s.hitRateLimit("r", now, 60, 2)).allowed, false);
    assert.equal((await s.hitRateLimit("r", new Date(now.getTime() + 61_000), 60, 2)).allowed, true);
    // A refused hit says when the oldest hit in the window leaves it: then the next one is allowed.
    assert.equal((await s.hitRateLimit("w", now, 60, 1)).retryAfter, 60);
    const refused = await s.hitRateLimit("w", new Date(now.getTime() + 15_000), 60, 1);
    assert.deepEqual(refused, { allowed: false, count: 1, retryAfter: 45 });
    assert.equal((await s.hitRateLimit("w", new Date(now.getTime() + 60_001), 60, 1)).allowed, true);
    assert.deepEqual(await s.hitRateLimit("empty", now, 60, 0), { allowed: false, count: 0, retryAfter: 0 });
  });
}

await conformance("memory", () => new MemoryStore());

// The Postgres store runs the same suite, on PGlite unless a database is given (ALP_TEST_POSTGRES_URL=postgres://...).
// Each test gets a schema of its own, dropped at the end.
const external = process.env["ALP_TEST_POSTGRES_URL"];
const bridge = external ? undefined : await startPgliteBridge();
const pgUrl = external ?? bridge?.url ?? "";
{
  const { createPostgresStore } = await import("./postgres.ts");
  const stores: { close(): Promise<void>; sql: { unsafe(q: string): Promise<unknown> } }[] = [];
  const schemas: string[] = [];
  await conformance(external ? "postgres" : "postgres (PGlite)", async () => {
    const schema = `alp_test_${process.pid}_${schemas.length}`;
    schemas.push(schema);
    const s = await createPostgresStore({ url: pgUrl, schema, max: 2 });
    stores.push(s);
    return s;
  });
  test("postgres: drop the test schemas", async () => {
    const first = stores[0];
    for (const schema of schemas) await first?.sql.unsafe(`drop schema if exists ${schema} cascade`);
    for (const s of stores) await s.close();
    await bridge?.close();
  });
}
const dirs: string[] = [];
process.on("exit", () => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
await conformance("file", () => {
  const d = mkdtempSync(join(tmpdir(), "alp-store-"));
  dirs.push(d);
  return new FileStore(d);
});

test("file store: state survives a restart; keys live in a separate 0600 file", async () => {
  const d = mkdtempSync(join(tmpdir(), "alp-store-"));
  dirs.push(d);
  const a = new FileStore(d);
  await a.putPrincipal(ana);
  await a.putKeyRing("broker", { version: 1, keys: [] });
  await a.close();
  const b = new FileStore(d);
  assert.equal((await b.getPrincipal(ana.address))?.principal_id, ana.principal_id);
  assert.deepEqual(await b.getKeyRing("broker"), { version: 1, keys: [] });
  assert.equal(statSync(join(d, "keys.json")).mode & 0o777, 0o600);
  assert.equal(statSync(join(d, "state.json")).mode & 0o777, 0o600);
});
