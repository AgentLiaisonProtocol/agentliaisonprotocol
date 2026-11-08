// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run verify-ledger`: two people's exported ledgers verify offline, and an altered entry is caught.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { ANA, LEE, buildWorld } from "./demo/world.ts";
import { verifyExports } from "./verify-ledger.ts";
import type { LedgerExport } from "./verify-ledger.ts";

const dir = mkdtempSync(join(tmpdir(), "alp-verify-ledger-"));
after(() => rmSync(dir, { recursive: true, force: true }));

function run(...files: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done) => {
    execFile(process.execPath, [fileURLToPath(new URL("./verify-ledger.ts", import.meta.url)), ...files], { timeout: 30_000 }, (err, stdout, stderr) =>
      done({ code: err ? Number((err as { code?: unknown }).code ?? 1) : 0, stdout, stderr }));
  });
}

test("two exported ledgers verify offline and cross-check; an altered entry or a missing received entry is caught", async () => {
  const w = await buildWorld({ domainDocs: false });
  for (const topic of ["Q4", "Q1"]) {
    const r = await w.example.send(w.ana.agent, { to: LEE, scope: "alp.briefing/1", type: "request", body: { topic, depth: "headline" } });
    assert.equal(r.status, "delivered");
  }
  const ana: LedgerExport = { principal: ANA, entries: await w.example.ledger(w.ana.human()) };
  const lee: LedgerExport = { principal: LEE, entries: await w.example.ledger(w.lee.human()) };
  writeFileSync(join(dir, "ana.json"), JSON.stringify({ principal: ANA, exported_at: "2026-11-09T14:00:00Z", entries: ana.entries }));
  writeFileSync(join(dir, "lee.json"), JSON.stringify({ principal: LEE, exported_at: "2026-11-09T14:00:00Z", entries: lee.entries }));

  const good = await run(join(dir, "ana.json"), join(dir, "lee.json"));
  assert.equal(good.code, 0, good.stdout + good.stderr);
  assert.match(good.stdout, /ana\.json \(alp:ana@example\.org\): chain intact, \d+ entries/);
  assert.match(good.stdout, /cross-checked 2 messages between the two ledgers/);
  assert.equal((await run(join(dir, "ana.json"))).code, 0, "one file: its chain only");

  // An entry altered after the fact breaks the chain.
  const altered = structuredClone(lee.entries);
  if (altered[0]) altered[0].scope = "alp.status/1";
  const broken = verifyExports([{ path: "lee.json", ledger: { principal: LEE, entries: altered } }]);
  assert.equal(broken.ok, false);
  assert.match(broken.lines[0] ?? "", /chain broken at entry 0: entry was altered \(hash\)/);
  // A received entry missing from the other side's export.
  const partial = verifyExports([{ path: "ana.json", ledger: ana }, { path: "lee.json", ledger: { principal: LEE, entries: lee.entries.slice(0, 1) } }]);
  assert.equal(partial.ok, false);
  assert.ok(partial.lines.some((l) => /lee\.json has no received entry/.test(l)), partial.lines.join("\n"));

  writeFileSync(join(dir, "nonsense.json"), "{");
  const usage = await run(join(dir, "nonsense.json"));
  assert.equal(usage.code, 2);
  assert.match(usage.stderr, /not a JSON file/);
});
