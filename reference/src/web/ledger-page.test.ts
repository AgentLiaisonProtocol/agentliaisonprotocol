// SPDX-License-Identifier: FSL-1.1-ALv2
// The person's ledger on the web view: the page lists the newest entries under the whole ledger's count, and the export
// has every entry. Before, both took the oldest (1,000 on the page, 10,000 in the export), so refused sends from a
// looping or hostile agent pushed the person's own entries out of both.

import assert from "node:assert/strict";
import { test } from "node:test";
import { buildLedgerEntry } from "../core/ledger.ts";
import { Browser, TEST_SECRET, startTestBroker } from "../mcp/testkit.ts";

test("more than 1,000 entries (memory store): the newest 1,000 on the page under the true count, and all of them in the export", async () => {
  const t = await startTestBroker();
  try {
    const ana = (await t.dev.broker.store.getPrincipal("alp:ana@example.org"))!;
    const at = new Date().toISOString();
    for (let i = 0; i < 1200; i++) await t.dev.store.appendLedger(ana.principal_id, (h) => buildLedgerEntry(ana, h, at, { kind: "refused_outbound", outcome: "rejected", code: "schema_invalid" }));
    await t.dev.store.appendLedger(ana.principal_id, (h) => buildLedgerEntry(ana, h, at, { kind: "grant_set", outcome: "info" }));
    const b = new Browser();
    assert.equal((await b.request(`${t.web}/web/login`, { form: { username: "ana", secret: TEST_SECRET } })).status, 303);

    const page = await (await b.request(`${t.web}/web/ledger`)).text();
    assert.match(page, /1,201 entries, showing the newest 1,000; the export has all of them\. Chain: <strong>intact<\/strong>/);
    const seqs = [...page.matchAll(/<tr><td>(\d+)<\/td>/g)].map((m) => Number(m[1]));
    assert.equal(seqs.length, 1000);
    assert.equal(seqs[0], 1200, "the newest first: the person's own entry after the refusals");
    assert.equal(Math.min(...seqs), 201, "the oldest 201 are left out of the page");

    const exported = (await (await b.request(`${t.web}/web/ledger.json`)).json()) as { entries: { seq: number }[] };
    assert.equal(exported.entries.length, 1201, "the export has every entry");
    assert.deepEqual([exported.entries[0]?.seq, exported.entries.at(-1)?.seq], [0, 1200]);
  } finally {
    await t.close();
  }
});
