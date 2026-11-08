// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run verify-ledger -- <export.json> [<other export.json>]`: checks ledgers exported from the web view
// (/web/ledger.json) offline, with the broker's own functions (spec 11): each file's hash chain (verifyLedger), and, given
// two people's exports, that every message one of them sent and the other's broker accepted is recorded alike on both
// sides (crossCheckEntries: the sent entry, the receipt entry, and the other side's received entry). It reads only the
// files: no broker, no network. Exit status 0 when everything checks, 1 when something doesn't, 2 on a usage error.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { crossCheckEntries, verifyLedger } from "./core/ledger.ts";
import type { LedgerEntry } from "./core/types.ts";

export interface LedgerExport {
  /** The person's address, as the export names it. */
  principal: string;
  entries: LedgerEntry[];
}

/** Reads one export (the web view's ledger.json), or throws saying why it isn't one. */
export function readExport(path: string): LedgerExport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new Error(`${path}: not a JSON file (${err instanceof Error ? err.message.slice(0, 120) : "unreadable"})`);
  }
  const o = parsed as { principal?: unknown; entries?: unknown };
  if (!o || typeof o !== "object" || !Array.isArray(o.entries)) throw new Error(`${path}: not a ledger export (no entries)`);
  return { principal: typeof o.principal === "string" ? o.principal : "", entries: o.entries as LedgerEntry[] };
}

/** Every check, as lines to print, and whether all of them passed. */
export function verifyExports(exports: readonly { path: string; ledger: LedgerExport }[]): { ok: boolean; lines: string[] } {
  const lines: string[] = [];
  let ok = true;
  for (const { path, ledger } of exports) {
    const principalId = ledger.entries[0]?.principal_id ?? "";
    const check = verifyLedger(principalId, ledger.entries);
    if (check.ok) lines.push(`${path} (${ledger.principal}): chain intact, ${check.count} entries`);
    else {
      ok = false;
      lines.push(`${path} (${ledger.principal}): chain broken at entry ${check.seq}: ${check.problem}`);
    }
  }
  const [a, b] = exports;
  if (a && b) {
    let matched = 0;
    for (const [s, r] of [[a, b], [b, a]] as const) {
      const other = r.ledger.principal;
      for (const sent of s.ledger.entries.filter((e) => e.kind === "sent" && e.counterparty === other)) {
        const receipt = s.ledger.entries.find((e) => e.kind === "receipt" && e.envelope_id === sent.envelope_id);
        // Only a message the other side's broker accepted is recorded there as received.
        if (!receipt || receipt.outcome !== "accepted") continue;
        const received = r.ledger.entries.find((e) => e.kind === "received" && e.envelope_id === sent.envelope_id);
        const problems = received ? crossCheckEntries(sent, receipt, received) : [`${r.path} has no received entry`];
        if (problems.length) {
          ok = false;
          lines.push(`message ${sent.envelope_id ?? "?"} from ${s.ledger.principal}: ${problems.join("; ")}`);
        } else matched += 1;
      }
    }
    lines.push(`cross-checked ${matched} message${matched === 1 ? "" : "s"} between the two ledgers`);
  }
  return { ok, lines };
}

function main(argv: string[]): number {
  const paths = argv.slice(2);
  if (paths.length < 1 || paths.length > 2) {
    console.error("usage: npm run verify-ledger -- <export.json> [<other export.json>]");
    return 2;
  }
  let exports: { path: string; ledger: LedgerExport }[];
  try {
    exports = paths.map((path) => ({ path, ledger: readExport(path) }));
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    return 2;
  }
  const r = verifyExports(exports);
  for (const line of r.lines) console.log(line);
  return r.ok ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv);
