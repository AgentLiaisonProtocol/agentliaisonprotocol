#!/usr/bin/env node
// Prints alp-check's text report from its JSON report, then judges a run against the reference broker
// (run-against-reference.sh):
//
//   node tools/check/ci/judge.mjs <report.json> <alp-check's exit code>
//
// The judgement is strict. It exits 1 unless every check in the catalogue passed for the subjects the setup gives
// it (the domain, the broker, and its MCP and REST URLs), except the four checks the setup cannot exercise (EXEMPT),
// which may be skipped. A check listed in EXPECTED_DIFFERENCES may fail or warn instead of passing, and must. Any
// other skip, failure, warning or undecided result fails the judgement, and so do an alp-check error, an exit code
// that differs from the report's, a report on another target, and a host map that does not name both origins.
// Licensed under Apache-2.0.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { toText } from "../report.mjs";
import { CHECKS } from "../catalog.mjs";
import { REPO } from "../spec-text.mjs";

/**
 * Checks the reference broker is expected to fail (or, for a recommended check, warn), each with the entry of
 * KNOWN-GAPS.md ("Where the reference broker and the specification differ") that records the difference. Only a
 * difference recorded there may be listed.
 */
export const EXPECTED_DIFFERENCES = [];

/**
 * The checks the setup cannot exercise: TLS and DNS (loopback through the development host map), and the Retry-After
 * check, which needs a 429 or 503 answer the reference broker gives to none of the probes.
 */
export const EXEMPT = new Set(["document.tls", "dns.txt-grammar", "dns.txt-id-serial", "inbox.retry-after"]);

/** What the setup runs alp-check against. */
export const TARGET = { domain: "example.org", broker: "https://broker.example.org" };

export const GAPS_HEADING = "## Where the reference broker and the specification differ";

/** The subjects a check must have a result for, in a run against TARGET. */
function subjectsOf(c, t) {
  if (c.family === "document" || c.family === "dns") return [t.domain];
  if (["signin.prm", "signin.prm-authorization-server", "signin.prm-scopes"].includes(c.id)) return [`${t.broker}/mcp`, `${t.broker}/rest`];
  return [t.broker];
}

/** Problems with a list of expected differences, given the text of KNOWN-GAPS.md and the check ids that exist. */
export function differenceProblems(list, gapsText, ids) {
  const at = gapsText.indexOf(GAPS_HEADING);
  if (at < 0) return [`KNOWN-GAPS.md has no heading "${GAPS_HEADING.slice(3)}"`];
  const rest = gapsText.slice(at + GAPS_HEADING.length);
  const next = rest.search(/^## /m);
  const section = next < 0 ? rest : rest.slice(0, next);
  const problems = [];
  for (const { check, gap } of list) {
    if (!ids.has(check)) problems.push(`${check} is listed as an expected difference but is no check of alp-check`);
    if (typeof gap !== "string" || !gap || !section.includes(gap)) problems.push(`${check} is listed as an expected difference, but "${gap}" is not in the KNOWN-GAPS.md section "${GAPS_HEADING.slice(3)}"`);
  }
  return problems;
}

/** The text report, from the JSON report of the same run. */
export function textOf(report) {
  return toText({ target: report.target, devMapOrigins: report.dev_map, results: report.results, requestCount: report.requests.count });
}

/** The judgement: { ok, lines }. */
export function judge(report, exitCode, expected = EXPECTED_DIFFERENCES, target = TARGET) {
  const lines = [];
  const problems = [];
  const s = report.summary;
  if (report.target?.domain !== target.domain) problems.push(`the report's target is ${report.target?.domain ?? report.target?.broker ?? "missing"}, not ${target.domain}`);
  const map = Array.isArray(report.dev_map) ? report.dev_map : [];
  for (const origin of [`https://${target.domain}`, target.broker]) if (!map.includes(origin)) problems.push(`the development host map does not name ${origin}`);
  if (exitCode !== s.exit_code) problems.push(`alp-check exited ${exitCode}, but its report gives exit code ${s.exit_code}`);
  if (s.exit_code === 2 || s.exit_code === 3 || s.alp_check_errors > 0) problems.push(`alp-check failed itself (exit code ${s.exit_code}, ${s.alp_check_errors} errors)`);
  const listed = new Map(expected.map((e) => [e.check, e.gap]));
  const undecided = [];
  for (const r of report.results) {
    const where = `${r.id ?? r.family ?? "alp-check"} [${r.subject ?? "no subject"}]`;
    if (r.result === "pass") continue;
    if (r.result === "error") { problems.push(`${where}: alp-check's own error: ${r.message}`); continue; }
    if (r.inconclusive) { undecided.push(where); continue; }
    if (r.result === "skip") {
      if (!EXEMPT.has(r.id)) problems.push(`${where} was skipped (${r.reason}), and only ${[...EXEMPT].join(", ")} may be`);
      continue;
    }
    const did = r.result === "fail" ? "failed" : "warned";
    if (listed.has(r.id)) lines.push(`expected difference: ${where} ${did} (KNOWN-GAPS.md: ${listed.get(r.id)})`);
    else problems.push(`${where} ${did}, and no recorded difference covers it`);
  }
  if (undecided.length || s.required_skipped_after_undecided) problems.push(`checks could not be decided against a broker on the same machine, which points at the setup: ${undecided.join(", ") || `${s.required_skipped_after_undecided} skipped after an undecided check`}`);
  // Every check, for each subject the setup gives it, has a result; anything but a pass was judged above.
  for (const c of CHECKS) {
    if (EXEMPT.has(c.id)) continue;
    for (const subject of subjectsOf(c, target)) {
      if (!report.results.some((r) => r.id === c.id && r.subject === subject)) problems.push(`${c.id} has no result for ${subject}`);
    }
  }
  for (const [id, gap] of listed) {
    if (!report.results.some((r) => r.id === id && (r.result === "fail" || (r.result === "warn" && !r.inconclusive)))) problems.push(`${id} is listed as an expected difference (${gap}) but did not fail or warn: remove it from the list`);
  }
  const passed = report.results.filter((r) => r.result === "pass").length;
  if (passed === 0) problems.push("no check passed");
  lines.push(...problems.map((p) => `problem: ${p}`));
  lines.push(problems.length ? "The run against the reference broker has problems (above)." : "The run against the reference broker matches what is expected: every check passed except those the setup cannot exercise.");
  return { ok: problems.length === 0, lines };
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const [file, code] = process.argv.slice(2);
  if (!file || code === undefined || !/^[0-9]+$/.test(code)) {
    process.stderr.write("usage: node tools/check/ci/judge.mjs <report.json> <alp-check's exit code>\n");
    process.exit(2);
  }
  const report = JSON.parse(fs.readFileSync(file, "utf8"));
  process.stdout.write(`${textOf(report)}\n`);
  const { ok, lines: judged } = judge(report, Number(code));
  const gaps = differenceProblems(EXPECTED_DIFFERENCES, fs.readFileSync(path.join(REPO, "KNOWN-GAPS.md"), "utf8"), new Set(CHECKS.map((c) => c.id)));
  const lines = [...gaps.map((p) => `problem: ${p}`), ...judged];
  if (gaps.length) lines[lines.length - 1] = "The run against the reference broker has problems (above).";
  process.stdout.write(`\nAgainst the reference broker\n${lines.map((l) => `  ${l}`).join("\n")}\n`);
  process.exitCode = ok && !gaps.length ? 0 : 1;
}
