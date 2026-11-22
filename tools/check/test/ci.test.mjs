// The scripts that run alp-check against the reference broker in CI (ci/): the domain document they build from a
// broker's key set, and the judgement of a run.
import "./guard.mjs";
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { jkt } from "../../spec/lib.mjs";
import { runChecks, parseArgs } from "../check.mjs";
import { toJson } from "../report.mjs";
import { schemas } from "../checks/common.mjs";
import { REPO } from "../spec-text.mjs";
import { buildDomainDocument } from "../ci/domain-document.mjs";
import { judge, textOf, EXPECTED_DIFFERENCES, EXEMPT, GAPS_HEADING, differenceProblems } from "../ci/judge.mjs";
import { createFakeBroker } from "./fake-broker.mjs";

const B = "https://broker.example.org";

test("the CI domain document is valid, names the broker at the reference's paths and pins every key in its key set", () => {
  const { jwks } = createFakeBroker();
  const set = jwks[B];
  const doc = buildDomainDocument({ jwks: set, brokerId: B, domain: "example.org" });
  const validate = schemas().document;
  assert.ok(validate(doc), JSON.stringify(validate.errors));
  assert.equal(doc.domain, "example.org");
  const [entry] = doc.brokers;
  assert.equal(entry.id, B);
  assert.equal(entry.inbox, `${B}/federation/inbox`);
  assert.equal(entry.jwks_uri, `${B}/.well-known/jwks.json`);
  assert.equal(entry.principals, "*");
  assert.deepEqual(entry.jkt, set.keys.map((k) => jkt(k)));
});

test("the CI domain document refuses an empty key set, more keys than an entry may pin, and an id that is not an https origin", () => {
  const { jwks } = createFakeBroker();
  const key = jwks[B].keys[0];
  assert.throws(() => buildDomainDocument({ jwks: { keys: [] }, brokerId: B, domain: "example.org" }), /no keys/);
  const five = Array.from({ length: 5 }, (_, i) => ({ ...key, x: Buffer.alloc(32, i + 1).toString("base64url") }));
  assert.throws(() => buildDomainDocument({ jwks: { keys: five }, brokerId: B, domain: "example.org" }), /at most 4/);
  assert.throws(() => buildDomainDocument({ jwks: jwks[B], brokerId: "http://broker.example.org", domain: "example.org" }), /https origin/);
});

const H = "https://hosted.example.net";
const D = "example.org";
/** The development host map a test run uses: as in CI, plus the fake's second broker. */
const DEV = { "https://example.org": "http://127.0.0.1:47101", [B]: "http://127.0.0.1:47102", [H]: "http://127.0.0.1:47103" };

/** A JSON report of a run against the fake through a development host map, as CI runs alp-check. */
async function reportOn(faults, extra = [], map = DEV) {
  const back = new Map(Object.entries(map).map(([k, v]) => [v, k]));
  const fake = createFakeBroker({ faults });
  const fetch = (url, init) => {
    const u = new URL(url);
    return fake.fetch(back.get(u.origin) + u.pathname + u.search, init);
  };
  const run = await runChecks(parseArgs([D, "--dev-map", JSON.stringify(map), ...extra]), { fetch, resolveTxt: fake.resolveTxt });
  return toJson(run);
}
const problemsOf = (j) => j.lines.filter((l) => l.startsWith("problem: ")).join("\n");

test("a run in which every check passes, except the four the setup cannot exercise, is judged ok, and its text report is printed", async () => {
  const report = await reportOn([]);
  assert.deepEqual([...new Set(report.results.filter((r) => r.result === "skip").map((r) => r.id))].sort(), [...EXEMPT].filter((id) => id !== "inbox.retry-after").sort());
  const j = judge(report, report.summary.exit_code, []);
  assert.equal(j.ok, true, j.lines.join("\n"));
  assert.match(textOf(report), /No required check failed and none was left undecided\./);
});

test("the checks the setup cannot exercise are exactly document.tls, the two DNS checks and inbox.retry-after", () => {
  assert.deepEqual([...EXEMPT].sort(), ["dns.txt-grammar", "dns.txt-id-serial", "document.tls", "inbox.retry-after"]);
});

test("a failure no recorded difference covers fails the judgement; a listed one does not", async () => {
  const report = await reportOn(["inbox-no-schema"]);
  assert.equal(judge(report, 1, []).ok, false);
  assert.match(problemsOf(judge(report, 1, [])), /inbox\.schema \[https:\/\/broker\.example\.org\] failed, and no recorded difference covers it/);
  // The fault touches both brokers; a listed difference covers the check for every subject.
  const listed = judge(report, 1, [{ check: "inbox.schema", gap: "an entry" }]);
  assert.equal(listed.ok, true, listed.lines.join("\n"));
});

test("a recommended check that warns fails the judgement unless it is a listed difference", async () => {
  const report = await reportOn(["no-revocation-endpoint"]);
  assert.equal(report.summary.exit_code, 0);
  const j = judge(report, 0, []);
  assert.equal(j.ok, false);
  assert.match(problemsOf(j), /signin\.revocation \[https:\/\/broker\.example\.org\] warned, and no recorded difference covers it/);
  assert.equal(judge(report, 0, [{ check: "signin.revocation", gap: "an entry" }]).ok, true);
});

test("a listed difference that no longer fails fails the judgement, so the list cannot go stale", async () => {
  const report = await reportOn([]);
  const j = judge(report, 0, [{ check: "inbox.schema", gap: "an entry" }]);
  assert.equal(j.ok, false);
  assert.match(problemsOf(j), /inbox\.schema is listed as an expected difference .* but did not fail or warn/);
});

test("a required check that could not be decided, or an exit code that differs from the report, fails the judgement", async () => {
  const busy = await reportOn(["inbox-rate-limited"]);
  assert.equal(busy.summary.exit_code, 4);
  assert.equal(judge(busy, 4, []).ok, false);
  const clean = await reportOn([]);
  assert.equal(judge(clean, 1, []).ok, false);
});

test("an inbox that answers every unsigned probe 401 fails the judgement, although alp-check exits 0", async () => {
  const report = await reportOn(["inbox-requires-signed-requests"]);
  assert.equal(report.summary.exit_code, 0);
  const j = judge(report, 0, []);
  assert.equal(j.ok, false);
  assert.match(problemsOf(j), /inbox\.version \[https:\/\/broker\.example\.org\] was skipped \(this inbox answers unsigned requests with 401/);
});

test("a report with one family skipped fails the judgement", async () => {
  const report = await reportOn([], ["--no-inbox-probes"]);
  assert.equal(report.summary.exit_code, 0);
  const j = judge(report, 0, []);
  assert.equal(j.ok, false);
  assert.match(problemsOf(j), /inbox\.error-shape \[https:\/\/broker\.example\.org\] was skipped \(--no-inbox-probes was given\)/);
});

test("a report whose host map leaves out the broker, or whose target is another domain, fails the judgement", async () => {
  const onlyDomain = await reportOn([], [], { "https://example.org": DEV["https://example.org"] });
  assert.equal(onlyDomain.summary.exit_code, 0, "every broker request is refused locally, so alp-check itself finds nothing wrong");
  const j = judge(onlyDomain, 0, []);
  assert.equal(j.ok, false);
  assert.match(problemsOf(j), /the development host map does not name https:\/\/broker\.example\.org/);
  assert.match(problemsOf(j), /keys\.served \[https:\/\/broker\.example\.org\] was skipped/);
  const other = await reportOn([]);
  other.target = { domain: "example.net" };
  assert.match(problemsOf(judge(other, 0, [])), /the report's target is example\.net, not example\.org/);
});

test("a check with no result for an expected subject fails the judgement", async () => {
  const report = await reportOn([]);
  report.results = report.results.filter((r) => !(r.id === "binding.rest-challenge" && r.subject === B));
  assert.match(problemsOf(judge(report, 0, [])), /binding\.rest-challenge has no result for https:\/\/broker\.example\.org/);
});

test("the expected differences are checked against KNOWN-GAPS.md: the heading exists, each check exists and each entry is in that section", async () => {
  const gaps = fs.readFileSync(`${REPO}/KNOWN-GAPS.md`, "utf8");
  assert.ok(gaps.includes(GAPS_HEADING), "KNOWN-GAPS.md has the heading");
  const ids = new Set((await reportOn([])).results.map((r) => r.id));
  assert.deepEqual(differenceProblems(EXPECTED_DIFFERENCES, gaps, ids), []);
  // A sample list, so the comparison is exercised while the real list is empty.
  const section = gaps.slice(gaps.indexOf(GAPS_HEADING));
  const entry = /^- \*\*([^*]+)\*\*/m.exec(section)[1];
  assert.deepEqual(differenceProblems([{ check: "keys.kid-thumbprint", gap: entry }], gaps, ids), []);
  assert.equal(differenceProblems([{ check: "keys.no-such-check", gap: entry }], gaps, ids).length, 1);
  assert.equal(differenceProblems([{ check: "keys.kid-thumbprint", gap: "an entry that is not there" }], gaps, ids).length, 1);
  // An entry of another section does not count, and a missing heading is a problem of its own.
  const before = /^- \*\*([^*]+)\*\*/m.exec(gaps.slice(0, gaps.indexOf(GAPS_HEADING)))[1];
  assert.equal(differenceProblems([{ check: "keys.kid-thumbprint", gap: before }], gaps, ids).length, 1);
  assert.match(differenceProblems([], gaps.replace(GAPS_HEADING, "## Something else"), ids).join(""), /has no heading/);
});
