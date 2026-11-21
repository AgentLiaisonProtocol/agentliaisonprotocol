// The report: one line per check, details for failures and warnings, a summary by family, the requirements
// observed in part, and what the tool does not check. `--json` gives the same as data. Licensed under Apache-2.0.
import { CHECKS, FAMILIES, NOT_CHECKED, VERSION, BY_ID, basisLabel, basisOf, FEDERATION_REQUIREMENTS } from "./catalog.mjs";
import { MAX_REQUESTS } from "./http.mjs";

const LABEL = { pass: "PASS", fail: "FAIL", warn: "WARN", skip: "SKIP", error: "ERROR" };

/**
 * Which results could not be decided, directly or through a prerequisite: every "could not decide" result, and every
 * skip whose prerequisite (`after`) could not be decided, for the same subject when that check has a result for it.
 */
function undecidedSet(results) {
  const tainted = new Set(results.filter((r) => r.inconclusive));
  for (let changed = true; changed;) {
    changed = false;
    for (const r of results) {
      if (tainted.has(r) || r.result !== "skip" || !r.after) continue;
      const hit = r.after.some((id) => {
        const same = results.filter((x) => x.id === id && x.subject === r.subject);
        return (same.length ? same : results.filter((x) => x.id === id)).some((x) => tainted.has(x));
      });
      if (hit) { tainted.add(r); changed = true; }
    }
  }
  return tainted;
}

/** Summary numbers by family and overall, and the exit code. */
export function summarise(results, { federating = true } = {}) {
  const byFamily = FAMILIES.map((f) => {
    const rs = results.filter((r) => r.family === f.id);
    const n = (k) => rs.filter((r) => r.result === k).length;
    return { family: f.id, title: f.title, pass: n("pass"), fail: n("fail"), warn: n("warn"), skip: n("skip"), error: n("error") };
  });
  const errors = results.filter((r) => r.result === "error").length;
  const capped = results.filter((r) => r.capped).length;
  const requiredFailed = results.filter((r) => r.result === "fail").length;
  const undecided = undecidedSet(results);
  const requiredUndecided = results.filter((r) => r.level === "required" && r.inconclusive).length;
  const requiredSkippedAfterUndecided = results.filter((r) => r.level === "required" && r.result === "skip" && undecided.has(r)).length;
  // Required results skipped for any other reason: an option, no such endpoint, a failed prerequisite, an inbox
  // that answers every unsigned probe 401. They are neither failures nor undecided, and the summary counts them.
  const requiredSkipped = results.filter((r) => r.level === "required" && r.result === "skip" && !undecided.has(r)).length;
  const recommendedWarned = results.filter((r) => r.level === "recommended" && r.result === "warn" && !r.inconclusive).length;
  const recommendedUndecided = results.filter((r) => r.level === "recommended" && r.inconclusive).length;
  const warnings = results.filter((r) => r.result === "warn").length;
  // A requirement is observed in part only through a check that was decided.
  const observed = new Set();
  for (const r of results) {
    if (r.result === "skip" || r.inconclusive || r.result === "error") continue;
    for (const q of BY_ID.get(r.id).requirements) if (federating || !FEDERATION_REQUIREMENTS.has(q)) observed.add(q);
  }
  const order = (id) => {
    const [p, n] = id.split("-");
    return ["BC", "OB", "HB", "PB", "NC", "CD"].indexOf(p) * 1000 + Number(n);
  };
  const exitCode = errors ? 3 : requiredFailed ? 1 : requiredUndecided + requiredSkippedAfterUndecided ? 4 : 0;
  return {
    byFamily, requiredFailed, requiredUndecided, requiredSkippedAfterUndecided, requiredSkipped, recommendedWarned, recommendedUndecided, warnings, errors, capped, exitCode,
    requirementsObserved: [...observed].sort((a, b) => order(a) - order(b)),
  };
}

export function toJson(run) {
  const s = summarise(run.results, { federating: !!run.target.domain });
  return {
    tool: "alp-check",
    version: VERSION,
    specification: "Agent Liaison Protocol v0.1 (spec/alp-v0.1.md)",
    target: run.target,
    dev_map: run.devMapOrigins,
    started_at: run.startedAt,
    results: run.results.map((r) => {
      const c = BY_ID.get(r.id);
      if (!c) return { ...r };
      return { ...r, basis: basisOf(c, r.basis_key), basis_label: basisLabel(c, r.basis_key), quote: c.quote, requirements: c.requirements };
    }),
    summary: {
      by_family: s.byFamily,
      required_failed: s.requiredFailed,
      required_undecided: s.requiredUndecided,
      required_skipped_after_undecided: s.requiredSkippedAfterUndecided,
      required_skipped: s.requiredSkipped,
      recommended_warned: s.recommendedWarned,
      recommended_undecided: s.recommendedUndecided,
      warnings: s.warnings,
      alp_check_errors: s.errors,
      stopped_by_request_limit: s.capped,
      exit_code: s.exitCode,
    },
    requirements_observed_in_part: s.requirementsObserved,
    requests: { count: run.requestCount, limit: MAX_REQUESTS, log: run.requests },
    not_checked: NOT_CHECKED,
  };
}

function wrap(text, indent, width = 100) {
  const words = String(text).split(" ");
  const lines = [];
  let line = "";
  for (const w of words) {
    if (line && (indent + line + " " + w).length > width) { lines.push(line); line = w; }
    else line = line ? `${line} ${w}` : w;
  }
  if (line) lines.push(line);
  return lines.map((l, i) => (i === 0 ? l : " ".repeat(indent) + l)).join("\n");
}

export function toText(run) {
  const out = [];
  if (run.devMapOrigins) {
    out.push(`Development host map in use (${run.devMapOrigins.join(", ")} go to loopback over plain HTTP): TLS and DNS checks are skipped, never passed.`);
  }
  const t = run.target;
  out.push(`alp-check ${VERSION}: ${t.domain ? `domain ${t.domain}` : `broker ${t.broker}`}`);
  out.push("Checks part of what the ALP v0.1 specification requires at a broker's public surface, with no credentials.");
  out.push("");
  for (const r of run.results) {
    const subject = r.subject ? ` [${r.subject}]` : "";
    const c = BY_ID.get(r.id);
    if (!c) {
      // An error outside any check: it names its family, not a check.
      out.push(wrap(`${LABEL[r.result]}  ${r.family ?? "alp-check"}: ${r.title}`, 6));
      out.push(`      ${wrap(`alp-check's own error, not a finding about the target: ${r.message}`, 8)}`);
      continue;
    }
    const basis = basisOf(c, r.basis_key);
    const head = `${LABEL[r.result]}${r.inconclusive ? "?" : " "} ${r.id}${subject}, ${basisLabel(c, r.basis_key)}: ${r.title}`;
    if (r.result === "skip") {
      out.push(wrap(`${head}. Skipped: ${r.reason}`, 6));
      continue;
    }
    // What a result did not judge is part of its line, so that a PASS never reads as covering it.
    out.push(wrap(r.not_judged ? `${head}. Not judged: ${r.not_judged}` : head, 6));
    if (r.result === "error") {
      out.push(`      ${wrap(`alp-check's own error, not a finding about the target: ${r.message}`, 8)}`);
      continue;
    }
    if (r.result === "fail" || r.result === "warn") {
      const lines = [];
      if (r.inconclusive) lines.push(["could not decide", r.message]);
      else if (r.message) lines.push(["found", r.message]);
      lines.push([`specification (Section ${c.section})`, `"${c.quote}"`]);
      if (basis.kind === "reference") for (const q of basis.sentences) lines.push([`rule (${basis.text})`, `"${q}"`]);
      if (r.sent) lines.push(["sent", r.sent]);
      if (r.received) lines.push(["received", r.received]);
      if (r.expected) lines.push(["expected", r.expected]);
      for (const n of r.notes ?? []) lines.push(["note", n]);
      if (c.note) lines.push(["about this check", c.note]);
      for (const [k, v] of lines) out.push(`      ${wrap(`${k}: ${v}`, 8)}`);
    }
  }
  const s = summarise(run.results, { federating: !!t.domain });
  out.push("", "Summary by family");
  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
  for (const f of s.byFamily) out.push(`  ${f.title}: ${f.pass} passed, ${f.fail} failed, ${plural(f.warn, "warning")}, ${f.skip} skipped${f.error ? `, ${f.error} alp-check errors` : ""}`);
  const undecided = s.requiredUndecided + s.requiredSkippedAfterUndecided;
  const how = `${s.requiredUndecided} marked "?"${s.requiredSkippedAfterUndecided ? `, ${s.requiredSkippedAfterUndecided} skipped because of them` : ""}`;
  out.push("");
  if (s.requiredFailed) {
    out.push(`${plural(s.requiredFailed, "required check result")} failed.`);
    if (undecided) out.push(wrap(`Besides, ${plural(undecided, "required check result")} could not be decided (${how}), so this run says nothing about them.`, 0));
  } else if (undecided) {
    out.push(wrap(`No required check failed, but ${plural(undecided, "required check result")} could not be decided (${how}), so this run says nothing about them (exit code 4).`, 0));
  } else {
    out.push("No required check failed and none was left undecided.");
    if (s.requiredSkipped) out.push(`${plural(s.requiredSkipped, "required check result")} ${s.requiredSkipped === 1 ? "was" : "were"} skipped; the SKIP lines above say why.`);
  }
  out.push(`Recommended checks: ${plural(s.recommendedWarned, "warning")}${s.recommendedUndecided ? `, and ${s.recommendedUndecided} could not be decided (marked "?")` : ""}.`);
  if (s.errors) out.push(`${plural(s.errors, "check")} stopped on an error of alp-check itself (exit code 3); please report it.`);
  out.push(`Requests made: ${run.requestCount} (at most ${MAX_REQUESTS}).${s.capped ? ` The request limit stopped ${plural(s.capped, "check result")}, reported as "could not decide".` : ""}`);
  out.push("", wrap(`Section 13 requirements this run observed in part: ${s.requirementsObserved.length ? s.requirementsObserved.join(", ") : "none"}.${t.domain ? "" : " With no domain (a Local-profile broker), the requirements that apply when a broker federates are not listed."}`, 0));
  out.push("", "What this report does not cover");
  for (const p of NOT_CHECKED) out.push(wrap(p, 0), "");
  return out.join("\n");
}

export { CHECKS };
