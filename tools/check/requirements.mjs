// Writes CONFORMANCE.md at the repository root from Section 13 of spec/alp-v0.1.md and the checker's catalogue.
//
//   node tools/check/requirements.mjs           write CONFORMANCE.md
//   node tools/check/requirements.mjs --check   exit 1 if CONFORMANCE.md is not current
//
// The vector column and what the checker can't see come from the hand-kept map below, taken from the
// specification's Appendix B and vectors/README.md. The script fails on a requirement id the map doesn't place,
// and on a map entry Section 13 doesn't have, so a new requirement can't go missing.
// Licensed under Apache-2.0.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CHECKS, BY_ID } from "./catalog.mjs";
import { REPO, readSpec, sections } from "./spec-text.mjs";

export const CONFORMANCE_PATH = path.join(REPO, "CONFORMANCE.md");

const CLASSES = [
  { section: "13.3", name: "Broker Core", prefix: "BC" },
  { section: "13.4", name: "Organization Broker", prefix: "OB" },
  { section: "13.5", name: "Hosted Broker", prefix: "HB" },
  { section: "13.7", name: "Provider Broker (PB-Core, Experimental)", prefix: "PB" },
  { section: "13.6", name: "Native Client (Experimental)", prefix: "NC" },
  { section: "13.8", name: "Client-mode Delegate", prefix: "CD" },
];

// What the checker can't see, alone and after a list of checks that see part of the requirement.
const TOKEN = { alone: "needs a token (not in this version)", rest: "the rest needs a token, not in this version" };
const PEER = { alone: "needs a peer broker (not in this version)", rest: "the rest needs a peer broker, not in this version" };
const NONE = { alone: "not observable from outside", rest: "the rest is not observable from outside" };
const CLIENT = { alone: "not observable from outside (a client requirement; the checker looks at brokers)", rest: null };

// For each requirement: the vector files that exercise it (paths under vectors/), and what the checker can't see
// of it from outside in this version. Checks that observe part of it come from the catalogue's `requirements`.
const MAP = {
  "BC-1": { vectors: ["envelope/validity.json"], outside: TOKEN },
  "BC-2": { vectors: ["policy/recipient.json"], outside: NONE },
  "BC-3": { vectors: ["delivery/visibility.json"], outside: TOKEN },
  "BC-4": { vectors: [], outside: TOKEN },
  "BC-5": { vectors: [], outside: TOKEN },
  "BC-6": { vectors: ["delivery/visibility.json"], outside: TOKEN },
  "BC-7": { vectors: ["delivery/sanitize.json"], outside: TOKEN },
  "BC-8": { vectors: [], outside: NONE },
  "BC-9": { vectors: ["policy/sender.json"], outside: TOKEN },
  "BC-10": { vectors: ["policy/recipient.json"], outside: PEER },
  "BC-11": { vectors: ["policy/recipient.json", "federation/connection-requests.json"], outside: PEER },
  "BC-12": { vectors: ["policy/sender.json", "policy/recipient.json"], outside: TOKEN },
  "BC-13": { vectors: ["policy/sender.json", "policy/recipient.json", "delivery/visibility.json"], outside: NONE },
  "BC-14": { vectors: ["scopes/bodies.json", "policy/sender.json"], outside: TOKEN },
  "BC-15": {
    vectors: ["jcs/jcs.json", "signatures/detached-jws.json", "signatures/jkt.json", "envelope/validity.json", "federation/acceptance.json"],
    outside: PEER,
  },
  "BC-16": { vectors: ["threads/conversations.json", "threads/meeting-commit.json"], outside: TOKEN },
  "BC-17": { vectors: ["threads/meeting-commit.json", "threads/conversations.json"], outside: NONE },
  "BC-18": { vectors: ["federation/acceptance.json", "ledger/matching-ledgers.json"], outside: PEER },
  "BC-19": { vectors: ["ledger/matching-ledgers.json"], outside: NONE },
  "BC-20": { vectors: [], outside: NONE },
  "BC-21": { vectors: [], outside: NONE },
  "BC-22": { vectors: ["federation/connection-requests.json", "policy/recipient.json"], outside: PEER },
  "BC-23": { vectors: ["policy/sender.json", "policy/recipient.json"], outside: NONE },
  "BC-24": { vectors: [], outside: PEER },
  "BC-25": { vectors: ["*"], outside: NONE },
  "OB-1": { vectors: [], outside: NONE },
  "OB-2": { vectors: [], outside: NONE },
  "OB-3": { vectors: ["policy/sender.json", "policy/recipient.json"], outside: NONE },
  "OB-4": { vectors: [], outside: NONE },
  "OB-5": { vectors: [], outside: NONE },
  "OB-6": { vectors: ["domain/resolution.json", "signatures/jkt.json", "federation/acceptance.json"], outside: PEER },
  "HB-1": { vectors: ["domain/resolution.json"], outside: PEER },
  "HB-2": { vectors: [], outside: NONE },
  "HB-3": { vectors: [], outside: NONE },
  "HB-4": { vectors: [], outside: { alone: "not checked in this version (the checker does not know which class a broker claims)", rest: null } },
  "HB-5": { vectors: ["domain/resolution.json", "federation/acceptance.json"], outside: PEER },
  "PB-1": { vectors: ["domain/resolution.json"], outside: PEER },
  "PB-2": { vectors: ["federation/acceptance.json", "policy/recipient.json"], outside: PEER },
  "PB-3": { vectors: ["scopes/bodies.json"], outside: TOKEN },
  "PB-4": { vectors: ["policy/recipient.json"], outside: PEER },
  "PB-5": { vectors: ["federation/connection-requests.json"], outside: PEER },
  "PB-6": { vectors: ["ledger/matching-ledgers.json"], outside: NONE },
  "PB-7": { vectors: [], outside: { alone: "not checked in this version", rest: "the operator statement is not checked in this version" } },
  "PB-8": { vectors: [], outside: TOKEN },
  "NC-1": { vectors: [], outside: CLIENT },
  "NC-2": { vectors: [], outside: CLIENT },
  "NC-3": { vectors: [], outside: CLIENT },
  "NC-4": { vectors: [], outside: CLIENT },
  "NC-5": { vectors: [], outside: CLIENT },
  "CD-1": { vectors: [], outside: CLIENT },
  "CD-2": { vectors: [], outside: CLIENT },
  "CD-3": { vectors: [], outside: CLIENT },
  "CD-4": { vectors: [], outside: CLIENT },
  "CD-5": { vectors: [], outside: CLIENT },
  "CD-6": { vectors: [], outside: CLIENT },
};

/** Parse the requirement tables of Section 13: [{ cls, id, text, sections }]. */
export function parseRequirements(spec) {
  const secs = sections(spec);
  const out = [];
  for (const cls of CLASSES) {
    const s = secs.get(cls.section);
    if (!s) throw new Error(`Section ${cls.section} is missing`);
    const rows = s.text.split("\n").filter((l) => l.startsWith("|"));
    if (rows.length < 3) throw new Error(`Section ${cls.section} has no requirement table`);
    const header = rows[0].split("|").slice(1, -1).map((c) => c.trim());
    if (header[0] !== "Id" || header[1] !== "Requirement") throw new Error(`Section ${cls.section}: unexpected table header`);
    for (const row of rows.slice(2)) {
      const cells = row.split("|").slice(1, -1).map((c) => c.trim());
      const id = cells[0];
      if (!new RegExp(`^${cls.prefix}-\\d+$`).test(id)) throw new Error(`Section ${cls.section}: unexpected id ${JSON.stringify(id)}`);
      out.push({ cls, id, text: cells[1], sections: header[2] === "Sections" ? cells[2] : null });
    }
  }
  // Every requirement row anywhere in Section 13 (a new class's table included) must have been parsed above.
  const all = [...secs].filter(([n]) => n === "13" || n.startsWith("13.")).flatMap(([, v]) => v.text.split("\n"));
  const parsed = new Set(out.map((r) => r.id));
  for (const line of all) {
    const m = /^\|\s*([A-Z]{2,}-\d+)\s*\|/.exec(line);
    if (m && !parsed.has(m[1])) throw new Error(`Section 13 has a requirement row ${m[1]} that requirements.mjs did not parse (a class it does not know?)`);
  }
  return out;
}

export const requirementIds = (spec) => parseRequirements(spec).map((r) => r.id);

function vectorFiles() {
  const dir = path.join(REPO, "vectors");
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".json")) files.push(path.relative(dir, p).split(path.sep).join("/"));
    }
  };
  walk(dir);
  return new Set(files);
}

export function render(spec) {
  const reqs = parseRequirements(spec);
  const ids = new Set(reqs.map((r) => r.id));
  for (const r of reqs) if (!MAP[r.id]) throw new Error(`requirement ${r.id} is not placed in the map of requirements.mjs`);
  for (const id of Object.keys(MAP)) if (!ids.has(id)) throw new Error(`requirements.mjs places ${id}, which Section 13 does not have`);
  const files = vectorFiles();
  for (const [id, m] of Object.entries(MAP))
    for (const v of m.vectors) if (v !== "*" && !files.has(v)) throw new Error(`${id}: no vector file vectors/${v}`);
  const checksFor = new Map();
  for (const c of CHECKS)
    for (const r of c.requirements) {
      if (!ids.has(r)) throw new Error(`check ${c.id} cites ${r}, which Section 13 does not have`);
      checksFor.set(r, [...(checksFor.get(r) ?? []), c.id]);
    }
  const secs = sections(spec);
  const claim = secs.get("13.1").text.trim().split("\n")[0].trim();

  const lines = [
    "# Requirements and how they are checked",
    "",
    "<!-- Generated by tools/check/requirements.mjs from Section 13 of spec/alp-v0.1.md. Do not edit by hand: run `node tools/check/requirements.mjs`. -->",
    "",
    "This table lists every numbered requirement of the Agent Liaison Protocol (ALP) v0.1, one table per conformance class, as Section 13 of [the specification](spec/alp-v0.1.md) gives them. For each requirement it names the vector files that exercise it and the checks of [`tools/check`](tools/check/README.md) that observe part of it from outside a running broker.",
    "",
    "What claiming a class means is set by Section 13.1:",
    "",
    `> ${claim}`,
    "",
    "The vector column is a map kept by hand from Appendix B of the specification and [vectors/README.md](vectors/README.md); the vector files themselves say what an implementation must reproduce. A requirement with no vector says \"none\". The last column names the checker's checks, each with its level (a failed required check is a failure, a failed recommended check a warning; [tools/check/README.md](tools/check/README.md) explains the basis of each), or why the checker can't see the requirement: it needs a token, it needs the checker to act as a peer broker with its own domain and keys, or it isn't observable from outside at all. A check that observes a requirement sees part of it, never all of it, so passing the checks is not a claim of a class. The 64 KiB body limit of Section 8.10 is not observed from outside: the specification does not say at which acceptance step the 64 KiB limit applies, so a broker may refuse an oversized probe from an unknown sender for the sender first; alp-check cannot require `body_too_large` and does not probe it.",
    "",
  ];
  const cell = (s) => s.replace(/\|/g, "\\|");
  for (const cls of CLASSES) {
    const rows = reqs.filter((r) => r.cls === cls);
    lines.push(`## ${cls.name} (Section ${cls.section})`, "");
    lines.push("| Id | Requirement | Sections | Vectors | From outside (tools/check) |", "|---|---|---|---|---|");
    for (const r of rows) {
      const m = MAP[r.id];
      const vectors = m.vectors.length === 0 ? "none" : m.vectors[0] === "*" ? "every file in `vectors/`" : m.vectors.map((v) => `\`${v}\``).join(", ");
      const checks = checksFor.get(r.id) ?? [];
      if (checks.length && !m.outside.rest) throw new Error(`${r.id}: checks observe it, but the map has no wording for the rest`);
      const outside = checks.length ? `${checks.map((c) => `\`${c}\` (${BY_ID.get(c).level})`).join(", ")}; each in part, and ${m.outside.rest}` : m.outside.alone;
      lines.push(`| ${r.id} | ${cell(r.text)} | ${r.sections ? cell(r.sections) : "none given"} | ${vectors} | ${outside} |`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

const isMain = (() => {
  if (!process.argv[1]) return false;
  try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
})();
if (isMain) {
  const args = process.argv.slice(2);
  const text = render(readSpec());
  if (args.includes("--check")) {
    const current = fs.existsSync(CONFORMANCE_PATH) ? fs.readFileSync(CONFORMANCE_PATH, "utf8") : "";
    if (current !== text) {
      console.error("CONFORMANCE.md is not current: run node tools/check/requirements.mjs");
      process.exit(1);
    }
    console.log("CONFORMANCE.md is current.");
  } else if (args.length) {
    console.error("usage: node tools/check/requirements.mjs [--check]");
    process.exit(2);
  } else {
    fs.writeFileSync(CONFORMANCE_PATH, text);
    console.log(`wrote ${path.relative(process.cwd(), CONFORMANCE_PATH) || CONFORMANCE_PATH}`);
  }
}
