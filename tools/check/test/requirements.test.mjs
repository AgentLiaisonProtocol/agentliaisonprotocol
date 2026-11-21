// CONFORMANCE.md is generated from Section 13; it must be current, and every requirement must be placed.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { render, parseRequirements, CONFORMANCE_PATH } from "../requirements.mjs";
import { readSpec } from "../spec-text.mjs";

const spec = readSpec();

test("CONFORMANCE.md is current (run node tools/check/requirements.mjs)", () => {
  assert.equal(fs.readFileSync(CONFORMANCE_PATH, "utf8"), render(spec));
});

test("Section 13 has the requirement ids it is known to have", () => {
  const ids = parseRequirements(spec).map((r) => r.id);
  const count = (p) => ids.filter((i) => i.startsWith(p + "-")).length;
  assert.deepEqual(
    { BC: count("BC"), OB: count("OB"), HB: count("HB"), PB: count("PB"), NC: count("NC"), CD: count("CD") },
    { BC: 25, OB: 6, HB: 5, PB: 8, NC: 5, CD: 6 },
  );
  assert.equal(new Set(ids).size, ids.length);
});

test("a requirement the map does not place stops the script", () => {
  const extra = spec.replace("| BC-25 | All vectors", "| BC-26 | A new requirement | 1 |\n| BC-25 | All vectors");
  assert.throws(() => render(extra), /BC-26 is not placed/);
});

test("a requirement that disappears from Section 13 stops the script", () => {
  const fewer = spec.replace(/^\| OB-5 \|.*\n/m, "");
  assert.throws(() => render(fewer), /OB-5, which Section 13 does not have/);
});

test("a requirement row elsewhere in Section 13, such as a new class's table, stops the script", () => {
  const extra = spec.replace("### 13.9 The operator statement", "### 13.9 A new class\n\n| Id | Requirement | Sections |\n|---|---|---|\n| NX-1 | Something new | 4 |\n\n### 13.10 The operator statement");
  assert.throws(() => render(extra), /NX-1 that requirements\.mjs did not parse/);
});

test("IMPLEMENTING.md places every requirement of Section 13", () => {
  const guide = fs.readFileSync(new URL("../../../IMPLEMENTING.md", import.meta.url), "utf8");
  const placed = new Set(guide.match(/\b(?:BC|OB|HB|PB|NC|CD)-\d+\b/g));
  // Ranges such as "BC-8 to BC-13" place every id between.
  for (const [, p, a, q, b] of guide.matchAll(/\b(BC|OB|HB|PB|NC|CD)-(\d+) to (BC|OB|HB|PB|NC|CD)-(\d+)\b/g)) {
    if (p === q) for (let n = Number(a); n <= Number(b); n++) placed.add(`${p}-${n}`);
  }
  const missing = parseRequirements(spec).map((r) => r.id).filter((id) => !placed.has(id));
  assert.deepEqual(missing, []);
});
