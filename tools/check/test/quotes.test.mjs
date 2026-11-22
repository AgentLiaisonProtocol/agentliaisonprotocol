// Every check is tied to the specification's text: its quote occurs word for word under the heading its `section`
// names, its requirement ids exist in Section 13, and the registry table matches Section 18.3.
import { test } from "node:test";
import assert from "node:assert/strict";
import { CHECKS, FAMILIES, REGISTRY, basisLabel } from "../catalog.mjs";
import { readSpec, sections, quoteOccurs, normalise } from "../spec-text.mjs";
import { requirementIds } from "../requirements.mjs";

const spec = readSpec();
const secs = sections(spec);

test("every quote occurs word for word under the heading its section names", () => {
  for (const c of CHECKS) {
    const s = secs.get(c.section);
    assert.ok(s, `${c.id}: no section ${c.section} in the specification`);
    assert.ok(quoteOccurs(c.quote, s.text), `${c.id}: quote not found in Section ${c.section}: ${c.quote}`);
  }
});

test("the quote matcher refuses text that is not there, and pieces out of order", () => {
  const s = secs.get("4.2.1").text;
  assert.equal(quoteOccurs("two entries have the same `id`;", s), true);
  assert.equal(quoteOccurs("two entries have the same `name`;", s), false);
  assert.equal(quoteOccurs("an explicitly listed address is not on `domain`; … two entries have the same `id`;", s), false);
  assert.equal(quoteOccurs("two entries have the same `id`; … an explicitly listed address is not on `domain`;", s), true);
  // A part may not start or end in the middle of a word, and a quote has at most two parts.
  assert.equal(quoteOccurs("wo entries have the same `id`;", s), false);
  assert.equal(quoteOccurs("two entries have the sam", s), false);
  assert.equal(quoteOccurs("A document is invalid … two entries have the same `id`; … more than one entry has `\"principals\": \"*\"`;", s), false);
  assert.equal(quoteOccurs("A document is invalid … more than one entry has `\"principals\": \"*\"`;", s), true);
  // A quote from another section does not count.
  assert.equal(quoteOccurs("Accept only status 200 with a JSON content type.", s), false);
});

const KEYWORDS = ["MUST NOT", "MUST", "REQUIRED", "SHALL NOT", "SHALL", "SHOULD NOT", "SHOULD", "NOT RECOMMENDED", "RECOMMENDED", "MAY", "OPTIONAL"];
const hasKeyword = (text, k) => new RegExp(`(^|[^A-Za-z])${k}([^A-Za-z]|$)`).test(text);
const anyKeyword = (text) => KEYWORDS.some((k) => hasKeyword(text, k));

/** The maturity of a section: the nearest "*Maturity: X" line at or above it. */
function maturityOf(section) {
  const parts = section.split(".");
  for (let n = parts.length; n > 0; n--) {
    const s = secs.get(parts.slice(0, n).join("."));
    const m = s && /^\*Maturity: ([A-Za-z]+)/m.exec(s.text);
    if (m) return m[1];
  }
  return null;
}

test("a check's level follows its basis: a key word in the quote, a statement in a normative section, or a referenced rule", () => {
  for (const c of CHECKS) for (const b of [c.basis, ...Object.values(c.otherBases ?? {})]) {
    assert.ok(b && ["keyword", "stated", "reference"].includes(b.kind), `${c.id}: basis`);
    const maturity = maturityOf(c.section);
    assert.ok(maturity === "Core" || maturity === "Experimental", `${c.id}: Section ${c.section} is ${maturity}, not normative`);
    if (b.kind === "keyword") {
      assert.ok(KEYWORDS.includes(b.keyword), `${c.id}: ${b.keyword}`);
      assert.ok(hasKeyword(c.quote, b.keyword), `${c.id}: the quote does not hold ${b.keyword}`);
      const strong = ["MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT"].includes(b.keyword);
      if (c.level === "required") assert.ok(strong, `${c.id}: required on ${b.keyword}`);
      // A recommended check on a MUST sentence is allowed only where the sentence can be read two ways.
      else assert.ok(!strong || b.reading, `${c.id}: recommended on ${b.keyword} with no reading named`);
    } else if (b.kind === "stated") {
      if (b.clause) assert.ok(normalise(c.quote).includes(normalise(b.clause)) && !anyKeyword(b.clause), `${c.id}: the stated clause is not in the quote, or holds a key word`);
      else assert.ok(!anyKeyword(c.quote), `${c.id}: a stated basis, but the quote holds a key word`);
      assert.equal(b.maturity ?? "Core", maturity, `${c.id}: maturity of Section ${c.section}`);
    } else {
      assert.ok(typeof b.text === "string" && b.text.length > 5, `${c.id}: reference text`);
      assert.ok(Array.isArray(b.sentences) && b.sentences.length >= 1 && b.sentences.every((x) => hasKeyword(x, "MUST")), `${c.id}: reference sentences`);
    }
  }
});

test("the word MUST is printed only for a check whose quote holds it", () => {
  for (const c of CHECKS) for (const label of [basisLabel(c), ...Object.keys(c.otherBases ?? {}).map((k) => basisLabel(c, k))]) {
    for (const k of ["MUST NOT", "MUST"]) if (label.includes(`(${k},`)) assert.ok(hasKeyword(c.quote, k), `${c.id}: ${label}`);
    assert.match(label, /^(required|recommended) \(/);
  }
});

test("every check is well formed", () => {
  const ids = new Set();
  const families = new Set(FAMILIES.map((f) => f.id));
  for (const c of CHECKS) {
    assert.match(c.id, /^[a-z]+\.[a-z0-9-]+$/, c.id);
    assert.ok(!ids.has(c.id), `duplicate id ${c.id}`);
    ids.add(c.id);
    assert.ok(families.has(c.family) && c.id.startsWith(c.family + "."), `${c.id}: family`);
    assert.ok(c.level === "required" || c.level === "recommended", `${c.id}: level`);
    assert.ok(typeof c.title === "string" && c.title.length > 10, `${c.id}: title`);
    assert.ok(Array.isArray(c.requirements), `${c.id}: requirements`);
  }
});

test("every requirement id a check cites exists in Section 13", () => {
  const known = new Set(requirementIds(spec));
  for (const c of CHECKS) for (const r of c.requirements) assert.ok(known.has(r), `${c.id}: unknown requirement ${r}`);
});

test("the registry statuses match Section 18.3", () => {
  const rows = secs.get("18.3").text.split("\n").filter((l) => /^\| `[a-z_]+` \|/.test(l));
  const fromSpec = {};
  for (const row of rows) {
    const cells = row.split("|").map((c) => c.trim());
    fromSpec[cells[1].replace(/`/g, "")] = cells[2] === "—" ? null : Number(cells[2]);
  }
  assert.deepEqual(fromSpec, REGISTRY);
});

test("titles never claim certification", () => {
  for (const c of CHECKS) {
    const t = normalise(`${c.title} ${c.note ?? ""}`).toLowerCase();
    assert.ok(!/\bcertif(?:y|ies|ied|ication)\b|\bcompliant\b|\bconformant\b/.test(t), `${c.id}: wording`);
  }
});
