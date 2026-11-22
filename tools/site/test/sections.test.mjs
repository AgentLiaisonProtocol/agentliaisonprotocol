import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { linkSectionRefs, markMaturityLines, sectionNumber } from "../lib/sections.mjs";
import { textContent } from "../lib/html.mjs";
import { renderMarkdown } from "../lib/markdown.mjs";
import { stripExampleMarkers } from "../lib/examples.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const ids = new Map([["6.6", "66-x"], ["6.7", "67-y"], ["4.2", "42-a"], ["4.8", "48-b"], ["12.2.4", "1224-c"], ["A", "appendix-a"], ["A.4", "a4-d"], ["17", "17-e"]]);
const spec = (html) => {
  const missing = [];
  const out = linkSectionRefs(html, { mode: "spec", hrefFor: (n) => (ids.has(n) ? `#${ids.get(n)}` : null), missing });
  return { out, missing };
};

test("section numbers from heading text", () => {
  assert.equal(sectionNumber("6.6 Sender-side evaluation"), "6.6");
  assert.equal(sectionNumber("1. Introduction"), "1");
  assert.equal(sectionNumber("Appendix A. Worked examples"), "A");
  assert.equal(sectionNumber("A.4 A rogue broker refused"), "A.4");
  assert.equal(sectionNumber("Abstract"), null);
  assert.equal(sectionNumber("References"), null);
});

test("references in running text become links", () => {
  assert.equal(spec("<p>See Section 6.6.</p>").out, '<p>See <a class="secref" href="#66-x">Section 6.6</a>.</p>');
  assert.equal(spec("<p>Sections 4.2–4.8 apply.</p>").out, '<p>Sections <a class="secref" href="#42-a">4.2</a>–<a class="secref" href="#48-b">4.8</a> apply.</p>');
  assert.equal(spec("<p>Sections 6.6 and 6.7</p>").out, '<p>Sections <a class="secref" href="#66-x">6.6</a> and <a class="secref" href="#67-y">6.7</a></p>');
  assert.equal(spec("<li>every check of Section 12.2.4</li>").out, '<li>every check of <a class="secref" href="#1224-c">Section 12.2.4</a></li>');
  assert.equal(spec("<p>in Appendix A.</p>").out, '<p>in <a class="secref" href="#appendix-a">Appendix A</a>.</p>');
  assert.equal(spec("<p>Section A.4</p>").out, '<p><a class="secref" href="#a4-d">Section A.4</a></p>');
});

test("references inside links, code and headings, and citations of other documents, are left alone", () => {
  for (const html of [
    '<p><a href="x">Section 6.6</a></p>', "<p><code>Section 6.6</code></p>", "<h2>Section 6.6</h2>",
    "<p>RFC 6749, Section 3.3</p>", "<p>([Poppy], Section 4.1)</p>", "<p>Section 2 of RFC 8414</p>", "<p>RFC 7515, Appendix F</p>",
  ]) assert.deepEqual(spec(html), { out: html, missing: [] }, html);
});

test("a reference to a section that doesn't exist is reported", () => {
  const r = spec("<p>Section 99.1 and Section 6.6</p>");
  assert.deepEqual(r.missing, ["99.1"]);
  assert.match(r.out, /Section 99\.1 and <a/);
});

test("on other pages the short form 'Spec 6.6' links too, and a missing section is reported", () => {
  const missing = [];
  const run = (html) => linkSectionRefs(html, { mode: "other", hrefFor: (n) => (ids.has(n) ? `../spec/#${ids.get(n)}` : null), missing });
  assert.equal(run("<td>Spec 6.6 (S1 to S8)</td>"), '<td><a class="secref" href="../spec/#66-x">Spec 6.6</a> (S1 to S8)</td>');
  assert.equal(run("<p>(spec 17).</p>"), '<p>(<a class="secref" href="../spec/#17-e">spec 17</a>).</p>');
  assert.equal(run("<td>Spec 4.2, 6.7 and 17; x</td>"), '<td>Spec <a class="secref" href="../spec/#42-a">4.2</a>, <a class="secref" href="../spec/#67-y">6.7</a> and <a class="secref" href="../spec/#17-e">17</a>; x</td>');
  assert.equal(run("<p>the spec says</p>"), "<p>the spec says</p>");
  assert.equal(run("<p><code>spec 6.6</code></p>"), "<p><code>spec 6.6</code></p>");
  assert.equal(run("<p>Spec 6.99</p>"), "<p>Spec 6.99</p>");
  assert.deepEqual(missing, ["6.99"]);
});

test("on other pages 'spec Section' and 'specification Section' link, other documents' sections don't", () => {
  const run = (html) => linkSectionRefs(html, { mode: "other", hrefFor: (n) => (ids.has(n) ? `../spec/#${ids.get(n)}` : null) });
  assert.equal(run("<p>(spec Section 6.6)</p>"), '<p>(<a class="secref" href="../spec/#66-x">spec Section 6.6</a>)</p>');
  assert.equal(run("<p>Spec Section 17 (x)</p>"), '<p><a class="secref" href="../spec/#17-e">Spec Section 17</a> (x)</p>');
  assert.equal(run("<p>see the specification's Section 6.7</p>"), '<p>see the <a class="secref" href="../spec/#67-y">specification\'s Section 6.7</a></p>');
  assert.equal(run("<p>Section 6.6 of the README</p>"), "<p>Section 6.6 of the README</p>");
  assert.equal(run("<p>Poppy 1.0, Section 4.1</p>"), "<p>Poppy 1.0, Section 4.1</p>");
});

test("maturity: each section's own line becomes its label, word for word; the rest of the paragraph stays", () => {
  const html = '<h2 id="3-a">3. A</h2>\n<p><em>Maturity: Core.</em></p>\n<h3 id="34-b">3.4 B</h3>\n<p><em>Maturity: client mode Core; native mode Experimental.</em></p>\n<h2 id="17-c">17. C</h2>\n<p><em>Informative.</em> This section cites <em>only</em> checked work.</p>\n<p>Plain <em>Maturity: no</em> text.</p>';
  const { html: out, lines } = markMaturityLines(html);
  assert.match(out, /<p class="has-maturity"><span class="maturity maturity-core">Maturity: Core\.<\/span><\/p>/);
  assert.match(out, /<span class="maturity maturity-core">Maturity: client mode Core; native mode Experimental\.<\/span>/);
  assert.match(out, /<p class="has-maturity"><span class="maturity maturity-informative">Informative\.<\/span> This section cites <em>only<\/em> checked work\.<\/p>/);
  assert.match(out, /<p>Plain <em>Maturity: no<\/em> text\.<\/p>/);
  assert.deepEqual(lines.map((l) => [l.section, l.label]), [["3", "Core"], ["3.4", "Core"], ["17", "Informative"]]);
  assert.equal(textContent(out), textContent(html));
});

test("maturity: every label line of the specification is shown, and the derived table labels are gone", () => {
  const md = fs.readFileSync(path.join(ROOT, "spec/alp-v0.1.md"), "utf8");
  const r = renderMarkdown(stripExampleMarkers(md), { file: "spec", resolveHref: (h) => h, maturity: true, figureFor: () => ({ html: "<figure></figure>" }), problems: [] });
  const inSource = (md.match(/^\*(?:Maturity: |Informative\.)/gm) || []).length;
  assert.equal(r.maturityLines.length, inSource);
  assert.ok(!/class="badge/.test(r.body));
  const bySection = Object.fromEntries(r.maturityLines.map((l) => [l.section, l]));
  assert.equal(bySection["3.4"].text, "Maturity: client mode Core; native mode Experimental.");
  assert.equal(bySection["17"].label, "Informative");
  assert.equal(bySection["19"].label, "Future");
  assert.equal(bySection["12.2"].label, "Experimental");
});
