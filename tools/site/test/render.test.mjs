import test from "node:test";
import assert from "node:assert/strict";
import { highlightJson } from "../lib/highlight.mjs";
import { textContent } from "../lib/html.mjs";
import { exampleProblem, extractExamples, stripExampleMarkers } from "../lib/examples.mjs";
import { parseFrontMatter } from "../lib/frontmatter.mjs";
import { analyzeMarkdown, renderMarkdown } from "../lib/markdown.mjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

test("JSON highlighting round-trips: the text content is the source, exactly", () => {
  const samples = [
    '{\n  "alp": "0.1",\n  "n": -1.5e3,\n  "ok": true,\n  "x": null,\n  "a": [1, "two", {"k": "v\\"q"}],\n  "…": "other members omitted"\n}',
    '{"broken": "unterminated',
    "not json at all <b>&amp;</b>",
    "",
  ];
  for (const s of samples) assert.equal(textContent(highlightJson(s)), s);
  const h = highlightJson('{"key": "value", "n": 2, "t": false}');
  assert.match(h, /<span class="j-k">&quot;key&quot;<\/span>/);
  assert.match(h, /<span class="j-s">&quot;value&quot;<\/span>/);
  assert.match(h, /<span class="j-n">2<\/span>/);
  assert.match(h, /<span class="j-l">false<\/span>/);
  assert.match(h, /<span class="j-p">\{<\/span>/);
});

test("JSON highlighting round-trips on every json block of the specification", () => {
  const md = fs.readFileSync(path.join(ROOT, "spec/alp-v0.1.md"), "utf8");
  const blocks = [...md.matchAll(/```json\n([\s\S]*?)\n```/g)].map((m) => m[1]);
  assert.ok(blocks.length > 5);
  for (const b of blocks) assert.equal(textContent(highlightJson(b)), b);
});

test("examples: blocks and spans are extracted by name, markers can be stripped", () => {
  const md = "a <!-- example:h -->`sha256:EqyxHr6qZqwa1WEfon7ufTXzTboeh1v-2TjkzlLoIsE`<!-- /example --> b\n\n<!-- example:obj -->\n```json\n{\"a\": 1}\n```\n<!-- /example -->\n";
  const ex = extractExamples(md);
  assert.deepEqual([...ex.keys()], ["h", "obj"]);
  assert.equal(ex.get("obj").text, '{"a": 1}');
  assert.equal(ex.get("obj").block, true);
  assert.equal(ex.get("h").block, false);
  assert.equal(exampleProblem(ex.get("h")), null);
  assert.equal(exampleProblem(ex.get("obj")), null);
  assert.ok(!stripExampleMarkers(md).includes("<!--"));
  assert.throws(() => extractExamples("<!-- example:x -->`1`"), /never closed/);
  assert.throws(() => extractExamples("<!-- example:x -->`1`<!-- /example --><!-- example:x -->`2`<!-- /example -->"), /appears twice/);
  assert.match(exampleProblem({ text: "{nope", block: true }), /does not parse/);
});

test("the specification's named examples all extract and are valid values", () => {
  const md = fs.readFileSync(path.join(ROOT, "spec/alp-v0.1.md"), "utf8");
  const ex = extractExamples(md);
  for (const name of ["a1_envelope", "a1_header", "a1_hash", "a2_doc", "a2_receipt", "a2_lee", "a2_pat", "a4_rogue", "a5_control", "a6_terms_hash", "a6_ratification"]) {
    assert.ok(ex.has(name), name);
    assert.equal(exampleProblem(ex.get(name)), null, name);
  }
});

test("front matter", () => {
  const r = parseFrontMatter('---\ntitle: What the demo prints\nexamples: [a1_envelope, a2_receipt]\nquote: "a \\"b\\""\n---\n# Body\n', "p.md");
  assert.deepEqual(r.data, { title: "What the demo prints", examples: ["a1_envelope", "a2_receipt"], quote: 'a "b"' });
  assert.equal(r.body, "# Body\n");
  assert.deepEqual(parseFrontMatter("# No front matter\n").data, {});
  assert.throws(() => parseFrontMatter("---\ntitle x\n---\n", "p.md"), /p\.md:2/);
  assert.throws(() => parseFrontMatter("---\na: 1\na: 2\n---\n", "p.md"), /appears twice/);
  assert.throws(() => parseFrontMatter("---\na: 1\n", "p.md"), /never closed/);
});

test("rendering: raw HTML is found and stays escaped; headings, tables and code are counted", () => {
  const md = "# T\n\nText <b>bold</b> and <your tenant>.\n\n## Part `x`\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n```json\n{\"a\": 1}\n```\n";
  const facts = analyzeMarkdown(md);
  assert.deepEqual(facts.html.map((h) => h.text), ["<b>", "</b>", "<your tenant>"]);
  assert.deepEqual(facts.counts, { headings: 2, tables: 1, code: 1, mermaid: 0 });
  const problems = [];
  const r = renderMarkdown(md, { file: "t.md", resolveHref: (h) => h, figureFor: () => null, problems });
  assert.deepEqual(problems, []);
  assert.match(r.h1, /^<h1 id="t">T<\/h1>$/);
  assert.match(r.body, /&lt;b&gt;bold&lt;\/b&gt;/);
  assert.match(r.body, /<h2 id="part-x">Part <code>x<\/code><a class="anchor" href="#part-x"/);
  assert.match(r.body, /<div class="table-wrap" tabindex="0" role="region" aria-label="Table">\n<table>/);
  assert.match(r.body, /<pre tabindex="0"><code class="language-json"><span class="j-p">\{<\/span>/);
});

test("rendering: a Mermaid block without a figure is a problem; with one it becomes the figure", () => {
  const md = "```mermaid\nflowchart LR\n  A --> B\n```\n";
  const problems = [];
  renderMarkdown(md, { file: "m.md", resolveHref: (h) => h, figureFor: () => null, problems });
  assert.match(problems[0], /Mermaid block .* has no figure/);
  const r = renderMarkdown(md, { file: "m.md", resolveHref: (h) => h, figureFor: (src) => (src === "flowchart LR\n  A --> B\n" ? { html: "<figure>F</figure>" } : null), problems: [] });
  assert.equal(r.body.trim(), "<figure>F</figure>");
});

test("example markers inside a code span or a fenced block are text, and are kept", () => {
  const md = "Between `<!-- example:NAME -->` and `<!-- /example -->` here <!-- example:h -->`1`<!-- /example -->.\n\n```md\n<!-- example:x -->\n```\n";
  assert.equal(stripExampleMarkers(md), "Between `<!-- example:NAME -->` and `<!-- /example -->` here `1`.\n\n```md\n<!-- example:x -->\n```\n");
  const spec = fs.readFileSync(path.join(ROOT, "spec/alp-v0.1.md"), "utf8");
  assert.ok(!stripExampleMarkers(spec).includes("<!--"));
});
