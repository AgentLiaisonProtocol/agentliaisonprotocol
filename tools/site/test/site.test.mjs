// Tests on the built site: one build into a temporary folder, then what particular pages say.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildSite } from "../build.mjs";
import { textContent } from "../lib/html.mjs";
import { CSP } from "../lib/shell.mjs";

let built = null;
function site() {
  if (built) return built;
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "alp-site-test-"));
  const outDir = path.join(base, "site");
  const { env } = buildSite({ outDir });
  const read = (rel) => fs.readFileSync(path.join(outDir, rel), "utf8");
  built = { base, outDir, env, read };
  return built;
}
test.after(() => { if (built) fs.rmSync(built.base, { recursive: true, force: true }); });

test("the spec tools page shows its sentence about the example markers exactly as written", () => {
  const { read } = site();
  const html = read("docs/reference/spec-tools/index.html");
  const want = "Replaces each block between <!-- example:NAME --> and <!-- /example --> in the specification with the matching object from the vectors.";
  assert.ok(textContent(html).includes(want));
  assert.ok(read("docs/reference/spec-tools.md").includes("`<!-- example:NAME -->` and `<!-- /example -->`"));
});

test("the specification's mirrors drop the example markers and keep everything else", () => {
  const { read } = site();
  for (const f of ["docs/spec.md", "docs/0.1/spec.md"]) {
    const md = read(f);
    assert.ok(!md.includes("<!--"), f);
    assert.ok(md.includes("```mermaid"), f);
  }
});

test("pages carry no copy of their Markdown; the copy button names the mirror, and the policy allows only that", () => {
  const { read } = site();
  assert.match(CSP, /connect-src 'self'/);
  const html = read("docs/spec/index.html");
  assert.ok(!html.includes("<template"));
  assert.ok(!html.includes("```mermaid"));
  assert.match(html, /<button type="button" class="copy-page" data-copy-page="\.\.\/spec\.md" hidden>Copy page as Markdown<\/button>/);
  const js = read("assets/site.js");
  assert.equal((js.match(/\bfetch\s*\(/g) || []).length, 1);
});

test("the published 0.1 page shows no last-changed date, and its notice gives the changelog's date", () => {
  const { read } = site();
  const html = read("docs/0.1/spec/index.html");
  assert.ok(!/Last changed/.test(html));
  const notice = /<p class="notice">([\s\S]*?)<\/p>/.exec(html)[1];
  assert.equal(textContent(notice), "Version 0.1.0 as first published (commit ff8d561). The changelog dates it November 9, 2026. The working text has later changes.");
  assert.match(notice, /href="\.\.\/\.\.\/changelog\/#010---2026-11-09-draft-for-implementers"/);
  assert.match(notice, /href="\.\.\/\.\.\/spec\/"/);
});

test("the working text shows each section's own maturity line as a label", () => {
  const { read } = site();
  const html = read("docs/spec/index.html");
  assert.match(html, /<span class="maturity maturity-core">Maturity: client mode Core; native mode Experimental\.<\/span>/);
  assert.match(html, /<span class="maturity maturity-future">Maturity: Future\. Not normative\.<\/span>/);
  assert.ok(!/class="badge/.test(html));
  // The published 0.1 page styles its own maturity lines the same way.
  assert.match(read("docs/0.1/spec/index.html"), /<span class="maturity maturity-future">Maturity: Future\. Not normative\.<\/span>/);
});

test("the top bar marks the link of the page's docs group", () => {
  const { read } = site();
  const current = (rel) => {
    const nav = /<nav class="top-nav"[\s\S]*?<\/nav>/.exec(read(rel))[0];
    return [...nav.matchAll(/<a [^>]*aria-current="true"[^>]*>([^<]*)<\/a>/g)].map((m) => m[1]);
  };
  assert.deepEqual(current("docs/changelog/index.html"), ["Status"]);
  assert.deepEqual(current("docs/0.1/spec/index.html"), ["Specification"]);
  assert.deepEqual(current("docs/guides/run-a-broker/index.html"), ["Guides"]);
  assert.deepEqual(current("docs/reference/schemas/envelope/index.html"), ["Docs"]);
  assert.deepEqual(current("poppy/index.html"), ["ALP and Poppy"]);
  assert.deepEqual(current("docs/project/governance/index.html"), ["Project"]);
  assert.deepEqual(current("docs/walkthroughs/index.html"), ["Docs"]);
  assert.deepEqual(current("index.html"), []);
});

test("the overview follows one exchange and links to the other three; the walkthroughs page has all four", () => {
  const { read } = site();
  const home = read("index.html");
  const scenarios = (html) => [...html.matchAll(/<section class="wt-scenario" id="(wt-[a-z-]+)"/g)].map((m) => m[1]);
  assert.deepEqual(scenarios(home), ["wt-one-organization"]);
  assert.ok(!home.includes('class="wt-tabs"'));
  for (const id of ["wt-two-organizations", "wt-connection-request", "wt-meeting"]) assert.match(home, new RegExp(`href="docs/walkthroughs/#${id}"`));
  const sentence = "These steps restate the specification’s worked examples (Appendix A). They are not recordings of a running system: what has been tested with real agents, and what has not, is on the status page.";
  assert.ok(textContent(home).replace(/\s+/g, " ").includes(sentence));
  const page = read("docs/walkthroughs/index.html");
  assert.deepEqual(scenarios(page), ["wt-one-organization", "wt-two-organizations", "wt-connection-request", "wt-meeting"]);
  assert.ok(textContent(page).replace(/\s+/g, " ").includes(sentence));
  // On a docs page the scenarios are h2 (under the page's h1) and their steps h3, and the outline lists them.
  assert.equal([...page.matchAll(/<h2 class="wt-title"/g)].length, 4);
  assert.match(page, /<h3 class="wt-step-title">/);
  assert.match(page, /href="#wt-meeting-title"/);
});

test("the scenario between two organizations says under its title that federation is Experimental, linking to Section 12.2", () => {
  const { read } = site();
  const page = read("docs/walkthroughs/index.html");
  const m = /<h2 class="wt-title" id="wt-two-organizations-title">[\s\S]*?<\/h2>\n<p class="wt-maturity">([\s\S]*?)<\/p>/.exec(page);
  assert.ok(m, "no maturity line directly under the title");
  assert.equal(textContent(m[1]), "Federation between brokers is Experimental in version 0.1: specified and testable, but more likely to change (Section 12.2).");
  assert.match(m[1], /class="maturity maturity-experimental"/);
  assert.match(m[1], /href="\.\.\/spec\/#122-the-federation-binding"/);
  assert.equal([...page.matchAll(/class="wt-maturity"/g)].length, 1);
});

test("every turned diagram of two or more columns scrolls inside its frame, with the line that says so", () => {
  const { read } = site();
  const page = read("docs/walkthroughs/index.html");
  const blocks = [...page.matchAll(/<div class="wt-svgs([^"]*)"[^>]*>[\s\S]*?<svg class="wt-svg wt-svg-narrow wt-cols-(\d)"[\s\S]*?<\/div>(\n<p class="wt-scroll-hint wt-hint-cols-(\d)">)?/g)];
  assert.equal(blocks.length, 4);
  for (const [, cls, cols, hint, hintCols] of blocks) {
    if (Number(cols) >= 2) {
      assert.equal(cls, " wt-svgs-scroll");
      assert.ok(hint, `a ${cols}-column drawing has no scroll line`);
      assert.equal(hintCols, cols);
    } else {
      assert.equal(cls, "");
      assert.ok(!hint);
    }
  }
  assert.deepEqual(blocks.map((b) => b[2]), ["1", "3", "2", "2"]);
});

test("the overview's order, and no sentence implies a hosted broker one can use or a third-party evaluator", () => {
  const { read } = site();
  const home = read("index.html");
  const order = [...home.matchAll(/<h2 id="([a-z-]+)"/g)].map((m) => m[1]);
  assert.deepEqual(order, ["at-a-glance", "problem", "guarantees", "follow-one-request", "what-you-would-do", "your-data", "tested", "two-ways-in", "other-protocols", "try-it", "take-part"]);
  const text = textContent(home).replace(/\s+/g, " ");
  assert.ok(!/independent evaluator/.test(text));
  assert.ok(!/uses a hosted one|with a hosted operator/.test(text));
  assert.ok(text.includes("Nothing has been deployed this way."));
  assert.ok(text.includes("The reference broker is new code and has not had an independent security review"));
  assert.match(text, /Agreements needed\s*None to implement it\./);
  assert.match(text, /Who is behind it\s*Brien Collier at Lucaryin wrote ALP\./);
});

test("the roadmap lists Section 19's items by their own lead-in words, after its maturity line, with no dates", () => {
  const { read } = site();
  const html = read("docs/status/roadmap/index.html");
  assert.match(html, /<span class="maturity maturity-future">Maturity: Future\. Not normative\.<\/span>/);
  const spec = fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), "..", "..", "..", "spec/alp-v0.1.md"), "utf8");
  const sec = spec.slice(spec.indexOf("\n## 19. Future work"), spec.indexOf("\n## Appendix A"));
  const leads = [...sec.matchAll(/^- \*\*(.+?)\*\*/gm)].map((m) => m[1]);
  assert.ok(leads.length >= 10);
  const linked = [...html.matchAll(/<li><a href="\.\.\/\.\.\/spec\/#19-future-work"><strong>([^<]*)<\/strong><\/a>/g)].map((m) => m[1]);
  assert.deepEqual(linked, leads);
  const text = textContent(html).replace(/\s+/g, " ");
  assert.ok(text.includes("Nothing here has a delivery date."));
  const body = textContent(/<div class="prose">([\s\S]*?)<\/div>/.exec(html)[1]);
  assert.ok(!/\b20\d\d\b/.test(body), "no year, so no date, in the roadmap's text");
});

test("the glossary ends with the other terms used on this site; other protocols opens with its table; status has the CI run", () => {
  const { read } = site();
  const g = read("docs/glossary/index.html");
  assert.match(g, /<h2 id="other-terms-used-on-this-site">/);
  for (const id of ["a2a", "conformance-vector", "connector", "federation", "mcp", "openid-connect-oidc", "reference-broker"]) assert.match(g, new RegExp(`<h3 id="${id}">`));
  const o = textContent(read("docs/other-protocols/index.html")).replace(/\s+/g, " ");
  assert.match(o, /Protocol What it connects MCP \(the Model Context Protocol\) Agents and tools A2A Agents and agents Poppy \(the Personal Agent Protocol\) A person’s agent and a business ALP People, through their agents, under each person’s rules/);
  const s = read("docs/status/index.html");
  assert.ok(textContent(s).includes("In the CI run of commit f05f787 on November 20, 2026, the reference broker’s test suite ran 661 tests and all passed"));
  assert.match(s, /href="https:\/\/github\.com\/AgentLiaisonProtocol\/agentliaisonprotocol\/actions\/runs\/44823159509"/);
  assert.ok(textContent(s).includes("written independently of the reference broker, by the same project"));
});
