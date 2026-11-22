import test from "node:test";
import assert from "node:assert/strict";
import { micromark } from "micromark";
import { fencedBlocks, normalizeFences } from "../lib/fences.mjs";
import { renderMarkdown } from "../lib/markdown.mjs";
import { codeBlockProblems } from "../lib/checks.mjs";
import { tokenize } from "../lib/html.mjs";

const TIGHT = "1. Check:\n   ```sql\n   -- a comment\n   select 1;\n   ```\n2. Next.\n";

test("the fence scanner finds blocks in lists and block quotes, with the fence's indentation removed", () => {
  const md = "Text\n\n```json\n{\"a\": 1}\n```\n\n" + TIGHT + "\n> ```\n> quoted\n>   two\n> ```\n\n~~~~\n```\nnot a fence\n```\n~~~~\n\n- ```sh\n  npm test\n  ```\n\nA ``` code span ``` here.\n\n```\nunclosed\n";
  const b = fencedBlocks(md);
  assert.deepEqual(b.map((x) => [x.line, x.info, x.text]), [
    [3, "json", "{\"a\": 1}\n"],
    [8, "sql", "-- a comment\nselect 1;\n"],
    [14, "", "quoted\n  two\n"],
    [19, "", "```\nnot a fence\n```\n"],
    [25, "sh", "npm test\n"],
    [31, "", "unclosed\n"],
  ]);
});

test("micromark 4.0.2 drops the line endings of a fence that directly follows text in a tight list item", () => {
  // The source is valid CommonMark (a fence may interrupt a paragraph); the renderer is what fails. The fault
  // is in micromark's own HTML compiler (lib/compile.js), which package-lock.json pins at 4.0.2 as well.
  // If this ever fails, micromark keeps the lines now and normalizeFences can go.
  assert.match(micromark(TIGHT), /<code class="language-sql">-- a commentselect 1;\n<\/code>/, "micromark no longer drops the line endings");
});

test("normalizeFences puts a blank line before such a fence, and the block keeps its lines", () => {
  const { md, lines } = normalizeFences(TIGHT);
  assert.deepEqual(lines, [2]);
  assert.equal(md, "1. Check:\n\n   ```sql\n   -- a comment\n   select 1;\n   ```\n2. Next.\n");
  const r = renderMarkdown(TIGHT, { file: "t.md", resolveHref: (h) => h, figureFor: () => null, problems: [] });
  assert.match(r.body, /<code class="language-sql">-- a comment\nselect 1;\n<\/code>/);
  // Nothing else is touched: fences after a blank line, top-level fences and quoted fences stay as they are.
  for (const s of ["Text\n```\na\n```\n", "1. a\n\n   ```\n   b\n   ```\n", "> a\n> ```\n> b\n> ```\n", "1. a\n   ```\n   b\n   ```\n   ```\n   c\n   ```\n"]) {
    const n = normalizeFences(s);
    assert.equal(n.md, s === "1. a\n   ```\n   b\n   ```\n   ```\n   c\n   ```\n" ? "1. a\n\n   ```\n   b\n   ```\n   ```\n   c\n   ```\n" : s);
  }
});

test("the code-block check fails when a block's text changed on the page, and passes when it is exact", () => {
  const blocks = fencedBlocks("```mermaid\ngraph\n```\n\n```sql\na\nb\n```\n\n```\nc\n```\n");
  const main = (html) => tokenize(html);
  const ok = '<figure>…</figure><pre tabindex="0"><code class="language-sql">a\nb\n</code></pre><pre><code>c\n</code></pre>';
  assert.deepEqual(codeBlockProblems(main(ok), { file: "x.md", blocks }, "x/index.html"), []);
  const broken = '<pre><code class="language-sql">ab\n</code></pre><pre><code>c\n</code></pre>';
  const p = codeBlockProblems(main(broken), { file: "x.md", blocks }, "x/index.html");
  assert.equal(p.length, 1);
  assert.match(p[0], /the fenced block at x\.md:5 \(sql\) isn't on the page with its text unchanged/);
  // Order matters: a block found only before the previous match counts as missing.
  const swapped = '<pre><code>c\n</code></pre><pre><code class="language-sql">a\nb\n</code></pre>';
  assert.equal(codeBlockProblems(main(swapped), { file: "x.md", blocks }, "x/index.html").length, 1);
  // Highlighting spans and entities don't matter, only the text.
  const spans = '<pre><code class="language-sql"><span>a</span>\n&#98;\n</code></pre><pre><code>c\n</code></pre>';
  assert.deepEqual(codeBlockProblems(main(spans), { file: "x.md", blocks }, "x/index.html"), []);
});
