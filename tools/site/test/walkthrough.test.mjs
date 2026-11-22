import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { inline, markedJson, memberSpans, objectText, validateWalkthroughs } from "../lib/walkthrough.mjs";
import { decode, textContent, tokenize } from "../lib/html.mjs";
import { extractExamples } from "../lib/examples.mjs";
import { sectionIds } from "../lib/headings.mjs";
import { walkthroughs } from "../../../site/walkthroughs.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const spec = fs.readFileSync(path.join(ROOT, "spec/alp-v0.1.md"), "utf8");
const env = { root: ROOT, examples: extractExamples(spec), specIds: sectionIds(spec) };

test("memberSpans finds every member by path, and the span is the member's own text", () => {
  const text = '{\n  "a": 1,\n  "b": { "c": [true, "x"] },\n  "d": "e"\n}';
  const spans = memberSpans(text);
  const at = (p) => text.slice(...spans.get(p));
  assert.equal(at("a"), '"a": 1');
  assert.equal(at("b.c"), '"c": [true, "x"]');
  assert.equal(at("b.c.1"), '"x"');
  assert.equal(at("d"), '"d": "e"');
  assert.throws(() => memberSpans('{"a": }'));
});

test("marked JSON keeps the text exactly and wraps only the marked members", () => {
  for (const ex of env.examples.values()) {
    if (!ex.block) continue;
    const spans = [...memberSpans(ex.text).keys()].filter((k) => !k.includes("."));
    const { html, problems } = markedJson(ex.text, spans.slice(0, 3));
    assert.deepEqual(problems, []);
    assert.equal(textContent(html), ex.text, ex.name);
    assert.equal((html.match(/<mark /g) || []).length, Math.min(3, spans.length), ex.name);
  }
  assert.deepEqual(markedJson('{"a": 1}', ["nope"]).problems, ["no member nope"]);
});

test("the walkthrough data is valid: steps, hops, nodes and sections all exist", () => {
  assert.deepEqual(validateWalkthroughs(walkthroughs, env), []);
  assert.equal(walkthroughs.length, 4);
});

test("every object the walkthrough shows exists and every marked member is in it", () => {
  for (const w of walkthroughs) {
    for (const s of w.steps) {
      for (const o of s.objects || []) {
        const t = objectText(o, env);
        assert.equal(t.problem, undefined, `${w.id}: ${t.problem}`);
        const { problems } = markedJson(t.text, o.mark || []);
        assert.deepEqual(problems, [], `${w.id} ${s.title}`);
      }
    }
  }
});

test("inline markup escapes text and makes code and links", () => {
  const ctx = { href: (t) => `/x/${t}` };
  assert.equal(inline("a <b> `c&d` [e](glossary:f)", ctx), 'a &lt;b&gt; <code>c&amp;d</code> <a href="/x/glossary:f">e</a>');
});

// The Poppy page moved into the shared shell with its text unchanged. Compare the fragment with the page as
// it was before the move (the last commit that changed site/poppy/index.html), when the history is there.
const POPPY_COMMIT = "f05f787";

function visible(html) {
  let out = "";
  let skip = 0;
  for (const t of tokenize(html)) {
    if (t.type === "tag" && ["style", "script", "template", "head"].includes(t.name)) { skip += t.close ? -1 : 1; continue; }
    if (t.type === "text" && !skip) out += decode(t.raw) + " ";
  }
  return out.replace(/\s+/g, " ").trim();
}

test("the Poppy page's text is word for word the text it had before it moved into the shell", (t) => {
  let before;
  try {
    before = execFileSync("git", ["show", `${POPPY_COMMIT}:site/poppy/index.html`], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    t.skip("git history not available");
    return;
  }
  const main = (h) => h.slice(h.indexOf("<article"), h.indexOf("</article>") + 10);
  const now = fs.readFileSync(path.join(ROOT, "site/pages/poppy.html"), "utf8");
  assert.equal(visible(main(now)), visible(main(before)));
});
