import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runChecks, visibleText } from "../lib/checks.mjs";
import { CSP } from "../lib/shell.mjs";

const page = (body, { head = "", csp = true } = {}) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8">${csp ? `<meta http-equiv="Content-Security-Policy" content="${CSP}">` : ""}
<title>T</title><meta name="description" content="D."><link rel="canonical" href="https://agentliaisonprotocol.org/x/">${head}</head>
<body><main>${body}</main></body></html>`;

function site(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "alp-site-test-"));
  for (const [f, c] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true }); fs.writeFileSync(path.join(dir, f), c); }
  return dir;
}
const env = { config: { pages: [] }, examples: new Map(), usedExamples: [], offline: false };

test("a sound page passes every check", () => {
  const dir = site({
    "index.html": page('<h1 id="top">Home</h1><h2 id="a">A</h2><p><a href="docs/#b">docs</a> <a href="#a">here</a></p>'),
    "docs/index.html": page('<h1>Docs</h1><h2 id="b">B</h2><h3>C</h3><p><a href="../">home</a></p>'),
  });
  try {
    assert.deepEqual(runChecks(dir, new Map(), env).problems, []);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("the checks catch broken links, remote loads, inline code, structure and wording", () => {
  const dir = site({
    "index.html": page(
      '<h1>One</h1><h1>Two</h1><h4>skip</h4><p style="color:red" onclick="x()">A seamless PAP <a href="nowhere/">x</a> <a href="docs/#missing">y</a> <a href="#nope">z</a></p><img src="https://cdn.example/x.png"><script>alert(1)</script>',
      { head: '<link rel="stylesheet" href="https://fonts.example/a.css"><style>p{}</style>', csp: false },
    ),
    "docs/index.html": page("<h1>Docs</h1><!-- a comment -->"),
  });
  try {
    const p = runChecks(dir, new Map(), env).problems.join("\n");
    for (const want of [
      /link nowhere\/ .* isn't built/, /points to #missing/, /link #nope has no matching id/, /inline style attribute/, /event handler attribute onclick/,
      /loads https:\/\/cdn\.example\/x\.png from another origin/, /loads https:\/\/fonts\.example\/a\.css from another origin/, /inline <style>/, /inline <script>/,
      /needs exactly one Content-Security-Policy tag/, /has 2 h1 elements/, /skips from h1 to h4/, /<img> without alt/, /banned word\(s\): seamless/,
      /"PAP" appears 1 time\(s\) but only 0/, /docs\/index\.html: contains an HTML comment/,
    ]) assert.match(p, want);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test("visible text leaves out templates and scripts but keeps labels and descriptions", () => {
  const t = visibleText('<meta name="description" content="Desc"><p title="Tip">Shown</p><template>Hidden</template><a aria-label="Label">x</a>');
  assert.match(t, /Desc/);
  assert.match(t, /Tip/);
  assert.match(t, /Shown/);
  assert.match(t, /Label/);
  assert.doesNotMatch(t, /Hidden/);
});
