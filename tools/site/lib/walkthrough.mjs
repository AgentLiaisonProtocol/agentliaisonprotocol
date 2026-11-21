// The walkthrough on the overview: real exchanges from the specification's Appendix A, step by step, built
// from the data in site/walkthroughs.mjs. Every object it shows is taken at build time from a named example
// of the specification or from a vector file, never retyped; the members a step talks about are marked.
//
// Without JavaScript every scenario and every step is visible, in order, as ordered lists. site.js turns the
// block into tabs (one per scenario) with one step at a time; the markup carries everything it needs as
// classes and data attributes (no inline styles).

import fs from "node:fs";
import path from "node:path";
import { esc } from "./html.mjs";
import { highlightJson } from "./highlight.mjs";

// ---------------------------------------------------------------- JSON members and marks

/**
 * Where each member of a JSON text is: a Map from its path ("from", "receipt.ledger_hash",
 * "brokers.0.jkt") to [start, end) offsets covering `"key": value` for object members and the value for
 * array items. Throws on text that is not JSON.
 */
export function memberSpans(text) {
  const spans = new Map();
  let i = 0;
  const fail = (what) => { throw new Error(`not JSON at offset ${i}: ${what}`); };
  const ws = () => { while (i < text.length && /\s/.test(text[i])) i++; };
  const expect = (c) => { ws(); if (text[i] !== c) fail(`expected ${c}`); i++; };
  const str = () => {
    if (text[i] !== '"') fail("expected a string");
    const s = i++;
    while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
    if (i >= text.length) fail("unterminated string");
    i++;
    return JSON.parse(text.slice(s, i));
  };
  const value = (p) => {
    ws();
    const c = text[i];
    if (c === "{") {
      i++; ws();
      if (text[i] === "}") { i++; return; }
      for (;;) {
        ws();
        const start = i;
        const key = str();
        expect(":");
        const kp = [...p, key];
        value(kp);
        spans.set(kp.join("."), [start, i]);
        ws();
        if (text[i] === ",") { i++; continue; }
        expect("}");
        return;
      }
    }
    if (c === "[") {
      i++; ws();
      if (text[i] === "]") { i++; return; }
      for (let n = 0; ; n++) {
        ws();
        const start = i;
        const kp = [...p, String(n)];
        value(kp);
        spans.set(kp.join("."), [start, i]);
        ws();
        if (text[i] === ",") { i++; continue; }
        expect("]");
        return;
      }
    }
    if (c === '"') { str(); return; }
    const m = /^(?:-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i, i + 64));
    if (!m) fail("unexpected character");
    i += m[0].length;
  };
  value([]);
  ws();
  if (i !== text.length) fail("trailing text");
  return spans;
}

/**
 * Highlighted HTML for a JSON text with the members at `marks` (paths as memberSpans names them) wrapped in
 * <mark>. The text content of the result is exactly `text`. Unknown or overlapping paths are returned in
 * `problems`.
 */
export function markedJson(text, marks = []) {
  const spans = memberSpans(text);
  const problems = [];
  const ranges = [];
  for (const m of marks) {
    const r = spans.get(m);
    if (!r) { problems.push(`no member ${m}`); continue; }
    ranges.push(r);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  for (let k = 1; k < ranges.length; k++) if (ranges[k][0] < ranges[k - 1][1]) problems.push("marked members overlap");
  let out = "";
  let at = 0;
  for (const [s, e] of ranges) {
    if (s < at) continue;
    out += highlightJson(text.slice(at, s)) + `<mark class="wt-mark">${highlightJson(text.slice(s, e))}</mark>`;
    at = e;
  }
  out += highlightJson(text.slice(at));
  return { html: out, problems };
}

// ---------------------------------------------------------------- inline text

/**
 * The small inline markup of site/walkthroughs.mjs: `code`, and [text](target) where target is
 * glossary:<id> (the glossary page), spec:<number> (a specification section) or a site path.
 */
export function inline(s, ctx) {
  const parts = String(s).split(/(`[^`]*`|\[[^\]]+\]\([^)]+\))/);
  return parts.map((p) => {
    if (p.startsWith("`") && p.endsWith("`") && p.length >= 2) return `<code>${esc(p.slice(1, -1))}</code>`;
    const m = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(p);
    if (m) return `<a href="${esc(ctx.href(m[2]))}">${inline(m[1], ctx)}</a>`;
    return esc(p);
  }).join("");
}

/** A section reference ("6.6", "A.1") as a link into the specification page. */
function secLink(n, ctx) {
  const label = /^[A-Z]/.test(n) ? `Appendix ${n}` : `Section ${n}`;
  return `<a href="${esc(ctx.href(`spec:${n}`))}">${esc(label)}</a>`;
}

// ---------------------------------------------------------------- objects

/** Read a value at a dotted path ("objects.propose", "cases.name=…") from parsed JSON. */
function at(value, p) {
  let v = value;
  for (const seg of p.split(".")) {
    if (v === undefined || v === null) return undefined;
    const eq = /^(\w+)=(.*)$/.exec(seg);
    if (eq && Array.isArray(v)) v = v.find((x) => x && x[eq[1]] === eq[2]);
    else v = v[seg];
  }
  return v;
}

/**
 * The text of an object a step shows: { example: name } from the specification's named examples, or
 * { vector: file, path } from a vector file (pretty-printed with two spaces, as the vector holds it).
 */
export function objectText(obj, env) {
  if (obj.example) {
    const ex = env.examples.get(obj.example);
    if (!ex) return { problem: `uses example ${obj.example}, which the specification doesn't have` };
    return { text: ex.text.replace(/\n$/, ""), source: `the specification’s example <code>${esc(obj.example)}</code>` };
  }
  if (obj.vector) {
    let json;
    try { json = JSON.parse(fs.readFileSync(path.join(env.root, obj.vector), "utf8")); } catch (e) { return { problem: `can't read ${obj.vector} (${e.message})` }; }
    const v = obj.path ? at(json, obj.path) : json;
    if (v === undefined) return { problem: `${obj.vector} has nothing at ${obj.path}` };
    return { text: JSON.stringify(v, null, 2), source: `<code>${esc(obj.vector)}</code>` };
  }
  return { problem: "an object needs example or vector" };
}

// ---------------------------------------------------------------- the diagram

const COL = 128, GAP = 38, ROW = 40, RGAP = 34, PAD = 6;

/**
 * Boxes for the nodes on a grid. `narrow` turns the grid a quarter turn (columns become rows), for small
 * screens: a scenario laid out in one wide row becomes one column.
 */
function layout(w, narrow = false) {
  // Turned, a node that spans columns takes one row, and empty rows close up.
  const starts = [...new Set(w.nodes.map((n) => n.col))].sort((x, y) => x - y);
  const place = (n) => (narrow ? { col: n.row, row: starts.indexOf(n.col), cs: 1, rs: 1 } : { col: n.col, row: n.row, cs: n.span || 1, rs: 1 });
  const cells = w.nodes.map((n) => [n, place(n)]);
  const cols = Math.max(...cells.map(([, c]) => c.col + c.cs));
  const rows = Math.max(...cells.map(([, c]) => c.row + c.rs));
  const width = cols * COL + (cols - 1) * GAP + 2 * PAD;
  const height = rows * ROW + (rows - 1) * RGAP + 2 * PAD;
  const box = new Map();
  for (const [n, c] of cells) {
    box.set(n.id, { x: PAD + c.col * (COL + GAP), y: PAD + c.row * (ROW + RGAP), w: c.cs * COL + (c.cs - 1) * GAP, h: c.rs * ROW + (c.rs - 1) * RGAP });
  }
  return { cols, width, height, box };
}

const r1 = (n) => Math.round(n * 10) / 10;

/** Where the line from a box's centre towards (dx, dy) leaves the box. */
function edgePoint(b, dx, dy) {
  const cx = b.x + b.w / 2, cy = b.y + b.h / 2;
  const tx = dx === 0 ? Infinity : (b.w / 2) / Math.abs(dx);
  const ty = dy === 0 ? Infinity : (b.h / 2) / Math.abs(dy);
  const t = Math.min(tx, ty);
  return [cx + dx * t, cy + dy * t];
}

function hopSvg(h, lay) {
  const a = lay.box.get(h.from), b = lay.box.get(h.to);
  let dx = (b.x + b.w / 2) - (a.x + a.w / 2), dy = (b.y + b.h / 2) - (a.y + a.h / 2);
  const len = Math.hypot(dx, dy);
  dx /= len; dy /= len;
  // Two hops between the same boxes (out and back) sit side by side.
  const off = (h.offset || 0) * 6;
  const nx = -dy * off, ny = dx * off;
  let [x1, y1] = edgePoint(a, dx, dy);
  let [x2, y2] = edgePoint(b, -dx, -dy);
  x1 += nx + dx * 3; y1 += ny + dy * 3; x2 += nx - dx * 3; y2 += ny - dy * 3;
  const cls = `wt-hop${h.refused ? " wt-hop-refused" : ""}${h.link ? " wt-hop-link" : ""}`;
  let end = "";
  if (h.link) {
    end = "";
  } else if (h.refused) {
    // A cross where the hop is stopped.
    const s = 4.5;
    end = `<path class="wt-hop-end" d="M${r1(x2 - s)} ${r1(y2 - s)}L${r1(x2 + s)} ${r1(y2 + s)}M${r1(x2 + s)} ${r1(y2 - s)}L${r1(x2 - s)} ${r1(y2 + s)}"/>`;
  } else {
    const bx = x2 - dx * 8, by = y2 - dy * 8;
    end = `<path class="wt-hop-head" d="M${r1(x2)} ${r1(y2)}L${r1(bx - dy * 4.5)} ${r1(by + dx * 4.5)}L${r1(bx + dy * 4.5)} ${r1(by - dx * 4.5)}Z"/>`;
  }
  const lineEnd = h.refused ? [x2, y2] : h.link ? [x2, y2] : [x2 - dx * 7, y2 - dy * 7];
  return `<g class="${cls}" data-hop="${esc(h.id)}"><path class="wt-hop-line" d="M${r1(x1)} ${r1(y1)}L${r1(lineEnd[0])} ${r1(lineEnd[1])}"/>${end}</g>`;
}

function nodeSvg(n, lay) {
  const b = lay.box.get(n.id);
  const lines = [].concat(n.label);
  const cy = b.y + b.h / 2;
  const first = cy - (lines.length - 1) * 7 + 4;
  const text = lines.map((l, k) => `<text x="${r1(b.x + b.w / 2)}" y="${r1(first + k * 14)}" text-anchor="middle">${esc(l)}</text>`).join("");
  const kind = n.kind || "agent";
  return `<g class="wt-node wt-node-${esc(n.side || "c")} wt-kind-${esc(kind)}" data-node="${esc(n.id)}"><rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="${kind === "person" ? 20 : kind === "doc" ? 4 : 9}"/>${text}</g>`;
}

/** A node's name in running text: its `name`, or its label on one line. */
export function nodeName(w, id) {
  const n = w.nodes.find((x) => x.id === id);
  return n.name || [].concat(n.label).join(" ");
}

/**
 * Both drawings of a scenario's diagram in one container. On a small screen the turned drawing keeps its
 * labels at 12px; when it has three or more columns it is wider than a phone, so the container scrolls
 * sideways and a line under it says so.
 */
function diagramBlock(w, base) {
  const scrolls = layout(w, true).cols >= 3;
  const box = scrolls ? ' tabindex="0" role="group" aria-label="Diagram: scroll sideways to see all of it"' : "";
  const hint = scrolls ? '\n<p class="wt-scroll-hint">Scroll sideways to see the whole diagram.</p>' : "";
  return `<div class="wt-svgs${scrolls ? " wt-svgs-scroll" : ""}"${box}>
${diagramSvg(w, base)}
${diagramSvg(w, base, true)}
</div>${hint}`;
}

export function diagramSvg(w, idBase, narrow = false) {
  const lay = layout(w, narrow);
  const name = (id) => nodeName(w, id);
  const desc = `${w.nodes.map((n) => name(n.id)).join(", ")}. ${w.hops.map((h) => `${name(h.from)} ${h.link ? "and" : "to"} ${name(h.to)}${h.refused ? " (refused)" : ""}`).join("; ")}.`;
  const id = `${idBase}-${narrow ? "narrow" : "wide"}`;
  return `<svg class="wt-svg wt-svg-${narrow ? "narrow" : "wide"} wt-cols-${lay.cols}" viewBox="0 0 ${lay.width} ${lay.height}" width="${lay.width}" role="img" aria-labelledby="${id}-title ${id}-desc">
<title id="${id}-title">${esc(`The parties in this scenario`)}</title>
<desc id="${id}-desc">${esc(desc)}</desc>
${w.hops.map((h) => hopSvg(h, lay)).join("\n")}
${w.nodes.map((n) => nodeSvg(n, lay)).join("\n")}
</svg>`;
}

// ---------------------------------------------------------------- the component

/**
 * Check the data's shape and its references, so a typo fails the build. Returns a list of problems.
 */
export function validateWalkthroughs(list, env) {
  const problems = [];
  const ids = new Set();
  for (const w of list) {
    const where = `site/walkthroughs.mjs ${w.id}`;
    if (!/^[a-z][a-z0-9-]*$/.test(w.id || "") || ids.has(w.id)) problems.push(`${where}: needs a unique lower-case id`);
    ids.add(w.id);
    const nodes = new Set(w.nodes.map((n) => n.id));
    const hops = new Set(w.hops.map((h) => h.id));
    for (const h of w.hops) if (!nodes.has(h.from) || !nodes.has(h.to)) problems.push(`${where}: hop ${h.id} names a node that doesn't exist`);
    if (w.steps.length < 4 || w.steps.length > 6) problems.push(`${where}: has ${w.steps.length} steps (four to six)`);
    w.steps.forEach((s, k) => {
      for (const h of s.hops || []) if (!hops.has(h)) problems.push(`${where} step ${k + 1}: hop ${h} doesn't exist`);
      for (const n of s.nodes || []) if (!nodes.has(n)) problems.push(`${where} step ${k + 1}: node ${n} doesn't exist`);
      if (!s.refs?.length) problems.push(`${where} step ${k + 1}: names no specification section`);
      for (const r of s.refs || []) if (!env.specIds.has(r)) problems.push(`${where} step ${k + 1}: section ${r} doesn't exist in the specification`);
      const sentences = s.text.join(" ").split(/(?<=[.?])\s+(?=[A-Z`])/).length;
      if (sentences < 1 || sentences > 3) problems.push(`${where} step ${k + 1}: ${sentences} sentences (one to three)`);
    });
    for (const r of [].concat(w.appendix)) if (!env.specIds.has(r)) problems.push(`${where}: appendix section ${r} doesn't exist`);
  }
  return problems;
}

/**
 * The walkthrough's HTML. env: the build environment (examples, specIds, root, problems, useExample);
 * pctx: the page context (link()); pageUrl for recording example use.
 */
/**
 * Render scenarios of the walkthrough. `level` is the heading level of a scenario's title (its steps use the
 * next level). With one scenario there are no tabs and no scenario number.
 */
export function renderWalkthroughs(list, env, pctx, pageUrl, { level = 3 } = {}) {
  const hs = `h${level}`, hst = `h${level + 1}`;
  const single = list.length === 1;
  const problems = env.problems;
  problems.push(...validateWalkthroughs(list, env));
  const ctx = {
    href(target) {
      if (target.startsWith("glossary:")) return pctx.link(`/docs/glossary/#${target.slice(9)}`);
      if (target.startsWith("spec:")) {
        const n = target.slice(5);
        const id = env.specIds.get(n);
        if (!id) problems.push(`site/walkthroughs.mjs: section ${n} doesn't exist in the specification`);
        return pctx.link(`/docs/spec/#${id || ""}`);
      }
      if (target.startsWith("/")) return pctx.link(target);
      problems.push(`site/walkthroughs.mjs: link target ${target} is not glossary:, spec: or a site path`);
      return "#";
    },
  };

  const tabs = list.map((w, i) => `<button type="button" role="tab" class="wt-tab" id="wt-tab-${esc(w.id)}" aria-controls="wt-${esc(w.id)}" aria-selected="${i === 0 ? "true" : "false"}" tabindex="${i === 0 ? "0" : "-1"}"><span class="wt-tab-n">${i + 1}</span> ${esc(w.short || w.title)}</button>`).join("");

  const scenarios = list.map((w, wi) => {
    const base = `wt-${w.id}`;
    const nameOf = (id) => nodeName(w, id);
    const steps = w.steps.map((s, si) => {
      const sideHtml = (key, cls) => {
        const text = s[key];
        if (!text) return "";
        const label = key === "c" ? (s.cLabel || w.sides.c) : `On ${w.sides[key]}’s side`;
        return `<div class="wt-side ${cls}"><p class="wt-side-label">${esc(label)}</p><p>${inline(text, ctx)}</p></div>`;
      };
      const sides = [sideHtml("a", "wt-side-a"), sideHtml("b", "wt-side-b"), sideHtml("c", "wt-side-c")].filter(Boolean).join("");
      const hopText = (s.hops || []).map((h) => {
        const hop = w.hops.find((x) => x.id === h);
        return hop ? `${nameOf(hop.from)} ${hop.link ? "↔" : "→"} ${nameOf(hop.to)}${hop.refused ? " (refused)" : ""}` : "";
      }).filter(Boolean);
      const where = hopText.length ? hopText.join("; ") : (s.nodes || []).map(nameOf).join(", ");
      const objects = (s.objects || []).map((o) => {
        const t = objectText(o, env);
        if (t.problem) { problems.push(`site/walkthroughs.mjs ${w.id} step ${si + 1}: ${t.problem}`); return ""; }
        if (o.example) env.useExample(pageUrl, o.example);
        const { html, problems: p } = markedJson(t.text, o.mark || []);
        for (const x of p) problems.push(`site/walkthroughs.mjs ${w.id} step ${si + 1}: ${x}`);
        const marked = (o.mark || []).map((m) => `<code>${esc(m)}</code>`).join(", ");
        return `<details class="wt-object">
<summary>Show the object<span class="wt-object-name">: ${inline(o.label, ctx)}</span></summary>
<p class="wt-object-source">From ${t.source}${o.note ? ` (${inline(o.note, ctx)})` : ""}.${marked ? ` Marked: ${marked}.` : ""}</p>
<pre class="wt-pre"><code class="language-json">${html}</code></pre>
</details>`;
      }).join("\n");
      const refs = s.refs.map((r) => secLink(r, ctx)).join(", ");
      return `<li class="wt-step" id="${base}-${si + 1}" data-hops="${esc((s.hops || []).join(" "))}" data-nodes="${esc((s.nodes || []).join(" "))}">
<${hst} class="wt-step-title"><span class="wt-step-n">Step ${si + 1} of ${w.steps.length}.</span> ${inline(s.title, ctx)}</${hst}>
${where ? `<p class="wt-where">${esc(where)}</p>` : ""}
${s.text.map((t) => `<p>${inline(t, ctx)}</p>`).join("")}
${sides ? `<div class="wt-sides">${sides}</div>` : ""}
<p class="wt-refs">From the specification: ${refs}</p>
${objects}
</li>`;
    }).join("\n");
    const appx = [].concat(w.appendix).map((r) => secLink(r, ctx)).join(" and ");
    return `<section class="wt-scenario" id="${base}" aria-labelledby="${base}-title" data-wt-scenario>
<${hs} class="wt-title" id="${base}-title">${single ? "" : `<span class="wt-title-n">${wi + 1}.</span> `}${esc(w.title)}</${hs}>
<p class="wt-intro">${inline(w.intro, ctx)} <span class="wt-from">From ${appx}.</span></p>
<figure class="wt-diagram">
${diagramBlock(w, base)}
<figcaption class="wt-legend"><span class="wt-key wt-key-a">${esc(w.sides.a)}’s side</span> <span class="wt-key wt-key-b">${esc(w.sides.b)}’s side</span>${w.sides.c ? ` <span class="wt-key wt-key-c">${esc(w.sides.cKey || w.sides.c)}</span>` : ""}</figcaption>
</figure>
<ol class="wt-steps">
${steps}
</ol>
</section>`;
  }).join("\n");

  return `<div class="wt" data-wt>
${single ? "" : `<div class="wt-tabs" role="tablist" aria-label="Scenarios" hidden>${tabs}</div>
`}${scenarios}
<div class="wt-controls" hidden>
<button type="button" class="wt-prev">Previous</button>
<ol class="wt-markers" aria-label="Steps"></ol>
<button type="button" class="wt-next">Next</button>
</div>
<p class="wt-live" aria-live="polite"></p>
</div>`;
}
