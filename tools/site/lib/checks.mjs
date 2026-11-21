// The checks the build runs on its own output (tools/site/README.md lists them). Each failure names the
// file and what is wrong.

import fs from "node:fs";
import path from "node:path";
import { decode, tokenize } from "./html.mjs";
import { resolveSitePath, splitUrl } from "./urls.mjs";
import { CSP } from "./shell.mjs";
import { exampleProblem } from "./examples.mjs";

export const BANNED = [
  "seamless(?:ly)?", "powerful(?:ly)?", "robust(?:ly|ness)?", "revolutionary", "leverag(?:e|es|ed|ing)", "unlock(?:s|ed|ing)?",
  "cutting-edge", "game-changing", "best-in-class", "world-class", "effortless(?:ly)?", "blazing(?:ly)?", "supercharg(?:e|es|ed|ing)",
  "next-generation", "enterprise-grade",
];
const BANNED_RE = new RegExp(`\\b(?:${BANNED.join("|")})\\b`, "gi");
const PAP_RE = /\bPAP\b/g;
const OPEN_SOURCE_RE = /\bopen[\s-]+source\b/gi;

// Tags that may appear inside rendered Markdown content (anything else is source HTML that escaped).
const CONTENT_TAGS = new Set(["p", "a", "code", "pre", "em", "strong", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "thead", "tbody", "tr", "th", "td", "div", "blockquote", "hr", "br", "span", "del", "input", "figure", "figcaption", "svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "text", "tspan", "title", "desc", "defs", "marker", "sup", "section", "time", "button", "template", "wbr"]);

function walk(dir, base = dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p, base));
    else out.push(path.relative(base, p).split(path.sep).join("/"));
  }
  return out;
}

/** The site path of an output file: "docs/spec/index.html" -> "/docs/spec/". */
function siteUrlOf(file) {
  return "/" + file.replace(/(^|\/)index\.html$/, "$1");
}

/** Visible text of a page (text nodes outside script/style/template, plus alt, title and aria-label). */
export function visibleText(html) {
  const toks = tokenize(html);
  let out = "";
  let skip = 0;
  for (const t of toks) {
    if (t.type === "tag") {
      if (["script", "style", "template"].includes(t.name)) { if (t.close) skip = Math.max(0, skip - 1); else skip++ }
      for (const k of ["alt", "title", "aria-label"]) if (t.attrs[k]) out += " " + t.attrs[k] + " ";
      if (t.name === "meta" && /description/.test(t.attrs.name || t.attrs.property || "")) out += " " + (t.attrs.content || "") + " ";
      out += " ";
    } else if (t.type === "text" && !skip) out += decode(t.raw);
  }
  return out.replace(/\s+/g, " ");
}

function contexts(text, re, width = 50) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text))) out.push(text.slice(Math.max(0, m.index - width), m.index + m[0].length + width).trim());
  return out;
}

/**
 * Run every check over `outDir`. records: Map(page url -> record from the page kinds; record.page is the
 * manifest entry). env: the build environment (config, examples, used examples, offline).
 * Returns { problems: [string], notes: { openSource: [], pap: [] } }.
 */
export function runChecks(outDir, records, env) {
  const problems = [];
  const notes = { openSource: [], pap: [] };
  const files = walk(outDir);
  const fileSet = new Set(files);
  const htmlFiles = files.filter((f) => f.endsWith(".html"));
  const ids = new Map();
  const parsed = new Map();
  for (const f of htmlFiles) {
    const html = fs.readFileSync(path.join(outDir, f), "utf8");
    const toks = tokenize(html);
    parsed.set(f, { html, toks });
    const set = new Set();
    for (const t of toks) if (t.type === "tag" && !t.close) { if (t.attrs.id) set.add(t.attrs.id); if (t.name === "a" && t.attrs.name) set.add(t.attrs.name); }
    ids.set(f, set);
  }

  // Resolve a site path to an output file, or null.
  const target = (p) => {
    if (p === null) return null;
    const rel = p.replace(/^\//, "");
    if (p.endsWith("/")) return fileSet.has(rel + "index.html") ? rel + "index.html" : null;
    if (fileSet.has(rel)) return rel;
    return null;
  };

  for (const page of env.config.pages) {
    const f = page.url.endsWith("/") ? page.url.slice(1) + "index.html" : page.url.slice(1);
    if (!fileSet.has(f)) problems.push(`${page.url}: in the manifest but not built`);
  }

  for (const f of htmlFiles) {
    const { html, toks } = parsed.get(f);
    const url = siteUrlOf(f);
    const record = records.get(url) || records.get("/" + f);
    const where = f;

    // 1. Internal links and fragments.
    for (const t of toks) {
      if (t.type !== "tag" || t.close) continue;
      for (const attr of ["href", "src"]) {
        const v = t.attrs[attr];
        if (v === undefined) continue;
        if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(v)) continue; // other schemes and sites (check 2 covers loads)
        if (v.startsWith("#")) {
          const frag = decodeURIComponent(v.slice(1));
          if (frag && !ids.get(f).has(frag)) problems.push(`${where}: link ${v} has no matching id on the page`);
          continue;
        }
        const base = env.notFoundRootRelative && url === "/404.html" ? "/" : url;
        const { path: p, fragment } = resolveSitePath(base, v);
        const tf = target(p);
        if (!tf) { problems.push(`${where}: link ${v} (${attr} of <${t.name}>) resolves to ${p ?? "outside the site"}, which isn't built`); continue; }
        if (fragment && fragment !== "#" && tf.endsWith(".html")) {
          const frag = decodeURIComponent(fragment.slice(1));
          if (!ids.get(tf).has(frag)) problems.push(`${where}: link ${v} points to #${frag}, which ${tf} doesn't have`);
        }
      }
    }

    // 2. Nothing from another origin; no inline style, script or handler; the CSP tag.
    {
      let cspCount = 0;
      for (let i = 0; i < toks.length; i++) {
        const t = toks[i];
        if (t.type !== "tag" || t.close) continue;
        for (const [k, v] of Object.entries(t.attrs)) {
          if (/^on/.test(k)) problems.push(`${where}: event handler attribute ${k} on <${t.name}>`);
          if (k === "style") problems.push(`${where}: inline style attribute on <${t.name}>`);
          if (["src", "srcset", "poster", "data", "background"].includes(k) && isRemote(v)) problems.push(`${where}: <${t.name} ${k}> loads ${v} from another origin`);
          if (k === "srcset" && v.split(",").some((s) => isRemote(s.trim().split(/\s+/)[0]))) problems.push(`${where}: <${t.name} srcset> loads from another origin`);
        }
        if (t.name === "link" && t.attrs.href && /(?:^|\s)(?:stylesheet|icon|preload|modulepreload|manifest|prefetch)(?:\s|$)/i.test(t.attrs.rel || "") && isRemote(t.attrs.href)) problems.push(`${where}: <link rel=${t.attrs.rel}> loads ${t.attrs.href} from another origin`);
        if (["iframe", "object", "embed", "frame", "applet", "base"].includes(t.name)) problems.push(`${where}: <${t.name}> is not allowed`);
        if (t.name === "style") problems.push(`${where}: inline <style>`);
        if (t.name === "script") {
          const next = toks[i + 1];
          if (!t.attrs.src) problems.push(`${where}: inline <script>`);
          else if (next && next.type === "text" && next.raw.trim()) problems.push(`${where}: <script src> with inline content`);
        }
        if (t.name === "meta" && (t.attrs["http-equiv"] || "").toLowerCase() === "content-security-policy") {
          cspCount++;
          if (t.attrs.content !== CSP) problems.push(`${where}: the Content-Security-Policy tag differs from the one in tools/site/lib/shell.mjs`);
        }
      }
      if (!env.offline && cspCount !== 1) problems.push(`${where}: needs exactly one Content-Security-Policy tag (has ${cspCount})`);
    }

    // 3. One h1, title, description, canonical, lang; heading levels; text alternatives.
    {
      const htmlTag = toks.find((t) => t.type === "tag" && t.name === "html" && !t.close);
      if (!htmlTag || htmlTag.attrs.lang !== "en") problems.push(`${where}: <html> needs lang="en"`);
      const h1s = toks.filter((t) => t.type === "tag" && !t.close && t.name === "h1").length;
      if (h1s !== 1) problems.push(`${where}: has ${h1s} h1 elements (needs exactly one)`);
      const ti = toks.findIndex((t) => t.type === "tag" && !t.close && t.name === "title");
      if (ti === -1 || !(toks[ti + 1]?.type === "text" && toks[ti + 1].raw.trim())) problems.push(`${where}: no <title>`);
      if (!toks.some((t) => t.type === "tag" && t.name === "meta" && t.attrs.name === "description" && t.attrs.content?.trim())) problems.push(`${where}: no description`);
      if (!toks.some((t) => t.type === "tag" && t.name === "link" && t.attrs.rel === "canonical" && /^https:\/\//.test(t.attrs.href || ""))) problems.push(`${where}: no canonical URL`);
      let prev = 0;
      for (const t of toks) {
        if (t.type !== "tag" || t.close || !/^h[1-6]$/.test(t.name)) continue;
        const d = Number(t.name[1]);
        if (prev && d > prev + 1) problems.push(`${where}: heading level skips from h${prev} to h${d}${t.attrs.id ? ` (#${t.attrs.id})` : ""}`);
        prev = d;
      }
      for (let i = 0; i < toks.length; i++) {
        const t = toks[i];
        if (t.type !== "tag" || t.close) continue;
        if (t.name === "img" && t.attrs.alt === undefined) problems.push(`${where}: <img> without alt`);
        if (t.name === "svg" && t.attrs["aria-hidden"] !== "true") {
          const labelled = t.attrs["aria-label"] || t.attrs["aria-labelledby"];
          const hasTitle = toks[i + 1]?.type === "tag" && toks[i + 1].name === "title";
          if (t.attrs.role !== "img" || !(labelled || hasTitle)) problems.push(`${where}: an <svg> that isn't aria-hidden needs role="img" and a text alternative`);
        }
      }
    }

    // 4. Pages rendered from Markdown: same counts as the source; no comments, Mermaid or source HTML.
    {
      if (html.includes("<!--")) problems.push(`${where}: contains an HTML comment`);
      if (/language-mermaid/.test(html)) problems.push(`${where}: contains a raw Mermaid block`);
    }
    if (record?.expect) {
      const main = region(toks, (t) => t.name === "main");
      const count = (pred) => main.filter((t) => t.type === "tag" && !t.close && pred(t)).length;
      const got = {
        headings: count((t) => /^h[1-6]$/.test(t.name)),
        tables: count((t) => t.name === "table"),
        pre: count((t) => t.name === "pre"),
        figures: count((t) => t.name === "figure" && /\bfigure-diagram\b/.test(t.attrs.class || "")),
      };
      const e = record.expect;
      if (got.headings !== e.headings) problems.push(`${where}: ${got.headings} headings, but the source has ${e.headings}`);
      if (got.tables !== e.tables) problems.push(`${where}: ${got.tables} tables, but the source has ${e.tables}`);
      if (got.pre + got.figures !== e.code) problems.push(`${where}: ${got.pre} code blocks and ${got.figures} figures, but the source has ${e.code} code blocks`);
      if (got.figures !== (e.mermaid || 0)) problems.push(`${where}: ${got.figures} diagram figures, but the source has ${e.mermaid || 0} Mermaid blocks`);
      if (record.codeBlocks) problems.push(...codeBlockProblems(main, record.codeBlocks, where));
      const prose = region(toks, (t) => t.name === "div" && /\bprose\b/.test(t.attrs.class || ""));
      for (const t of prose) if (t.type === "tag" && !CONTENT_TAGS.has(t.name)) problems.push(`${where}: unexpected <${t.name}> in the content (source HTML must stay escaped)`);
    }

    // 6. Wording.
    const text = visibleText(html);
    wording(where, text, record?.sourceText ?? null, problems, notes);
  }

  // Mirrors and text outputs: wording, and absolute links to this site must resolve.
  for (const f of files.filter((x) => x.endsWith(".md") || x.endsWith(".txt") || x.endsWith(".xml"))) {
    const text = fs.readFileSync(path.join(outDir, f), "utf8");
    const record = [...records.values()].find((r) => r.mirror && r.mirror.url === "/" + f);
    if (!f.endsWith(".xml")) wording(f, text, record ? record.sourceText : null, problems, notes);
    for (const m of text.matchAll(/https:\/\/agentliaisonprotocol\.org(\/[^\s)<>"\]]*)?/g)) {
      const { path: p, fragment } = splitUrl((m[1] || "/").replace(/[.,;:]+$/, ""));
      const tf = target(p);
      if (!tf) { problems.push(`${f}: links to ${m[0]}, which isn't built`); continue; }
      if (fragment && tf.endsWith(".html") && !ids.get(tf).has(decodeURIComponent(fragment.slice(1)))) problems.push(`${f}: links to ${m[0]}, but ${tf} has no #${fragment.slice(1)}`);
    }
  }

  // The stylesheet loads nothing from elsewhere.
  for (const f of files.filter((x) => x.endsWith(".css"))) {
    const css = fs.readFileSync(path.join(outDir, f), "utf8");
    for (const m of css.matchAll(/url\(\s*['"]?([^'")]+)/g)) if (isRemote(m[1])) problems.push(`${f}: url(${m[1]}) loads from another origin`);
    if (/@import/.test(css)) problems.push(`${f}: @import is not allowed`);
  }
  for (const f of files.filter((x) => x.endsWith(".js"))) {
    const js = fs.readFileSync(path.join(outDir, f), "utf8");
    for (const word of ["localStorage", "sessionStorage", "indexedDB", "document.cookie", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "importScripts", "eval(", "new Function"]) {
      if (js.includes(word)) problems.push(`${f}: uses ${word}`);
    }
    // One fetch only: "Copy page as Markdown" reading the page's own mirror (the CSP limits it to this site).
    const fetches = (js.match(/\bfetch\s*\(/g) || []).length;
    if (fetches > 1) problems.push(`${f}: calls fetch ${fetches} times; only "Copy page as Markdown" may fetch, once`);
  }

  // 5. Examples: every example a page uses exists in the specification and is a valid value.
  for (const [name, ex] of env.examples) {
    const p = exampleProblem(ex);
    if (p) problems.push(`spec/alp-v0.1.md:${ex.line}: example ${name} ${p}`);
  }
  for (const { page, name } of env.usedExamples) {
    if (!env.examples.has(name)) problems.push(`${page}: uses example ${name}, which the specification doesn't have`);
  }

  return { problems, notes };
}

/**
 * Check 4, code blocks: every fenced block of the source (found by lib/fences.mjs, not by the renderer) has a
 * <pre> in the page's <main> whose text is exactly the block's text, in the same order. A Mermaid block is
 * replaced by its figure, so it is the one exception. `main`: the tokens of the page's <main>.
 */
export function codeBlockProblems(main, { file, blocks }, where) {
  const pres = [];
  for (let i = 0; i < main.length; i++) {
    const t = main[i];
    if (t.type !== "tag" || t.close || t.name !== "pre") continue;
    let depth = 0, text = "";
    for (let j = i; j < main.length; j++) {
      const u = main[j];
      if (u.type === "tag" && u.name === "pre" && !u.selfClose) { depth += u.close ? -1 : 1; if (depth === 0) break; }
      else if (u.type === "text") text += decode(u.raw);
    }
    pres.push(text);
  }
  const out = [];
  let next = 0;
  for (const b of blocks) {
    if (/^mermaid\b/.test(b.info)) continue;
    const at = pres.indexOf(b.text, next);
    if (at === -1) {
      const near = pres[next] === undefined ? "no <pre> is left" : `the next <pre> starts ${JSON.stringify(pres[next].slice(0, 60))}`;
      out.push(`${where}: the fenced block at ${file}:${b.line}${b.info ? ` (${b.info.split(/\s/)[0]})` : ""} isn't on the page with its text unchanged; ${near}`);
      continue;
    }
    next = at + 1;
  }
  return out;
}

function isRemote(v) {
  return /^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(String(v).trim()) && !/^data:/i.test(String(v).trim());
}

/** Tokens inside the first element matching `pred` (exclusive of its own tags). */
function region(toks, pred) {
  const start = toks.findIndex((t) => t.type === "tag" && !t.close && pred(t));
  if (start === -1) return [];
  const name = toks[start].name;
  let depth = 0;
  for (let i = start; i < toks.length; i++) {
    const t = toks[i];
    if (t.type !== "tag" || t.name !== name || t.selfClose) continue;
    depth += t.close ? -1 : 1;
    if (depth === 0) return toks.slice(start + 1, i);
  }
  return toks.slice(start + 1);
}

function wording(where, text, sourceText, problems, notes) {
  const banned = [...new Set([...text.matchAll(BANNED_RE)].map((m) => m[0].toLowerCase()))];
  if (banned.length) problems.push(`${where}: contains banned word(s): ${banned.join(", ")}`);
  const src = sourceText === null ? "" : sourceText;
  const papHere = contexts(text, PAP_RE);
  const papSrc = (src.match(PAP_RE) || []).length;
  for (const c of papHere) notes.pap.push({ where, context: c });
  if (papHere.length > papSrc) problems.push(`${where}: "PAP" appears ${papHere.length} time(s) but only ${papSrc} in its source document; write "Poppy" (rule 1.1.3)`);
  const osHere = contexts(text, OPEN_SOURCE_RE);
  const osSrc = (src.match(OPEN_SOURCE_RE) || []).length;
  for (const c of osHere) notes.openSource.push({ where, context: c });
  if (osHere.length > osSrc) problems.push(`${where}: "open source" appears ${osHere.length} time(s) but only ${osSrc} in its source document`);
}
