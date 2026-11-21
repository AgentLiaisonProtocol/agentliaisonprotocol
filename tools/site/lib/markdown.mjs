// Markdown to HTML for pages rendered from the repository's documents: micromark with GFM, raw HTML kept
// escaped, then a fixed set of passes over micromark's (predictable) output: heading ids that match
// GitHub's, permalinks, link rewriting, section references, maturity labels, JSON highlighting, the
// Mermaid figure, and scrolling containers for tables and code.

import crypto from "node:crypto";
import { micromark, parse, postprocess, preprocess } from "micromark";
import { gfm, gfmHtml } from "micromark-extension-gfm";
import { decode, esc, textContent } from "./html.mjs";
import { Slugger } from "./slug.mjs";
import { highlightJson } from "./highlight.mjs";
import { linkSectionRefs, markMaturityLines, sectionNumber } from "./sections.mjs";
import { normalizeFences } from "./fences.mjs";

/** micromark's events for `md` (GFM on). */
function events(md) {
  return postprocess(parse({ extensions: [gfm()] }).document().write(preprocess()(md, undefined, true)));
}

/**
 * What the source holds, before rendering: raw HTML (each with its line), counts of headings, tables and
 * code blocks (Mermaid blocks counted separately as well), and the position of every link destination so
 * the Markdown mirror can rewrite them in place.
 */
export function analyzeMarkdown(md) {
  const ev = events(md);
  const html = [];
  const links = [];
  const headings = [];
  const counts = { headings: 0, tables: 0, code: 0, mermaid: 0 };
  for (let i = 0; i < ev.length; i++) {
    const [kind, tok, ctx] = ev[i];
    if (kind !== "enter") continue;
    switch (tok.type) {
      case "htmlFlow":
      case "htmlText":
        html.push({ line: tok.start.line, text: ctx.sliceSerialize(tok).trim() });
        break;
      case "atxHeading":
      case "setextHeading":
        counts.headings++;
        headings.push({ line: tok.start.line });
        break;
      case "atxHeadingSequence":
        if (headings.length) headings.at(-1).depth = ctx.sliceSerialize(tok).length;
        break;
      case "setextHeadingLineSequence":
        if (headings.length) headings.at(-1).depth = ctx.sliceSerialize(tok)[0] === "=" ? 1 : 2;
        break;
      case "table":
        counts.tables++;
        break;
      case "codeFenced":
      case "codeIndented":
        counts.code++;
        break;
      case "codeFencedFenceInfo":
        if (ctx.sliceSerialize(tok).trim() === "mermaid") counts.mermaid++;
        break;
      case "resourceDestinationString":
      case "definitionDestinationString": {
        const s = tok.start.offset, e = tok.end.offset;
        const text = ctx.sliceSerialize(tok);
        if (md.slice(s, e) !== text) throw new Error(`markdown:${tok.start.line}: link offsets don't match the source`);
        links.push({ start: s, end: e, dest: text, line: tok.start.line });
        break;
      }
      default:
        break;
    }
  }
  return { html, links, headings, counts };
}

/**
 * Rewrite every link destination in `md` with `rewrite(dest, line)` (which returns the new destination),
 * leaving everything else byte for byte. Used for the Markdown mirrors.
 */
export function rewriteMarkdownLinks(md, rewrite) {
  const { links } = analyzeMarkdown(md);
  let out = "";
  let last = 0;
  for (const l of links) {
    out += md.slice(last, l.start) + rewrite(l.dest, l.line);
    last = l.end;
  }
  return out + md.slice(last);
}

export function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

/**
 * Render Markdown for a page.
 *
 * opts:
 *   file           the source's name, for messages
 *   resolveHref    (href) -> href to write; called for every link micromark writes
 *   sectionRefs    null, or { mode: "spec" | "other", hrefFor(number) -> href | null }
 *   maturity       true to show each section's own maturity line as a label (the working specification)
 *   figureFor      (mermaidSource) -> { html } | null
 *   problems       array that collects error strings (file:line: message)
 *
 * Returns { h1, body, headings: [{ depth, id, text, number }], figures, maturityLines }.
 */
export function renderMarkdown(md, opts) {
  const { file, resolveHref, sectionRefs = null, maturity = false, figureFor, problems } = opts;
  // A fence that directly follows a line of text inside a tight list item loses its line endings in
  // micromark's HTML (lib/fences.mjs, normalizeFences); a blank line before it makes the block unambiguous.
  let html = micromark(normalizeFences(md).md, { extensions: [gfm()], htmlExtensions: [gfmHtml()] });

  // Code blocks: the Mermaid figure, JSON highlighting, and a focusable scrolling container.
  let figures = 0;
  html = html.replace(/<pre><code(?: class="language-([^"]*)")?>([\s\S]*?)<\/code><\/pre>/g, (_m, lang, code) => {
    const text = decode(code);
    if (lang === "mermaid") {
      const fig = figureFor(text);
      if (!fig) {
        problems.push(`${file}: a Mermaid block (sha256 ${sha256(text).slice(0, 16)}) has no figure in site.config.mjs figures`);
        return `<pre><code class="language-mermaid">${code}</code></pre>`;
      }
      figures++;
      return fig.html;
    }
    const cls = lang ? ` class="language-${esc(lang)}"` : "";
    const inner = lang === "json" ? highlightJson(text) : code;
    return `<pre tabindex="0"><code${cls}>${inner}</code></pre>`;
  });

  // Long paths in code spans may break after a slash rather than in the middle of a name.
  html = html.replace(/(?<!<pre tabindex="0">)<code>([^<\n]{21,})<\/code>/g, (_m, c) => `<code>${c.replace(/\/(?=[^/])/g, "/<wbr>")}</code>`);

  // Tables scroll sideways inside their own container.
  html = html.replace(/<table>/g, '<div class="table-wrap" tabindex="0" role="region" aria-label="Table">\n<table>').replace(/<\/table>/g, "</table>\n</div>");

  // Links.
  html = html.replace(/<a href="([^"]*)"/g, (_m, href) => `<a href="${esc(resolveHref(decode(href)))}"`);
  html = html.replace(/<img src="([^"]*)"/g, (m, src) => {
    problems.push(`${file}: an image (${decode(src)}) can't be shown; the site loads no remote images and copies none from Markdown`);
    return m;
  });

  // Section references in running text.
  if (sectionRefs) {
    const missing = [];
    html = linkSectionRefs(html, { mode: sectionRefs.mode, hrefFor: sectionRefs.hrefFor, missing });
    for (const n of missing) problems.push(`${file}: refers to Section ${n}, which doesn't exist in the specification`);
  }

  // Headings: GitHub ids and permalinks (h2-h4).
  const slugger = new Slugger();
  const headings = [];
  html = html.replace(/<h([1-6])>([\s\S]*?)<\/h\1>/g, (_m, d, inner) => {
    const depth = Number(d);
    const text = textContent(inner).trim();
    const id = slugger.slug(text);
    const number = sectionNumber(text);
    headings.push({ depth, id, text, number });
    const anchor = depth >= 2 && depth <= 4 ? `<a class="anchor" href="#${id}" aria-label="Link to this section: ${esc(text)}">#</a>` : "";
    return `<h${depth} id="${id}">${inner}${anchor}</h${depth}>`;
  });

  // Each section's own maturity line, shown as a label.
  let maturityLines = [];
  if (maturity) ({ html, lines: maturityLines } = markMaturityLines(html));

  // The document's first heading, when it is an h1 at the very start, becomes the page title.
  let h1 = null;
  const lead = /^\s*(<h1 id="[^"]*">[\s\S]*?<\/h1>)\n?/.exec(html);
  if (lead) { h1 = lead[1]; html = html.slice(lead[0].length); }
  return { h1, body: html, headings, figures, maturityLines };
}
