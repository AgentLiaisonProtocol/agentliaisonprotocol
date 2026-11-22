// Specification sections: numbering, references in running text, and maturity labels.

import { textContent, tokenize } from "./html.mjs";

/**
 * The section number a specification heading carries, or null: "6.6 Sender-side evaluation" -> "6.6",
 * "1. Introduction" -> "1", "Appendix A. Worked examples" -> "A", "A.4 A rogue broker refused" -> "A.4".
 */
export function sectionNumber(headingText) {
  const t = String(headingText).trim();
  let m = /^(\d+(?:\.\d+)*)\.?\s/.exec(t);
  if (m) return m[1];
  m = /^Appendix ([A-Z])\b/.exec(t);
  if (m) return m[1];
  m = /^([A-Z](?:\.\d+)+)\s/.exec(t);
  if (m) return m[1];
  return null;
}

const REF = String.raw`(?:\d+(?:\.\d+)*|[A-Z](?:\.\d+)+)`;
const APPX = String.raw`[A-Z](?:\.\d+)*`;
const SEP = String.raw`(?:\s*[–-]\s*|,\s+|,?\s+(?:and|or|to)\s+)`;

// On the specification's own pages: "Section 6.6", "Sections 4.2–4.8", "Sections 6.6 and 6.7", "Appendix A".
const SPEC_RE = new RegExp(String.raw`\b(?:(Section)\s+(${REF})|(Sections)\s+(${REF}(?:${SEP}${REF})*)|(Appendix)\s+(${APPX}))\b`, "g");
// Elsewhere: "spec Section 5.3", "specification Section 5.3", "the specification's Section 5.4", plurals too,
// and the short form CLAIMS.md and CHANGELOG.md use: "Spec 6.6", "spec 6.14", "Spec 4.2, 4.3 and 12.6".
const OTHER_RE = new RegExp(String.raw`\b((?:[Ss]pec|[Ss]pecification(?:'s|’s)?)\s+)(?:(Section)\s+(${REF})|(Sections)\s+(${REF}(?:${SEP}${REF})*))\b|\b([Ss]pec)\s+(\d+(?:\.\d+)*(?:${SEP}\d+(?:\.\d+)*)*)\b`, "g");

const SKIP = new Set(["a", "code", "pre", "h1", "h2", "h3", "h4", "h5", "h6", "svg", "figure", "script", "style", "template", "title", "summary"]);
const BLOCK = new Set(["p", "li", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "div", "blockquote", "dd", "dt", "figcaption", "table", "ul", "ol", "tr"]);

/**
 * Link section references in the running text of rendered HTML (not inside links, code, headings or
 * figures). `mode` is "spec" on the specification's pages and "other" elsewhere. `hrefFor(number)` returns
 * the link for a section number, or null when the section doesn't exist, which is recorded in `missing`.
 * A reference that cites another document ("RFC 6749, Section 3.3", "[Poppy], Section 4.1",
 * "Section 2 of RFC ...") is left alone.
 */
export function linkSectionRefs(html, { mode, hrefFor, missing = [] }) {
  const toks = tokenize(html);
  const stack = [];
  let recent = "";
  let out = "";
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.type === "tag") {
      if (BLOCK.has(t.name)) recent = "";
      if (!t.close && !t.selfClose && !VOID.has(t.name)) stack.push(t.name);
      else if (t.close) { const k = stack.lastIndexOf(t.name); if (k !== -1) stack.length = k; }
      out += t.raw;
      continue;
    }
    if (t.type !== "text" || stack.some((n) => SKIP.has(n))) {
      if (t.type === "text") recent = (recent + t.raw).slice(-60);
      out += t.raw;
      continue;
    }
    const after = toks.slice(i + 1, i + 4).filter((x) => x.type === "text").map((x) => x.raw).join("");
    out += replaceRefs(t.raw, recent, after, mode, hrefFor, missing);
    recent = (recent + t.raw).slice(-60);
  }
  return out;
}

const VOID = new Set(["br", "hr", "img", "input", "meta", "link", "wbr", "source", "col", "area", "base", "embed", "param", "track", "path", "circle", "rect", "line", "polyline", "polygon", "ellipse", "use", "stop"]);

function replaceRefs(text, before, after, mode, hrefFor, missing) {
  const re = mode === "spec" ? SPEC_RE : OTHER_RE;
  re.lastIndex = 0;
  let out = "";
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    const pre = before + text.slice(0, m.index);
    const post = text.slice(m.index + m[0].length) + after;
    if (/(?:\bRFC\s?\d+|\])\s*,\s*$/.test(pre) || /^\s+of\s+(?:\[|RFC\b)/.test(post)) continue;
    out += text.slice(last, m.index);
    out += mode === "spec" ? specLink(m, hrefFor, missing) : otherLink(m, hrefFor, missing);
    last = m.index + m[0].length;
  }
  return out + text.slice(last);
}

function link(label, num, hrefFor, missing) {
  const href = hrefFor(num);
  if (!href) { missing.push(num); return label; }
  return `<a class="secref" href="${href}">${label}</a>`;
}

function linkList(list, hrefFor, missing) {
  return list.replace(new RegExp(REF, "g"), (n) => link(n, n, hrefFor, missing));
}

function specLink(m, hrefFor, missing) {
  if (m[1]) return link(`${m[1]} ${m[2]}`, m[2], hrefFor, missing);
  if (m[3]) return `${m[3]} ${linkList(m[4], hrefFor, missing)}`;
  return link(`${m[5]} ${m[6]}`, m[6], hrefFor, missing);
}

function otherLink(m, hrefFor, missing) {
  if (m[2]) return link(`${m[1]}${m[2]} ${m[3]}`, m[3], hrefFor, missing);
  if (m[4]) return `${m[1]}${m[4]} ${linkList(m[5], hrefFor, missing)}`;
  // The short form: one section links as a whole ("Spec 6.6"); in a list each number links on its own.
  if (/^\d+(?:\.\d+)*$/.test(m[7])) return link(`${m[6]} ${m[7]}`, m[7], hrefFor, missing);
  return `${m[6]} ${linkList(m[7], hrefFor, missing)}`;
}

// ---------------------------------------------------------------------------------------------------
// Maturity labels

export const LABELS = ["Core", "Experimental", "Future", "Informative"];

// A section's own label: a paragraph that starts with an emphasised "Maturity: …" or "Informative." line.
const LABEL_LINE = /<p><em>((?:Maturity: |Informative\.)(?:(?!<\/?em>)[\s\S])*?)<\/em>/g;

/**
 * Show each section's own maturity line as a label: the emphasised words at the start of the paragraph
 * become a styled span, word for word, and anything after them in the paragraph stays as text. The class
 * comes from the first label word in the line (Core, Experimental, Future or Informative); nothing is
 * derived from anywhere else. Returns { html, lines: [{ section, label, text }] }, where `section` is the
 * number of the heading the line sits under.
 */
export function markMaturityLines(html) {
  const lines = [];
  let section = null;
  const re = new RegExp(`<h[1-6] id="[^"]*">([\\s\\S]*?)<\\/h[1-6]>|${LABEL_LINE.source}`, "g");
  const out = html.replace(re, (m, heading, inner) => {
    if (heading !== undefined) {
      section = sectionNumber(textContent(heading)) ?? section;
      return m;
    }
    const text = textContent(inner).replace(/\s+/g, " ").trim();
    const word = new RegExp(`\\b(${LABELS.join("|")})\\b`).exec(text);
    const label = word ? word[1] : null;
    lines.push({ section, label, text });
    const cls = label ? ` maturity-${label.toLowerCase()}` : "";
    return `<p class="has-maturity"><span class="maturity${cls}">${inner}</span>`;
  });
  return { html: out, lines };
}
