// Small HTML helpers. The site's HTML comes from micromark and from this tool's own templates, so a
// tag/text tokenizer is enough: it is not a general HTML parser, and it is not used on HTML from elsewhere
// (the two pages copied through unchanged are only read by the checks).

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escape text for an element's content or a double-quoted attribute value. */
export function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ESC[c]);
}

const NAMED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

/** Decode the character references micromark and these templates produce (named basics and numeric). */
export function decode(s) {
  return String(s).replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (m, ref) => {
    if (ref[0] === "#") {
      const n = ref[1] === "x" || ref[1] === "X" ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
      return Number.isFinite(n) ? String.fromCodePoint(n) : m;
    }
    return ref in NAMED ? NAMED[ref] : m;
  });
}

const RAW_TEXT = new Set(["script", "style", "template", "textarea", "title"]);

/**
 * Split HTML into tokens: { type: "tag", name, close, selfClose, attrs, raw } and { type: "text", raw }.
 * Comments and doctypes are { type: "comment" | "doctype", raw }. Content of script, style, template,
 * textarea and title is one text token.
 */
export function tokenize(html) {
  const out = [];
  let i = 0;
  const n = html.length;
  while (i < n) {
    const lt = html.indexOf("<", i);
    if (lt === -1) { out.push({ type: "text", raw: html.slice(i) }); break; }
    if (lt > i) out.push({ type: "text", raw: html.slice(i, lt) });
    if (html.startsWith("<!--", lt)) {
      const end = html.indexOf("-->", lt + 4);
      const stop = end === -1 ? n : end + 3;
      out.push({ type: "comment", raw: html.slice(lt, stop) });
      i = stop;
      continue;
    }
    if (html[lt + 1] === "!" || html[lt + 1] === "?") {
      const end = html.indexOf(">", lt);
      const stop = end === -1 ? n : end + 1;
      out.push({ type: "doctype", raw: html.slice(lt, stop) });
      i = stop;
      continue;
    }
    const m = /^<(\/?)([a-zA-Z][a-zA-Z0-9-]*)((?:\s+[^\s"'>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*(\/?)>/.exec(html.slice(lt, lt + 4000));
    if (!m) { out.push({ type: "text", raw: "<" }); i = lt + 1; continue; }
    const tok = { type: "tag", name: m[2].toLowerCase(), close: m[1] === "/", selfClose: m[4] === "/", attrs: parseAttrs(m[3]), raw: m[0] };
    out.push(tok);
    i = lt + m[0].length;
    if (!tok.close && RAW_TEXT.has(tok.name)) {
      const end = html.toLowerCase().indexOf(`</${tok.name}`, i);
      const stop = end === -1 ? n : end;
      if (stop > i) out.push({ type: "text", raw: html.slice(i, stop) });
      i = stop;
    }
  }
  return out;
}

/** Parse an attribute string into an ordered object (names lower-cased; values decoded). */
export function parseAttrs(s) {
  const attrs = {};
  const re = /([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m;
  while ((m = re.exec(s))) {
    const v = m[2] ?? m[3] ?? m[4];
    attrs[m[1].toLowerCase()] = v === undefined ? "" : decode(v);
  }
  return attrs;
}

/** Text content of an HTML fragment (tags removed, references decoded). */
export function textContent(html) {
  return decode(String(html).replace(/<[^>]*>/g, ""));
}

/** Serialize attributes in the order given; `true` writes a bare attribute, null/false/undefined skip it. */
export function attrs(obj) {
  let s = "";
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined || v === false) continue;
    s += v === true ? ` ${k}` : ` ${k}="${esc(v)}"`;
  }
  return s;
}
