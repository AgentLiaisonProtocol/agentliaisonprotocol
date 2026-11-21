// The specification's named examples: the text between <!-- example:NAME --> and <!-- /example -->,
// which tools/spec/examples.mjs fills from the vectors. A block example is a fenced code block; an inline
// one is a code span. The site never retypes a protocol object: pages take them from here.

const OPEN = /<!-- example:([a-z0-9_]+) -->/g;
const CLOSE = "<!-- /example -->";

/** Map of name -> { name, text, block, line } for every named example in `md`. Throws on a malformed one. */
export function extractExamples(md, file = "spec/alp-v0.1.md") {
  const out = new Map();
  OPEN.lastIndex = 0;
  let m;
  while ((m = OPEN.exec(md))) {
    const name = m[1];
    const line = md.slice(0, m.index).split("\n").length;
    const start = m.index + m[0].length;
    const end = md.indexOf(CLOSE, start);
    if (end === -1) throw new Error(`${file}:${line}: example "${name}" is never closed with ${CLOSE}`);
    const nextOpen = md.indexOf("<!-- example:", start);
    if (nextOpen !== -1 && nextOpen < end) throw new Error(`${file}:${line}: example "${name}" contains another example`);
    if (out.has(name)) throw new Error(`${file}:${line}: example "${name}" appears twice`);
    const inner = md.slice(start, end);
    const fence = /^\s*(`{3,}|~{3,})([^\n]*)\n([\s\S]*?)\n\1\s*$/.exec(inner);
    const span = /^(`+)([^`][\s\S]*?)\1$/.exec(inner);
    if (fence) out.set(name, { name, text: fence[3], block: true, lang: fence[2].trim(), line });
    else if (span) out.set(name, { name, text: span[2], block: false, lang: "", line });
    else throw new Error(`${file}:${line}: example "${name}" is neither a fenced code block nor a code span`);
    OPEN.lastIndex = end + CLOSE.length;
  }
  return out;
}

const MARKER = /<!-- example:[a-z0-9_]+ -->|<!-- \/example -->/y;

/**
 * The Markdown with the example markers removed (the examples themselves stay). A marker written inside a
 * code span or a fenced code block is text, not a marker, and is kept as it is.
 */
export function stripExampleMarkers(md) {
  const lines = md.split("\n");
  const out = [];
  let fence = null; // the opening fence's character and length while inside a fenced block
  let prose = []; // consecutive lines outside fences, scanned together so a code span may cross a line
  const flush = () => {
    if (prose.length) out.push(stripInProse(prose.join("\n")));
    prose = [];
  };
  for (const line of lines) {
    const f = /^ {0,3}(`{3,}|~{3,})/.exec(line);
    if (fence) {
      out.push(line);
      if (f && f[1][0] === fence[0] && f[1].length >= fence.length && /^ {0,3}(`+|~+)\s*$/.test(line)) fence = null;
    } else if (f && !(f[1][0] === "`" && line.slice(f[0].length).includes("`"))) {
      flush();
      out.push(line);
      fence = f[1];
    } else prose.push(line);
  }
  flush();
  return out.join("\n");
}

/** Removes markers outside code spans in text that holds no fenced block. */
function stripInProse(text) {
  let out = "";
  let i = 0;
  while (i < text.length) {
    if (text[i] === "`") {
      let n = 0;
      while (text[i + n] === "`") n++;
      const close = findClosingRun(text, i + n, n);
      if (close !== -1) {
        out += text.slice(i, close + n);
        i = close + n;
      } else {
        out += text.slice(i, i + n);
        i += n;
      }
      continue;
    }
    if (text[i] === "<") {
      MARKER.lastIndex = i;
      const m = MARKER.exec(text);
      if (m) {
        i += m[0].length;
        continue;
      }
    }
    out += text[i];
    i++;
  }
  return out;
}

/** Index of the next run of exactly `n` backticks at or after `from`, before a blank line; -1 if none. */
function findClosingRun(text, from, n) {
  let j = from;
  while (j < text.length) {
    if (text[j] === "\n" && /^\n[ \t]*(\n|$)/.test(text.slice(j, j + 80))) return -1;
    if (text[j] === "`") {
      let k = 0;
      while (text[j + k] === "`") k++;
      if (k === n) return j;
      j += k;
      continue;
    }
    j++;
  }
  return -1;
}

/**
 * Whether an example's text is a protocol value the site can show: a block or an object/array must parse
 * as JSON; an inline value that is not JSON must be a hash ("sha256:" and 43 base64url characters).
 * Returns null when it is, or a sentence saying what is wrong.
 */
export function exampleProblem(ex) {
  const t = ex.text.trim();
  if (ex.block || t.startsWith("{") || t.startsWith("[")) {
    try { JSON.parse(t); return null; } catch (e) { return `does not parse as JSON (${e.message})`; }
  }
  if (/^sha256:[A-Za-z0-9_-]{43}$/.test(t)) return null;
  try { JSON.parse(t); return null; } catch { return "is neither JSON nor a sha256 hash"; }
}
