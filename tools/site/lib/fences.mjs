// Fenced code blocks, found with a line scanner of this tool's own rather than with the renderer, so the
// build can check that every block in a source reaches the page with its text unchanged (check 4), and can
// make one CommonMark construct unambiguous before rendering (normalizeFences).
//
// The scanner understands what the repository's documents use: fences of three or more backticks or tildes,
// indented by a list item or not, inside block quotes or not, closed by a fence of the same character that
// is at least as long, or by the end of the document. Each content line loses its block-quote markers and
// up to as many leading spaces as the opening fence had, as CommonMark says.

const OPEN = /^(\s*)((?:[-+*]|\d{1,9}[.)])[ \t]+)?(`{3,}|~{3,})(.*)$/;

/** Split a line into its block-quote markers (">" and one optional space each) and the rest. */
function quoteSplit(line) {
  const m = /^((?: {0,3}> ?)*)(.*)$/.exec(line);
  return { depth: (m[1].match(/>/g) || []).length, rest: m[2] };
}

const expandTabs = (s) => s.replace(/^[ \t]+/, (ws) => ws.replace(/\t/g, "    "));

/**
 * Every fenced code block in `md`, in order: { line (1-based, of the opening fence), endLine, info (the
 * info string, trimmed), text (the content as a renderer must show it: each line ending in "\n") }.
 */
export function fencedBlocks(md) {
  const lines = md.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const { depth, rest } = quoteSplit(lines[i]);
    const m = OPEN.exec(expandTabs(rest));
    if (!m) continue;
    const [, ws, marker = "", fence, info] = m;
    if (fence[0] === "`" && info.includes("`")) continue; // not a fence: a code span
    const indent = ws.length + marker.length;
    const body = [];
    let j = i + 1;
    let closed = false;
    for (; j < lines.length; j++) {
      const q = quoteSplit(lines[j]);
      if (q.depth < depth && q.rest.trim() !== "") break; // the block quote ended, and the block with it
      const content = expandTabs(q.depth >= depth ? q.rest : lines[j]);
      const close = /^(\s*)(`{3,}|~{3,})\s*$/.exec(content);
      if (close && close[2][0] === fence[0] && close[2].length >= fence.length && close[1].length <= indent + 3) { closed = true; break; }
      const lead = /^ */.exec(content)[0].length;
      body.push(content.slice(Math.min(lead, indent)));
    }
    out.push({ line: i + 1, endLine: closed ? j + 1 : j, info: info.trim(), text: body.map((l) => l + "\n").join("") });
    i = closed ? j : j - 1;
  }
  return out;
}

/**
 * Put a blank line before every fenced block that is indented (inside a list item, not a block quote) and
 * follows a line of text directly. CommonMark lets such a fence interrupt the paragraph, and the block's
 * text is the same either way; but micromark 4.0.2's HTML compiler drops every line ending inside the block
 * when the list is tight (the paragraph's end sets "slurpAllLineEndings", and entering fenced code doesn't
 * clear it). With the blank line the list is loose, the paragraph is closed, and the block keeps its lines.
 * Returns { md, lines: [line numbers of the fences that got a blank line before them] }.
 */
export function normalizeFences(md) {
  const blocks = fencedBlocks(md);
  const lines = md.split("\n");
  const fenceLines = new Set();
  for (const b of blocks) { fenceLines.add(b.line); fenceLines.add(b.endLine); }
  const before = new Set();
  for (const b of blocks) {
    const open = lines[b.line - 1];
    const prev = lines[b.line - 2];
    if (b.line < 2 || /^\s*>/.test(open) || !/^\s+\S/.test(open)) continue;
    if (prev.trim() === "" || /^\s*>/.test(prev) || fenceLines.has(b.line - 1)) continue;
    before.add(b.line);
  }
  if (!before.size) return { md, lines: [] };
  const out = [];
  lines.forEach((l, i) => { if (before.has(i + 1)) out.push(""); out.push(l); });
  return { md: out.join("\n"), lines: [...before] };
}
