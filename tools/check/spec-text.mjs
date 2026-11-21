// Reads spec/alp-v0.1.md by numbered section. Used by the quote test and by requirements.mjs; the checker itself
// never reads the specification at run time. Licensed under Apache-2.0.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const SPEC_PATH = path.join(REPO, "spec", "alp-v0.1.md");

export const readSpec = () => fs.readFileSync(SPEC_PATH, "utf8");

/** Collapse every run of whitespace to one space and trim. */
export const normalise = (s) => s.replace(/\s+/g, " ").trim();

const HEADING = /^#{1,6}\s/;
const NUMBERED = /^#{2,6}\s+(\d+(?:\.\d+)*)\.?\s+(.*)$/;

/**
 * Map of section number ("4.2.1", "16") to { title, text }, where text is everything between that heading and the
 * next heading of any level. Throws on a section number that appears twice.
 */
export function sections(spec) {
  const out = new Map();
  let current = null;
  for (const line of spec.split("\n")) {
    if (HEADING.test(line)) {
      const m = NUMBERED.exec(line);
      current = null;
      if (m) {
        if (out.has(m[1])) throw new Error(`section ${m[1]} appears twice`);
        current = { title: m[2].trim(), lines: [] };
        out.set(m[1], current);
      }
      continue;
    }
    if (current) current.lines.push(line);
  }
  return new Map([...out].map(([k, v]) => [k, { title: v.title, text: v.lines.join("\n") }]));
}

const WORD = /[A-Za-z0-9_]/;

/**
 * Whether `quote` occurs word for word in `text` after whitespace is normalised. A quote may be at most two parts
 * joined with " … "; each part must occur, in order, and start and end at word boundaries (a part may not begin or
 * end in the middle of a word).
 */
export function quoteOccurs(quote, text) {
  const hay = normalise(text);
  const pieces = quote.split(" … ").map(normalise);
  if (pieces.length > 2) return false;
  let from = 0;
  for (const piece of pieces) {
    if (!piece) return false;
    let at = hay.indexOf(piece, from);
    const bounded = (i) =>
      (i === 0 || !WORD.test(hay[i - 1]) || !WORD.test(piece[0])) &&
      (i + piece.length === hay.length || !WORD.test(hay[i + piece.length]) || !WORD.test(piece[piece.length - 1]));
    while (at >= 0 && !bounded(at)) at = hay.indexOf(piece, at + 1);
    if (at < 0) return false;
    from = at + piece.length;
  }
  return true;
}
