// The small front-matter block of a hand-written page in site/pages/:
//
//   ---
//   title: What the demo prints
//   examples: [a1_envelope, a2_receipt]
//   ---
//
// One "key: value" per line. A value is a string (optionally in double quotes), or a list in square
// brackets with comma-separated items. Keys are lower-case letters, digits and underscores. Anything else
// is an error naming the line, so a typo can't pass silently.

export function parseFrontMatter(text, file = "page") {
  const src = String(text).replace(/^﻿/, "");
  if (!src.startsWith("---\n")) return { data: {}, body: src, bodyLine: 1 };
  const end = src.indexOf("\n---\n", 3);
  const endAtEof = src.endsWith("\n---") ? src.length - 4 : -1;
  const stop = end !== -1 ? end : endAtEof;
  if (stop === -1) throw new Error(`${file}:1: front matter opened with --- but never closed`);
  const lines = src.slice(4, stop).split("\n");
  const data = {};
  lines.forEach((line, i) => {
    if (line.trim() === "") return;
    const m = /^([a-z][a-z0-9_]*):\s*(.*)$/.exec(line);
    if (!m) throw new Error(`${file}:${i + 2}: front matter line is not "key: value": ${line}`);
    const [, key, raw] = m;
    if (key in data) throw new Error(`${file}:${i + 2}: front matter key "${key}" appears twice`);
    data[key] = parseValue(raw.trim(), `${file}:${i + 2}`);
  });
  const body = src.slice(stop + 5);
  return { data, body, bodyLine: lines.length + 3 };
}

function parseValue(raw, where) {
  if (raw.startsWith("[")) {
    if (!raw.endsWith("]")) throw new Error(`${where}: list must end with ]`);
    const inner = raw.slice(1, -1).trim();
    return inner === "" ? [] : inner.split(",").map((s) => parseValue(s.trim(), where));
  }
  if (raw.startsWith('"')) {
    if (!raw.endsWith('"') || raw.length < 2) throw new Error(`${where}: unterminated quoted value`);
    return raw.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }
  return raw;
}
