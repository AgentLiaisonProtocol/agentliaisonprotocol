// Headings of a Markdown document with their GitHub ids and section numbers, without any rendering passes.

import { micromark } from "micromark";
import { gfm, gfmHtml } from "micromark-extension-gfm";
import { textContent } from "./html.mjs";
import { Slugger } from "./slug.mjs";
import { stripExampleMarkers } from "./examples.mjs";
import { sectionNumber } from "./sections.mjs";

/** Headings of a Markdown document with their GitHub ids and section numbers (no rendering passes). */
export function headingsOf(md) {
  const html = micromark(stripExampleMarkers(md), { extensions: [gfm()], htmlExtensions: [gfmHtml()] });
  const slugger = new Slugger();
  const out = [];
  for (const m of html.matchAll(/<h([1-6])>([\s\S]*?)<\/h\1>/g)) {
    const text = textContent(m[2]).trim();
    out.push({ depth: Number(m[1]), text, id: slugger.slug(text), number: sectionNumber(text) });
  }
  return out;
}

/** Map of section number -> heading id for a specification text. */
export function sectionIds(md) {
  const ids = new Map();
  for (const h of headingsOf(md)) if (h.number && !ids.has(h.number)) ids.set(h.number, h.id);
  return ids;
}

