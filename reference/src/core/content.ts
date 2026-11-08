// SPDX-License-Identifier: FSL-1.1-ALv2
// How inbound counterparty content is shaped for an agent or a person (spec 12.1.6). Every free-text
// value is sanitized before delivery: invisible and control characters removed, markup tags stripped, URLs defanged.
// Typed values are delivered as validated. The vectors are vectors/delivery/sanitize.json. Sanitizing removes the
// cheapest tricks; it is never presented as protection against prompt injection.

import { getAt, leafPointers, matchPattern } from "./pointers.ts";
import type { Json, JsonObject } from "./types.ts";

// C0 controls except LF, DEL, C1 controls; bidi controls; zero-width characters; BOM; Unicode tag characters.
const INVISIBLE = /[\u0000-\u0009\u000B-\u001F\u007F-\u009F؜‎‏‪-‮⁦-⁩​-‍⁠-⁤﻿]|\uDB40[\uDC00-\uDC7F]/g;
// A tag: `<`, an optional `/`, a letter, then anything up to the next `>`.
const TAG = /<\/?[A-Za-z][^>]*>/g;
const URL_RE = /\b(https?|ftp):\/\/([^\s/?#]*)/gi;

/** Spec 12.1.6 steps 1 to 3. */
export function sanitizeText(text: string): string {
  return text
    .replace(INVISIBLE, "")
    .replace(TAG, "")
    .replace(URL_RE, (_m, scheme: string, host: string) => {
      const s = scheme.toLowerCase();
      const fanged = s === "https" ? "hxxps" : s === "http" ? "hxxp" : "fxp";
      return `${fanged}://${host.replace(/\./g, "[.]")}`;
    });
}

/** A copy of an envelope body with every free-text leaf (envelope-relative patterns, e.g. `/body/questions/*`) sanitized. */
export function sanitizeBody(body: JsonObject, freeTextPatterns: readonly string[]): JsonObject {
  const copy = structuredClone(body);
  if (freeTextPatterns.length === 0 || Object.keys(copy).length === 0) return copy;
  for (const p of leafPointers(copy, ["body"])) {
    if (!freeTextPatterns.some((ft) => matchPattern(ft, p))) continue;
    const v = getAt(copy, p.slice("/body".length));
    if (typeof v !== "string") continue;
    const tokens = p.split("/").slice(2).map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
    let cur: Json = copy;
    for (let i = 0; i < tokens.length - 1; i++) cur = (cur as Record<string, Json>)[tokens[i] as string] as Json;
    (cur as Record<string, Json>)[tokens[tokens.length - 1] as string] = sanitizeText(v);
  }
  return copy;
}
