// SPDX-License-Identifier: FSL-1.1-ALv2
// RFC 6901 JSON pointers, plus the pattern form grants and classification maps use:
// a pattern token `*` matches any one token, and a pattern also matches every pointer below it
// (`/context` covers `/context/summary`).

import { AlpError } from "./errors.ts";
import type { Json, JsonObject } from "./types.ts";

export function parsePointer(pointer: string): string[] {
  if (pointer === "") return [];
  if (typeof pointer !== "string" || !pointer.startsWith("/")) {
    throw new AlpError("invalid_input", `not a JSON pointer: ${JSON.stringify(pointer)}`);
  }
  return pointer
    .slice(1)
    .split("/")
    .map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
}

export function formatPointer(tokens: readonly string[]): string {
  return tokens.map((t) => `/${t.replace(/~/g, "~0").replace(/\//g, "~1")}`).join("");
}

export function isPointer(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value === "") return true;
  return value.startsWith("/") && !/~[^01]|~$/.test(value);
}

function isObject(v: Json | undefined): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Pointers of every leaf: primitives, and empty arrays or objects below the root. */
export function leafPointers(value: Json, prefix: string[] = []): string[] {
  const out: string[] = [];
  const walk = (v: Json, path: string[]): void => {
    if (Array.isArray(v)) {
      if (v.length === 0 && path.length > 0) out.push(formatPointer(path));
      v.forEach((item, i) => walk(item, [...path, String(i)]));
    } else if (isObject(v)) {
      const keys = Object.keys(v);
      if (keys.length === 0 && path.length > 0) out.push(formatPointer(path));
      for (const k of keys) walk(v[k] as Json, [...path, k]);
    } else {
      out.push(formatPointer(path));
    }
  };
  walk(value, prefix);
  return out;
}

export function matchPattern(pattern: string, pointer: string): boolean {
  const p = parsePointer(pattern);
  const t = parsePointer(pointer);
  if (p.length > t.length) return false;
  for (let i = 0; i < p.length; i++) {
    if (p[i] !== "*" && p[i] !== t[i]) return false;
  }
  return true;
}

export function matchesAny(patterns: readonly string[], pointer: string): boolean {
  return patterns.some((p) => matchPattern(p, pointer));
}

/** Most specific match wins: more tokens first, then fewer wildcards. */
export function mostSpecific<T>(entries: readonly (readonly [string, T])[], pointer: string): T | undefined {
  let best: { depth: number; literal: number; value: T } | undefined;
  for (const [pattern, value] of entries) {
    if (!matchPattern(pattern, pointer)) continue;
    const tokens = parsePointer(pattern);
    const depth = tokens.length;
    const literal = tokens.filter((t) => t !== "*").length;
    if (!best || depth > best.depth || (depth === best.depth && literal > best.literal)) best = { depth, literal, value };
  }
  return best?.value;
}

function compareTokensDesc(a: string[], b: string[]): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a[i] as string;
    const y = b[i] as string;
    if (x === y) continue;
    const nx = /^(0|[1-9][0-9]*)$/.test(x) ? Number(x) : NaN;
    const ny = /^(0|[1-9][0-9]*)$/.test(y) ? Number(y) : NaN;
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) return ny - nx;
    return x < y ? 1 : -1;
  }
  return b.length - a.length;
}

/** Returns true when `container` became empty because of the removal. */
function removeAt(container: Json, tokens: string[]): boolean {
  const [head, ...rest] = tokens;
  if (head === undefined) return false;
  if (Array.isArray(container)) {
    if (!/^(0|[1-9][0-9]*)$/.test(head)) return false;
    const i = Number(head);
    if (i >= container.length) return false;
    if (rest.length === 0) container.splice(i, 1);
    else if (removeAt(container[i] as Json, rest)) container.splice(i, 1);
    return container.length === 0;
  }
  if (isObject(container)) {
    if (!Object.hasOwn(container, head)) return false;
    if (rest.length === 0) delete container[head];
    else if (removeAt(container[head] as Json, rest)) delete container[head];
    return Object.keys(container).length === 0;
  }
  return false;
}

/** A copy of `body` without the given leaves; containers emptied by the removal are pruned. */
export function removePointers(body: JsonObject, pointers: readonly string[]): JsonObject {
  const copy = structuredClone(body);
  const lists = pointers.map(parsePointer).sort(compareTokensDesc);
  for (const tokens of lists) {
    if (tokens.length > 0) removeAt(copy, tokens);
  }
  return copy;
}

export function getAt(value: Json, pointer: string): Json | undefined {
  let cur: Json | undefined = value;
  for (const t of parsePointer(pointer)) {
    if (Array.isArray(cur)) cur = /^(0|[1-9][0-9]*)$/.test(t) ? cur[Number(t)] : undefined;
    else if (isObject(cur)) cur = Object.hasOwn(cur, t) ? cur[t] : undefined;
    else return undefined;
  }
  return cur;
}

/** Prefix body-relative pointers so they name a place in the envelope. */
export function envelopePointer(bodyPointer: string): string {
  return `/body${bodyPointer}`;
}
