// SPDX-License-Identifier: FSL-1.1-ALv2
// The core scopes' semantic rules (spec 7.8), checked beyond the JSON Schemas at the recipient's step 9 and before
// signing at the sender. They compare a message with the one it answers, or with the request it keeps to.

import { canonicalize } from "../jcs.ts";
import type { Json, JsonObject, MessageType, ScopeId } from "../types.ts";

const same = (a: Json | undefined, b: Json | undefined): boolean => a !== undefined && b !== undefined && canonicalize(a) === canonicalize(b);
const obj = (v: Json | undefined): JsonObject | undefined => (v && typeof v === "object" && !Array.isArray(v) ? v : undefined);
const time = (v: Json | undefined): number => (typeof v === "string" ? Date.parse(v) : Number.NaN);

/**
 * alp.availability/1 (spec 7.8): the envelope id of the request whose window an inform keeps to, in one broker's copy
 * of the thread. It is the request the inform answers, when it answers a request its recipient sent; otherwise the
 * latest request its recipient sent in the thread. Null: there is none (the inform answers a request its own sender
 * sent, or its recipient has asked nothing), and the inform is refused. In this copy, the inform's recipient sent the
 * messages whose direction is the opposite of the inform's.
 */
export function windowRequestId(
  history: readonly { envelope_id: string; type: MessageType; direction: "in" | "out" }[],
  msg: { direction: "in" | "out"; in_reply_to?: string; reply_to?: { type: MessageType; direction: "in" | "out" } },
): string | null {
  const theirs = msg.direction === "out" ? "in" : "out";
  if (msg.reply_to?.type === "request") return msg.reply_to.direction === theirs ? (msg.in_reply_to ?? null) : null;
  for (let i = history.length - 1; i >= 0; i--) {
    const h = history[i];
    if (h && h.type === "request" && h.direction === theirs) return h.envelope_id;
  }
  return null;
}

/**
 * Null when the body keeps the scope's semantic rules, otherwise why not. `answers` is the message this one replies
 * to (its type and body), when there is one. `window` is, for an alp.availability/1 inform, the body of the request
 * whose window it keeps to (`windowRequestId`), or null when there is none; a caller that leaves the thread out of its
 * checks (the sender-side policy vectors) passes nothing.
 */
export function scopeSemantics(scope: ScopeId, type: MessageType, body: JsonObject, answers?: { type: MessageType; body: JsonObject }, window?: JsonObject | null): string | null {
  if (scope === "alp.meeting/1" && type === "accept") {
    // The accept fixes one slot of the proposal it answers, with the proposal's title, duration, timezone and location.
    if (!answers || (answers.type !== "propose" && answers.type !== "counter")) return "an accept answers a propose or counter";
    const terms = obj(body["terms"]);
    if (!terms) return "an accept carries terms";
    for (const k of ["title", "duration_minutes", "timezone", "location"]) {
      if (answers.body[k] === undefined && terms[k] === undefined) continue;
      if (!same(terms[k], answers.body[k])) return `the accepted ${k} differs from the proposal's`;
    }
    const slots = Array.isArray(answers.body["slots"]) ? answers.body["slots"] : [];
    if (!slots.some((s) => same(obj(s)?.["start"], terms["start"]) && same(obj(s)?.["end"], terms["end"]))) return "the accepted time is not one of the proposed slots";
  }
  if (scope === "alp.availability/1" && type === "inform" && window !== undefined) {
    // An answer carries free intervals inside the window its recipient asked about, whether it answers that request,
    // updates an earlier answer or follows up: never times nobody asked for.
    if (window === null) return "free intervals answer a request from their recipient in this thread, and there is none to answer";
    const w = obj(window["window"]);
    const from = time(w?.["start"]);
    const to = time(w?.["end"]);
    const free = Array.isArray(body["free"]) ? body["free"] : [];
    for (const f of free) {
      const s = time(obj(f)?.["start"]);
      const e = time(obj(f)?.["end"]);
      if (!(s >= from && e <= to && e > s)) return "a free interval lies outside the window its recipient asked about";
    }
  }
  return null;
}
