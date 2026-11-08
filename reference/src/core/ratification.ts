// SPDX-License-Identifier: FSL-1.1-ALv2
// Ratification (spec 9.4): after terms are agreed, each principal ratifies them on their own broker, by a
// fresh step-up (or a standing grant whose limits cover the terms). The broker signs a ratification record
// (typ alp-ratification+jws) bound to the terms_hash, sends it to the counterparty inside an ack (status ratified),
// and the commit references both records by hash. Any change to the terms voids them.

import { randomBytes } from "node:crypto";
import { hashJson } from "./hash.ts";
import type { EffectiveTerms } from "./relationships.ts";
import { localTime } from "./relationships.ts";
import type { JsonObject, OrgPolicy, ScopeId, Sha256 } from "./types.ts";

/** SHA-256 of the JCS form of the terms (body.terms of accept and commit). */
export function termsHash(terms: JsonObject): Sha256 {
  return hashJson(terms);
}

export function newNonce(): string {
  return randomBytes(18).toString("base64url");
}

/** At most this many open ratification requests per counterparty. */
export const MAX_OPEN_RATIFICATIONS_PER_COUNTERPARTY = 3;

export function humanRatificationRequired(terms: EffectiveTerms, policy: OrgPolicy | null, scope: ScopeId): boolean {
  return terms.commit === "ask_me" || (policy?.ratification?.required_scopes.includes(scope) ?? false);
}

/** Scope-specific check that agreed terms fall inside a standing grant's limits. Unknown scopes never qualify. */
export function withinLimits(scope: ScopeId, limits: JsonObject | undefined, terms: JsonObject): boolean {
  if (!limits) return false;
  if (scope === "alp.meeting/1") {
    const tz = String(limits["timezone"] ?? "UTC");
    const duration = Number(terms["duration_minutes"]);
    if (!(duration <= Number(limits["max_duration_minutes"]))) return false;
    const start = new Date(String(terms["start"]));
    const end = new Date(String(terms["end"]));
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) return false;
    const s = localTime(tz, start);
    const e = localTime(tz, end);
    const weekdays = limits["weekdays"];
    if (Array.isArray(weekdays) && !weekdays.includes(s.weekday)) return false;
    if (typeof limits["earliest_minute"] === "number" && s.minute < limits["earliest_minute"]) return false;
    if (typeof limits["latest_minute"] === "number" && (e.minute === 0 ? 1440 : e.minute) > limits["latest_minute"]) return false;
    const kinds = limits["location_kinds"];
    const loc = terms["location"] as JsonObject | undefined;
    if (Array.isArray(kinds) && !kinds.includes(String(loc?.["kind"]))) return false;
    return true;
  }
  return false;
}
