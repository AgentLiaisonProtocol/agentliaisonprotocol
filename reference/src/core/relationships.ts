// SPDX-License-Identifier: FSL-1.1-ALv2
// Relationships and grants. Effective terms for one message direction of one pair in one scope:
//  - an active `consent` grant that covers the scope is the person's own approval;
//  - otherwise an org default relationship (forward/reverse) applies, narrowed by a `narrowing` grant if one exists;
//  - a revoked grant blocks the pair outright (defaults included); a counterparty's revocation stops our outbound sends.
// Org deny rules apply on top (policy/evaluate.ts). Individual grants narrow defaults; only the org widens them.

import { AlpError } from "./errors.ts";
import { JWS_TYP, signDetached, verifyDetached } from "./jws.ts";
import type { VerifyResult } from "./jws.ts";
import type { KeyRing } from "./keys.ts";
import { matchPattern, parsePointer } from "./pointers.ts";
import { defaultRef, findDefault, hasAnyDefault } from "./policy/org-policy.ts";
import type { ClaimsOf } from "./policy/org-policy.ts";
import { suggestedFields } from "./scopes/index.ts";
import type { CompiledScope } from "./scopes/index.ts";
import { MESSAGE_TYPES, isMessageType } from "./types.ts";
import type {
  Address,
  CommitMode,
  CounterpartyRevocation,
  Jwks,
  JsonObject,
  MessageType,
  OrgPolicy,
  QuietHours,
  RateLimit,
  RedactionMode,
  RelationshipGrant,
  ScopeId,
  ScopeTerms,
} from "./types.ts";

export type Direction = "outbound" | "inbound";

export interface EffectiveTerms {
  source: "grant" | "default" | "narrowed" | "self";
  /** The grant id, or `default:<id>`, or both joined with `+`, or `self` between one person's own agents. */
  ref: string;
  may: MessageType[];
  /** Every set must allow a pointer for it to cross (one set per layer). */
  fieldSets: string[][];
  commit: CommitMode;
  limits?: JsonObject;
  redaction: RedactionMode;
  rate_limit?: RateLimit;
  quiet_hours?: QuietHours;
  hold_for_review?: boolean;
  /** Between one person's own agents (spec 6.14): every field of the scope is covered; no field sets apply. */
  all_fields?: true;
}

/** Negotiation needs two people: one person's own agents don't propose, accept or commit to each other (spec 6.14). */
export const SELF_EXCLUDED_TYPES: readonly MessageType[] = ["propose", "counter", "accept", "commit"];

/** The terms between one person's own agents (spec 6.14): no connection or grant, every field, no negotiation. */
export function selfTerms(): EffectiveTerms {
  return { source: "self", ref: "self", may: MESSAGE_TYPES.filter((t) => !SELF_EXCLUDED_TYPES.includes(t)), fieldSets: [], commit: "ask_me", redaction: "reject", all_fields: true };
}

export type TermsResult = { ok: true; terms: EffectiveTerms } | { ok: false; code: "no_relationship"; revoked: boolean };

function stricterRate(a?: RateLimit, b?: RateLimit): RateLimit | undefined {
  if (!a) return b;
  if (!b) return a;
  return a.count / a.per_seconds <= b.count / b.per_seconds ? a : b;
}

function live(g: RelationshipGrant, now: Date): boolean {
  return g.status === "active" && (!g.expires_at || Date.parse(g.expires_at) > now.getTime());
}

export function revocationCovers(r: CounterpartyRevocation | null, scope: ScopeId, now: Date): boolean {
  if (!r || Date.parse(r.effective_at) > now.getTime()) return false;
  return r.scopes[0] === "*" || (r.scopes as string[]).includes(scope);
}

/**
 * Effective terms (spec 6.6.1) for a holder H, a counterparty C and a scope, in the direction of one message:
 * - G, the explicit grant: H's grant about C, active, not expired, listing the scope;
 * - D, the default: the organization default relationship that applies to the pair in this scope.
 * G and D: `may` is the intersection, a leaf must be covered by G's list and D's fields, redaction and hold come from
 * G (hold also from policy), the `grant` reference is G's id. G only: G. D only: D, `reject`, hold from policy,
 * `default:<id>`. Neither: no relationship. A revoked grant blocks the pair outright (defaults included), and a
 * counterparty's revocation stops our outbound sends.
 */
export function effectiveTerms(args: {
  owner: Address;
  counterparty: Address;
  scope: ScopeId;
  direction: Direction;
  grant: RelationshipGrant | null;
  revocation?: CounterpartyRevocation | null;
  policy: OrgPolicy | null;
  claimsOf?: ClaimsOf;
  now: Date;
}): TermsResult {
  const { owner, counterparty, scope, direction, grant, policy, now } = args;
  if (owner === counterparty) return { ok: true, terms: selfTerms() };
  if (direction === "outbound" && revocationCovers(args.revocation ?? null, scope, now)) return { ok: false, code: "no_relationship", revoked: true };
  const sender = direction === "outbound" ? owner : counterparty;
  const recipient = direction === "outbound" ? counterparty : owner;
  const def = policy ? findDefault(policy, sender, recipient, scope, args.claimsOf) : null;
  if (grant && (grant.principal !== owner || grant.counterparty !== counterparty)) throw new AlpError("internal", "grant does not belong to this pair");
  if (grant?.status === "revoked") return { ok: false, code: "no_relationship", revoked: true };
  const t = grant && live(grant, now) ? grant.scopes[scope] : undefined;
  // A narrowing grant that leaves out a scope the default covers narrows that scope away (the stricter reading of
  // spec 6.6.1; see ARCHITECTURE.md "Decisions").
  if (grant && live(grant, now) && grant.basis === "narrowing" && !t && def) return { ok: false, code: "no_relationship", revoked: false };
  const policyHold = direction === "outbound" && (policy?.hold_for_review?.scopes ?? []).includes(scope);
  if (grant && t && def) {
    const listed = direction === "outbound" ? t.disclose : t.receive;
    const rate = stricterRate(def.rel.rate_limit, grant.rate_limit);
    const commit: CommitMode = (def.terms.commit ?? "ask_me") === "ask_me" || t.commit === "ask_me" ? "ask_me" : "within_limits";
    return {
      ok: true,
      terms: {
        source: "narrowed",
        ref: grant.id,
        may: def.direction.may.filter((m) => t.may.includes(m)),
        fieldSets: [[...def.direction.fields], [...listed]],
        commit,
        ...(commit === "within_limits" && t.limits ? { limits: t.limits } : {}),
        redaction: t.redaction,
        ...(rate ? { rate_limit: rate } : {}),
        ...(grant.quiet_hours ? { quiet_hours: grant.quiet_hours } : {}),
        ...(direction === "outbound" && (t.hold_for_review || policyHold) ? { hold_for_review: true } : {}),
      },
    };
  }
  if (grant && t) {
    const listed = direction === "outbound" ? t.disclose : t.receive;
    return {
      ok: true,
      terms: {
        source: "grant",
        ref: grant.id,
        may: [...t.may],
        fieldSets: [[...listed]],
        commit: t.commit,
        ...(t.limits ? { limits: t.limits } : {}),
        redaction: t.redaction,
        ...(grant.rate_limit ? { rate_limit: grant.rate_limit } : {}),
        ...(grant.quiet_hours ? { quiet_hours: grant.quiet_hours } : {}),
        ...(direction === "outbound" && (t.hold_for_review || policyHold) ? { hold_for_review: true } : {}),
      },
    };
  }
  if (def) {
    return {
      ok: true,
      terms: {
        source: "default",
        ref: defaultRef(def.rel),
        may: [...def.direction.may],
        fieldSets: [[...def.direction.fields]],
        commit: def.terms.commit ?? "ask_me",
        ...(def.terms.limits ? { limits: def.terms.limits } : {}),
        redaction: "reject",
        ...(def.rel.rate_limit ? { rate_limit: def.rel.rate_limit } : {}),
        ...(policyHold ? { hold_for_review: true } : {}),
      },
    };
  }
  return { ok: false, code: "no_relationship", revoked: false };
}

/** Is there any relationship at all between the pair? Without one, a sender is a stranger. */
export function hasAnyRelationship(args: { owner: Address; counterparty: Address; grant: RelationshipGrant | null; policy: OrgPolicy | null; claimsOf?: ClaimsOf; now: Date }): boolean {
  const { grant, now } = args;
  if (args.owner === args.counterparty) return true; // one person's own agents
  if (grant?.status === "revoked") return true; // known, and blocked: not a stranger to file requests for
  if (grant && live(grant, now) && Object.keys(grant.scopes).length > 0) return true;
  return hasAnyDefault(args.policy, args.owner, args.counterparty, args.claimsOf);
}

/**
 * Free text (`x-alp-text: untrusted`, and `/note`) is covered only by a pattern with exactly as many tokens that
 * matches it (spec 6.5): `/body/questions/*` covers `/body/questions/0`, `/body` and `/body/questions` don't.
 * `_freeTextPattern` is kept for callers.
 */
export function namesExplicitly(patterns: readonly string[], _freeTextPattern: string, pointer: string): boolean {
  const depth = parsePointer(pointer).length;
  return patterns.some((p) => parsePointer(p).length === depth && matchPattern(p, pointer));
}

const POINTER_RE = /^(?:\/body(?:\/(?:[^/~]|~[01])*)*|\/note)$/;

/** Check scope terms against the scope's definition. Throws `invalid_input`. */
export function checkScopeTerms(terms: ScopeTerms, scope: CompiledScope): void {
  const fail = (m: string): never => {
    throw new AlpError("invalid_input", `${scope.id}: ${m}`);
  };
  if (!Array.isArray(terms.may) || terms.may.some((m) => !isMessageType(m) || !scope.types.has(m))) fail("`may` lists a type the scope doesn't define");
  for (const list of [terms.disclose, terms.receive]) {
    if (!Array.isArray(list) || list.some((p) => typeof p !== "string" || !POINTER_RE.test(p))) fail("pointers must be envelope-relative (/body/... or /note)");
  }
  if (terms.commit !== "ask_me" && terms.commit !== "within_limits") fail("commit must be ask_me or within_limits");
  if (terms.commit === "within_limits") {
    if (!terms.limits) fail("within_limits needs limits");
    if (scope.limits && !scope.limits(terms.limits)) fail("limits do not match the scope's limits schema");
  }
  if (terms.redaction !== "reject" && terms.redaction !== "redact") fail("redaction must be reject or redact");
}

/**
 * Terms for a new connection when nobody chose any: every type the scope defines, and the scope's suggested fields
 * only. `commit` is among the types, with `ask_me`: a commit still needs both people's ratification records (spec 9.4
 * step 6), which only they make, each on their own broker's page. Without it a thread set up through a connection
 * request could reach `agreed` and never be committed.
 */
export function defaultScopeTerms(scope: CompiledScope): ScopeTerms {
  const fields = suggestedFields(scope);
  return { may: [...scope.types], disclose: fields, receive: fields, commit: "ask_me", redaction: "reject" };
}

export function unsealedGrant(g: RelationshipGrant): Omit<RelationshipGrant, "broker_sig"> {
  const { broker_sig: _sig, ...rest } = g;
  return rest;
}

/** The broker signs a grant when its principal seals it, so it can be shown and audited later. */
export async function signGrant(g: RelationshipGrant, ring: KeyRing): Promise<RelationshipGrant> {
  const unsigned = unsealedGrant(g);
  return { ...unsigned, broker_sig: await signDetached(unsigned, JWS_TYP.grant, ring) };
}

export async function verifyGrant(g: RelationshipGrant, jwks: Jwks): Promise<VerifyResult> {
  if (!g.broker_sig) return { ok: false, failure: "malformed" };
  return verifyDetached(unsealedGrant(g), g.broker_sig, JWS_TYP.grant, jwks);
}

function minutesOf(hhmm: string): number {
  const m = /^([01][0-9]|2[0-3]):([0-5][0-9])$/.exec(hhmm);
  if (!m) throw new AlpError("invalid_input", `bad time ${hhmm}`);
  return Number(m[1]) * 60 + Number(m[2]);
}

/** Local wall-clock minute and ISO weekday (1 = Monday) of an instant in a time zone. */
export function localTime(tz: string, at: Date): { minute: number; weekday: number } {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone: tz, hour: "2-digit", minute: "2-digit", hourCycle: "h23", weekday: "short" }).formatToParts(at);
  const h = Number(parts.find((p) => p.type === "hour")?.value);
  const m = Number(parts.find((p) => p.type === "minute")?.value);
  const wd = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].indexOf(parts.find((p) => p.type === "weekday")?.value ?? "") + 1;
  return { minute: h * 60 + m, weekday: wd };
}

/** True inside the quiet window (which may cross midnight) in its own time zone. */
export function isQuietTime(q: QuietHours, now: Date): boolean {
  const cur = localTime(q.tz, now).minute;
  const start = minutesOf(q.start);
  const end = minutesOf(q.end);
  if (start === end) return false;
  return start < end ? cur >= start && cur < end : cur >= start || cur < end;
}

/** When the quiet hours that are on at `now` end (to the minute): held messages are delivered then (spec 6.7). */
export function quietHoursEnd(q: QuietHours, now: Date): Date {
  let t = Math.floor(now.getTime() / 60000) * 60000;
  for (let i = 0; i <= 24 * 60; i++, t += 60000) if (!isQuietTime(q, new Date(t))) return new Date(t);
  return new Date(now.getTime() + 24 * 3600 * 1000);
}
