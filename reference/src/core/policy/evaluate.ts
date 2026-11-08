// SPDX-License-Identifier: FSL-1.1-ALv2
// The policy evaluator. The same function runs on both sides of the wire, in the specification's order, and stops
// at the first failure:
//  - outbound, at the sender's home broker, before anything is signed (spec 6.6, steps S4 to S8; S1 to S3 and the
//    rate limit run in the broker);
//  - inbound, at the recipient's home broker, which never relies on the sender's broker having done its part
//    (spec 6.7, steps 7 to 10; kill switches, the rate limit, thread checks and step 11 run in the broker).
// Deny by default: a leaf crosses only if no enforced organization rule stops it and the effective terms cover it.
// Free text (`x-alp-text: untrusted`) and the note are covered only by a pattern that names them exactly (spec 6.5).

import { displayAddress, domainOf } from "../address.ts";
import { joinWithin } from "../ajv.ts";
import { canonicalBytes } from "../jcs.ts";
import { getAt, leafPointers, matchPattern, matchesAny, removePointers } from "../pointers.ts";
import { namesExplicitly } from "../relationships.ts";
import type { EffectiveTerms } from "../relationships.ts";
import { freeTextPatterns, labelsOf, undefinedField, validateBody } from "../scopes/index.ts";
import type { CompiledScope } from "../scopes/index.ts";
import { isCommonType } from "../types.ts";
import type { Address, DlpCategory, ErrorCode, JsonObject, MessageType, OrgPolicy, PrincipalId, Reason } from "../types.ts";
import { runDlp } from "./dlp.ts";
import type { DlpHook } from "./dlp.ts";
import { anyRefMatches, federationAllows, labelMatches, policyRef } from "./org-policy.ts";
import type { ClaimsOf } from "./org-policy.ts";

export const NOTE_POINTER = "/note";
/** `/note` is `internal` (spec 6.5). */
export const NOTE_LABEL = "internal";
/** What DLP span redaction puts in place of the matched text (spec 6.9). */
export const REDACTED_TEXT = "[redacted]";
/**
 * What an envelope's `decision.redacted` can list (common.schema.json, `decision` and `pointer`): at most 64 pointers,
 * each of at most 512 characters. Leaves the sender's rules would remove beyond that couldn't be listed in a valid
 * envelope, so the draft is refused instead, as without redaction; nothing that large is marked, signed or logged.
 */
export const REDACTED_MAX = 64;
export const REDACTED_POINTER_MAX = 512;

export interface EvaluationLimits {
  noteMaxChars: number;
  bodyMaxBytes: number;
}

export interface EvaluationInput {
  direction: "outbound" | "inbound";
  owner: Address;
  owner_id: string;
  counterparty: Address;
  scope: CompiledScope;
  type: MessageType;
  body: JsonObject;
  note?: string;
  /** The effective terms (spec 6.6.1), or null when there is no relationship. */
  terms: EffectiveTerms | null;
  policy: OrgPolicy | null;
  claimsOf?: ClaimsOf;
  dlp: DlpHook;
  limits: EvaluationLimits;
  /** Outbound: labels the delegate adds (additions only). Inbound: the envelope's `labels`. */
  extraLabels?: readonly string[];
}

export interface Evaluation {
  outcome: "allow" | "redact" | "reject";
  /** The primary code when rejecting. */
  code?: ErrorCode;
  body: JsonObject;
  note?: string;
  /** Envelope-relative pointers that cross. */
  disclosed: string[];
  /** Envelope-relative pointers removed or altered before signing (outbound only). */
  redacted: string[];
  labels: string[];
  /** Full detail for the owner's own side; the other side only ever sees one error code. */
  reasons: Reason[];
  /** `decision.policy_ids`: the organization's policy as `<domain>#<serial>`, plus DLP verdict ids. */
  policy_ids: string[];
  /** Ids of `report`-mode rules that would have applied (the owner's ledger only, never the envelope). */
  report_ids: string[];
  /** A DLP `require_justification` verdict: the message waits for the person's review (spec 6.9, 6.12). */
  hold_for_review?: boolean;
  /** A DLP `notify` verdict fired: allowed, with a security event. */
  notify?: boolean;
}

function bodyLeaves(body: JsonObject): string[] {
  return Object.keys(body).length === 0 ? [] : leafPointers(body, ["body"]);
}

function setAt(body: JsonObject, pointer: string, value: string): void {
  const tokens = pointer.split("/").slice(2).map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
  let cur: unknown = body;
  for (let i = 0; i < tokens.length - 1; i++) cur = (cur as Record<string, unknown>)[tokens[i] as string];
  (cur as Record<string, unknown>)[tokens[tokens.length - 1] as string] = value;
}

function redactSpans(text: string, spans: [number, number][]): string {
  const chars = [...text];
  const sorted = [...spans].sort((a, b) => b[0] - a[0]);
  for (const [a, b] of sorted) {
    const from = Math.max(0, a);
    const to = Math.min(chars.length, b);
    if (to > from) chars.splice(from, to - from, REDACTED_TEXT);
  }
  return chars.join("");
}

/**
 * Sorted, each once. Sorted first and compared with the neighbor, never put in a Set: V8 hashes a string longer than
 * 16,383 characters by its length alone, so a Set of many such pointers (a long member name above many leaves) is
 * quadratic.
 */
function sortedUnique(xs: readonly string[]): string[] {
  const sorted = [...xs].sort();
  return sorted.filter((x, i) => i === 0 || x !== sorted[i - 1]);
}

// What the sender's own side is told about each refused field (outbound only): pointers, field names from the scope's
// schema and rule ids, never a value, because these reasons go to the sender's ledger (spec 6.6). The recipient's side
// keeps its own wording, and the sender only ever learns its single code (spec 6.8). Every text is bounded, whatever the
// draft: a pointer is cut to POINTER_TEXT_MAX characters, a list of pointers to LIST_TEXT_MAX, and a text shared by many
// reasons never lists them all.

/** How much of one pointer a refusal's text shows (the reason's `pointer` member keeps it whole). */
const POINTER_TEXT_MAX = 120;
/** How long a list of pointers in one refusal's text may grow before the rest are counted ("and 12 more"). */
const LIST_TEXT_MAX = 300;
/** How long the list of a draft's other schema problems may grow, after a name the scope doesn't define. */
const ALSO_TEXT_MAX = 500;

/** A pointer as a refusal's text shows it: whole, or cut with "…" (never inside a surrogate pair). */
export function pointerText(p: string, max = POINTER_TEXT_MAX): string {
  if (p.length <= max) return p;
  let cut = max - 1;
  const c = p.charCodeAt(cut - 1);
  if (c >= 0xd800 && c <= 0xdbff) cut -= 1;
  return `${p.slice(0, cut)}…`;
}

/** "a", "a and b", "a, b and c". */
function andList(items: readonly string[]): string {
  return items.length > 1 ? `${items.slice(0, -1).join(", ")} and ${items[items.length - 1] ?? ""}` : (items[0] ?? "");
}

/** Pointers as "a, b and c" within about `max` characters; beyond that, "a, b and 12 more". */
function pointerList(pointers: readonly string[], max = LIST_TEXT_MAX): string {
  const shown: string[] = [];
  let length = 0;
  for (const p of pointers) {
    const t = pointerText(p);
    if (shown.length > 0 && length + 2 + t.length > max) break;
    length += (shown.length > 0 ? 2 : 0) + t.length;
    shown.push(t);
  }
  const rest = pointers.length - shown.length;
  return rest > 0 ? `${shown.join(", ")} and ${rest} more` : andList(shown);
}

/** S5: a pointer the scope's schema doesn't define, with the fields it does define there. */
function unknownFieldText(scope: CompiledScope, type: MessageType, at: string, fields: readonly string[], suggestion: string | undefined): string {
  return `${pointerText(at)} isn't a field of ${scope.id} ${type}${fields.length ? ` (fields: ${fields.join(", ")})` : ""}${suggestion ? `; did you mean ${suggestion}?` : "."}`;
}

/** S5: free text the person's terms don't name exactly (spec 6.5). */
function unnamedFreeTextText(scope: CompiledScope, counterparty: Address, pointer: string): string {
  return `Your person's terms for ${scope.id} with ${displayAddress(counterparty)} don't name the free-text field ${pointerText(pointer)}: send without it, or ask your person to allow it on their broker page.`;
}

/** S5: a type the terms don't allow. Between one person's own agents the terms are the scope's own (spec 6.14 item 2). */
function typeNotAllowedText(scope: CompiledScope, counterparty: Address, type: MessageType, terms: EffectiveTerms): string {
  if (terms.source === "self") return `${type} isn't sent between one person's own agents: propose, counter, accept and commit need two people.`;
  return `Your person's terms for ${scope.id} with ${displayAddress(counterparty)} don't allow ${type} messages.`;
}

export async function evaluateMessage(input: EvaluationInput): Promise<Evaluation> {
  const { direction, owner, counterparty, scope, type, body, terms, policy, dlp, limits } = input;
  const out = direction === "outbound";
  const policyIds: string[] = policy ? [policyRef(policy)] : [];
  const reportIds: string[] = [];
  const common = isCommonType(type);
  const overrides = policy?.classification?.overrides?.[scope.id];
  const freeText = freeTextPatterns(scope, type);
  const labelsAt = (p: string): string[] => labelsOf(scope, type, p, overrides);
  const isText = (p: string): boolean => p === NOTE_POINTER || freeText.some((ft) => matchPattern(ft, p) && ft.split("/").length === p.split("/").length);
  const reject = (code: ErrorCode, reasons: Reason[]): Evaluation => ({
    outcome: "reject",
    code,
    body,
    disclosed: [],
    redacted: [],
    labels: [],
    reasons: reasons.length ? reasons : [{ code }],
    policy_ids: policyIds,
    report_ids: reportIds,
  });
  // The recipient reports steps 7, 8 and 10 as not_accepted; its own ledger keeps the detail.
  const fieldCode: ErrorCode = out ? "not_disclosed" : "not_accepted";
  const leaves = [...bodyLeaves(body), ...(input.note !== undefined ? [NOTE_POINTER] : [])];

  // S1 limits (the broker checked the rest of S1).
  if (canonicalBytes(body).byteLength > limits.bodyMaxBytes) return reject("body_too_large", [{ code: "body_too_large", pointer: "/body", ...(out ? { detail: `The body is larger than ${limits.bodyMaxBytes} bytes as canonical JSON.` } : {}) }]);
  if (input.note !== undefined && [...input.note].length > limits.noteMaxChars) return reject(out ? "invalid_input" : "schema_invalid", [{ code: "schema_invalid", pointer: NOTE_POINTER, detail: `note is limited to ${limits.noteMaxChars} characters` }]);

  // S4 / 7: the organization's deny rules. The federation list, then each enforced classification rule in order.
  if (!federationAllows(policy, domainOf(counterparty))) return reject(out ? "federation_blocked" : "not_accepted", [{ code: "federation_blocked", rule: "federation", ...(out ? { detail: `Your organization doesn't exchange messages with ${domainOf(counterparty)}.` } : {}) }]);
  const marked = new Set<string>();
  const markedBy = new Map<string, string>();
  for (const rule of policy?.classification?.rules ?? []) {
    if (rule.direction !== "both" && rule.direction !== direction) continue;
    if (policy && anyRefMatches(policy, rule.allow, counterparty, input.claimsOf)) continue;
    const hits = leaves.filter((p) => {
      const ls = out ? labelsAt(p) : [...labelsAt(p), ...(input.extraLabels ?? [])];
      return ls.some((l) => rule.labels.some((pat) => labelMatches(pat, l)));
    });
    if (hits.length === 0) continue;
    if (rule.mode === "report") {
      reportIds.push(`report:${rule.id}`);
      continue;
    }
    if (!out) return reject("not_accepted", hits.map((p) => ({ code: "org_policy", pointer: p, rule: rule.id })));
    if (rule.action === "redact") {
      const fresh = hits.filter((p) => !marked.has(p));
      // Removed only while decision.redacted can list them all; otherwise the rule refuses them, as a reject rule does.
      if (marked.size + fresh.length <= REDACTED_MAX && fresh.every((p) => p.length <= REDACTED_POINTER_MAX)) {
        for (const p of hits) {
          marked.add(p);
          markedBy.set(p, rule.id);
        }
        continue;
      }
    }
    const refused = sortedUnique(hits);
    // One bounded text for all of them: a reason per refused field, never a list of every field in each.
    const detail = `Your organization's rule ${rule.id} keeps ${pointerList(refused)} from ${displayAddress(counterparty)}.`;
    return reject("org_policy", refused.map((p) => ({ code: "org_policy", pointer: p, rule: rule.id, detail })));
  }

  // S5 / 8: the relationship, the type, and field coverage. Common-type bodies are exempt from coverage; notes aren't.
  if (!terms) return reject(out ? "no_relationship" : "not_accepted", [{ code: "no_relationship" }]);
  if (!terms.may.includes(type)) return reject(out ? "type_not_allowed" : "not_accepted", [{ code: "type_not_allowed", detail: out ? typeNotAllowedText(scope, counterparty, type, terms) : type }]);
  const uncovered: string[] = [];
  for (const p of leaves) {
    if (marked.has(p)) continue;
    if (terms.all_fields) continue;
    if (common && p !== NOTE_POINTER) continue;
    const ok = terms.fieldSets.every((set) => (isText(p) ? namesExplicitly(set, p, p) : matchesAny(set, p)));
    if (!ok) uncovered.push(p);
  }
  if (uncovered.length > 0) {
    if (!out) return reject(fieldCode, sortedUnique(uncovered).map((p) => ({ code: fieldCode, pointer: p, ...(isText(p) ? { detail: "free text must be named explicitly" } : {}) })));
    // Redaction removes them only while decision.redacted can list every removed leaf.
    const listable = marked.size + uncovered.length <= REDACTED_MAX && uncovered.every((p) => p.length <= REDACTED_POINTER_MAX);
    if (terms.redaction !== "redact" || !listable) {
      // The code and pointers stay those of S5; the text says which pointers aren't fields of the scope at all (a
      // misspelled or misremembered name), and then, in one more reason right after the last of them, what else in the
      // draft the schema would refuse, so the agent can fix it in one go. Each refused pointer's schema is read once.
      const refused = sortedUnique(uncovered);
      const where = refused.map((p) => undefinedField(scope, type, p));
      const leftOut = refused.filter((p, i) => !isText(p) && where[i] === null);
      const notIncluded = `Your person's terms for ${scope.id} with ${displayAddress(counterparty)} don't include ${pointerList(leftOut)}.`;
      const unknown = new Set<string>();
      let lastUnknown = -1;
      const reasons: Reason[] = refused.map((p, i) => {
        const u = where[i];
        if (u) {
          unknown.add(u.at);
          lastUnknown = i;
          return { code: fieldCode, pointer: p, detail: unknownFieldText(scope, type, u.at, u.fields, u.suggestion) };
        }
        return { code: fieldCode, pointer: p, detail: isText(p) ? unnamedFreeTextText(scope, counterparty, p) : notIncluded };
      });
      if (lastUnknown >= 0) {
        // A schema problem at or below a name the scope doesn't define belongs to that name. Such a name is one level
        // below a pointer the schema defines, so each problem's pointer is looked up only that many levels deep.
        let depth = 0;
        for (const u of unknown) depth = Math.max(depth, u.split("/").length);
        const below = (q: string): boolean => {
          if (unknown.has(q)) return true;
          let i = q.indexOf("/", 1);
          for (let level = 2; i !== -1 && level < depth; level++) {
            i = q.indexOf("/", i + 1);
            if (unknown.has(i === -1 ? q : q.slice(0, i))) return true;
          }
          return false;
        };
        const others = validateBody(scope, type, body).filter((e) => !below(e.pointer));
        if (others.length) {
          const also = `The draft also doesn't match the schema: ${joinWithin(others.map((e) => `${pointerText(e.pointer)} ${e.message}`), ALSO_TEXT_MAX, "; ")}.`;
          reasons.splice(lastUnknown + 1, 0, { code: fieldCode, detail: also });
        }
      }
      if (terms.redaction === "redact") {
        reasons.unshift({ code: fieldCode, detail: `Your person's terms remove the fields they don't allow, but this draft has ${uncovered.length + marked.size} fields to remove${uncovered.every((p) => p.length <= REDACTED_POINTER_MAX) ? "" : ", some with names over 512 characters"}, more than one message can list (${REDACTED_MAX}, of up to ${REDACTED_POINTER_MAX} characters each), so it is refused instead.` });
      }
      return reject(fieldCode, reasons);
    }
    for (const p of uncovered) marked.add(p);
  }

  // S6 / 9: remove what was marked (outbound only; a recipient never alters a signed envelope), then the schema.
  let newBody = marked.size ? removePointers(body, [...marked].filter((p) => p !== NOTE_POINTER).map((p) => p.slice("/body".length))) : body;
  let note = marked.has(NOTE_POINTER) ? undefined : input.note;
  const schema = validateBody(scope, type, newBody);
  if (schema.length > 0) return reject("schema_invalid", schema.map((e) => ({ code: "schema_invalid", pointer: e.pointer, detail: `${pointerText(e.pointer)} ${e.message}` })));

  // S7 / 10: DLP on every remaining free-text leaf and the note: outbound always, inbound when the policy asks.
  const redactedSpans: string[] = [];
  let holdForReview = false;
  let notify = false;
  const remaining = [...bodyLeaves(newBody), ...(note !== undefined ? [NOTE_POINTER] : [])];
  if (out || policy?.dlp?.inbound) {
    for (const p of remaining) {
      if (!isText(p)) continue;
      const text = p === NOTE_POINTER ? note : getAt(newBody, p.slice("/body".length));
      if (typeof text !== "string") continue;
      const v = await runDlp(
        dlp,
        { principal_id: input.owner_id, principal: owner, counterparty, direction, scope: scope.id, labels: labelsAt(p), pointer: p, text },
        { ...(policy?.dlp?.timeout_ms ? { timeoutMs: policy.dlp.timeout_ms } : {}), ...(policy?.dlp?.on_error ? { onError: policy.dlp.on_error } : {}) },
      );
      if (v.verdict === "allow") continue;
      const categories: DlpCategory[] | undefined = v.verdict === "block" ? v.categories : undefined;
      if (!out) {
        // Inbound DLP only refuses for the categories the organization asked for (a hook's own verdicts always count).
        if (v.verdict === "notify") continue;
        const orgCategories = policy?.dlp?.categories;
        if (categories && orgCategories && !categories.some((c) => orgCategories.includes(c))) continue;
        return reject("not_accepted", [{ code: "dlp_blocked", pointer: p, ...(categories ? { categories } : {}) }]);
      }
      if (v.id) policyIds.push(v.id);
      if (v.verdict === "notify") {
        notify = true;
        continue;
      }
      if (v.verdict === "require_justification") {
        holdForReview = true;
        continue;
      }
      if (v.verdict === "redact" && terms.redaction === "redact") {
        if (p === NOTE_POINTER) note = redactSpans(note ?? "", v.spans);
        else {
          if (newBody === body) newBody = structuredClone(body);
          setAt(newBody, p, redactSpans(text, v.spans));
        }
        redactedSpans.push(p);
        continue;
      }
      return reject("dlp_blocked", [{ code: "dlp_blocked", pointer: p, ...(categories ? { categories } : {}), detail: `${pointerText(p)} looks like sensitive data${categories?.length ? ` (${categories.join(", ")})` : ""}.` }]);
    }
  }

  // S8: the decision.
  const crossing = [...bodyLeaves(newBody), ...(note !== undefined ? [NOTE_POINTER] : [])];
  const labels = sortedUnique([...crossing.flatMap(labelsAt), ...(out ? input.extraLabels ?? [] : [])]);
  const redacted = sortedUnique([...marked, ...redactedSpans]);
  if (newBody !== body) newBody = structuredClone(newBody);
  return {
    outcome: redacted.length ? "redact" : "allow",
    body: newBody,
    ...(note !== undefined ? { note } : {}),
    disclosed: crossing,
    redacted,
    labels,
    reasons: [...marked].map((p) => ({ code: (markedBy.has(p) ? "org_policy" : fieldCode) as ErrorCode, pointer: p, ...(markedBy.has(p) ? { rule: markedBy.get(p) as string } : {}) })),
    policy_ids: sortedUnique(policyIds),
    report_ids: reportIds,
    ...(holdForReview ? { hold_for_review: true } : {}),
    ...(notify ? { notify: true } : {}),
  };
}

/**
 * The single code a recipient's broker returns to the sender (spec 6.8). It never names the recipient's rules or
 * reveals whom the recipient accepts: anything about fields, grants or org rules becomes `not_accepted`.
 */
export function codeForSender(reasons: Reason[]): ErrorCode {
  const first = reasons[0]?.code ?? "not_accepted";
  const passthrough: ErrorCode[] = ["schema_invalid", "body_too_large", "rate_limited", "replay", "expired", "thread_state", "unknown_scope", "unknown_type", "constraints_unsupported", "internal"];
  return passthrough.includes(first) ? first : "not_accepted";
}

/** The shape the sender-side vectors (vectors/policy/sender.json) describe a rejection with. */
export function rejectionDetail(reasons: Reason[], code: ErrorCode): { pointers?: string[]; rule?: string; categories?: DlpCategory[] } {
  const mine = reasons.filter((r) => r.code === code || (code === "dlp_blocked" && r.code === "dlp_blocked"));
  const pointers = sortedUnique(mine.flatMap((r) => (r.pointer ? [r.pointer] : [])));
  const rule = mine.find((r) => r.rule)?.rule;
  const categories = mine.find((r) => r.categories)?.categories;
  return { ...(pointers.length ? { pointers } : {}), ...(rule && code === "org_policy" ? { rule } : {}), ...(categories ? { categories: [...categories].sort() } : {}) };
}

export type { PrincipalId };
