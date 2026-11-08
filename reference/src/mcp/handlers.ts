// SPDX-License-Identifier: FSL-1.1-ALv2
// The seven client-binding tools (spec 12.1; schemas/client/tools.json), shared by the MCP server and the REST mirror.
// Each takes the verified caller (one principal, one delegate) and calls the Broker API; nothing here decides what
// may cross: the core does, at the sender's broker and again at the recipient's.

import { createHash } from "node:crypto";
import { displayAddress, domainOf, parseAddress } from "../core/address.ts";
import { joinWithin } from "../core/ajv.ts";
import type { SendResult } from "../core/api.ts";
import type { Broker } from "../core/broker.ts";
import { AlpError, isAlpError } from "../core/errors.ts";
import { isUlid } from "../core/ids.ts";
import type { Notifier } from "../core/interfaces.ts";
import { matchPattern } from "../core/pointers.ts";
import { pointerText } from "../core/policy/evaluate.ts";
import { clientRule, describeMinimum, hasAnyDefault } from "../core/policy/org-policy.ts";
import type { ClaimsOf } from "../core/policy/org-policy.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { effectiveTerms, selfTerms } from "../core/relationships.ts";
import type { EffectiveTerms } from "../core/relationships.ts";
import { freeTextPatterns, undefinedField } from "../core/scopes/index.ts";
import type { CompiledScope } from "../core/scopes/index.ts";
import { MAX_THREAD_MESSAGES, TERMINAL_STATES, acceptedTypes, expireIfDue, latestProposal, mayFollowUp, messageCount } from "../core/threads.ts";
import { ERROR_CODES, MESSAGE_TYPES } from "../core/types.ts";
import { ackedBy } from "../core/visibility.ts";
import type { Address, DelegateId, DelegateRecord, Envelope, ErrorCode, JsonObject, MessageType, OrgPolicy, PrincipalRecord, Reason, ScopeId, ThreadRecord } from "../core/types.ts";
import type { AuthContext } from "../oauth/resource.ts";
import type { BindingStore, JsonRecord, JsonValue } from "../oauth/state.ts";
import { filePending, pendingFor } from "./pending.ts";
import { UNTRUSTED_FOOTER, blockJson, renderUntrusted, sanitizeBody, sanitizeFreeText } from "./render.ts";
import { commonBodySchema, commonDefs } from "./tools.ts";
import type { ToolCatalog } from "./tools.ts";

export interface ToolContext {
  broker: Broker;
  state: BindingStore;
  catalog: ToolCatalog;
  /** The broker's private org policies (to show a person's own terms; enforcement stays in the core). */
  policies: () => readonly OrgPolicy[];
  notifier: Notifier;
  now: () => Date;
  log: (line: string) => void;
}

export type ToolOutcome =
  | { ok: true; structured: JsonRecord; text: string }
  | { ok: false; code: ErrorCode; status: number; message: string; structured?: JsonRecord; text: string };

/** HTTP status per error code (spec 18.3). */
export const ERROR_STATUS: Record<ErrorCode, number> = {
  invalid_input: 400, identity_mismatch: 403, unknown_scope: 422, unknown_type: 422, schema_invalid: 422, body_too_large: 413,
  no_relationship: 403, type_not_allowed: 403, not_disclosed: 403, org_policy: 403, federation_blocked: 403, client_not_allowed: 403,
  blocked: 403, dlp_blocked: 403, rate_limited: 429, thread_state: 409, needs_ratification: 409, unknown_recipient: 404,
  discovery_failed: 503, unreachable: 502, expired: 400, bad_envelope: 400, unsupported_version: 400, bad_signature: 401,
  wrong_audience: 400, replay: 409, broker_not_authorized: 403, not_accepted: 403, constraints_unsupported: 422, internal: 500,
};

/** What an agent should do about each refusal. Never names the recipient's rules. */
const ADVICE: Partial<Record<ErrorCode, string>> = {
  no_relationship: "Your person has no relationship with this person for this scope. Use alp_request_connection; it goes to them (not their agent) after your person approves it.",
  not_disclosed: "A field you included isn't one your person allows for this counterparty and scope (see pointers). Leave it out; don't move it into another field.",
  org_policy: "Your organization's policy doesn't let a field go to this counterparty (see pointers). Leave it out.",
  dlp_blocked: "Leave that text out; don't rephrase it or move it into another field.",
  schema_invalid: "The body doesn't match the scope's schema (see pointers). alp_whoami with include_scopes returns the schemas.",
  type_not_allowed: "alp_contacts lists the types you may send each contact.",
  client_not_allowed: "Your person's organization doesn't allow this agent to use this scope.",
  thread_state: "That message doesn't fit the thread. alp_thread shows its state and the types you may send next.",
  needs_ratification: "Both people must approve the agreed terms before a commit, each on their broker's page unless they approved such terms in advance, within limits they set. Then send the commit again, with a new idempotency_key if you set one.",
  unknown_recipient: "Check the address, and the agent's name in to_delegate.",
  rate_limited: "Wait at least retry_after seconds, then send it again, with a new idempotency_key if you set one (the same key returns this answer for 24 hours).",
  blocked: "Your person's organization has blocked this.",
  federation_blocked: "Tell your person: their organization's administrator decides which domains it exchanges messages with.",
  not_accepted: "Nothing reached their agent, and their broker doesn't say why: tell your person, and don't send it again in another form.",
  unreachable: "Tell your person; don't send it again unless they ask, since a second send would be a second message.",
  discovery_failed: "The recipient's domain couldn't be checked. Try again later, with a new idempotency_key if you set one.",
};

/**
 * Refusals of a draft the agent should fix and send once more. alp_send keeps each answer under its idempotency_key for
 * 24 hours (spec 10.3; every answer but internal), so the advice for these says that the corrected draft needs a new
 * key; after internal, a timeout or no answer, the same key is the right retry (spec 13.8 CD-6).
 */
const FIX_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>(["invalid_input", "unknown_scope", "unknown_type", "schema_invalid", "body_too_large", "thread_state", "unknown_recipient"]);
const NEW_KEY_ADVICE = "Send the corrected draft with a new idempotency_key if you set one (the same key returns this answer for 24 hours).";

/** A recipient's rate_limited refusal that came with no Retry-After: the sender's first retry interval of spec 10.2 (30 seconds, doubling). */
const RECIPIENT_RETRY_SECONDS = 30;

/** not_disclosed advice when every refused pointer isn't a field of the scope at all (a misspelled or misremembered name). */
const FIX_FIELD_ADVICE = "Use the field names the scope defines (alp_whoami with include_scopes returns its schemas) and send it again.";
/** not_disclosed advice when some refused pointers aren't fields of the scope and others are fields the terms leave out. */
const MIXED_FIELD_ADVICE = "Correct the names the scope doesn't define; leave out the fields your person's terms don't allow, and don't move them into another field.";
/** alp_thread's advice when the id names none of the person's threads (no message was sent, so none to fix). */
const THREAD_ID_ADVICE = "Check the thread id: use an inbox item's thread, or the thread an alp_send result names.";
/** type_not_allowed advice between one person's own agents, who have no terms with each other but the scope's own (spec 6.14). */
const OWN_TYPE_ADVICE = "alp_whoami lists the scopes and types you can use with your person's other agents.";

/**
 * Whether a send is to another of the caller's person's own agents (spec 6.14): `to` is the person's own address, and
 * an agent is named, in `to_delegate` or, for a reply that names none, as the agent it answers (`resolved`).
 */
function toOwnAgent(auth: AuthContext, args: Record<string, unknown>, resolved: string | undefined): boolean {
  if (typeof args["to_delegate"] !== "string" && resolved === undefined) return false;
  try {
    return parseAddress(String(args["to"])) === auth.caller.principal;
  } catch {
    return false;
  }
}

const PLUMBING: readonly MessageType[] = ["ack", "decline", "error"];
const POINTER_RE = /^(?:\/body(?:\/(?:[^/~]|~[01])*)*|\/note)$/;

/** A sentence: trimmed, with a closing stop (a text cut with "…", or ending in joinWithin's "(and N more)", has one). */
function sentence(text: string): string {
  const t = text.trim();
  return /(?:[.?!…]|\(and \d+ more\))$/.test(t) ? t : `${t}.`;
}

/**
 * The refusal message from every reason (spec 18.3), within `max` characters: the broker's own words, which name
 * pointers, field names from the schemas, rule ids and limits, never a submitted value. Each distinct sentence once;
 * once the message is full the rest are only counted, so a draft with thousands of problems costs no more than one
 * pass over its reasons.
 */
function refusalMessage(code: ErrorCode, reasons: readonly Reason[], max = 1000): string {
  const seen = new Set<string>();
  const parts: string[] = [];
  let length = 0;
  let omitted = 0;
  for (const r of reasons) {
    const at = r.pointer ? pointerText(r.pointer) : "";
    const text = r.detail ?? (code === "org_policy" && r.rule ? `your organization's rule ${r.rule}${at ? ` keeps ${at} from this counterparty` : ""}` : at ? `${at} was refused (${code})` : "");
    if (!text) continue;
    const s = sentence(text);
    if (seen.has(s)) continue;
    seen.add(s);
    if (length > max) omitted += 1;
    else {
      parts.push(s);
      length += s.length + 1;
    }
  }
  return parts.length ? joinWithin(parts, max, " ", omitted) : `Refused by your person's broker (${code}).`;
}

/** The error's pointers (tools.json): valid patterns of at most 512 characters, each once, at most 64. */
function errorPointers(given: readonly string[]): string[] {
  const out: string[] = [];
  for (const p of given) {
    if (out.length >= 64) break;
    if (p.length <= 512 && POINTER_RE.test(p) && !out.includes(p)) out.push(p);
  }
  return out;
}

/**
 * A refusal: the structured error (tools.json, and the REST mirror's body) and the text. The message is the broker's
 * own words, closed as a sentence, then the advice for its code, so a REST caller gets the guidance an MCP client
 * gets, all within 1,000 characters.
 */
function fail(code: ErrorCode, message: string, opts: { status?: number; withStructured?: boolean; pointers?: string[]; rule?: string; categories?: string[]; advice?: string; retryAfter?: number } = {}): ToolOutcome {
  const advice = opts.advice ?? ADVICE[code];
  const base = message.trim() ? sentence(message) : "";
  const room = advice ? 1000 - advice.length - 1 : 1000;
  const fitted = base.length <= room ? base : `${base.slice(0, Math.max(0, room - 1))}…`;
  const msg = advice && !fitted.includes(advice) ? (fitted ? `${fitted} ${advice}` : advice) : fitted.slice(0, 1000);
  const err: JsonRecord = { code, message: msg };
  if (opts.retryAfter !== undefined) err["retry_after"] = Math.max(1, Math.ceil(opts.retryAfter));
  const pointers = errorPointers(opts.pointers ?? []);
  if (pointers.length) err["pointers"] = pointers;
  if (opts.rule) err["rule"] = opts.rule.slice(0, 64);
  if (opts.categories?.length) err["categories"] = [...new Set(opts.categories)];
  return {
    ok: false,
    code,
    status: opts.status ?? ERROR_STATUS[code],
    message: msg,
    ...(opts.withStructured ? { structured: { error: err } } : {}),
    text: `Refused (${code}): ${msg}${pointers.length ? ` Pointers: ${pointers.join(", ")}.` : ""}`,
  };
}

function fromThrown(err: unknown, withStructured: boolean): ToolOutcome {
  if (isAlpError(err)) return fail(err.code, err.message, { status: ERROR_STATUS[err.code] ?? err.status, withStructured, pointers: err.reasons.map((r) => r.pointer ?? "").filter(Boolean) });
  return fail("internal", "the broker hit an internal error", { withStructured });
}

function typeOrder(types: Iterable<MessageType>): MessageType[] {
  const set = new Set(types);
  return MESSAGE_TYPES.filter((t) => set.has(t));
}

function policyFor(c: ToolContext, address: Address): OrgPolicy | null {
  const d = domainOf(address);
  return c.policies().find((p) => p.domains.includes(d)) ?? null;
}

async function principalOf(c: ToolContext, auth: AuthContext): Promise<PrincipalRecord> {
  const p = await c.broker.store.getPrincipalById(auth.principal_id);
  if (!p || p.status !== "active") throw new AlpError("identity_mismatch", "unknown or suspended principal", { status: 401 });
  return p;
}

// ---------------------------------------------------------------------------------------------
// Relationships as the person's own rules show them (whoami scopes, contacts).

interface ScopeView {
  scope: ScopeId;
  may: MessageType[];
  disclose: string[];
  commit: "ask_me" | "within_limits";
  hold_for_review: boolean;
}

interface ContactView {
  address: Address;
  basis: "grant" | "org_default";
  status: "active" | "pending";
  scopes: ScopeView[];
}

function discloseOf(t: EffectiveTerms): string[] {
  const sets = t.fieldSets;
  if (sets.length === 0) return [];
  const last = sets[sets.length - 1] ?? [];
  // A field crosses only if every layer allows it: show the last layer's patterns that every other layer covers.
  return last.filter((p) => sets.slice(0, -1).every((s) => s.some((q) => matchPattern(q, p)))).slice(0, 64);
}

function scopeView(scope: CompiledScope, t: EffectiveTerms): ScopeView {
  const may = typeOrder([...t.may.filter((m) => scope.types.has(m)), ...PLUMBING.filter((m) => scope.types.has(m))]).slice(0, 10);
  return { scope: scope.id, may, disclose: discloseOf(t), commit: t.commit, hold_for_review: t.hold_for_review === true };
}

async function contactViews(c: ToolContext, owner: PrincipalRecord, now: Date): Promise<ContactView[]> {
  const store = c.broker.store;
  const policy = policyFor(c, owner.address);
  const principals = await store.listPrincipals();
  const byAddress = new Map(principals.map((p) => [p.address, p]));
  const claimsOf: ClaimsOf = (a) => byAddress.get(a)?.claims ?? [];
  const candidates = new Map<Address, "grant" | "org_default">();
  for (const g of await store.listGrants(owner.address)) {
    // A grant an earlier holder of this address sealed is not this person's (spec 5.2).
    if (g.basis === "consent" && g.status !== "revoked" && g.principal_id === owner.principal_id) candidates.set(g.counterparty, "grant");
  }
  if (policy) {
    for (const p of principals) {
      if (p.status !== "active" || p.address === owner.address || candidates.has(p.address)) continue;
      if (hasAnyDefault(policy, owner.address, p.address, claimsOf)) candidates.set(p.address, "org_default");
    }
  }
  const out: ContactView[] = [];
  for (const [address, basis] of candidates) {
    const grant = await c.broker.grantOf(owner, address);
    const revocation = await store.getRevocation(owner.address, address);
    const scopes: ScopeView[] = [];
    for (const id of c.broker.scopes.ids()) {
      const scope = c.broker.scopes.get(id);
      if (!scope) continue;
      const tr = effectiveTerms({ owner: owner.address, counterparty: address, scope: id, direction: "outbound", grant, revocation, policy, claimsOf, now });
      if (tr.ok) scopes.push(scopeView(scope, tr.terms));
    }
    const pending = grant?.status === "pending";
    if (scopes.length === 0 && !pending) continue;
    out.push({ address, basis, status: scopes.length === 0 ? "pending" : "active", scopes: scopes.slice(0, 32) });
  }
  // Requests waiting for an answer: the core's outgoing ones and the ones this binding holds for the person.
  const waiting = new Map<Address, ScopeId[]>();
  for (const r of await store.listConnections(owner.address)) {
    if (r.principal_id !== undefined && r.principal_id !== owner.principal_id) continue;
    if (r.direction === "outgoing" && r.state === "pending" && Date.parse(r.expires_at) > now.getTime()) waiting.set(r.counterparty, r.scopes);
  }
  for (const p of await pendingFor(c.state, owner.principal_id, now)) if (p.state === "pending_principal") waiting.set(p.to, p.scopes);
  for (const [address, scopes] of waiting) {
    if (out.some((x) => x.address === address)) continue;
    out.push({ address, basis: "grant", status: "pending", scopes: scopes.slice(0, 32).map((s) => ({ scope: s, may: [], disclose: [], commit: "ask_me", hold_for_review: false })) });
  }
  return out.sort((a, b) => a.address.localeCompare(b.address));
}

// ---------------------------------------------------------------------------------------------
// The person's own agents (spec 6.14), as whoami's text shows them.

/**
 * The person's other agents that can receive a message now: active delegates of this principal (an earlier holder of
 * the address had their own, spec 5.2), not blocked, whose client the organization's list allows, ranked by that list
 * (spec 5.4). Never another person's.
 */
async function ownAgents(c: ToolContext, owner: PrincipalRecord, self: DelegateId): Promise<DelegateRecord[]> {
  const mine = (await c.broker.store.listDelegates(owner.address)).filter((d) => d.status === "active" && d.principal_id === owner.principal_id && d.id !== self && !c.broker.agentBlocked(owner.address, d.id, d.client_id) && !c.broker.clientRefused(owner.address, d.client_id));
  return mine.map((d) => c.broker.ranked(d)).sort((a, b) => a.label.localeCompare(b.label));
}

interface OwnScopeView {
  scope: CompiledScope;
  /** The types that start a thread (the scope's `starts`), then the types that continue an open one (spec 9.2). */
  starts: MessageType[];
  continues: MessageType[];
}

/**
 * What an agent may send the person's other agents: the terms between one person's own agents (no grant; no
 * negotiation types), in the scopes its client may use (every registered scope unless the organization's list is
 * enforced). A scope none of whose starting types is allowed is left out. Advisory: the core decides.
 */
function ownScopeViews(c: ToolContext, allowed: Set<ScopeId> | null): OwnScopeView[] {
  const may = new Set(selfTerms().may);
  const out: OwnScopeView[] = [];
  for (const id of c.broker.scopes.ids()) {
    const scope = c.broker.scopes.get(id);
    if (!scope || (allowed && !allowed.has(id))) continue;
    const usable = (t: MessageType): boolean => may.has(t) && scope.types.has(t);
    const starts = typeOrder(scope.def.starts.filter(usable)).slice(0, 10);
    if (starts.length === 0) continue;
    // One person's own agents never negotiate, so their threads stay open until they end: what an open thread takes.
    const continues = typeOrder(acceptedTypes(scope, "open").filter(usable)).slice(0, 10);
    out.push({ scope, starts, continues });
  }
  return out;
}

/** "a", "a or b", "a, b or c". */
function orList(items: readonly string[]): string {
  return items.length > 1 ? `${items.slice(0, -1).join(", ")} or ${items[items.length - 1] ?? ""}` : (items[0] ?? "");
}

// ---------------------------------------------------------------------------------------------
// Inbound items

function resolveCommonRefs(schema: unknown, defs: Record<string, unknown>): unknown {
  if (Array.isArray(schema)) return schema.map((s) => resolveCommonRefs(s, defs));
  if (!schema || typeof schema !== "object") return schema;
  const o = schema as Record<string, unknown>;
  const ref = o["$ref"];
  if (typeof ref === "string") {
    const m = /common\.schema\.json#\/\$defs\/([A-Za-z0-9_]+)$/.exec(ref);
    const def = m?.[1] !== undefined ? defs[m[1]] : undefined;
    // Only the broker sends ratification records; an agent's schema doesn't offer them.
    return def !== undefined ? resolveCommonRefs(def, defs) : false;
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) if (k !== "$id") out[k] = resolveCommonRefs(v, defs);
  return out;
}

let commonDefinitions: Record<string, unknown> | undefined;
function bodySchemaFor(scope: CompiledScope, type: MessageType): unknown {
  const own = scope.def.types[type as keyof typeof scope.def.types];
  if (own) return own.schema;
  commonDefinitions ??= commonDefs();
  const s = commonBodySchema(type);
  return s ? resolveCommonRefs(s, commonDefinitions) : { type: "object" };
}

interface Shaped {
  item: JsonRecord;
  text: string;
}

async function shapeInbound(c: ToolContext, owner: PrincipalRecord, e: Envelope, receivedAt: string, opts: { includeEnvelope: boolean; acked: boolean }): Promise<Shaped> {
  const scope = c.broker.scopes.get(e.scope);
  const ft = scope ? freeTextPatterns(scope, e.type) : [];
  const stored = await c.broker.store.getThread(owner.address, e.thread);
  const threadState = stored ? expireIfDue(stored, c.now()).state : "open";
  const handling = policyFor(c, owner.address)?.inbound_default === "response_only" ? "response_only" : "open";
  const from: JsonRecord = { address: e.from.address, display: displayAddress(e.from.address), principal_id: e.from.principal_id };
  if (e.from.delegate) from["delegate"] = e.from.delegate;
  if (e.from.attestation) from["attestation"] = e.from.attestation;
  if (e.from.class) from["class"] = e.from.class;
  const verified: JsonRecord = {
    from,
    scope: e.scope,
    type: e.type,
    ...(e.in_reply_to ? { in_reply_to: e.in_reply_to } : {}),
    thread_state: threadState,
    decision: { outcome: e.decision.outcome, redacted: [...e.decision.redacted], policy_ids: [...e.decision.policy_ids] },
    origin_broker: e.origin_broker,
    testing: false,
    handling,
    ...(e.constraints ? { constraints: JSON.parse(JSON.stringify(e.constraints)) as JsonRecord } : {}),
  };
  const body = sanitizeBody(e.body, ft);
  const note = e.note !== undefined ? Array.from(sanitizeFreeText(e.note)).slice(0, 280).join("") : undefined;
  const content: JsonRecord = { kind: "untrusted", notice: c.catalog.untrustedNotice, body: body as JsonValue, ...(note !== undefined ? { note } : {}) };
  const item: JsonRecord = {
    id: e.id,
    thread: e.thread,
    received_at: receivedAt,
    acked: opts.acked,
    verified,
    content,
    ...(opts.includeEnvelope ? { envelope: JSON.parse(JSON.stringify(e)) as JsonRecord } : {}),
  };
  const label = e.from.delegate ? e.from.delegate.slice(e.from.delegate.lastIndexOf("/") + 1) : undefined;
  const text = renderUntrusted(
    e.id,
    {
      from: displayAddress(e.from.address),
      ...(label ? { delegateLabel: label } : {}),
      ...(e.from.class ? { delegateClass: e.from.class } : {}),
      ...(e.from.attestation ? { attestation: e.from.attestation } : {}),
      ...(e.from.address === owner.address ? { own: true } : {}),
      ...(e.origin_broker !== c.broker.id ? { recordedBy: e.origin_broker } : {}),
      scope: e.scope,
      type: e.type,
      threadState,
      handling,
    },
    { body, ...(note !== undefined ? { note } : {}) },
  );
  return { item, text };
}

// ---------------------------------------------------------------------------------------------
// The tools

type Args = Record<string, unknown>;

async function whoami(c: ToolContext, auth: AuthContext, args: Args): Promise<ToolOutcome> {
  const w = await c.broker.whoami(auth.caller);
  const owner = await principalOf(c, auth);
  const policy = policyFor(c, owner.address);
  const rule = policy?.clients?.mode === "enforce" ? clientRule(policy, auth.caller.client_id) : undefined;
  const allowed = policy?.clients?.mode === "enforce" ? new Set(rule?.scopes ?? []) : null;
  const byScope = new Map<ScopeId, Set<MessageType>>();
  const views = await contactViews(c, owner, c.now());
  for (const cv of views) {
    if (cv.status !== "active") continue;
    for (const s of cv.scopes) {
      if (allowed && !allowed.has(s.scope)) continue;
      const set = byScope.get(s.scope) ?? new Set<MessageType>();
      s.may.forEach((m) => set.add(m));
      byScope.set(s.scope, set);
    }
  }
  const include = args["include_scopes"] === true;
  const scopes: JsonRecord[] = [];
  for (const [id, types] of [...byScope.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const scope = c.broker.scopes.get(id);
    if (!scope || types.size === 0) continue;
    const list = typeOrder(types).slice(0, 10);
    const entry: JsonRecord = { id, title: scope.def.title.slice(0, 64), types: list };
    if (include) {
      const schemas: JsonRecord = {};
      for (const t of list) schemas[t] = bodySchemaFor(scope, t) as JsonValue;
      entry["schemas"] = schemas;
    }
    scopes.push(entry);
  }
  const structured: JsonRecord = {
    id: w.principal_id,
    address: w.principal,
    display: w.display,
    delegate: w.delegate,
    attestation: w.attestation,
    class: w.class,
    broker: w.broker,
    alp: PROTOCOL.version,
    scopes: scopes.slice(0, 64),
  };
  // Writing to the person's other agents needs no relationship (spec 6.14), so `scopes` above, which lists what the
  // person's relationships allow, doesn't cover it. Only the text says who they are and what this agent may send them;
  // the structured result stays as tools.json defines it.
  const others = await ownAgents(c, owner, w.delegate);
  const own = others.length ? ownScopeViews(c, allowed) : [];
  const named = others.slice(0, 32).map((d) => `${d.label} (${d.class}, ${d.attestation}-attested)`).join(", ");
  const schemaText: string[] = [];
  if (!include) schemaText.push("Call again with include_scopes: true for the body schemas.");
  else {
    if (scopes.length || own.length === 0) schemaText.push("The body schema for each type is in structuredContent.scopes[].schemas.");
    if (own.length) {
      const schemas: JsonRecord = {};
      for (const v of own) {
        const byType: JsonRecord = {};
        for (const t of typeOrder([...v.starts, ...v.continues])) byType[t] = bodySchemaFor(v.scope, t) as JsonValue;
        schemas[v.scope.id] = byType;
      }
      schemaText.push(`The body schemas for what you can send your person's other agents, by scope and type: ${blockJson(schemas)}`);
    }
  }
  const text = [
    `You act for ${w.display}${w.display_name ? ` (${w.display_name})` : ""} as delegate ${w.delegate}, through the broker ${w.broker}.`,
    `Recorded for this agent: attestation ${w.attestation}, class ${w.class}.`,
    scopes.length
      ? `Scopes you can use: ${scopes.map((s) => `${String(s["id"])} (${(s["types"] as string[]).join(", ")})`).join("; ")}.`
      : views.some((cv) => cv.status === "active")
        ? "Your person has relationships with other people, but this agent's client may use none of their scopes."
        : others.length
          ? "Your person has no relationships with other people yet: to reach someone else, use alp_request_connection."
          : "You have no relationships yet: use alp_request_connection.",
    others.length ? `Your person's other agents: ${named}${others.length > 32 ? `, and ${others.length - 32} more` : ""}.` : "Your person's other agents: none.",
    ...(others.length
      ? [
          `To write to one, use alp_send with to = ${w.display} (your person's own address) and to_delegate = its label; no connection is needed.`,
          own.length
            ? `Scopes you can use with them: ${own.map((v) => `${v.scope.id} (start with ${orList(v.starts)}${v.continues.length ? `; continue with ${v.continues.join(", ")}` : ""})`).join("; ")}.`
            : "None of the scopes this agent may use lets it start a thread with them.",
        ]
      : []),
    ...schemaText,
  ].join(" ");
  return { ok: true, structured, text };
}

async function contacts(c: ToolContext, auth: AuthContext, args: Args): Promise<ToolOutcome> {
  await c.broker.whoami(auth.caller);
  const owner = await principalOf(c, auth);
  const query = typeof args["query"] === "string" ? args["query"].toLowerCase() : "";
  const scope = typeof args["scope"] === "string" ? args["scope"] : undefined;
  const limit = typeof args["limit"] === "number" ? args["limit"] : 25;
  const cursor = typeof args["cursor"] === "string" && /^[0-9]{1,6}$/.test(args["cursor"]) ? Number(args["cursor"]) : 0;
  let all = await contactViews(c, owner, c.now());
  if (query) all = all.filter((x) => x.address.includes(query));
  if (scope) all = all.filter((x) => x.scopes.some((s) => s.scope === scope));
  const page = all.slice(cursor, cursor + limit);
  const next = cursor + limit < all.length ? String(cursor + limit) : undefined;
  const structured: JsonRecord = {
    contacts: page.map((x) => ({ address: x.address, display: displayAddress(x.address), basis: x.basis, status: x.status, scopes: x.scopes.map((s) => ({ scope: s.scope, may: s.may, disclose: s.disclose, commit: s.commit, hold_for_review: s.hold_for_review })) })),
    ...(next ? { next_cursor: next } : {}),
  };
  const text = page.length
    ? page
        .map((x) => `${displayAddress(x.address)} (${x.basis === "org_default" ? "organization default" : "your person's grant"}${x.status === "pending" ? ", waiting for an answer" : ""}): ${x.scopes.map((s) => `${s.scope} may ${s.may.join("/") || "nothing yet"}${s.disclose.length ? `; fields ${s.disclose.join(" ")}` : ""}`).join(" | ")}`)
        .join("\n")
    : "No contacts match.";
  return { ok: true, structured, text: `${text}${next ? `\nMore: call again with cursor ${next}.` : ""}` };
}

/** Per binding (spec 5.4): an agent that takes a disconnected agent's label never gets the earlier one's results back. */
function idempotencyKey(auth: AuthContext, since: string, key: string): string {
  return createHash("sha256").update(`${auth.caller.delegate}\u0000${since}\u0000${key}`).digest("base64url");
}

function storeOutcome(o: ToolOutcome): JsonRecord {
  return o.ok ? { ok: true, structured: o.structured, text: o.text } : { ok: false, code: o.code, status: o.status, message: o.message, text: o.text, ...(o.structured ? { structured: o.structured } : {}) };
}

function loadOutcome(r: JsonRecord): ToolOutcome | null {
  const text = typeof r["text"] === "string" ? r["text"] : "";
  const structured = r["structured"] && typeof r["structured"] === "object" && !Array.isArray(r["structured"]) ? (r["structured"] as JsonRecord) : undefined;
  if (r["ok"] === true && structured) return { ok: true, structured, text };
  const code = r["code"];
  if (r["ok"] === false && typeof code === "string" && (ERROR_CODES as readonly string[]).includes(code)) {
    return { ok: false, code: code as ErrorCode, status: typeof r["status"] === "number" ? r["status"] : 400, message: typeof r["message"] === "string" ? r["message"] : "", text, ...(structured ? { structured } : {}) };
  }
  return null;
}

/**
 * How long the call that claimed an idempotency key may take to answer before a call with the same key takes the key
 * over: one that holds it longer stopped without answering (the broker restarted). Far beyond what a send takes.
 */
const SENDING_MS = 5 * 60_000;
/** The record of a key whose first call is still being sent. */
const SENDING: JsonRecord = { sending: true };

function stillSending(): ToolOutcome {
  return fail("internal", "The first alp_send with this idempotency_key is still being sent.", { withStructured: true, retryAfter: 2, advice: "Try again in a few seconds with the same idempotency_key: you get the first call's answer once it has one." });
}

async function send(c: ToolContext, auth: AuthContext, args: Args): Promise<ToolOutcome> {
  const since = (await c.broker.store.getDelegate(auth.caller.delegate))?.created_at ?? "";
  const key = typeof args["idempotency_key"] === "string" ? idempotencyKey(auth, since, args["idempotency_key"]) : undefined;
  if (!key) return sendOnce(c, auth, args);
  // Spec 10.3: a call with a key this binding used within 24 hours never sends again. The first call claims the key
  // before it sends, atomically, so of two calls at once only one sends (an agent whose client gave up on the first
  // retries); the other is told it is still being sent. Its answer then stays under the key, all but an `internal`,
  // after which the message can't have arrived and a call with the same key tries again.
  let claimed: number | undefined;
  for (let tries = 0; tries < 2 && claimed === undefined; tries++) {
    const now = c.now().getTime();
    const prior = await c.state.getIdempotency(key);
    if (prior && now - prior.at < 24 * 3600_000) {
      const o = loadOutcome(prior.result);
      if (o) return o;
      if (prior.result["sending"] === true && now - prior.at < SENDING_MS) return stillSending();
    }
    if (await c.state.swapIdempotency(key, prior?.at ?? null, { at: now, result: SENDING })) claimed = now;
  }
  if (claimed === undefined) return stillSending();
  let outcome: ToolOutcome;
  try {
    outcome = await sendOnce(c, auth, args);
  } catch (err) {
    await c.state.swapIdempotency(key, claimed, null).catch(() => false);
    throw err;
  }
  const internal = outcome.ok === false && outcome.code === "internal";
  try {
    await c.state.swapIdempotency(key, claimed, internal ? null : { at: c.now().getTime(), result: storeOutcome(outcome) });
  } catch (err) {
    // The answer stands: the message went (or didn't) whatever the store says. The claim stays until SENDING_MS.
    c.log(`mcp: alp_send couldn't record its answer under its idempotency key: ${err instanceof Error ? err.message : String(err)}`);
  }
  return outcome;
}

/**
 * Spec 12.1.3: a reply that names no to_delegate goes to the agent the conversation is with: the agent that sent the
 * message it answers, or, for a reply to a message of the caller's own side, the agent that message was addressed to.
 * Undefined when there is none (the message came from the person's broker, or went to the person).
 */
async function replyAddressee(c: ToolContext, owner: PrincipalRecord, caller: DelegateId, to: string, inReplyTo: string): Promise<DelegateId | undefined> {
  let address: Address;
  try {
    address = parseAddress(to);
  } catch {
    return undefined;
  }
  const mine = (m: { principal_id?: string } | null): boolean => !!m && (m.principal_id === undefined || m.principal_id === owner.principal_id);
  const received = await c.broker.store.getMessage(owner.address, "in", inReplyTo);
  const from = received?.envelope.from;
  if (mine(received) && from?.address === address && from.delegate !== undefined && from.delegate !== caller) return from.delegate;
  const sent = await c.broker.store.getMessage(owner.address, "out", inReplyTo);
  const target = sent?.envelope.to;
  if (mine(sent) && target?.address === address && target.delegate !== undefined && target.delegate !== caller) return target.delegate;
  return undefined;
}

async function sendOnce(c: ToolContext, auth: AuthContext, args: Args): Promise<ToolOutcome> {
  // tools.json takes the recipient delegate's label; the core takes the full delegate id.
  let toDelegate: string | undefined;
  if (typeof args["to_delegate"] === "string") {
    try {
      toDelegate = `${parseAddress(String(args["to"]))}/${args["to_delegate"]}`;
    } catch {
      return fail("invalid_input", "`to` is not an address like ana@example.org", { withStructured: true, advice: NEW_KEY_ADVICE });
    }
  } else if (typeof args["in_reply_to"] === "string" && isUlid(args["in_reply_to"])) {
    toDelegate = await replyAddressee(c, await principalOf(c, auth), auth.caller.delegate, String(args["to"]), args["in_reply_to"]);
  }
  // Once the envelope has left, any failure may follow a delivery: the answer then says it may have arrived, and, as
  // any answer but `internal`, stays under the idempotency key, so a retry with the same key doesn't send it again.
  let sent: string | undefined;
  let r: SendResult;
  try {
    r = await c.broker.send(auth.caller, {
      to: String(args["to"]),
      scope: String(args["scope"]),
      type: args["type"] as MessageType,
      body: args["body"] as JsonObject,
      ...(typeof args["note"] === "string" ? { note: args["note"] } : {}),
      ...(typeof args["thread"] === "string" ? { thread: args["thread"] } : {}),
      ...(typeof args["in_reply_to"] === "string" ? { in_reply_to: args["in_reply_to"] } : {}),
      ...(toDelegate ? { to_delegate: toDelegate } : {}),
      ...(typeof args["expires_in"] === "number" ? { expires_in_seconds: args["expires_in"] } : {}),
      ...(typeof args["from"] === "string" ? { from: args["from"] } : {}),
      ...(Array.isArray(args["labels"]) && args["labels"].length > 0 ? { labels: args["labels"].map(String) } : {}),
    }, { onSent: (id) => (sent = id) });
  } catch (err) {
    if (sent === undefined) throw err;
    c.log(`mcp: alp_send failed after message ${sent} was sent: ${err instanceof Error ? err.message : String(err)}`);
    return fail("unreachable", `Your broker hit an internal error after it sent message ${sent}, which may still have arrived.`, { withStructured: true });
  }
  switch (r.status) {
    case "held_for_review": {
      const scope = String(args["scope"]);
      // A message that would open a thread doesn't open it until it is sent: `thread` is only reserved for it.
      const opens = typeof args["thread"] !== "string" && typeof args["in_reply_to"] !== "string";
      const why = r.reason === "delivery_minimums"
        ? `Held for your person: their organization's rules keep ${r.withheld ? `fields labeled ${r.withheld.labels.join(", ")}` : "some of its fields"} from ${typeof args["to_delegate"] === "string" ? `your agent ${args["to_delegate"]}` : "that agent"}, and this ${scope} message isn't valid without them.`
        : r.reason === "dlp_justification"
          ? `Held for your person's review: a data-loss check asked them to approve this ${scope} message before it leaves.`
          : `Held for your person's review: their rules ask to approve ${scope} messages before they leave.`;
      const deadline = r.thread_expires_at ? ` It can go only while thread ${r.thread} is open: your person must approve it before ${r.thread_expires_at}, when the thread expires unless a later message in it extends it.` : "";
      return {
        ok: true,
        structured: { status: "held_for_review", id: r.held, thread: r.thread, decision: { outcome: r.decision.outcome, redacted: [...r.decision.redacted], policy_ids: [...r.decision.policy_ids] }, expires_at: r.expires_at },
        text: `${why} Nothing was sent yet. If they approve it on their broker's page, the broker checks it again in full before sending it${opens ? `, and thread ${r.thread} starts then` : ""}.${deadline}`,
      };
    }
    case "delivered": {
      const e = r.envelope;
      const label = (id: string): string => id.slice(id.lastIndexOf("/") + 1);
      const removed = e.decision.outcome === "redacted" ? ` Your person's rules removed ${e.decision.redacted.join(", ")} before it left.` : "";
      let text: string;
      if (e.to.address === auth.caller.principal && e.to.delegate) {
        // Between the person's own agents (spec 6.14): the receiving side is the same person's, so the sending agent may
        // be told what happened there (spec 6.8).
        const target = label(e.to.delegate);
        const arrived = await c.broker.store.getMessage(e.to.address, "in", e.id);
        text = arrived?.status === "held"
          ? `Your broker accepted it, but your agent ${target} can't receive messages now (your person's organization blocked it, or no longer lists its client), so it waits for your person on their broker's page: ${e.scope} ${e.type}, message ${e.id} in thread ${r.thread}.`
          : r.held
            ? `Delivered to your agent ${target} without ${r.held.withheld.join(", ")} (labeled ${r.held.labels.join(", ")}): your person's organization keeps those fields from that agent unless your person approves. The full message waits for them on their broker's page. Message ${e.id} in thread ${r.thread}.`
            : `Delivered to your agent ${target}: ${e.scope} ${e.type}, message ${e.id} in thread ${r.thread}.${removed}`;
      } else {
        // Across people, `delivered` means their broker accepted it (spec 12.1.3). Only this side's facts: their broker
        // never says whether it reached an agent or waits for their person (spec 6.8).
        const named = e.to.delegate ? `, addressed to their agent named ${label(e.to.delegate)}` : "";
        const constraints = e.constraints ? ` Your person's organization added delivery constraints: only an agent of theirs with ${describeMinimum(e.constraints)} may receive it.` : "";
        text = `Accepted by ${displayAddress(e.to.address)}'s broker: ${e.scope} ${e.type}${named}, message ${e.id} in thread ${r.thread}.${removed}${constraints} Their broker passes it to their agents under their rules, or holds it for them; it doesn't tell you which. Replies arrive in alp_inbox.`;
      }
      return {
        ok: true,
        structured: { status: "delivered", id: e.id, thread: r.thread, decision: { outcome: e.decision.outcome, redacted: [...e.decision.redacted], policy_ids: [...e.decision.policy_ids] }, expires_at: e.expires_at },
        text,
      };
    }
    case "rejected": {
      const first = r.reasons[0];
      const categories = r.reasons.flatMap((x) => x.categories ?? []);
      let advice: string | undefined;
      if (r.code === "not_disclosed") {
        // Which refused pointers aren't fields of the scope at all: those are to be fixed, not left out. Judged on the
        // first 64, as many as the error lists, so a draft with thousands of refused fields costs no more.
        const scope = c.broker.scopes.get(String(args["scope"]));
        const fields = r.reasons.flatMap((x) => (x.code === "not_disclosed" && x.pointer ? [x.pointer] : [])).slice(0, 64);
        const unknown = scope ? fields.filter((p) => undefinedField(scope, args["type"] as MessageType, p) !== null).length : 0;
        if (unknown > 0) advice = unknown === fields.length ? FIX_FIELD_ADVICE : MIXED_FIELD_ADVICE;
      }
      if (r.code === "type_not_allowed" && toOwnAgent(auth, args, toDelegate)) advice = OWN_TYPE_ADVICE;
      // A draft to fix: the corrected one needs a new idempotency key (a not_disclosed field to fix included).
      if (FIX_CODES.has(r.code) || advice === FIX_FIELD_ADVICE || advice === MIXED_FIELD_ADVICE) advice = [advice ?? ADVICE[r.code], NEW_KEY_ADVICE].filter(Boolean).join(" ");
      const adviceText = advice ?? ADVICE[r.code];
      return fail(r.code, refusalMessage(r.code, r.reasons, adviceText ? 999 - adviceText.length : 1000), { withStructured: true, pointers: r.reasons.map((x) => x.pointer ?? "").filter(Boolean), ...(first?.rule ? { rule: first.rule } : {}), ...(categories.length ? { categories } : {}), ...(advice ? { advice } : {}), ...(r.retry_after !== undefined ? { retryAfter: r.retry_after } : {}) });
    }
    case "refused":
      // A receipt itself carries no wait: the one the recipient's broker sent with it (HTTP Retry-After), or, for its
      // rate limit without one, the first retry interval of spec 10.2.
      if (r.code === "rate_limited") {
        const wait = r.retry_after !== undefined ? `Their broker asks to wait ${r.retry_after} second${r.retry_after === 1 ? "" : "s"}.` : `Their broker doesn't say for how long: retry after ${RECIPIENT_RETRY_SECONDS} seconds at the earliest, waiting longer each time.`;
        return fail(r.code, `The recipient's broker refused message ${r.envelope_id} (rate_limited); nothing reached their agent. ${wait}`, { withStructured: true, retryAfter: r.retry_after ?? RECIPIENT_RETRY_SECONDS });
      }
      return fail(r.code, `The recipient's broker refused message ${r.envelope_id} (${r.code}).`, { withStructured: true, ...(r.retry_after !== undefined ? { retryAfter: r.retry_after } : {}) });
    case "needs_ratification":
      return fail("needs_ratification", r.detail, { withStructured: true });
    case "undeliverable":
      // The recipient's broker refused before evaluating it (its federation inbox limit, a 429): its Retry-After, or
      // the first retry interval of spec 10.2 when it gave none.
      if (r.code === "rate_limited") return fail(r.code, `not delivered: ${r.detail}`, { withStructured: true, retryAfter: r.retry_after ?? RECIPIENT_RETRY_SECONDS });
      // unreachable: the broker signed and sent it, then got no answer within its retries; it may have arrived. So may
      // an envelope the recipient's broker answered only with `internal` (still being evaluated, or its own failure).
      if (r.code === "unreachable" || (r.code === "internal" && r.envelope_id)) return fail("unreachable", `Delivery failed (${r.detail})${r.envelope_id ? `; message ${r.envelope_id} may still have arrived` : ""}.`, { withStructured: true });
      return fail(r.code, `not delivered: ${r.detail}`, { withStructured: true });
  }
}

async function inbox(c: ToolContext, auth: AuthContext, args: Args): Promise<ToolOutcome> {
  const owner = await principalOf(c, auth);
  const limit = typeof args["limit"] === "number" ? args["limit"] : 20;
  const scope = typeof args["scope"] === "string" ? args["scope"] : undefined;
  const thread = typeof args["thread"] === "string" ? args["thread"] : undefined;
  const includeAcked = args["include_acked"] === true;
  const includeEnvelope = args["include_envelope"] === true;
  let cursor = typeof args["cursor"] === "string" && args["cursor"] !== "" ? args["cursor"] : undefined;
  if (cursor !== undefined && !isUlid(cursor)) return fail("invalid_input", "cursor is not one this broker issued");
  const items: Shaped[] = [];
  let more = false;
  // Acknowledgements count per binding (spec 5.4): one an earlier agent with this label made isn't this agent's.
  const since = (await c.broker.store.getDelegate(auth.caller.delegate))?.created_at;
  for (let round = 0; round < 50 && !more; round++) {
    const page = await c.broker.inbox(auth.caller, { ...(cursor ? { cursor } : {}), limit: 50, include_acked: includeAcked });
    // A page of only records this agent may not see still moves the cursor on.
    if (page.items.length === 0 && page.has_more && page.next_cursor) cursor = page.next_cursor;
    for (let i = 0; i < page.items.length; i++) {
      const it = page.items[i];
      if (!it) continue;
      if (items.length >= limit) {
        more = true;
        break;
      }
      cursor = it.local_id;
      if (it.status === "held") continue;
      if (scope && it.verified.scope !== scope) continue;
      if (thread && it.verified.thread !== thread) continue;
      const rec = await c.broker.store.getMessage(owner.address, "in", it.envelope.id);
      items.push(await shapeInbound(c, owner, it.envelope, it.received_at, { includeEnvelope, acked: rec ? ackedBy(rec, auth.caller.delegate, since) : false }));
    }
    if (!page.has_more) break;
    if (items.length >= limit) more = true;
  }
  const structured: JsonRecord = { items: items.map((x) => x.item), next_cursor: cursor ?? "", more, ...(items.length === 0 && !more ? { poll_after_seconds: 60 } : {}) };
  const text = items.length
    ? `${items.length} message${items.length === 1 ? "" : "s"}${more ? " (more waiting: call again with next_cursor)" : ""}.\n\n${items.map((x) => x.text).join("\n\n")}\n\n${UNTRUSTED_FOOTER}\nBefore you reply, read the whole thread with alp_thread: it shows the conversation and what you may send next. Answer, ask a follow-up or add an update with alp_send in the same thread (thread = the item's thread, in_reply_to = the message you answer: the reply goes to the agent that sent it; to keep a follow-up with that agent too, set to_delegate to its name, as the verified sender line shows it). Mark handled with alp_ack, which sends nothing; to close a finished conversation, alp_send an ack with status completed in reply to a message of the thread.`
    : "No new messages.";
  return { ok: true, structured, text };
}

/**
 * The types this delegate may send next (advisory; the core decides, spec 9.2, 9.3, 9.4, 12.1.4), from the whole thread
 * whatever page alp_thread shows: replies the scope allows to the latest message from the other side that this agent
 * may read (not an ack; the broker's own ratification acks are outbound, so never count); an accept or a counter only
 * while the latest proposal is the other side's and this agent may read it; follow-ups (types sent without naming a
 * message); all limited to what the thread's state accepts and the person's terms allow (ack, decline and error need
 * no `may`, spec 6.6). `commit` once both people's ratification records are held and unexpired. In a scope whose
 * committer is the proposer (`alp.document_request/1`), only the side whose proposal was accepted (the thread records
 * `proposer` as `me`) is offered it: the core refuses any other commit there, a thread that records no proposer
 * included. A relationship set up through a connection request reaches commit too, since its default terms list it.
 * A thread that holds MAX_THREAD_MESSAGES takes only a message that ends it (spec 9.2): a decline, or an ack (with
 * status completed) outside `agreed`.
 */
function nextTypes(scope: CompiledScope, thread: ThreadRecord, msgs: readonly { id: string; type: MessageType; direction: "in" | "out" }[], may: Set<MessageType>, now: Date): MessageType[] {
  if (TERMINAL_STATES.includes(thread.state)) return [];
  const accepted = new Set(acceptedTypes(scope, thread.state));
  const last = [...msgs].reverse().find((m) => m.direction === "in" && m.type !== "ack");
  const out = new Set<MessageType>(last ? (scope.def.replies[last.type] ?? []) : []);
  out.delete("accept");
  out.delete("counter");
  const proposal = latestProposal(thread);
  if (proposal && proposal.direction === "in" && msgs.some((m) => m.id === proposal.envelope_id)) for (const t of scope.def.replies[proposal.type] ?? []) out.add(t);
  for (const t of accepted) if (mayFollowUp(scope, t)) out.add(t);
  const live = (r: { expires_at: string } | undefined): boolean => r !== undefined && Date.parse(r.expires_at) > now.getTime();
  const ratified = thread.state === "agreed" && live(thread.ratifications?.mine?.record) && live(thread.ratifications?.theirs?.record);
  // As applyToThread checks an outbound commit (core/threads.ts): where the proposer commits, only if this side proposed.
  const mayCommit = scope.def.committer !== "proposer" || thread.proposer === "me";
  if (ratified && mayCommit) out.add("commit");
  else out.delete("commit");
  const full = messageCount(thread) >= MAX_THREAD_MESSAGES;
  const ends = (t: MessageType): boolean => t === "decline" || (t === "ack" && thread.state !== "agreed");
  return typeOrder([...out].filter((t) => accepted.has(t) && scope.types.has(t) && (may.has(t) || PLUMBING.includes(t)) && (!full || ends(t)))).slice(0, 10);
}

/** What ends a thread in each state that isn't terminal (spec 9.2), as alp_thread's text names it. */
const THREAD_ENDS: Partial<Record<ThreadRecord["state"], string>> = {
  open: "an ack with status completed, or a decline of its first message",
  negotiating: "an ack with status completed, or a decline of its first message or of the proposal",
  agreed: "a decline that cancels the agreed terms",
  committed: "an ack with status completed",
};

/** How a thread ends, as alp_thread's text says it (spec 9.2). */
function threadLife(t: ThreadRecord): string {
  if (TERMINAL_STATES.includes(t.state)) return `The thread has ended (${t.state}): anything more needs a new thread.`;
  const ends = THREAD_ENDS[t.state] ?? "a message that ends it";
  if (messageCount(t) >= MAX_THREAD_MESSAGES) return `It holds ${MAX_THREAD_MESSAGES} messages, the most a thread takes: only a message that ends it goes now (${ends}); continue in a new thread.`;
  if (t.state === "committed") return `It stays open for reports of what happened until either side closes it (${ends}).`;
  if (t.state === "agreed") return `The agreed terms end with a commit, or a decline that cancels them; otherwise the thread expires at ${t.expires_at}.`;
  if (t.state === "negotiating") return `Unless a new proposal or an accept extends it, or either side closes it first (${ends}), it expires at ${t.expires_at}.`;
  return `Unless a later message extends it, or either side closes it first (${ends}), it expires at ${t.expires_at}.`;
}

const labelOf = (id: string): string => id.slice(id.lastIndexOf("/") + 1);

async function threadTool(c: ToolContext, auth: AuthContext, args: Args): Promise<ToolOutcome> {
  const owner = await principalOf(c, auth);
  // The core returns only what this agent may see (spec 12.1.4): its own sent messages, what the broker sent for its
  // person, and received messages addressed to it or its person that meet their delivery constraints and aren't held.
  let view: Awaited<ReturnType<Broker["thread"]>>;
  try {
    view = await c.broker.thread(auth.caller, String(args["thread"]));
  } catch (err) {
    if (isAlpError(err) && err.code === "thread_state") return fail("thread_state", err.message, { withStructured: hasErrorMember(c, `${PROTOCOL.toolPrefix}thread`), advice: THREAD_ID_ADVICE });
    throw err;
  }
  const t = view.thread;
  const includeEnvelope = args["include_envelope"] === true;
  const limit = typeof args["limit"] === "number" ? args["limit"] : 50;
  const scope = c.broker.scopes.get(t.scope);
  // The page: the latest `limit` messages this agent may read, ending before `before` when it is given.
  let end = view.messages.length;
  if (typeof args["before"] === "string") {
    const before = args["before"];
    end = view.messages.findIndex((m) => m.envelope.id === before);
    if (end < 0) return fail("invalid_input", "before names no message of this thread that you may read");
  }
  const start = Math.max(0, end - limit);
  const messages: JsonRecord[] = [];
  const texts: string[] = [];
  for (const m of view.messages.slice(start, end)) {
    const e = m.envelope;
    const mine = m.direction === "out" && e.from.delegate === auth.caller.delegate;
    const byBroker = m.direction === "out" && e.from.delegate === undefined;
    if (mine || byBroker) {
      // The caller's own words, or the broker's for its person: never anyone else's, so never inside the wrapper.
      messages.push({ id: e.id, direction: "outbound", type: e.type, at: e.created_at, status: "delivered", content: { kind: mine ? "sent_by_you" : "sent_by_your_broker", body: e.body as JsonValue, ...(e.note !== undefined ? { note: e.note } : {}) }, ...(includeEnvelope ? { envelope: JSON.parse(JSON.stringify(e)) as JsonRecord } : {}) });
      texts.push(`${mine ? "You sent" : "Your broker sent, for your person,"} ${e.type} ${e.id} at ${e.created_at}${mine && e.to.delegate ? ` to ${e.to.address === owner.address ? "your agent" : "their agent"} ${labelOf(e.to.delegate)}` : ""}: ${blockJson(e.body).slice(0, 2000)}`);
      continue;
    }
    // Anyone else's words, another of this person's own agents included (spec 6.14): sanitized, inside the wrapper,
    // and attributed to the sending agent the broker verified.
    const shaped = await shapeInbound(c, owner, e, e.created_at, { includeEnvelope: false, acked: false });
    const it = shaped.item;
    messages.push({ id: e.id, direction: "inbound", type: e.type, at: e.created_at, status: "delivered", verified: it["verified"] ?? {}, content: it["content"] ?? {}, ...(includeEnvelope ? { envelope: JSON.parse(JSON.stringify(e)) as JsonRecord } : {}) });
    texts.push(shaped.text);
  }
  let may = new Set<MessageType>();
  if (scope) {
    const policy = policyFor(c, owner.address);
    const tr = effectiveTerms({ owner: owner.address, counterparty: t.counterparty, scope: t.scope, direction: "outbound", grant: await c.broker.grantOf(owner, t.counterparty), revocation: await c.broker.store.getRevocation(owner.address, t.counterparty), policy, claimsOf: await c.broker.claimsWith(owner, t.counterparty), now: c.now() });
    if (tr.ok) may = new Set(tr.terms.may);
  }
  // The whole thread, whatever the page: what may come next, and which of the other side's agents wrote in it.
  const all = view.messages.map((m) => ({ id: m.envelope.id, type: m.envelope.type, direction: m.direction }));
  const next = scope ? nextTypes(scope, t, all, may, c.now()) : [];
  const writers = view.messages.flatMap((m) => (m.direction === "in" && m.envelope.from.delegate !== undefined && m.envelope.from.delegate !== auth.caller.delegate ? [labelOf(m.envelope.from.delegate)] : []));
  // Newest first: the first is the agent this one is talking with.
  const agents = [...new Set(writers.reverse())].slice(0, 32);
  const own = t.counterparty === owner.address;
  const structured: JsonRecord = {
    thread: t.id,
    scope: t.scope,
    counterparty: { address: t.counterparty, display: displayAddress(t.counterparty), ...(agents.length ? { agents } : {}) },
    state: t.state,
    messages,
    earlier: start,
    ...(t.terms_hash
      ? { ratification: { terms_hash: t.terms_hash, mine: t.ratifications?.mine ? "ratified" : t.state === "cancelled" ? "declined" : "pending", theirs: t.ratifications?.theirs ? "ratified" : t.state === "cancelled" ? "declined" : "pending" } }
      : {}),
    next_types: next,
  };
  const who = own ? `your person's own agents${agents.length ? ` (${agents.join(", ")})` : ""}` : `${displayAddress(t.counterparty)}${agents.length ? ` (their agent${agents.length > 1 ? "s" : ""} ${agents.join(", ")})` : ""}`;
  const shown = start > 0 || end < view.messages.length
    ? ` Showing ${end - start} of the ${view.messages.length} messages you may read${start > 0 ? `; for the ${start} before them, call alp_thread with before ${view.messages[start]?.envelope.id ?? ""}` : ""}${end < view.messages.length ? `; ${view.messages.length - end} later ones are left out` : ""}.`
    : "";
  const talkingTo = agents[0];
  // A full thread takes only replies that end it: no follow-up is offered then.
  const followUp = scope !== undefined && next.some((x) => mayFollowUp(scope, x));
  const toSend = next.length
    ? ` You may send next: ${next.join(", ")}. Send in this thread: alp_send with to ${own ? "your person's own address" : displayAddress(t.counterparty)}, thread ${t.id} and in_reply_to the message you answer (the reply goes to the agent that sent it)${followUp ? `, or no in_reply_to to follow up${talkingTo ? `, with to_delegate ${talkingTo} to keep to the agent you are talking with` : own ? ", with to_delegate the agent you write to" : ""}` : ""}.`
    : TERMINAL_STATES.includes(t.state) ? "" : " Nothing for you to send now.";
  const text = [
    `Thread ${t.id} with ${who}, scope ${t.scope}, state ${t.state}.${shown}${toSend} ${threadLife(t)}`,
    ...texts,
    texts.some((x) => x.includes("Verified by your broker")) ? UNTRUSTED_FOOTER : "",
  ].filter(Boolean).join("\n\n");
  return { ok: true, structured, text };
}

async function ack(c: ToolContext, auth: AuthContext, args: Args): Promise<ToolOutcome> {
  const owner = await principalOf(c, auth);
  const ids = Array.isArray(args["ids"]) ? args["ids"].filter((x): x is string => typeof x === "string") : [];
  // Only messages this agent may read (the core's rule: addressed to it or its person, not held, constraints met).
  const visible = new Set(await c.broker.visibleInbound(auth.caller, ids));
  const known = ids.filter((id) => visible.has(id));
  const unknown = ids.filter((id) => !visible.has(id));
  if (known.length) await c.broker.ack(auth.caller, { envelope_ids: known });
  return { ok: true, structured: { acked: known, unknown }, text: `Marked ${known.length} handled.${unknown.length ? ` Unknown ids: ${unknown.join(", ")}.` : ""} Nothing was sent.` };
}

const LINKY = /(?:[a-z][a-z0-9+.-]*:\/\/|www\.)/i;

async function requestConnection(c: ToolContext, auth: AuthContext, args: Args): Promise<ToolOutcome> {
  const owner = await principalOf(c, auth);
  await c.broker.whoami(auth.caller);
  let to: Address;
  try {
    to = parseAddress(String(args["to"]));
  } catch {
    return fail("invalid_input", "`to` is not an address like ana@example.org", { withStructured: true });
  }
  if (to === owner.address) return fail("invalid_input", "you can't connect to your own person", { withStructured: true });
  const scopes = Array.isArray(args["scopes"]) ? [...new Set(args["scopes"].filter((s): s is string => typeof s === "string"))] : [];
  for (const s of scopes) if (!c.broker.scopes.get(s)) return fail("unknown_scope", `unknown scope ${s}`, { withStructured: true });
  const note = typeof args["note"] === "string" ? args["note"] : undefined;
  if (note !== undefined && LINKY.test(note)) return fail("invalid_input", "the note must not contain links", { withStructured: true, pointers: ["/note"] });
  const now = c.now();
  const existing = (await contactViews(c, owner, now)).find((x) => x.address === to && x.status === "active");
  if (existing && scopes.every((s) => existing.scopes.some((v) => v.scope === s))) {
    return { ok: true, structured: { status: "already_connected" }, text: `Your person is already connected with ${displayAddress(to)} for ${scopes.join(", ")}. Use alp_send.` };
  }
  const filed = await filePending(c.state, {
    principal_id: owner.principal_id,
    principal: owner.address,
    delegate: auth.caller.delegate,
    client_id: auth.caller.client_id,
    to,
    scopes,
    purpose: String(args["purpose"]),
    ...(note !== undefined ? { note } : {}),
  }, now);
  if (filed.kind === "rate_limited") return fail("rate_limited", `your person already has 5 connection requests from today waiting; retry after ${filed.retryAfter} seconds`, { withStructured: true, retryAfter: filed.retryAfter, advice: "Wait at least retry_after seconds before asking again." });
  if (filed.kind === "filed") {
    const email = owner.contact?.email;
    if (email) {
      try {
        await c.notifier.notify({
          principal: owner.address,
          kind: "connection_request",
          channel: "email",
          to: email,
          subject: `Your agent asked to connect with ${displayAddress(to)}`,
          text: `Your agent (${auth.caller.delegate.slice(auth.caller.delegate.lastIndexOf("/") + 1)}) asked to connect with ${displayAddress(to)} for ${scopes.join(", ")}. Nothing has been sent. Review it on your broker page; this message can't approve anything.`,
          link: c.broker.links.connection(filed.request.id),
          at: now.toISOString(),
        });
      } catch {
        // the web view shows it either way
      }
    }
  }
  return {
    ok: true,
    structured: { status: "pending_principal", request_id: filed.request.id },
    text: `Held for your person: nothing is sent until they approve it on their broker page. Then it goes to ${displayAddress(to)} (the person, not their agent), who decides. Request ${filed.request.id}.`,
  };
}

const HANDLERS: Record<string, (c: ToolContext, auth: AuthContext, args: Args) => Promise<ToolOutcome>> = {
  [`${PROTOCOL.toolPrefix}whoami`]: whoami,
  [`${PROTOCOL.toolPrefix}contacts`]: contacts,
  [`${PROTOCOL.toolPrefix}send`]: send,
  [`${PROTOCOL.toolPrefix}inbox`]: inbox,
  [`${PROTOCOL.toolPrefix}thread`]: threadTool,
  [`${PROTOCOL.toolPrefix}ack`]: ack,
  [`${PROTOCOL.toolPrefix}request_connection`]: requestConnection,
};

/** Tools whose output schema has an `error` member (refusals carry structured content there). */
function hasErrorMember(c: ToolContext, name: string): boolean {
  const props = (c.catalog.byName.get(name)?.def.outputSchema["properties"] ?? {}) as Record<string, unknown>;
  return "error" in props;
}

export async function runTool(c: ToolContext, auth: AuthContext, name: string, rawArgs: unknown): Promise<ToolOutcome> {
  const handler = HANDLERS[name];
  if (!handler) return fail("invalid_input", `unknown tool ${name}`);
  const withStructured = hasErrorMember(c, name);
  const args = rawArgs ?? {};
  const errs = c.catalog.validateInput(name, args);
  if (errs.length) {
    return fail("invalid_input", `The arguments don't match the tool's schema: ${joinWithin(errs.map((e) => `${e.pointer || "/"} ${e.message}`), 900, "; ")}.`, { withStructured });
  }
  if (!auth.scopes.includes(c.catalog.scopeFor(name))) {
    const needed = c.catalog.scopeFor(name);
    return fail("identity_mismatch", `This token lacks the ${needed} scope.`, { withStructured, status: 403, advice: `Create a personal access token with ${needed} on your person's broker page, or connect the agent again asking for ${needed}.` });
  }
  try {
    // The whole tool call is one answer (spec 6.7): what the broker does after accepting a message to another of its
    // people (the notice, the pushes) waits until this call has returned, its idempotency record included.
    return await c.broker.asOneAnswer(() => handler(c, auth, args as Args));
  } catch (err) {
    if (!isAlpError(err)) c.log(`mcp: ${name} failed: ${err instanceof Error ? err.message : String(err)}`);
    return fromThrown(err, withStructured);
  }
}
