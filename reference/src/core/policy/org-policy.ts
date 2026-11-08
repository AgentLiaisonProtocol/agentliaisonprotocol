// SPDX-License-Identifier: FSL-1.1-ALv2
// Org policy: PRIVATE local configuration of the organization's own brokers (spec 6.4). Never published.

import { domainOf } from "../address.ts";
import { AlpError } from "../errors.ts";
import { assertValid } from "../spec-schemas.ts";
import { ATTESTATIONS, CLASSES } from "../types.ts";
import type {
  Address,
  Attestation,
  BrokerId,
  ClientRule,
  Constraints,
  DefaultDirectionTerms,
  DefaultRelationship,
  DefaultScopeTerms,
  DelegateClass,
  DelegateId,
  DeliveryMinimum,
  MessageType,
  OrgPolicy,
  PrincipalRef,
  ScopeId,
} from "../types.ts";

export function checkOrgPolicy(value: unknown): OrgPolicy {
  return assertValid<OrgPolicy>("orgPolicy", value, "invalid_input");
}

/** The policy as `decision.policy_ids` names it (spec 8.2): `<domain>#<serial>`, the organization's first domain. */
export function policyRef(p: OrgPolicy): string {
  return `${p.domains[0] ?? p.id}#${p.serial}`;
}

/** Group claims of local principals (from their IdP); counterparties from elsewhere have none. */
export type ClaimsOf = (address: Address) => { issuer: string; name: string; value: string }[];

export function inGroup(policy: OrgPolicy, group: string, who: Address, claimsOf?: ClaimsOf, depth = 0): boolean {
  const g = policy.groups?.[group];
  if (!g || depth > 4) return false;
  if ("members" in g) return g.members.some((m) => refMatches(policy, m, who, claimsOf, depth + 1));
  return (claimsOf?.(who) ?? []).some((c) => c.issuer === g.claim.issuer && c.name === g.claim.name && c.value === g.claim.value);
}

/** An exact address, `alp:*@domain`, `group:<name>`, `@org` (any of the policy's domains) or `*`. */
export function refMatches(policy: OrgPolicy, ref: PrincipalRef, who: Address, claimsOf?: ClaimsOf, depth = 0): boolean {
  if (ref === "*") return true;
  if (ref === "@org") return policy.domains.includes(domainOf(who));
  if (ref.startsWith("group:")) return inGroup(policy, ref.slice(6), who, claimsOf, depth);
  const at = ref.lastIndexOf("@");
  if (at > 0 && ref.slice(0, at).endsWith(":*")) return domainOf(who) === ref.slice(at + 1);
  return ref === who;
}

export function anyRefMatches(policy: OrgPolicy, refs: readonly PrincipalRef[], who: Address, claimsOf?: ClaimsOf): boolean {
  return refs.some((r) => refMatches(policy, r, who, claimsOf));
}

/** `confidential.financial` (exact), `restricted.*` (`restricted` and every label below it, spec 6.5), or `*`. */
export function labelMatches(pattern: string, label: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return label === prefix || label.startsWith(`${prefix}.`);
  }
  return pattern === label;
}

/** `*.example.com` matches any subdomain of example.com; otherwise exact. */
export function domainPatternMatches(pattern: string, domain: string): boolean {
  if (pattern.startsWith("*.")) return domain.endsWith(pattern.slice(1));
  return pattern === domain;
}

/** Whether the org lets messages cross to/from the counterparty's domain at all. */
export function federationAllows(policy: OrgPolicy | null, counterpartyDomain: string): boolean {
  if (!policy?.federation || policy.domains.includes(counterpartyDomain)) return true;
  const listed = policy.federation.domains.some((p) => domainPatternMatches(p, counterpartyDomain));
  return policy.federation.mode === "allow" ? listed : !listed;
}

export function connectionRequestsAllowed(policy: OrgPolicy | null, fromDomain: string): boolean {
  const cr = policy?.connection_requests;
  if (!cr || policy?.domains.includes(fromDomain)) return true;
  if (cr.inbound === "deny") return false;
  if (cr.inbound === "allow_listed") return (cr.allow_domains ?? []).some((p) => domainPatternMatches(p, fromDomain));
  return true;
}

export interface KillCheck {
  principals?: Address[];
  delegate?: DelegateId;
  client_id?: string;
  scope?: ScopeId;
  domains?: string[];
  broker?: BrokerId;
}

/** Kill switches (`blocked`): the first matching entry, or null. */
export function blockedBy(policy: OrgPolicy | null, c: KillCheck): string | null {
  const b = policy?.blocked;
  if (!b) return null;
  for (const p of c.principals ?? []) if (b.principals?.includes(p)) return `blocked:principal`;
  if (c.delegate && b.delegates?.includes(c.delegate)) return "blocked:delegate";
  if (c.client_id && b.client_ids?.includes(c.client_id)) return "blocked:client";
  if (c.scope && b.scopes?.includes(c.scope)) return "blocked:scope";
  for (const d of c.domains ?? []) if (b.domains?.some((p) => domainPatternMatches(p, d))) return "blocked:domain";
  if (c.broker && b.brokers?.includes(c.broker)) return "blocked:broker";
  return null;
}

export function clientRule(policy: OrgPolicy | null, clientId: string): ClientRule | undefined {
  return policy?.clients?.allowed.find((c) => c.client_id === clientId);
}

export interface DefaultMatch {
  rel: DefaultRelationship;
  terms: DefaultScopeTerms;
  direction: DefaultDirectionTerms;
}

/** The default relationship terms for a message from `sender` to `recipient` in `scope` (forward and reverse united). */
export function findDefault(policy: OrgPolicy, sender: Address, recipient: Address, scope: ScopeId, claimsOf?: ClaimsOf): DefaultMatch | null {
  for (const rel of policy.default_relationships ?? []) {
    const terms = rel.scopes[scope];
    if (!terms) continue;
    const forward = anyRefMatches(policy, rel.from, sender, claimsOf) && anyRefMatches(policy, rel.to, recipient, claimsOf);
    const reverse = terms.reverse !== undefined && anyRefMatches(policy, rel.to, sender, claimsOf) && anyRefMatches(policy, rel.from, recipient, claimsOf);
    if (!forward && !reverse) continue;
    const parts = [...(forward ? [terms.forward] : []), ...(reverse && terms.reverse ? [terms.reverse] : [])];
    const may = [...new Set(parts.flatMap((p) => p.may))] as MessageType[];
    const fields = [...new Set(parts.flatMap((p) => p.fields))];
    return { rel, terms, direction: { may, fields } };
  }
  return null;
}

export function hasAnyDefault(policy: OrgPolicy | null, a: Address, b: Address, claimsOf?: ClaimsOf): boolean {
  if (!policy) return false;
  return (policy.default_relationships ?? []).some(
    (rel) =>
      (anyRefMatches(policy, rel.from, a, claimsOf) && anyRefMatches(policy, rel.to, b, claimsOf)) ||
      (anyRefMatches(policy, rel.to, a, claimsOf) && anyRefMatches(policy, rel.from, b, claimsOf)),
  );
}

export function defaultRef(rel: DefaultRelationship): string {
  return `default:${rel.id}`;
}

export function attestationRank(a: Attestation): number {
  return ATTESTATIONS.indexOf(a);
}
export function classRank(c: DelegateClass): number {
  return CLASSES.indexOf(c);
}
/** The lower of two attestations. */
export function lowerAttestation(a: Attestation, b: Attestation): Attestation {
  return attestationRank(a) <= attestationRank(b) ? a : b;
}
/** The lower of two classes. */
export function lowerClass(a: DelegateClass, b: DelegateClass): DelegateClass {
  return classRank(a) <= classRank(b) ? a : b;
}

/** Delivery constraints the org requires for these labels (the strictest of every matching minimum). */
export function deliveryConstraints(policy: OrgPolicy | null, labels: readonly string[], base: Constraints = {}): Constraints | undefined {
  const out: Constraints = structuredClone(base);
  for (const m of policy?.delivery_minimums ?? []) {
    if (!labels.some((l) => m.labels.some((p) => labelMatches(p, l)))) continue;
    const dt = { ...(out.deliver_to ?? {}) };
    if (m.min_attestation && (!dt.min_attestation || attestationRank(m.min_attestation) > attestationRank(dt.min_attestation))) dt.min_attestation = m.min_attestation;
    if (m.min_class && (!dt.min_class || classRank(m.min_class) > classRank(dt.min_class))) dt.min_class = m.min_class;
    if (dt.min_attestation || dt.min_class) out.deliver_to = dt;
    if (m.no_training) out.no_training = true;
    if (m.retention_max !== undefined) out.retention_max = Math.min(out.retention_max ?? m.retention_max, m.retention_max);
  }
  return Object.keys(out).length ? out : undefined;
}

/**
 * Does a delegate meet the envelope's delivery constraints (spec 6.11)? `client` is what the organization recorded
 * for the delegate's client (its `clients` rule): whether it excludes training, and how long it keeps content.
 */
export function meetsConstraints(c: Constraints | undefined, d: { attestation: Attestation; class: DelegateClass }, client: boolean | { no_training?: boolean; retention_days?: number } | undefined): boolean {
  if (!c) return true;
  const rec = typeof client === "boolean" ? { no_training: client } : client ?? {};
  if (c.deliver_to?.min_attestation && attestationRank(d.attestation) < attestationRank(c.deliver_to.min_attestation)) return false;
  if (c.deliver_to?.min_class && classRank(d.class) < classRank(c.deliver_to.min_class)) return false;
  if (c.no_training && rec.no_training !== true) return false;
  if (c.retention_max !== undefined && (rec.retention_days === undefined || rec.retention_days > c.retention_max)) return false;
  return true;
}

/** The envelope-style constraints one delivery minimum stands for. */
export function minimumConstraints(m: DeliveryMinimum): Constraints {
  const deliver_to = { ...(m.min_attestation ? { min_attestation: m.min_attestation } : {}), ...(m.min_class ? { min_class: m.min_class } : {}) };
  return { ...(Object.keys(deliver_to).length ? { deliver_to } : {}), ...(m.no_training ? { no_training: true as const } : {}), ...(m.retention_max !== undefined ? { retention_max: m.retention_max } : {}) };
}

/** A minimum in words, for the person's page and the agent's text: "enterprise class, org-client attestation or higher". */
export function describeMinimum(c: Constraints): string {
  const parts = [
    ...(c.deliver_to?.min_class ? [`${c.deliver_to.min_class} class or higher`] : []),
    ...(c.deliver_to?.min_attestation ? [`${c.deliver_to.min_attestation} attestation or higher`] : []),
    ...(c.no_training ? ["no training on content"] : []),
    ...(c.retention_max !== undefined ? [`retention of at most ${c.retention_max} days`] : []),
  ];
  return parts.join(", ") || "no minimum";
}

export interface OwnAgentField {
  /** Envelope-relative pointer of a field that would cross. */
  pointer: string;
  /** Its labels, the message-wide ones included. */
  labels: string[];
}

export interface OwnAgentCheck {
  /** Fields whose minimum says `block`: the message is refused. */
  blocked: (OwnAgentField & { needs: string })[];
  /** Fields whose minimum says `hold` (the default): the person approves them on the web view. */
  held: (OwnAgentField & { needs: string })[];
}

/**
 * Between one person's own agents (spec 6.14), the organization's delivery minimums apply per field and per receiving
 * agent: a field crosses only if the agent meets every minimum whose labels match the field's labels; otherwise the
 * minimum's `otherwise` decides. Only the labels that matched are reported, never values.
 */
export function checkOwnAgentDelivery(policy: OrgPolicy | null, fields: readonly OwnAgentField[], agent: { attestation: Attestation; class: DelegateClass }, client: ClientRule | undefined): OwnAgentCheck {
  const blocked = new Map<string, OwnAgentField & { needs: string }>();
  const held = new Map<string, OwnAgentField & { needs: string }>();
  for (const m of policy?.delivery_minimums ?? []) {
    const c = minimumConstraints(m);
    if (meetsConstraints(c, agent, client)) continue;
    for (const f of fields) {
      const hit = f.labels.filter((l) => m.labels.some((p) => labelMatches(p, l)));
      if (hit.length === 0) continue;
      const into = m.otherwise === "block" ? blocked : held;
      const prev = into.get(f.pointer);
      into.set(f.pointer, { pointer: f.pointer, labels: [...new Set([...(prev?.labels ?? []), ...hit])].sort(), needs: prev ? `${prev.needs}; ${describeMinimum(c)}` : describeMinimum(c) });
    }
  }
  for (const p of blocked.keys()) held.delete(p);
  return { blocked: [...blocked.values()], held: [...held.values()] };
}

/** Policies are replaced only by a higher serial. */
export function checkPolicyUpdate(current: OrgPolicy | undefined, next: OrgPolicy): void {
  if (current && next.serial <= current.serial) throw new AlpError("invalid_input", "a policy update needs a higher serial");
}
