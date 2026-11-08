// SPDX-License-Identifier: FSL-1.1-ALv2
// Agent Liaison Protocol v0.1 — protocol and record types.
// They mirror the spec's JSON Schemas in <repo>/schemas (validated at runtime by spec-schemas.ts).
// The spec defines each one (aud, principal_id, attestation, constraints, private org policy, pinned keys, signed
// ratification records, envelope-relative pointers).

import { ALP_VERSION } from "./protocol.ts";

export { ALP_VERSION };
export type AlpVersion = typeof ALP_VERSION;

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };

/** A principal address in protocol form: `alp:ana@example.org` (shown to people as `ana@example.org`). A changeable alias. */
export type Address = string;
/** Immutable, never-reused id issued by the home broker and bound to the IdP's iss + sub. */
export type PrincipalId = string;
/** A delegate id: the principal's address plus a label, `alp:ana@example.org/muse`. */
export type DelegateId = string;
/** `alp.briefing/1`, or an organization scope `org.example.org.incident/1`. */
export type ScopeId = string;
/** A broker's HTTPS origin, `https://broker.example.org`. */
export type BrokerId = string;
/** RFC 3339 UTC with Z and at most millisecond precision. */
export type Timestamp = string;
/** `sha256:<base64url>` */
export type Sha256 = string;

export const MESSAGE_TYPES = [
  "request",
  "propose",
  "counter",
  "accept",
  "decline",
  "inform",
  "ask_human",
  "commit",
  "ack",
  "error",
] as const;
export type MessageType = (typeof MESSAGE_TYPES)[number];

/** Message types whose bodies the protocol defines (the same in every scope). */
export const COMMON_TYPES = ["ack", "decline", "error", "ask_human"] as const;
export type CommonType = (typeof COMMON_TYPES)[number];

/** Federation control messages: they reach people and brokers, never agents. */
export const CONTROL_TYPES = ["connection_request", "connection_response", "revoke"] as const;
export type ControlType = (typeof CONTROL_TYPES)[number];

export function isMessageType(v: unknown): v is MessageType {
  return typeof v === "string" && (MESSAGE_TYPES as readonly string[]).includes(v);
}
export function isCommonType(v: unknown): v is CommonType {
  return typeof v === "string" && (COMMON_TYPES as readonly string[]).includes(v);
}
export function isControlType(v: unknown): v is ControlType {
  return typeof v === "string" && (CONTROL_TYPES as readonly string[]).includes(v);
}

/** Ordered self < vendor < native < org-client < tenant (spec 5.4). */
export const ATTESTATIONS = ["self", "vendor", "native", "org-client", "tenant"] as const;
export type Attestation = (typeof ATTESTATIONS)[number];
/** Ordered consumer < business < enterprise. */
export const CLASSES = ["consumer", "business", "enterprise"] as const;
export type DelegateClass = (typeof CLASSES)[number];

/** Error codes the spec defines (receipts, ledger entries, error bodies, security events). */
export const ERROR_CODES = [
  "invalid_input",
  "identity_mismatch",
  "unknown_scope",
  "unknown_type",
  "schema_invalid",
  "body_too_large",
  "no_relationship",
  "type_not_allowed",
  "not_disclosed",
  "org_policy",
  "federation_blocked",
  "client_not_allowed",
  "blocked",
  "dlp_blocked",
  "rate_limited",
  "thread_state",
  "needs_ratification",
  "unknown_recipient",
  "discovery_failed",
  "unreachable",
  "expired",
  "bad_envelope",
  "unsupported_version",
  "bad_signature",
  "wrong_audience",
  "replay",
  "broker_not_authorized",
  "not_accepted",
  "constraints_unsupported",
  "internal",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

// ---------------------------------------------------------------------------------------------
// Envelopes

export interface Sender {
  address: Address;
  principal_id: PrincipalId;
  /** Absent when the broker itself sends for the principal (ratification acks, revocations). */
  delegate?: DelegateId;
  attestation?: Attestation;
  class?: DelegateClass;
}

export interface Recipient {
  address: Address;
  principal_id?: PrincipalId;
  delegate?: DelegateId;
}

export interface Decision {
  outcome: "allowed" | "redacted";
  /** Envelope-relative pointers removed by the sender's broker (non-empty exactly when outcome is redacted). */
  redacted: string[];
  /** Grant or default relationship ids, org rule ids and DLP verdict ids that applied. */
  policy_ids: string[];
}

export interface Constraints {
  deliver_to?: { min_attestation?: Attestation; min_class?: DelegateClass };
  no_training?: true;
  /** Days. */
  retention_max?: number;
}

/** typ alp-envelope+jws */
export interface UnsignedEnvelope {
  alp: AlpVersion;
  id: string;
  thread: string;
  in_reply_to?: string;
  in_reply_to_hash?: Sha256;
  from: Sender;
  to: Recipient;
  /** The recipient's home broker. */
  aud: BrokerId;
  scope: ScopeId;
  type: MessageType;
  body: JsonObject;
  note?: string;
  /** SHA-256 of the JCS form of body.terms; required on accept and commit. */
  terms_hash?: Sha256;
  /** On commit: the hashes of both principals' ratification records. */
  ratifications?: [Sha256, Sha256];
  grant: string;
  labels: string[];
  constraints?: Constraints;
  created_at: Timestamp;
  expires_at: Timestamp;
  origin_broker: BrokerId;
  decision: Decision;
}
export interface Envelope extends UnsignedEnvelope {
  broker_sig: string;
}

/** typ alp-control+jws */
export interface UnsignedControlEnvelope {
  alp: AlpVersion;
  id: string;
  thread: string;
  in_reply_to?: string;
  in_reply_to_hash?: Sha256;
  from: Sender;
  to: { address: Address; principal_id?: PrincipalId };
  aud: BrokerId;
  type: ControlType;
  body: JsonObject;
  /** connection_request only, at most 140 characters. */
  note?: string;
  created_at: Timestamp;
  expires_at: Timestamp;
  origin_broker: BrokerId;
}
export interface ControlEnvelope extends UnsignedControlEnvelope {
  broker_sig: string;
}

export type AnyEnvelope = Envelope | ControlEnvelope;

export function isControlEnvelope(e: AnyEnvelope): e is ControlEnvelope {
  return isControlType(e.type);
}

/** typ alp-receipt+jws: signed by the receiving broker, addressed (aud) to the sending broker. */
export interface UnsignedReceipt {
  alp: AlpVersion;
  id: string;
  envelope_id: string;
  envelope_hash: Sha256;
  status: "accepted" | "refused";
  /** Only when refused. Names no rule of the recipient's. */
  code?: ErrorCode;
  /** Only when accepted: the recipient's ledger entry hash. */
  ledger_hash?: Sha256;
  created_at: Timestamp;
  expires_at: Timestamp;
  origin_broker: BrokerId;
  aud: BrokerId;
}
export interface Receipt extends UnsignedReceipt {
  broker_sig: string;
}

export type RatificationMethod = "webauthn-uv" | "sso-stepup" | "native-uv" | "reauth-dev" | `standing-grant:${string}`;

/** typ alp-ratification+jws: made on the principal's own broker; travels in an ack (status ratified); the commit references it by hash. */
export interface UnsignedRatification {
  alp: AlpVersion;
  id: string;
  thread: string;
  scope: ScopeId;
  terms_hash: Sha256;
  principal_id: PrincipalId;
  address: Address;
  method: RatificationMethod;
  /** Seconds since the epoch. */
  iat: number;
  nonce: string;
  created_at: Timestamp;
  expires_at: Timestamp;
  origin_broker: BrokerId;
  /** The counterparty's home broker. */
  aud: BrokerId;
}
export interface Ratification extends UnsignedRatification {
  broker_sig: string;
}

// ---------------------------------------------------------------------------------------------
// Domain authority (public): https://<domain>/.well-known/alp.json

export interface BrokerEntry {
  id: BrokerId;
  inbox: string;
  jwks_uri: string;
  mcp?: string;
  rest?: string;
  /** RFC 7638 thumbprints of the broker's signing keys (current and next). Its JWKS may hold only these. */
  jkt: string[];
  /** `*` (at most one broker per document) or an explicit list. The home broker for an address is unique. */
  principals: "*" | Address[];
  operator_statement?: string;
}

export interface DomainDocument {
  alp: AlpVersion;
  domain: string;
  /** Monotonic; a lower serial than one already seen is refused. */
  serial: number;
  /** Seconds (60..86400). Brokers and keys are never used past it. */
  max_age: number;
  mode: "testing" | "enforce";
  brokers: BrokerEntry[];
  revoked_jkt?: { jkt: string; compromised_since: Timestamp }[];
  security_contact: string[];
  updated_at?: Timestamp;
}

export interface Jwk {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
  kid?: string;
  alg?: string;
  use?: string;
  alp_use?: "federation" | "http" | "ledger" | "push";
  [key: string]: unknown;
}

export interface Jwks {
  keys: Jwk[];
}

// ---------------------------------------------------------------------------------------------
// Org policy (PRIVATE local configuration; never published)

/** An exact address, `alp:*@domain`, `group:<name>`, `@org` (any principal of the policy's domains) or `*`. */
export type PrincipalRef = string;

export interface ClassificationRule {
  id: string;
  /** Label patterns: exact, `prefix.*`, or `*`. */
  labels: string[];
  direction: "outbound" | "inbound" | "both";
  /** Counterparties the labeled field may cross to (outbound) or from (inbound). Empty: nobody. */
  allow: PrincipalRef[];
  action: "reject" | "redact";
  /** `report` only records what would have been blocked. */
  mode: "enforce" | "report";
  description?: string;
}

export interface DefaultDirectionTerms {
  may: MessageType[];
  /** Envelope-relative pointer patterns. */
  fields: string[];
}

export interface DefaultScopeTerms {
  /** Messages from `from` to `to`. */
  forward: DefaultDirectionTerms;
  /** Replies from `to` back to `from`. */
  reverse?: DefaultDirectionTerms;
  commit?: CommitMode;
  limits?: JsonObject;
}

export interface DefaultRelationship {
  id: string;
  from: PrincipalRef[];
  to: PrincipalRef[];
  scopes: Record<ScopeId, DefaultScopeTerms>;
  rate_limit?: RateLimit;
}

export interface ClientRule {
  client_id: string;
  label?: string;
  scopes: ScopeId[];
  attestation: Attestation;
  class: DelegateClass;
  no_training: boolean;
  retention_days?: number;
}

/** The `client_id` that stands for personal access tokens (spec 5.7, 6.10). */
export const PAT_CLIENT_ID = "pat";

export interface DeliveryMinimum {
  labels: string[];
  min_attestation?: Attestation;
  min_class?: DelegateClass;
  no_training?: true;
  retention_max?: number;
  /**
   * Between one person's own agents (spec 6.14), what happens to fields with these labels when the receiving agent
   * doesn't meet the minimum: `hold` (the default) keeps them for the person to approve on the web view and delivers
   * the rest; `block` refuses the message.
   */
  otherwise?: "hold" | "block";
}

export type DlpCategory = "payment_card" | "private_key" | "credential" | "government_id";

export interface OrgPolicy {
  alp: AlpVersion;
  id: string;
  serial: number;
  domains: string[];
  updated_at: Timestamp;
  groups?: Record<string, { members: PrincipalRef[] } | { claim: { issuer: string; name: string; value: string } }>;
  classification?: {
    /** Per scope, per pointer: labels that replace the scope's own. */
    overrides?: Record<ScopeId, Record<string, string[]>>;
    rules?: ClassificationRule[];
  };
  default_relationships?: DefaultRelationship[];
  ratification?: { required_scopes: ScopeId[] };
  hold_for_review?: { scopes: ScopeId[] };
  dlp?: { hook?: string; categories: DlpCategory[]; inbound: boolean; timeout_ms?: number; on_error?: "block" | "allow" };
  retention?: { ledger_days?: number; store_values?: "never" | "free_text" | "all"; journal_scopes?: ScopeId[]; never_store_values_groups?: string[] };
  federation?: { mode: "allow" | "deny"; domains: string[] };
  connection_requests?: { inbound: "allow" | "allow_listed" | "deny"; allow_domains?: string[] };
  clients?: { mode: "enforce" | "report"; allowed: ClientRule[] };
  delivery_minimums?: DeliveryMinimum[];
  /** Kill switches, effective on the next policy load. */
  blocked?: { principals?: Address[]; delegates?: DelegateId[]; client_ids?: string[]; scopes?: ScopeId[]; domains?: string[]; brokers?: BrokerId[] };
  human_fallback?: "notify_only" | "off";
  sms?: boolean;
  inbound_default?: "response_only" | "open";
}

// ---------------------------------------------------------------------------------------------
// Relationships and grants (local to the holder's home broker; never sent to another broker)

export type CommitMode = "ask_me" | "within_limits";
export type RedactionMode = "reject" | "redact";

export interface ScopeTerms {
  may: MessageType[];
  /** Envelope-relative pointer patterns this principal's agent may send. */
  disclose: string[];
  /** Envelope-relative pointer patterns this principal accepts. Free text (and `/note`) must be named explicitly. */
  receive: string[];
  commit: CommitMode;
  /** Scope-defined commit limits (the scope's limits_schema); required when commit is within_limits. */
  limits?: JsonObject;
  redaction: RedactionMode;
  hold_for_review?: boolean;
}

export interface RateLimit {
  count: number;
  per_seconds: number;
}

export interface QuietHours {
  tz: string;
  start: string;
  end: string;
}

export type GrantBasis = "consent" | "narrowing";
export type SealMethod = "webauthn-uv" | "sso-stepup" | "native-uv" | "reauth-dev";

export interface RelationshipGrant {
  alp: AlpVersion;
  id: string;
  principal: Address;
  principal_id: PrincipalId;
  counterparty: Address;
  counterparty_principal_id?: PrincipalId;
  basis: GrantBasis;
  status: "pending" | "active" | "revoked";
  scopes: Record<ScopeId, ScopeTerms>;
  rate_limit?: RateLimit;
  quiet_hours?: QuietHours;
  connection?: string;
  created_at: Timestamp;
  updated_at: Timestamp;
  expires_at?: Timestamp;
  /** Who sealed it, how, when (required when active). */
  sealed?: { by: PrincipalId; method: SealMethod; at: Timestamp };
  broker_sig?: string;
}

/** The counterparty told us they no longer accept these scopes from our principal (local record). */
export interface CounterpartyRevocation {
  principal: Address;
  counterparty: Address;
  scopes: ScopeId[] | ["*"];
  reason: string;
  effective_at: Timestamp;
  received_at: Timestamp;
}

// ---------------------------------------------------------------------------------------------
// Connection requests

export type ConnectionState = "pending" | "approved" | "declined" | "expired" | "cancelled";

export type ConnectionPurpose = "work_request" | "scheduling" | "briefing" | "status_updates" | "document_exchange" | "introduction" | "other";

export interface ConnectionRequestRecord {
  /** Equals the id of the connection_request envelope. */
  id: string;
  direction: "outgoing" | "incoming";
  principal: Address;
  /** The principal that owns this record; a new holder of the address never sees it (spec 5.2). */
  principal_id?: PrincipalId;
  counterparty: Address;
  counterparty_principal_id?: PrincipalId;
  scopes: ScopeId[];
  purpose: ConnectionPurpose;
  /** Untrusted text; shown only on the broker's own page, never in a notification. */
  note?: string;
  /** The display name the requester's broker asserted. Untrusted. */
  display_name?: string;
  state: ConnectionState;
  origin: "explicit" | "stranger_message";
  /** Outgoing: the requester's terms, applied when the other side approves. */
  requester_terms?: Record<ScopeId, ScopeTerms>;
  /** Outgoing, filed by the person with a fresh sign-in: their terms are sealed now and become active on approval. */
  requester_sealed?: { method: SealMethod; at: Timestamp };
  approved_scopes?: ScopeId[];
  remote_broker?: BrokerId;
  /** Hash of the connection_request envelope (for the response's in_reply_to_hash). */
  envelope_hash?: Sha256;
  created_at: Timestamp;
  updated_at: Timestamp;
  expires_at: Timestamp;
}

// ---------------------------------------------------------------------------------------------
// Threads

export type ThreadState = "open" | "negotiating" | "agreed" | "committed" | "done" | "expired" | "cancelled";

export interface ThreadRecord {
  id: string;
  principal: Address;
  /** The principal that owns this record; a new holder of the address never sees it (spec 5.2). */
  principal_id?: PrincipalId;
  counterparty: Address;
  scope: ScopeId;
  state: ThreadState;
  created_at: Timestamp;
  updated_at: Timestamp;
  expires_at: Timestamp;
  /** Agreed terms (set by accept). */
  terms_hash?: Sha256;
  /** Who proposed the accepted terms ("me" = this principal), for scopes whose committer is the proposer. */
  proposer?: "me" | "counterparty";
  /** Ratification records for the agreed terms: ours (signed by our broker) and theirs (received in an ack). */
  ratifications?: { mine?: { id: string; hash: Sha256; record: Ratification }; theirs?: { id: string; hash: Sha256; record: Ratification } };
  /** Set once; a second commit is refused. */
  commit?: { envelope_id: string; direction: "in" | "out"; at: Timestamp };
  history: ThreadTransition[];
}

export interface ThreadTransition {
  envelope_id: string;
  type: MessageType;
  direction: "in" | "out";
  from: ThreadState | null;
  to: ThreadState;
  at: Timestamp;
}

/** A pending request for the person to ratify agreed terms (local; the signed record is made when they approve). */
export interface RatificationRequest {
  id: string;
  principal: Address;
  /** The principal that owns this record; a new holder of the address never sees it (spec 5.2). */
  principal_id?: PrincipalId;
  counterparty: Address;
  thread: string;
  scope: ScopeId;
  terms_hash: Sha256;
  terms: JsonObject;
  /** The accept envelope the terms came from (the ack and decline answer it). */
  accept_id: string;
  state: "pending" | "approved" | "declined" | "expired" | "voided";
  created_at: Timestamp;
  decided_at?: Timestamp;
  expires_at: Timestamp;
  record?: Ratification;
}

// ---------------------------------------------------------------------------------------------
// Principals, delegates, messages

export interface PrincipalRecord {
  principal_id: PrincipalId;
  address: Address;
  /** The IdP identity this principal is bound to (for Entra: iss of the tenant + oid). Never the email. */
  identity: { iss: string; sub: string };
  display_name?: string;
  contact?: { email?: string; sms?: string };
  /** The person's agent has no connector: accepted messages also notify the person (if org policy allows). */
  human_fallback?: boolean;
  /** Group claims from the IdP, for org policy groups defined by claim. */
  claims?: { issuer: string; name: string; value: string }[];
  status: "active" | "suspended" | "retired";
  created_at: Timestamp;
}

export interface DelegateRecord {
  id: DelegateId;
  principal: Address;
  principal_id: PrincipalId;
  label: string;
  kind: "bridged" | "native";
  /** OAuth client id (a CIMD URL or a registered id). */
  client_id: string;
  attestation: Attestation;
  class: DelegateClass;
  status: "active" | "revoked";
  created_at: Timestamp;
}

export interface IntakeVerification {
  /** The sender domain's home broker for the sender address, or this broker for a local sender. */
  sender_broker: BrokerId;
  home_broker: true;
  signature: "verified";
  kid: string;
  verified_at: Timestamp;
  /** Set when the signing key was later reported compromised (revoked_jkt). */
  flags?: string[];
}

export type MessageStatus = "delivered" | "held" | "released";

/**
 * An outbound message held for its sender's review (spec 6.12): nothing is signed until the person approves it on
 * the web view; on approval the broker evaluates it again in full, then signs and sends it.
 */
export interface HeldOutbound {
  id: string;
  principal: Address;
  /** The principal that owns this record; a new holder of the address never sees it (spec 5.2). */
  principal_id?: PrincipalId;
  delegate?: DelegateId;
  /** When the binding of `delegate` (the agent that wrote it) started: it is sent only as that binding (spec 5.4). */
  delegate_since?: Timestamp;
  client_id?: string;
  to: Address;
  to_delegate?: DelegateId;
  /**
   * Between the person's own agents: when the binding of `to_delegate` started. It goes only to that binding, never
   * to an agent that took the label after a disconnection (spec 5.4).
   */
  to_delegate_since?: Timestamp;
  scope: ScopeId;
  type: MessageType;
  body: JsonObject;
  note?: string;
  thread: string;
  /**
   * The message opens a thread: `thread` is the id the broker reserved for it when it held it, and the thread starts
   * only when the person approves the message and it is sent (spec 9.1).
   */
  opens_thread?: boolean;
  in_reply_to?: string;
  labels?: string[];
  expires_in_seconds?: number;
  /**
   * Why it waits: the grant or the organization asked for review, a DLP hook asked for a justification, or (between
   * the person's own agents) fields the receiving agent doesn't meet the organization's minimum for (spec 6.14).
   */
  reason: "review" | "dlp_justification" | "delivery_minimums";
  /** For `delivery_minimums`: the fields the receiving agent doesn't qualify for, and their labels. */
  withheld?: { pointers: string[]; labels: string[] };
  /**
   * For `delivery_minimums`: `whole` when what is left without `withheld` isn't a valid message, so nothing was sent;
   * otherwise the receiving agent already got a copy without them, whose envelope id is `partial_envelope_id`. A record
   * written before these existed that has `withheld` is of the second kind (a copy went; its id wasn't kept).
   */
  whole?: boolean;
  partial_envelope_id?: string;
  /**
   * `sending`: the person approved it and the broker is sending it (it stays so if the broker stopped before recording
   * the outcome; the ledger shows whether it went). `refused`: the evaluation again, or the recipient's broker, didn't
   * let it through (`result`).
   */
  state: "pending" | "sending" | "sent" | "refused" | "discarded" | "expired";
  created_at: Timestamp;
  expires_at: Timestamp;
  decided_at?: Timestamp;
  /** The envelope id, once the broker signed it (a `sent` ledger entry names it). */
  envelope_id?: string;
  /** For `refused`: what sending it answered. */
  result?: { status: "rejected" | "refused" | "needs_ratification" | "undeliverable"; code: ErrorCode };
}

export interface MessageRecord {
  /** Monotonic ULID assigned by the storing broker; the inbox cursor. */
  local_id: string;
  principal: Address;
  /** The principal that owns this record; a new holder of the address never sees it (spec 5.2). */
  principal_id?: PrincipalId;
  direction: "in" | "out";
  envelope: Envelope;
  envelope_hash: Sha256;
  /** `held`: the delivery constraints or `to.delegate` rule out this person's agents, or quiet hours are on; the person sees it on the web view. */
  status: MessageStatus;
  /** Quiet hours: held until this time, then delivered (spec 6.7). */
  held_until?: Timestamp;
  /**
   * Why it is held for the person's web view: no agent of theirs meets its delivery constraints, or the agent its
   * `to.delegate` names can't receive it (none with that label is active, it is blocked, or its client is refused).
   */
  held_reason?: "constraints" | "to_delegate";
  receipt?: Receipt;
  receipt_hash?: Sha256;
  verification?: IntakeVerification;
  acked_by: Record<DelegateId, Timestamp>;
  stored_at: Timestamp;
}

/**
 * The person's notification of a message that arrived during the grant's quiet hours, which waits until they end
 * (spec 6.7). It names the message only; what it says is decided when it is sent, as for a message arriving then.
 */
export interface DeferredNotice {
  /** ULID. */
  id: string;
  principal: Address;
  principal_id: PrincipalId;
  /** The received message (`MessageRecord`, direction `in`). */
  envelope_id: string;
  /** When the quiet hours end. */
  due_at: Timestamp;
}

// ---------------------------------------------------------------------------------------------
// Ledger

export const LEDGER_KINDS = [
  "sent", "refused_outbound", "held", "released", "delivery_failed", "receipt", "received", "refused_inbound", "delivered",
  "connection_requested", "connection_received", "connection_decided", "grant_set", "grant_revoked", "counterparty_revoked",
  "ratification", "commit", "flagged", "legal_hold", "erased",
] as const;
export type LedgerKind = (typeof LEDGER_KINDS)[number];
export type LedgerOutcome = "allowed" | "redacted" | "rejected" | "refused" | "accepted" | "held" | "delivered" | "info";

export interface LedgerEntry {
  alp: AlpVersion;
  principal: Address;
  principal_id: PrincipalId;
  seq: number;
  at: Timestamp;
  kind: LedgerKind;
  delegate?: DelegateId;
  client_id?: string;
  counterparty?: Address;
  counterparty_broker?: BrokerId;
  envelope_id?: string;
  thread?: string;
  scope?: ScopeId;
  type?: MessageType | ControlType;
  disclosed?: string[];
  redacted?: string[];
  labels?: string[];
  outcome: LedgerOutcome;
  code?: ErrorCode;
  policy_ids?: string[];
  envelope_hash?: Sha256;
  receipt_hash?: Sha256;
  counterparty_ledger_hash?: Sha256;
  ref?: string;
  /** Digest of the separately stored payload (values, note, free text). The chain covers the digest, so a payload can be shredded. */
  payload_hash?: Sha256;
  /**
   * 16 to 64 random bytes as unpadded base64url (spec 11.4), so a hash that reaches another party (a receipt's
   * `ledger_hash`) confirms no guess of what the entry says. Entries written before the reference added it have none.
   */
  salt?: string;
  prev_hash: Sha256 | null;
  hash: Sha256;
}

/**
 * A ledger entry's payload, stored apart from the chain (spec 11.4): envelope-relative pointers (`/body/...`,
 * `/note`) mapped to their values. The reference also keeps, under the non-pointer key `detail`, the reasons of a
 * refusal (with rule ids) for the owner's own view; refusal entries never cross-reference another ledger.
 */
export interface LedgerPayload {
  [pointer: string]: Json | Reason[] | undefined;
  detail?: Reason[];
}

export interface LedgerHead {
  seq: number;
  hash: Sha256;
}

// ---------------------------------------------------------------------------------------------
// Reasons (agent- and person-facing detail; the wire carries only ErrorCode)

export interface Reason {
  code: ErrorCode;
  /** Envelope-relative pointer into the sender's own message. */
  pointer?: string;
  /** Id of the rule that fired; shown only to the rule owner's own side. */
  rule?: string;
  /** DLP categories of a block (never the matched text). */
  categories?: DlpCategory[];
  detail?: string;
}

// ---------------------------------------------------------------------------------------------
// Callers

/** An agent, authenticated to its own home broker (OAuth access token or personal access token). */
export interface DelegateCaller {
  kind: "delegate";
  principal: Address;
  delegate: DelegateId;
  client_id: string;
}

/** The person, signed in to the broker's own page (or a native app's own UI). */
export interface HumanCaller {
  kind: "human";
  principal: Address;
  /**
   * The principal the person signed in as. When set, the broker refuses the call if the address now belongs to
   * someone else (spec 5.2): a page left open by an earlier holder of the address acts for no one.
   */
  principal_id?: PrincipalId;
  /** How and when the person last authenticated; approvals need a fresh step-up. */
  auth?: { method: SealMethod; at: Timestamp };
}

/** The operator (admin CLI or loopback-only admin endpoint). */
export interface AdminCaller {
  kind: "admin";
  operator: string;
}

export type Caller = DelegateCaller | HumanCaller;
