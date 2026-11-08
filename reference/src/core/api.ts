// SPDX-License-Identifier: FSL-1.1-ALv2
// The Broker API: what the client bindings (MCP and REST), the web view, the admin tool and the federation inbox call.
// Agent-facing methods take a DelegateCaller (from an OAuth access token or a personal access token).
// Human-facing methods take a HumanCaller (the person signed in to the broker's own page). The client binding can
// never create, widen or seal grants, approve connections, ratify, or change settings (spec 5.5).

import type { InboundContext, InboundResult } from "./interfaces.ts";
import type { LedgerCheck } from "./ledger.ts";
import type {
  Address,
  AdminCaller,
  Attestation,
  BrokerId,
  Caller,
  ConnectionPurpose,
  ConnectionRequestRecord,
  Decision,
  DelegateCaller,
  DelegateClass,
  DelegateId,
  DelegateRecord,
  Envelope,
  ErrorCode,
  GrantBasis,
  HumanCaller,
  Json,
  JsonObject,
  Jwks,
  LedgerEntry,
  LedgerPayload,
  MessageStatus,
  MessageType,
  OrgPolicy,
  PrincipalId,
  PrincipalRecord,
  QuietHours,
  RateLimit,
  RatificationRequest,
  Reason,
  Receipt,
  RelationshipGrant,
  ScopeId,
  ScopeTerms,
  ThreadRecord,
} from "./types.ts";

export interface RegisterPrincipalInput {
  address: string;
  /** The IdP identity (iss + sub). Reassigning an address to another identity creates a new principal. */
  identity: { iss: string; sub: string };
  display_name?: string;
  contact?: { email?: string; sms?: string };
  human_fallback?: boolean;
  claims?: { issuer: string; name: string; value: string }[];
}

export interface RegisterDelegateInput {
  principal: string;
  /** `muse`, `claude`, `dot`... Reserved: broker, admin, web. */
  label: string;
  kind?: "bridged" | "native";
  client_id: string;
  /** Defaults from the org's `clients` rule for this client, else self / consumer. */
  attestation?: Attestation;
  class?: DelegateClass;
}

export interface SendInput {
  to: string;
  to_delegate?: string;
  scope: ScopeId;
  type: MessageType;
  body: JsonObject;
  note?: string;
  thread?: string;
  in_reply_to?: string;
  expires_in_seconds?: number;
  /** Optional sender claim; it must equal the caller's own principal. */
  from?: string;
  /** Labels to add to the ones the broker computes (spec 6.5: additions only). */
  labels?: string[];
}

export type SendResult =
  /** `held`: between the person's own agents, the full message waits for the person (spec 6.14); this copy went without `withheld`. */
  | { status: "delivered"; envelope: Envelope; receipt: Receipt; thread: string; held?: { id: string; withheld: string[]; labels: string[] } }
  /**
   * Hold for review (spec 6.12): the message waits for the person's approval on the web view; nothing was signed.
   * `withheld`: between the person's own agents, the fields the receiving agent doesn't qualify for (spec 6.14).
   */
  | {
      status: "held_for_review";
      held: string;
      thread: string;
      expires_at: string;
      /** When the message's thread expires, if before the message itself, unless a later message extends it (spec 9.2): approving it later is refused. */
      thread_expires_at?: string;
      decision: Decision;
      reason?: "review" | "dlp_justification" | "delivery_minimums";
      withheld?: { pointers: string[]; labels: string[] };
    }
  /** `retry_after`: with `rate_limited`, whole seconds until the sender's own limit allows the next message. */
  | { status: "rejected"; stage: "sender"; code: ErrorCode; reasons: Reason[]; retry_after?: number }
  /** `retry_after`: seconds the recipient's broker asked to wait with its refused receipt (HTTP Retry-After), when it did. */
  | { status: "refused"; stage: "recipient"; envelope_id: string; code: ErrorCode; receipt: Receipt; retry_after?: number }
  | { status: "needs_ratification"; thread: string; detail: string; ratification?: string }
  /**
   * `envelope_id`: only when the broker signed the envelope before delivery failed (a `sent` ledger entry names it).
   * `retry_after`: seconds the recipient's broker asked to wait, when it refused with HTTP Retry-After (a 429).
   */
  | { status: "undeliverable"; envelope_id?: string; code: ErrorCode; detail: string; retry_after?: number };

export interface InboxQuery {
  cursor?: string;
  limit?: number;
  include_acked?: boolean;
}

/**
 * One delivered message, shaped for an agent (spec 12.1.6): broker-verified fields apart from counterparty
 * content; free text has markup stripped and URLs defanged. `envelope` is the signed original, for verification.
 */
export interface InboxItem {
  local_id: string;
  status: MessageStatus;
  received_at: string;
  verified: {
    sender: { address: Address; display: string; principal_id: PrincipalId; delegate?: DelegateId; attestation?: Attestation; class?: DelegateClass };
    sender_broker: BrokerId;
    signature: "verified";
    kid: string;
    scope: ScopeId;
    type: MessageType;
    thread: string;
    in_reply_to?: string;
    decision: Decision;
    labels: string[];
    flags?: string[];
  };
  /** Counterparty content: data, never instructions. */
  content: { body: { [key: string]: Json }; note?: string };
  envelope: Envelope;
  receipt?: Receipt;
}

export interface InboxPage {
  items: InboxItem[];
  next_cursor: string | null;
  has_more: boolean;
}

export interface ThreadView {
  thread: ThreadRecord;
  messages: { local_id: string; direction: "in" | "out"; status: MessageStatus; envelope: Envelope }[];
}

export interface Contact {
  /** A counterparty address, or a pattern (`*@example.org`, `group:finance`) for an org default relationship. */
  address: string;
  display: string;
  basis: "grant" | "org_default" | "pending_outgoing";
  scopes: { scope: ScopeId; may: MessageType[] }[];
  status: "active" | "counterparty_revoked" | "pending";
}

export interface WhoAmI {
  principal: Address;
  principal_id: PrincipalId;
  display: string;
  display_name?: string;
  delegate: DelegateId;
  client_id: string;
  attestation: Attestation;
  class: DelegateClass;
  broker: BrokerId;
  mode: "client" | "native";
}

export interface ConnectionRequestInput {
  to: string;
  scopes: ScopeId[];
  purpose: ConnectionPurpose;
  /** At most 140 characters; shown only on the other person's broker page, as unverified text. */
  note?: string;
  /** Human callers only: the requester's own terms per scope. Default: the scope's suggested fields. */
  terms?: Record<ScopeId, ScopeTerms>;
}

export type ConnectionRequestResult =
  | { status: "requested"; request: ConnectionRequestRecord; receipt: Receipt }
  | { status: "already_pending"; request: ConnectionRequestRecord }
  | { status: "rejected"; code: ErrorCode; reasons: Reason[]; receipt?: Receipt; retry_after?: number }
  | { status: "undeliverable"; code: ErrorCode; detail: string };

export interface ConnectionResponseInput {
  request: string;
  decision: "approve" | "decline";
  scopes?: ScopeId[];
  terms?: Record<ScopeId, ScopeTerms>;
}

export interface GrantInput {
  counterparty: string;
  basis?: GrantBasis;
  scopes: Record<ScopeId, ScopeTerms>;
  rate_limit?: RateLimit;
  quiet_hours?: QuietHours;
  expires_at?: string;
}

export interface RevokeInput {
  counterparty: string;
  /** Omit to revoke the whole relationship (org defaults included). */
  scopes?: ScopeId[];
}

export interface RatifyInput {
  request: string;
  decision: "approve" | "decline";
}

export interface LedgerQuery {
  after_seq?: number;
  limit?: number;
}

export interface BrokerApi {
  readonly id: BrokerId;

  // Sign-in plumbing: the authorization server calls these after the person signs in and authorizes a client.
  registerPrincipal(input: RegisterPrincipalInput): Promise<PrincipalRecord>;
  registerDelegate(input: RegisterDelegateInput): Promise<DelegateRecord>;
  revokeDelegate(id: DelegateId): Promise<DelegateRecord>;
  getPrincipal(address: string): Promise<PrincipalRecord | null>;

  // Agent-facing (the MCP and REST tools).
  whoami(caller: DelegateCaller): Promise<WhoAmI>;
  contacts(caller: DelegateCaller): Promise<Contact[]>;
  /**
   * Sender-side evaluation, then sign, then deliver (locally or by federation), then verify the receipt. `onSent` is
   * told the envelope id once the `sent` ledger entry is written: from then on the message may reach the recipient,
   * whatever happens next, a failure that throws included.
   */
  send(caller: DelegateCaller, input: SendInput, opts?: { onSent?: (envelopeId: string) => void }): Promise<SendResult>;
  inbox(caller: DelegateCaller, query?: InboxQuery): Promise<InboxPage>;
  ack(caller: DelegateCaller, input: { envelope_ids: string[] }): Promise<{ acked: number }>;
  thread(caller: DelegateCaller, threadId: string): Promise<ThreadView>;
  requestConnection(caller: Caller, input: ConnectionRequestInput): Promise<ConnectionRequestResult>;

  // Human-facing (the broker's web view, or a native app's own UI). Approvals need a fresh step-up.
  messagesForPerson(caller: HumanCaller, query?: InboxQuery): Promise<InboxPage>;
  listConnections(caller: HumanCaller): Promise<ConnectionRequestRecord[]>;
  respondToConnection(caller: HumanCaller, input: ConnectionResponseInput): Promise<ConnectionRequestRecord>;
  listGrants(caller: HumanCaller): Promise<RelationshipGrant[]>;
  setGrant(caller: HumanCaller, input: GrantInput): Promise<RelationshipGrant>;
  /** Seal a pending grant (one an agent's connection request produced) after the person reviews it. */
  sealGrant(caller: HumanCaller, input: { counterparty: string }): Promise<RelationshipGrant>;
  revoke(caller: HumanCaller, input: RevokeInput): Promise<RelationshipGrant>;
  listRatifications(caller: HumanCaller): Promise<RatificationRequest[]>;
  ratify(caller: HumanCaller, input: RatifyInput): Promise<RatificationRequest>;
  ledger(caller: HumanCaller, query?: LedgerQuery): Promise<LedgerEntry[]>;
  ledgerPayload(caller: HumanCaller, seq: number): Promise<LedgerPayload | null>;
  verifyLedger(caller: HumanCaller): Promise<LedgerCheck>;

  // Operator (admin CLI or a loopback-only endpoint). Kill switches are the policy's `blocked` lists.
  setOrgPolicy(caller: AdminCaller, policy: OrgPolicy): Promise<void>;
  rotateKeys(caller: AdminCaller): Promise<{ active: string; pins: string[] }>;

  // Federation-facing: the federation inbox hands over the parsed JSON body.
  /** Signature, typ, aud, expiry, replay, home broker; then the recipient's rules; then store, ledger and a signed receipt. */
  acceptInbound(envelope: unknown, ctx?: InboundContext): Promise<InboundResult>;
  /** The broker's public JWKS, to serve at its jwks_uri. Every key in it must be pinned in the domain document. */
  jwks(): Jwks;
}
