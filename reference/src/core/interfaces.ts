// SPDX-License-Identifier: FSL-1.1-ALv2
// The seams. The broker core depends only on these; storage, federation, identity, notification and security
// events are swappable. Implementations: src/storage (Store), src/federation (FederationTransport, DomainResolver),
// src/oauth (IdentityVerifier and the authorization server), src/web + core/notify.ts (Notifier, LinkBuilder),
// core/security-events.ts (SecurityEventSink).

import type { StoredKeyRing } from "./keys.ts";
import type {
  Address,
  AnyEnvelope,
  BrokerId,
  ConnectionRequestRecord,
  CounterpartyRevocation,
  DeferredNotice,
  DelegateId,
  DelegateRecord,
  DomainDocument,
  ErrorCode,
  HeldOutbound,
  Jwks,
  LedgerEntry,
  LedgerHead,
  LedgerPayload,
  MessageRecord,
  MessageStatus,
  PrincipalId,
  PrincipalRecord,
  RatificationRequest,
  Receipt,
  RelationshipGrant,
  ThreadRecord,
  Timestamp,
} from "./types.ts";

export type { Clock } from "./clock.ts";
export type { SecurityEventSink } from "./security-events.ts";

// ---------------------------------------------------------------------------------------------
// Store: memory and file now, Postgres for the hosted broker. Each method is atomic on its own; records go in
// and come out as copies.

export interface MessageQuery {
  direction?: "in" | "out";
  /** Exclusive cursor: local_id greater than this. */
  after?: string;
  /** Exclusive cursor: local_id less than this. */
  before?: string;
  /** By local_id: `asc` (the default), oldest first, or `desc`, newest first. `limit` takes the first ones in this order. */
  order?: "asc" | "desc";
  limit: number;
  thread?: string;
  status?: MessageStatus[];
  /** Only messages this delegate hasn't acknowledged. */
  unackedBy?: DelegateId;
  /** Only messages addressed to the principal in general or to this delegate. */
  forDelegate?: DelegateId;
  /**
   * When the binding of the delegate in `forDelegate` and `unackedBy` started (spec 5.4): a message addressed to it
   * counts only if it was stored at or after this time, and an acknowledgement only if it was made at or after it.
   * Earlier ones belong to an earlier binding with the same label.
   */
  bindingSince?: Timestamp;
}

/** What `hitRateLimit` answers. */
export interface RateLimitHit {
  allowed: boolean;
  count: number;
  /** Whole seconds until the oldest hit in the window leaves it; 0 when the window is empty. */
  retryAfter: number;
}

/** Whole seconds until the oldest of `hits` (epoch milliseconds) leaves a window of `windowSeconds` ending at `now`. */
export function secondsUntilOldestLeaves(hits: readonly number[], now: number, windowSeconds: number): number {
  if (hits.length === 0) return 0;
  // A loop, not Math.min(...hits): spreading 100,000 or so arguments overflows the stack.
  let oldest = Number.POSITIVE_INFINITY;
  for (const h of hits) if (h < oldest) oldest = h;
  return Math.max(1, Math.ceil((oldest + windowSeconds * 1000 - now) / 1000));
}

export interface Store {
  readonly kind: string;

  /** The active principal that currently holds this address (aliases move; principal_ids never do). */
  getPrincipal(address: Address): Promise<PrincipalRecord | null>;
  getPrincipalById(id: PrincipalId): Promise<PrincipalRecord | null>;
  getPrincipalByIdentity(iss: string, sub: string): Promise<PrincipalRecord | null>;
  putPrincipal(rec: PrincipalRecord): Promise<void>;
  listPrincipals(): Promise<PrincipalRecord[]>;

  getDelegate(id: DelegateId): Promise<DelegateRecord | null>;
  putDelegate(rec: DelegateRecord): Promise<void>;
  listDelegates(principal: Address): Promise<DelegateRecord[]>;

  /** One grant per (owner, counterparty). */
  getGrant(principal: Address, counterparty: Address): Promise<RelationshipGrant | null>;
  putGrant(grant: RelationshipGrant): Promise<void>;
  listGrants(principal: Address): Promise<RelationshipGrant[]>;

  getRevocation(principal: Address, counterparty: Address): Promise<CounterpartyRevocation | null>;
  putRevocation(rec: CounterpartyRevocation): Promise<void>;

  getConnection(principal: Address, id: string): Promise<ConnectionRequestRecord | null>;
  putConnection(rec: ConnectionRequestRecord): Promise<void>;
  listConnections(principal: Address): Promise<ConnectionRequestRecord[]>;

  /** Insert or replace, keyed by (principal, direction, envelope.id). */
  putMessage(rec: MessageRecord): Promise<void>;
  getMessage(principal: Address, direction: "in" | "out", envelopeId: string): Promise<MessageRecord | null>;
  /** Ascending local_id. */
  listMessages(principal: Address, q: MessageQuery): Promise<MessageRecord[]>;

  /** A notification that waits until the grant's quiet hours end (spec 6.7). */
  putDeferredNotice(rec: DeferredNotice): Promise<void>;
  /**
   * Removes and returns the deferred notifications due at `now` (`due_at` at or before it), earliest first, at most
   * `limit`, in one atomic step: of several brokers sharing the store, each notification goes to one.
   */
  takeDueNotices(now: Date, limit: number): Promise<DeferredNotice[]>;

  getThread(principal: Address, id: string): Promise<ThreadRecord | null>;
  putThread(rec: ThreadRecord): Promise<void>;

  /** Outbound messages held for their sender's review (spec 6.12). */
  putHeldOutbound(rec: HeldOutbound): Promise<void>;
  /**
   * Replaces a held message's record only if the stored one is still in state `from` (default `pending`), in one
   * atomic step; true when this call replaced it. Every decision on a held message goes through here, so of two at
   * once exactly one takes effect; an approval that failed leaves `sending` the same way.
   */
  claimHeldOutbound(next: HeldOutbound, from?: HeldOutbound["state"]): Promise<boolean>;
  getHeldOutbound(principal: Address, id: string): Promise<HeldOutbound | null>;
  listHeldOutbound(principal: Address): Promise<HeldOutbound[]>;

  getRatificationRequest(id: string): Promise<RatificationRequest | null>;
  putRatificationRequest(rec: RatificationRequest): Promise<void>;
  listRatificationRequests(principal: Address): Promise<RatificationRequest[]>;

  /** Receipts this broker issued, keyed `${origin_broker}|${envelope id}`. */
  putReceipt(key: string, receipt: Receipt): Promise<void>;
  getReceipt(key: string): Promise<Receipt | null>;

  /**
   * Append to a principal's ledger (keyed by principal_id). `build` gets the head and returns the entry (and its
   * payload, stored apart); read-head + build + insert is atomic (a transaction with a row lock in Postgres).
   */
  appendLedger(principalId: PrincipalId, build: (head: LedgerHead | null) => { entry: LedgerEntry; payload?: LedgerPayload }): Promise<LedgerEntry>;
  listLedger(principalId: PrincipalId, q?: { afterSeq?: number; limit?: number }): Promise<LedgerEntry[]>;
  getLedgerPayload(principalId: PrincipalId, seq: number): Promise<LedgerPayload | null>;
  /** Crypto-shredding stand-in: drop the payload; the chain still verifies. */
  eraseLedgerPayload(principalId: PrincipalId, seq: number): Promise<void>;

  /** Replay window: record `key` until `expiresAt`. False if already recorded and unexpired. Atomic. */
  recordOnce(key: string, expiresAt: string, now: Date): Promise<boolean>;
  /**
   * Sliding-window rate limit; counts the hit only when allowed. Atomic per key. `count` is the hits in the window
   * (the new one included when allowed); `retryAfter` is the whole seconds until the oldest of them leaves the window
   * (0 when there are none), which, for a refused hit, is when the next one can be allowed.
   */
  hitRateLimit(key: string, now: Date, windowSeconds: number, limit: number): Promise<RateLimitHit>;

  /** Private key material. File store: a separate 0600 file. Hosted: an encrypted column or a KMS. */
  getKeyRing(name: string): Promise<StoredKeyRing | null>;
  putKeyRing(name: string, ring: StoredKeyRing): Promise<void>;

  close(): Promise<void>;
}

// ---------------------------------------------------------------------------------------------
// Federation (src/federation)

export interface DomainResolver {
  /**
   * The validated domain document (checkDomainDocument), fetched only from https://<domain>/.well-known/alp.json
   * or https://alp.<domain>/.well-known/alp.json through the hardened fetcher (443 only, no redirects,
   * 200 only, at most 64 KiB, 5 s, no private or loopback addresses; dev host map for localhost). Cached up to max_age;
   * a lower serial is refused; brokers and keys are never used past max_age even when a refresh fails, while de-listings
   * keep applying for RESTRICTION_PERSIST_SECONDS. Throws AlpError("discovery_failed") and never echoes fetch errors.
   * When the domain definitely publishes no document (404 or 410, or no address records, at both locations) the
   * error also carries `absent: true`: the broker then refuses its senders (broker_not_authorized) and reports its
   * addresses as unknown_recipient, both permanent, instead of the retryable discovery_failed.
   */
  domainDocument(domain: string, opts?: { refresh?: boolean; budget?: string }): Promise<DomainDocument>;
  /** A broker's published JWKS (raw; the core pins it against the domain document). `refresh` bypasses the cache once. */
  jwks(jwksUri: string, opts?: { refresh?: boolean }): Promise<Jwks>;
}

export interface DeliveryTarget {
  broker: BrokerId;
  inbox: string;
}

/** Transport metadata. Authentication comes from the signed envelope itself (aud + pinned keys), not the request. */
export interface InboundContext {
  remote?: string;
}

/**
 * What a recipient broker answers: a signed receipt (the envelope's signature verified), or a plain refusal (steps 0
 * and 1 of spec 12.2.4). `step` is the acceptance step that refused it (0 to 11), for diagnostics and the vectors;
 * `duplicate` marks the original receipt returned for an identical retry (spec 10.3).
 */
export type InboundResult =
  /** `retry_after`: seconds, for a refusal the sender may retry (a reply that overtook the message it answers). */
  | { kind: "receipt"; receipt: Receipt; step?: number; duplicate?: true; retry_after?: number }
  | { kind: "refused"; status: number; code: ErrorCode; message: string; step?: number; /** Seconds, for a retryable refusal (HTTP Retry-After). */ retry_after?: number };

export type DeliveryResult = InboundResult | { kind: "unreachable"; message: string };

export interface FederationTransport {
  /** HTTPS POST of the signed envelope (JSON) to the target's inbox; maps the answer. Never throws for remote failures. */
  deliver(target: DeliveryTarget, envelope: AnyEnvelope): Promise<DeliveryResult>;
}

// ---------------------------------------------------------------------------------------------
// Identity (src/oauth): who the signing-in person is. The dev IdP (core/identity.ts: test identities), or the
// organization's OpenID provider (src/oauth/oidc.ts, e.g. Entra). Principals bind to iss + sub (for Entra: the tenant
// issuer + oid), never to email or upn.

export type IdentityAssertion = { kind: "dev"; username: string; secret?: string } | { kind: "oidc"; id_token: string; nonce?: string };

export interface VerifiedIdentity {
  address: Address;
  display_name?: string;
  method: "dev" | "oidc" | "invite";
  iss: string;
  sub: string;
  claims?: { issuer: string; name: string; value: string }[];
  verified_at: string;
}

export interface IdentityVerifier {
  readonly id: string;
  /** Throws AlpError("identity_mismatch") when the assertion doesn't verify. */
  verify(assertion: IdentityAssertion): Promise<VerifiedIdentity>;
  listTestIdentities?(): { username: string; address: Address; display_name?: string }[];
}

// ---------------------------------------------------------------------------------------------
// People: notifications only notify (spec 12.5.1). Broker-generated text only; links only to the broker's
// own origin behind full sign-in; no link, code or reply acts.

export type NotificationKind = "connection_request" | "connection_decided" | "ratification_needed" | "ask_human" | "message_waiting" | "message_held" | "new_device";

export interface HumanNotification {
  principal: Address;
  kind: NotificationKind;
  channel: "email" | "sms";
  to: string;
  subject: string;
  text: string;
  link: string;
  at: string;
}

export interface Notifier {
  notify(n: HumanNotification): Promise<void>;
}

/** Paths the web surface (src/web) serves. No personal data in them. */
export interface LinkBuilder {
  connection(id: string): string;
  ratification(id: string): string;
  message(envelopeId: string): string;
  /** An outbound message held for the person's review (spec 6.12). */
  held(id: string): string;
  ledger(): string;
}

/** Push for agents whose platform accepts webhooks: an opaque id only; the agent fetches the inbox. */
export interface AgentPush {
  push(delegate: DelegateRecord, opaqueRef: string): Promise<void>;
}
