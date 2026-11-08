// SPDX-License-Identifier: FSL-1.1-ALv2
// The home broker. One class runs every profile: Local (one organization's broker for its own people: no domain
// document, no published policy, no federation listener needed), federated organization brokers, and hosted brokers.
// What differs is configuration: its private org policies, store, resolver and transport.

import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { RESERVED_DELEGATE_LABELS, delegateBelongsTo, delegateIdOf, displayAddress, domainOf, isDelegateLabel, parseAddress, parseDelegateId } from "./address.ts";
import type {
  BrokerApi,
  ConnectionRequestInput,
  ConnectionRequestResult,
  ConnectionResponseInput,
  Contact,
  GrantInput,
  InboxItem,
  InboxPage,
  InboxQuery,
  LedgerQuery,
  RatifyInput,
  RegisterDelegateInput,
  RegisterPrincipalInput,
  RevokeInput,
  SendInput,
  SendResult,
  ThreadView,
  WhoAmI,
} from "./api.ts";
import type { Clock } from "./clock.ts";
import { addSeconds, iso, systemClock } from "./clock.ts";
import { expireConnectionIfDue, transitionConnection } from "./connections.ts";
import { sanitizeBody, sanitizeText } from "./content.ts";
import { homeBroker, pinnedFederationKeys, revokedKeys } from "./domain.ts";
import {
  checkEnvelopeStructure,
  checkRatification,
  checkReceipt,
  objectHash,
  signControl,
  signEnvelope,
  signRatification,
  signReceipt,
  verifyAnyEnvelope,
  verifyRatification,
  verifyReceipt,
} from "./envelope.ts";
import { AlpError, errMessage } from "./errors.ts";
import { IdSource, isUlid } from "./ids.ts";
import { getAt, removePointers } from "./pointers.ts";
import type {
  AgentPush,
  DeliveryResult,
  DomainResolver,
  FederationTransport,
  InboundContext,
  InboundResult,
  LinkBuilder,
  NotificationKind,
  Notifier,
  SecurityEventSink,
  Store,
} from "./interfaces.ts";
import type { KeyRing } from "./keys.ts";
import { buildLedgerEntry, payloadFor, verifyLedger } from "./ledger.ts";
import type { LedgerCheck, LedgerFields } from "./ledger.ts";
import { webLinks } from "./notify.ts";
import { SampleDlp, runDlp } from "./policy/dlp.ts";
import type { DlpHook } from "./policy/dlp.ts";
import { NOTE_POINTER, codeForSender, evaluateMessage, rejectionDetail } from "./policy/evaluate.ts";
import type { Evaluation } from "./policy/evaluate.ts";
import {
  anyRefMatches,
  blockedBy,
  checkOrgPolicy,
  checkOwnAgentDelivery,
  checkPolicyUpdate,
  clientRule,
  connectionRequestsAllowed,
  deliveryConstraints,
  federationAllows,
  lowerAttestation,
  lowerClass,
  meetsConstraints,
  policyRef,
} from "./policy/org-policy.ts";
import type { ClaimsOf } from "./policy/org-policy.ts";
import { MAX_OPEN_RATIFICATIONS_PER_COUNTERPARTY, humanRatificationRequired, newNonce, termsHash, withinLimits } from "./ratification.ts";
import { checkScopeTerms, defaultScopeTerms, effectiveTerms, hasAnyRelationship, isQuietTime, quietHoursEnd, signGrant } from "./relationships.ts";
import type { EffectiveTerms } from "./relationships.ts";
import { ScopeRegistry, freeTextPatterns, labelsOf, validateBody } from "./scopes/index.ts";
import type { CompiledScope } from "./scopes/index.ts";
import { scopeSemantics, windowRequestId } from "./scopes/semantics.ts";
import { buildSecurityEvent } from "./security-events.ts";
import type { SecurityEvent, SecurityEventName } from "./security-events.ts";
import { MAX_THREAD_MESSAGES, TERMINAL_STATES, applyToThread, expireIfDue } from "./threads.ts";
import { ackedBy, agentMayRead } from "./visibility.ts";
import type { ThreadMessage } from "./threads.ts";
import { ALP_VERSION, PAT_CLIENT_ID, isControlType, isMessageType } from "./types.ts";
import type {
  Address,
  AdminCaller,
  AnyEnvelope,
  BrokerEntry,
  BrokerId,
  Caller,
  ConnectionRequestRecord,
  Constraints,
  ControlEnvelope,
  ControlType,
  CounterpartyRevocation,
  Decision,
  DelegateCaller,
  DelegateId,
  DelegateRecord,
  DlpCategory,
  DomainDocument,
  Envelope,
  ErrorCode,
  HeldOutbound,
  HumanCaller,
  IntakeVerification,
  JsonObject,
  Jwks,
  LedgerEntry,
  LedgerPayload,
  MessageRecord,
  MessageType,
  OrgPolicy,
  PrincipalRecord,
  RateLimit,
  Ratification,
  RatificationRequest,
  Reason,
  Receipt,
  RelationshipGrant,
  ScopeId,
  ScopeTerms,
  SealMethod,
  Sender,
  ThreadRecord,
  UnsignedEnvelope,
} from "./types.ts";

export interface BrokerLimits {
  noteMaxChars: number;
  controlNoteMaxChars: number;
  bodyMaxBytes: number;
  defaultTtlSeconds: number;
  /** expires_at is at most created_at + 7 days. */
  maxTtlSeconds: number;
  clockSkewSeconds: number;
  /** The replay window runs to expires_at plus this. */
  replayGraceSeconds: number;
  receiptTtlSeconds: number;
  connectionTtlSeconds: number;
  ratificationTtlSeconds: number;
  /** Approvals need a sign-in at most this old. */
  stepUpMaxAgeSeconds: number;
  connectionRequestsPerSenderPerDay: number;
  /** Per registrable domain of the requester (spec 6.2.2), so a wildcard domain can't multiply its quota. */
  connectionRequestsPerDomainPerDay: number;
  /** Per origin broker, whatever domains it signs for. */
  connectionRequestsPerBrokerPerDay: number;
  /** Requests from a requester the person declined this recently are dropped (spec 6.2.2). */
  declinedRequesterDays: number;
  outgoingConnectionRequestsPerDay: number;
  /**
   * Messages between two people, in each direction, when their terms set no rate limit: one bucket per sending
   * person and counterparty (`out|`), and per receiving person and sender (`in|`).
   */
  defaultRateLimit: RateLimit;
  /**
   * Messages between one person's own agents (spec 6.14): one bucket per sending agent and receiving agent, in each
   * direction, apart from the person's limits with other people.
   */
  ownAgentRateLimit: RateLimit;
  inboxPageMax: number;
  /**
   * An envelope being evaluated is marked in flight for this long (spec 10.3): a duplicate that arrives meanwhile is
   * told to retry later instead of being evaluated a second time. After it, a first attempt that never answered is
   * presumed to have crashed and the envelope is evaluated again.
   */
  inFlightSeconds: number;
  /** At most this many labels a delegate may add to one message (spec 6.5). */
  maxAddedLabels: number;
}

export const DEFAULT_LIMITS: BrokerLimits = {
  noteMaxChars: 280,
  controlNoteMaxChars: 140,
  bodyMaxBytes: 64 * 1024,
  defaultTtlSeconds: 3 * 24 * 3600,
  maxTtlSeconds: 7 * 24 * 3600,
  clockSkewSeconds: 300,
  replayGraceSeconds: 300,
  receiptTtlSeconds: 7 * 24 * 3600,
  connectionTtlSeconds: 14 * 24 * 3600,
  ratificationTtlSeconds: 3 * 24 * 3600,
  stepUpMaxAgeSeconds: 300,
  connectionRequestsPerSenderPerDay: 5,
  connectionRequestsPerDomainPerDay: 50,
  connectionRequestsPerBrokerPerDay: 100,
  declinedRequesterDays: 90,
  outgoingConnectionRequestsPerDay: 20,
  defaultRateLimit: { count: 120, per_seconds: 3600 },
  ownAgentRateLimit: { count: 600, per_seconds: 3600 },
  inboxPageMax: 100,
  inFlightSeconds: 30,
  maxAddedLabels: 4,
};

/**
 * The registrable domain of a host, without a public-suffix list: the last two labels, or the last three when the
 * second-level label is a common one under a two-letter country code (`co.uk`, `com.au`). An approximation, used only
 * to group connection-request quotas so that `a1.evil.example` and `a2.evil.example` share one.
 */
export function registrableDomain(domain: string): string {
  const labels = domain.toLowerCase().split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const tld = labels[labels.length - 1] ?? "";
  const sld = labels[labels.length - 2] ?? "";
  const take = tld.length === 2 && ["ac", "co", "com", "edu", "gov", "net", "org", "or", "ne", "go"].includes(sld) ? 3 : 2;
  return labels.slice(-take).join(".");
}

export interface BrokerOptions {
  /** The broker's HTTPS origin. */
  id: BrokerId;
  store: Store;
  keys: KeyRing;
  resolver: DomainResolver;
  transport: FederationTransport;
  notifier: Notifier;
  /** Private org policies for the domains this broker hosts. */
  policies?: OrgPolicy[];
  /** Domains whose principals this broker hosts. Default: the policies' domains. */
  domains?: string[];
  securityEvents?: SecurityEventSink;
  /** Base URL of the broker's web view. Default `${id}/web`. */
  webBaseUrl?: string;
  links?: LinkBuilder;
  clock?: Clock;
  scopes?: ScopeRegistry;
  dlp?: DlpHook;
  push?: AgentPush;
  limits?: Partial<BrokerLimits>;
  /** A message from a stranger becomes a connection request to the person. Default true. */
  strangerMessagesBecomeRequests?: boolean;
  /**
   * Delivery constraints this broker can honor (spec 6.11). Default: `deliver_to` and `no_training` yes;
   * `retention_max` only when the organization's policy keeps no payload values longer than asked.
   */
  constraintSupport?: { deliver_to?: boolean; no_training?: boolean; retention_max?: boolean };
  /**
   * Runs the work the broker does after it has answered an accepted message (spec 6.7): the `held` ledger entry, the
   * person's notification and the pushes to agents, so that how long the answer takes doesn't depend on which agents
   * the recipient has. Default: on the next turn of the event loop (`setImmediate`), after the answer has been
   * written. A host that may freeze the process once a response is sent (a serverless function) passes a hook that
   * keeps it alive until the task settles, for example with the platform's `waitUntil`.
   */
  background?: (task: () => Promise<void>) => void;
  /** Called when that work fails. Default: one line on stderr, naming no message content. */
  onBackgroundError?: (err: unknown) => void;
}

/**
 * Where an address lives. `unknown_local`: on a domain this broker is home for, but nobody holds the address; it is
 * delivered locally anyway so the answer is the uniform one an unknown address gets from any broker (spec 6.2.2, 6.8).
 */
type Home =
  | { kind: "local"; principal: PrincipalRecord }
  | { kind: "unknown_local" }
  | { kind: "remote"; entry: BrokerEntry }
  | { kind: "none"; code: ErrorCode; detail: string };
/** Whether this broker is an address's home broker (spec 4.5). `unknown`: its domain's document couldn't be checked. */
type HomeStatus = "here" | "elsewhere" | "unknown";
type Reachable = Exclude<Home, { kind: "none" }>;
/** `retry_after`: seconds the recipient's broker asked the sender to wait (HTTP Retry-After on a refusal, or with a refused receipt). */
type Outcome = { kind: "ok"; receipt: Receipt; hash: string; retry_after?: number } | { kind: "failed"; code: ErrorCode; detail: string; retry_after?: number };
type EventArgs = { failed?: boolean; message?: string; details?: Omit<SecurityEvent["detail"], "event" | "broker"> };

interface Draft {
  /** null: the broker sends for its principal (ratification acks and declines). */
  delegate: DelegateRecord | null;
  to: string;
  to_delegate?: string;
  scope: ScopeId;
  type: MessageType;
  body: JsonObject;
  note?: string;
  thread?: string;
  /**
   * A held message that opens a thread, approved by the person: the thread id the broker reserved for it when it held
   * it. Unlike `thread`, the thread need not exist; the message opens it.
   */
  open_thread?: string;
  in_reply_to?: string;
  expires_in_seconds?: number;
  /** Labels the delegate adds (additions only). */
  labels?: string[];
  /** The id of a held message the person just approved: it is evaluated again but not held again. */
  released?: string;
}

/** Fields the organization's minimums keep from one of the person's own agents (spec 6.14): pointers, labels, what they need. */
type OwnWithheld = { withheld: string[]; labels: string[]; needs: string; target: DelegateRecord };

type Prepared =
  | {
      kind: "ready";
      now: Date;
      to: Address;
      toDelegate?: string;
      scope: CompiledScope;
      threadId: string;
      replyTo: MessageRecord | null;
      terms_hash?: string;
      ratifications?: [string, string];
      terms: EffectiveTerms;
      ev: Evaluation;
      policy: OrgPolicy | null;
      hold: boolean;
      /** Why the whole message waits for the person (with `hold`). */
      holdReason?: HeldOutbound["reason"];
      /** Between the person's own agents: fields this copy goes without, held in full for the person (spec 6.14). */
      ownSplit?: OwnWithheld;
      /** Between the person's own agents: the fields that hold the whole message, when what is left isn't a valid message. */
      ownHold?: OwnWithheld;
      /** Between the person's own agents: the agent `to_delegate` names, ranked by the current list. */
      ownTarget?: DelegateRecord;
      constraints?: Constraints;
      /** The sender's grant, still unbound to the counterparty's principal_id: bound on first local delivery (spec 5.2). */
      grantToBind?: RelationshipGrant;
      tmsg: ThreadMessage | null;
      envelopeId: string;
      createdAt: string;
      expiresAt: string;
      ttl: number;
      base: Partial<LedgerFields>;
    }
  | { kind: "rejected"; code: ErrorCode; reasons: Reason[]; ledger: Partial<LedgerFields>; event?: { name: SecurityEventName; failed?: boolean; message?: string } }
  | { kind: "needs_ratification"; thread: string; detail: string };

/** The result of acceptance steps 0 to 6: an answer already (a refusal or a duplicate's receipt), or authenticated. */
export type Authentication =
  | { kind: "answered"; result: InboundResult }
  | { kind: "authenticated"; env: AnyEnvelope; hash: string; typ: string; home_broker: BrokerId; verification: IntakeVerification; testing?: boolean };

/** A dry-run sender-side decision (`evaluateSend`), in the shape of vectors/policy/sender.json. */
export type SendDecision =
  | { outcome: "rejected"; code: ErrorCode; pointers?: string[]; rule?: string; categories?: DlpCategory[] }
  | { outcome: "allowed" | "redacted"; grant: string; labels: string[]; redacted: string[]; body?: JsonObject; policy_ids: string[]; constraints?: Constraints; status: "queued" | "held_for_review" };

/** Refusals a duplicate may be evaluated again for (spec 10.2). */
const RETRYABLE_REFUSALS: readonly ErrorCode[] = ["rate_limited", "thread_state", "internal"];

/** Store keys of the replay window and of the receipts this broker issued, per (origin_broker, id). */
export const replayKey = (origin: string, id: string): string => `seen|${origin}|${id}`;
export const receiptKey = (origin: string, id: string): string => `${origin}|${id}`;
/** Store key of the mark an envelope carries while it is being evaluated (spec 10.3). */
export const inFlightKey = (origin: string, id: string): string => `inflight|${origin}|${id}`;

/** ack, decline and error carry only ids and enums; they need no `may` (spec 6.6), so either side can always close or decline. */
const PLUMBING: readonly MessageType[] = ["ack", "decline", "error"];

/** Retry-After, in seconds, for a reply whose message this broker doesn't hold yet (spec 9.3, 10.2). */
const REPLY_RETRY_SECONDS = 2;

/** `thread` reads a thread's records newest first, this many at a time, and at most THREAD_READ_MAX of them. */
const THREAD_READ_BATCH = 250;
const THREAD_READ_MAX = 4 * (MAX_THREAD_MESSAGES + 1) + THREAD_READ_BATCH;

/** At most this many of a refusal's reasons go in its ledger entry's payload, and about this many characters of them. */
export const LEDGER_REASONS = 64;
export const LEDGER_REASON_CHARS = 32_768;

/**
 * The reasons a refusal's ledger entry keeps (spec 6.6, 6.7: pointers and rule ids, never values): the first ones, up to
 * LEDGER_REASONS and LEDGER_REASON_CHARS (the first always), then one more that counts the rest. A draft with thousands
 * of refused fields writes an entry of bounded size; the entry is written either way.
 */
export function ledgerReasons(code: ErrorCode, reasons: readonly Reason[]): Reason[] {
  const kept: Reason[] = [];
  let chars = 0;
  for (const r of reasons) {
    const size = 32 + (r.pointer?.length ?? 0) + (r.detail?.length ?? 0) + (r.rule?.length ?? 0);
    if (kept.length >= LEDGER_REASONS || (kept.length > 0 && chars + size > LEDGER_REASON_CHARS)) break;
    kept.push(r);
    chars += size;
  }
  const rest = reasons.length - kept.length;
  return rest > 0 ? [...kept, { code, detail: `${rest} more ${rest === 1 ? "reason" : "reasons"}, not recorded` }] : kept;
}

function sealMethod(caller: HumanCaller): SealMethod {
  return caller.auth?.method ?? "reauth-dev";
}

/**
 * Whether `d` is still the binding a held message was written by, or for (spec 5.4): active, and the same binding as
 * when it was held. `since` is that binding's start, recorded with the message; a record written before it was
 * recorded falls back to "the binding started no later than the message was held".
 */
function sameBinding(d: DelegateRecord | null, since: string | undefined, heldAt: string): boolean {
  if (!d || d.status !== "active") return false;
  return since !== undefined ? d.created_at === since : Date.parse(d.created_at) <= Date.parse(heldAt);
}

/** What an approved held message's send answered when it didn't deliver it (null when it did), for the held record. */
function releaseFailure(r: SendResult): HeldOutbound["result"] | null {
  switch (r.status) {
    case "delivered":
      return null;
    case "needs_ratification":
      return { status: r.status, code: "needs_ratification" };
    case "held_for_review":
      // An approved message is evaluated again but never held again (`released`); this can't happen.
      return { status: "rejected", code: "internal" };
    default:
      return { status: r.status, code: r.code };
  }
}

/**
 * Which notification a message accepted for this person brings them (spec 6.7, 12.5.1), if any: an `ask_human`, a
 * message held for their web view because of their agents, or any message for a person whose agent has no connector.
 */
function noticeOf(recipient: PrincipalRecord, env: Envelope, heldReason: MessageRecord["held_reason"]): "ask_human" | "message_held" | "message_waiting" | null {
  if (env.type === "ask_human") return "ask_human";
  if (heldReason !== undefined) return "message_held";
  return recipient.human_fallback ? "message_waiting" : null;
}

/** What an approved held message's send answered, as the held record and the `released` ledger entry keep it. */
interface ReleaseOutcome {
  record: HeldOutbound;
  entry: LedgerFields;
}

function releaseOutcome(rec: HeldOutbound, result: SendResult, decidedAt: string): ReleaseOutcome {
  // The envelope id only when the broker signed the envelope (a `sent` ledger entry names it).
  const envelopeId = result.status === "delivered" ? result.envelope.id : result.status === "refused" || result.status === "undeliverable" ? result.envelope_id : undefined;
  const failure = releaseFailure(result);
  return {
    record: { ...rec, state: failure ? "refused" : "sent", decided_at: decidedAt, ...(envelopeId ? { envelope_id: envelopeId } : {}), ...(failure ? { result: failure } : {}) },
    entry: { kind: "released", counterparty: rec.to, scope: rec.scope, type: rec.type, thread: rec.thread, outcome: failure ? "refused" : "accepted", ...(failure ? { code: failure.code } : {}), ...(envelopeId ? { envelope_id: envelopeId } : {}), ref: rec.id },
  };
}

export class Broker implements BrokerApi {
  readonly id: BrokerId;
  readonly store: Store;
  readonly keys: KeyRing;
  readonly scopes: ScopeRegistry;
  readonly limits: BrokerLimits;
  readonly links: LinkBuilder;
  private readonly domains: Set<string>;
  private readonly policies = new Map<string, OrgPolicy>();
  private readonly resolver: DomainResolver;
  private readonly transport: FederationTransport;
  private readonly notifier: Notifier;
  private readonly events: SecurityEventSink | undefined;
  private readonly clock: Clock;
  private readonly ids: IdSource;
  private readonly dlp: DlpHook;
  private readonly pusher: AgentPush | undefined;
  private readonly strangerToRequest: boolean;
  private readonly constraintSupport: { deliver_to?: boolean; no_training?: boolean; retention_max?: boolean };
  private readonly background: (task: () => Promise<void>) => void;
  private readonly onBackgroundError: (err: unknown) => void;
  /** Background work handed out and not finished yet (`settled`). */
  private readonly pending = new Set<Promise<void>>();
  /** Security events the sink or the schema refused since start (`securityEventsDropped`), and when stderr last said so. */
  private droppedEvents = 0;
  private droppedNoticeAt = Number.NEGATIVE_INFINITY;
  /**
   * Work held back until the outermost call on this broker has answered: a message between two of its own principals
   * is accepted inside the sender's own call, whose answer must not wait for, or overlap, the recipient's work either.
   */
  private readonly answering = new AsyncLocalStorage<(() => Promise<void>)[]>();

  constructor(opts: BrokerOptions) {
    this.id = opts.id;
    this.store = opts.store;
    this.keys = opts.keys;
    this.resolver = opts.resolver;
    this.transport = opts.transport;
    this.notifier = opts.notifier;
    this.events = opts.securityEvents;
    this.clock = opts.clock ?? systemClock;
    this.ids = new IdSource(this.clock);
    this.scopes = opts.scopes ?? ScopeRegistry.load();
    this.dlp = opts.dlp ?? new SampleDlp();
    this.pusher = opts.push;
    this.limits = { ...DEFAULT_LIMITS, ...opts.limits };
    this.links = opts.links ?? webLinks(opts.webBaseUrl ?? `${opts.id}/web`);
    this.strangerToRequest = opts.strangerMessagesBecomeRequests ?? true;
    this.constraintSupport = opts.constraintSupport ?? {};
    this.background = opts.background ?? ((task) => void setImmediate(() => void task()));
    this.onBackgroundError = opts.onBackgroundError ?? ((err) => console.error(`broker: work after an answer failed: ${errMessage(err)}`));
    for (const p of opts.policies ?? []) this.installPolicy(checkOrgPolicy(structuredClone(p)));
    this.domains = new Set(opts.domains ?? [...this.policies.keys()]);
  }

  jwks(): Jwks {
    return this.keys.jwks();
  }

  /** Resolves once the work handed to `background` so far has finished (tests, and a host shutting down). */
  async settled(): Promise<void> {
    while (this.pending.size > 0) await Promise.all([...this.pending]);
  }

  /**
   * Runs `fn` as one answer to a caller: work `afterAnswering` gets meanwhile (spec 6.7: the person's notice and the
   * pushes for a message this broker accepted) is handed out only once `fn` has returned; a call inside joins it. The
   * broker's own entry points run this way. A binding with work of its own after the broker's call (an idempotency
   * record, the result) runs its whole call in one, so that work for a message between two of this broker's people
   * never runs inside the sender's call.
   */
  async asOneAnswer<T>(fn: () => Promise<T>): Promise<T> {
    if (this.answering.getStore()) return fn();
    const queue: (() => Promise<void>)[] = [];
    try {
      return await this.answering.run(queue, fn);
    } finally {
      for (const task of queue) this.handOut(task);
    }
  }

  /** Work to do once the current answer is out (spec 6.7); never throws, and a failure goes to `onBackgroundError`. */
  private afterAnswering(task: () => Promise<void>): void {
    const queue = this.answering.getStore();
    if (queue) queue.push(task);
    else this.handOut(task);
  }

  /** Hands work to `background`, tracked for `settled`. False when `background` refused it (the work won't run). */
  private handOut(task: () => Promise<void>): boolean {
    let finish = (): void => undefined;
    const done = new Promise<void>((resolve) => {
      finish = resolve;
    });
    this.pending.add(done);
    const end = (): void => {
      this.pending.delete(done);
      finish();
    };
    const run = async (): Promise<void> => {
      try {
        await task();
      } catch (err) {
        this.reportBackgroundError(err);
      } finally {
        end();
      }
    };
    try {
      this.background(run);
      return true;
    } catch (err) {
      this.reportBackgroundError(err);
      end();
      return false;
    }
  }

  /** Gives a failure of work done after an answer to `onBackgroundError`; reporting a failure must not fail. */
  private reportBackgroundError(err: unknown): void {
    try {
      this.onBackgroundError(err);
    } catch {
      // nothing more to do
    }
  }

  // =========================================================================================
  // Registration

  async registerPrincipal(input: RegisterPrincipalInput): Promise<PrincipalRecord> {
    const address = parseAddress(input.address);
    if (!this.domains.has(domainOf(address))) throw new AlpError("invalid_input", `this broker does not host ${domainOf(address)}`);
    if (!input.identity?.iss || !input.identity?.sub) throw new AlpError("invalid_input", "a principal binds to the IdP's iss and sub");
    const now = iso(this.clock.now());
    const byIdentity = await this.store.getPrincipalByIdentity(input.identity.iss, input.identity.sub);
    const byAddress = await this.store.getPrincipal(address);
    if (byAddress && (byAddress.identity.iss !== input.identity.iss || byAddress.identity.sub !== input.identity.sub)) {
      // The address now belongs to another person (spec 5.2): first end the old principal's relationships, then
      // retire it; the new one gets a new id and inherits nothing.
      await this.endRelationships(byAddress, this.clock.now());
      await this.store.putPrincipal({ ...byAddress, status: "retired" });
    }
    const base = byIdentity && byIdentity.status !== "retired" ? byIdentity : null;
    const pick = <K extends keyof PrincipalRecord>(k: K, v: PrincipalRecord[K] | undefined): Partial<PrincipalRecord> => {
      const value = v ?? base?.[k];
      return value === undefined ? {} : ({ [k]: value } as Partial<PrincipalRecord>);
    };
    const rec: PrincipalRecord = {
      principal_id: base?.principal_id ?? randomBytes(18).toString("base64url"),
      address,
      identity: { iss: input.identity.iss, sub: input.identity.sub },
      status: base?.status ?? "active",
      created_at: base?.created_at ?? now,
      ...pick("display_name", input.display_name),
      ...pick("contact", input.contact),
      ...pick("human_fallback", input.human_fallback),
      ...pick("claims", input.claims),
    };
    await this.store.putPrincipal(rec);
    return rec;
  }

  async registerDelegate(input: RegisterDelegateInput): Promise<DelegateRecord> {
    const principal = await this.store.getPrincipal(parseAddress(input.principal));
    if (!principal || principal.status !== "active") throw new AlpError("identity_mismatch", "register the principal first", { status: 404 });
    const label = input.label.trim().toLowerCase();
    if (!isDelegateLabel(label) || RESERVED_DELEGATE_LABELS.includes(label)) throw new AlpError("invalid_input", `invalid or reserved delegate label: ${JSON.stringify(input.label)}`);
    if (!input.client_id) throw new AlpError("invalid_input", "a delegate records its client_id");
    const rule = clientRule(this.policyFor(principal.address), input.client_id);
    const id = delegateIdOf(principal.address, label);
    const existing = await this.store.getDelegate(id);
    // The binding's start (spec 5.4): the same client signing in again for the same person while its binding is
    // active keeps it. Anything else with this label is a new binding (a label taken again after a disconnection, or
    // given to another client), which reads nothing addressed to, or sent by, the earlier one.
    const same = existing !== null && existing.status === "active" && existing.client_id === input.client_id && existing.principal_id === principal.principal_id;
    const rec: DelegateRecord = {
      id,
      principal: principal.address,
      principal_id: principal.principal_id,
      label,
      kind: input.kind ?? existing?.kind ?? "bridged",
      client_id: input.client_id,
      // The org's client rule is authoritative; otherwise what the binding attests, else the lowest. A personal access
      // token is never recorded above `self` and `business`, whatever the list says (spec 5.7).
      attestation: input.client_id === PAT_CLIENT_ID ? "self" : rule?.attestation ?? input.attestation ?? "self",
      class: input.client_id === PAT_CLIENT_ID ? lowerClass(rule?.class ?? input.class ?? "consumer", "business") : rule?.class ?? input.class ?? "consumer",
      status: "active",
      created_at: same ? existing.created_at : iso(this.clock.now()),
    };
    await this.store.putDelegate(rec);
    return rec;
  }

  async revokeDelegate(id: DelegateId): Promise<DelegateRecord> {
    const rec = await this.store.getDelegate(id.toLowerCase());
    if (!rec) throw new AlpError("invalid_input", "no such delegate", { status: 404 });
    const next: DelegateRecord = { ...rec, status: "revoked" };
    await this.store.putDelegate(next);
    return next;
  }

  async getPrincipal(address: string): Promise<PrincipalRecord | null> {
    return this.store.getPrincipal(parseAddress(address));
  }

  // =========================================================================================
  // Agent-facing

  async whoami(caller: DelegateCaller): Promise<WhoAmI> {
    const { principal, delegate } = await this.authReader(caller);
    return {
      principal: principal.address,
      principal_id: principal.principal_id,
      display: displayAddress(principal.address),
      ...(principal.display_name ? { display_name: principal.display_name } : {}),
      delegate: delegate.id,
      client_id: delegate.client_id,
      attestation: delegate.attestation,
      class: delegate.class,
      broker: this.id,
      mode: delegate.kind === "native" ? "native" : "client",
    };
  }

  async contacts(caller: DelegateCaller): Promise<Contact[]> {
    const { principal } = await this.authReader(caller);
    const out: Contact[] = [];
    for (const g of await this.store.listGrants(principal.address)) {
      if (g.status !== "active" || g.basis !== "consent" || g.principal_id !== principal.principal_id) continue;
      const rev = await this.store.getRevocation(principal.address, g.counterparty);
      out.push({
        address: g.counterparty,
        display: displayAddress(g.counterparty),
        basis: "grant",
        scopes: Object.entries(g.scopes).map(([scope, t]) => ({ scope, may: [...t.may] })),
        status: rev ? "counterparty_revoked" : "active",
      });
    }
    const policy = this.policyFor(principal.address);
    if (policy) {
      for (const rel of policy.default_relationships ?? []) {
        if (!anyRefMatches(policy, rel.from, principal.address, this.claimsFor([principal]))) continue;
        for (const ref of rel.to) {
          const pattern = ref === "@org" ? policy.domains.map((d) => `*@${d}`).join(", ") : ref.includes(":*@") ? `*@${ref.slice(ref.indexOf("@") + 1)}` : ref;
          out.push({
            address: pattern,
            display: pattern.includes("@") && !pattern.startsWith("*") ? displayAddress(pattern) : pattern,
            basis: "org_default",
            scopes: Object.entries(rel.scopes).map(([scope, t]) => ({ scope, may: [...t.forward.may] })),
            status: "active",
          });
        }
      }
    }
    const now = this.clock.now();
    for (const c of await this.connectionsOf(principal)) {
      if (c.direction !== "outgoing" || expireConnectionIfDue(c, now).state !== "pending") continue;
      out.push({ address: c.counterparty, display: displayAddress(c.counterparty), basis: "pending_outgoing", scopes: c.scopes.map((scope) => ({ scope, may: [] })), status: "pending" });
    }
    return out;
  }

  async send(caller: DelegateCaller, input: SendInput, opts: { onSent?: (envelopeId: string) => void } = {}): Promise<SendResult> {
    return this.asOneAnswer(() => this.sendNow(caller, input, opts.onSent));
  }

  private async sendNow(caller: DelegateCaller, input: SendInput, onSent?: (envelopeId: string) => void): Promise<SendResult> {
    const { principal, delegate } = await this.authDelegate(caller);
    const reject = async (code: ErrorCode, detail: string): Promise<SendResult> => {
      const reasons: Reason[] = [{ code, detail }];
      await this.log(principal, { kind: "refused_outbound", outcome: "rejected", code, delegate: delegate.id, client_id: delegate.client_id }, { detail: ledgerReasons(code, reasons) });
      return { status: "rejected", stage: "sender", code, reasons };
    };
    const claim = this.checkClaim(principal, input);
    // Spec 5.1: a send whose `from` claims another principal is refused and logged as a security event, which names
    // the caller (principal, delegate, client), never the address it claimed or anything of the message.
    if (claim?.code === "identity_mismatch") await this.securityEvent("token_refused", { failed: true, message: "a send claimed another principal", details: { code: "identity_mismatch", principal_id: principal.principal_id, delegate: delegate.id, client_id: delegate.client_id.slice(0, 2048) } });
    if (claim) return reject(claim.code, claim.detail);
    return this.sendAs(principal, this.draftOf(delegate, input), onSent);
  }

  /**
   * The sender-side evaluation (spec 6.6, S1 to S8) of a draft, without sending, signing, writing the ledger or
   * counting it against a rate limit. `send` runs the same steps. `skipThreadChecks` leaves out S3, as the
   * sender-side conformance vectors do (vectors/policy/sender.json).
   */
  async evaluateSend(caller: DelegateCaller, input: SendInput, opts: { skipThreadChecks?: boolean } = {}): Promise<SendDecision> {
    const { principal, delegate } = await this.authDelegate(caller);
    const claim = this.checkClaim(principal, input);
    if (claim) return { outcome: "rejected", code: claim.code };
    const prep = await this.prepareSend(principal, this.draftOf(delegate, input), opts);
    if (prep.kind === "rejected") return { outcome: "rejected", code: prep.code, ...rejectionDetail(prep.reasons, prep.code) };
    if (prep.kind === "needs_ratification") return { outcome: "rejected", code: "needs_ratification" };
    const ev = prep.ev;
    return {
      outcome: ev.outcome === "redact" ? "redacted" : "allowed",
      grant: prep.terms.ref,
      labels: ev.labels,
      redacted: ev.redacted,
      ...(ev.outcome === "redact" ? { body: ev.body } : {}),
      policy_ids: ev.policy_ids,
      ...(prep.constraints ? { constraints: prep.constraints } : {}),
      status: prep.hold ? "held_for_review" : "queued",
    };
  }

  private checkClaim(principal: PrincipalRecord, input: SendInput): { code: ErrorCode; detail: string } | null {
    if (input.from !== undefined) {
      let claimed: Address | null = null;
      try {
        claimed = parseAddress(input.from);
      } catch {
        claimed = null;
      }
      if (claimed !== principal.address) return { code: "identity_mismatch", detail: "the sender is the signed-in principal; a payload cannot claim another" };
    }
    if (!isMessageType(input.type)) return { code: "unknown_type", detail: "use requestConnection for connection requests" };
    if (!input.body || typeof input.body !== "object" || Array.isArray(input.body)) return { code: "invalid_input", detail: "body must be an object" };
    if (input.labels !== undefined) {
      if (!Array.isArray(input.labels) || input.labels.length > this.limits.maxAddedLabels || input.labels.some((l) => typeof l !== "string")) {
        return { code: "invalid_input", detail: `labels lists at most ${this.limits.maxAddedLabels} labels to add` };
      }
      // Spec 6.5: an added label must be one the rules name exactly. A label the agent could make up, even below a
      // pattern such as confidential.*, would carry data no grant, policy or DLP covers.
      const vocabulary = this.labelVocabulary(principal.address, typeof input.scope === "string" ? input.scope : "", "added");
      const unknown = input.labels.filter((l) => !vocabulary.has(l));
      if (unknown.length) return { code: "invalid_input", detail: `labels must be ones the scope's classification or your organization's rules name exactly; not known: ${unknown.length} label${unknown.length === 1 ? "" : "s"}` };
    }
    return null;
  }

  /**
   * The labels this side knows (spec 6.5): those the scope's classification map uses, those the organization's
   * overrides, classification rules and delivery minimums name, and the baseline `public`, `internal`, `confidential`
   * and `restricted`. `added`: what a delegate may add, only labels named exactly (a pattern `x.*` names `x`, never a
   * label below it). `known`: what a recipient keeps of the sender's labels, also any label below a named pattern.
   */
  labelVocabulary(owner: Address, scopeId: string, mode: "added" | "known"): { has(label: string): boolean } {
    const exact = new Set<string>(["public", "internal", "confidential", "restricted"]);
    const prefixes: string[] = [];
    const add = (l: string): void => {
      if (l === "*") return;
      if (l.endsWith(".*")) {
        exact.add(l.slice(0, -2));
        if (mode === "known") prefixes.push(l.slice(0, -2));
      } else exact.add(l);
    };
    const scope = this.scopes.get(scopeId);
    if (scope) for (const [, labels] of scope.classification) for (const l of labels) add(l);
    const policy = this.policyFor(owner);
    for (const r of policy?.classification?.rules ?? []) for (const l of r.labels) add(l);
    for (const byScope of Object.values(policy?.classification?.overrides ?? {})) for (const labels of Object.values(byScope)) for (const l of labels) add(l);
    for (const m of policy?.delivery_minimums ?? []) for (const l of m.labels) add(l);
    return { has: (label: string) => exact.has(label) || prefixes.some((p) => label.startsWith(`${p}.`)) };
  }

  private draftOf(delegate: DelegateRecord, input: SendInput): Draft {
    return {
      delegate,
      to: input.to,
      scope: input.scope,
      type: input.type,
      body: input.body,
      ...(input.to_delegate !== undefined ? { to_delegate: input.to_delegate } : {}),
      ...(input.note !== undefined ? { note: input.note } : {}),
      ...(input.thread !== undefined ? { thread: input.thread } : {}),
      ...(input.in_reply_to !== undefined ? { in_reply_to: input.in_reply_to } : {}),
      ...(input.expires_in_seconds !== undefined ? { expires_in_seconds: input.expires_in_seconds } : {}),
      ...(input.labels !== undefined && input.labels.length ? { labels: input.labels } : {}),
    };
  }

  async inbox(caller: DelegateCaller, query: InboxQuery = {}): Promise<InboxPage> {
    const { principal, delegate } = await this.authReader(caller);
    return this.page(principal, query, {
      forDelegate: delegate.id,
      ...(query.include_acked ? {} : { unackedBy: delegate.id }),
      // Spec 5.4: what was addressed to, or acknowledged by, an earlier binding with this label isn't this agent's.
      bindingSince: delegate.created_at,
      // Delivery constraints: an agent sees only what it qualifies for; the rest waits for the person. A message
      // held for quiet hours appears once they end.
      filter: (m) => this.visibleTo(principal, delegate, m),
    });
  }

  /**
   * What one agent may read (spec 6.11, 6.14, 12.1.4), the same rule for the inbox, threads and acks, whatever the
   * binding: received messages addressed to the person or to this agent, not held, whose delivery constraints the
   * agent meets; the agent's own sent messages; and the messages the broker itself sent for the person (ratification
   * acks and declines). Never another of the person's agents' sent messages: those reach this agent, if at all, as
   * received messages, checked like any other. Nor what was addressed to, or sent by, an earlier binding with this
   * agent's label (spec 5.4).
   */
  private visibleTo(principal: PrincipalRecord, delegate: DelegateRecord, m: MessageRecord): boolean {
    const reader = { id: delegate.id, attestation: delegate.attestation, class: delegate.class, since: delegate.created_at };
    return this.owns(principal, m) && agentMayRead(m, reader, clientRule(this.policyFor(principal.address), delegate.client_id), this.clock.now());
  }

  /** The ids among `ids` of received messages this agent may read (the client binding's ack checks them). */
  async visibleInbound(caller: DelegateCaller, ids: readonly string[]): Promise<string[]> {
    const { principal, delegate } = await this.authReader(caller);
    const out: string[] = [];
    for (const id of ids) {
      if (!isUlid(id)) continue;
      const m = await this.store.getMessage(principal.address, "in", id);
      if (m && this.visibleTo(principal, delegate, m)) out.push(id);
    }
    return out;
  }

  async ack(caller: DelegateCaller, input: { envelope_ids: string[] }): Promise<{ acked: number }> {
    const { principal, delegate } = await this.authReader(caller);
    if (!Array.isArray(input.envelope_ids) || input.envelope_ids.length > 500) throw new AlpError("invalid_input", "envelope_ids must list at most 500 ids");
    let acked = 0;
    const at = iso(this.clock.now());
    for (const id of input.envelope_ids) {
      if (!isUlid(id)) continue;
      const m = await this.store.getMessage(principal.address, "in", id);
      if (!m || !this.visibleTo(principal, delegate, m) || ackedBy(m, delegate.id, delegate.created_at)) continue;
      await this.store.putMessage({ ...m, acked_by: { ...m.acked_by, [delegate.id]: at } });
      acked++;
    }
    return { acked };
  }

  /**
   * One thread and every message of it this agent may read (spec 12.1.4), oldest first. The records are read newest
   * first, so the newest are always there: a thread holds at most MAX_THREAD_MESSAGES messages (one person's own
   * agents' copy keeps two records of each), and at most THREAD_READ_MAX records are read.
   */
  async thread(caller: DelegateCaller, threadId: string): Promise<ThreadView> {
    const { principal, delegate } = await this.authReader(caller);
    if (!isUlid(threadId)) throw new AlpError("invalid_input", "bad thread id");
    const stored = await this.store.getThread(principal.address, threadId);
    if (!stored || !this.owns(principal, stored)) throw new AlpError("thread_state", "no such thread", { status: 404 });
    const thread = expireIfDue(stored, this.clock.now());
    if (thread !== stored) await this.store.putThread(thread);
    const records: MessageRecord[] = [];
    let before: string | undefined;
    while (records.length < THREAD_READ_MAX) {
      const batch = await this.store.listMessages(principal.address, { thread: threadId, order: "desc", limit: Math.min(THREAD_READ_BATCH, THREAD_READ_MAX - records.length), ...(before !== undefined ? { before } : {}) });
      records.push(...batch);
      const last = batch[batch.length - 1];
      if (!last || batch.length < THREAD_READ_BATCH) break;
      before = last.local_id;
    }
    const visible = records.filter((m) => this.visibleTo(principal, delegate, m)).reverse();
    return { thread, messages: visible.map((m) => ({ local_id: m.local_id, direction: m.direction, status: m.status, envelope: m.envelope })) };
  }

  async requestConnection(caller: Caller, input: ConnectionRequestInput): Promise<ConnectionRequestResult> {
    const now = this.clock.now();
    const human = caller.kind === "human";
    const principal = human ? await this.authHuman(caller, true) : (await this.authDelegate(caller)).principal;
    const delegate = human ? null : (await this.authDelegate(caller)).delegate;
    const to = parseAddress(input.to);
    if (to === principal.address) throw new AlpError("invalid_input", "cannot connect to yourself");
    if (!Array.isArray(input.scopes) || input.scopes.length === 0 || input.scopes.length > 10) throw new AlpError("invalid_input", "ask for between 1 and 10 scopes");
    const scopes = [...new Set(input.scopes)];
    if (input.terms !== undefined && !human) throw new AlpError("identity_mismatch", "only the person can set terms; an agent's request uses the scope's suggested fields", { status: 403 });
    const terms: Record<ScopeId, ScopeTerms> = {};
    for (const s of scopes) {
      const scope = this.scopes.require(s);
      const t = input.terms?.[s] ?? defaultScopeTerms(scope);
      checkScopeTerms(t, scope);
      terms[s] = t;
    }
    const policy = this.policyFor(principal.address);
    if (input.note !== undefined) {
      if ([...input.note].length > this.limits.controlNoteMaxChars) throw new AlpError("schema_invalid", `the note is limited to ${this.limits.controlNoteMaxChars} characters`);
      const v = await runDlp(this.dlp, { principal_id: principal.principal_id, principal: principal.address, counterparty: to, direction: "outbound", scope: scopes[0] as string, labels: ["note"], pointer: "/note", text: input.note });
      if (v.verdict !== "allow" && v.verdict !== "notify") return { status: "rejected", code: "dlp_blocked", reasons: [{ code: "dlp_blocked", pointer: "/note" }] };
    }
    if (!federationAllows(policy, domainOf(to))) return { status: "rejected", code: "federation_blocked", reasons: [{ code: "federation_blocked", rule: "federation" }] };
    const killed = blockedBy(policy, { principals: [principal.address, to], domains: [domainOf(to)], ...(delegate ? { delegate: delegate.id, client_id: delegate.client_id } : {}) });
    if (killed) return { status: "rejected", code: "blocked", reasons: [{ code: "blocked", rule: killed }] };
    const pending = (await this.connectionsOf(principal)).find((c) => c.direction === "outgoing" && c.counterparty === to && expireConnectionIfDue(c, now).state === "pending");
    if (pending) return { status: "already_pending", request: pending };
    const outgoing = await this.store.hitRateLimit(`conn-out|${principal.principal_id}`, now, 86400, this.limits.outgoingConnectionRequestsPerDay);
    if (!outgoing.allowed) {
      return { status: "rejected", code: "rate_limited", reasons: [{ code: "rate_limited", detail: `too many connection requests today; retry after ${outgoing.retryAfter} seconds` }], retry_after: outgoing.retryAfter };
    }
    // An address on a domain this broker is home for that nobody holds is still "delivered" here and answered like
    // any other (spec 6.2.2): a shared broker never tells a requester which addresses exist.
    const home = await this.homeOf(to);
    if (home.kind === "none") return { status: "undeliverable", code: home.code, detail: home.detail };
    const env = await this.buildControl(principal, delegate, to, home, "connection_request",
      { scopes, purpose: input.purpose, ...(principal.display_name ? { display_name: principal.display_name.slice(0, 64) } : {}) },
      input.note !== undefined ? { note: input.note } : {});
    const hash = objectHash(env);
    const outcome = await this.deliverAndVerify(env, home);
    const base: LedgerFields = {
      kind: "connection_requested",
      counterparty: to,
      counterparty_broker: home.kind === "remote" ? home.entry.id : this.id,
      envelope_id: env.id,
      type: "connection_request",
      outcome: "info",
      envelope_hash: hash,
      ...(delegate ? { delegate: delegate.id, client_id: delegate.client_id } : {}),
    };
    if (outcome.kind === "failed") {
      await this.log(principal, { ...base, kind: "delivery_failed", outcome: "refused", code: outcome.code });
      return { status: "undeliverable", code: outcome.code, detail: outcome.detail };
    }
    if (outcome.receipt.status !== "accepted") {
      const code = outcome.receipt.code ?? "not_accepted";
      await this.log(principal, { ...base, outcome: "refused", code, receipt_hash: outcome.hash });
      return { status: "rejected", code, reasons: [{ code }], receipt: outcome.receipt };
    }
    const rec: ConnectionRequestRecord = {
      id: env.id,
      direction: "outgoing",
      principal: principal.address,
      principal_id: principal.principal_id,
      counterparty: to,
      scopes,
      purpose: input.purpose,
      ...(input.note !== undefined ? { note: input.note } : {}),
      state: "pending",
      origin: "explicit",
      requester_terms: terms,
      ...(human ? { requester_sealed: { method: sealMethod(caller), at: iso(now) } } : {}),
      remote_broker: home.kind === "remote" ? home.entry.id : this.id,
      envelope_hash: hash,
      created_at: iso(now),
      updated_at: iso(now),
      expires_at: iso(addSeconds(now, this.limits.connectionTtlSeconds)),
    };
    await this.store.putConnection(rec);
    await this.log(principal, { ...base, outcome: "delivered", ref: rec.id, receipt_hash: outcome.hash, ...(outcome.receipt.ledger_hash ? { counterparty_ledger_hash: outcome.receipt.ledger_hash } : {}) }, input.note !== undefined ? { note: input.note } : undefined);
    return { status: "requested", request: rec, receipt: outcome.receipt };
  }

  // =========================================================================================
  // Human-facing

  async messagesForPerson(caller: HumanCaller, query: InboxQuery = {}): Promise<InboxPage> {
    const principal = await this.authHuman(caller);
    return this.page(principal, query, {});
  }

  async listConnections(caller: HumanCaller): Promise<ConnectionRequestRecord[]> {
    const principal = await this.authHuman(caller);
    const now = this.clock.now();
    return (await this.connectionsOf(principal)).map((c) => expireConnectionIfDue(c, now));
  }

  async respondToConnection(caller: HumanCaller, input: ConnectionResponseInput): Promise<ConnectionRequestRecord> {
    const principal = await this.authHuman(caller, true);
    const now = this.clock.now();
    const stored = await this.store.getConnection(principal.address, input.request);
    if (!stored || stored.direction !== "incoming" || !this.owns(principal, stored)) throw new AlpError("invalid_input", "no such connection request", { status: 404 });
    let rec: ConnectionRequestRecord;
    let approved: ScopeId[] = [];
    if (input.decision === "approve") {
      approved = (input.scopes ?? stored.scopes).filter((s) => stored.scopes.includes(s));
      if (approved.length === 0) throw new AlpError("invalid_input", "approve at least one of the requested scopes");
      rec = transitionConnection(stored, "approved", now, { approved_scopes: approved });
      const scopes: Record<ScopeId, ScopeTerms> = {};
      for (const s of approved) {
        const scope = this.scopes.require(s);
        const t = input.terms?.[s] ?? defaultScopeTerms(scope);
        checkScopeTerms(t, scope);
        scopes[s] = t;
      }
      await this.mergeGrant(principal, stored.counterparty, stored.counterparty_principal_id, scopes, caller, rec.id, now);
    } else {
      rec = transitionConnection(stored, "declined", now);
    }
    await this.store.putConnection(rec);
    await this.log(principal, { kind: "connection_decided", counterparty: rec.counterparty, outcome: rec.state === "approved" ? "accepted" : "refused", ref: rec.id });
    const home = await this.homeOf(rec.counterparty);
    if (home.kind !== "none" && stored.envelope_hash) {
      const env = await this.buildControl(principal, null, rec.counterparty, home, "connection_response",
        { of: rec.id, decision: rec.state === "approved" ? "accepted" : "declined", ...(approved.length ? { scopes: approved } : {}) },
        { in_reply_to: rec.id, in_reply_to_hash: stored.envelope_hash });
      const outcome = await this.deliverAndVerify(env, home);
      if (outcome.kind === "failed") await this.log(principal, { kind: "delivery_failed", counterparty: rec.counterparty, envelope_id: env.id, type: "connection_response", outcome: "refused", code: outcome.code });
    }
    return rec;
  }

  /** Outbound messages waiting for this person's review (spec 6.12). */
  async listHeld(caller: HumanCaller): Promise<HeldOutbound[]> {
    const principal = await this.authHuman(caller);
    const now = this.clock.now();
    return (await this.store.listHeldOutbound(principal.address)).filter((h) => this.owns(principal, h)).map((h) => (h.state === "pending" && Date.parse(h.expires_at) <= now.getTime() ? { ...h, state: "expired" as const } : h));
  }

  /**
   * Whether a held message can still go out as written (spec 5.4): `writer` when the agent that wrote it, and `target`
   * when the one of the person's own agents it is for, was disconnected since, its label perhaps taken by a new
   * agent. Such a message can only be discarded: sending it would hand it to, or send it as, another agent.
   */
  async heldBindingChanged(h: HeldOutbound): Promise<"writer" | "target" | null> {
    if (h.delegate) {
      const writer = await this.store.getDelegate(h.delegate);
      if (!sameBinding(writer, h.delegate_since, h.created_at)) return "writer";
    }
    if (h.to_delegate && h.to === h.principal) {
      const target = await this.store.getDelegate(h.to_delegate);
      if (!sameBinding(target, h.to_delegate_since, h.created_at)) return "target";
    }
    return null;
  }

  /**
   * The person approves or discards a held message, with a fresh sign-in. On approval the broker evaluates it again
   * in full (the rules may have changed), then signs and sends it; on discard nothing leaves. Either way the ledger
   * gets a `released` entry, and the held record keeps the outcome: `sent`, or `refused` with what sending answered.
   * The record leaves `pending` in one atomic step (`claimHeldOutbound`), so of two decisions at once only one acts.
   */
  async reviewHeld(caller: HumanCaller, input: { held: string; decision: "send" | "discard" }): Promise<SendResult | { status: "discarded"; held: string }> {
    return this.asOneAnswer(() => this.reviewHeldNow(caller, input));
  }

  private async reviewHeldNow(caller: HumanCaller, input: { held: string; decision: "send" | "discard" }): Promise<SendResult | { status: "discarded"; held: string }> {
    const principal = await this.authHuman(caller, true);
    const now = this.clock.now();
    const rec = await this.store.getHeldOutbound(principal.address, input.held);
    if (!rec || !this.owns(principal, rec)) throw new AlpError("invalid_input", "no such held message", { status: 404 });
    const taken = (): AlpError => new AlpError("invalid_input", "this message was already decided", { status: 409 });
    if (rec.state !== "pending") throw new AlpError("invalid_input", rec.state === "sending" ? "this message is being sent" : `this message was already ${rec.state}`, { status: 409 });
    if (Date.parse(rec.expires_at) <= now.getTime()) {
      await this.store.claimHeldOutbound({ ...rec, state: "expired", decided_at: iso(now) });
      throw new AlpError("expired", "this held message expired", { status: 409 });
    }
    if (input.decision === "discard") {
      if (!(await this.store.claimHeldOutbound({ ...rec, state: "discarded", decided_at: iso(now) }))) throw taken();
      await this.log(principal, { kind: "released", counterparty: rec.to, scope: rec.scope, type: rec.type, thread: rec.thread, outcome: "rejected", ref: rec.id });
      return { status: "discarded", held: rec.id };
    }
    // Only the binding that wrote it, and only to the binding it was for: an agent that took either label after a
    // disconnection is another agent (spec 5.4).
    const changed = await this.heldBindingChanged(rec);
    if (changed === "writer") throw new AlpError("identity_mismatch", "the agent that wrote this message was disconnected", { status: 409 });
    if (changed === "target") throw new AlpError("identity_mismatch", "the agent this message is for was disconnected; it can't go to an agent connected since", { status: 409 });
    const stored = rec.delegate ? await this.store.getDelegate(rec.delegate) : null;
    const delegate = stored ? this.ranked(stored) : null;
    // From here on this call alone sends it (`sending`), and it leaves `sending` with what this broker knows, also when
    // something fails on the way (releaseFailed). Only a broker that stops before then leaves it `sending`: the person
    // can't send it twice, and the ledger shows whether it went.
    if (!(await this.store.claimHeldOutbound({ ...rec, state: "sending", decided_at: iso(now) }))) throw taken();
    let sent: string | undefined;
    // What sending answered, once it has, and whether the record says so yet.
    let answered: ReleaseOutcome | undefined;
    let recorded = false;
    try {
      // A message that opens a thread starts it now, under the id reserved when it was held. A record written before
      // `opens_thread` existed opens one when it replies to nothing and its thread doesn't exist.
      const opens = rec.opens_thread ?? (!rec.in_reply_to && !(await this.threadOf(principal, rec.thread)));
      const result = await this.sendAs(principal, {
        delegate,
        to: rec.to,
        scope: rec.scope,
        type: rec.type,
        body: rec.body,
        ...(rec.to_delegate ? { to_delegate: rec.to_delegate } : {}),
        ...(rec.note !== undefined ? { note: rec.note } : {}),
        ...(opens ? { open_thread: rec.thread } : { thread: rec.thread }),
        ...(rec.in_reply_to ? { in_reply_to: rec.in_reply_to } : {}),
        ...(rec.labels ? { labels: rec.labels } : {}),
        ...(rec.expires_in_seconds !== undefined ? { expires_in_seconds: rec.expires_in_seconds } : {}),
        released: rec.id,
      }, (id) => {
        sent = id;
      });
      answered = releaseOutcome(rec, result, iso(now));
      await this.store.putHeldOutbound(answered.record);
      recorded = true;
      await this.log(principal, answered.entry);
      return result;
    } catch (err) {
      await this.releaseFailed(principal, rec, sent, answered, recorded, iso(now));
      throw err;
    }
  }

  /**
   * An approval that failed after it claimed the held record (a store or connection error, a bug): the record leaves
   * `sending`. When sending had answered and only recording that failed, the record and the `released` entry say what
   * it answered. Otherwise, before the envelope's `sent` entry was written nothing left this broker, so the message
   * waits for the person again, as it was; after it, the envelope may have reached the recipient: the record says its
   * delivery failed (it may still have arrived), the ledger gets the `released` entry, and it is never sent again. If
   * the store fails here too, the record stays `sending`, as when the broker stops (or keeps the outcome it already
   * recorded, without the `released` entry). A write can land and still report a failure (the connection drops after
   * the database committed), so the record is read again when it has left `sending`, and the ledger is searched before
   * the `released` entry is written: one per held message.
   */
  private async releaseFailed(principal: PrincipalRecord, rec: HeldOutbound, sent: string | undefined, answered: ReleaseOutcome | undefined, recorded: boolean, decidedAt: string): Promise<void> {
    try {
      if (answered) {
        const kept = recorded || (await this.store.claimHeldOutbound(answered.record, "sending")) || (await this.heldRecordSays(principal, answered.record));
        if (kept && !(await this.hasReleasedEntry(principal, rec.id))) await this.log(principal, answered.entry);
        return;
      }
      if (sent === undefined) {
        await this.store.claimHeldOutbound(rec, "sending");
        return;
      }
      const result: NonNullable<HeldOutbound["result"]> = { status: "undeliverable", code: "internal" };
      if (await this.store.claimHeldOutbound({ ...rec, state: "refused", decided_at: decidedAt, envelope_id: sent, result }, "sending")) {
        await this.log(principal, { kind: "released", counterparty: rec.to, scope: rec.scope, type: rec.type, thread: rec.thread, outcome: "refused", code: result.code, envelope_id: sent, ref: rec.id });
      }
    } catch {
      // the store is failing too: the record stays as it is (`sending`, or its outcome without the `released` entry)
    }
  }

  /** Whether the held record already says what sending answered: its write landed, though it reported a failure. */
  private async heldRecordSays(principal: PrincipalRecord, outcome: HeldOutbound): Promise<boolean> {
    const stored = await this.store.getHeldOutbound(principal.address, outcome.id);
    return stored?.state === outcome.state && stored.decided_at === outcome.decided_at && stored.envelope_id === outcome.envelope_id;
  }

  /** Whether the person's ledger has the `released` entry of this held message (read only after a failure). */
  private async hasReleasedEntry(principal: PrincipalRecord, heldId: string): Promise<boolean> {
    return (await this.store.listLedger(principal.principal_id)).some((e) => e.kind === "released" && e.ref === heldId);
  }

  async listGrants(caller: HumanCaller): Promise<RelationshipGrant[]> {
    const principal = await this.authHuman(caller);
    return (await this.store.listGrants(principal.address)).filter((g) => g.principal_id === principal.principal_id);
  }

  async setGrant(caller: HumanCaller, input: GrantInput): Promise<RelationshipGrant> {
    const principal = await this.authHuman(caller, true);
    const now = this.clock.now();
    const counterparty = parseAddress(input.counterparty);
    if (counterparty === principal.address) throw new AlpError("invalid_input", "a grant needs another principal");
    if (Object.keys(input.scopes).length === 0) throw new AlpError("invalid_input", "a grant needs at least one scope; use revoke to end a relationship");
    for (const [s, t] of Object.entries(input.scopes)) checkScopeTerms(t, this.scopes.require(s));
    if (input.quiet_hours) isQuietTime(input.quiet_hours, now);
    const existing = await this.grantOf(principal, counterparty);
    const grant: RelationshipGrant = {
      alp: ALP_VERSION,
      id: existing?.id ?? this.ids.ulid(),
      principal: principal.address,
      principal_id: principal.principal_id,
      counterparty,
      ...(existing?.counterparty_principal_id ? { counterparty_principal_id: existing.counterparty_principal_id } : {}),
      basis: input.basis ?? "consent",
      status: "active",
      scopes: structuredClone(input.scopes),
      ...(input.rate_limit ? { rate_limit: input.rate_limit } : {}),
      ...(input.quiet_hours ? { quiet_hours: input.quiet_hours } : {}),
      ...(existing?.connection ? { connection: existing.connection } : {}),
      created_at: existing?.created_at ?? iso(now),
      updated_at: iso(now),
      ...(input.expires_at ? { expires_at: input.expires_at } : {}),
      sealed: { by: principal.principal_id, method: sealMethod(caller), at: iso(now) },
    };
    return this.storeGrant(principal, grant, "grant_set");
  }

  async sealGrant(caller: HumanCaller, input: { counterparty: string }): Promise<RelationshipGrant> {
    const principal = await this.authHuman(caller, true);
    const now = this.clock.now();
    const g = await this.grantOf(principal, parseAddress(input.counterparty));
    if (!g || g.status !== "pending") throw new AlpError("invalid_input", "no pending grant for this counterparty", { status: 404 });
    return this.storeGrant(principal, { ...g, status: "active", updated_at: iso(now), sealed: { by: principal.principal_id, method: sealMethod(caller), at: iso(now) } }, "grant_set");
  }

  async revoke(caller: HumanCaller, input: RevokeInput): Promise<RelationshipGrant> {
    const principal = await this.authHuman(caller, true);
    const now = this.clock.now();
    const counterparty = parseAddress(input.counterparty);
    const existing = await this.grantOf(principal, counterparty);
    let grant: RelationshipGrant;
    if (input.scopes && input.scopes.length > 0) {
      if (!existing) throw new AlpError("invalid_input", "no grant to narrow; set a narrowing grant to limit an org default");
      const scopes = { ...existing.scopes };
      for (const s of input.scopes) delete scopes[s];
      grant = Object.keys(scopes).length === 0
        ? { ...existing, status: "revoked", updated_at: iso(now) }
        : { ...existing, scopes, updated_at: iso(now), sealed: { by: principal.principal_id, method: sealMethod(caller), at: iso(now) } };
    } else {
      const placeholder: ScopeTerms = { may: [], disclose: [], receive: [], commit: "ask_me", redaction: "reject" };
      grant = {
        alp: ALP_VERSION,
        id: existing?.id ?? this.ids.ulid(),
        principal: principal.address,
        principal_id: principal.principal_id,
        counterparty,
        basis: existing?.basis ?? "consent",
        status: "revoked",
        // A revoked grant keeps its scopes for the record; a new one blocks the pair, org defaults included.
        scopes: existing && Object.keys(existing.scopes).length ? existing.scopes : { [this.scopes.ids()[0] as string]: placeholder },
        created_at: existing?.created_at ?? iso(now),
        updated_at: iso(now),
        ...(existing?.sealed ? { sealed: existing.sealed } : {}),
      };
    }
    const stored = await this.storeGrant(principal, grant, "grant_revoked");
    const home = await this.homeOf(counterparty);
    if (home.kind !== "none") {
      const env = await this.buildControl(principal, null, counterparty, home, "revoke",
        { scopes: input.scopes?.length ? input.scopes : ["*"], reason: "principal_revoked", effective_at: iso(now) }, {});
      const outcome = await this.deliverAndVerify(env, home);
      if (outcome.kind === "failed") await this.log(principal, { kind: "delivery_failed", counterparty, envelope_id: env.id, type: "revoke", outcome: "refused", code: outcome.code });
    }
    return stored;
  }

  async listRatifications(caller: HumanCaller): Promise<RatificationRequest[]> {
    const principal = await this.authHuman(caller);
    return (await this.store.listRatificationRequests(principal.address)).filter((r) => this.owns(principal, r));
  }

  async ratify(caller: HumanCaller, input: RatifyInput): Promise<RatificationRequest> {
    return this.asOneAnswer(() => this.ratifyNow(caller, input));
  }

  private async ratifyNow(caller: HumanCaller, input: RatifyInput): Promise<RatificationRequest> {
    const principal = await this.authHuman(caller, true);
    const now = this.clock.now();
    const req = await this.store.getRatificationRequest(input.request);
    if (!req || req.principal !== principal.address || !this.owns(principal, req)) throw new AlpError("invalid_input", "no such ratification request", { status: 404 });
    if (req.state !== "pending") throw new AlpError("invalid_input", `ratification request is ${req.state}`, { status: 409 });
    const stored = await this.threadOf(principal, req.thread);
    const thread = stored ? expireIfDue(stored, now) : null;
    if (!thread || thread.state !== "agreed" || thread.terms_hash !== req.terms_hash) {
      await this.store.putRatificationRequest({ ...req, state: "voided", decided_at: iso(now) });
      const why = thread && thread.state !== "agreed" ? `the thread is ${thread.state}` : "the terms changed";
      throw new AlpError("thread_state", `${why}; this ratification request no longer applies`, { status: 409 });
    }
    if (Date.parse(req.expires_at) <= now.getTime()) {
      const expired: RatificationRequest = { ...req, state: "expired", decided_at: iso(now) };
      await this.store.putRatificationRequest(expired);
      return expired;
    }
    if (input.decision === "decline") {
      const declined: RatificationRequest = { ...req, state: "declined", decided_at: iso(now) };
      await this.store.putRatificationRequest(declined);
      await this.log(principal, { kind: "ratification", counterparty: req.counterparty, thread: req.thread, scope: req.scope, outcome: "refused", ref: req.id });
      await this.sendAs(principal, { delegate: null, to: req.counterparty, scope: req.scope, type: "decline", body: { of: req.accept_id, reason: "ratification_declined" }, thread: req.thread, in_reply_to: req.accept_id });
      return declined;
    }
    const record = await this.makeRatification(principal, thread, req.counterparty, sealMethod(caller), now);
    const approved: RatificationRequest = { ...req, state: "approved", decided_at: iso(now), record };
    await this.store.putRatificationRequest(approved);
    await this.sendRatificationAck(principal, thread, req.counterparty, req.accept_id, record);
    return approved;
  }

  async ledger(caller: HumanCaller, query: LedgerQuery = {}): Promise<LedgerEntry[]> {
    const principal = await this.authHuman(caller);
    return this.store.listLedger(principal.principal_id, {
      ...(query.after_seq !== undefined ? { afterSeq: query.after_seq } : {}),
      ...(query.limit !== undefined ? { limit: query.limit } : {}),
    });
  }

  async ledgerPayload(caller: HumanCaller, seq: number): Promise<LedgerPayload | null> {
    const principal = await this.authHuman(caller);
    return this.store.getLedgerPayload(principal.principal_id, seq);
  }

  async verifyLedger(caller: HumanCaller): Promise<LedgerCheck> {
    const principal = await this.authHuman(caller);
    const entries = await this.store.listLedger(principal.principal_id);
    const payloads = new Map<number, LedgerPayload>();
    for (const e of entries) {
      if (!e.payload_hash) continue;
      const p = await this.store.getLedgerPayload(principal.principal_id, e.seq);
      if (p) payloads.set(e.seq, p);
    }
    return verifyLedger(principal.principal_id, entries, payloads);
  }

  /** For the authorization server and the web view: write to the same security-event stream (token_issued, token_refused...). */
  async recordSecurityEvent(event: SecurityEventName, args: EventArgs = {}): Promise<void> {
    await this.securityEvent(event, args);
  }

  // =========================================================================================
  // Operator

  async setOrgPolicy(caller: AdminCaller, policy: OrgPolicy): Promise<void> {
    if (caller?.kind !== "admin") throw new AlpError("identity_mismatch", "operator only", { status: 403 });
    const next = checkOrgPolicy(structuredClone(policy));
    for (const d of next.domains) checkPolicyUpdate(this.policies.get(d), next);
    this.installPolicy(next);
    for (const d of next.domains) this.domains.add(d);
    await this.securityEvent("policy_changed", { message: `${policyRef(next)} installed by ${caller.operator}` });
  }

  async rotateKeys(caller: AdminCaller): Promise<{ active: string; pins: string[] }> {
    if (caller?.kind !== "admin") throw new AlpError("identity_mismatch", "operator only", { status: 403 });
    const k = await this.keys.rotate(this.clock.now(), this.limits.maxTtlSeconds + this.limits.receiptTtlSeconds);
    await this.keys.prepareNext(this.clock.now());
    await this.securityEvent("key_rotated", { details: { kid: k.kid } });
    return { active: k.kid, pins: this.keys.jkts() };
  }

  // =========================================================================================
  // Federation-facing

  async acceptInbound(raw: unknown, ctx: InboundContext = {}): Promise<InboundResult> {
    return this.asOneAnswer(() => this.acceptInboundNow(raw, ctx));
  }

  private async acceptInboundNow(raw: unknown, _ctx: InboundContext): Promise<InboundResult> {
    const now = this.clock.now();
    const auth = await this.authenticateInbound(raw, now, _ctx.remote);
    if (auth.kind === "answered") return auth.result;
    const { env, hash, verification } = auth;
    // A connection request naming no scope this broker knows is refused the same way whoever it is addressed to.
    if (env.type === "connection_request" && !(env.body["scopes"] as string[]).some((s) => this.scopes.get(s) !== undefined)) {
      return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "refused", "unknown_scope"), step: 9 };
    }
    const recipient = await this.store.getPrincipal(env.to.address);
    if (!recipient || recipient.status !== "active" || (env.to.principal_id !== undefined && env.to.principal_id !== recipient.principal_id)) {
      // Uniform answers (spec 6.2.2, 6.8): a connection request to an address nobody holds gets the same `accepted`
      // receipt as any other; a message is refused like one the recipient's rules don't accept.
      if (env.type === "connection_request") return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "accepted") };
      return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "refused", "not_accepted"), step: 8 };
    }
    if (isControlType(env.type)) return this.acceptControl(env as ControlEnvelope, hash, recipient, now);
    return this.acceptMessage(env as Envelope, hash, recipient, verification, now);
  }

  /**
   * Acceptance steps 0 to 6 (spec 12.2.4), in the specification's order; every refusal names its step. Steps 0 and 1
   * answer with an unsigned error; later steps with a signed `refused` receipt (spec 12.2.3). A sender who is a
   * principal of this broker (the Local profile) is checked against local state: this broker signed the envelope,
   * for that principal_id, with its own keys. The replay record (step 5) is the only thing this writes.
   */
  async authenticateInbound(raw: unknown, now: Date = this.clock.now(), remote?: string): Promise<Authentication> {
    const originOf = (v: unknown): string | undefined => {
      const o = v && typeof v === "object" ? (v as { origin_broker?: unknown }).origin_broker : undefined;
      return typeof o === "string" && /^https:\/\/[a-z0-9.-]+(:[0-9]+)?$/.test(o) ? o : undefined;
    };
    const plain = async (step: number, status: number, code: ErrorCode, message: string, event: SecurityEventName): Promise<Authentication> => {
      const origin = originOf(raw);
      await this.securityEvent(event, { failed: true, details: { code, ...(origin ? { origin_broker: origin } : {}) } });
      return { kind: "answered", result: { kind: "refused", status, code, message, step } };
    };
    const signed = async (env: AnyEnvelope, hash: string, step: number, code: ErrorCode, event: SecurityEventName, remember = false): Promise<Authentication> => {
      await this.securityEvent(event, { failed: true, details: { code, origin_broker: env.origin_broker } });
      return { kind: "answered", result: { kind: "receipt", receipt: await this.issueReceipt(env, hash, "refused", code, undefined, remember), step } };
    };

    // Step 0: structure, version, lifetime, clock skew.
    const st = checkEnvelopeStructure(raw, now, { maxTtlSeconds: this.limits.maxTtlSeconds, clockSkewSeconds: this.limits.clockSkewSeconds, bodyMaxBytes: this.limits.bodyMaxBytes });
    if (!st.ok) return plain(0, st.code === "body_too_large" ? 413 : 400, st.code, st.detail, "envelope_refused");
    const env = st.envelope;
    if (env.from.delegate !== undefined && !delegateBelongsTo(env.from.delegate, env.from.address)) return plain(0, 400, "bad_envelope", "from.delegate is not the sender's", "envelope_refused");
    // Decided from the envelope alone, so it says nothing about which agents the recipient has.
    const toDelegate = "delegate" in env.to ? env.to.delegate : undefined;
    if (toDelegate !== undefined && !delegateBelongsTo(toDelegate, env.to.address)) return plain(0, 400, "bad_envelope", "to.delegate is not the recipient's", "envelope_refused");
    const senderDomain = domainOf(env.from.address);

    // Step 1: the sender's domain lists origin_broker, and a key it pins for that broker verifies the signature.
    let jwks: Jwks;
    let doc: DomainDocument | null = null;
    let entry: BrokerEntry | null = null;
    const local = await this.store.getPrincipal(env.from.address);
    if (local && local.status === "active") {
      if (env.origin_broker !== this.id || local.principal_id !== env.from.principal_id) return plain(1, 403, "broker_not_authorized", `${env.origin_broker} is not the home broker for ${displayAddress(env.from.address)}`, "broker_not_authorized");
      jwks = this.keys.jwks();
    } else {
      try {
        // Discovery of a never-seen sender domain is budgeted per requester (spec 4.3).
        doc = await this.resolver.domainDocument(senderDomain, { budget: remote ?? env.origin_broker });
      } catch (err) {
        // A domain this broker hosts, or one that publishes no document at all (the resolver marks the error
        // `absent`), authorizes no other broker: a permanent refusal. Any other failure is retryable.
        if (this.domains.has(senderDomain) || (err as { absent?: unknown } | null)?.absent === true) {
          return plain(1, 403, "broker_not_authorized", `${env.origin_broker} is not the home broker for ${displayAddress(env.from.address)}`, "broker_not_authorized");
        }
        return plain(1, 503, "discovery_failed", "the sender's domain could not be checked", "discovery_failure");
      }
      entry = doc.brokers.find((b) => b.id === env.origin_broker) ?? null;
      if (!entry) return plain(1, 403, "broker_not_authorized", `${senderDomain} does not list ${env.origin_broker}`, "broker_not_authorized");
      try {
        jwks = await pinnedFederationKeys(await this.resolver.jwks(entry.jwks_uri), entry, revokedKeys(doc));
      } catch {
        return plain(1, 503, "discovery_failed", "the sender's broker keys could not be checked", "discovery_failure");
      }
    }
    let v = await verifyAnyEnvelope(env, jwks);
    if (!v.ok && v.failure === "unknown_kid" && entry && doc) {
      try {
        v = await verifyAnyEnvelope(env, await pinnedFederationKeys(await this.resolver.jwks(entry.jwks_uri, { refresh: true }), entry, revokedKeys(doc)));
      } catch {
        // reported below as a signature failure
      }
    }
    if (!v.ok && v.failure !== "wrong_typ") return plain(1, 401, "bad_signature", `signature did not verify (${v.failure})`, "signature_failure");
    const hash = objectHash(env);
    // Step 2: the typ this kind of object requires.
    if (!v.ok) return signed(env, hash, 2, "bad_signature", "signature_failure");
    // Step 3: addressed to this broker, which is the recipient's home broker: under the recipient domain's document
    // when it publishes one, for local principals too (spec 4.5); only a hosted domain with no document at all (the
    // Local profile) is decided by local configuration.
    if (env.aud !== this.id) return signed(env, hash, 3, "wrong_audience", "envelope_refused");
    const toHome = await this.homeStatus(env.to.address);
    if (toHome === "unknown") return plain(3, 503, "discovery_failed", "the recipient's domain could not be checked", "discovery_failure");
    if (toHome === "elsewhere") return signed(env, hash, 3, "wrong_audience", "envelope_refused");
    // Step 4: at most 300 seconds past expires_at.
    if (now.getTime() > Date.parse(env.expires_at) + this.limits.clockSkewSeconds * 1000) return signed(env, hash, 4, "expired", "envelope_refused");
    // Step 5: the replay window runs to expires_at plus a grace period. A duplicate of an envelope already answered
    // (same hash) gets the original receipt and changes nothing (spec 10.3), so a sender's retry is safe; one refused
    // for a retryable reason is evaluated again. The same id with other content is a replay, and its refusal never
    // replaces the original receipt. While an envelope is being evaluated it is marked in flight, so a duplicate that
    // arrives meanwhile (a sender's retry after a timeout) is told to retry shortly instead of being evaluated twice.
    const until = iso(addSeconds(new Date(Date.parse(env.expires_at)), this.limits.replayGraceSeconds + this.limits.clockSkewSeconds));
    const inFlightUntil = iso(addSeconds(now, this.limits.inFlightSeconds));
    const busy = async (): Promise<Authentication> => {
      await this.securityEvent("envelope_refused", { failed: false, details: { code: "internal", origin_broker: env.origin_broker }, message: "duplicate while the first copy is in flight" });
      return { kind: "answered", result: { kind: "refused", status: 503, code: "internal", message: "this envelope is still being processed; retry shortly", step: 5, retry_after: 2 } };
    };
    if (!(await this.store.recordOnce(replayKey(env.origin_broker, env.id), until, now))) {
      const original = await this.store.getReceipt(receiptKey(env.origin_broker, env.id));
      if (original && original.envelope_hash === hash) {
        const retryable = original.status === "refused" && RETRYABLE_REFUSALS.includes(original.code ?? "not_accepted");
        if (!retryable) return { kind: "answered", result: { kind: "receipt", receipt: original, duplicate: true } };
        // Evaluated again after a retryable refusal: by one caller at a time.
        if (!(await this.store.recordOnce(`${inFlightKey(env.origin_broker, env.id)}|${original.id}`, inFlightUntil, now))) return busy();
      } else if (original) {
        await this.securityEvent("replay_refused", { failed: true, details: { code: "replay", origin_broker: env.origin_broker } });
        return { kind: "answered", result: { kind: "receipt", receipt: await this.issueReceipt(env, hash, "refused", "replay", undefined, false), step: 5 } };
      } else if (!(await this.store.recordOnce(inFlightKey(env.origin_broker, env.id), inFlightUntil, now))) {
        // Seen and not answered yet: the first copy is still being evaluated.
        return busy();
      }
      // Seen, never answered, and its in-flight mark has lapsed: the first attempt was interrupted. Evaluate it again.
    } else if (!(await this.store.recordOnce(inFlightKey(env.origin_broker, env.id), inFlightUntil, now))) {
      // First sight, but a copy that arrived meanwhile took the in-flight mark first (the two writes are separate, and
      // a store may complete them out of order): exactly one copy holds the mark, and only that one is evaluated.
      return busy();
    }
    // Step 6: origin_broker is the sender's home broker under the sender domain's current document. For a sender who
    // is a principal of this broker the same holds whenever the domain publishes a document: a broker the document no
    // longer names stops speaking for its stale local principals at once.
    if (doc) {
      const home = homeBroker(doc, env.from.address);
      if (!home || home.id !== env.origin_broker) return signed(env, hash, 6, "broker_not_authorized", "broker_not_authorized", true);
    } else {
      const fromHome = await this.homeStatus(env.from.address);
      if (fromHome === "unknown") return plain(6, 503, "discovery_failed", "the sender's domain could not be checked", "discovery_failure");
      if (fromHome === "elsewhere") return signed(env, hash, 6, "broker_not_authorized", "broker_not_authorized", true);
    }
    const verification: IntakeVerification = { sender_broker: env.origin_broker, home_broker: true, signature: "verified", kid: v.kid, verified_at: iso(now) };
    return { kind: "authenticated", env, hash, typ: st.typ, home_broker: env.origin_broker, verification, ...(doc ? { testing: doc.mode === "testing" } : {}) };
  }

  /**
   * Is this broker the home broker of an address (spec 4.5)? The domain's published document decides, for local
   * principals too. Only a domain this broker hosts that publishes no document at all (the Local profile) is decided
   * by this broker's configuration. A document that can't be fetched right now is `unknown`, never assumed.
   */
  private async homeStatus(address: Address): Promise<HomeStatus> {
    const domain = domainOf(address);
    if (!this.domains.has(domain)) return "elsewhere";
    let doc: DomainDocument;
    try {
      doc = await this.resolver.domainDocument(domain);
    } catch (err) {
      return (err as { absent?: unknown } | null)?.absent === true ? "here" : "unknown";
    }
    return homeBroker(doc, address)?.id === this.id ? "here" : "elsewhere";
  }

  // =========================================================================================
  // Sending internals

  /**
   * The sender-side evaluation (spec 6.6), in order, stopping at the first failure: S1 input and identity, S2 kill
   * switches and client governance, S3 the thread, S4 the organization's deny rules, S5 the relationship and field
   * coverage, S6 removal and the schema, S7 DLP, S8 the decision (labels, constraints, hold for review).
   * Nothing here writes; `sendAs` writes the ledger and sends.
   */
  private async prepareSend(principal: PrincipalRecord, draft: Draft, opts: { skipThreadChecks?: boolean } = {}): Promise<Prepared> {
    const now = this.clock.now();
    const owner = principal.address;
    const d = draft.delegate;
    const rejected = (code: ErrorCode, detail: string, ledger: Partial<LedgerFields> = {}, reasons?: Reason[]): Extract<Prepared, { kind: "rejected" }> => ({ kind: "rejected", code, reasons: reasons ?? [{ code, detail }], ledger });
    // S1
    let to: Address;
    try {
      to = parseAddress(draft.to);
    } catch {
      return rejected("invalid_input", "not an ALP address");
    }
    // Spec 6.14: one person's own agents write to each other, agent to agent; the broker itself never writes to its person.
    if (to === owner && (!d || draft.to_delegate === undefined)) return rejected("invalid_input", d ? "to write to another of your own agents, name it in to_delegate" : "cannot send to yourself");
    const toDelegate = draft.to_delegate?.toLowerCase();
    if (toDelegate !== undefined && !delegateBelongsTo(toDelegate, to)) return rejected("invalid_input", "to_delegate is not the recipient's");
    let ownTarget: DelegateRecord | null = null;
    if (to === owner && toDelegate !== undefined) {
      ownTarget = await this.store.getDelegate(toDelegate);
      if (!ownTarget || ownTarget.status !== "active" || ownTarget.principal !== owner) {
        // The person's own agents are the person's own information (spec 6.8): name the ones that are connected.
        const others = (await this.store.listDelegates(owner)).filter((x) => x.status === "active" && x.principal_id === principal.principal_id && x.id !== d?.id).map((x) => x.label).sort();
        return rejected("unknown_recipient", others.length ? `No agent of your person's is connected under that name. Your person's other connected agents: ${others.slice(0, 32).join(", ")}${others.length > 32 ? ` and ${others.length - 32} more` : ""}.` : "No agent of your person's is connected under that name, and your person has no other connected agent.");
      }
      ownTarget = this.ranked(ownTarget);
      if (d && ownTarget.id === d.id) return rejected("invalid_input", "an agent cannot write to itself");
    }
    const scope = this.scopes.get(draft.scope);
    const base: Partial<LedgerFields> = { counterparty: to, scope: draft.scope, type: draft.type };
    if (!scope) return rejected("unknown_scope", draft.scope, base);
    if (!scope.types.has(draft.type)) return rejected("unknown_type", `${scope.id} has no ${draft.type}`, base);

    // S2: kill switches and client governance.
    const policy = this.policyFor(owner);
    const killed = blockedBy(policy, { principals: [owner, to], scope: scope.id, domains: [domainOf(to)], ...(d ? { delegate: d.id, client_id: d.client_id } : {}) });
    if (killed) return { ...rejected("blocked", killed, base), event: { name: "kill_switch", message: killed } };
    if (d && policy?.clients) {
      const rule = clientRule(policy, d.client_id);
      if (!rule || !rule.scopes.includes(scope.id)) {
        const event = { name: "client_refused" as const, failed: policy.clients.mode === "enforce" };
        if (policy.clients.mode === "enforce") return { ...rejected("client_not_allowed", rule ? "this client may not use this scope" : "this client is not on the organization's allow-list", base), event };
        if (!opts.skipThreadChecks) await this.securityEvent("client_refused", { failed: false, details: { client_id: d.client_id, scope: scope.id, principal_id: principal.principal_id } });
      }
    }

    // S3: the thread and the reply rules. A reply without `thread` belongs to the thread of what it answers.
    let thread: ThreadRecord | null = null;
    let threadId: string;
    let replyTo: MessageRecord | null = null;
    if (draft.in_reply_to !== undefined && !isUlid(draft.in_reply_to)) return rejected("invalid_input", "bad in_reply_to", base);
    if (draft.thread !== undefined && !isUlid(draft.thread)) return rejected("invalid_input", "bad thread id", base);
    if (draft.open_thread !== undefined && !isUlid(draft.open_thread)) return rejected("invalid_input", "bad thread id", base);
    if (draft.in_reply_to !== undefined && !opts.skipThreadChecks) replyTo = await this.messageOf(principal, draft.in_reply_to);
    threadId = draft.thread ?? replyTo?.envelope.thread ?? draft.open_thread ?? this.ids.ulid();
    let terms_hash: string | undefined;
    let ratifications: [string, string] | undefined;
    const body = draft.body;
    if (draft.type === "accept" || draft.type === "commit") {
      const t = body["terms"];
      if (!t || typeof t !== "object" || Array.isArray(t)) return rejected("schema_invalid", "accept and commit carry body.terms", base);
      terms_hash = termsHash(t);
    }
    const ttl = Math.max(60, Math.min(draft.expires_in_seconds ?? this.limits.defaultTtlSeconds, this.limits.maxTtlSeconds));
    const envelopeId = this.ids.ulid();
    const createdAt = iso(now);
    const expiresAt = iso(addSeconds(now, ttl));
    let tmsg: ThreadMessage | null = null;
    if (!opts.skipThreadChecks) {
      if (draft.thread !== undefined || replyTo) {
        thread = await this.threadOf(principal, threadId);
        if (!thread) return rejected("thread_state", "unknown thread", base);
      } else if (draft.open_thread !== undefined) {
        // Usually the thread doesn't exist yet and this message starts it (a type in the scope's `starts`); if it does,
        // the usual participant, scope and state checks apply.
        thread = await this.threadOf(principal, threadId);
      }
      if (draft.in_reply_to !== undefined && (!replyTo || replyTo.envelope.thread !== threadId)) return rejected("thread_state", "in_reply_to names no message in this thread", { ...base, thread: threadId });
      if (draft.type === "commit") {
        if (!thread || thread.state !== "agreed" || thread.terms_hash !== terms_hash) return rejected("thread_state", "commit needs the agreed terms", { ...base, thread: threadId });
        const mine = thread.ratifications?.mine?.hash;
        const theirs = thread.ratifications?.theirs?.hash;
        if (!mine || !theirs) return { kind: "needs_ratification", thread: threadId, detail: !mine ? "your person has not ratified the agreed terms yet" : "the other person has not ratified the agreed terms yet" };
        ratifications = [mine, theirs].sort() as [string, string];
      }
      tmsg = {
        thread: threadId,
        principal: owner,
        principal_id: principal.principal_id,
        counterparty: to,
        scope: scope.id,
        envelope_id: envelopeId,
        type: draft.type,
        direction: "out",
        at: createdAt,
        expires_at: expiresAt,
        ...(draft.in_reply_to ? { in_reply_to: draft.in_reply_to } : {}),
        ...(replyTo && isMessageType(replyTo.envelope.type) ? { reply_to: { type: replyTo.envelope.type, direction: replyTo.direction } } : {}),
        ...(terms_hash ? { terms_hash } : {}),
        ...(ratifications ? { ratifications } : {}),
        ...(draft.type === "ack" ? { ack_status: body["status"] as "received" } : {}),
      };
      const tcheck = applyToThread(scope, thread, tmsg, now);
      if (!tcheck.ok) return rejected(tcheck.code, tcheck.detail, { ...base, thread: threadId });
    }

    // S4 to S8: the organization's deny rules, then the relationship (effective terms), then the evaluator. A grant
    // bound to an earlier holder of either address is void (spec 5.2).
    const localTo = to === owner ? null : await this.store.getPrincipal(to);
    const grant = await this.grantOf(principal, to, localTo && localTo.status === "active" ? localTo.principal_id : undefined);
    const revocation = await this.store.getRevocation(owner, to);
    // Claim-based groups (spec 6.4) see the claims of the people this broker signed in: the sender's, and the
    // recipient's when the recipient is one of them. A recipient elsewhere has none here (fail closed).
    const claimsOf = this.claimsFor(localTo && localTo.status === "active" ? [principal, localTo] : [principal]);
    const tr = effectiveTerms({ owner, counterparty: to, scope: scope.id, direction: "outbound", grant, revocation, policy, claimsOf, now });
    const terms = tr.ok ? this.withPlumbing(tr.terms, draft.type) : null;
    const ev = await evaluateMessage({
      direction: "outbound",
      owner,
      owner_id: principal.principal_id,
      counterparty: to,
      scope,
      type: draft.type,
      body,
      ...(draft.note !== undefined ? { note: draft.note } : {}),
      terms,
      policy,
      claimsOf,
      dlp: this.dlp,
      limits: { noteMaxChars: this.limits.noteMaxChars, bodyMaxBytes: this.limits.bodyMaxBytes },
      ...(draft.labels ? { extraLabels: draft.labels } : {}),
    });
    if (ev.outcome === "reject" || !terms) {
      const code = ev.code ?? "no_relationship";
      const reasons = code === "no_relationship" && !tr.ok && tr.revoked ? [{ code, detail: "the relationship was revoked" }] : code === "no_relationship" ? [{ code, detail: "not a counterparty in this scope; ask your person to connect (alp_request_connection)" }] : ev.reasons;
      return { kind: "rejected", code, reasons, ledger: { ...base, thread: threadId, ...(ev.policy_ids.length ? { policy_ids: ev.policy_ids.slice(0, 32) } : {}) }, ...(code === "dlp_blocked" ? { event: { name: "dlp_blocked" as const } } : {}) };
    }
    if (!opts.skipThreadChecks) {
      const window = tmsg && scope.id === "alp.availability/1" && draft.type === "inform" ? await this.windowBody(principal, thread, tmsg, replyTo) : undefined;
      const semantic = scopeSemantics(scope.id, draft.type, ev.body, replyTo && isMessageType(replyTo.envelope.type) ? { type: replyTo.envelope.type, body: replyTo.envelope.body } : undefined, window);
      if (semantic) return rejected("schema_invalid", semantic, { ...base, thread: threadId }, [{ code: "schema_invalid", detail: semantic }]);
    }
    let hold = !draft.released && (terms.hold_for_review === true || ev.hold_for_review === true);
    let holdReason: HeldOutbound["reason"] | undefined = hold ? (terms.hold_for_review ? "review" : "dlp_justification") : undefined;
    let constraints = deliveryConstraints(policy, ev.labels);
    let evOut = ev;
    let ownSplit: OwnWithheld | undefined;
    let ownHold: OwnWithheld | undefined;
    if (ownTarget) {
      // Spec 6.14: between the person's own agents the minimums apply per field, to the agent named in to_delegate,
      // here and now; the envelope carries no delivery constraints, so nothing is held again on arrival.
      constraints = undefined;
      const overrides = policy?.classification?.overrides?.[scope.id];
      const extra = draft.labels ?? [];
      const fields = ev.disclosed.map((p) => ({ pointer: p, labels: [...new Set([...labelsOf(scope, draft.type, p, overrides), ...extra])].sort() }));
      const own = checkOwnAgentDelivery(policy, fields, ownTarget, clientRule(policy, ownTarget.client_id));
      const who = `your agent ${ownTarget.label} (${ownTarget.class}, ${ownTarget.attestation}-attested)`;
      if (own.blocked.length > 0) {
        const labels = [...new Set(own.blocked.flatMap((b) => b.labels))].sort();
        const detail = `your organization's rules keep ${labels.join(", ")} from ${who}: it needs ${own.blocked[0]?.needs ?? "more"}`;
        return rejected("org_policy", detail, { ...base, thread: threadId }, own.blocked.map((b, i) => ({ code: "org_policy" as const, pointer: b.pointer, rule: "delivery_minimums", ...(i === 0 ? { detail } : { detail: `${b.labels.join(", ")}: needs ${b.needs}` }) })));
      }
      if (own.held.length > 0 && !draft.released) {
        const withheld = own.held.map((h) => h.pointer).sort();
        const labels = [...new Set(own.held.flatMap((h) => h.labels))].sort();
        const needs = [...new Set(own.held.map((h) => h.needs))].join("; ");
        const kept = removePointers(ev.body, withheld.filter((p) => p !== NOTE_POINTER).map((p) => p.slice("/body".length)));
        const note = withheld.includes(NOTE_POINTER) ? undefined : ev.note;
        const remaining = ev.disclosed.filter((p) => !withheld.includes(p) && (p === NOTE_POINTER ? note !== undefined : getAt(kept, p.slice("/body".length)) !== undefined));
        if (remaining.length === 0 || validateBody(scope, draft.type, kept).length > 0) {
          // What is left isn't a valid message on its own: the whole message waits for the person.
          hold = true;
          holdReason = "delivery_minimums";
          ownHold = { withheld, labels, needs, target: ownTarget };
        } else {
          const keptLabels = [...new Set([...remaining.flatMap((p) => labelsOf(scope, draft.type, p, overrides)), ...extra])].sort();
          evOut = { ...ev, outcome: "redact", body: kept, disclosed: remaining, redacted: [...new Set([...ev.redacted, ...withheld])].sort(), labels: keptLabels };
          if (note === undefined) delete evOut.note;
          else evOut.note = note;
          ownSplit = { withheld, labels, needs, target: ownTarget };
        }
      }
    }
    const grantToBind = grant && grant.status === "active" && grant.counterparty_principal_id === undefined ? grant : undefined;
    return { kind: "ready", now, to, ...(toDelegate ? { toDelegate } : {}), scope, threadId, replyTo, ...(terms_hash ? { terms_hash } : {}), ...(ratifications ? { ratifications } : {}), terms, ev: evOut, policy, hold, ...(holdReason ? { holdReason } : {}), ...(ownSplit ? { ownSplit } : {}), ...(ownHold ? { ownHold } : {}), ...(ownTarget ? { ownTarget } : {}), ...(constraints ? { constraints } : {}), ...(grantToBind ? { grantToBind } : {}), tmsg, envelopeId, createdAt, expiresAt, base, ttl };
  }

  /**
   * Evaluates a draft, then holds it, refuses it or signs and sends it. `onSent` is told the envelope id once the `sent`
   * ledger entry is written: from then on the envelope may reach the recipient, whatever happens next.
   */
  private async sendAs(principal: PrincipalRecord, draft: Draft, onSent?: (envelopeId: string) => void): Promise<SendResult> {
    const owner = principal.address;
    const d = draft.delegate;
    const who: Partial<LedgerFields> = d ? { delegate: d.id, client_id: d.client_id } : {};
    const prep = await this.prepareSend(principal, draft);
    if (prep.kind === "needs_ratification") return { status: "needs_ratification", thread: prep.thread, detail: prep.detail };
    const reject = async (code: ErrorCode, reasons: Reason[], extra: Partial<LedgerFields>): Promise<SendResult> => {
      // A refusal names pointers and rule ids, never values (spec 6.6).
      await this.log(principal, { kind: "refused_outbound", outcome: "rejected", code, ...who, ...extra }, { detail: ledgerReasons(code, reasons) });
      return { status: "rejected", stage: "sender", code, reasons };
    };
    if (prep.kind === "rejected") {
      if (prep.event) await this.securityEvent(prep.event.name, { ...(prep.event.failed !== undefined ? { failed: prep.event.failed } : {}), ...(prep.event.message ? { message: prep.event.message } : {}), details: { code: prep.code, principal_id: principal.principal_id, scope: draft.scope, ...(d ? { client_id: d.client_id } : {}) } });
      return reject(prep.code, prep.reasons, prep.ledger);
    }
    const { scope, to, ev, terms, policy, base, threadId } = prep;

    // S5's rate limit, counted only for messages that would leave. Between one person's own agents, each directed pair
    // of agents has its own bucket, apart from the person's limits with other people.
    const ownPair = prep.ownTarget && d ? { from: d, to: prep.ownTarget } : undefined;
    const rate = ownPair ? this.limits.ownAgentRateLimit : (terms.rate_limit ?? this.limits.defaultRateLimit);
    const bucket = ownPair ? `own-out|${principal.principal_id}|${ownPair.from.id}|${ownPair.to.id}` : `out|${principal.principal_id}|${to}`;
    const hit = await this.store.hitRateLimit(bucket, prep.now, rate.per_seconds, rate.count);
    if (!hit.allowed) {
      await this.securityEvent("rate_limited", { details: { principal_id: principal.principal_id, scope: scope.id } });
      const wait = `retry after ${hit.retryAfter} second${hit.retryAfter === 1 ? "" : "s"}`;
      const detail = ownPair ? `too many messages from your agent ${ownPair.from.label} to your agent ${ownPair.to.label}; ${wait}` : `too many messages to ${displayAddress(to)}; ${wait}`;
      const r = await reject("rate_limited", [{ code: "rate_limited", detail }], { ...base, thread: threadId });
      return r.status === "rejected" ? { ...r, retry_after: hit.retryAfter } : r;
    }

    // S8: hold for the person's review (spec 6.12): nothing is signed until they approve it on the web view.
    const decision: Decision = { outcome: ev.outcome === "redact" ? "redacted" : "allowed", redacted: ev.redacted, policy_ids: ev.policy_ids.slice(0, 32) };
    if (prep.hold) {
      const held: HeldOutbound = {
        id: this.ids.ulid(),
        principal: owner,
        principal_id: principal.principal_id,
        ...(d ? { delegate: d.id, delegate_since: d.created_at, client_id: d.client_id } : {}),
        to,
        ...(prep.toDelegate ? { to_delegate: prep.toDelegate } : {}),
        // Between the person's own agents it goes, if the person approves, only to the binding it was written for.
        ...(prep.ownTarget ? { to_delegate_since: prep.ownTarget.created_at } : {}),
        scope: scope.id,
        type: draft.type,
        body: draft.body,
        ...(draft.note !== undefined ? { note: draft.note } : {}),
        thread: threadId,
        // The thread id was only reserved: nothing was sent, so the thread starts when the person approves the message.
        ...(draft.thread === undefined && !prep.replyTo ? { opens_thread: true } : {}),
        ...(draft.in_reply_to ? { in_reply_to: draft.in_reply_to } : {}),
        ...(draft.labels ? { labels: draft.labels } : {}),
        ...(draft.expires_in_seconds !== undefined ? { expires_in_seconds: draft.expires_in_seconds } : {}),
        reason: prep.holdReason ?? (terms.hold_for_review ? "review" : "dlp_justification"),
        // What is left isn't a valid message: nothing goes until the person decides.
        ...(prep.ownHold ? { withheld: { pointers: prep.ownHold.withheld, labels: prep.ownHold.labels }, whole: true } : {}),
        state: "pending",
        created_at: prep.createdAt,
        expires_at: prep.expiresAt,
      };
      await this.store.putHeldOutbound(held);
      await this.log(principal, { kind: "held", outcome: "held", ...who, ...base, thread: threadId, labels: ev.labels, policy_ids: decision.policy_ids, ref: held.id });
      const toWhom = to === owner && prep.toDelegate ? `your agent ${parseDelegateId(prep.toDelegate).label}` : displayAddress(to);
      const writer = `Your agent${d ? ` ${d.label}` : ""}`;
      const own = prep.ownHold;
      // A reply or a follow-up goes only while its thread is open (spec 9.2): when the thread would expire before the
      // message itself, the person is told by when to decide.
      const threadEnds = held.opens_thread ? undefined : await this.threadDeadline(principal, threadId);
      const decideBy = threadEnds !== undefined && Date.parse(threadEnds) < Date.parse(held.expires_at) ? threadEnds : undefined;
      const deadline = decideBy ? ` Decide before ${decideBy}: its thread expires then, unless a later message in it extends it.` : "";
      // Names labels and the requirement, never values (spec 6.14 item 4, 12.5.1).
      await this.notifyPerson(principal, "message_held", "A message is waiting for your review",
        own
          ? `${writer} wrote your agent ${own.target.label} a message (${scope.id}) with fields labeled ${own.labels.join(", ")}: ${own.target.label} is ${own.target.class} class and ${own.target.attestation}-attested, and your organization's rules need ${own.needs} for them. Without those fields it isn't a valid message, so nothing has been sent. The full message waits on your broker's page; send it to ${own.target.label} from there if you want it to have them.${deadline}`
          : held.reason === "dlp_justification"
            ? `${writer} wrote a ${scope.id} message to ${toWhom}. A data-loss check asked for your review before it leaves; nothing has been sent. Review it on your broker's page.${deadline}`
            : `${writer} wrote a ${scope.id} message to ${toWhom}. Your rules hold it until you review it on your broker's page; nothing has been sent.${deadline}`,
        this.links.held(held.id));
      return { status: "held_for_review", held: held.id, thread: threadId, expires_at: prep.expiresAt, decision, ...(decideBy ? { thread_expires_at: decideBy } : {}), ...(prep.holdReason ? { reason: prep.holdReason } : {}), ...(held.withheld ? { withheld: held.withheld } : {}) };
    }

    const home = await this.homeOf(to);
    if (home.kind === "none") {
      await this.log(principal, { ...base, ...who, kind: "delivery_failed", outcome: "refused", code: home.code, thread: threadId });
      // Nothing was signed: no envelope id to name.
      return { status: "undeliverable", code: home.code, detail: home.detail };
    }
    const from: Sender = d
      ? { address: owner, principal_id: principal.principal_id, delegate: d.id, attestation: d.attestation, class: d.class }
      : { address: owner, principal_id: principal.principal_id };
    const unsigned: UnsignedEnvelope = {
      alp: ALP_VERSION,
      id: prep.envelopeId,
      thread: threadId,
      ...(prep.replyTo ? { in_reply_to: prep.replyTo.envelope.id, in_reply_to_hash: prep.replyTo.envelope_hash } : {}),
      from,
      to: { address: to, ...(home.kind === "local" ? { principal_id: home.principal.principal_id } : {}), ...(prep.toDelegate ? { delegate: prep.toDelegate } : {}) },
      aud: home.kind === "remote" ? home.entry.id : this.id,
      scope: scope.id,
      type: draft.type,
      body: ev.body,
      ...(ev.note !== undefined ? { note: ev.note } : {}),
      ...(prep.terms_hash ? { terms_hash: prep.terms_hash } : {}),
      ...(prep.ratifications ? { ratifications: prep.ratifications } : {}),
      grant: terms.ref.slice(0, 128),
      labels: ev.labels,
      ...(prep.constraints ? { constraints: prep.constraints } : {}),
      created_at: prep.createdAt,
      expires_at: prep.expiresAt,
      origin_broker: this.id,
      decision,
    };
    const envelope = await signEnvelope(unsigned, this.keys);
    const hash = objectHash(envelope);
    const counterpartyBroker = home.kind === "remote" ? home.entry.id : this.id;
    // S8: write `sent` before delivery; the receipt gets its own entry (spec 11.5).
    const payload = this.payloadOf(policy, scope, draft.type, ev.body, ev.note);
    await this.log(principal, {
      kind: "sent",
      outcome: ev.outcome === "redact" ? "redacted" : "allowed",
      ...who,
      ...base,
      counterparty_broker: counterpartyBroker,
      envelope_id: envelope.id,
      thread: threadId,
      disclosed: ev.disclosed,
      ...(ev.redacted.length ? { redacted: ev.redacted } : {}),
      labels: ev.labels,
      policy_ids: [...decision.policy_ids, ...ev.report_ids].slice(0, 32),
      envelope_hash: hash,
    }, payload);
    onSent?.(envelope.id);
    const outcome = await this.deliverAndVerify(envelope, home);
    const receiptBase: LedgerFields = { kind: "receipt", outcome: "accepted", counterparty: to, counterparty_broker: counterpartyBroker, envelope_id: envelope.id, thread: threadId, envelope_hash: hash };
    if (outcome.kind === "failed") {
      await this.log(principal, { ...receiptBase, kind: "delivery_failed", outcome: "refused", code: outcome.code });
      return { status: "undeliverable", envelope_id: envelope.id, code: outcome.code, detail: outcome.detail, ...(outcome.retry_after !== undefined ? { retry_after: outcome.retry_after } : {}) };
    }
    const { receipt } = outcome;
    const receiptFields = { receipt_hash: outcome.hash, ...(receipt.ledger_hash ? { counterparty_ledger_hash: receipt.ledger_hash } : {}) };
    if (receipt.status === "refused") {
      await this.log(principal, { ...receiptBase, ...receiptFields, outcome: "refused", code: receipt.code ?? "not_accepted" });
      await this.recordContactAttempt(principal, envelope, hash, receipt, terms, counterpartyBroker);
      return { status: "refused", stage: "recipient", envelope_id: envelope.id, code: receipt.code ?? "not_accepted", receipt, ...(outcome.retry_after !== undefined ? { retry_after: outcome.retry_after } : {}) };
    }
    // Accepted: the message crossed. Re-read the thread in case something arrived meanwhile.
    if (home.kind === "local" && prep.grantToBind) await this.bindCounterparty(principal, prep.grantToBind, home.principal.principal_id);
    if (prep.tmsg) {
      const fresh = await this.store.getThread(owner, threadId);
      const applied = applyToThread(scope, fresh, prep.tmsg, this.clock.now());
      if (applied.ok) await this.store.putThread(applied.thread);
      if (applied.ok && fresh?.state === "agreed" && applied.thread.state !== "agreed") await this.voidRatifications(principal, applied.thread);
      await this.store.putMessage({ local_id: this.ids.ulid(), principal: owner, principal_id: principal.principal_id, direction: "out", envelope, envelope_hash: hash, status: "delivered", receipt, receipt_hash: outcome.hash, acked_by: {}, stored_at: iso(this.clock.now()) });
      await this.log(principal, { ...receiptBase, ...receiptFields });
      if (draft.type === "accept" && applied.ok && applied.thread.state === "agreed") await this.beginRatification(principal, applied.thread, to, envelope.id, draft.body["terms"] as JsonObject);
    } else {
      await this.log(principal, { ...receiptBase, ...receiptFields });
    }
    const held = prep.ownSplit ? await this.holdOwnRemainder(principal, draft, prep, decision) : undefined;
    return { status: "delivered", envelope, receipt, thread: threadId, ...(held ? { held } : {}) };
  }

  /**
   * Between the person's own agents (spec 6.14): the copy without the withheld fields went out; the full message waits
   * for the person, who can send it to that agent from the web view. The notification names labels, never values.
   */
  private async holdOwnRemainder(principal: PrincipalRecord, draft: Draft, prep: Extract<Prepared, { kind: "ready" }>, decision: Decision): Promise<{ id: string; withheld: string[]; labels: string[] } | undefined> {
    const split = prep.ownSplit;
    if (!split) return undefined;
    const d = draft.delegate;
    const held: HeldOutbound = {
      id: this.ids.ulid(),
      principal: principal.address,
      principal_id: principal.principal_id,
      ...(d ? { delegate: d.id, delegate_since: d.created_at, client_id: d.client_id } : {}),
      to: prep.to,
      to_delegate: split.target.id,
      to_delegate_since: split.target.created_at,
      scope: prep.scope.id,
      type: draft.type,
      body: draft.body,
      ...(draft.note !== undefined ? { note: draft.note } : {}),
      thread: prep.threadId,
      ...(draft.in_reply_to ? { in_reply_to: draft.in_reply_to } : {}),
      ...(draft.labels ? { labels: draft.labels } : {}),
      ...(draft.expires_in_seconds !== undefined ? { expires_in_seconds: draft.expires_in_seconds } : {}),
      reason: "delivery_minimums",
      withheld: { pointers: split.withheld, labels: split.labels },
      partial_envelope_id: prep.envelopeId,
      state: "pending",
      created_at: prep.createdAt,
      expires_at: prep.expiresAt,
    };
    await this.store.putHeldOutbound(held);
    await this.log(principal, { kind: "held", outcome: "held", ...(d ? { delegate: d.id, client_id: d.client_id } : {}), ...prep.base, thread: prep.threadId, labels: split.labels, policy_ids: decision.policy_ids, ref: held.id });
    const t = split.target;
    await this.notifyPerson(principal, "message_held", "Part of a message between your agents is waiting for you",
      `Your agent${d ? ` ${d.label}` : ""} sent your agent ${t.label} a message (${prep.scope.id}) without its fields labeled ${split.labels.join(", ")}: ${t.label} is ${t.class} class and ${t.attestation}-attested, and your organization's rules need ${split.needs} for them. The full message waits on your broker's page; send it to ${t.label} from there if you want it to have them.`,
      this.links.held(held.id));
    return { id: held.id, withheld: split.withheld, labels: split.labels };
  }

  /**
   * The other side refused a message we sent under our own person's grant, and we have no connection with them: the
   * recipient's broker may have recorded a contact attempt and may answer it with a `connection_response` (spec
   * 6.2.5). Remember the attempt as an outgoing request (pending until it expires), so that answer is recognized.
   */
  private async recordContactAttempt(principal: PrincipalRecord, env: Envelope, hash: string, receipt: Receipt, terms: EffectiveTerms, remoteBroker: BrokerId): Promise<void> {
    if (receipt.code !== "not_accepted" || terms.source !== "grant") return;
    const now = this.clock.now();
    const known = (await this.connectionsOf(principal)).some((c) => c.counterparty === env.to.address && (c.state === "pending" || c.state === "approved"));
    if (known) return;
    await this.store.putConnection({
      id: env.id,
      direction: "outgoing",
      principal: principal.address,
      principal_id: principal.principal_id,
      counterparty: env.to.address,
      scopes: [env.scope],
      purpose: "other",
      state: "pending",
      origin: "stranger_message",
      remote_broker: remoteBroker,
      envelope_hash: hash,
      created_at: iso(now),
      updated_at: iso(now),
      expires_at: iso(addSeconds(now, this.limits.connectionTtlSeconds)),
    });
  }

  /**
   * alp.availability/1 (spec 7.8): the body of the request whose window an inform keeps to, in this principal's copy
   * of the thread (`windowRequestId`), or null when there is none.
   */
  private async windowBody(principal: PrincipalRecord, thread: ThreadRecord | null, msg: ThreadMessage, replyTo: MessageRecord | null): Promise<JsonObject | null> {
    const id = windowRequestId(thread?.history ?? [], msg);
    if (id === null) return null;
    if (replyTo?.envelope.id === id) return replyTo.envelope.body;
    const m = await this.store.getMessage(principal.address, msg.direction === "out" ? "in" : "out", id);
    return m && this.owns(principal, m) ? m.envelope.body : null;
  }

  private withPlumbing(terms: EffectiveTerms, type: MessageType): EffectiveTerms {
    if (!PLUMBING.includes(type) || terms.may.includes(type)) return terms;
    return { ...terms, may: [...terms.may, type] };
  }

  /**
   * A ledger payload (spec 11.4): envelope-relative pointers mapped to their values. By default the message's free
   * text and note; `all` also stores typed values; `never` stores nothing. Both sides compute it from the same
   * envelope, so the two ledgers' payload hashes match.
   */
  private payloadOf(policy: OrgPolicy | null, scope: CompiledScope, type: MessageType, body: JsonObject, note: string | undefined): LedgerPayload | undefined {
    return payloadFor(body, note, freeTextPatterns(scope, type), policy?.retention?.store_values ?? "free_text");
  }


  /**
   * Where an address lives (spec 4.5). The domain's document decides, for this broker's own principals too: a stale
   * local record never keeps an address here once the document names another broker. A hosted domain with no
   * document (the Local profile) is decided by local state. An address here that nobody holds is `unknown_local`.
   */
  private async homeOf(address: Address): Promise<Home> {
    const domain = domainOf(address);
    const local = await this.store.getPrincipal(address);
    const here = (): Home => (local && local.status === "active" ? { kind: "local", principal: local } : { kind: "unknown_local" });
    let doc: DomainDocument;
    try {
      doc = await this.resolver.domainDocument(domain);
    } catch (err) {
      // A domain that publishes no document has no home broker except, for a domain this broker hosts, this one.
      const absent = (err as { absent?: unknown } | null)?.absent === true;
      if (absent) return this.domains.has(domain) ? here() : { kind: "none", code: "unknown_recipient", detail: `${domain} publishes no domain document` };
      await this.securityEvent("discovery_failure", { failed: true, details: { domain } });
      return { kind: "none", code: "discovery_failed", detail: `could not discover ${domain}` };
    }
    const entry = homeBroker(doc, address);
    if (entry && entry.id === this.id) return here();
    if (!entry) return { kind: "none", code: "unknown_recipient", detail: `${domain} names no home broker for ${displayAddress(address)}` };
    return { kind: "remote", entry };
  }

  private async deliverAndVerify(env: AnyEnvelope, home: Reachable): Promise<Outcome> {
    if (home.kind === "remote" && blockedBy(this.policyFor(env.from.address), { broker: home.entry.id })) return { kind: "failed", code: "blocked", detail: "that broker is blocked" };
    let result: DeliveryResult;
    if (home.kind !== "remote") result = await this.acceptInbound(structuredClone(env));
    else result = await this.transport.deliver({ broker: home.entry.id, inbox: home.entry.inbox }, env);
    if (result.kind === "unreachable") return { kind: "failed", code: "unreachable", detail: result.message };
    if (result.kind === "refused") return { kind: "failed", code: result.code, detail: result.message, ...(result.retry_after !== undefined ? { retry_after: result.retry_after } : {}) };
    let receipt: Receipt;
    try {
      receipt = checkReceipt(result.receipt);
    } catch (err) {
      return { kind: "failed", code: "bad_envelope", detail: `bad receipt: ${errMessage(err)}` };
    }
    const issuer = home.kind === "remote" ? home.entry.id : this.id;
    if (receipt.origin_broker !== issuer || receipt.aud !== this.id || receipt.envelope_id !== env.id || receipt.envelope_hash !== objectHash(env)) {
      return { kind: "failed", code: "bad_envelope", detail: "the receipt does not match the envelope or the recipient's broker" };
    }
    let v;
    if (home.kind !== "remote") {
      v = await verifyReceipt(receipt, this.keys.jwks());
    } else {
      try {
        v = await verifyReceipt(receipt, await pinnedFederationKeys(await this.resolver.jwks(home.entry.jwks_uri), home.entry));
        if (!v.ok && v.failure === "unknown_kid") v = await verifyReceipt(receipt, await pinnedFederationKeys(await this.resolver.jwks(home.entry.jwks_uri, { refresh: true }), home.entry));
      } catch (err) {
        return { kind: "failed", code: "discovery_failed", detail: errMessage(err) };
      }
    }
    if (!v.ok) return { kind: "failed", code: "bad_signature", detail: `receipt signature did not verify (${v.failure})` };
    return { kind: "ok", receipt, hash: objectHash(receipt), ...(receipt.status === "refused" && result.retry_after !== undefined ? { retry_after: result.retry_after } : {}) };
  }

  private async buildControl(
    principal: PrincipalRecord,
    delegate: DelegateRecord | null,
    to: Address,
    home: Reachable,
    type: ControlType,
    body: JsonObject,
    extra: { note?: string; in_reply_to?: string; in_reply_to_hash?: string },
  ): Promise<ControlEnvelope> {
    const now = this.clock.now();
    const from: Sender = delegate
      ? { address: principal.address, principal_id: principal.principal_id, delegate: delegate.id, attestation: delegate.attestation, class: delegate.class }
      : { address: principal.address, principal_id: principal.principal_id };
    return signControl(
      {
        alp: ALP_VERSION,
        id: this.ids.ulid(),
        thread: this.ids.ulid(),
        ...(extra.in_reply_to && extra.in_reply_to_hash ? { in_reply_to: extra.in_reply_to, in_reply_to_hash: extra.in_reply_to_hash } : {}),
        from,
        to: { address: to, ...(home.kind === "local" ? { principal_id: home.principal.principal_id } : {}) },
        aud: home.kind === "remote" ? home.entry.id : this.id,
        type,
        body,
        ...(extra.note !== undefined ? { note: extra.note } : {}),
        created_at: iso(now),
        expires_at: iso(addSeconds(now, this.limits.defaultTtlSeconds)),
        origin_broker: this.id,
      },
      this.keys,
    );
  }

  // =========================================================================================
  // Ratification internals

  /** Terms were just agreed: ratify by standing grant if its limits cover them, otherwise ask the person. */
  private async beginRatification(principal: PrincipalRecord, thread: ThreadRecord, counterparty: Address, acceptId: string, terms: JsonObject): Promise<void> {
    const now = this.clock.now();
    // Run after an answer, it acts only while the terms still stand.
    const latest = await this.threadOf(principal, thread.id);
    if (!latest || expireIfDue(latest, now).state !== "agreed" || latest.terms_hash !== thread.terms_hash) return;
    const policy = this.policyFor(principal.address);
    const grant = await this.grantOf(principal, counterparty);
    const tr = effectiveTerms({ owner: principal.address, counterparty, scope: thread.scope, direction: "outbound", grant, policy, claimsOf: await this.claimsWith(principal, counterparty), now });
    const standing = tr.ok && grant !== null && tr.terms.source !== "default" && !humanRatificationRequired(tr.terms, policy, thread.scope) && withinLimits(thread.scope, tr.terms.limits, terms);
    if (standing && grant) {
      const record = await this.makeRatification(principal, thread, counterparty, `standing-grant:${grant.id}`, now);
      await this.sendRatificationAck(principal, thread, counterparty, acceptId, record);
      return;
    }
    const open = (await this.store.listRatificationRequests(principal.address)).filter((r) => r.counterparty === counterparty && r.state === "pending" && this.owns(principal, r));
    if (open.length >= MAX_OPEN_RATIFICATIONS_PER_COUNTERPARTY) {
      await this.securityEvent("ratification_paused", { details: { principal_id: principal.principal_id, scope: thread.scope } });
      return;
    }
    const req: RatificationRequest = {
      id: this.ids.ulid(),
      principal: principal.address,
      principal_id: principal.principal_id,
      counterparty,
      thread: thread.id,
      scope: thread.scope,
      terms_hash: thread.terms_hash as string,
      terms,
      accept_id: acceptId,
      state: "pending",
      created_at: iso(now),
      expires_at: iso(addSeconds(now, this.limits.ratificationTtlSeconds)),
    };
    await this.store.putRatificationRequest(req);
    await this.notifyPerson(principal, "ratification_needed", "Terms are waiting for your approval",
      `Your agent agreed terms with ${displayAddress(counterparty)} (${thread.scope}). Nothing is final until you approve them on your broker's page.`,
      this.links.ratification(req.id));
  }

  /**
   * When a thread this principal holds expires, if it can (spec 9.2): not once it is committed or closed. A held reply
   * or follow-up can go only before then; a later message in the thread may extend it.
   */
  async threadDeadline(principal: PrincipalRecord, threadId: string): Promise<string | undefined> {
    const t = await this.threadOf(principal, threadId);
    if (!t || t.state === "committed" || TERMINAL_STATES.includes(t.state)) return undefined;
    return t.expires_at;
  }

  /** The thread left `agreed` (spec 9.2): what still waits for the person's ratification there no longer applies. */
  private async voidRatifications(principal: PrincipalRecord, thread: ThreadRecord): Promise<void> {
    const at = iso(this.clock.now());
    for (const r of await this.store.listRatificationRequests(principal.address)) {
      if (r.thread === thread.id && r.state === "pending" && this.owns(principal, r)) await this.store.putRatificationRequest({ ...r, state: "voided", decided_at: at });
    }
  }

  private async makeRatification(principal: PrincipalRecord, thread: ThreadRecord, counterparty: Address, method: Ratification["method"], now: Date): Promise<Ratification> {
    const home = await this.homeOf(counterparty);
    const record = await signRatification(
      {
        alp: ALP_VERSION,
        id: this.ids.ulid(),
        thread: thread.id,
        scope: thread.scope,
        terms_hash: thread.terms_hash as string,
        principal_id: principal.principal_id,
        address: principal.address,
        method,
        iat: Math.floor(now.getTime() / 1000),
        nonce: newNonce(),
        created_at: iso(now),
        expires_at: iso(addSeconds(now, this.limits.ratificationTtlSeconds)),
        origin_broker: this.id,
        aud: home.kind === "remote" ? home.entry.id : this.id,
      },
      this.keys,
    );
    const latest = (await this.store.getThread(principal.address, thread.id)) ?? thread;
    await this.store.putThread({ ...latest, ratifications: { ...(latest.ratifications ?? {}), mine: { id: record.id, hash: objectHash(record), record } } });
    await this.log(principal, { kind: "ratification", counterparty, thread: thread.id, scope: thread.scope, outcome: "accepted", ref: record.id, policy_ids: [String(method).slice(0, 128)] });
    return record;
  }

  private async sendRatificationAck(principal: PrincipalRecord, thread: ThreadRecord, counterparty: Address, acceptId: string, record: Ratification): Promise<void> {
    await this.sendAs(principal, {
      delegate: null,
      to: counterparty,
      scope: thread.scope,
      type: "ack",
      body: { of: acceptId, status: "ratified", ratification: record as unknown as JsonObject },
      thread: thread.id,
      in_reply_to: acceptId,
    });
  }

  // =========================================================================================
  // Receiving internals

  /** Recipient-side evaluation, steps 7 to 11 (spec 6.7), then the ledger, the receipt and delivery. */
  private async acceptMessage(env: Envelope, hash: string, recipient: PrincipalRecord, verification: IntakeVerification, now: Date): Promise<InboundResult> {
    const owner = recipient.address;
    const sender = env.from.address;
    const base: Partial<LedgerFields> = { counterparty: sender, counterparty_broker: env.origin_broker, envelope_id: env.id, thread: env.thread, scope: env.scope, type: env.type, envelope_hash: hash };
    const refuse = async (step: number, code: ErrorCode, reasons: Reason[], policy_ids?: string[], retryAfter?: number): Promise<InboundResult> => {
      await this.log(recipient, { ...base, kind: "refused_inbound", outcome: "refused", code, ...(policy_ids ? { policy_ids: policy_ids.slice(0, 32) } : {}) }, { detail: ledgerReasons(code, reasons) });
      if (reasons.some((r) => r.code === "dlp_blocked")) await this.securityEvent("dlp_blocked", { details: { code: "dlp_blocked", principal_id: recipient.principal_id, scope: env.scope } });
      return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "refused", codeForSender([{ code }])), step, ...(retryAfter !== undefined ? { retry_after: retryAfter } : {}) };
    };
    const scope = this.scopes.get(env.scope);
    if (!scope) return refuse(9, "unknown_scope", [{ code: "unknown_scope" }]);
    if (!scope.types.has(env.type)) return refuse(9, "unknown_type", [{ code: "unknown_type" }]);
    const policy = this.policyFor(owner);

    // Step 7: kill switches (the sender's address, domain and broker, the scope); the evaluator runs the federation
    // list and the inbound classification rules.
    const killed = blockedBy(policy, { principals: [owner, sender], scope: scope.id, domains: [domainOf(sender)], broker: env.origin_broker, ...(env.from.delegate ? { delegate: env.from.delegate } : {}) });
    if (killed) {
      await this.securityEvent("kill_switch", { details: { scope: scope.id, origin_broker: env.origin_broker }, message: killed });
      return refuse(7, "blocked", [{ code: "blocked", rule: killed }]);
    }

    const vocabulary = this.labelVocabulary(owner, scope.id, "known");
    // Steps 7 to 10 in the evaluator: deny rules, the relationship and coverage, the schema, inbound DLP. A grant bound
    // to another holder of the sender's address is void for this sender (spec 5.2): a new holder inherits nothing.
    const grant = await this.grantOf(recipient, sender, env.from.principal_id);
    // The sender's claims count only when this broker signed the sender in: the envelope is its own, for that
    // principal_id (step 1 checked it). A sender from elsewhere has none here (fail closed, spec 6.4).
    const claimsOf = env.origin_broker === this.id ? await this.claimsWith(recipient, sender, env.from.principal_id) : this.claimsFor([recipient]);
    const tr = effectiveTerms({ owner, counterparty: sender, scope: scope.id, direction: "inbound", grant, policy, claimsOf, now });
    const terms = tr.ok ? this.withPlumbing(tr.terms, env.type) : null;
    const ev = await evaluateMessage({
      direction: "inbound",
      owner,
      owner_id: recipient.principal_id,
      counterparty: sender,
      scope,
      type: env.type,
      body: env.body,
      ...(env.note !== undefined ? { note: env.note } : {}),
      terms,
      policy,
      claimsOf,
      dlp: this.dlp,
      limits: { noteMaxChars: this.limits.noteMaxChars, bodyMaxBytes: this.limits.bodyMaxBytes },
      // Labels the sender added count only if this side's rules know them (spec 6.5); others are dropped.
      extraLabels: env.labels.filter((l) => vocabulary.has(l)),
    });
    if (ev.outcome !== "allow") {
      const first = ev.reasons[0]?.code ?? "not_accepted";
      // A stranger's message becomes a contact attempt: a connection request to the person (spec 6.2.5).
      if (first === "no_relationship" && !(tr.ok === false && tr.revoked)) {
        const stranger = !hasAnyRelationship({ owner, counterparty: sender, grant, policy, claimsOf, now });
        if (stranger && this.strangerToRequest && connectionRequestsAllowed(policy, domainOf(sender))) {
          return this.fileConnectionRequest(env, hash, recipient, [scope.id], "other", "stranger_message", now);
        }
      }
      const step = first === "federation_blocked" || first === "org_policy" ? 7 : first === "schema_invalid" ? 9 : first === "dlp_blocked" ? 10 : 8;
      return refuse(step, ev.code === "schema_invalid" ? "schema_invalid" : first, ev.reasons, ev.policy_ids);
    }
    const okTerms = terms as EffectiveTerms;

    // Step 8: the rate limit and the thread (participants, scope, state, in_reply_to with a matching hash).
    // Between one person's own agents, per directed pair of agents, as at the sender's side.
    const own = sender === owner && env.from.delegate !== undefined && env.to.delegate !== undefined;
    const rate = own ? this.limits.ownAgentRateLimit : (okTerms.rate_limit ?? this.limits.defaultRateLimit);
    const bucket = own ? `own-in|${recipient.principal_id}|${env.from.delegate ?? ""}|${env.to.delegate ?? ""}` : `in|${recipient.principal_id}|${sender}`;
    if (!(await this.store.hitRateLimit(bucket, now, rate.per_seconds, rate.count)).allowed) {
      await this.securityEvent("rate_limited", { details: { principal_id: recipient.principal_id, scope: scope.id, origin_broker: env.origin_broker } });
      return refuse(8, "rate_limited", [{ code: "rate_limited" }]);
    }
    const stored = await this.store.getThread(owner, env.thread);
    if (stored && !this.owns(recipient, stored)) return refuse(8, "thread_state", [{ code: "thread_state", detail: "the thread belongs to an earlier holder of this address" }]);
    const thread = stored;
    let replyTo: MessageRecord | null = null;
    if (env.in_reply_to) {
      replyTo = await this.messageOf(recipient, env.in_reply_to, "out");
      // A reply to a message this broker doesn't hold may have overtaken it (spec 9.3, 10.6): refused as retryable.
      if (!replyTo) return refuse(8, "thread_state", [{ code: "thread_state", detail: "in_reply_to names a message this broker doesn't hold (yet)" }], undefined, REPLY_RETRY_SECONDS);
      if (replyTo.envelope.thread !== env.thread || replyTo.envelope_hash !== env.in_reply_to_hash) {
        return refuse(8, "thread_state", [{ code: "thread_state", detail: "in_reply_to does not match a message in this thread" }]);
      }
    }
    let theirRatification: Ratification | null = null;
    if (env.type === "ack" && env.body["status"] === "ratified") {
      const r = await this.checkInboundRatification(env, thread, now);
      if (typeof r === "string") return refuse(8, "thread_state", [{ code: "thread_state", detail: r }]);
      theirRatification = r;
    }
    const tmsg: ThreadMessage = {
      thread: env.thread,
      principal: owner,
      principal_id: recipient.principal_id,
      counterparty: sender,
      scope: scope.id,
      envelope_id: env.id,
      type: env.type,
      direction: "in",
      at: iso(now),
      expires_at: env.expires_at,
      ...(env.in_reply_to ? { in_reply_to: env.in_reply_to } : {}),
      ...(replyTo && isMessageType(replyTo.envelope.type) ? { reply_to: { type: replyTo.envelope.type, direction: replyTo.direction } } : {}),
      ...(env.terms_hash ? { terms_hash: env.terms_hash } : {}),
      ...(env.ratifications ? { ratifications: env.ratifications } : {}),
      ...(env.type === "ack" ? { ack_status: env.body["status"] as "received" } : {}),
    };
    const applied = applyToThread(scope, thread, tmsg, now);
    if (!applied.ok) return refuse(8, applied.code, [{ code: applied.code, detail: applied.detail }]);
    // Step 9's semantic rules (spec 7.8), against the message answered and, for availability, the request kept to.
    const window = scope.id === "alp.availability/1" && env.type === "inform" ? await this.windowBody(recipient, thread, tmsg, replyTo) : undefined;
    const semantic = scopeSemantics(scope.id, env.type, env.body, replyTo && isMessageType(replyTo.envelope.type) ? { type: replyTo.envelope.type, body: replyTo.envelope.body } : undefined, window);
    if (semantic) return refuse(9, "schema_invalid", [{ code: "schema_invalid", detail: semantic }]);

    // Step 11: delivery constraints. One this broker can't honor at all is refused; otherwise only the person's
    // agents that meet them see the message, and if none does it waits on the person's web view.
    const unsupported = this.unsupportedConstraint(policy, env.constraints);
    if (unsupported) return refuse(11, "constraints_unsupported", [{ code: "constraints_unsupported", detail: unsupported }]);
    const nextThread = applied.thread;
    if (theirRatification) {
      nextThread.ratifications = { ...(nextThread.ratifications ?? {}), theirs: { id: theirRatification.id, hash: objectHash(theirRatification), record: theirRatification } };
    }
    await this.store.putThread(nextThread);

    // An agent the organization blocked, or whose client its list no longer allows, never counts as able to receive
    // (spec 5.8, 6.10): it can't read, and isn't pushed to. Each agent is ranked by the current list (spec 5.4). The
    // agent `to.delegate` names counts only if its binding had started when this broker received the message: one
    // that started later is another agent and can't read it (spec 5.4), so the message waits for the person instead.
    const receivedAt = now.getTime();
    const named = (x: DelegateRecord): boolean => !env.to.delegate || (env.to.delegate === x.id && Date.parse(x.created_at) <= receivedAt);
    const delegates = (await this.store.listDelegates(owner))
      .filter((x) => x.status === "active" && x.principal_id === recipient.principal_id && named(x) && !blockedBy(policy, { delegate: x.id, client_id: x.client_id }) && !this.clientRefused(owner, x.client_id))
      .map((x) => this.ranked(x));
    const qualifying = delegates.filter((x) => meetsConstraints(env.constraints, x, clientRule(policy, x.client_id)));
    // Held for the person's web view (spec 6.7, 6.11): no agent meets the delivery constraints, or the agent `to.delegate`
    // names can't receive it (none with that label is active, it is blocked, or its client is refused). The sender
    // addressed that one agent, so the message never goes to the person's other agents instead. The receipt is the
    // same either way, and what a hold adds happens after the answer (below).
    const heldReason: MessageRecord["held_reason"] = qualifying.length > 0 ? undefined : env.to.delegate !== undefined && delegates.length === 0 ? "to_delegate" : env.constraints !== undefined ? "constraints" : undefined;
    const heldForPerson = heldReason !== undefined;
    // When the grant's quiet hours end, if they are on, whatever else the message waits for. Only a message an agent
    // may read waits for them to end (`held_until`); one held for the person stays on the web view. Either way the
    // person's notification, if it needs one, waits until then (below).
    const quietHours = okTerms.quiet_hours;
    const quietEnd = quietHours !== undefined && isQuietTime(quietHours, now) ? quietHoursEnd(quietHours, now) : undefined;
    const quietUntil = quietEnd !== undefined && !heldForPerson ? iso(quietEnd) : undefined;
    const held = heldForPerson || quietUntil !== undefined;
    // Accept: `received` in the ledger (its hash goes in the receipt), then the receipt, then delivery. A message that
    // waits says where in that entry (`ref`), so the ledger records the hold before the answer, in the one entry written
    // either way: nothing is lost if the broker stops right after answering. The entry's random salt (spec 11.4) keeps
    // the receipt's `ledger_hash` from confirming any guess of it, the hold included.
    const entry = await this.log(recipient, {
      ...base,
      kind: "received",
      outcome: "accepted",
      ...(held ? { ref: quietUntil ? `until:${quietUntil}` : "web_view" } : {}),
      disclosed: ev.disclosed,
      labels: ev.labels,
      policy_ids: [...ev.policy_ids, ...ev.report_ids].slice(0, 32),
    }, this.payloadOf(policy, scope, env.type, env.body, env.note));
    const receipt = await this.issueReceipt(env, hash, "accepted", undefined, entry.hash);
    // First contact under a grant: from now on it holds only for this sender's principal_id (spec 5.2).
    if (grant && grant.status === "active" && grant.counterparty_principal_id === undefined && sender !== owner) await this.bindCounterparty(recipient, grant, env.from.principal_id);
    await this.store.putMessage({ local_id: this.ids.ulid(), principal: owner, principal_id: recipient.principal_id, direction: "in", envelope: env, envelope_hash: hash, status: held ? "held" : "delivered", ...(quietUntil ? { held_until: quietUntil } : {}), ...(heldReason ? { held_reason: heldReason } : {}), receipt, receipt_hash: objectHash(receipt), verification, acked_by: {}, stored_at: iso(now) });
    // Agreed terms: the person's ratification, or the standing grant's, once the answer is out. The accepting broker
    // records its own accept only when this receipt is back, so a ratification ack sent before then would find no
    // agreed terms there (and how long the answer takes doesn't depend on the recipient's grant).
    if (env.type === "accept" && nextThread.state === "agreed") {
      const terms = env.body["terms"] as JsonObject;
      this.afterAnswering(() => this.beginRatification(recipient, nextThread, sender, env.id, terms));
    }
    if (stored?.state === "agreed" && nextThread.state !== "agreed") this.afterAnswering(() => this.voidRatifications(recipient, nextThread));

    // Up to here the work is the same whether or not the message waits for the person. What a hold adds (the person's
    // notification, with its rate-limit record) and the pushes run after the answer, handed out last so that nothing
    // awaited comes between them and the answer: how long the answer takes doesn't tell the sender which agents the
    // person has (spec 6.7). A failure there never undoes what was recorded.
    this.afterAnswering(() => this.afterAccepting(recipient, env, heldReason, quietEnd, held ? [] : qualifying, now));
    return { kind: "receipt", receipt };
  }

  /**
   * After a message is accepted and the sender answered (spec 6.7, 12.5.1): the person's notification if any, then a
   * push to each agent that may read it. During the grant's quiet hours the person is told of nothing from this sender
   * until they end, whatever the message waits for, and the page lists it: a message an agent can read brings no
   * notification then, so one that waits because of the person's agents (which the sender controls) brings none
   * either, or the sender could disturb the person at will and learn from their reaction that the message waits for
   * them. The notification is kept (`DeferredNotice`) and sent once they end (`sendDueNotices`), which tells the
   * sender no more than a message sent at that moment would.
   */
  private async afterAccepting(recipient: PrincipalRecord, env: Envelope, heldReason: MessageRecord["held_reason"], quietEnd: Date | undefined, push: DelegateRecord[], now: Date): Promise<void> {
    if (quietEnd === undefined) await this.notifyAccepted(recipient, env, heldReason, now);
    else if (noticeOf(recipient, env, heldReason) !== null) {
      await this.store.putDeferredNotice({ id: this.ids.ulid(), principal: recipient.address, principal_id: recipient.principal_id, envelope_id: env.id, due_at: iso(quietEnd) });
    }
    const pusher = this.pusher;
    if (!pusher) return;
    for (const x of push) {
      try {
        await pusher.push(x, this.ids.ulid());
      } catch {
        // a push is a hint; the message waits in the inbox either way
      }
    }
  }

  /**
   * The person's notification of an accepted message, if it needs one (`noticeOf`): as it arrives, or once the
   * grant's quiet hours it arrived in have ended (`sendDueNotices`), judged at `now`.
   */
  private async notifyAccepted(recipient: PrincipalRecord, env: Envelope, heldReason: MessageRecord["held_reason"], now: Date): Promise<void> {
    const kind = noticeOf(recipient, env, heldReason);
    if (kind === null) return;
    const from = displayAddress(env.from.address);
    const link = this.links.message(env.id);
    if (kind === "ask_human") {
      // ask_human is for the person whichever agents they have (spec 6.7): each one is notified, also when it waits
      // because of the person's agents.
      await this.notifyPerson(recipient, "ask_human", "An agent asked for your decision",
        `The agent of ${from} asked for a person's decision (${env.scope}). Open your broker's page to see it.`, link);
    } else if (kind === "message_held") {
      // A sender with a relationship controls both reasons a message waits for the person because of the person's
      // agents: it can name agents that don't exist, or set constraints none meets. So at most one such notification an
      // hour per sender (the page lists them all), and never with the label the sender chose.
      if (!(await this.store.hitRateLimit(`held-notify|${recipient.principal_id}|${env.from.address}`, now, 3600, 1)).allowed) return;
      await this.notifyPerson(recipient, "message_held", "A message is waiting on your broker's page", heldReason === "to_delegate"
        ? `A ${env.scope} message from ${from} names one of your agents that isn't connected or can't receive it, so it is shown only on your broker's page.`
        : `A ${env.scope} message from ${from} needs an agent setup that meets its sender's delivery rules, so it is shown only on your broker's page.`, link);
    } else {
      await this.notifyPerson(recipient, "message_waiting", "A message is waiting on your broker's page",
        `A ${env.scope} message from ${from} is waiting. Your agent has no connector, so it is shown on your broker's page.`, link);
    }
  }

  /**
   * Sends the notifications that waited for a grant's quiet hours to end and are due now (spec 6.7): what the person
   * would have been told when each message arrived, judged now (each `ask_human`; at most one an hour per sender of
   * the messages held for them). One whose person or message is gone is dropped, and one that fails doesn't stop the
   * rest (the failure goes to `onBackgroundError`). The servers run it every minute (`startNoticeTimer`). Returns how
   * many it took from the store.
   */
  async sendDueNotices(): Promise<number> {
    const now = this.clock.now();
    const batch = 100;
    let taken = 0;
    for (;;) {
      const due = await this.store.takeDueNotices(now, batch);
      taken += due.length;
      for (const n of due) {
        try {
          const recipient = await this.store.getPrincipalById(n.principal_id);
          if (!recipient || recipient.status !== "active" || recipient.address !== n.principal) continue;
          const m = await this.store.getMessage(recipient.address, "in", n.envelope_id);
          if (!m || !this.owns(recipient, m)) continue;
          await this.notifyAccepted(recipient, m.envelope, m.held_reason, now);
        } catch (err) {
          this.reportBackgroundError(err);
        }
      }
      if (due.length < batch) return taken;
    }
  }

  /**
   * Runs `sendDueNotices` every `everyMs` (default a minute) as work handed out after an answer is: `settled` waits
   * for a run in progress, and a failure goes to `onBackgroundError`. Returns the function that stops it. The servers
   * start it; tests call `sendDueNotices` themselves.
   */
  startNoticeTimer(everyMs = 60_000): () => void {
    // One run at a time: a store slow enough to take longer than `everyMs` doesn't pile runs up.
    let running = false;
    const timer = setInterval(() => {
      if (running) return;
      running = true;
      const handed = this.handOut(async () => {
        try {
          await this.sendDueNotices();
        } finally {
          running = false;
        }
      });
      if (!handed) running = false;
    }, everyMs);
    timer.unref();
    return () => clearInterval(timer);
  }

  /**
   * A delivery constraint this broker can't honor at all (spec 6.11), or null. `retention_max`: the reference has
   * no timed purge yet, so it can honor a retention limit only when it keeps no payload values longer than that.
   */
  private unsupportedConstraint(policy: OrgPolicy | null, c: Constraints | undefined): string | null {
    if (!c) return null;
    const support = this.constraintSupport;
    if (c.deliver_to && support.deliver_to === false) return "deliver_to";
    if (c.no_training && support.no_training === false) return "no_training";
    if (c.retention_max !== undefined) {
      if (support.retention_max === false) return "retention_max";
      const keepsValues = (policy?.retention?.store_values ?? "free_text") !== "never";
      if (support.retention_max === undefined && keepsValues && (policy?.retention?.ledger_days ?? Number.POSITIVE_INFINITY) > c.retention_max) return "retention_max";
    }
    return null;
  }

  private async checkInboundRatification(env: Envelope, thread: ThreadRecord | null, now: Date): Promise<Ratification | string> {
    let record: Ratification;
    try {
      record = checkRatification(env.body["ratification"]);
    } catch {
      return "the ratification record is malformed";
    }
    if (!thread || thread.state !== "agreed" || !thread.terms_hash) return "no agreed terms to ratify";
    if (record.terms_hash !== thread.terms_hash || record.thread !== env.thread || record.scope !== env.scope) return "the ratification is for other terms";
    if (record.address !== env.from.address || record.principal_id !== env.from.principal_id || record.origin_broker !== env.origin_broker) return "the ratification is not the sender's";
    if (record.aud !== this.id) return "the ratification is addressed to another broker";
    if (Date.parse(record.expires_at) <= now.getTime()) return "the ratification has expired";
    let keys: Jwks;
    if (env.origin_broker === this.id) {
      keys = this.keys.jwks();
    } else {
      try {
        const doc = await this.resolver.domainDocument(domainOf(env.from.address));
        const home = homeBroker(doc, env.from.address);
        if (!home) return "no home broker for the sender";
        keys = await pinnedFederationKeys(await this.resolver.jwks(home.jwks_uri), home);
      } catch {
        return "the sender's keys could not be checked";
      }
    }
    return (await verifyRatification(record, keys)).ok ? record : "the ratification signature did not verify";
  }

  private async acceptControl(env: ControlEnvelope, hash: string, recipient: PrincipalRecord, now: Date): Promise<InboundResult> {
    const owner = recipient.address;
    const sender = env.from.address;
    const policy = this.policyFor(owner);
    const base: Partial<LedgerFields> = { counterparty: sender, counterparty_broker: env.origin_broker, envelope_id: env.id, type: env.type, envelope_hash: hash };
    const refuse = async (code: ErrorCode, detail?: string): Promise<InboundResult> => {
      await this.log(recipient, { ...base, kind: "refused_inbound", outcome: "refused", code }, detail ? { detail: [{ code, detail }] } : undefined);
      return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "refused", codeForSender([{ code }])) };
    };
    if (env.type === "connection_request") {
      // Spec 6.2.2: past steps 0 to 6, every connection request gets the same `accepted` receipt, with no ledger hash,
      // whether the person sees it, a rule or limit drops it, or nobody holds the address.
      const drop = async (why: string, code: ErrorCode): Promise<InboundResult> => {
        await this.securityEvent("connection_request_dropped", { details: { domain: domainOf(sender), code }, message: why });
        await this.log(recipient, { ...base, kind: "refused_inbound", outcome: "refused", code });
        return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "accepted") };
      };
      if (!federationAllows(policy, domainOf(sender))) return drop("federation list", "federation_blocked");
      const killed = blockedBy(policy, { principals: [owner, sender], domains: [domainOf(sender)], broker: env.origin_broker });
      if (killed) return drop(killed, "blocked");
      if (!connectionRequestsAllowed(policy, domainOf(sender))) return drop("connection_requests.inbound", "not_accepted");
      const scopes = (env.body["scopes"] as string[]).filter((s) => this.scopes.get(s) !== undefined);
      return this.fileConnectionRequest(env, hash, recipient, scopes, env.body["purpose"] as ConnectionRequestRecord["purpose"], "explicit", now);
    }

    if (!federationAllows(policy, domainOf(sender))) return refuse("federation_blocked");
    if (blockedBy(policy, { principals: [owner, sender], domains: [domainOf(sender)], broker: env.origin_broker })) return refuse("blocked");

    if (env.type === "connection_response") {
      const reqId = String(env.body["of"]);
      const req = await this.store.getConnection(owner, reqId);
      if (!req || !this.owns(recipient, req) || req.direction !== "outgoing" || req.counterparty !== sender || env.in_reply_to !== reqId || env.in_reply_to_hash !== req.envelope_hash) {
        return refuse("thread_state", "no matching connection request or contact attempt");
      }
      let next: ConnectionRequestRecord;
      try {
        if (env.body["decision"] === "accepted") {
          const approved = (env.body["scopes"] as string[]).filter((s) => req.scopes.includes(s));
          next = transitionConnection(req, approved.length ? "approved" : "declined", now, approved.length ? { approved_scopes: approved } : {});
          if (approved.length) {
            const scopes: Record<ScopeId, ScopeTerms> = {};
            for (const s of approved) scopes[s] = req.requester_terms?.[s] ?? defaultScopeTerms(this.scopes.require(s));
            // The requester's terms become a grant: active if the person sealed them when filing, else pending
            // until the person reviews and seals them (an agent can never seal a grant).
            const sealedBy: HumanCaller | null = req.requester_sealed ? { kind: "human", principal: owner, auth: req.requester_sealed } : null;
            await this.mergeGrant(recipient, sender, env.from.principal_id, scopes, sealedBy, req.id, now);
          }
        } else {
          next = transitionConnection(req, "declined", now);
        }
      } catch {
        return refuse("thread_state", "the request is no longer pending");
      }
      await this.store.putConnection({ ...next, counterparty_principal_id: env.from.principal_id });
      const entry = await this.log(recipient, { ...base, kind: "connection_decided", outcome: next.state === "approved" ? "accepted" : "refused", ref: next.id });
      await this.notifyPerson(recipient, "connection_decided",
        next.state === "approved" ? "Your connection request was approved" : "Your connection request was declined",
        next.state === "approved"
          ? `${displayAddress(sender)} approved: ${(next.approved_scopes ?? []).join(", ")}. Review and confirm the terms on your broker's page before your agent can use them.`
          : `${displayAddress(sender)} declined your connection request.`,
        this.links.connection(next.id));
      return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "accepted", undefined, entry.hash) };
    }

    // revoke, address_reassigned (spec 5.2): the person who held the sender's address is gone. Our principal's grant
    // stays bound to that person's principal_id, so it is void for whoever holds the address next; nothing is recorded
    // against the address itself, which a new holder would otherwise inherit.
    if (env.body["reason"] === "address_reassigned") {
      const g = await this.store.getGrant(owner, sender);
      if (g && g.principal_id === recipient.principal_id && (g.counterparty_principal_id === undefined || g.counterparty_principal_id === env.from.principal_id)) {
        await this.storeGrant(recipient, { ...g, counterparty_principal_id: env.from.principal_id, status: "revoked", updated_at: iso(now) }, "grant_revoked");
      }
      const entry = await this.log(recipient, { ...base, kind: "counterparty_revoked", outcome: "info" });
      return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "accepted", undefined, entry.hash) };
    }

    // revoke: the counterparty no longer accepts these scopes from our principal, so we stop sending them.
    const listed = env.body["scopes"] as string[];
    const prior = await this.store.getRevocation(owner, sender);
    const all = listed[0] === "*" || prior?.scopes[0] === "*";
    const rec: CounterpartyRevocation = {
      principal: owner,
      counterparty: sender,
      scopes: all ? ["*"] : [...new Set([...((prior?.scopes as string[] | undefined) ?? []), ...listed])],
      reason: String(env.body["reason"]),
      effective_at: String(env.body["effective_at"]),
      received_at: iso(now),
    };
    await this.store.putRevocation(rec);
    const entry = await this.log(recipient, { ...base, kind: "counterparty_revoked", outcome: "info" });
    return { kind: "receipt", receipt: await this.issueReceipt(env, hash, "accepted", undefined, entry.hash) };
  }

  /** A connection request reaches the person (their broker's page, and a notification that only notifies), never the agent. */
  private async fileConnectionRequest(
    env: AnyEnvelope,
    hash: string,
    recipient: PrincipalRecord,
    scopes: ScopeId[],
    purpose: ConnectionRequestRecord["purpose"],
    origin: "explicit" | "stranger_message",
    now: Date,
  ): Promise<InboundResult> {
    const owner = recipient.address;
    const sender = env.from.address;
    const base: Partial<LedgerFields> = { counterparty: sender, counterparty_broker: env.origin_broker, envelope_id: env.id, type: env.type, envelope_hash: hash };
    // The requester gets the same answer whatever happens here (spec 6.2.2): an explicit request is `accepted`, with
    // no ledger hash; a stranger's message is refused `not_accepted`, like any message the recipient's rules refuse.
    const answer = async (): Promise<InboundResult> =>
      origin === "stranger_message"
        ? { kind: "receipt", receipt: await this.issueReceipt(env, hash, "refused", "not_accepted"), step: 8 }
        : { kind: "receipt", receipt: await this.issueReceipt(env, hash, "accepted") };
    const drop = async (code: ErrorCode, why: string): Promise<InboundResult> => {
      await this.securityEvent("connection_request_dropped", { details: { domain: domainOf(sender), code }, message: why });
      await this.log(recipient, { ...base, kind: "refused_inbound", outcome: "refused", code });
      return answer();
    };
    if (scopes.length === 0) return drop("unknown_scope", "no scope this broker knows");
    const mine = await this.connectionsOf(recipient);
    const declinedSince = now.getTime() - this.limits.declinedRequesterDays * 86400 * 1000;
    if (mine.some((c) => c.direction === "incoming" && c.counterparty === sender && c.state === "declined" && Date.parse(c.updated_at) >= declinedSince)) {
      return drop("not_accepted", `the person declined this requester within ${this.limits.declinedRequesterDays} days`);
    }
    // Quotas per requester, per registrable domain (a wildcard domain shares one) and per origin broker.
    const limits: [string, number][] = [
      [`conn-in|${recipient.principal_id}|${sender}`, this.limits.connectionRequestsPerSenderPerDay],
      [`conn-in-domain|${recipient.principal_id}|${registrableDomain(domainOf(sender))}`, this.limits.connectionRequestsPerDomainPerDay],
      [`conn-in-broker|${recipient.principal_id}|${env.origin_broker}`, this.limits.connectionRequestsPerBrokerPerDay],
    ];
    for (const [key, max] of limits) {
      if (!(await this.store.hitRateLimit(key, now, 86400, max)).allowed) return drop("rate_limited", "connection request quota");
    }
    let note = isControlType(env.type) ? (env as ControlEnvelope).note : undefined;
    if (note !== undefined) {
      const v = await runDlp(this.dlp, { principal_id: recipient.principal_id, principal: owner, counterparty: sender, direction: "inbound", scope: scopes[0] as string, labels: ["note"], pointer: "/note", text: note });
      note = v.verdict === "allow" || v.verdict === "notify" ? sanitizeText(note) : undefined;
    }
    const displayName = isControlType(env.type) && typeof env.body["display_name"] === "string" ? sanitizeText(env.body["display_name"]) : undefined;
    const pending = mine.find((c) => c.direction === "incoming" && c.counterparty === sender && expireConnectionIfDue(c, now).state === "pending");
    const rec: ConnectionRequestRecord = pending
      ? { ...pending, scopes: [...new Set([...pending.scopes, ...scopes])], updated_at: iso(now) }
      : {
          id: env.id,
          direction: "incoming",
          principal: owner,
          principal_id: recipient.principal_id,
          counterparty: sender,
          counterparty_principal_id: env.from.principal_id,
          scopes,
          purpose,
          ...(note !== undefined ? { note } : {}),
          ...(displayName !== undefined ? { display_name: displayName } : {}),
          state: "pending",
          origin,
          remote_broker: env.origin_broker,
          envelope_hash: hash,
          created_at: iso(now),
          updated_at: iso(now),
          expires_at: iso(addSeconds(now, this.limits.connectionTtlSeconds)),
        };
    await this.store.putConnection(rec);
    await this.log(recipient, { ...base, kind: "connection_received", outcome: "held", ref: rec.id }, note !== undefined ? { note } : undefined);
    // A digest by default (spec 6.2.2): at most one email a day about connection requests; the page lists them all.
    if (!pending && (await this.store.hitRateLimit(`conn-notify|${recipient.principal_id}`, now, 86400, 1)).allowed) {
      await this.notifyPerson(recipient, "connection_request", "Someone asked to connect",
        [
          `${displayAddress(sender)} asked to connect for: ${scopes.join(", ")}.`,
          origin === "stranger_message" ? "Their agent tried to send a message first; it was held back and your agent did not see it." : "",
          "Review it on your broker's page. Until you approve it there, their agent cannot reach yours. Other requests that arrive today are listed there too, without another email.",
        ].filter(Boolean).join("\n"),
        this.links.connection(rec.id));
    }
    return answer();
  }

  /** `remember: false` for a replay refusal, which must not replace the receipt the original envelope got. */
  private async issueReceipt(env: AnyEnvelope, hash: string, status: "accepted" | "refused", code?: ErrorCode, ledgerHash?: string, remember = true): Promise<Receipt> {
    const now = this.clock.now();
    const receipt = await signReceipt(
      {
        alp: ALP_VERSION,
        id: this.ids.ulid(),
        envelope_id: env.id,
        envelope_hash: hash,
        status,
        ...(status === "refused" ? { code: code ?? "not_accepted" } : {}),
        ...(status === "accepted" && ledgerHash ? { ledger_hash: ledgerHash } : {}),
        created_at: iso(now),
        expires_at: iso(addSeconds(now, this.limits.receiptTtlSeconds)),
        origin_broker: this.id,
        aud: env.origin_broker,
      },
      this.keys,
    );
    if (remember) await this.store.putReceipt(receiptKey(env.origin_broker, env.id), receipt);
    return receipt;
  }

  // =========================================================================================
  // Shared helpers

  /**
   * Records keyed by address belong to the principal that wrote them (spec 5.2): a record stamped with another
   * principal_id belongs to an earlier holder of the address, and its new holder never sees or uses it.
   */
  private owns(principal: PrincipalRecord, rec: { principal_id?: string }): boolean {
    return rec.principal_id === undefined || rec.principal_id === principal.principal_id;
  }

  private async connectionsOf(principal: PrincipalRecord): Promise<ConnectionRequestRecord[]> {
    return (await this.store.listConnections(principal.address)).filter((c) => this.owns(principal, c));
  }

  private async threadOf(principal: PrincipalRecord, id: string): Promise<ThreadRecord | null> {
    const t = await this.store.getThread(principal.address, id);
    return t && this.owns(principal, t) ? t : null;
  }

  /** A message of this principal's, sent or received (`first` is the direction to look in first). */
  private async messageOf(principal: PrincipalRecord, envelopeId: string, first: "in" | "out" = "in"): Promise<MessageRecord | null> {
    for (const dir of first === "in" ? (["in", "out"] as const) : (["out", "in"] as const)) {
      const m = await this.store.getMessage(principal.address, dir, envelopeId);
      if (m && this.owns(principal, m)) return m;
    }
    return null;
  }

  /**
   * The principal's own grant toward a counterparty (spec 5.2): a grant an earlier holder of the principal's address
   * sealed is void, and so is one bound to an earlier holder of the counterparty's address (`counterpartyId` is the
   * counterparty's principal_id, where known).
   */
  async grantOf(principal: PrincipalRecord, counterparty: Address, counterpartyId?: string): Promise<RelationshipGrant | null> {
    const g = await this.store.getGrant(principal.address, counterparty);
    if (!g || g.principal_id !== principal.principal_id) return null;
    if (counterpartyId !== undefined && g.counterparty_principal_id !== undefined && g.counterparty_principal_id !== counterpartyId) return null;
    return g;
  }

  /** First contact: bind a grant to the counterparty's principal_id, so it never carries over to a new holder of the address. */
  private async bindCounterparty(principal: PrincipalRecord, grant: RelationshipGrant, counterpartyId: string): Promise<void> {
    const current = await this.store.getGrant(principal.address, grant.counterparty);
    if (!current || current.id !== grant.id || current.counterparty_principal_id !== undefined) return;
    await this.store.putGrant(await signGrant({ ...current, counterparty_principal_id: counterpartyId }, this.keys));
  }

  /**
   * Spec 5.2: before an address goes to a different person, end the old principal's relationships. Their grants are
   * voided and each counterparty is told (`revoke`, reason `address_reassigned`); their agents are disconnected; what
   * waits for them (held messages, ratifications, connection requests) is closed. Their ledger is kept.
   */
  private async endRelationships(old: PrincipalRecord, now: Date): Promise<void> {
    for (const g of await this.store.listGrants(old.address)) {
      if (g.principal_id !== old.principal_id || g.status === "revoked") continue;
      await this.storeGrant(old, { ...g, status: "revoked", updated_at: iso(now) }, "grant_revoked");
      if (g.basis !== "consent" || g.status !== "active") continue;
      const home = await this.homeOf(g.counterparty);
      if (home.kind === "none" || home.kind === "unknown_local") continue;
      const env = await this.buildControl(old, null, g.counterparty, home, "revoke", { scopes: ["*"], reason: "address_reassigned", effective_at: iso(now) }, {});
      const outcome = await this.deliverAndVerify(env, home);
      if (outcome.kind === "failed") await this.log(old, { kind: "delivery_failed", counterparty: g.counterparty, envelope_id: env.id, type: "revoke", outcome: "refused", code: outcome.code });
    }
    for (const d of await this.store.listDelegates(old.address)) {
      if (d.principal_id === old.principal_id && d.status === "active") await this.store.putDelegate({ ...d, status: "revoked" });
    }
    for (const h of await this.store.listHeldOutbound(old.address)) {
      if (h.state === "pending" && this.owns(old, h)) await this.store.claimHeldOutbound({ ...h, state: "discarded", decided_at: iso(now) });
    }
    for (const r of await this.store.listRatificationRequests(old.address)) {
      if (r.state === "pending" && this.owns(old, r)) await this.store.putRatificationRequest({ ...r, state: "voided", decided_at: iso(now) });
    }
    for (const c of await this.connectionsOf(old)) {
      if (c.state === "pending") await this.store.putConnection({ ...c, principal_id: old.principal_id, state: "cancelled", updated_at: iso(now) });
    }
    await this.securityEvent("principal_reassigned", { details: { principal_id: old.principal_id } });
  }

  /**
   * A kill switch (spec 5.8) on this agent, its client or its principal: the first matching entry, or null. The
   * client binding's resource server and token refresh use it too, so a blocked agent can neither read nor renew.
   */
  agentBlocked(principal: Address, delegate: DelegateId | undefined, clientId: string | undefined): string | null {
    return blockedBy(this.policyFor(principal), { principals: [principal], ...(delegate ? { delegate } : {}), ...(clientId ? { client_id: clientId } : {}) });
  }

  /**
   * Whether the organization's list of agents keeps this client out (spec 6.10): in `enforce` mode, a client the list
   * doesn't name may not sign in, read, send or refresh; `pat` stands for personal access tokens. The client binding's
   * resource server, token refresh and the person's page (minting a personal access token) use it too.
   */
  clientRefused(principal: Address, clientId: string | undefined): boolean {
    const policy = this.policyFor(principal);
    if (clientId === undefined || policy?.clients?.mode !== "enforce") return false;
    return clientRule(policy, clientId) === undefined;
  }

  /** An agent reading (whoami, contacts, inbox, thread, ack): authenticated, not blocked, and its client allowed. */
  private async authReader(caller: DelegateCaller): Promise<{ principal: PrincipalRecord; delegate: DelegateRecord }> {
    const who = await this.authDelegate(caller);
    const killed = this.agentBlocked(who.principal.address, who.delegate.id, who.delegate.client_id);
    if (killed) {
      await this.securityEvent("kill_switch", { message: killed, details: { principal_id: who.principal.principal_id, client_id: who.delegate.client_id } });
      throw new AlpError("blocked", "your organization has blocked this agent", { status: 403 });
    }
    if (this.clientRefused(who.principal.address, who.delegate.client_id)) {
      await this.securityEvent("client_refused", { failed: true, details: { principal_id: who.principal.principal_id, client_id: who.delegate.client_id } });
      throw new AlpError("client_not_allowed", "your organization's list of agents doesn't include this agent", { status: 403 });
    }
    return who;
  }

  /**
   * A delegate as its organization's current list of agents ranks it (spec 5.4). A lower attestation or class in the
   * current list applies at once to agents already connected; a higher one waits for the agent's next sign-in, when
   * the broker checks the client's credential. A client the list no longer names is at most `vendor` and `consumer`.
   * A personal access token is never above `self` and `business`. The client binding's `alp_whoami` uses it too, to
   * show a person's other agents as the broker ranks them.
   */
  ranked(d: DelegateRecord): DelegateRecord {
    let attestation = d.attestation;
    let cls = d.class;
    const policy = this.policyFor(d.principal);
    if (policy?.clients) {
      const rule = clientRule(policy, d.client_id);
      attestation = lowerAttestation(attestation, rule ? rule.attestation : "vendor");
      cls = lowerClass(cls, rule ? rule.class : "consumer");
    }
    if (d.client_id === PAT_CLIENT_ID) {
      attestation = "self";
      cls = lowerClass(cls, "business");
    }
    return attestation === d.attestation && cls === d.class ? d : { ...d, attestation, class: cls };
  }

  private async page(
    principal: PrincipalRecord,
    query: InboxQuery,
    q: { forDelegate?: DelegateId; unackedBy?: DelegateId; bindingSince?: string; filter?: (m: MessageRecord) => boolean },
  ): Promise<InboxPage> {
    const own = q.filter;
    q = { ...q, filter: (m) => this.owns(principal, m) && (own ? own(m) : true) };
    if (query.cursor !== undefined && !isUlid(query.cursor)) throw new AlpError("invalid_input", "bad cursor");
    const limit = Math.max(1, Math.min(query.limit ?? 20, this.limits.inboxPageMax));
    const items: InboxItem[] = [];
    let after = query.cursor;
    let hasMore = false;
    let done = false;
    // Read in batches so records an agent may not see never shorten a page.
    for (let round = 0; round < 100 && !done; round++) {
      const batch = await this.store.listMessages(principal.address, {
        direction: "in",
        limit: limit + 1,
        ...(after ? { after } : {}),
        ...(q.forDelegate ? { forDelegate: q.forDelegate } : {}),
        ...(q.unackedBy ? { unackedBy: q.unackedBy } : {}),
        ...(q.bindingSince ? { bindingSince: q.bindingSince } : {}),
      });
      for (const m of batch) {
        if (q.filter && !q.filter(m)) {
          after = m.local_id;
          continue;
        }
        if (items.length === limit) {
          hasMore = true;
          break;
        }
        items.push(this.toItem(m));
        after = m.local_id;
      }
      done = hasMore || batch.length <= limit;
    }
    if (!done) {
      // Records this reader may not see filled every batch read: say there is more, from past the last one read, so a
      // reader can go on instead of being told there is nothing (and asking again from the same place).
      return { items, next_cursor: after ?? null, has_more: true };
    }
    const last = items[items.length - 1];
    return { items, next_cursor: last ? last.local_id : query.cursor ?? null, has_more: hasMore };
  }

  private toItem(m: MessageRecord): InboxItem {
    const e = m.envelope;
    const vocabulary = this.labelVocabulary(m.principal, e.scope, "known");
    const scope = this.scopes.get(e.scope);
    const ft = scope ? freeTextPatterns(scope, e.type) : [];
    const v = m.verification as IntakeVerification;
    return {
      local_id: m.local_id,
      status: m.status === "held" && m.held_until !== undefined && Date.parse(m.held_until) <= this.clock.now().getTime() ? "released" : m.status,
      received_at: m.stored_at,
      verified: {
        sender: {
          address: e.from.address,
          display: displayAddress(e.from.address),
          principal_id: e.from.principal_id,
          ...(e.from.delegate ? { delegate: e.from.delegate } : {}),
          ...(e.from.attestation ? { attestation: e.from.attestation } : {}),
          ...(e.from.class ? { class: e.from.class } : {}),
        },
        sender_broker: e.origin_broker,
        signature: "verified",
        kid: v.kid,
        scope: e.scope,
        type: e.type,
        thread: e.thread,
        ...(e.in_reply_to ? { in_reply_to: e.in_reply_to } : {}),
        decision: e.decision,
        labels: e.labels.filter((l) => vocabulary.has(l)),
        ...(v.flags ? { flags: v.flags } : {}),
      },
      content: { body: sanitizeBody(e.body, ft), ...(e.note !== undefined ? { note: sanitizeText(e.note) } : {}) },
      envelope: e,
      ...(m.receipt ? { receipt: m.receipt } : {}),
    };
  }

  private async mergeGrant(
    principal: PrincipalRecord,
    counterparty: Address,
    counterpartyId: string | undefined,
    scopes: Record<ScopeId, ScopeTerms>,
    sealedBy: HumanCaller | null,
    connection: string,
    now: Date,
  ): Promise<RelationshipGrant> {
    const existing = await this.store.getGrant(principal.address, counterparty);
    const keep = existing && existing.status !== "revoked" && existing.basis === "consent" ? existing.scopes : {};
    // Only a person's fresh sign-in can seal (or widen) a grant; anything else lands as pending for review.
    const activeAlready = existing?.status === "active" && existing.basis === "consent";
    const grant: RelationshipGrant = {
      alp: ALP_VERSION,
      id: existing?.id ?? this.ids.ulid(),
      principal: principal.address,
      principal_id: principal.principal_id,
      counterparty,
      ...(counterpartyId ? { counterparty_principal_id: counterpartyId } : existing?.counterparty_principal_id ? { counterparty_principal_id: existing.counterparty_principal_id } : {}),
      basis: "consent",
      status: sealedBy ? "active" : activeAlready ? "active" : "pending",
      scopes: sealedBy || !activeAlready ? { ...keep, ...scopes } : keep,
      ...(existing?.rate_limit ? { rate_limit: existing.rate_limit } : {}),
      ...(existing?.quiet_hours ? { quiet_hours: existing.quiet_hours } : {}),
      connection,
      created_at: existing?.created_at ?? iso(now),
      updated_at: iso(now),
      ...(sealedBy ? { sealed: { by: principal.principal_id, method: sealMethod(sealedBy), at: iso(now) } } : existing?.sealed ? { sealed: existing.sealed } : {}),
    };
    return this.storeGrant(principal, grant, "grant_set");
  }

  private async storeGrant(principal: PrincipalRecord, grant: RelationshipGrant, kind: "grant_set" | "grant_revoked"): Promise<RelationshipGrant> {
    const signed = await signGrant(grant, this.keys);
    await this.store.putGrant(signed);
    await this.log(principal, { kind, counterparty: grant.counterparty, outcome: "info", ref: grant.id, policy_ids: [`grant:${grant.id}`] });
    return signed;
  }

  private async authDelegate(caller: DelegateCaller): Promise<{ principal: PrincipalRecord; delegate: DelegateRecord }> {
    if (caller?.kind !== "delegate") throw new AlpError("identity_mismatch", "agent calls need a delegate caller", { status: 401 });
    const principal = await this.store.getPrincipal(caller.principal);
    if (!principal || principal.status !== "active") throw new AlpError("identity_mismatch", "unknown or suspended principal", { status: 401 });
    const delegate = await this.store.getDelegate(caller.delegate);
    if (!delegate || delegate.principal_id !== principal.principal_id || delegate.status !== "active" || delegate.client_id !== caller.client_id) {
      throw new AlpError("identity_mismatch", "this agent is not an active delegate of the signed-in principal", { status: 401 });
    }
    return { principal, delegate: this.ranked(delegate) };
  }

  private async authHuman(caller: HumanCaller, stepUp = false): Promise<PrincipalRecord> {
    if (caller?.kind !== "human") throw new AlpError("identity_mismatch", "only the person can do this, on the broker's own page", { status: 403 });
    const principal = await this.store.getPrincipal(caller.principal);
    if (!principal || principal.status !== "active") throw new AlpError("identity_mismatch", "unknown or suspended principal", { status: 401 });
    // A page signed in before the address passed to someone else acts for no one (spec 5.2).
    if (caller.principal_id !== undefined && caller.principal_id !== principal.principal_id) throw new AlpError("identity_mismatch", "this sign-in belongs to an earlier holder of the address", { status: 401 });
    if (stepUp) {
      const at = caller.auth ? Date.parse(caller.auth.at) : Number.NaN;
      if (Number.isNaN(at) || this.clock.now().getTime() - at > this.limits.stepUpMaxAgeSeconds * 1000) {
        throw new AlpError("identity_mismatch", "sign in again to approve this", { status: 401 });
      }
    }
    return principal;
  }

  private installPolicy(p: OrgPolicy): void {
    for (const d of p.domains) this.policies.set(d, p);
  }

  private policyFor(address: Address): OrgPolicy | null {
    return this.policies.get(domainOf(address)) ?? null;
  }

  private claimsFor(principals: PrincipalRecord[]): ClaimsOf {
    const map = new Map(principals.map((p) => [p.address, p.claims ?? []]));
    return (a) => map.get(a) ?? [];
  }

  /**
   * The group claims the policy's claim-based groups see between a person and a counterparty (spec 6.4: a claim-based
   * group can only be evaluated for principals the broker signed in through the claim's issuer). The person's own, and
   * the counterparty's when it is an active principal of this broker (with `principalId`, only that holder of the
   * address). Anyone else has none, so they are in no claim-based group (fail closed).
   */
  async claimsWith(principal: PrincipalRecord, counterparty: Address, principalId?: string): Promise<ClaimsOf> {
    const other = counterparty === principal.address ? null : await this.store.getPrincipal(counterparty);
    if (!other || other.status !== "active" || (principalId !== undefined && other.principal_id !== principalId)) return this.claimsFor([principal]);
    return this.claimsFor([principal, other]);
  }

  private async log(principal: PrincipalRecord, fields: LedgerFields, payload?: LedgerPayload): Promise<LedgerEntry> {
    const at = iso(this.clock.now());
    return this.store.appendLedger(principal.principal_id, (head) => buildLedgerEntry(principal, head, at, fields, payload));
  }

  /** Notifications only notify: broker-generated text, a link to this broker's own page, nothing that acts. */
  private async notifyPerson(p: PrincipalRecord, kind: NotificationKind, subject: string, text: string, link: string): Promise<void> {
    const policy = this.policyFor(p.address);
    if (policy?.human_fallback === "off" && (kind === "message_waiting" || kind === "message_held")) return;
    const at = iso(this.clock.now());
    try {
      if (p.contact?.email) await this.notifier.notify({ principal: p.address, kind, channel: "email", to: p.contact.email, subject, text, link, at });
      else if (p.contact?.sms && policy?.sms === true) await this.notifier.notify({ principal: p.address, kind, channel: "sms", to: p.contact.sms, subject, text, link, at });
    } catch {
      // a failed notification never undoes what the broker recorded; the web view shows it either way
    }
  }

  /** Security events dropped since start because the sink or the event schema refused them (/healthz reports it). */
  securityEventsDropped(): number {
    return this.droppedEvents;
  }

  private async securityEvent(event: SecurityEventName, a: EventArgs): Promise<void> {
    if (!this.events) return;
    try {
      await this.events.emit(buildSecurityEvent({ uid: this.ids.ulid(), at: this.clock.now(), event, broker: this.id, ...(a.failed !== undefined ? { failed: a.failed } : {}), ...(a.message ? { message: a.message } : {}), ...(a.details ? { details: a.details } : {}) }));
    } catch (err) {
      // The event stream must never break message handling, but a dropped event is counted, and said on stderr at most
      // once a minute (the reason names no value: schema errors give pointers and the schema's own words).
      this.droppedEvents += 1;
      const now = this.clock.now().getTime();
      if (now - this.droppedNoticeAt >= 60_000) {
        this.droppedNoticeAt = now;
        console.error(`${this.droppedEvents} security events dropped since start: ${errMessage(err).slice(0, 300)}`);
      }
    }
  }
}
