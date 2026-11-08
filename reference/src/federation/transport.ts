// SPDX-License-Identifier: FSL-1.1-ALv2
// The HTTPS FederationTransport (spec 10.1 to 10.5, 12.2). POSTs a signed envelope to the recipient home broker's
// inbox (named in the recipient domain's document) through the hardened fetcher, and maps the answer. It never
// throws for remote failures.
//  - Idempotency by id: the same envelope (same id and hash) to the same broker is one delivery. Concurrent calls
//    share the request in flight, and a final receipt is reused until the envelope expires. A retry resends the
//    identical bytes, so the recipient answers it with the original receipt (core step 5, spec 10.3).
//  - TTL: an envelope at or past its expires_at is never sent, and retries stop before it.
//  - Retries (spec 10.2): after a network failure, HTTP 408, 425, 429 or 5xx, or a retryable refusal (rate_limited,
//    discovery_failed, internal, thread_state with Retry-After). Backoff doubles with ±20% jitter and honors
//    Retry-After. The core waits for the answer inside `send`, so the reference retries within a short budget
//    (default about 10 seconds) rather than the spec's store-and-forward schedule (30 seconds doubling to 1 hour);
//    that needs a persistent outbox in the core (see ARCHITECTURE.md, Not built yet).
//  - Optional RFC 9421 request signatures (spec 12.2.2) with a `alp_use: http` key ring.
// Remote error text never reaches the agent: refusals carry the code and a fixed message.

import { randomBytes } from "node:crypto";
import type { Clock } from "../core/clock.ts";
import { systemClock } from "../core/clock.ts";
import { FETCH_LIMITS } from "../core/domain.ts";
import { objectHash } from "../core/envelope.ts";
import type { DeliveryResult, DeliveryTarget, FederationTransport } from "../core/interfaces.ts";
import type { KeyRing } from "../core/keys.ts";
import { ERROR_CODES } from "../core/types.ts";
import type { AnyEnvelope, ErrorCode, Receipt } from "../core/types.ts";
import type { HardenedFetcher, HttpResponse } from "./fetcher.ts";
import { FEDERATION_SIGNATURE_PROFILE, contentDigest, signRequest } from "./http-signatures.ts";
import { parseStrictJsonBytes } from "./strict-json.ts";

export interface RetryPolicy {
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  /** ±fraction, e.g. 0.2. */
  jitter: number;
  /** Total time one deliver() may spend waiting between attempts. */
  budgetMs: number;
}

/** The reference's inline retries: a few quick attempts so an agent's send returns in seconds. */
export const DEFAULT_RETRY_POLICY: RetryPolicy = { maxAttempts: 4, initialDelayMs: 250, maxDelayMs: 4000, jitter: 0.2, budgetMs: 10_000 };

/** The spec's store-and-forward schedule (10.2), for an outbox that outlives the request. */
export const SPEC_RETRY_SCHEDULE = { initialDelayMs: 30_000, maxDelayMs: 3_600_000, jitter: 0.2 } as const;

const RETRYABLE_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>(["rate_limited", "discovery_failed", "internal"]);
const RECEIPT_MAX_BYTES = 64 * 1024;
const ERROR_CODE_SET: ReadonlySet<string> = new Set<string>(ERROR_CODES);

/** One attempt, for transcripts and tests (no envelope content). */
export interface DeliveryAttempt {
  at: string;
  from: string;
  to: string;
  inbox: string;
  envelope_id: string;
  type: string;
  attempt: number;
  status?: number;
  outcome: string;
  request_signed: boolean;
}

export interface HttpsTransportOptions {
  /** The sending broker's id (labels attempts). */
  brokerId: string;
  fetcher: HardenedFetcher;
  clock?: Clock;
  retry?: Partial<RetryPolicy>;
  /** Tests replace these. */
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
  /** Sign each POST with RFC 9421 using this `alp_use: http` ring. Its keys must be published and pinned. */
  requestSigningKeys?: KeyRing;
  onAttempt?: (a: DeliveryAttempt) => void;
}

type Attempt = { result: DeliveryResult; retryable: boolean; retryAfterMs?: number; status?: number };

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Retry-After as delay seconds or an HTTP date; capped at one hour. */
export function parseRetryAfter(value: string | string[] | undefined, now: Date): number | undefined {
  const v = Array.isArray(value) ? value[0] : value;
  if (v === undefined) return undefined;
  const ms = /^[0-9]{1,6}$/.test(v.trim()) ? Number(v.trim()) * 1000 : Date.parse(v) - now.getTime();
  if (!Number.isFinite(ms)) return undefined;
  return Math.min(Math.max(0, ms), 3_600_000);
}

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export class HttpsFederationTransport implements FederationTransport {
  private readonly opts: HttpsTransportOptions;
  private readonly clock: Clock;
  private readonly policy: RetryPolicy;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly random: () => number;
  private readonly inflight = new Map<string, Promise<DeliveryResult>>();
  private readonly finished = new Map<string, { result: DeliveryResult; until: number }>();
  /** Every attempt, newest last. */
  readonly attempts: DeliveryAttempt[] = [];

  constructor(opts: HttpsTransportOptions) {
    this.opts = opts;
    this.clock = opts.clock ?? systemClock;
    this.policy = { ...DEFAULT_RETRY_POLICY, ...opts.retry };
    this.sleep = opts.sleep ?? defaultSleep;
    this.random = opts.random ?? Math.random;
  }

  async deliver(target: DeliveryTarget, envelope: AnyEnvelope): Promise<DeliveryResult> {
    let key: string;
    try {
      key = `${target.broker}|${envelope.id}|${objectHash(envelope)}`;
    } catch {
      return { kind: "refused", status: 400, code: "bad_envelope", message: "the envelope can't be serialized" };
    }
    const now = this.clock.now().getTime();
    for (const [k, v] of this.finished) if (v.until <= now) this.finished.delete(k);
    const done = this.finished.get(key);
    if (done) return structuredClone(done.result);
    const running = this.inflight.get(key);
    if (running) return structuredClone(await running);
    const p = this.attemptAll(target, envelope).finally(() => this.inflight.delete(key));
    this.inflight.set(key, p);
    const result = await p;
    if (result.kind === "receipt") this.finished.set(key, { result: structuredClone(result), until: Date.parse(envelope.expires_at) + 300_000 });
    return structuredClone(result);
  }

  private async attemptAll(target: DeliveryTarget, envelope: AnyEnvelope): Promise<DeliveryResult> {
    const expiresAt = Date.parse(envelope.expires_at);
    if (!Number.isFinite(expiresAt) || this.clock.now().getTime() >= expiresAt) {
      this.log(target, envelope, 0, undefined, "not sent: expired");
      return { kind: "refused", status: 400, code: "expired", message: "the envelope expired before it could be delivered" };
    }
    const body = Buffer.from(JSON.stringify(envelope), "utf8");
    if (body.byteLength > FETCH_LIMITS.envelopeMaxBytes) {
      this.log(target, envelope, 0, undefined, "not sent: over 1 MiB");
      return { kind: "refused", status: 413, code: "bad_envelope", message: "the envelope is over 1 MiB" };
    }
    const budgetEnd = Date.now() + this.policy.budgetMs;
    let last: Attempt = { result: { kind: "unreachable", message: "not attempted" }, retryable: false };
    for (let attempt = 1; attempt <= this.policy.maxAttempts; attempt++) {
      last = await this.once(target, envelope, body, attempt);
      this.log(target, envelope, attempt, last.status, `${describe(last.result)}${last.retryable && attempt < this.policy.maxAttempts ? " (will retry)" : ""}`);
      if (!last.retryable || attempt === this.policy.maxAttempts) break;
      const base = Math.min(this.policy.maxDelayMs, this.policy.initialDelayMs * 2 ** (attempt - 1));
      let delay = Math.round(base * (1 + (this.random() * 2 - 1) * this.policy.jitter));
      if (last.retryAfterMs !== undefined) delay = Math.max(delay, last.retryAfterMs);
      // Never wait past the budget, nor past the envelope's lifetime.
      if (Date.now() + delay > budgetEnd || this.clock.now().getTime() + delay >= expiresAt) break;
      await this.sleep(delay);
    }
    return last.result;
  }

  private async once(target: DeliveryTarget, envelope: AnyEnvelope, body: Buffer, attempt: number): Promise<Attempt> {
    const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
    const ring = this.opts.requestSigningKeys;
    if (ring) {
      const created = Math.floor(this.clock.now().getTime() / 1000);
      headers["content-digest"] = contentDigest(body);
      const k = ring.active();
      Object.assign(
        headers,
        signRequest(
          { method: "POST", targetUri: target.inbox, headers },
          { kid: k.kid, privateKey: ring.privateKey(k.kid) },
          { created, expires: created + FEDERATION_SIGNATURE_PROFILE.maxLifetimeSeconds, nonce: randomBytes(16).toString("base64url") },
        ),
      );
    }
    let res: HttpResponse;
    try {
      res = await this.opts.fetcher.request(target.inbox, { method: "POST", headers, body, maxBytes: RECEIPT_MAX_BYTES });
    } catch {
      return { result: { kind: "unreachable", message: "no answer from the recipient's broker" }, retryable: true };
    }
    const retryAfterMs = parseRetryAfter(res.headers["retry-after"], this.clock.now());
    const status = res.status;
    let parsed: unknown;
    try {
      parsed = parseStrictJsonBytes(res.body);
    } catch {
      parsed = undefined;
    }
    const transient = status === 408 || status === 425 || status === 429 || status >= 500;
    if (isObject(parsed) && isObject(parsed["receipt"])) {
      // A signed receipt answers the envelope (accepted, or refused by the recipient's rules). The core verifies it.
      const receipt = parsed["receipt"] as unknown as Receipt;
      const code = receipt.code;
      const retryable = receipt.status === "refused" && (code === "rate_limited" || code === "internal" || (code === "thread_state" && retryAfterMs !== undefined));
      // The wait the recipient's broker asked for with a refused receipt travels with it, as with a plain refusal.
      const wait = receipt.status === "refused" && retryAfterMs !== undefined ? { retry_after: Math.max(1, Math.ceil(retryAfterMs / 1000)) } : {};
      return { result: { kind: "receipt", receipt, ...wait }, retryable, ...(retryAfterMs !== undefined ? { retryAfterMs } : {}), status };
    }
    const error = isObject(parsed) && isObject(parsed["error"]) ? parsed["error"] : undefined;
    const code = error && typeof error["code"] === "string" && ERROR_CODE_SET.has(error["code"]) ? (error["code"] as ErrorCode) : undefined;
    if (code) {
      // `replay` on a retry means the first attempt may still be in flight at the recipient: try once more.
      const retryable = RETRYABLE_CODES.has(code) || transient || (code === "replay" && attempt > 1);
      return {
        // The wait the recipient's broker asked for travels with the refusal (seconds, as InboundResult carries it).
        result: { kind: "refused", status, code, message: `refused by the recipient's broker (${code})`, ...(retryAfterMs !== undefined ? { retry_after: Math.max(1, Math.ceil(retryAfterMs / 1000)) } : {}) },
        retryable,
        ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
        status,
      };
    }
    return {
      result: { kind: "unreachable", message: `the recipient's broker answered HTTP ${status} without a protocol answer` },
      retryable: transient,
      ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
      status,
    };
  }

  private log(target: DeliveryTarget, envelope: AnyEnvelope, attempt: number, status: number | undefined, outcome: string): void {
    const a: DeliveryAttempt = {
      at: this.clock.now().toISOString(),
      from: this.opts.brokerId,
      to: target.broker,
      inbox: target.inbox,
      envelope_id: envelope.id,
      type: envelope.type,
      attempt,
      ...(status !== undefined ? { status } : {}),
      outcome,
      request_signed: this.opts.requestSigningKeys !== undefined,
    };
    this.attempts.push(a);
    if (this.attempts.length > 1000) this.attempts.splice(0, this.attempts.length - 1000);
    this.opts.onAttempt?.(a);
  }
}

function describe(r: DeliveryResult): string {
  if (r.kind === "receipt") return `receipt ${r.receipt.status}${r.receipt.code ? `: ${r.receipt.code}` : ""}`;
  if (r.kind === "refused") return `refused: ${r.code}`;
  return "unreachable";
}
