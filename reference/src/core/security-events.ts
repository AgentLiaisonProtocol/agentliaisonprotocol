// SPDX-License-Identifier: FSL-1.1-ALv2
// Broker security events (spec 11.8): a stream separate from the ledger, one OCSF-mapped JSON object per
// line (Authentication 3002, API Activity 6003, plus the protocol's profile under `detail`). Never message values,
// notes or free text.

import { appendFileSync } from "node:fs";
import { PROTOCOL } from "./protocol.ts";
import { assertValid } from "./spec-schemas.ts";
import type { BrokerId, DelegateId, ErrorCode, PrincipalId, ScopeId } from "./types.ts";

export type SecurityEventName =
  | "envelope_refused" | "signature_failure" | "replay_refused" | "broker_not_authorized" | "token_issued" | "token_refused"
  | "token_revoked" | "refresh_reuse" | "client_refused" | "rate_limited" | "dlp_blocked" | "dlp_error" | "policy_changed"
  | "admin_action" | "kill_switch" | "key_rotated" | "key_revoked" | "discovery_failure" | "connection_request_dropped"
  | "ratification_paused" | "principal_reassigned";

export interface SecurityEvent {
  time: number;
  class_uid: 3002 | 6003;
  category_uid: 3 | 6;
  activity_id: number;
  type_uid: number;
  severity_id: number;
  status_id?: 0 | 1 | 2 | 99;
  message?: string;
  metadata: { uid: string; version: string; product: { name: string; vendor_name?: string; version?: string }; profiles?: string[] };
  detail: {
    event: SecurityEventName;
    broker: BrokerId;
    origin_broker?: BrokerId;
    code?: ErrorCode;
    principal_id?: PrincipalId;
    delegate?: DelegateId;
    client_id?: string;
    scope?: ScopeId;
    domain?: string;
    kid?: string;
    count?: number;
  };
}

export interface SecurityEventSink {
  emit(event: SecurityEvent): Promise<void>;
}

const AUTH_EVENTS: SecurityEventName[] = ["token_issued", "token_refused", "token_revoked", "refresh_reuse"];
const HIGH: SecurityEventName[] = ["signature_failure", "broker_not_authorized", "refresh_reuse", "key_revoked", "kill_switch"];
const MEDIUM: SecurityEventName[] = ["envelope_refused", "replay_refused", "client_refused", "dlp_blocked", "token_refused", "dlp_error"];

export function buildSecurityEvent(args: {
  uid: string;
  at: Date;
  event: SecurityEventName;
  broker: BrokerId;
  failed?: boolean;
  message?: string;
  details?: Omit<SecurityEvent["detail"], "event" | "broker">;
}): SecurityEvent {
  const auth = AUTH_EVENTS.includes(args.event);
  const class_uid = auth ? 3002 : 6003;
  // OCSF activity: Authentication 1 = Logon, 99 = Other; API Activity 99 = Other.
  const activity_id = args.event === "token_issued" ? 1 : 99;
  const ev: SecurityEvent = {
    time: args.at.getTime(),
    class_uid,
    category_uid: auth ? 3 : 6,
    activity_id,
    type_uid: class_uid * 100 + activity_id,
    severity_id: HIGH.includes(args.event) ? 4 : MEDIUM.includes(args.event) ? 3 : 1,
    status_id: args.failed === undefined ? 0 : args.failed ? 2 : 1,
    ...(args.message ? { message: args.message.slice(0, 500) } : {}),
    metadata: { uid: args.uid, version: "1.3.0", product: { name: `${PROTOCOL.name} reference broker`, vendor_name: PROTOCOL.name, version: "0.1.0" }, profiles: [PROTOCOL.ocsfProfile] },
    detail: { event: args.event, broker: args.broker, ...(args.details ?? {}) },
  };
  return assertValid<SecurityEvent>("securityEvent", ev, "internal");
}

/**
 * Folds repeats of one security event into one (spec 11.8's `detail.count`): the first event for a key in a window is
 * written at once; the rest in that window are counted and written as one event, with `count`, when the window ends,
 * or at `flush` (when the broker stops). For refusals a caller can repeat at will, such as requests with a bearer token
 * that doesn't verify, so one client can't write one event per request to the stream (and to the disk). Timers are
 * unref'd: a pending window never keeps the process alive.
 */
export class EventFolder {
  private readonly windowMs: number;
  private readonly maxKeys: number;
  private readonly windows = new Map<string, { count: number; timer: NodeJS.Timeout; emit: (count: number) => void }>();

  constructor(windowMs = 60_000, maxKeys = 10_000) {
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
  }

  /** One occurrence of the event `key` names; `emit` writes it (with `count` for the folded rest). */
  note(key: string, emit: (count?: number) => void): void {
    const open = this.windows.get(key);
    if (open) {
      open.count += 1;
      return;
    }
    emit();
    if (this.windows.size >= this.maxKeys) return;
    const timer = setTimeout(() => this.close(key), this.windowMs);
    timer.unref();
    this.windows.set(key, { count: 0, timer, emit: (n) => emit(n) });
  }

  private close(key: string): void {
    const w = this.windows.get(key);
    if (!w) return;
    this.windows.delete(key);
    clearTimeout(w.timer);
    if (w.count > 0) w.emit(w.count);
  }

  /** Writes every folded count now (the broker is stopping). */
  flush(): void {
    for (const key of [...this.windows.keys()]) this.close(key);
  }
}

export class MemorySecurityEvents implements SecurityEventSink {
  readonly events: SecurityEvent[] = [];
  async emit(event: SecurityEvent): Promise<void> {
    this.events.push(structuredClone(event));
  }
}

/** Appends one JSON object per line (for Splunk HEC, Sentinel or syslog forwarders to pick up). */
export class JsonlSecurityEvents implements SecurityEventSink {
  readonly path: string;
  constructor(path: string) {
    this.path = path;
  }
  async emit(event: SecurityEvent): Promise<void> {
    appendFileSync(this.path, `${JSON.stringify(event)}\n`, { mode: 0o600 });
  }
}

/** Writes one JSON object per line to standard output, for a platform whose log drain ships it (a hosted broker). */
export class StdoutSecurityEvents implements SecurityEventSink {
  async emit(event: SecurityEvent): Promise<void> {
    process.stdout.write(`${JSON.stringify({ alp_security_event: event })}\n`);
  }
}
