// SPDX-License-Identifier: FSL-1.1-ALv2
// In-memory Store. Single process; each method runs without awaiting in the middle, so it is atomic.
// Records are cloned on the way in and out, so callers never share mutable state with the store.

import { secondsUntilOldestLeaves } from "../core/interfaces.ts";
import type { MessageQuery, RateLimitHit, Store } from "../core/interfaces.ts";
import type { StoredKeyRing } from "../core/keys.ts";
import type {
  Address,
  ConnectionRequestRecord,
  CounterpartyRevocation,
  DeferredNotice,
  DelegateId,
  DelegateRecord,
  HeldOutbound,
  LedgerEntry,
  LedgerHead,
  LedgerPayload,
  MessageRecord,
  PrincipalId,
  PrincipalRecord,
  RatificationRequest,
  Receipt,
  RelationshipGrant,
  ThreadRecord,
} from "../core/types.ts";

export interface MemoryState {
  version: 2;
  principals: Record<string, PrincipalRecord>;
  delegates: Record<string, DelegateRecord>;
  grants: Record<string, RelationshipGrant>;
  revocations: Record<string, CounterpartyRevocation>;
  connections: Record<string, ConnectionRequestRecord>;
  messages: Record<string, MessageRecord>;
  /** Notifications waiting for the end of quiet hours (absent in state written before they were kept). */
  notices?: Record<string, DeferredNotice>;
  threads: Record<string, ThreadRecord>;
  ratifications: Record<string, RatificationRequest>;
  held?: Record<string, HeldOutbound>;
  receipts: Record<string, Receipt>;
  ledgers: Record<string, LedgerEntry[]>;
  payloads: Record<string, LedgerPayload>;
  seen: Record<string, string>;
  rate: Record<string, number[]>;
  keyrings: Record<string, StoredKeyRing>;
}

export function emptyState(): MemoryState {
  return {
    version: 2,
    principals: {},
    delegates: {},
    grants: {},
    revocations: {},
    connections: {},
    messages: {},
    notices: {},
    threads: {},
    ratifications: {},
    held: {},
    receipts: {},
    ledgers: {},
    payloads: {},
    seen: {},
    rate: {},
    keyrings: {},
  };
}

const clone = <T>(v: T): T => structuredClone(v);
const k2 = (a: string, b: string): string => `${a}\u0000${b}`;
const k3 = (a: string, b: string, c: string): string => `${a}\u0000${b}\u0000${c}`;

export class MemoryStore implements Store {
  readonly kind: string = "memory";
  protected state: MemoryState;

  constructor(initial?: MemoryState) {
    this.state = initial ? clone(initial) : emptyState();
  }

  /** Called after every mutation; the file store persists here. */
  protected changed(): void {}

  async getPrincipal(address: Address): Promise<PrincipalRecord | null> {
    return clone(Object.values(this.state.principals).find((p) => p.address === address && p.status !== "retired") ?? null);
  }
  async getPrincipalById(id: PrincipalId): Promise<PrincipalRecord | null> {
    return clone(this.state.principals[id] ?? null);
  }
  async getPrincipalByIdentity(iss: string, sub: string): Promise<PrincipalRecord | null> {
    return clone(Object.values(this.state.principals).find((p) => p.identity.iss === iss && p.identity.sub === sub && p.status !== "retired") ?? null);
  }
  async putPrincipal(rec: PrincipalRecord): Promise<void> {
    this.state.principals[rec.principal_id] = clone(rec);
    this.changed();
  }
  async listPrincipals(): Promise<PrincipalRecord[]> {
    return clone(Object.values(this.state.principals));
  }

  async getDelegate(id: DelegateId): Promise<DelegateRecord | null> {
    return clone(this.state.delegates[id] ?? null);
  }
  async putDelegate(rec: DelegateRecord): Promise<void> {
    this.state.delegates[rec.id] = clone(rec);
    this.changed();
  }
  async listDelegates(principal: Address): Promise<DelegateRecord[]> {
    return clone(Object.values(this.state.delegates).filter((d) => d.principal === principal));
  }

  async getGrant(principal: Address, counterparty: Address): Promise<RelationshipGrant | null> {
    return clone(this.state.grants[k2(principal, counterparty)] ?? null);
  }
  async putGrant(grant: RelationshipGrant): Promise<void> {
    this.state.grants[k2(grant.principal, grant.counterparty)] = clone(grant);
    this.changed();
  }
  async listGrants(principal: Address): Promise<RelationshipGrant[]> {
    return clone(Object.values(this.state.grants).filter((g) => g.principal === principal));
  }

  async getRevocation(principal: Address, counterparty: Address): Promise<CounterpartyRevocation | null> {
    return clone(this.state.revocations[k2(principal, counterparty)] ?? null);
  }
  async putRevocation(rec: CounterpartyRevocation): Promise<void> {
    this.state.revocations[k2(rec.principal, rec.counterparty)] = clone(rec);
    this.changed();
  }

  async getConnection(principal: Address, id: string): Promise<ConnectionRequestRecord | null> {
    return clone(this.state.connections[k2(principal, id)] ?? null);
  }
  async putConnection(rec: ConnectionRequestRecord): Promise<void> {
    this.state.connections[k2(rec.principal, rec.id)] = clone(rec);
    this.changed();
  }
  async listConnections(principal: Address): Promise<ConnectionRequestRecord[]> {
    return clone(
      Object.values(this.state.connections)
        .filter((c) => c.principal === principal)
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    );
  }

  async putMessage(rec: MessageRecord): Promise<void> {
    this.state.messages[k3(rec.principal, rec.direction, rec.envelope.id)] = clone(rec);
    this.changed();
  }
  async getMessage(principal: Address, direction: "in" | "out", envelopeId: string): Promise<MessageRecord | null> {
    return clone(this.state.messages[k3(principal, direction, envelopeId)] ?? null);
  }
  async listMessages(principal: Address, q: MessageQuery): Promise<MessageRecord[]> {
    // Spec 5.4: what an earlier binding with the delegate's label received, or acknowledged, isn't this binding's.
    const since = q.bindingSince !== undefined ? Date.parse(q.bindingSince) : undefined;
    const unacked = (m: MessageRecord, id: DelegateId): boolean => {
      const at = m.acked_by[id];
      return at === undefined || (since !== undefined && Date.parse(at) < since);
    };
    const addressed = (m: MessageRecord, id: DelegateId): boolean => {
      const to = m.envelope.to.delegate;
      return to === undefined || (to === id && (since === undefined || Date.parse(m.stored_at) >= since));
    };
    const out = Object.values(this.state.messages)
      .filter((m) => m.principal === principal)
      .filter((m) => q.direction === undefined || m.direction === q.direction)
      .filter((m) => q.after === undefined || m.local_id > q.after)
      .filter((m) => q.before === undefined || m.local_id < q.before)
      .filter((m) => q.thread === undefined || m.envelope.thread === q.thread)
      .filter((m) => q.status === undefined || q.status.includes(m.status))
      .filter((m) => q.unackedBy === undefined || unacked(m, q.unackedBy))
      .filter((m) => q.forDelegate === undefined || addressed(m, q.forDelegate))
      .sort((a, b) => (a.local_id < b.local_id ? -1 : a.local_id > b.local_id ? 1 : 0) * (q.order === "desc" ? -1 : 1))
      .slice(0, Math.max(0, q.limit));
    return clone(out);
  }

  async putDeferredNotice(rec: DeferredNotice): Promise<void> {
    (this.state.notices ??= {})[rec.id] = clone(rec);
    this.changed();
  }
  async takeDueNotices(now: Date, limit: number): Promise<DeferredNotice[]> {
    const t = now.getTime();
    const due = Object.values(this.state.notices ?? {})
      .filter((n) => Date.parse(n.due_at) <= t)
      .sort((a, b) => Date.parse(a.due_at) - Date.parse(b.due_at) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .slice(0, Math.max(0, limit));
    if (due.length === 0) return [];
    for (const n of due) delete this.state.notices?.[n.id];
    this.changed();
    return clone(due);
  }

  async getThread(principal: Address, id: string): Promise<ThreadRecord | null> {
    return clone(this.state.threads[k2(principal, id)] ?? null);
  }
  async putThread(rec: ThreadRecord): Promise<void> {
    this.state.threads[k2(rec.principal, rec.id)] = clone(rec);
    this.changed();
  }

  async putHeldOutbound(rec: HeldOutbound): Promise<void> {
    (this.state.held ??= {})[k2(rec.principal, rec.id)] = clone(rec);
    this.changed();
  }
  async claimHeldOutbound(next: HeldOutbound, from: HeldOutbound["state"] = "pending"): Promise<boolean> {
    const key = k2(next.principal, next.id);
    if (this.state.held?.[key]?.state !== from) return false;
    (this.state.held ??= {})[key] = clone(next);
    this.changed();
    return true;
  }
  async getHeldOutbound(principal: Address, id: string): Promise<HeldOutbound | null> {
    return clone(this.state.held?.[k2(principal, id)] ?? null);
  }
  async listHeldOutbound(principal: Address): Promise<HeldOutbound[]> {
    return clone(Object.values(this.state.held ?? {}).filter((h) => h.principal === principal).sort((a, b) => (a.id < b.id ? -1 : 1)));
  }

  async getRatificationRequest(id: string): Promise<RatificationRequest | null> {
    return clone(this.state.ratifications[id] ?? null);
  }
  async putRatificationRequest(rec: RatificationRequest): Promise<void> {
    this.state.ratifications[rec.id] = clone(rec);
    this.changed();
  }
  async listRatificationRequests(principal: Address): Promise<RatificationRequest[]> {
    return clone(Object.values(this.state.ratifications).filter((r) => r.principal === principal).sort((a, b) => (a.id < b.id ? -1 : 1)));
  }

  async putReceipt(key: string, receipt: Receipt): Promise<void> {
    this.state.receipts[key] = clone(receipt);
    this.changed();
  }
  async getReceipt(key: string): Promise<Receipt | null> {
    return clone(this.state.receipts[key] ?? null);
  }

  async appendLedger(principalId: PrincipalId, build: (head: LedgerHead | null) => { entry: LedgerEntry; payload?: LedgerPayload }): Promise<LedgerEntry> {
    const list = (this.state.ledgers[principalId] ??= []);
    const last = list[list.length - 1];
    const { entry, payload } = build(last ? { seq: last.seq, hash: last.hash } : null);
    if (entry.principal_id !== principalId || entry.seq !== (last ? last.seq + 1 : 0) || entry.prev_hash !== (last ? last.hash : null)) {
      throw new Error("ledger append: the entry does not extend the chain");
    }
    list.push(clone(entry));
    if (payload) this.state.payloads[k2(principalId, String(entry.seq))] = clone(payload);
    this.changed();
    return clone(entry);
  }
  async listLedger(principalId: PrincipalId, q: { afterSeq?: number; limit?: number } = {}): Promise<LedgerEntry[]> {
    const list = (this.state.ledgers[principalId] ?? []).filter((e) => q.afterSeq === undefined || e.seq > q.afterSeq);
    return clone(q.limit === undefined ? list : list.slice(0, q.limit));
  }
  async getLedgerPayload(principalId: PrincipalId, seq: number): Promise<LedgerPayload | null> {
    return clone(this.state.payloads[k2(principalId, String(seq))] ?? null);
  }
  async eraseLedgerPayload(principalId: PrincipalId, seq: number): Promise<void> {
    delete this.state.payloads[k2(principalId, String(seq))];
    this.changed();
  }

  async recordOnce(key: string, expiresAt: string, now: Date): Promise<boolean> {
    const t = now.getTime();
    const existing = this.state.seen[key];
    if (existing !== undefined && Date.parse(existing) > t) return false;
    for (const [k, exp] of Object.entries(this.state.seen)) if (Date.parse(exp) <= t) delete this.state.seen[k];
    this.state.seen[key] = expiresAt;
    this.changed();
    return true;
  }

  async hitRateLimit(key: string, now: Date, windowSeconds: number, limit: number): Promise<RateLimitHit> {
    const t = now.getTime();
    const hits = (this.state.rate[key] ?? []).filter((x) => x > t - windowSeconds * 1000);
    if (hits.length >= limit) {
      this.state.rate[key] = hits;
      return { allowed: false, count: hits.length, retryAfter: secondsUntilOldestLeaves(hits, t, windowSeconds) };
    }
    hits.push(t);
    this.state.rate[key] = hits;
    this.changed();
    return { allowed: true, count: hits.length, retryAfter: secondsUntilOldestLeaves(hits, t, windowSeconds) };
  }

  async getKeyRing(name: string): Promise<StoredKeyRing | null> {
    return clone(this.state.keyrings[name] ?? null);
  }
  async putKeyRing(name: string, ring: StoredKeyRing): Promise<void> {
    this.state.keyrings[name] = clone(ring);
    this.changed();
  }

  async close(): Promise<void> {}
}
