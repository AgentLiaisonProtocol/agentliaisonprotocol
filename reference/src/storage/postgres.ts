// SPDX-License-Identifier: FSL-1.1-ALv2
// Postgres Store for hosted and organization brokers (the `postgres` client, postgres@3.4.9). The same Store
// interface as the memory and file stores, and the same conformance suite (store.test.ts, with ALP_TEST_POSTGRES_URL).
//  - Tables come from migrations/ (applied by `migrate`, recorded in schema_migrations), in a schema of their own
//    (default `broker`) selected through the connection's search_path.
//  - Records are jsonb next to the columns queries use; every method is one statement or one transaction.
//  - appendLedger: a transaction holding an advisory lock on the principal reads the head, runs build(head) and
//    inserts; the (principal_id, seq) primary key and the unique hash reject anything that doesn't extend the chain.
//  - recordOnce: INSERT ... ON CONFLICT DO UPDATE ... WHERE the old entry expired, RETURNING: a row means first sight.
//  - hitRateLimit: a transaction holding an advisory lock on the key counts the window and inserts when allowed.
//  - Supabase: use the transaction pooler (port 6543) with `prepare: false`, which `createPostgresStore` sets.
//  - Key rings (private signing keys) are sealed with AES-256-GCM under a key held outside the database
//    (`keyEncryptionKey`, ALP_KEYRING_KEY), so a copy of the database holds no usable signing key. Without one they are
//    stored as they are (a local deployment); a ring written before a key was set is sealed on its next write.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import postgres from "postgres";
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

export const MIGRATIONS_DIR = fileURLToPath(new URL("../../migrations/", import.meta.url));
const SCHEMA_RE = /^[a-z_][a-z0-9_]{0,62}$/;

type Sql = postgres.Sql;
type Row = Record<string, unknown>;

export interface PostgresStoreOptions {
  /** postgres://user:password@host:port/database. Never logged. */
  url: string;
  /** The schema that holds the tables. Default `broker`. */
  schema?: string;
  /** Connections in the pool. Default 5. */
  max?: number;
  /** Prepared statements (off for Supabase's transaction pooler). Default false. */
  prepare?: boolean;
  /** TLS: `require` for hosted databases. Default: from the URL. */
  ssl?: "require" | "prefer" | false;
  /** 32 random bytes, base64url: seals the key rings (AES-256-GCM). Keep it outside the database (an environment secret or a KMS). */
  keyEncryptionKey?: string;
}

/** A key ring as stored when sealed. */
interface SealedRing {
  alp_sealed: "A256GCM";
  /** Which key-encryption key sealed it (the first 8 bytes of its SHA-256, base64url). */
  kek: string;
  iv: string;
  ct: string;
  tag: string;
}

function isSealed(v: unknown): v is SealedRing {
  return typeof v === "object" && v !== null && (v as Record<string, unknown>)["alp_sealed"] === "A256GCM";
}

/** Parse a key-encryption key: exactly 32 bytes, base64url. */
export function parseKeyEncryptionKey(value: string): Buffer {
  const k = Buffer.from(value.trim(), "base64url");
  if (k.length !== 32 || k.toString("base64url") !== value.trim().replace(/=+$/, "")) throw new Error("the key-encryption key must be 32 random bytes, base64url (43 characters)");
  return k;
}

function kekId(kek: Buffer): string {
  return createHash("sha256").update(kek).digest().subarray(0, 8).toString("base64url");
}

function sealRing(name: string, ring: StoredKeyRing, kek: Buffer): SealedRing {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", kek, iv);
  c.setAAD(Buffer.from(`alp-keyring:${name}`, "utf8"));
  const ct = Buffer.concat([c.update(JSON.stringify(ring), "utf8"), c.final()]);
  return { alp_sealed: "A256GCM", kek: kekId(kek), iv: iv.toString("base64url"), ct: ct.toString("base64url"), tag: c.getAuthTag().toString("base64url") };
}

function openRing(name: string, sealed: SealedRing, kek: Buffer | undefined): StoredKeyRing {
  if (!kek) throw new Error(`key ring ${name} is sealed: set the key-encryption key (ALP_KEYRING_KEY)`);
  if (sealed.kek !== kekId(kek)) throw new Error(`key ring ${name} was sealed with another key-encryption key`);
  const d = createDecipheriv("aes-256-gcm", kek, Buffer.from(sealed.iv, "base64url"));
  d.setAAD(Buffer.from(`alp-keyring:${name}`, "utf8"));
  d.setAuthTag(Buffer.from(sealed.tag, "base64url"));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(sealed.ct, "base64url")), d.final()]).toString("utf8")) as StoredKeyRing;
}

/**
 * Apply every migration not yet recorded, in file-name order, each in its own transaction. Returns the versions applied.
 * Each transaction holds an advisory lock on the schema and checks the version again inside it, so instances starting at
 * once (several cold starts on a fresh database) apply each migration exactly once. Transaction-level locks work
 * through a transaction pooler (Supabase's port 6543), where session-level ones don't.
 */
export async function migrate(sql: Sql, schema = "broker", dir = MIGRATIONS_DIR): Promise<string[]> {
  if (!SCHEMA_RE.test(schema)) throw new Error("invalid schema name");
  const lock = `alp-migrate|${schema}`;
  await sql.begin(async (tx) => {
    await tx`select pg_advisory_xact_lock(hashtextextended(${lock}, 0))`;
    await tx.unsafe(`create schema if not exists ${schema}`);
    await tx.unsafe(`create table if not exists ${schema}.schema_migrations (version text primary key, applied_at timestamptz not null default now())`);
  });
  const done = new Set((await sql.unsafe(`select version from ${schema}.schema_migrations`)).map((r) => String((r as Row)["version"])));
  const applied: string[] = [];
  for (const file of readdirSync(dir).filter((f) => /^[0-9]{3}_[a-z0-9_]+\.sql$/.test(f)).sort()) {
    const version = file.slice(0, 3);
    if (done.has(version)) continue;
    const text = readFileSync(join(dir, file), "utf8");
    const ran = await sql.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtextextended(${lock}, 0))`;
      if ((await tx.unsafe(`select 1 from ${schema}.schema_migrations where version = $1`, [version])).length) return false;
      await tx.unsafe(`set local search_path to ${schema}`);
      await tx.unsafe(text);
      await tx.unsafe(`insert into ${schema}.schema_migrations (version) values ($1)`, [version]);
      return true;
    });
    if (ran) applied.push(version);
  }
  return applied;
}

const clone = <T>(v: T): T => structuredClone(v);

export class PostgresStore implements Store {
  readonly kind: string = "postgres";
  readonly sql: Sql;
  private seenCalls = 0;
  private readonly kek: Buffer | undefined;

  constructor(sql: Sql, opts: { keyEncryptionKey?: string } = {}) {
    this.sql = sql;
    this.kek = opts.keyEncryptionKey ? parseKeyEncryptionKey(opts.keyEncryptionKey) : undefined;
  }

  /** Whether key rings are sealed under a key-encryption key. */
  get sealsKeys(): boolean {
    return this.kek !== undefined;
  }

  private one<T>(rows: readonly Row[], col = "rec"): T | null {
    const r = rows[0];
    return r ? clone(r[col] as T) : null;
  }

  private many<T>(rows: readonly Row[], col = "rec"): T[] {
    return rows.map((r) => clone(r[col] as T));
  }

  private json(v: unknown): postgres.Parameter {
    return this.sql.json(v as postgres.JSONValue);
  }

  async getPrincipal(address: Address): Promise<PrincipalRecord | null> {
    return this.one(await this.sql`select rec from principals where address = ${address} and status <> 'retired' limit 1`);
  }
  async getPrincipalById(id: PrincipalId): Promise<PrincipalRecord | null> {
    return this.one(await this.sql`select rec from principals where principal_id = ${id}`);
  }
  async getPrincipalByIdentity(iss: string, sub: string): Promise<PrincipalRecord | null> {
    return this.one(await this.sql`select rec from principals where iss = ${iss} and sub = ${sub} order by (status = 'retired') limit 1`);
  }
  async putPrincipal(rec: PrincipalRecord): Promise<void> {
    await this.sql`insert into principals (principal_id, address, iss, sub, status, rec)
      values (${rec.principal_id}, ${rec.address}, ${rec.identity.iss}, ${rec.identity.sub}, ${rec.status}, ${this.json(rec)})
      on conflict (principal_id) do update set address = excluded.address, iss = excluded.iss, sub = excluded.sub, status = excluded.status, rec = excluded.rec`;
  }
  async listPrincipals(): Promise<PrincipalRecord[]> {
    return this.many(await this.sql`select rec from principals order by principal_id`);
  }

  async getDelegate(id: DelegateId): Promise<DelegateRecord | null> {
    return this.one(await this.sql`select rec from delegates where id = ${id}`);
  }
  async putDelegate(rec: DelegateRecord): Promise<void> {
    await this.sql`insert into delegates (id, principal, rec) values (${rec.id}, ${rec.principal}, ${this.json(rec)})
      on conflict (id) do update set principal = excluded.principal, rec = excluded.rec`;
  }
  async listDelegates(principal: Address): Promise<DelegateRecord[]> {
    return this.many(await this.sql`select rec from delegates where principal = ${principal} order by id`);
  }

  async getGrant(principal: Address, counterparty: Address): Promise<RelationshipGrant | null> {
    return this.one(await this.sql`select rec from grants where principal = ${principal} and counterparty = ${counterparty}`);
  }
  async putGrant(grant: RelationshipGrant): Promise<void> {
    await this.sql`insert into grants (principal, counterparty, rec) values (${grant.principal}, ${grant.counterparty}, ${this.json(grant)})
      on conflict (principal, counterparty) do update set rec = excluded.rec`;
  }
  async listGrants(principal: Address): Promise<RelationshipGrant[]> {
    return this.many(await this.sql`select rec from grants where principal = ${principal} order by counterparty`);
  }

  async getRevocation(principal: Address, counterparty: Address): Promise<CounterpartyRevocation | null> {
    return this.one(await this.sql`select rec from revocations where principal = ${principal} and counterparty = ${counterparty}`);
  }
  async putRevocation(rec: CounterpartyRevocation): Promise<void> {
    await this.sql`insert into revocations (principal, counterparty, rec) values (${rec.principal}, ${rec.counterparty}, ${this.json(rec)})
      on conflict (principal, counterparty) do update set rec = excluded.rec`;
  }

  async getConnection(principal: Address, id: string): Promise<ConnectionRequestRecord | null> {
    return this.one(await this.sql`select rec from connections where principal = ${principal} and id = ${id}`);
  }
  async putConnection(rec: ConnectionRequestRecord): Promise<void> {
    await this.sql`insert into connections (principal, id, rec) values (${rec.principal}, ${rec.id}, ${this.json(rec)})
      on conflict (principal, id) do update set rec = excluded.rec`;
  }
  async listConnections(principal: Address): Promise<ConnectionRequestRecord[]> {
    return this.many(await this.sql`select rec from connections where principal = ${principal} order by id`);
  }

  async putMessage(rec: MessageRecord): Promise<void> {
    await this.sql`insert into messages (principal, direction, envelope_id, local_id, thread, status, to_delegate, rec)
      values (${rec.principal}, ${rec.direction}, ${rec.envelope.id}, ${rec.local_id}, ${rec.envelope.thread}, ${rec.status}, ${rec.envelope.to.delegate ?? null}, ${this.json(rec)})
      on conflict (principal, direction, envelope_id) do update set local_id = excluded.local_id, thread = excluded.thread, status = excluded.status, to_delegate = excluded.to_delegate, rec = excluded.rec`;
  }
  async getMessage(principal: Address, direction: "in" | "out", envelopeId: string): Promise<MessageRecord | null> {
    return this.one(await this.sql`select rec from messages where principal = ${principal} and direction = ${direction} and envelope_id = ${envelopeId}`);
  }
  async listMessages(principal: Address, q: MessageQuery): Promise<MessageRecord[]> {
    const s = this.sql;
    // Spec 5.4: what an earlier binding with the delegate's label received, or acknowledged, isn't this binding's.
    const since = q.bindingSince;
    const unacked = (id: string) => since !== undefined
      ? s`and (not (rec -> 'acked_by' ? ${id}) or (rec -> 'acked_by' ->> ${id})::timestamptz < ${since}::timestamptz)`
      : s`and not (rec -> 'acked_by' ? ${id})`;
    const addressed = (id: string) => since !== undefined
      ? s`and (to_delegate is null or (to_delegate = ${id} and (rec ->> 'stored_at')::timestamptz >= ${since}::timestamptz))`
      : s`and (to_delegate is null or to_delegate = ${id})`;
    const rows = await s`select rec from messages
      where principal = ${principal}
      ${q.direction !== undefined ? s`and direction = ${q.direction}` : s``}
      ${q.after !== undefined ? s`and local_id > ${q.after}` : s``}
      ${q.before !== undefined ? s`and local_id < ${q.before}` : s``}
      ${q.thread !== undefined ? s`and thread = ${q.thread}` : s``}
      ${q.status !== undefined ? s`and status in ${s(q.status)}` : s``}
      ${q.unackedBy !== undefined ? unacked(q.unackedBy) : s``}
      ${q.forDelegate !== undefined ? addressed(q.forDelegate) : s``}
      ${q.order === "desc" ? s`order by local_id desc` : s`order by local_id asc`}
      limit ${Math.max(0, q.limit)}`;
    return this.many(rows);
  }

  async putDeferredNotice(rec: DeferredNotice): Promise<void> {
    await this.sql`insert into deferred_notices (id, principal_id, due_at, rec) values (${rec.id}, ${rec.principal_id}, ${rec.due_at}, ${this.json(rec)})
      on conflict (id) do update set principal_id = excluded.principal_id, due_at = excluded.due_at, rec = excluded.rec`;
  }
  async takeDueNotices(now: Date, limit: number): Promise<DeferredNotice[]> {
    // One statement: a row is returned only to the call whose delete removed it, so each notice goes to one instance.
    const rows = await this.sql`delete from deferred_notices where id in (
        select id from deferred_notices where due_at <= ${now.toISOString()} order by due_at, id limit ${Math.max(0, limit)} for update skip locked
      ) returning rec`;
    return this.many<DeferredNotice>(rows).sort((a, b) => Date.parse(a.due_at) - Date.parse(b.due_at) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  async getThread(principal: Address, id: string): Promise<ThreadRecord | null> {
    return this.one(await this.sql`select rec from threads where principal = ${principal} and id = ${id}`);
  }
  async putThread(rec: ThreadRecord): Promise<void> {
    await this.sql`insert into threads (principal, id, rec) values (${rec.principal}, ${rec.id}, ${this.json(rec)})
      on conflict (principal, id) do update set rec = excluded.rec`;
  }

  async putHeldOutbound(rec: HeldOutbound): Promise<void> {
    await this.sql`insert into held_outbound (principal, id, rec) values (${rec.principal}, ${rec.id}, ${this.json(rec)})
      on conflict (principal, id) do update set rec = excluded.rec`;
  }
  async claimHeldOutbound(next: HeldOutbound, from: HeldOutbound["state"] = "pending"): Promise<boolean> {
    const rows = await this.sql`update held_outbound set rec = ${this.json(next)}
      where principal = ${next.principal} and id = ${next.id} and rec ->> 'state' = ${from}
      returning id`;
    return rows.length === 1;
  }
  async getHeldOutbound(principal: Address, id: string): Promise<HeldOutbound | null> {
    return this.one(await this.sql`select rec from held_outbound where principal = ${principal} and id = ${id}`);
  }
  async listHeldOutbound(principal: Address): Promise<HeldOutbound[]> {
    return this.many(await this.sql`select rec from held_outbound where principal = ${principal} order by id`);
  }

  async getRatificationRequest(id: string): Promise<RatificationRequest | null> {
    return this.one(await this.sql`select rec from ratification_requests where id = ${id}`);
  }
  async putRatificationRequest(rec: RatificationRequest): Promise<void> {
    await this.sql`insert into ratification_requests (id, principal, rec) values (${rec.id}, ${rec.principal}, ${this.json(rec)})
      on conflict (id) do update set principal = excluded.principal, rec = excluded.rec`;
  }
  async listRatificationRequests(principal: Address): Promise<RatificationRequest[]> {
    return this.many(await this.sql`select rec from ratification_requests where principal = ${principal} order by id`);
  }

  async putReceipt(key: string, receipt: Receipt): Promise<void> {
    await this.sql`insert into receipts (key, rec) values (${key}, ${this.json(receipt)}) on conflict (key) do update set rec = excluded.rec`;
  }
  async getReceipt(key: string): Promise<Receipt | null> {
    return this.one(await this.sql`select rec from receipts where key = ${key}`);
  }

  async appendLedger(principalId: PrincipalId, build: (head: LedgerHead | null) => { entry: LedgerEntry; payload?: LedgerPayload }): Promise<LedgerEntry> {
    return this.sql.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtextextended(${`ledger|${principalId}`}, 0))`;
      const last = (await tx`select seq, hash from ledger where principal_id = ${principalId} order by seq desc limit 1`)[0];
      const head: LedgerHead | null = last ? { seq: Number(last["seq"]), hash: String(last["hash"]) } : null;
      const { entry, payload } = build(head);
      if (entry.principal_id !== principalId || entry.seq !== (head ? head.seq + 1 : 0) || entry.prev_hash !== (head ? head.hash : null)) {
        throw new Error("ledger append: the entry does not extend the chain");
      }
      await tx`insert into ledger (principal_id, seq, hash, entry) values (${principalId}, ${entry.seq}, ${entry.hash}, ${tx.json(entry as unknown as postgres.JSONValue)})`;
      if (payload) await tx`insert into ledger_payloads (principal_id, seq, payload) values (${principalId}, ${entry.seq}, ${tx.json(payload as unknown as postgres.JSONValue)})`;
      return clone(entry);
    });
  }
  async listLedger(principalId: PrincipalId, q: { afterSeq?: number; limit?: number } = {}): Promise<LedgerEntry[]> {
    const s = this.sql;
    const rows = await s`select entry from ledger where principal_id = ${principalId}
      ${q.afterSeq !== undefined ? s`and seq > ${q.afterSeq}` : s``}
      order by seq asc
      ${q.limit !== undefined ? s`limit ${Math.max(0, q.limit)}` : s``}`;
    return this.many(rows, "entry");
  }
  async getLedgerPayload(principalId: PrincipalId, seq: number): Promise<LedgerPayload | null> {
    return this.one(await this.sql`select payload from ledger_payloads where principal_id = ${principalId} and seq = ${seq}`, "payload");
  }
  async eraseLedgerPayload(principalId: PrincipalId, seq: number): Promise<void> {
    await this.sql`delete from ledger_payloads where principal_id = ${principalId} and seq = ${seq}`;
  }

  async recordOnce(key: string, expiresAt: string, now: Date): Promise<boolean> {
    const rows = await this.sql`insert into seen (key, expires_at) values (${key}, ${expiresAt})
      on conflict (key) do update set expires_at = excluded.expires_at where seen.expires_at <= ${now.toISOString()}
      returning key`;
    if (++this.seenCalls % 256 === 0) await this.sql`delete from seen where expires_at <= ${now.toISOString()}`;
    return rows.length === 1;
  }
  async hitRateLimit(key: string, now: Date, windowSeconds: number, limit: number): Promise<RateLimitHit> {
    return this.sql.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtextextended(${`rate|${key}`}, 0))`;
      const since = new Date(now.getTime() - windowSeconds * 1000).toISOString();
      await tx`delete from rate_hits where key = ${key} and at <= ${since}`;
      const row = (await tx`select count(*)::int as n, min(at) as oldest from rate_hits where key = ${key}`)[0];
      const count = Number(row?.["n"] ?? 0);
      const at = row?.["oldest"];
      const oldest = at instanceof Date ? at.getTime() : typeof at === "string" ? Date.parse(at) : undefined;
      const t = now.getTime();
      if (count >= limit) return { allowed: false, count, retryAfter: secondsUntilOldestLeaves(oldest !== undefined ? [oldest] : [], t, windowSeconds) };
      await tx`insert into rate_hits (key, at) values (${key}, ${now.toISOString()})`;
      return { allowed: true, count: count + 1, retryAfter: secondsUntilOldestLeaves(oldest !== undefined ? [oldest, t] : [t], t, windowSeconds) };
    });
  }

  async getKeyRing(name: string): Promise<StoredKeyRing | null> {
    const ring = this.one<unknown>(await this.sql`select ring from keyrings where name = ${name}`, "ring");
    if (ring === null) return null;
    return isSealed(ring) ? openRing(name, ring, this.kek) : (ring as StoredKeyRing);
  }
  async putKeyRing(name: string, ring: StoredKeyRing): Promise<void> {
    const value = this.kek ? sealRing(name, ring, this.kek) : ring;
    await this.sql`insert into keyrings (name, ring) values (${name}, ${this.json(value)}) on conflict (name) do update set ring = excluded.ring`;
  }

  async close(): Promise<void> {
    await this.sql.end({ timeout: 5 });
  }
}

/** Connect, apply pending migrations, and return the store. */
export async function createPostgresStore(opts: PostgresStoreOptions): Promise<PostgresStore> {
  const schema = opts.schema ?? "broker";
  if (!SCHEMA_RE.test(schema)) throw new Error("invalid schema name");
  if (opts.keyEncryptionKey !== undefined) parseKeyEncryptionKey(opts.keyEncryptionKey);
  const sql = postgres(opts.url, {
    max: opts.max ?? 5,
    prepare: opts.prepare ?? false,
    ...(opts.ssl !== undefined ? { ssl: opts.ssl } : {}),
    connection: { search_path: schema, application_name: "reference-broker" },
    onnotice: () => undefined,
  });
  try {
    await migrate(sql, schema);
  } catch (err) {
    await sql.end({ timeout: 5 });
    throw err;
  }
  return new PostgresStore(sql, opts.keyEncryptionKey ? { keyEncryptionKey: opts.keyEncryptionKey } : {});
}
