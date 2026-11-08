// SPDX-License-Identifier: FSL-1.1-ALv2
// The client binding's state in Postgres (src/oauth/state.ts BindingStore): the authorization server's artifacts,
// personal access tokens, held connection requests, send idempotency, and the web view's sessions, step-up challenges,
// invites, passkeys and known devices. Tables from migrations/002_binding.sql and 003_web.sql, in the same schema as the
// core's store, through the same connection pool. Every method is one statement, so it is atomic on its own; the
// single-use and once-only rules (consume, the refresh overlap, login transactions, challenges, passkey counters) are
// conditional updates or deletes with RETURNING, so two instances can't both win. Uses and revocations of tokens and
// invites change one field each, so a request that read a record before a revocation can't write it back live; a
// person's first passkey is stored under a transaction-level advisory lock on the person.

import type postgres from "postgres";
import type {
  BindingStore,
  DeviceRecord,
  IdempotencyRecord,
  InviteRecord,
  JsonRecord,
  PasskeyRecord,
  PatRecord,
  PendingConnection,
  StepUpChallenge,
  WebSessionRecord,
} from "../oauth/state.ts";
import { REUSED_FIELD } from "../oauth/state.ts";

type Sql = postgres.Sql;
type Row = Record<string, unknown>;

const clone = <T>(v: T): T => structuredClone(v);
const iso = (ms: number): string => new Date(ms).toISOString();

export class PostgresBindingStore implements BindingStore {
  readonly kind: string = "postgres";
  readonly sql: Sql;
  private calls = 0;

  constructor(sql: Sql) {
    this.sql = sql;
  }

  private json(v: unknown): postgres.Parameter {
    return this.sql.json(v as postgres.JSONValue);
  }

  private one<T>(rows: readonly Row[], col = "rec"): T | null {
    const r = rows[0];
    return r ? clone(r[col] as T) : null;
  }

  private many<T>(rows: readonly Row[], col = "rec"): T[] {
    return rows.map((r) => clone(r[col] as T));
  }

  /** Expired rows are invisible at once and deleted now and then. */
  private async sweep(nowMs: number): Promise<void> {
    if (++this.calls % 256 !== 0) return;
    const now = iso(nowMs);
    await this.sql`delete from oauth_artifacts where expires_at is not null and expires_at <= ${now}`;
    await this.sql`delete from idempotency where at <= ${iso(nowMs - 24 * 3600_000)}`;
    await this.sql`delete from web_challenges where expires_at <= ${now}`;
    await this.sql`delete from web_sessions where expires_at <= ${now}`;
  }

  // ---- oidc-provider's models

  async oidcGet(model: string, key: string, nowMs: number): Promise<JsonRecord | null> {
    await this.sweep(nowMs);
    return this.one(await this.sql`select payload from oauth_artifacts where model = ${model} and key = ${key} and (expires_at is null or expires_at > ${iso(nowMs)})`, "payload");
  }
  async oidcPut(model: string, key: string, payload: JsonRecord, expiresAtMs?: number): Promise<void> {
    const grantId = typeof payload["grantId"] === "string" ? payload["grantId"] : null;
    const uid = typeof payload["uid"] === "string" ? payload["uid"] : null;
    const account = typeof payload["accountId"] === "string" ? payload["accountId"] : null;
    const client = typeof payload["clientId"] === "string" ? payload["clientId"] : null;
    const expires = expiresAtMs !== undefined ? iso(expiresAtMs) : null;
    await this.sql`insert into oauth_artifacts (model, key, payload, expires_at, grant_id, uid, account_id, client_id)
      values (${model}, ${key}, ${this.json(payload)}, ${expires}, ${grantId}, ${uid}, ${account}, ${client})
      on conflict (model, key) do update set payload = excluded.payload, expires_at = excluded.expires_at, grant_id = excluded.grant_id,
        uid = excluded.uid, account_id = excluded.account_id, client_id = excluded.client_id`;
  }
  async oidcTake(model: string, key: string, nowMs: number): Promise<JsonRecord | null> {
    const r = (await this.sql`delete from oauth_artifacts where model = ${model} and key = ${key} returning payload, expires_at`)[0];
    if (!r) return null;
    const expires = r["expires_at"] === null || r["expires_at"] === undefined ? undefined : new Date(r["expires_at"] as string | Date).getTime();
    return expires !== undefined && expires <= nowMs ? null : clone(r["payload"] as JsonRecord);
  }
  async oidcFindBy(model: string, field: "uid" | "userCode", value: string, nowMs: number): Promise<JsonRecord | null> {
    const s = this.sql;
    const rows = field === "uid"
      ? await s`select payload from oauth_artifacts where model = ${model} and uid = ${value} and (expires_at is null or expires_at > ${iso(nowMs)}) limit 1`
      : await s`select payload from oauth_artifacts where model = ${model} and payload ->> 'userCode' = ${value} and (expires_at is null or expires_at > ${iso(nowMs)}) limit 1`;
    return this.one(rows, "payload");
  }
  async oidcConsume(model: string, key: string, atSeconds: number): Promise<void> {
    await this.sql`update oauth_artifacts set payload = payload || jsonb_build_object('consumed', ${atSeconds}::bigint)
      where model = ${model} and key = ${key} and not (payload ? 'consumed')`;
  }
  async oidcTakeReuse(model: string, key: string, nowSeconds: number, intervalSeconds: number): Promise<boolean> {
    const rows = await this.sql`update oauth_artifacts set payload = payload || jsonb_build_object(${REUSED_FIELD}::text, ${nowSeconds}::bigint)
      where model = ${model} and key = ${key}
        and (expires_at is null or expires_at > ${iso(nowSeconds * 1000)})
        and jsonb_typeof(payload -> 'consumed') = 'number'
        and not (payload ? ${REUSED_FIELD})
        and ${nowSeconds}::bigint - (payload ->> 'consumed')::numeric <= ${intervalSeconds}
      returning key`;
    return rows.length === 1;
  }
  async oidcSetExpiry(model: string, key: string, expiresAtMs: number): Promise<void> {
    await this.sql`update oauth_artifacts set expires_at = ${iso(expiresAtMs)} where model = ${model} and key = ${key}`;
  }
  async oidcDelete(model: string, key: string): Promise<void> {
    await this.sql`delete from oauth_artifacts where model = ${model} and key = ${key}`;
  }
  async oidcDeleteByGrant(model: string, grantId: string): Promise<void> {
    await this.sql`delete from oauth_artifacts where model = ${model} and grant_id = ${grantId}`;
  }
  async oidcGrantIds(accountId: string, clientId: string, nowMs: number): Promise<string[]> {
    const rows = await this.sql`select payload ->> 'jti' as jti from oauth_artifacts
      where model = 'Grant' and account_id = ${accountId} and client_id = ${clientId} and (expires_at is null or expires_at > ${iso(nowMs)})
      order by key`;
    return rows.map((r) => r["jti"]).filter((j): j is string => typeof j === "string");
  }
  async oidcCount(model: string, nowMs: number): Promise<number> {
    const rows = await this.sql`select count(*)::int as n from oauth_artifacts where model = ${model} and (expires_at is null or expires_at > ${iso(nowMs)})`;
    return Number(rows[0]?.["n"] ?? 0);
  }

  // ---- personal access tokens

  async putPat(rec: PatRecord): Promise<void> {
    await this.sql`insert into pats (id, hash, principal_id, delegate, created_at, rec)
      values (${rec.id}, ${rec.hash}, ${rec.principal_id}, ${rec.delegate}, ${rec.created_at}, ${this.json(rec)})
      on conflict (id) do update set hash = excluded.hash, principal_id = excluded.principal_id, delegate = excluded.delegate, rec = excluded.rec`;
  }
  async getPat(id: string): Promise<PatRecord | null> {
    return this.one(await this.sql`select rec from pats where id = ${id}`);
  }
  async findPatByHash(hash: string): Promise<PatRecord | null> {
    return this.one(await this.sql`select rec from pats where hash = ${hash}`);
  }
  async listPats(principalId: string): Promise<PatRecord[]> {
    return this.many(await this.sql`select rec from pats where principal_id = ${principalId} order by created_at desc, id desc`);
  }
  async listPatsOfDelegate(delegate: string): Promise<PatRecord[]> {
    return this.many(await this.sql`select rec from pats where delegate = ${delegate} order by id`);
  }
  async touchPat(id: string, at: string): Promise<boolean> {
    const rows = await this.sql`update pats set rec = rec || jsonb_build_object('last_used_at', ${at}::text)
      where id = ${id} and not (rec ? 'revoked_at') returning id`;
    return rows.length === 1;
  }
  async revokePat(id: string, at: string): Promise<PatRecord | null> {
    // The left side loses on a key both have: a token already revoked keeps its first revocation time.
    return this.one(await this.sql`update pats set rec = jsonb_build_object('revoked_at', ${at}::text) || rec where id = ${id} returning rec`);
  }

  // ---- connection requests an agent filed

  async putPending(rec: PendingConnection): Promise<void> {
    await this.sql`insert into pending_connections (id, principal_id, created_at, rec) values (${rec.id}, ${rec.principal_id}, ${rec.created_at}, ${this.json(rec)})
      on conflict (id) do update set principal_id = excluded.principal_id, rec = excluded.rec`;
  }
  async getPending(id: string): Promise<PendingConnection | null> {
    return this.one(await this.sql`select rec from pending_connections where id = ${id}`);
  }
  async listPending(principalId: string): Promise<PendingConnection[]> {
    return this.many(await this.sql`select rec from pending_connections where principal_id = ${principalId} order by created_at desc, id desc`);
  }

  // ---- send idempotency

  async getIdempotency(key: string): Promise<IdempotencyRecord | null> {
    const r = (await this.sql`select at, result from idempotency where key = ${key}`)[0];
    return r ? { at: new Date(r["at"] as string | Date).getTime(), result: clone(r["result"] as JsonRecord) } : null;
  }
  async putIdempotency(key: string, rec: IdempotencyRecord): Promise<void> {
    await this.sql`insert into idempotency (key, at, result) values (${key}, ${iso(rec.at)}, ${this.json(rec.result)})
      on conflict (key) do update set at = excluded.at, result = excluded.result`;
  }
  async swapIdempotency(key: string, seen: number | null, rec: IdempotencyRecord | null): Promise<boolean> {
    // One statement each: the primary key, or the `at` the caller read, makes the check and the write one step.
    if (seen === null) {
      if (!rec) return (await this.sql`select 1 from idempotency where key = ${key}`).length === 0;
      return (await this.sql`insert into idempotency (key, at, result) values (${key}, ${iso(rec.at)}, ${this.json(rec.result)})
        on conflict (key) do nothing returning key`).length === 1;
    }
    if (!rec) return (await this.sql`delete from idempotency where key = ${key} and at = ${iso(seen)} returning key`).length === 1;
    return (await this.sql`update idempotency set at = ${iso(rec.at)}, result = ${this.json(rec.result)} where key = ${key} and at = ${iso(seen)} returning key`).length === 1;
  }

  // ---- the web view

  async getWebSession(idHash: string): Promise<WebSessionRecord | null> {
    await this.sweep(Date.now());
    return this.one(await this.sql`select rec from web_sessions where id_hash = ${idHash}`);
  }
  async putWebSession(rec: WebSessionRecord): Promise<void> {
    // Kept a day past the last request at most; the web view itself ends a session after 15 idle minutes.
    const expires = iso(rec.last_seen + 24 * 3600_000);
    await this.sql`insert into web_sessions (id_hash, principal_id, rec, expires_at) values (${rec.id_hash}, ${rec.principal_id}, ${this.json(rec)}, ${expires})
      on conflict (id_hash) do update set principal_id = excluded.principal_id, rec = excluded.rec, expires_at = excluded.expires_at`;
  }
  async deleteWebSession(idHash: string): Promise<void> {
    await this.sql`delete from web_challenges where session_hash = ${idHash}`;
    await this.sql`delete from web_sessions where id_hash = ${idHash}`;
  }
  async deleteWebSessionsOf(principalId: string): Promise<void> {
    await this.sql`delete from web_challenges where session_hash in (select id_hash from web_sessions where principal_id = ${principalId})`;
    await this.sql`delete from web_sessions where principal_id = ${principalId}`;
  }
  async putChallenge(rec: StepUpChallenge): Promise<void> {
    await this.sql`insert into web_challenges (challenge, session_hash, rec, expires_at) values (${rec.challenge}, ${rec.session_hash}, ${this.json(rec)}, ${iso(rec.expires_at)})
      on conflict (challenge) do nothing`;
  }
  async takeChallenge(sessionHash: string, challenge: string, nowMs: number): Promise<StepUpChallenge | null> {
    const rows = await this.sql`delete from web_challenges where challenge = ${challenge} and session_hash = ${sessionHash} returning rec, expires_at`;
    const r = rows[0];
    if (!r || new Date(r["expires_at"] as string | Date).getTime() <= nowMs) return null;
    return clone(r["rec"] as StepUpChallenge);
  }

  async putInvite(rec: InviteRecord): Promise<void> {
    await this.sql`insert into invites (id, username, created_at, rec) values (${rec.id}, ${rec.username}, ${rec.created_at}, ${this.json(rec)})
      on conflict (id) do update set username = excluded.username, rec = excluded.rec`;
  }
  async getInvite(id: string): Promise<InviteRecord | null> {
    return this.one(await this.sql`select rec from invites where id = ${id}`);
  }
  async listInvites(username?: string): Promise<InviteRecord[]> {
    const s = this.sql;
    return this.many(await s`select rec from invites ${username !== undefined ? s`where username = ${username}` : s``} order by created_at, id`);
  }
  async touchInvite(id: string, at: string): Promise<boolean> {
    const rows = await this.sql`update invites set rec = rec || jsonb_build_object('last_used_at', ${at}::text)
      where id = ${id} and not (rec ? 'revoked_at') returning id`;
    return rows.length === 1;
  }
  async revokeInvite(id: string, at: string): Promise<InviteRecord | null> {
    return this.one(await this.sql`update invites set rec = jsonb_build_object('revoked_at', ${at}::text) || rec where id = ${id} returning rec`);
  }

  async putPasskey(rec: PasskeyRecord): Promise<void> {
    await this.sql`insert into passkeys (credential_id, principal_id, counter, rec) values (${rec.credential_id}, ${rec.principal_id}, ${rec.counter}, ${this.json(rec)})
      on conflict (credential_id) do update set principal_id = excluded.principal_id, counter = excluded.counter, rec = excluded.rec`;
  }
  async addFirstPasskey(rec: PasskeyRecord): Promise<boolean> {
    // The lock makes "has none yet" and the insert one step: of two registrations at once, the second waits, then sees
    // the first one's passkey. Transaction-level, so it works through a transaction pooler.
    return this.sql.begin(async (tx) => {
      await tx`select pg_advisory_xact_lock(hashtextextended(${`passkey-first|${rec.principal_id}`}, 0))`;
      if ((await tx`select 1 from passkeys where principal_id = ${rec.principal_id} limit 1`).length) return false;
      const rows = await tx`insert into passkeys (credential_id, principal_id, counter, rec) values (${rec.credential_id}, ${rec.principal_id}, ${rec.counter}, ${tx.json(rec as unknown as postgres.JSONValue)})
        on conflict (credential_id) do nothing returning credential_id`;
      return rows.length === 1;
    });
  }
  async getPasskey(credentialId: string): Promise<PasskeyRecord | null> {
    return this.one(await this.sql`select rec from passkeys where credential_id = ${credentialId}`);
  }
  async listPasskeys(principalId: string): Promise<PasskeyRecord[]> {
    return this.many(await this.sql`select rec from passkeys where principal_id = ${principalId} order by rec ->> 'created_at', credential_id`);
  }
  async usePasskey(credentialId: string, counter: number, at: string): Promise<boolean> {
    const rows = await this.sql`update passkeys set counter = ${counter},
        rec = rec || jsonb_build_object('counter', ${counter}::bigint, 'last_used_at', ${at}::text)
      where credential_id = ${credentialId} and (${counter}::bigint > counter or (${counter}::bigint = 0 and counter = 0))
      returning credential_id`;
    return rows.length === 1;
  }

  async noteDevice(principalId: string, deviceHash: string, at: string): Promise<boolean> {
    const rows = await this.sql`insert into web_devices (principal_id, device_hash, first_seen, last_seen) values (${principalId}, ${deviceHash}, ${at}, ${at})
      on conflict (principal_id, device_hash) do update set last_seen = excluded.last_seen
      returning (xmax = 0) as inserted`;
    return rows[0]?.["inserted"] === true;
  }
  async listDevices(principalId: string): Promise<DeviceRecord[]> {
    const rows = await this.sql`select principal_id, device_hash, first_seen, last_seen from web_devices where principal_id = ${principalId} order by first_seen`;
    return rows.map((r) => ({
      principal_id: String(r["principal_id"]),
      device_hash: String(r["device_hash"]),
      first_seen: new Date(r["first_seen"] as string | Date).toISOString(),
      last_seen: new Date(r["last_seen"] as string | Date).toISOString(),
    }));
  }

  /** The pool belongs to the core's PostgresStore (closed with it). */
  async close(): Promise<void> {}
}
