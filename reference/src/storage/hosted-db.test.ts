// SPDX-License-Identifier: FSL-1.1-ALv2
// The hosted database's defenses, on PGlite (Postgres compiled to WebAssembly, in this process; the bridge on a
// loopback port from the tests' pool) or ALP_TEST_POSTGRES_URL:
// - row-level security on every table with no policy (migrations/004): Supabase's `anon` and `authenticated` roles
//   read and write nothing, even if someone later grants them the schema;
// - key rings sealed under a key-encryption key held outside the database: the database holds no usable private key.

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { copyFileSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import postgres from "postgres";
import { KeyRing } from "../core/keys.ts";
import { startPgliteBridge } from "./pglite-bridge.ts";
import type { PgliteBridge } from "./pglite-bridge.ts";
import { MIGRATIONS_DIR, createPostgresStore, migrate, parseKeyEncryptionKey } from "./postgres.ts";
import { sha256b64u } from "../oauth/state.ts";
import type { PostgresStore } from "./postgres.ts";
import { PostgresBindingStore } from "./postgres-binding.ts";

const SCHEMA = `alp_hosted_${process.pid}`;
const external = process.env["ALP_TEST_POSTGRES_URL"];

describe("hosted database: deny by default", () => {
  let bridge: PgliteBridge | undefined;
  let url = "";
  let store: PostgresStore;
  let admin: postgres.Sql;
  let tables: string[] = [];

  before(async () => {
    bridge = external ? undefined : await startPgliteBridge();
    url = external ?? bridge?.url ?? "";
    admin = postgres(url, { max: 1, prepare: false, onnotice: () => undefined });
    // Supabase's API roles, before the migrations run (as on a new Supabase project).
    for (const role of ["anon", "authenticated"]) {
      await admin.unsafe(`do $$ begin if not exists (select 1 from pg_roles where rolname = '${role}') then create role ${role} nologin; end if; end $$`);
    }
    store = await createPostgresStore({ url, schema: SCHEMA, max: 2 });
    // Data in the tables a leak would matter for.
    await store.putPrincipal({ principal_id: "ana-principal-00001", address: "alp:ana@example.org", identity: { iss: "https://idp.example", sub: "a1" }, status: "active", created_at: new Date().toISOString() });
    await store.putKeyRing("federation", (await KeyRing.generate(new Date())).toJSON());
    const binding = new PostgresBindingStore(store.sql);
    await binding.oidcPut("RefreshToken", "k", { grantId: "g", jti: "r" }, Date.now() + 60_000);
    await binding.putPasskey({ credential_id: "cred", principal_id: "ana-principal-00001", public_key: "pk", counter: 0, created_at: new Date().toISOString() });
    await binding.putInvite({ id: "01JCI00000000000000000000A", username: "ana", address: "alp:ana@example.org", secret_hash: "scrypt$16384$8$1$AAAA$BBBB", created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 86400_000).toISOString() });
    tables = (await admin`select tablename from pg_tables where schemaname = ${SCHEMA} order by tablename`).map((r) => String(r["tablename"]));
  });

  after(async () => {
    await admin?.unsafe(`drop schema if exists ${SCHEMA} cascade`);
    await admin?.end({ timeout: 2 });
    await store?.close();
    await bridge?.close();
  });

  /** Run `fn` as `role` inside a transaction that is always rolled back. */
  async function as<T>(role: string, fn: (tx: postgres.TransactionSql) => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> {
    let out: { ok: true; value: T } | { ok: false; error: string } = { ok: false, error: "not run" };
    await admin
      .begin(async (tx) => {
        await tx.unsafe(`set local role ${role}`);
        try {
          out = { ok: true, value: await fn(tx) };
        } catch (err) {
          out = { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
        throw new Error("rollback");
      })
      .catch(() => undefined);
    return out;
  }

  test("every table of the schema has row-level security on (a new migration that forgets fails here)", async () => {
    assert.ok(tables.length >= 20, `the schema's tables (${tables.join(", ")})`);
    for (const t of ["oauth_artifacts", "pats", "pending_connections", "idempotency", "web_sessions", "web_challenges", "invites", "passkeys", "web_devices", "keyrings", "principals", "ledger", "deferred_notices", "schema_migrations"]) assert.ok(tables.includes(t), t);
    const off = await admin`select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = ${SCHEMA} and c.relkind in ('r', 'p') and not c.relrowsecurity`;
    assert.deepEqual(off.map((r) => r["relname"]), []);
    const policies = await admin`select count(*)::int as n from pg_policies where schemaname = ${SCHEMA}`;
    assert.equal(policies[0]?.["n"], 0, "no policy: nothing is allowed to anyone the rules apply to");
  });

  test("anon and authenticated can't even reach the schema as migrated", async () => {
    for (const role of ["anon", "authenticated"]) {
      for (const t of tables) {
        const r = await as(role, (tx) => tx.unsafe(`select * from ${SCHEMA}.${t} limit 1`));
        assert.equal(r.ok, false, `${role} read ${t}`);
        if (!r.ok) assert.match(r.error, /permission denied/);
      }
      const w = await as(role, (tx) => tx.unsafe(`insert into ${SCHEMA}.invites (id, username, created_at, rec) values ('x', 'x', 'x', '{}')`));
      assert.equal(w.ok, false, `${role} wrote invites`);
    }
  });

  test("even with the schema granted to them (a mistake later), anon reads no row and writes none", async () => {
    await admin.unsafe(`grant usage on schema ${SCHEMA} to anon, authenticated`);
    await admin.unsafe(`grant all on all tables in schema ${SCHEMA} to anon, authenticated`);
    try {
      for (const role of ["anon", "authenticated"]) {
        for (const t of tables) {
          const r = await as(role, (tx) => tx.unsafe(`select count(*)::int as n from ${SCHEMA}.${t}`));
          assert.ok(r.ok, `${role} may run a select on ${t} now`);
          if (r.ok) assert.equal((r.value as unknown as { n: number }[])[0]?.n, 0, `${role} sees no row of ${t}`);
        }
        const ins = await as(role, (tx) => tx.unsafe(`insert into ${SCHEMA}.invites (id, username, created_at, rec) values ('x', 'x', 'x', '{}')`));
        assert.equal(ins.ok, false, "insert refused");
        if (!ins.ok) assert.match(ins.error, /row-level security/);
        const upd = await as(role, (tx) => tx.unsafe(`update ${SCHEMA}.passkeys set counter = 99 returning credential_id`));
        assert.ok(upd.ok && (upd.value as unknown as unknown[]).length === 0, "update touches no row");
        const del = await as(role, (tx) => tx.unsafe(`delete from ${SCHEMA}.keyrings returning name`));
        assert.ok(del.ok && (del.value as unknown as unknown[]).length === 0, "delete touches no row");
      }
      // The broker's own role (the tables' owner) still reads and writes.
      assert.equal((await store.getPrincipal("alp:ana@example.org"))?.principal_id, "ana-principal-00001");
      assert.equal((await admin.unsafe(`select count(*)::int as n from ${SCHEMA}.passkeys where counter = 99`))[0]?.["n"], 0);
    } finally {
      await admin.unsafe(`revoke all on all tables in schema ${SCHEMA} from anon, authenticated`);
      await admin.unsafe(`revoke usage on schema ${SCHEMA} from anon, authenticated`);
    }
  });
});

test("instances starting at once on a fresh database apply each migration exactly once", async () => {
  const b = external ? undefined : await startPgliteBridge();
  const u = external ?? b?.url ?? "";
  const schema = `alp_race_${process.pid}`;
  const stores = await Promise.all([1, 2, 3].map(() => createPostgresStore({ url: u, schema, max: 1 })));
  try {
    const versions = (await stores[0]!.sql.unsafe(`select version from ${schema}.schema_migrations order by version`)).map((r) => String((r as Record<string, unknown>)["version"]));
    assert.deepEqual(versions, ["001", "002", "003", "004", "005", "006", "007"]);
    await stores[0]!.sql.unsafe(`drop schema ${schema} cascade`);
  } finally {
    for (const s of stores) await s.close();
    await b?.close();
  }
});

test("migration 005 takes the raw token ids out of rows stored before it; 006 allows one live principal per address and identity", async () => {
  const b = external ? undefined : await startPgliteBridge();
  const u = external ?? b?.url ?? "";
  const schema = `alp_m005_${process.pid}`;
  const sql = postgres(u, { max: 1, prepare: false, onnotice: () => undefined });
  const early = mkdtempSync(join(tmpdir(), "alp-migrations-"));
  try {
    for (const f of readdirSync(MIGRATIONS_DIR).filter((f) => f < "005")) copyFileSync(join(MIGRATIONS_DIR, f), join(early, f));
    assert.deepEqual(await migrate(sql, schema, early), ["001", "002", "003", "004"]);
    // As the adapter stored them before version 5: the token itself in the payload, next to its hash.
    const rt = "refresh-token-value-0000000000000000000042";
    await sql.unsafe(`insert into ${schema}.oauth_artifacts (model, key, payload) values ($1, $2, $3::text::jsonb), ($4, $5, $6::text::jsonb), ($7, $8, $9::text::jsonb)`, [
      "RefreshToken", sha256b64u(rt), JSON.stringify({ jti: rt, grantId: "g" }),
      "Interaction", sha256b64u("uid-42"), JSON.stringify({ jti: "uid-42", session: { uid: "s42", cookie: "cookie-value-42" } }),
      "Grant", sha256b64u("grant-42"), JSON.stringify({ jti: "grant-42", accountId: "acc", clientId: "c" }),
    ]);
    assert.deepEqual(await migrate(sql, schema), ["005", "006", "007"]);
    const rows = await sql.unsafe(`select model, payload::text as p from ${schema}.oauth_artifacts order by model`);
    const text = rows.map((r) => String((r as Record<string, unknown>)["p"])).join(" ");
    assert.ok(!text.includes(rt) && !text.includes("cookie-value-42") && !text.includes("uid-42\""), `no token, cookie or interaction id left: ${text}`);
    assert.ok(text.includes("grant-42"), "grant ids stay");
    // 006: a second live principal for an address or an identity is refused; a retired one may share them.
    const put = (id: string, address: string, sub: string, status: string): Promise<unknown> =>
      sql.unsafe(`insert into ${schema}.principals (principal_id, address, iss, sub, status, rec) values ($1, $2, 'https://idp.example', $3, $4, '{}'::jsonb)`, [id, address, sub, status]);
    await put("p1", "alp:ana@example.org", "a1", "active");
    await put("p0", "alp:ana@example.org", "a1", "retired");
    await assert.rejects(put("p2", "alp:ana@example.org", "a2", "active"), /duplicate key|unique/);
    await assert.rejects(put("p3", "alp:ann@example.org", "a1", "active"), /duplicate key|unique/);
  } finally {
    await sql.unsafe(`drop schema if exists ${schema} cascade`);
    await sql.end({ timeout: 2 });
    rmSync(early, { recursive: true, force: true });
    await b?.close();
  }
});

describe("hosted database: key rings sealed under a key held outside it", () => {
  let bridge: PgliteBridge | undefined;
  let url = "";
  const schema = `alp_keys_${process.pid}`;
  const opened: PostgresStore[] = [];

  before(async () => {
    bridge = external ? undefined : await startPgliteBridge();
    url = external ?? bridge?.url ?? "";
  });
  after(async () => {
    await opened[0]?.sql.unsafe(`drop schema if exists ${schema} cascade`);
    for (const s of opened) await s.close();
    await bridge?.close();
  });

  test("with ALP_KEYRING_KEY the row holds ciphertext only; the key opens it, nothing else does", async () => {
    const kek = randomBytes(32).toString("base64url");
    const sealed = await createPostgresStore({ url, schema, max: 1, keyEncryptionKey: kek });
    opened.push(sealed);
    const ring = (await KeyRing.generate(new Date())).toJSON();
    await sealed.putKeyRing("federation", ring);
    const raw = (await sealed.sql`select ring from keyrings where name = 'federation'`)[0]?.["ring"] as Record<string, unknown>;
    assert.equal(raw["alp_sealed"], "A256GCM");
    const d = String(ring.keys[0]?.private_jwk["d"] ?? "");
    assert.ok(d.length > 20 && !JSON.stringify(raw).includes(d), "no private key material in the row");
    assert.deepEqual(await sealed.getKeyRing("federation"), ring);

    const without = await createPostgresStore({ url, schema, max: 1 });
    opened.push(without);
    await assert.rejects(without.getKeyRing("federation"), /sealed: set the key-encryption key/);
    const wrong = await createPostgresStore({ url, schema, max: 1, keyEncryptionKey: randomBytes(32).toString("base64url") });
    opened.push(wrong);
    await assert.rejects(wrong.getKeyRing("federation"), /another key-encryption key/);

    // A ring stored before a key was set stays readable, and is sealed on its next write.
    await without.putKeyRing("http", ring);
    assert.deepEqual(await sealed.getKeyRing("http"), ring);
    await sealed.putKeyRing("http", ring);
    assert.equal(((await sealed.sql`select ring from keyrings where name = 'http'`)[0]?.["ring"] as Record<string, unknown>)["alp_sealed"], "A256GCM");
    assert.throws(() => parseKeyEncryptionKey("too-short"), /32 random bytes/);
    await assert.rejects(createPostgresStore({ url, schema, keyEncryptionKey: "too-short" }), /32 random bytes/, "checked before connecting");
  });
});
