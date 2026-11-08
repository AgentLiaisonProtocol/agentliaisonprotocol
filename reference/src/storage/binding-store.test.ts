// SPDX-License-Identifier: FSL-1.1-ALv2
// One conformance suite for the client binding's state (src/oauth/state.ts BindingStore), run against the memory and
// file stores and against Postgres: PGlite (Postgres compiled to WebAssembly, in this process) behind the wire-protocol
// bridge on a loopback port from the tests' pool, or a real database with ALP_TEST_POSTGRES_URL. Each Postgres test gets
// a schema of its own.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BindingState, ID_IS_SECRET, sha256b64u } from "../oauth/state.ts";
import type { BindingStore, InviteRecord, JsonRecord, JsonValue, PasskeyRecord, PatRecord, PendingConnection, WebSessionRecord } from "../oauth/state.ts";
import { StateAdapter } from "../oauth/adapter.ts";
import { startPgliteBridge } from "./pglite-bridge.ts";
import { createPostgresStore } from "./postgres.ts";
import type { PostgresStore } from "./postgres.ts";
import { PostgresBindingStore } from "./postgres-binding.ts";

const T0 = Date.parse("2026-11-09T14:00:00.000Z");

const pat = (id: string, extra: Partial<PatRecord> = {}): PatRecord => ({
  id,
  hash: `hash-${id}`,
  principal_id: "ana-principal-00001",
  delegate: "alp:ana@example.org/muse",
  label: "muse",
  scopes: ["read", "send"],
  created_at: new Date(T0 + id.charCodeAt(id.length - 1) * 1000).toISOString(),
  expires_at: new Date(T0 + 86400_000).toISOString(),
  ...extra,
});

const session = (idHash: string, extra: Partial<WebSessionRecord> = {}): WebSessionRecord => ({
  id_hash: idHash,
  principal: "alp:ana@example.org",
  principal_id: "ana-principal-00001",
  username: "ana",
  csrf: "csrf-token-not-a-secret",
  stage: "full",
  auth_at: T0,
  method: "webauthn-uv",
  created_at: T0,
  last_seen: T0,
  ...extra,
});

/** Every string anywhere in a stored payload. */
function strings(v: JsonValue, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (v !== null && typeof v === "object") for (const x of Object.values(v)) strings(x, out);
  return out;
}

/** The ids the adapter test below stores, by model: each is a usable token, cookie or grant id. */
const ARTIFACTS: [model: string, id: string, payload: JsonRecord][] = [
  ["RefreshToken", "refresh-token-value-0000000000000000000001", { grantId: "grant-id-1", accountId: "acc", clientId: "c", kind: "RefreshToken", iat: 1, exp: 4102444800 }],
  ["AuthorizationCode", "authorization-code-value-00000000000000001", { grantId: "grant-id-1", accountId: "acc", clientId: "c", kind: "AuthorizationCode", codeChallenge: "x", iat: 1, exp: 4102444800 }],
  ["RegistrationAccessToken", "registration-access-token-000000000000001", { clientId: "c", kind: "RegistrationAccessToken", iat: 1, exp: 4102444800 }],
  ["Session", "session-cookie-value-00000000000000000001", { uid: "session-uid-1", accountId: "acc", kind: "Session", authorizations: { c: { sid: "sid-1", grantId: "grant-id-1" } }, iat: 1, exp: 4102444800 }],
  ["Interaction", "interaction-uid-0000000000001", { kind: "Interaction", session: { uid: "session-uid-1", accountId: "acc", cookie: "session-cookie-value-00000000000000000001" }, params: { client_id: "c" }, iat: 1, exp: 4102444800 }],
  ["Grant", "grant-id-1", { kind: "Grant", accountId: "acc", clientId: "c", iat: 1, exp: 4102444800 }],
];

async function conformance(name: string, make: () => Promise<BindingStore>): Promise<void> {
  await test(`${name}: no stored payload holds a usable token: raw ids leave the payload and come back on lookup`, async () => {
    const s = await make();
    for (const [model, id, payload] of ARTIFACTS) await new StateAdapter(s, model).upsert(id, { ...payload, jti: id } as never, 3600);
    const secrets = ARTIFACTS.filter(([model]) => model !== "Grant").map(([, id]) => id);
    for (const [model, id] of ARTIFACTS) {
      const key = sha256b64u(id);
      const stored = await s.oidcGet(model, key, Date.now());
      assert.ok(stored, `${model} stored under the id's hash`);
      const found = strings(stored);
      assert.ok(!found.some((v) => sha256b64u(v) === key) || model === "Grant", `${model}: no value in the payload hashes to its key`);
      for (const secret of secrets) assert.ok(!found.includes(secret), `${model}: no other artifact's token or cookie either`);
      const back = (await new StateAdapter(s, model).find(id)) as Record<string, unknown> | undefined;
      assert.equal(back?.["jti"], id, `${model}: oidc-provider gets its id back as jti`);
    }
    assert.equal((await s.oidcGet("Grant", sha256b64u("grant-id-1"), Date.now()))?.["jti"], "grant-id-1", "a grant keeps its id (listed per account and client)");
    assert.deepEqual(await s.oidcGrantIds("acc", "c", Date.now()), ["grant-id-1"]);
    const interaction = (await new StateAdapter(s, "Interaction").find("interaction-uid-0000000000001")) as Record<string, Record<string, unknown>> | undefined;
    assert.equal(interaction?.["session"]?.["uid"], "session-uid-1", "the interaction still names its session by uid");
    assert.equal(interaction?.["session"]?.["cookie"], undefined, "but not by its cookie");
    const byUid = (await new StateAdapter(s, "Session").findByUid("session-uid-1")) as Record<string, unknown> | undefined;
    assert.equal(byUid?.["accountId"], "acc", "a session found by uid (oidc-provider only checks it)");
    assert.equal(byUid?.["jti"], undefined, "comes back without its cookie value");
    assert.ok(ID_IS_SECRET.has("RefreshToken") && !ID_IS_SECRET.has("Grant") && !ID_IS_SECRET.has("Client"));
  });

  await test(`${name}: a login transaction or hand-off is taken once, even twice at once`, async () => {
    const s = await make();
    const tx = new StateAdapter(s, "AlpOidcLogin");
    await tx.upsert("state-value-1", { purpose: "web" } as never, 600);
    const both = await Promise.all([tx.take("state-value-1"), tx.take("state-value-1")]);
    assert.equal(both.filter((x) => x !== undefined).length, 1, "exactly one taker");
    assert.equal(await tx.find("state-value-1"), undefined, "gone");
    await s.oidcPut("AlpOidcLogin", sha256b64u("old"), { purpose: "web" }, Date.now() - 1);
    assert.equal(await s.oidcTake("AlpOidcLogin", sha256b64u("old"), Date.now()), null, "an expired one isn't returned");
  });

  await test(`${name}: oidc-provider artifacts: put, get, expiry, lookups by uid and grant, delete`, async () => {
    const s = await make();
    await s.oidcPut("Session", "k1", { uid: "u1", accountId: "acc", jti: "s1" }, T0 + 60_000);
    await s.oidcPut("Interaction", "k2", { uid: "u2", jti: "i1" });
    await s.oidcPut("AccessToken", "k3", { grantId: "g1", jti: "a1" }, T0 + 600_000);
    await s.oidcPut("RefreshToken", "k4", { grantId: "g1", jti: "r1" }, T0 + 600_000);
    await s.oidcPut("AccessToken", "k5", { grantId: "g2", jti: "a2" }, T0 + 600_000);
    assert.deepEqual(await s.oidcGet("Session", "k1", T0), { uid: "u1", accountId: "acc", jti: "s1" });
    assert.equal(await s.oidcGet("Session", "k1", T0 + 60_000), null, "expired at expiresAt");
    assert.equal(await s.oidcGet("Session", "k2", T0), null, "keys are per model");
    assert.deepEqual(await s.oidcFindBy("Interaction", "uid", "u2", T0), { uid: "u2", jti: "i1" });
    assert.equal(await s.oidcFindBy("Interaction", "uid", "nope", T0), null);
    await s.oidcDeleteByGrant("AccessToken", "g1");
    assert.equal(await s.oidcGet("AccessToken", "k3", T0), null);
    assert.ok(await s.oidcGet("RefreshToken", "k4", T0), "only that model's artifacts of the grant");
    assert.ok(await s.oidcGet("AccessToken", "k5", T0), "only that grant");
    await s.oidcDelete("RefreshToken", "k4");
    assert.equal(await s.oidcGet("RefreshToken", "k4", T0), null);
    await s.oidcSetExpiry("AccessToken", "k5", T0 + 1000);
    assert.equal(await s.oidcGet("AccessToken", "k5", T0 + 2000), null, "a moved expiry applies");
  });

  await test(`${name}: grants by account and client; counts skip expired artifacts`, async () => {
    const s = await make();
    await s.oidcPut("Grant", "g1", { accountId: "acc", clientId: "https://a.example/c.json", jti: "grant-1" }, T0 + 86400_000);
    await s.oidcPut("Grant", "g2", { accountId: "acc", clientId: "https://a.example/c.json", jti: "grant-2" }, T0 + 1000);
    await s.oidcPut("Grant", "g3", { accountId: "acc", clientId: "https://b.example/c.json", jti: "grant-3" }, T0 + 86400_000);
    await s.oidcPut("Grant", "g4", { accountId: "other", clientId: "https://a.example/c.json", jti: "grant-4" }, T0 + 86400_000);
    assert.deepEqual((await s.oidcGrantIds("acc", "https://a.example/c.json", T0)).sort(), ["grant-1", "grant-2"]);
    assert.deepEqual(await s.oidcGrantIds("acc", "https://a.example/c.json", T0 + 5000), ["grant-1"]);
    await s.oidcPut("Client", "c1", { client_id: "x" }, T0 + 1000);
    await s.oidcPut("Client", "c2", { client_id: "y" }, T0 + 100_000);
    assert.equal(await s.oidcCount("Client", T0), 2);
    assert.equal(await s.oidcCount("Client", T0 + 5000), 1, "an expired registration no longer counts");
  });

  await test(`${name}: consume keeps the first time; the overlapping refresh is spent exactly once, inside its interval`, async () => {
    const s = await make();
    const nowS = Math.floor(T0 / 1000);
    await s.oidcPut("RefreshToken", "rt", { grantId: "g", jti: "r" }, T0 + 3600_000);
    assert.equal(await s.oidcTakeReuse("RefreshToken", "rt", nowS, 30), false, "not consumed yet");
    await s.oidcConsume("RefreshToken", "rt", nowS);
    await s.oidcConsume("RefreshToken", "rt", nowS + 10);
    assert.equal((await s.oidcGet("RefreshToken", "rt", T0))?.["consumed"], nowS, "the first consumption time is kept");
    const both = await Promise.all([s.oidcTakeReuse("RefreshToken", "rt", nowS + 5, 30), s.oidcTakeReuse("RefreshToken", "rt", nowS + 5, 30)]);
    assert.deepEqual(both.sort(), [false, true], "two at once: exactly one gets the overlap");
    assert.equal(await s.oidcTakeReuse("RefreshToken", "rt", nowS + 6, 30), false, "spent");
    await s.oidcPut("RefreshToken", "rt2", { grantId: "g", jti: "r2" }, T0 + 3600_000);
    await s.oidcConsume("RefreshToken", "rt2", nowS);
    assert.equal(await s.oidcTakeReuse("RefreshToken", "rt2", nowS + 31, 30), false, "past the interval");
  });

  await test(`${name}: the oidc-provider adapter over the store: hashed keys, consume, refresh overlap, revoke by grant, registrations expire unused`, async () => {
    const s = await make();
    const rt = new StateAdapter(s, "RefreshToken");
    await rt.upsert("token-value-1", { grantId: "g9", jti: "token-value-1", accountId: "acc", kind: "RefreshToken" } as never, 3600);
    assert.equal(await s.oidcGet("RefreshToken", "token-value-1", Date.now()), null, "stored under the id's hash, not the id");
    assert.equal((await rt.find("token-value-1"))?.["grantId"], "g9");
    await rt.consume("token-value-1");
    const overlap = await rt.find("token-value-1");
    assert.equal(overlap?.["consumed"], undefined, "one overlapping use inside the interval");
    assert.equal(typeof (await rt.find("token-value-1"))?.["consumed"], "number", "then it reads as consumed (reuse)");
    await new StateAdapter(s, "RefreshToken").revokeByGrantId("g9");
    assert.equal(await rt.find("token-value-1"), undefined);
    const clients = new StateAdapter(s, "Client");
    await clients.upsert("https-client", { client_id: "https-client", redirect_uris: ["http://127.0.0.1/cb"] } as never);
    assert.equal((await clients.find("https-client"))?.["client_id"], "https-client");
    assert.equal(((await clients.find("https-client")) as Record<string, unknown> | undefined)?.["alp_touched"], undefined, "the touch mark never reaches oidc-provider");
    // (Probing the future last: the memory store drops what it sees expired.)
    assert.equal(await s.oidcCount("Client", Date.now() + 29 * 86400_000), 1, "a registration lives 30 days from its last use");
    assert.equal(await s.oidcCount("Client", Date.now() + 31 * 86400_000), 0, "and expires if it goes unused");
  });

  await test(`${name}: personal access tokens by id, by hash, by principal (newest first) and by delegate`, async () => {
    const s = await make();
    await s.putPat(pat("01JCP00000000000000000000A"));
    await s.putPat(pat("01JCP00000000000000000000B", { delegate: "alp:ana@example.org/other", label: "other" }));
    await s.putPat(pat("01JCP00000000000000000000C", { principal_id: "lee-principal-00001", delegate: "alp:lee@example.org/x" }));
    assert.equal((await s.findPatByHash("hash-01JCP00000000000000000000B"))?.id, "01JCP00000000000000000000B");
    assert.equal(await s.findPatByHash("hash-unknown"), null);
    assert.deepEqual((await s.listPats("ana-principal-00001")).map((p) => p.id.slice(-1)), ["B", "A"]);
    assert.deepEqual((await s.listPatsOfDelegate("alp:ana@example.org/muse")).map((p) => p.id.slice(-1)), ["A"]);
    const a = (await s.getPat("01JCP00000000000000000000A"))!;
    a.revoked_at = new Date(T0).toISOString();
    assert.equal((await s.getPat("01JCP00000000000000000000A"))?.revoked_at, undefined, "records are copies");
    await s.putPat(a);
    assert.equal((await s.getPat("01JCP00000000000000000000A"))?.revoked_at, new Date(T0).toISOString());
  });

  await test(`${name}: a token's use never undoes its revocation, and a revocation keeps its first time`, async () => {
    const s = await make();
    await s.putPat(pat("01JCP00000000000000000000D"));
    const t1 = new Date(T0 + 1000).toISOString();
    const t2 = new Date(T0 + 2000).toISOString();
    assert.equal(await s.touchPat("01JCP00000000000000000000D", t1), true, "a live token's use is noted");
    assert.equal((await s.getPat("01JCP00000000000000000000D"))?.last_used_at, t1);
    // A request read the token, then the person revoked it, then the request noted its use: the revocation stands.
    const readBefore = await s.findPatByHash("hash-01JCP00000000000000000000D");
    assert.equal((await s.revokePat("01JCP00000000000000000000D", t2))?.revoked_at, t2);
    assert.equal(readBefore?.revoked_at, undefined);
    assert.equal(await s.touchPat("01JCP00000000000000000000D", new Date(T0 + 3000).toISOString()), false, "the late use is refused");
    const after = await s.getPat("01JCP00000000000000000000D");
    assert.equal(after?.revoked_at, t2, "still revoked");
    assert.equal(after?.last_used_at, t1, "and the late use left nothing");
    assert.equal((await s.revokePat("01JCP00000000000000000000D", new Date(T0 + 4000).toISOString()))?.revoked_at, t2, "a second revocation keeps the first time");
    assert.equal(await s.revokePat("missing", t2), null);
    assert.equal(await s.touchPat("missing", t2), false);
  });

  await test(`${name}: an invite's sign-in never undoes its revocation`, async () => {
    const s = await make();
    const inv: InviteRecord = { id: "01JCI00000000000000000000Z", username: "kim", address: "alp:kim@preview.example", secret_hash: "scrypt$16384$8$1$AAAA$BBBB", created_at: new Date(T0).toISOString(), expires_at: new Date(T0 + 86400_000).toISOString() };
    await s.putInvite(inv);
    const t1 = new Date(T0 + 1000).toISOString();
    assert.equal(await s.touchInvite(inv.id, t1), true);
    assert.equal((await s.revokeInvite(inv.id, new Date(T0 + 2000).toISOString()))?.revoked_at, new Date(T0 + 2000).toISOString());
    assert.equal(await s.touchInvite(inv.id, new Date(T0 + 3000).toISOString()), false, "a sign-in that was checking the secret meanwhile is refused");
    const after = await s.getInvite(inv.id);
    assert.equal(after?.revoked_at, new Date(T0 + 2000).toISOString());
    assert.equal(after?.last_used_at, t1);
    assert.equal(after?.secret_hash, inv.secret_hash, "nothing else rewritten");
    assert.equal(await s.revokeInvite("missing", t1), null);
  });

  await test(`${name}: only a person's first passkey is stored, even when two registrations land at once`, async () => {
    const s = await make();
    const pk = (id: string, principal = "kim-principal-00001"): PasskeyRecord => ({ credential_id: id, principal_id: principal, public_key: `pk-${id}`, counter: 0, created_at: new Date(T0).toISOString() });
    const both = await Promise.all([s.addFirstPasskey(pk("cred-a")), s.addFirstPasskey(pk("cred-b"))]);
    assert.deepEqual(both.sort(), [false, true], "one of the two");
    assert.equal((await s.listPasskeys("kim-principal-00001")).length, 1);
    assert.equal(await s.addFirstPasskey(pk("cred-c")), false, "a later one isn't a first one");
    const kept = (await s.listPasskeys("kim-principal-00001"))[0]?.credential_id ?? "";
    assert.equal(await s.addFirstPasskey(pk(kept, "zoe-principal-00001")), false, "a credential id that exists isn't taken over");
    assert.equal(await s.addFirstPasskey(pk("cred-z", "zoe-principal-00001")), true, "another person's first");
  });

  await test(`${name}: held connection requests and send idempotency`, async () => {
    const s = await make();
    const p = (id: string, created: number): PendingConnection => ({ id, principal_id: "ana-principal-00001", principal: "alp:ana@example.org", delegate: "alp:ana@example.org/muse", client_id: "pat", to: "alp:lee@example.org", scopes: ["alp.briefing/1"], purpose: "work", state: "pending_principal", created_at: new Date(created).toISOString(), updated_at: new Date(created).toISOString(), expires_at: new Date(created + 86400_000).toISOString() });
    await s.putPending(p("01JCQ00000000000000000000A", T0));
    await s.putPending(p("01JCQ00000000000000000000B", T0 + 1000));
    assert.deepEqual((await s.listPending("ana-principal-00001")).map((x) => x.id.slice(-1)), ["B", "A"]);
    assert.equal((await s.getPending("01JCQ00000000000000000000A"))?.state, "pending_principal");
    assert.deepEqual(await s.listPending("someone-else-0000001"), []);
    await s.putIdempotency("idem", { at: T0, result: { ok: true, structured: { status: "delivered" }, text: "Sent." } });
    assert.deepEqual(await s.getIdempotency("idem"), { at: T0, result: { ok: true, structured: { status: "delivered" }, text: "Sent." } });
    assert.equal(await s.getIdempotency("nope"), null);
    // A claim replaces only the record its caller read: of two calls that read none, one claims the key.
    const claims = await Promise.all([s.swapIdempotency("claim", null, { at: T0, result: { sending: true } }), s.swapIdempotency("claim", null, { at: T0 + 1, result: { sending: true } })]);
    assert.deepEqual(claims.sort(), [false, true], "one of the two");
    const held = (await s.getIdempotency("claim"))!;
    assert.equal(await s.swapIdempotency("claim", held.at + 5, { at: T0 + 9, result: {} }), false, "not a record it read");
    assert.equal(await s.swapIdempotency("claim", held.at, { at: T0 + 2, result: { ok: true, structured: {}, text: "Sent." } }), true);
    assert.deepEqual(await s.getIdempotency("claim"), { at: T0 + 2, result: { ok: true, structured: {}, text: "Sent." } });
    assert.equal(await s.swapIdempotency("claim", T0 + 2, null), true, "removed");
    assert.equal(await s.getIdempotency("claim"), null);
    assert.equal(await s.swapIdempotency("claim", T0 + 2, null), false, "already gone");
  });

  await test(`${name}: web sessions, sign-out everywhere, and single-use challenges bound to one session`, async () => {
    const s = await make();
    await s.putWebSession(session("sess-a"));
    await s.putWebSession(session("sess-b"));
    await s.putWebSession(session("sess-c", { principal_id: "lee-principal-00001", principal: "alp:lee@example.org", username: "lee" }));
    assert.equal((await s.getWebSession("sess-a"))?.stage, "full");
    await s.putChallenge({ challenge: "challenge-for-a-0000000000000000", session_hash: "sess-a", purpose: "stepup", action: "/web/tokens", binding: "b", expires_at: Date.now() + 60_000 });
    assert.equal(await s.takeChallenge("sess-b", "challenge-for-a-0000000000000000", Date.now()), null, "another session can't take it");
    const both = await Promise.all([s.takeChallenge("sess-a", "challenge-for-a-0000000000000000", Date.now()), s.takeChallenge("sess-a", "challenge-for-a-0000000000000000", Date.now())]);
    assert.equal(both.filter((c) => c !== null).length, 1, "single use, even when taken twice at once");
    assert.equal(both.find((c) => c !== null)?.binding, "b");
    await s.putChallenge({ challenge: "expired-challenge-00000000000000", session_hash: "sess-a", purpose: "signin", expires_at: Date.now() - 1 });
    assert.equal(await s.takeChallenge("sess-a", "expired-challenge-00000000000000", Date.now()), null, "expired");
    await s.deleteWebSessionsOf("ana-principal-00001");
    assert.equal(await s.getWebSession("sess-a"), null);
    assert.equal(await s.getWebSession("sess-b"), null);
    assert.ok(await s.getWebSession("sess-c"), "another person's session stays");
    await s.deleteWebSession("sess-c");
    assert.equal(await s.getWebSession("sess-c"), null);
  });

  await test(`${name}: invites, passkeys (counters only move forward) and known devices`, async () => {
    const s = await make();
    const inv = (id: string, username: string): InviteRecord => ({ id, username, address: `alp:${username}@preview.example`, secret_hash: "scrypt$16384$8$1$AAAA$BBBB", created_at: new Date(T0).toISOString(), expires_at: new Date(T0 + 86400_000).toISOString() });
    await s.putInvite(inv("01JCI00000000000000000000A", "ana"));
    await s.putInvite(inv("01JCI00000000000000000000B", "lee"));
    await s.putInvite(inv("01JCI00000000000000000000C", "ana"));
    assert.deepEqual((await s.listInvites("ana")).map((i) => i.id.slice(-1)), ["A", "C"]);
    assert.equal((await s.listInvites()).length, 3);
    const a = (await s.getInvite("01JCI00000000000000000000A"))!;
    a.revoked_at = new Date(T0).toISOString();
    await s.putInvite(a);
    assert.equal((await s.getInvite("01JCI00000000000000000000A"))?.revoked_at, new Date(T0).toISOString());

    const pk: PasskeyRecord = { credential_id: "cred-1", principal_id: "ana-principal-00001", public_key: "pk", counter: 5, created_at: new Date(T0).toISOString() };
    await s.putPasskey(pk);
    await s.putPasskey({ ...pk, credential_id: "cred-0", counter: 0, created_at: new Date(T0 + 1).toISOString() });
    assert.deepEqual((await s.listPasskeys("ana-principal-00001")).map((p) => p.credential_id), ["cred-1", "cred-0"]);
    assert.equal(await s.usePasskey("cred-1", 5, new Date(T0).toISOString()), false, "a counter that doesn't move forward is refused (a cloned authenticator)");
    assert.equal(await s.usePasskey("cred-1", 6, new Date(T0).toISOString()), true);
    assert.equal((await s.getPasskey("cred-1"))?.counter, 6);
    assert.equal(await s.usePasskey("cred-0", 0, new Date(T0).toISOString()), true, "an authenticator without a counter keeps 0");
    assert.equal(await s.usePasskey("missing", 1, new Date(T0).toISOString()), false);

    assert.equal(await s.noteDevice("ana-principal-00001", "dev-1", new Date(T0).toISOString()), true, "new");
    assert.equal(await s.noteDevice("ana-principal-00001", "dev-1", new Date(T0 + 1000).toISOString()), false, "seen before");
    assert.equal(await s.noteDevice("lee-principal-00001", "dev-1", new Date(T0).toISOString()), true, "per person");
    const devices = await s.listDevices("ana-principal-00001");
    assert.equal(devices.length, 1);
    assert.equal(devices[0]?.last_seen, new Date(T0 + 1000).toISOString());
  });
}

await conformance("memory", async () => BindingState.memory());

const dirs: string[] = [];
process.on("exit", () => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});
await conformance("file", async () => {
  const d = mkdtempSync(join(tmpdir(), "alp-binding-"));
  dirs.push(d);
  return BindingState.file(d);
});

test("file binding store: a file written before raw token ids were dropped is cleaned as it loads", async () => {
  const d = mkdtempSync(join(tmpdir(), "alp-binding-"));
  dirs.push(d);
  const rt = "refresh-token-value-0000000000000000000009";
  const old = {
    version: 1,
    oidc: {
      RefreshToken: { [sha256b64u(rt)]: { payload: { grantId: "g", jti: rt, kind: "RefreshToken" }, expiresAt: Date.now() + 60_000 } },
      Interaction: { [sha256b64u("uid-9")]: { payload: { jti: "uid-9", session: { uid: "s9", cookie: "cookie-value-9" } }, expiresAt: Date.now() + 60_000 } },
      Grant: { [sha256b64u("grant-9")]: { payload: { jti: "grant-9", accountId: "acc", clientId: "c" }, expiresAt: Date.now() + 60_000 } },
    },
    pats: {},
    pending: {},
    idempotency: {},
  };
  writeFileSync(join(d, "binding.json"), JSON.stringify(old), { mode: 0o600 });
  const s = BindingState.file(d);
  const text = readFileSync(join(d, "binding.json"), "utf8");
  assert.ok(!text.includes(rt) && !text.includes("cookie-value-9"), "no refresh token or session cookie left in the file");
  assert.ok(text.includes("grant-9"), "grant ids stay");
  assert.equal(((await new StateAdapter(s, "RefreshToken").find(rt)) as Record<string, unknown> | undefined)?.["jti"], rt, "and lookups work as before");
});

test("file binding store: state survives a restart (sessions and challenges stay in memory)", async () => {
  const d = mkdtempSync(join(tmpdir(), "alp-binding-"));
  dirs.push(d);
  const a = BindingState.file(d);
  await a.putPat(pat("01JCP00000000000000000000A"));
  await a.oidcPut("Grant", "g", { accountId: "acc", clientId: "c", jti: "grant" }, Date.now() + 60_000);
  await a.putWebSession(session("sess"));
  const b = BindingState.file(d);
  assert.equal((await b.getPat("01JCP00000000000000000000A"))?.label, "muse");
  assert.deepEqual(await b.oidcGrantIds("acc", "c", Date.now()), ["grant"]);
  assert.equal(await b.getWebSession("sess"), null);
});

// Postgres: PGlite through the bridge (no server installed), or ALP_TEST_POSTGRES_URL.
const external = process.env["ALP_TEST_POSTGRES_URL"];
const bridge = external ? undefined : await startPgliteBridge();
const url = external ?? bridge?.url ?? "";
const stores: PostgresStore[] = [];
await conformance(external ? "postgres" : "postgres (PGlite)", async () => {
  const store = await createPostgresStore({ url, schema: `alp_binding_${process.pid}_${stores.length}`, max: 2 });
  stores.push(store);
  return new PostgresBindingStore(store.sql);
});
test("postgres: drop the test schemas", async () => {
  for (const [i, s] of stores.entries()) await s.sql.unsafe(`drop schema if exists alp_binding_${process.pid}_${i} cascade`);
  for (const s of stores) await s.close();
  await bridge?.close();
});
