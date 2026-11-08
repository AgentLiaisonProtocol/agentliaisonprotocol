// SPDX-License-Identifier: FSL-1.1-ALv2
// Message rate limits (spec 6.6 S5, 6.7 step 8): between one person's own agents (spec 6.14) each directed pair of
// agents has its own bucket (default 600 an hour), apart from the person's limits with other people (default 120 an
// hour per counterparty, shared by all the person's agents); every rate_limited refusal says how long to wait. Run on
// the memory store and on the Postgres store (PGlite, or ALP_TEST_POSTGRES_URL).

import assert from "node:assert/strict";
import { after, test } from "node:test";
import { ANA, CLIENTS, IDS, buildWorld } from "../demo/world.ts";
import type { World } from "../demo/world.ts";
import { rateLimitEnv, rateLimitsFromEnv } from "../limits-env.ts";
import { runTool } from "../mcp/handlers.ts";
import type { ToolContext } from "../mcp/handlers.ts";
import { toolCatalog } from "../mcp/tools.ts";
import { BindingState } from "../oauth/state.ts";
import { MemoryStore } from "../storage/memory.ts";
import { startPgliteBridge } from "../storage/pglite-bridge.ts";
import { createPostgresStore } from "../storage/postgres.ts";
import type { PostgresStore } from "../storage/postgres.ts";
import type { SendResult } from "./api.ts";
import { secondsUntilOldestLeaves } from "./interfaces.ts";
import type { Store } from "./interfaces.ts";
import type { DelegateCaller } from "./types.ts";
import { DEFAULT_LIMITS } from "./broker.ts";
import { MemoryWindows } from "./windows.ts";

const LIMITS = { ownAgentRateLimit: { count: 2, per_seconds: 3600 }, defaultRateLimit: { count: 3, per_seconds: 3600 } };
const WINDOW = { start: "2026-11-10T09:00:00Z", end: "2026-11-10T17:00:00Z" };

function status(r: SendResult): string {
  return r.status === "rejected" ? `rejected:${r.code}` : r.status;
}

async function scenario(w: World): Promise<void> {
  const caller = async (label: string): Promise<DelegateCaller> => {
    const d = await w.example.registerDelegate({ principal: ANA, label, kind: "bridged", client_id: CLIENTS.connector });
    return { kind: "delegate", principal: ANA, delegate: d.id, client_id: CLIENTS.connector };
  };
  const muse = w.ana.agent;
  const helper = await caller("helper");
  const third = await caller("third");
  const toOwn = (from: DelegateCaller, to: string): Promise<SendResult> => w.example.send(from, { to: "ana@example.org", to_delegate: `${ANA}/${to}`, scope: "alp.availability/1", type: "request", body: { window: WINDOW, duration_minutes: 30 } });
  const toLee = (from: DelegateCaller): Promise<SendResult> => w.example.send(from, { to: "lee@example.org", scope: "alp.availability/1", type: "request", body: { window: WINDOW, duration_minutes: 30 } });

  // muse → helper: the pair's own limit (2 here).
  assert.deepEqual([status(await toOwn(muse, "helper")), status(await toOwn(muse, "helper"))], ["delivered", "delivered"]);
  w.clock.advance(600);
  const third_ = await toOwn(muse, "helper");
  assert.equal(third_.status, "rejected");
  if (third_.status !== "rejected") return;
  assert.equal(third_.code, "rate_limited");
  assert.equal(third_.retry_after, 3000, "until the first of the two leaves the hour");
  assert.equal(third_.reasons[0]?.detail, "too many messages from your agent muse to your agent helper; retry after 3000 seconds");

  // The reverse direction and a third agent have buckets of their own.
  assert.equal(status(await toOwn(helper, "muse")), "delivered");
  assert.equal(status(await toOwn(third, "helper")), "delivered");

  // Between people nothing changed: one bucket per counterparty, shared by every agent of Ana's (3 here), and the
  // messages between her own agents didn't count toward it.
  assert.deepEqual([status(await toLee(muse)), status(await toLee(helper)), status(await toLee(third))], ["delivered", "delivered", "delivered"]);
  const over = await toLee(muse);
  assert.equal(status(over), "rejected:rate_limited");
  if (over.status === "rejected") {
    assert.equal(over.retry_after, 3600);
    assert.equal(over.reasons[0]?.detail, "too many messages to lee@example.org; retry after 3600 seconds");
  }

  // The client binding: retry_after in the structured error, the advice in the message.
  const ana = (await w.example.getPrincipal(ANA))!;
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const o = await runTool(ctx, { caller: muse, principal_id: ana.principal_id, scopes: ["read", "send"], via: "oauth", resource: "mcp" }, "alp_send", { to: "ana@example.org", to_delegate: "helper", scope: "alp.availability/1", type: "request", body: { window: WINDOW, duration_minutes: 30 } });
  assert.equal(o.ok, false);
  const err = (o.ok ? {} : o.structured?.["error"]) as Record<string, unknown>;
  assert.equal(err["code"], "rate_limited");
  assert.equal(err["retry_after"], 3000);
  assert.equal(err["message"], "too many messages from your agent muse to your agent helper; retry after 3000 seconds. Wait at least retry_after seconds, then send it again, with a new idempotency_key if you set one (the same key returns this answer for 24 hours).");
  assert.deepEqual(toolCatalog().validateOutput("alp_send", o.ok ? {} : o.structured), []);
  assert.ok(w.events.events.some((e) => e.detail.event === "rate_limited"));
  assert.equal((await w.example.inbox(w.lee.agent)).items.length, 3, "Lee got the three that were allowed");
}

test("memory store: each pair of one person's own agents has its own bucket; between people it is unchanged", async () => {
  await scenario(await buildWorld({ domainDocs: false, brokerOptions: { limits: LIMITS } }));
});

const external = process.env["ALP_TEST_POSTGRES_URL"];
const bridge = external ? undefined : await startPgliteBridge();
let pg: PostgresStore | undefined;
const schema = `alp_rates_${process.pid}`;
after(async () => {
  await pg?.sql.unsafe(`drop schema if exists ${schema} cascade`);
  await pg?.close();
  await bridge?.close();
});

test("Postgres store (PGlite unless ALP_TEST_POSTGRES_URL): the same buckets", async () => {
  pg = await createPostgresStore({ url: external ?? bridge?.url ?? "", schema, max: 2 });
  const store: Store = pg;
  await scenario(await buildWorld({ domainDocs: false, brokerOptions: { limits: LIMITS }, storeFor: (id) => (id === IDS.example ? store : new MemoryStore()) }));
});

test("the defaults: 120 an hour between two people, 600 an hour per pair of one person's own agents; the windows say how long to wait", async () => {
  assert.deepEqual(DEFAULT_LIMITS.defaultRateLimit, { count: 120, per_seconds: 3600 });
  assert.deepEqual(DEFAULT_LIMITS.ownAgentRateLimit, { count: 600, per_seconds: 3600 });
  const w = new MemoryWindows();
  const t0 = new Date("2026-11-09T14:00:00.000Z");
  await w.hitRateLimit("k", t0, 60, 1);
  assert.deepEqual(await w.hitRateLimit("k", new Date(t0.getTime() + 20_000), 60, 1), { allowed: false, count: 1, retryAfter: 40 });
});

test("ALP_DEFAULT_RATE_LIMIT and ALP_OWN_AGENT_RATE_LIMIT: count/seconds, refused when malformed", () => {
  assert.deepEqual(rateLimitsFromEnv({}), {});
  assert.deepEqual(rateLimitsFromEnv({ ALP_DEFAULT_RATE_LIMIT: "240/3600", ALP_OWN_AGENT_RATE_LIMIT: " 1000 / 3600 " }), { defaultRateLimit: { count: 240, per_seconds: 3600 }, ownAgentRateLimit: { count: 1000, per_seconds: 3600 } });
  for (const bad of ["600", "0/3600", "600/0", "600 per hour", "-1/60", "1.5/60", "1/9999999", "100001/3600", "1000000/86400"]) assert.throws(() => rateLimitEnv("ALP_OWN_AGENT_RATE_LIMIT", { ALP_OWN_AGENT_RATE_LIMIT: bad }), /ALP_OWN_AGENT_RATE_LIMIT must be count\/seconds/, bad);
  assert.deepEqual(rateLimitEnv("ALP_DEFAULT_RATE_LIMIT", { ALP_DEFAULT_RATE_LIMIT: "100000/86400" }), { count: 100_000, per_seconds: 86400 }, "the largest count");
});

test("a full window of hundreds of thousands of hits still says how long to wait (no argument spread)", () => {
  const t0 = Date.parse("2026-11-09T14:00:00.000Z");
  const hits = Array.from({ length: 300_000 }, (_, i) => t0 + i);
  assert.equal(secondsUntilOldestLeaves(hits, t0 + 300_000, 3600), 3300);
  assert.equal(secondsUntilOldestLeaves([...hits].reverse(), t0 + 300_000, 3600), 3300, "in any order");
  assert.equal(secondsUntilOldestLeaves([], t0, 3600), 0);
});

test("connection requests: the broker's 20 a day and the client binding's 5 held a day each say how long to wait", async () => {
  const w = await buildWorld({ domainDocs: false });
  // The broker's own limit on a person's outgoing requests (spec 6.2): addresses on its own domain that nobody holds
  // are answered like any other.
  for (let i = 0; i < DEFAULT_LIMITS.outgoingConnectionRequestsPerDay; i++) {
    const r = await w.example.requestConnection(w.ana.human(), { to: `nobody${i}@example.org`, scopes: ["alp.briefing/1"], purpose: "work_request" });
    assert.equal(r.status, "requested", `request ${i + 1}`);
  }
  w.clock.advance(3600);
  const over = await w.example.requestConnection(w.ana.human(), { to: "nobody-else@example.org", scopes: ["alp.briefing/1"], purpose: "work_request" });
  assert.equal(over.status, "rejected");
  if (over.status === "rejected") {
    assert.equal(over.code, "rate_limited");
    assert.equal(over.retry_after, 82800, "until the first of the day's requests is a day old");
    assert.deepEqual(over.reasons, [{ code: "rate_limited", detail: "too many connection requests today; retry after 82800 seconds" }]);
  }

  // alp_request_connection holds at most five a day for the person's approval; the sixth says when the oldest is a day old.
  const ana = (await w.example.getPrincipal(ANA))!;
  const ctx: ToolContext = { broker: w.example, state: BindingState.memory(), catalog: toolCatalog(), policies: () => [], notifier: w.notifier, now: () => w.clock.now(), log: () => undefined };
  const ask = (to: string) => runTool(ctx, { caller: w.ana.agent, principal_id: ana.principal_id, scopes: ["read", "send"], via: "oauth", resource: "mcp" }, "alp_request_connection", { to, scopes: ["alp.briefing/1"], purpose: "briefing" });
  for (let i = 0; i < 5; i++) {
    const o = await ask(`held${i}@partner.example`);
    assert.equal(o.ok && o.structured["status"], "pending_principal", o.text);
    w.clock.advance(60);
  }
  const sixth = await ask("held5@partner.example");
  assert.equal(sixth.ok, false);
  const err = (sixth.ok ? {} : sixth.structured?.["error"]) as Record<string, unknown>;
  assert.equal(err["code"], "rate_limited");
  assert.equal(err["retry_after"], 86400 - 300, "the first of the five was filed five minutes earlier");
  assert.equal(err["message"], "your person already has 5 connection requests from today waiting; retry after 86100 seconds. Wait at least retry_after seconds before asking again.", "alp_request_connection takes no idempotency_key");
  assert.deepEqual(toolCatalog().validateOutput("alp_request_connection", sixth.ok ? {} : sixth.structured), []);
});
