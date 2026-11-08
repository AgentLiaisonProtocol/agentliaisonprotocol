// SPDX-License-Identifier: FSL-1.1-ALv2
// The security event stream (spec 11.8) under load and failure: an event the sink or the schema refuses is counted and
// said on stderr at most once a minute; a refusal a client can repeat at will (a bearer token that doesn't verify) is one
// event per reason and client per minute, plus one with the count of the rest.

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { LEE, buildWorld } from "../demo/world.ts";
import { startTestBroker } from "../mcp/testkit.ts";
import { EventFolder } from "./security-events.ts";
import type { SecurityEvent, SecurityEventSink } from "./security-events.ts";

test("a dropped security event is counted, and stderr says so at most once a minute", async () => {
  let fail = true;
  const kept: SecurityEvent[] = [];
  const sink: SecurityEventSink = {
    emit: async (e) => {
      if (fail) throw new Error("no space left on device");
      kept.push(e);
    },
  };
  const w = await buildWorld({ brokerOptions: { securityEvents: sink } });
  const lines: string[] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => void lines.push(args.map(String).join(" "));
  try {
    const kill = (): Promise<unknown> => w.example.send(w.ana.agent, { from: "lee@example.org", to: LEE, scope: "alp.briefing/1", type: "request", body: { topic: "x", depth: "headline" } });
    await kill();
    await kill();
    assert.equal(w.example.securityEventsDropped(), 2);
    assert.deepEqual(lines, ["1 security events dropped since start: no space left on device"], "one line, not one per event");
    w.clock.advance(61);
    await kill();
    assert.deepEqual(lines.slice(1), ["3 security events dropped since start: no space left on device"]);
    fail = false;
    await kill();
    assert.equal(w.example.securityEventsDropped(), 3, "an event the sink takes isn't counted");
    assert.equal(kept.length, 1);
  } finally {
    console.error = original;
  }
});

test("EventFolder: the first occurrence at once, the rest of the window as one count, and a flush writes what is pending", async () => {
  const out: (number | undefined)[] = [];
  const f = new EventFolder(40);
  for (let i = 0; i < 5; i++) f.note("a", (n) => out.push(n));
  f.note("b", (n) => out.push(n === undefined ? -1 : n));
  assert.deepEqual(out, [undefined, -1], "one event for each key at once");
  await new Promise((done) => setTimeout(done, 80));
  assert.deepEqual(out, [undefined, -1, 4], "the window's other four as one count; b had no others");
  f.note("a", (n) => out.push(n));
  f.note("a", (n) => out.push(n));
  f.flush();
  assert.deepEqual(out, [undefined, -1, 4, undefined, 1]);
});

test("500 requests with tokens that don't verify write two token_refused events, not 500", async () => {
  const t = await startTestBroker();
  try {
    for (let i = 0; i < 500; i++) {
      const res = await fetch(`${t.base}/rest/alp_whoami`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer alpat_${randomBytes(32).toString("base64url")}` }, body: "{}" });
      assert.equal(res.status, 401);
      await res.arrayBuffer();
    }
    const first = t.events.events.filter((e) => e.detail.event === "token_refused");
    assert.equal(first.length, 1, "the first is written at once");
    assert.equal(first[0]?.detail.count, undefined);
  } finally {
    await t.close();
  }
  const all = t.events.events.filter((e) => e.detail.event === "token_refused");
  assert.equal(all.length, 2, "stopping writes the folded rest");
  assert.equal(all[1]?.detail.count, 499);
  assert.equal(all[1]?.message, "unknown personal access token");
  assert.equal(all[1]?.detail.client_id, "pat");
});
