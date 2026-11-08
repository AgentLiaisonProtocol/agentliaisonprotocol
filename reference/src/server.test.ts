// SPDX-License-Identifier: FSL-1.1-ALv2
// How a broker process stops (stopBroker): the work a broker does after answering finishes before its stores close.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { IDS, LEE, buildWorld } from "./demo/world.ts";
import { stopBroker } from "./server.ts";
import { FileStore } from "./storage/file.ts";
import { MemoryStore } from "./storage/memory.ts";

const brief = { topic: "Q4 launch readiness", depth: "summary" };

test("stopping right after an answer: the person's notice still goes out, and only then does the store close", async () => {
  const dir = mkdtempSync(join(tmpdir(), "alp-stop-"));
  try {
    const file = new FileStore(dir);
    const failures: unknown[] = [];
    const w = await buildWorld({ storeFor: (id) => (id === IDS.example ? file : new MemoryStore()), brokerOptions: { onBackgroundError: (err) => void failures.push(err) } });
    // Lee has no agent named nobody: the message waits for him, and he is told after Ana's broker has its answer.
    const r = await w.example.send(w.ana.agent, { to: LEE, to_delegate: `${LEE}/nobody`, scope: "alp.briefing/1", type: "request", body: brief });
    assert.equal(r.status, "delivered");
    // SIGTERM as soon as Ana's call has returned.
    const order: string[] = [];
    await stopBroker({ running: { close: async () => void order.push("listeners") }, broker: w.example, stores: [{ close: async () => {
      order.push("store");
      await file.close();
    } }] });
    assert.deepEqual(order, ["listeners", "store"]);
    assert.deepEqual(failures, [], "nothing ran against a closed store");
    assert.deepEqual(w.notifier.sent.filter((n) => n.principal === LEE).map((n) => n.kind), ["message_held"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("stopping never waits longer than its grace period for work that doesn't end", async () => {
  // Work handed out that never runs, as with a hung notifier.
  const w = await buildWorld({ brokerOptions: { background: () => undefined } });
  const r = await w.example.send(w.ana.agent, { to: LEE, to_delegate: `${LEE}/nobody`, scope: "alp.briefing/1", type: "request", body: brief });
  assert.equal(r.status, "delivered");
  let closed = false;
  const started = Date.now();
  await stopBroker({ running: { close: async () => undefined }, broker: w.example, stores: [{ close: async () => void (closed = true) }], graceMs: 50 });
  assert.equal(closed, true);
  assert.ok(Date.now() - started < 5000);
});
