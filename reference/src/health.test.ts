// SPDX-License-Identifier: FSL-1.1-ALv2
// The public listener's health checks (SELF-HOST.md, Dockerfile HEALTHCHECK): /healthz while the process serves, with
// the count of dropped security events; /readyz when a cheap read of the broker's store answers, 503 when it fails.
// Nothing else in either body.

import assert from "node:assert/strict";
import { test } from "node:test";
import { startTestBroker } from "./mcp/testkit.ts";

test("/healthz and /readyz answer on the public listener with nothing but their status", async () => {
  const t = await startTestBroker();
  try {
    const health = await fetch(`${t.base}/healthz`);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get("cache-control"), "no-store");
    assert.deepEqual(await health.json(), { status: "ok", security_events_dropped: 0 });
    const ready = await fetch(`${t.base}/readyz`);
    assert.equal(ready.status, 200);
    assert.deepEqual(await ready.json(), { status: "ready" });

    // The store stops answering: not ready, and the body says no more than that.
    const store = t.dev.store as { getPrincipalById: (id: string) => Promise<unknown> };
    const original = store.getPrincipalById.bind(store);
    store.getPrincipalById = async () => {
      throw new Error("connection to the database refused: secret details");
    };
    const down = await fetch(`${t.base}/readyz`);
    assert.equal(down.status, 503);
    assert.deepEqual(await down.json(), { status: "unavailable" });
    assert.equal((await fetch(`${t.base}/healthz`)).status, 200, "the process still serves");
    store.getPrincipalById = original;
    assert.equal((await fetch(`${t.web}/healthz`)).status, 404, "the web view's listener has no health route");
  } finally {
    await t.close();
  }
});
