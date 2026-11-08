// SPDX-License-Identifier: FSL-1.1-ALv2
// The bridge kit's example poller (bridge-kit/poller/alp-watch.mjs) against a running broker: it checks the REST inbox
// with a read-only personal access token for the same agent name the model uses, and wakes the model only for ids it
// hasn't seen, passing ids and never content.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { startTestBroker } from "./mcp/testkit.ts";
import type { TestBroker } from "./mcp/testkit.ts";
import { mintPat, revokePat } from "./oauth/pat.ts";
import { onFreePorts } from "./test-ports.ts";

const SCRIPT = fileURLToPath(new URL("../../bridge-kit/poller/alp-watch.mjs", import.meta.url));
let t: TestBroker;
let dir = "";
const tokens: Record<string, string> = {};
let watchRecord = "";

before(async () => {
  t = await onFreePorts(2, ([port, webPort]) => startTestBroker({ ...(port !== undefined ? { port } : {}), ...(webPort !== undefined ? { webPort } : {}) }));
  dir = mkdtempSync(join(tmpdir(), "alp-watch-"));
  const now = new Date();
  const lee = (await t.dev.broker.store.getPrincipal("alp:lee@example.org"))!;
  const ana = (await t.dev.broker.store.getPrincipal("alp:ana@example.org"))!;
  // Lee's model connects as the agent "model"; the poller holds a second, read-only token for the same name.
  tokens["model"] = (await mintPat({ broker: t.dev.broker, state: t.server.state, principal: lee, label: "model", scopes: ["read", "send"], days: 7, maxDays: 30, now })).token;
  const watch = await mintPat({ broker: t.dev.broker, state: t.server.state, principal: lee, label: "model", scopes: ["read"], days: 7, maxDays: 30, now });
  tokens["watch"] = watch.token;
  watchRecord = watch.record.id;
  tokens["ana"] = (await mintPat({ broker: t.dev.broker, state: t.server.state, principal: ana, label: "script", scopes: ["read", "send"], days: 7, maxDays: 30, now })).token;
  writeFileSync(join(dir, "token"), tokens["watch"] ?? "", { mode: 0o600 });
});
after(async () => {
  await t?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

function watchOnce(extra: Record<string, string> = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done) => {
    execFile(process.execPath, [SCRIPT, "--once"], {
      env: { PATH: process.env["PATH"] ?? "", ALP_REST: `${t.base}/rest`, ALP_TOKEN_FILE: join(dir, "token"), ALP_WATCH_STATE: join(dir, "state.json"), WAKE_CMD: `printf '%s\\n' "$ALP_NEW_IDS" >> '${join(dir, "woken")}'`, ...extra },
      timeout: 30_000,
    }, (err, stdout, stderr) => done({ code: err ? Number((err as { code?: unknown }).code ?? 1) : 0, stdout, stderr }));
  });
}

const woken = (): string[] => (existsSync(join(dir, "woken")) ? readFileSync(join(dir, "woken"), "utf8").split("\n").filter(Boolean) : []);

test("a quiet check wakes nothing; one new message wakes the model once, with its id only; the same message again wakes nothing", async () => {
  const quiet = await watchOnce();
  assert.equal(quiet.code, 0, quiet.stderr);
  assert.deepEqual(woken(), [], "nothing new, nothing woken");
  assert.equal(statSync(join(dir, "state.json")).mode & 0o777, 0o600, "the state file is the person's alone");
  assert.equal(JSON.parse(readFileSync(join(dir, "state.json"), "utf8")).cursor, "", "the cursor stays empty until something arrives");

  const sent = await fetch(`${t.base}/rest/alp_send`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tokens["ana"]}` }, body: JSON.stringify({ to: "lee@example.org", scope: "alp.briefing/1", type: "request", body: { topic: "Q4 SECRET-TOPIC", depth: "summary" } }) });
  assert.equal(sent.status, 200);
  const id = String(((await sent.json()) as Record<string, unknown>)["id"]);

  const first = await watchOnce();
  assert.equal(first.code, 0, first.stderr);
  assert.deepEqual(woken(), [id], "woken once, with the new id");
  assert.ok(!readFileSync(join(dir, "woken"), "utf8").includes("SECRET-TOPIC") && !readFileSync(join(dir, "state.json"), "utf8").includes("SECRET-TOPIC"), "ids only, never content");

  const again = await watchOnce();
  assert.equal(again.code, 0, again.stderr);
  assert.deepEqual(woken(), [id], "the same message doesn't wake it again");

  // The model reads the same inbox: the poller's token is the same agent's.
  const inbox = await fetch(`${t.base}/rest/alp_inbox`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tokens["model"]}` }, body: "{}" });
  assert.deepEqual((((await inbox.json()) as Record<string, unknown>)["items"] as { id: string }[]).map((i) => i.id), [id]);
});

test("a token file others can read is refused, and so, with a clear message, is a revoked token", async () => {
  chmodSync(join(dir, "token"), 0o644);
  const open = await watchOnce();
  assert.equal(open.code, 2);
  assert.match(open.stderr, /can be read by others: run chmod 600/);
  chmodSync(join(dir, "token"), 0o600);

  const lee = (await t.dev.broker.store.getPrincipal("alp:lee@example.org"))!;
  await revokePat(t.server.state, lee.principal_id, watchRecord, new Date());
  const refused = await watchOnce();
  assert.equal(refused.code, 2);
  assert.match(refused.stderr, /the broker refused the token \(HTTP 401\): the personal access token was revoked or has expired\. .*Create a new read-only personal access token/);
});
