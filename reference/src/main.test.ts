// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm start`'s checks before it listens (src/main.ts), run as the operator would run it: a configuration whose `id`
// isn't https is refused with the ways to evaluate on one machine; a test identity's secret under 12 characters, or
// ALP_DEV_LOGIN_SECRETS that isn't a JSON object, is refused without printing it; Postgres without ALP_KEYRING_KEY and
// a policy's retention.ledger_days are warned about; ALP_SECURITY_EVENTS and ALP_TRUSTED_PROXY_HOPS out of range are
// refused; HOST 0.0.0.0 with no client-address header is warned about. None of these runs reaches the point of
// listening on a port. The last test starts it on loopback ports from the tests' pool: ALP_PID_FILE gets the node
// process's id, and SIGTERM ends with a `stopped` line. The first checks that the policy these runs use,
// policy.eval.json, is still the example policy plus `pat` and the script client, as SELF-HOST.md says.

import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";
import { onFreePorts } from "./test-ports.ts";

const MAIN = fileURLToPath(new URL("./main.ts", import.meta.url));
const DEPLOY = fileURLToPath(new URL("../deploy/", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "alp-main-"));
after(() => rmSync(dir, { recursive: true, force: true }));

function config(overrides: Record<string, unknown> = {}): string {
  copyFileSync(join(DEPLOY, "policy.eval.json"), join(dir, "policy.eval.json"));
  const c = { ...(JSON.parse(readFileSync(join(DEPLOY, "config.example.json"), "utf8")) as Record<string, unknown>), policies: ["policy.eval.json"], ...overrides };
  const path = join(dir, `config-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(path, JSON.stringify(c));
  return path;
}

function start(configPath: string, env: Record<string, string> = {}): Promise<{ code: number; stderr: string; stdout: string }> {
  return new Promise((done) => {
    execFile(process.execPath, [MAIN], { env: { PATH: process.env["PATH"] ?? "", ALP_CONFIG: configPath, ALP_DATA_DIR: join(dir, "data"), PORT: "1", WEB_PORT: "2", ...env }, timeout: 30_000 }, (err, stdout, stderr) =>
      done({ code: err ? Number((err as { code?: unknown }).code ?? 1) : 0, stdout, stderr }));
  });
}

test("policy.eval.json is the example policy plus `pat` and the script client in its list of agents, under its own id (SELF-HOST.md)", () => {
  const example = JSON.parse(readFileSync(join(DEPLOY, "policy.example.json"), "utf8")) as { id: string; clients: { allowed: { client_id: string }[] } };
  const evaluation = JSON.parse(readFileSync(join(DEPLOY, "policy.eval.json"), "utf8")) as { id: string; clients: { allowed: { client_id: string }[] } };
  const added = evaluation.clients.allowed.filter((c) => !example.clients.allowed.some((e) => e.client_id === c.client_id)).map((c) => c.client_id);
  assert.deepEqual(added, ["pat", "eval-script"]);
  assert.notEqual(evaluation.id, example.id, "its own id");
  const rest = { ...evaluation, id: example.id, clients: { ...evaluation.clients, allowed: evaluation.clients.allowed.filter((c) => !added.includes(c.client_id)) } };
  assert.deepEqual(rest, example, "everything else, default relationships included, is the example policy's");
});

test("an `id` that isn't https is refused, naming the field and the two ways to evaluate on one machine", async () => {
  const r = await start(config({ id: "http://127.0.0.1:8080" }));
  assert.equal(r.code, 1);
  assert.match(r.stderr, /the configuration's `id` must be the broker's https origin/);
  assert.match(r.stderr, /keep an https id and call the loopback listener over the REST mirror with a personal access token/);
  assert.match(r.stderr, /put a TLS proxy in front of the broker/);
  assert.doesNotMatch(r.stderr, /PUBLIC_URL/);
});

test("a test identity's secret under 12 characters, or ALP_DEV_LOGIN_SECRETS that isn't a JSON object, is refused without printing it", async () => {
  const short = await start(config(), { ALP_DEV_LOGIN_SECRETS: JSON.stringify({ ana: "SHORT-xyz", lee: "a-long-enough-secret" }) });
  assert.equal(short.code, 1);
  assert.match(short.stderr, /ALP_DEV_LOGIN_SECRETS: the secret for ana must be a string of at least 12 characters/);
  assert.ok(!short.stderr.includes("SHORT-xyz") && !short.stdout.includes("SHORT-xyz"));
  const broken = await start(config(), { ALP_DEV_LOGIN_SECRETS: '{"ana": "SECRET-VALUE-0001", lee' });
  assert.equal(broken.code, 1);
  assert.match(broken.stderr, /ALP_DEV_LOGIN_SECRETS must be a JSON object of one secret per test identity/);
  assert.ok(!broken.stderr.includes("SECRET-VALUE-0001"), "a JSON error never echoes the value");
});

test("Postgres without ALP_KEYRING_KEY, and a policy's retention.ledger_days, are warned about before anything connects", async () => {
  // Nothing listens on 127.0.0.1:1: the run stops at connecting, after the warnings.
  const r = await start(config(), { DATABASE_URL: "postgres://alp@127.0.0.1:1/alp" });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /DATABASE_URL is set without ALP_KEYRING_KEY: the broker's signing keys are stored unsealed in the database/);
  assert.match(r.stderr, /sets retention\.ledger_days \(365\): the broker records it but doesn't enforce it yet, and purges nothing/);
});

test("ALP_SECURITY_EVENTS and ALP_TRUSTED_PROXY_HOPS out of range are refused, naming what they take", async () => {
  const events = await start(config(), { ALP_SECURITY_EVENTS: "syslog" });
  assert.equal(events.code, 1);
  assert.match(events.stderr, /ALP_SECURITY_EVENTS must be file \(security-events\.jsonl in ALP_DATA_DIR, the default\) or stdout/);
  for (const hops of ["0", "11", "two", "1.5"]) {
    const r = await start(config(), { ALP_TRUSTED_PROXY_HOPS: hops });
    assert.equal(r.code, 1, hops);
    assert.match(r.stderr, /ALP_TRUSTED_PROXY_HOPS must be 1 to 10: the number of proxies in front that append to ALP_CLIENT_IP_HEADER/, hops);
  }
});

test("HOST 0.0.0.0 with neither ALP_CLIENT_IP_HEADER nor ALP_BEHIND_CLOUDFLARE is warned about; with a header it isn't", async () => {
  // An access-token lifetime out of range stops each run right after the check, before anything listens (and port 0,
  // which `npm start` refuses, would stop it before listening too).
  const never = { HOST: "0.0.0.0", ALP_ACCESS_TOKEN_TTL: "5", PORT: "0", WEB_PORT: "0" };
  const bare = await start(config(), never);
  assert.equal(bare.code, 1);
  assert.match(bare.stderr, /warning: HOST is 0\.0\.0\.0 and neither ALP_CLIENT_IP_HEADER nor ALP_BEHIND_CLOUDFLARE is set\. Behind a proxy, every request comes from the proxy's address/);
  assert.match(bare.stderr, /ALP_ACCESS_TOKEN_TTL must be 60 to 900 seconds/);
  const quiet: Record<string, string>[] = [{ ALP_CLIENT_IP_HEADER: "x-real-ip" }, { ALP_BEHIND_CLOUDFLARE: "1" }];
  for (const env of quiet) {
    const r = await start(config(), { ...never, ...env });
    assert.match(r.stderr, /ALP_ACCESS_TOKEN_TTL must be 60 to 900 seconds/);
    assert.doesNotMatch(r.stderr, /warning: HOST is 0\.0\.0\.0/, JSON.stringify(env));
  }
});

test("ALP_PID_FILE gets the node process's id once it listens (on loopback), and SIGTERM ends with a stopped line", async () => {
  const pidFile = join(dir, "broker.pid");
  const run = await onFreePorts(2, async ([port = 0, webPort = 0]) => {
    rmSync(pidFile, { force: true });
    const child = spawn(process.execPath, [MAIN], { env: { PATH: process.env["PATH"] ?? "", ALP_CONFIG: config(), ALP_DATA_DIR: join(dir, "pid-data"), PORT: String(port), WEB_PORT: String(webPort), ALP_PID_FILE: pidFile }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr.on("data", (d: Buffer) => (out += d.toString()));
    let exited = false;
    child.on("exit", () => (exited = true));
    for (let i = 0; i < 300 && !exited && !existsSync(pidFile); i++) await sleep(50);
    if (!existsSync(pidFile)) {
      child.kill("SIGKILL");
      // Another test process took a port first: onFreePorts tries new ones.
      throw new Error(/EADDRINUSE/.test(out) ? "EADDRINUSE" : `the broker didn't start: ${out.slice(-500)}`);
    }
    return { child, output: () => out, exited: () => exited };
  });
  try {
    assert.equal(readFileSync(pidFile, "utf8"), `${run.child.pid}\n`);
    run.child.kill("SIGTERM");
    for (let i = 0; i < 300 && !run.exited(); i++) await sleep(50);
    assert.ok(run.exited(), "SIGTERM stopped it");
    assert.match(run.output(), /^ {2}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z stopped$/m);
  } finally {
    if (!run.exited()) run.child.kill("SIGKILL");
  }
});
