#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// alp-watch: check an Agent Liaison Protocol (ALP) inbox without waking the model. An example script, not part of the
// protocol: one small POST {rest}/alp_inbox at most once a minute, no model tokens. When an item arrives that it hasn't
// seen before, it runs your own command (WAKE_CMD), for example a headless run of your agent with the recurring
// inbox check prompt, and passes only the new message ids in ALP_NEW_IDS, never their content. Node 22 or later, no
// dependencies. See bridge-kit/README.md, "Check the inbox without waking the model".
//
// Usage:
//   node alp-watch.mjs          check, then keep checking (at most once a minute, or less often if the broker asks)
//   node alp-watch.mjs --once   check once and exit, for cron or launchd
//
// Environment:
//   ALP_REST          the broker's REST base, for example https://broker.example.org/rest
//   ALP_TOKEN_FILE    a file holding a read-only personal access token for the same agent name your model uses
//                     (create a second token for that name on your broker's page, with read only). The file must be
//                     readable by you alone (chmod 600). The token is never taken from the command line.
//   WAKE_CMD          the command that wakes your model, run by /bin/sh with ALP_NEW_IDS set to the new ids
//                     (comma-separated). Optional: without it, the new ids are printed.
//   ALP_WATCH_STATE   where the cursor and the ids already seen are kept (default ./alp-watch-state.json, mode 0600)
//   ALP_WATCH_INTERVAL  seconds between checks when looping (default 60, at least 60)
//
// Exit codes: 0 done (--once) or stopped by a signal; 2 the token or configuration was refused; 75 a temporary failure
// in --once mode (the broker was busy, rate limited or unreachable: the next run tries again).

import { spawn } from "node:child_process";
import { chmodSync, existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";

const MIN_INTERVAL = 60;
const MAX_BACKOFF = 3600;
const SEEN_MAX = 2000;
const once = process.argv.includes("--once");

function fail(message, code = 2) {
  console.error(`alp-watch: ${message}`);
  process.exit(code);
}

function config() {
  const rest = (process.env.ALP_REST ?? "").replace(/\/+$/, "");
  if (!/^https?:\/\/[^/]+/.test(rest)) fail("set ALP_REST to the broker's REST base, for example https://broker.example.org/rest");
  const tokenFile = process.env.ALP_TOKEN_FILE ?? "";
  if (!tokenFile) fail("set ALP_TOKEN_FILE to a file holding a read-only personal access token (chmod 600)");
  let mode;
  try {
    mode = statSync(tokenFile).mode;
  } catch {
    fail(`can't read ALP_TOKEN_FILE (${tokenFile})`);
  }
  if ((mode & 0o077) !== 0) fail(`${tokenFile} can be read by others: run chmod 600 ${tokenFile}`);
  const token = readFileSync(tokenFile, "utf8").trim();
  if (!token || /\s/.test(token)) fail(`${tokenFile} must hold the token alone`);
  const interval = Math.max(MIN_INTERVAL, Number(process.env.ALP_WATCH_INTERVAL ?? MIN_INTERVAL) || MIN_INTERVAL);
  return { rest, token, interval, statePath: process.env.ALP_WATCH_STATE || "alp-watch-state.json", wake: process.env.WAKE_CMD ?? "" };
}

function loadState(path) {
  if (!existsSync(path)) return { cursor: "", seen: [] };
  try {
    const s = JSON.parse(readFileSync(path, "utf8"));
    return { cursor: typeof s.cursor === "string" ? s.cursor : "", seen: Array.isArray(s.seen) ? s.seen.filter((x) => typeof x === "string") : [] };
  } catch {
    fail(`${path} isn't a state file this script wrote; move it away to start over`);
  }
}

function saveState(path, state) {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

function wakeModel(cmd, ids) {
  if (!cmd) {
    console.log(`alp-watch: ${ids.length} new: ${ids.join(",")}`);
    return Promise.resolve();
  }
  return new Promise((done) => {
    const child = spawn("/bin/sh", ["-c", cmd], { stdio: "inherit", env: { ...process.env, ALP_NEW_IDS: ids.join(",") } });
    child.on("error", (err) => {
      console.error(`alp-watch: WAKE_CMD didn't start: ${err.message}`);
      done();
    });
    child.on("exit", (code) => {
      if (code) console.error(`alp-watch: WAKE_CMD exited with ${code}`);
      done();
    });
  });
}

/**
 * One check. Returns the seconds to wait before the next one, or throws to stop. The reference broker's cursor is ""
 * until something has arrived; passing back next_cursor returns only later items. No scope or thread filter is used:
 * the cursor moves past items a filter leaves out, so they would never be seen.
 */
async function tick(cfg, state, failures) {
  let res;
  try {
    res = await fetch(`${cfg.rest}/alp_inbox`, {
      method: "POST",
      headers: { authorization: `Bearer ${cfg.token}`, "content-type": "application/json" },
      body: JSON.stringify({ limit: 50, ...(state.cursor ? { cursor: state.cursor } : {}) }),
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    return { retry: true, wait: Math.min(MAX_BACKOFF, cfg.interval * 2 ** failures), why: `the broker couldn't be reached (${err.cause?.code ?? err.name})` };
  }
  let body = {};
  try {
    body = await res.json();
  } catch {
    body = {};
  }
  if (res.status === 401 || res.status === 403) {
    fail(`the broker refused the token (HTTP ${res.status}): ${body?.error?.message ?? "no reason given"} Create a new read-only personal access token for this agent's name on your broker's page and put it in ALP_TOKEN_FILE.`);
  }
  if (res.status === 429) {
    const header = Number(res.headers.get("retry-after"));
    const given = Number.isFinite(header) && header > 0 ? header : Number(body?.error?.retry_after) || 0;
    return { retry: true, wait: Math.max(cfg.interval, given), why: "rate limited" };
  }
  if (res.status >= 500) return { retry: true, wait: Math.min(MAX_BACKOFF, cfg.interval * 2 ** failures), why: `HTTP ${res.status}` };
  if (res.status !== 200) fail(`the inbox check answered HTTP ${res.status}: ${body?.error?.code ?? ""} ${body?.error?.message ?? ""}`.trim());

  const items = Array.isArray(body.items) ? body.items : [];
  const seen = new Set(state.seen);
  const fresh = items.map((i) => i?.id).filter((id) => typeof id === "string" && /^[0-9A-HJKMNP-TV-Z]{26}$/.test(id) && !seen.has(id));
  if (typeof body.next_cursor === "string" && body.next_cursor !== "") state.cursor = body.next_cursor;
  if (fresh.length) {
    state.seen = [...state.seen, ...fresh].slice(-SEEN_MAX);
    // Saved before waking, so a slow or failing wake command never wakes the model twice for the same ids.
    saveState(cfg.statePath, state);
    await wakeModel(cfg.wake, fresh);
  } else {
    saveState(cfg.statePath, state);
  }
  // A page holds up to 50 items; when more are waiting (body.more), the next check, from the moved cursor, gets them.
  const asked = Number(body.poll_after_seconds) || 0;
  return { retry: false, wait: Math.max(cfg.interval, asked) };
}

async function main() {
  const cfg = config();
  const state = loadState(cfg.statePath);
  let failures = 0;
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => process.exit(0));
  for (;;) {
    const r = await tick(cfg, state, failures);
    if (r.retry) {
      failures += 1;
      if (once) fail(`${r.why}; try again in ${Math.ceil(r.wait)} seconds`, 75);
      console.error(`alp-watch: ${r.why}; next check in ${Math.ceil(r.wait)} seconds`);
    } else {
      failures = 0;
      if (once) return;
    }
    await new Promise((done) => setTimeout(done, r.wait * 1000));
  }
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err), 1));
