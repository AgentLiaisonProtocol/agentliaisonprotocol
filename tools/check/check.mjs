#!/usr/bin/env node
// alp-check: checks part of what the Agent Liaison Protocol v0.1 requires at a broker's public surface, with no
// credentials. See README.md for what it sends and what it does not check. Licensed under Apache-2.0.
//
//   node tools/check/check.mjs example.org
//   node tools/check/check.mjs --broker https://broker.example.org --mcp <url> --rest <url> [--inbox <url> --jwks <url>]
import fs from "node:fs";
import dns from "node:dns";
import { fileURLToPath } from "node:url";
import { CHECKS, BY_ID, FAMILIES } from "./catalog.mjs";
import { createHttp, parseDevMap, excerpt } from "./http.mjs";
import { toJson, toText, summarise } from "./report.mjs";
import { documentEntries } from "./checks/document.mjs";
import * as documentFamily from "./checks/document.mjs";
import * as keysFamily from "./checks/keys.mjs";
import * as dnsFamily from "./checks/dns.mjs";
import * as signinFamily from "./checks/signin.mjs";
import * as bindingFamily from "./checks/binding.mjs";
import * as inboxFamily from "./checks/inbox.mjs";

const RUN_ORDER = [documentFamily, dnsFamily, keysFamily, signinFamily, bindingFamily, inboxFamily];
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const BROKER_ID = /^https:\/\/[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?$/;
const FIELD_CAP = 400;

export class UsageError extends Error {}

export const USAGE = `Usage:
  node tools/check/check.mjs <domain> [options]
  node tools/check/check.mjs --broker <https origin> [--mcp <url>] [--rest <url>] [--inbox <url>] [--jwks <url>] [options]

The first form checks a domain that federates: the domain document, the keys, the DNS hint, and every broker entry
the document names. The second checks a Local-profile broker that publishes no domain document.

Options:
  --json                 print the report as JSON
  --only <id or prefix>  run only these checks (repeatable), for example --only inbox or --only document.schema
  --timeout <seconds>    how long to wait for each answer (default 10, at most 60)
  --no-inbox-probes      send nothing to the inbox
  --dev-map '<json>'     development and CI only: map published https origins of reserved names to
                         http://127.0.0.1:<port> or http://[::1]:<port>, for example
                         '{"https://example.org":"http://127.0.0.1:8080"}'; TLS and DNS checks are then skipped,
                         never passed
  --help                 show this text

Exit codes: 0 when no required check failed and none was left undecided (skipped checks do not change it; the
report counts them); 1 when a required check failed; 2 for a usage error; 3 for an error of alp-check itself; 4 when
no required check failed but at least one could not be decided (a rate limit, a temporary failure, no usable answer).
0 means only that nothing this version checks from outside was found wrong.
It makes at most 80 requests, one at a time, and sends no credentials. See tools/check/README.md.`;

/** Parse command-line arguments into options. Throws UsageError. */
export function parseArgs(argv) {
  const o = { domain: null, broker: null, mcp: null, rest: null, inbox: null, jwks: null, json: false, only: [], timeout: 10, probes: true, devMap: null, help: false };
  const positional = [];
  const value = (i, name) => {
    if (i + 1 >= argv.length || argv[i + 1].startsWith("--")) throw new UsageError(`${name} needs a value`);
    return argv[i + 1];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--help": case "-h": o.help = true; break;
      case "--json": o.json = true; break;
      case "--no-inbox-probes": o.probes = false; break;
      case "--only": o.only.push(value(i, a)); i++; break;
      case "--timeout": {
        const v = value(i, a); i++;
        const n = Number(v);
        if (!Number.isFinite(n) || n <= 0 || n > 60) throw new UsageError("--timeout takes a number of seconds above 0 and at most 60");
        o.timeout = n;
        break;
      }
      case "--dev-map":
        try { o.devMap = parseDevMap(value(i, a)); } catch (e) { throw e instanceof UsageError ? e : new UsageError(e.message); }
        i++;
        break;
      case "--broker": case "--mcp": case "--rest": case "--inbox": case "--jwks":
        o[a.slice(2)] = value(i, a); i++; break;
      default:
        if (a.startsWith("-")) throw new UsageError(`unknown option ${a}`);
        positional.push(a);
    }
  }
  if (o.help) return o;
  if (positional.length > 1) throw new UsageError("give one domain");
  if (positional.length === 1) {
    if (o.broker || o.mcp || o.rest || o.inbox || o.jwks) throw new UsageError("give a domain, or --broker with its URLs, not both: a domain's broker URLs come from its document");
    const d = positional[0].toLowerCase().replace(/\.$/, "");
    if (!DOMAIN.test(d) || d.length > 253 || d.includes("..")) throw new UsageError(`${positional[0]} is not a domain name`);
    o.domain = d;
  } else if (o.broker) {
    if (!BROKER_ID.test(o.broker)) throw new UsageError("--broker takes the broker's https origin: scheme, lower-case host, optional port, no path");
    try { new URL(o.broker); } catch { throw new UsageError(`--broker ${o.broker} is not an origin a URL parser accepts (a port above 65535, or a numeric last label)`); }
    for (const k of ["mcp", "rest", "inbox", "jwks"]) {
      if (o[k] == null) continue;
      let u;
      try { u = new URL(o[k]); } catch { throw new UsageError(`--${k} is not a URL`); }
      if (u.protocol !== "https:") throw new UsageError(`--${k} must be an https URL`);
    }
    if (!o.mcp && !o.rest && !o.inbox && !o.jwks) throw new UsageError("with --broker, give at least one of --mcp, --rest, --inbox, --jwks");
  } else {
    throw new UsageError("give a domain, or --broker with its URLs");
  }
  for (const p of o.only) if (!CHECKS.some((c) => c.id.startsWith(p))) throw new UsageError(`--only ${p} matches no check`);
  return o;
}

const cap = (s) => (typeof s === "string" ? excerpt(s, FIELD_CAP) : s);

/**
 * Run the checks. `deps` lets tests replace the network: { fetch } (a function with the shape of fetch) or
 * { transport: { resolve, request } } (the node:https transport with a replaced resolver and request function),
 * and { resolveTxt, now }; `families` replaces the check families (tests only).
 * Returns { target, devMapOrigins, startedAt, results, requests, requestCount }.
 */
export async function runChecks(o, deps = {}) {
  const now = deps.now ?? (() => Date.now());
  const resolveTxt = deps.resolveTxt ?? ((name) => dns.promises.resolveTxt(name));
  const http = createHttp({ fetch: deps.fetch ?? null, transport: deps.transport ?? {}, timeoutMs: o.timeout * 1000, devMap: o.devMap });
  const memos = new Map();
  const results = [];
  const wants = (id) => o.only.length === 0 || o.only.some((p) => id.startsWith(p));

  if (o.domain) {
    const [l1, l2] = documentFamily.locations(o.domain);
    http.allowUrl(l1, "the domain's first well-known location");
    http.allowUrl(l2, "the domain's second well-known location");
  }
  // In --broker mode every URL was given by the person running the check, so each of their origins is allowed.
  const givenOrigins = o.domain ? [] : [...new Set([o.broker, o.mcp, o.rest, o.inbox, o.jwks].filter(Boolean).map((u) => new URL(u).origin))];
  for (const origin of givenOrigins) http.allowOrigin(origin, "a URL given on the command line");

  const ctx = {
    domain: o.domain,
    devMap: !!o.devMap,
    probes: o.probes,
    timeoutMs: o.timeout * 1000,
    http,
    resolveTxt,
    now,
    wants,
    idsOf: (family) => CHECKS.filter((c) => c.family === family).map((c) => c.id),
    memo(key, fn) {
      if (!memos.has(key)) memos.set(key, fn());
      return memos.get(key);
    },
    entries() {
      return ctx.memo("entries", async () => {
        if (!o.domain) {
          http.shareAmong(1);
          return { entries: [{ id: o.broker, mcp: o.mcp ?? undefined, rest: o.rest ?? undefined, inbox: o.inbox ?? undefined, jwks_uri: o.jwks ?? undefined, index: 0, origins: givenOrigins }], reason: null };
        }
        const found = await documentEntries(ctx);
        // A domain's document names each entry's URLs; a request for an entry goes only to that entry's own origin.
        found.entries = found.entries.map((e) => ({ ...e, origins: [e.origin] }));
        for (const e of found.entries) http.allowOrigin(e.origin, "a broker entry's own origin");
        http.shareAmong(new Set(found.entries.map((e) => e.id)).size);
        return found;
      });
    },
    async check(id, subject, fn) {
      const c = BY_ID.get(id);
      if (!c) throw new Error(`no check ${id}`);
      if (!wants(id)) return;
      let out;
      // An exception inside a check is alp-check's own error: reported as such, never as "could not decide".
      try { out = await fn(); } catch (e) { out = { outcome: "error", message: `alp-check error: ${e && e.message}` }; }
      if (!out || typeof out.outcome !== "string") out = { outcome: "error", message: "alp-check error: the check gave no result" };
      const result = out.outcome === "pass" ? "pass" : out.outcome === "skip" ? "skip" : out.outcome === "error" ? "error" : out.outcome === "inconclusive" ? "warn" : c.level === "required" ? "fail" : "warn";
      const r = { id, family: c.family, level: c.level, section: c.section, title: c.title, subject: subject == null ? null : cap(subject), result };
      if (out.outcome === "inconclusive") r.inconclusive = true;
      if (out.capped) r.capped = true;
      if (typeof out.basisKey === "string" && c.otherBases && Object.hasOwn(c.otherBases, out.basisKey)) r.basis_key = out.basisKey;
      // Text from a response is already cut to 400 characters where it is quoted; every field is escaped again
      // here, so that nothing a target serves (a URL in a document, a header) can write control characters.
      for (const k of ["message", "reason", "expected"]) if (out[k]) r[k] = cap(out[k]);
      if (out.notJudged) r.not_judged = cap(out.notJudged);
      for (const k of ["sent", "received"]) if (out[k]) r[k] = excerpt(out[k], 1600);
      if (out.notes?.length) r.notes = out.notes.map(cap);
      if (r.result === "skip") {
        const after = out.after ?? [...String(out.reason ?? "").matchAll(/\(see ([^)]*)\)/g)].flatMap((m) => m[1].split(/,| and /).map((x) => x.trim()));
        const known = after.filter((x) => BY_ID.has(x));
        if (known.length) r.after = known;
      }
      results.push(r);
    },
  };

  // Nothing a target serves may stop the report: an error outside any check stops only its own family, which
  // gets an ERROR result, and the run goes on (exit code 3).
  for (const family of deps.families ?? RUN_ORDER) {
    try {
      await family.run(ctx);
    } catch (e) {
      const id = family.FAMILY ?? null;
      const title = FAMILIES.find((f) => f.id === id)?.title ?? "A family of checks";
      results.push({ id: null, family: id, level: null, section: null, title: `${title}: the remaining checks of this family did not run`, subject: null, result: "error", message: cap(`alp-check error outside a check: ${e && e.message}`) });
    }
  }
  return {
    target: o.domain ? { domain: o.domain } : { broker: o.broker, mcp: o.mcp, rest: o.rest, inbox: o.inbox, jwks: o.jwks },
    devMapOrigins: o.devMap ? [...o.devMap.keys()] : null,
    startedAt: new Date(now()).toISOString(),
    results,
    requests: http.log,
    requestCount: http.count,
  };
}

/**
 * 3 when alp-check itself failed, else 1 when a required check failed, else 4 when a required check could not be
 * decided (or was skipped because one could not), else 0.
 */
export const exitCode = (run) => summarise(run.results).exitCode;

/**
 * The command: parse, run, print, and return the exit code. `deps` replaces the network (tests and
 * test/against-fake.mjs only); `out` and `err` receive the text.
 */
export async function main(argv, deps = {}, out = (s) => process.stdout.write(s), err = (s) => process.stderr.write(s)) {
  let o;
  try { o = parseArgs(argv); } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    err(`alp-check: ${e.message}\n\n${USAGE}\n`);
    return 2;
  }
  if (o.help) { out(`${USAGE}\n`); return 0; }
  const run = await runChecks(o, deps);
  out(o.json ? `${JSON.stringify(toJson(run), null, 2)}\n` : `${toText(run)}\n`);
  return exitCode(run);
}

/** Whether this file is the program being run, also when it is run through a symbolic link. */
function isEntry(argv1, url) {
  if (!argv1) return false;
  try { return fs.realpathSync(argv1) === fs.realpathSync(fileURLToPath(url)); } catch { return false; }
}
const isMain = isEntry(process.argv[1], import.meta.url);
if (isMain) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { process.stderr.write(`alp-check: ${e && e.stack}\n`); process.exitCode = 3; });
}

export { FAMILIES, isEntry };
