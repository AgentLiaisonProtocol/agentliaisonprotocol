// The run as a whole: what it contacts and sends, the probes, the command-line options, the development host map
// and the report.
import "./guard.mjs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrict, fromB64url, canonicalize } from "../../spec/lib.mjs";
import { runChecks, parseArgs, main, exitCode, UsageError } from "../check.mjs";
import { toText, toJson } from "../report.mjs";
import { schemas } from "../checks/common.mjs";
import { PROBES, probeText, baseControl, baseMessage } from "../checks/inbox.mjs";
import { parseDevMap, MAX_REQUESTS } from "../http.mjs";
import { CHECKS, NOT_CHECKED, USER_AGENT } from "../catalog.mjs";
import { createFakeBroker, FAULTS, VARIANTS } from "./fake-broker.mjs";
import { stubTransport } from "./transport-stub.mjs";

const run = async (args, faults = [], wrap = (f) => f) => {
  const fake = createFakeBroker({ faults });
  const r = await runChecks(parseArgs(args), { fetch: wrap(fake.fetch), resolveTxt: fake.resolveTxt });
  return { run: r, fake };
};

// The kinds of request README.md "What it sends" lists, and nothing else.
const KINDS = [
  ["GET", /^https:\/\/(alp\.)?example\.org\/\.well-known\/alp\.json$/, "domain document"],
  ["GET", /^https:\/\/[^/]+\/\.well-known\/jwks\.json$/, "JWKS at jwks_uri"],
  ["GET", /^https:\/\/[^/]+\/\.well-known\/oauth-protected-resource(\/mcp|\/rest(\/alp_whoami)?)?$/, "protected resource metadata"],
  ["GET", /^https:\/\/[^/]+\/\.well-known\/oauth-authorization-server$/, "RFC 8414 metadata"],
  ["GET", /^https:\/\/[^/]+\/\.well-known\/openid-configuration$/, "OpenID Connect discovery"],
  ["POST", /^https:\/\/[^/]+\/mcp$/, "MCP initialize with no token"],
  ["POST", /^https:\/\/[^/]+\/rest\/alp_whoami$/, "REST alp_whoami with no token"],
  ["POST", /^https:\/\/[^/]+\/federation\/inbox$/, "inbox probe"],
];
const HOSTS = new Set(["example.org", "alp.example.org", "broker.example.org", "hosted.example.net"]);

test("across every fault and variant, alp-check contacts only allowed hosts, with the listed request kinds, within the limit", async () => {
  for (const f of [[], ...Object.keys(FAULTS).map((x) => [x]), ...Object.keys(VARIANTS).map((x) => [x])]) {
    const { fake, run: r } = await run(["example.org"], f);
    assert.ok(fake.calls.length <= MAX_REQUESTS, `${f}: ${fake.calls.length} requests`);
    assert.equal(r.requestCount, fake.calls.length, `${f}: request count`);
    for (const c of fake.calls) {
      const u = new URL(c.url);
      assert.ok(HOSTS.has(u.hostname), `${f}: contacted ${c.url}`);
      assert.ok(KINDS.some(([m, re]) => m === c.method && re.test(c.url)), `${f}: unlisted request ${c.method} ${c.url}`);
      assert.equal(c.headers["user-agent"], USER_AGENT);
      for (const h of Object.keys(c.headers)) assert.ok(!/^(authorization|cookie)$/i.test(h), `${f}: sent ${h}`);
    }
  }
});

test("a redirect, and a URL off the entry's origin, are reported and not fetched", async () => {
  const a = await run(["example.org"], ["location-1-redirects"]);
  assert.ok(!a.fake.calls.some((c) => c.url.includes("www.example.org")));
  const b = await run(["example.org"], ["document-url-off-origin"]);
  assert.ok(!b.fake.calls.some((c) => c.url.includes("cdn.example.net")));
  const skipped = b.run.results.filter((r) => r.id === "keys.served" && r.subject === "https://hosted.example.net");
  assert.equal(skipped[0].result, "skip");
  assert.match(skipped[0].reason, /did not fetch/);
});

test("every inbox probe is valid except in the one respect it tests, and can reach no person", () => {
  const v = schemas();
  const ctx = { aud: "https://broker.example.org", targetDomain: "example.org", now: Date.now() };
  const base = baseControl(ctx);
  assert.ok(v.control(base), JSON.stringify(v.control.errors));
  const message = baseMessage(base);
  assert.ok(v.envelope(message), JSON.stringify(v.envelope.errors));
  const header = JSON.parse(fromB64url(base.broker_sig.split("..")[0]).toString("utf8"));
  assert.deepEqual(Object.keys(header).sort(), ["alg", "kid", "typ"]);
  assert.ok(fromB64url(base.broker_sig.split("..")[1]).every((b) => b === 0), "the signature is zero bytes: alp-check signs nothing");
  const delegateOk = (env) => (!env.from.delegate || env.from.delegate.startsWith(`${env.from.address}/`)) && (!env.to.delegate || env.to.delegate.startsWith(`${env.to.address}/`));
  for (const { probe } of PROBES) {
    const text = probeText(probe, ctx);
    let env;
    if (probe === "strict-json") {
      assert.throws(() => parseStrict(text), /duplicate member name/);
      env = JSON.parse(text);
    } else env = parseStrict(text);
    const validate = env.type === "request" ? v.envelope : v.control;
    // The sender is on a domain that cannot exist; the recipient is a long random local part on the target domain.
    assert.match(env.from.address, /@alp-check-[0-9a-f]{16}\.invalid$/, probe);
    assert.match(env.to.address, /^alp:alp-check-[0-9a-f]{40}@example\.org$/, probe);
    assert.equal(env.aud, ctx.aud);
    assert.match(env.origin_broker, /^https:\/\/broker\.alp-check-[0-9a-f]{16}\.invalid$/);
    assert.ok(Buffer.byteLength(text) < 4096, `${probe}: small`);
    const created = Date.parse(env.created_at);
    const expires = Date.parse(env.expires_at);
    const lifetimeOk = expires > created && expires - created <= 7 * 86_400_000;
    const clockOk = created <= ctx.now + 300_000;
    switch (probe) {
      case "version":
        assert.equal(env.alp, "0.0");
        assert.ok(validate({ ...env, alp: "0.1" }), probe);
        break;
      case "schema":
        assert.ok(!("broker_sig" in env));
        assert.ok(!validate(env));
        assert.ok(validate({ ...env, broker_sig: base.broker_sig }), probe);
        break;
      case "lifetime":
        assert.ok(validate(env), probe);
        assert.ok(expires - created > 7 * 86_400_000 && clockOk);
        break;
      case "expiry-order":
        assert.ok(validate(env), probe);
        assert.ok(expires < created && clockOk && expires > ctx.now, "expires before it was created, but not yet expired");
        break;
      case "created-ahead":
        assert.ok(validate(env), probe);
        assert.ok(created > ctx.now + 3_000_000 && lifetimeOk);
        break;
      case "from-delegate":
        assert.ok(validate(env), probe);
        assert.ok(!env.from.delegate.startsWith(env.from.address + "/"));
        assert.ok(delegateOk({ ...env, from: { ...env.from, delegate: `${env.from.address}/agent` } }));
        break;
      case "to-delegate":
        assert.equal(env.type, "request");
        assert.ok(validate(env), JSON.stringify(validate.errors));
        assert.ok(env.from.delegate.startsWith(env.from.address + "/"), "from.delegate is the sender's own");
        assert.ok(!env.to.delegate.startsWith(env.to.address + "/"));
        break;
      default:
        assert.ok(validate(env), `${probe}: ${JSON.stringify(validate.errors)}`);
    }
    if (!["lifetime", "expiry-order", "created-ahead"].includes(probe)) {
      assert.ok(created <= ctx.now && expires > ctx.now && lifetimeOk, `${probe}: fresh timestamps`);
    }
    if (!["from-delegate", "to-delegate"].includes(probe)) assert.ok(delegateOk(env), probe);
  }
  // Fresh ids: two probes never share an id.
  assert.notEqual(baseControl(ctx).id, baseControl(ctx).id);
});

test("usage errors", () => {
  for (const args of [
    [],
    ["example.org", "partner.example"],
    ["Example..org"],
    ["https://example.org"],
    ["example.org", "--broker", "https://broker.example.org"],
    ["--broker", "https://broker.example.org"],
    ["--broker", "https://broker.example.org/path", "--mcp", "https://broker.example.org/mcp"],
    ["--broker", "https://broker.example.org", "--mcp", "http://broker.example.org/mcp"],
    ["example.org", "--timeout", "0"],
    ["example.org", "--timeout", "600"],
    ["example.org", "--only", "nothing.here"],
    ["example.org", "--only"],
    ["example.org", "--dev-map", '{"https://agentliaisonprotocol.org":"http://127.0.0.1:1"}'],
    ["example.org", "--unknown"],
    // Matches the shape of a broker id, but is not an origin a URL parser accepts.
    ["--broker", "https://broker.example.org:99999", "--mcp", "https://broker.example.org/mcp"],
    ["--broker", "https://broker.123", "--mcp", "https://broker.example.org/mcp"],
  ]) assert.throws(() => parseArgs(args), UsageError, JSON.stringify(args));
  assert.equal(parseArgs(["EXAMPLE.org."]).domain, "example.org");
  assert.equal(parseArgs(["--help"]).help, true);
});

test("the command's exit codes and output", async () => {
  let text = "";
  let errText = "";
  const fake = createFakeBroker();
  const deps = { fetch: fake.fetch, resolveTxt: fake.resolveTxt };
  assert.equal(await main(["example.org"], deps, (s) => (text += s)), 0);
  assert.match(text, /^alp-check 0\.1: domain example\.org/);
  assert.equal(await main(["nope"], deps, () => {}, (s) => (errText += s)), 2);
  assert.match(errText, /not a domain name/);
  const bad = createFakeBroker({ faults: ["document-extra-member"] });
  assert.equal(await main(["example.org"], { fetch: bad.fetch, resolveTxt: bad.resolveTxt }, () => {}), 1);
  const warnOnly = createFakeBroker({ faults: ["kid-not-thumbprint"] });
  assert.equal(await main(["example.org"], { fetch: warnOnly.fetch, resolveTxt: warnOnly.resolveTxt }, () => {}), 0, "a failed recommended check does not change the exit code");
});

test("the command runs from a shell for --help and usage errors (no network involved)", () => {
  const cli = fileURLToPath(new URL("../check.mjs", import.meta.url));
  const help = spawnSync(process.execPath, [cli, "--help"], { encoding: "utf8", timeout: 20_000 });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /^Usage:/);
  const none = spawnSync(process.execPath, [cli], { encoding: "utf8", timeout: 20_000 });
  assert.equal(none.status, 2);
});

test("the command and the table generator work when run through a symbolic link", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "alp-check-link-"));
  try {
    const cli = path.join(dir, "check.mjs");
    const gen = path.join(dir, "requirements.mjs");
    fs.symlinkSync(fileURLToPath(new URL("../check.mjs", import.meta.url)), cli);
    fs.symlinkSync(fileURLToPath(new URL("../requirements.mjs", import.meta.url)), gen);
    const help = spawnSync(process.execPath, [cli, "--help"], { encoding: "utf8", timeout: 20_000 });
    assert.equal(help.status, 0);
    assert.match(help.stdout, /^Usage:/);
    const none = spawnSync(process.execPath, [cli], { encoding: "utf8", timeout: 20_000 });
    assert.equal(none.status, 2, "a usage error through a link still exits 2");
    const check = spawnSync(process.execPath, [gen, "--check"], { encoding: "utf8", timeout: 20_000 });
    assert.equal(check.status, 0);
    assert.match(check.stdout, /CONFORMANCE\.md is current/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an error inside a check is reported as alp-check's own error, and the run exits 3", async () => {
  const broken = { run: (ctx) => ctx.check("document.found", "example.org", () => { throw new Error("a bug"); }) };
  const fake = createFakeBroker();
  const r = await runChecks(parseArgs(["example.org"]), { fetch: fake.fetch, resolveTxt: fake.resolveTxt, families: [broken] });
  assert.equal(r.results[0].result, "error");
  assert.ok(!r.results[0].inconclusive);
  assert.equal(exitCode(r), 3);
  const text = toText(r);
  assert.match(text, /^ERROR  document\.found/m);
  assert.match(text, /alp-check's own error, not a finding about the target: alp-check error: a bug/);
  assert.equal(toJson(r).summary.exit_code, 3);
  let out = "";
  const code = await main(["example.org"], { fetch: fake.fetch, resolveTxt: fake.resolveTxt, families: [broken] }, (x) => (out += x));
  assert.equal(code, 3);
});

test("a schema-valid document whose entry id is not an origin still gives a full report, and that entry is not contacted", async () => {
  for (const bad of ["https://b2.example.org:99999", "https://broker.123", "https://999.1.1.1"]) {
    const fake = createFakeBroker();
    const doc = JSON.parse(JSON.stringify(fake.document));
    const first = doc.brokers[0];
    doc.brokers.push({ ...first, id: bad, inbox: `${bad}/federation/inbox`, jwks_uri: `${bad}/.well-known/jwks.json`, mcp: `${bad}/mcp`, rest: `${bad}/rest`, principals: ["alp:extra@example.org"] });
    assert.ok(schemas().document(doc), `${bad}: the schema allows this id`);
    const wrap = (f) => async (url, init) => {
      if (url === "https://example.org/.well-known/alp.json") return new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } });
      return f(url, init);
    };
    let out = "";
    const code = await main(["example.org"], { fetch: wrap(fake.fetch), resolveTxt: fake.resolveTxt }, (x) => (out += x));
    assert.notEqual(code, 3, `${bad}: ${out.slice(0, 400)}`);
    assert.match(out, /^alp-check 0\.1: domain example\.org/, bad);
    assert.match(out, /What this report does not cover/, `${bad}: the report is complete`);
    assert.ok(!out.includes("ERROR "), `${bad}: no alp-check error`);
    assert.ok(!fake.calls.some((c) => c.url.startsWith(bad)), `${bad}: contacted`);
    const { run: r } = await run(["example.org"], [], wrap);
    const off = r.results.find((x) => x.id === "document.urls-on-origin");
    assert.equal(off.result, "fail", bad);
    assert.ok(off.message.includes(bad), `${bad}: ${off.message}`);
    assert.ok(r.results.some((x) => x.id === "keys.served" && x.subject === "https://broker.example.org" && x.result === "pass"), `${bad}: the other entries are still checked`);
  }
});

test("an error outside any check stops only its family: an ERROR result, the rest of the report, exit 3", async () => {
  const fake = createFakeBroker();
  const documentFamily = await import("../checks/document.mjs");
  const broken = { FAMILY: "keys", run: async () => { throw new Error("a bug outside the checks"); } };
  const r = await runChecks(parseArgs(["example.org"]), { fetch: fake.fetch, resolveTxt: fake.resolveTxt, families: [broken, documentFamily] });
  const err = r.results.find((x) => x.result === "error");
  assert.ok(err, "an ERROR result");
  assert.equal(err.family, "keys");
  assert.match(err.message, /a bug outside the checks/);
  assert.ok(r.results.some((x) => x.id === "document.found" && x.result === "pass"), "the next family still ran");
  assert.equal(exitCode(r), 3);
  const text = toText(r);
  assert.match(text, /^ERROR  keys/m);
  assert.match(text, /What this report does not cover/);
  assert.equal(toJson(r).summary.exit_code, 3);
});

test("a run in which required checks could not be decided says so, counts them, lists no requirement as observed, and exits 4", async () => {
  for (const variant of ["everything-unavailable", "brokers-unavailable"]) {
    const fake = createFakeBroker({ faults: [variant] });
    let text = "";
    const code = await main(["example.org"], { fetch: fake.fetch, resolveTxt: fake.resolveTxt }, (x) => (text += x));
    assert.equal(code, 4, variant);
    const flat = text.replace(/\n/g, " ");
    assert.doesNotMatch(flat, /No required check failed\.(?! *but)/, `${variant}: never "No required check failed" alone`);
    assert.match(flat, /No required check failed, but \d+ required check results? could not be decided/, variant);
    assert.match(flat, /this run says nothing about them/, variant);
    const { run: r } = await run(["example.org"], [variant]);
    const j = toJson(r);
    assert.equal(j.summary.exit_code, 4, variant);
    assert.equal(j.summary.required_failed, 0, variant);
    assert.ok(j.summary.required_undecided >= 1, variant);
    const skippedRequired = r.results.filter((x) => x.result === "skip" && x.level === "required").length;
    if (variant === "everything-unavailable") {
      assert.equal(j.summary.required_undecided, 1, "document.found");
      assert.equal(j.summary.required_skipped_after_undecided, skippedRequired, "every required check skipped is skipped because document.found could not decide");
      assert.deepEqual(j.requirements_observed_in_part, [], "nothing was decided, so no requirement was observed");
    } else {
      assert.ok(j.summary.required_skipped_after_undecided > 0, variant);
    }
    assert.equal(typeof j.summary.recommended_warned, "number");
  }
  // A clean run says nothing about undecided checks, and exits 0.
  const { run: clean } = await run(["example.org"]);
  const j = toJson(clean);
  assert.equal(j.summary.exit_code, 0);
  assert.equal(j.summary.required_undecided, 0);
  assert.equal(j.summary.required_skipped_after_undecided, 0);
  assert.equal(j.summary.required_skipped, 0);
  assert.match(toText(clean), /^No required check failed and none was left undecided\.$/m);
  assert.doesNotMatch(toText(clean), /were skipped; the SKIP lines/);
});

test("a run with no failure and nothing undecided counts the required check results that were skipped, and never calls them decided", async () => {
  for (const [args, faults] of [[["example.org"], ["inbox-requires-signed-requests"]], [["example.org", "--no-inbox-probes"], []]]) {
    const { run: r } = await run(args, faults);
    const n = r.results.filter((x) => x.level === "required" && x.result === "skip").length;
    assert.ok(n > 1, `${args.join(" ")}: required checks skipped`);
    const j = toJson(r);
    assert.equal(j.summary.exit_code, 0);
    assert.equal(j.summary.required_skipped, n);
    const text = toText(r);
    assert.match(text, new RegExp(`^No required check failed and none was left undecided\\.\\n${n} required check results were skipped; the SKIP lines above say why\\.$`, "m"));
    assert.doesNotMatch(text, /every required check was decided/);
  }
  // One skipped result reads in the singular.
  const B = "https://broker.example.org";
  const { run: one } = await run(["--broker", B, "--inbox", `${B}/federation/inbox`, "--only", "inbox.version", "--no-inbox-probes"]);
  assert.equal(one.results.filter((x) => x.level === "required" && x.result === "skip").length, 1, "inbox.version");
  assert.match(toText(one), /^No required check failed and none was left undecided\.\n1 required check result was skipped; the SKIP lines above say why\.$/m);
});

test("checks are total over hostile JSON: odd ids and prototype-named codes give results, not errors", async () => {
  const fake = createFakeBroker();
  const doc = JSON.parse(JSON.stringify(fake.document));
  doc.brokers.push({ id: { toString: 1 }, inbox: { valueOf: 2 }, jwks_uri: ["x"], jkt: [{ a: 1 }], principals: [{ toString: 1 }] });
  const wrap = (f) => async (url, init) => {
    if (url === "https://example.org/.well-known/alp.json") return new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } });
    if (url.endsWith("/federation/inbox")) return new Response(JSON.stringify({ error: { code: "constructor", message: "x" } }), { status: 400, headers: { "content-type": "application/json" } });
    return f(url, init);
  };
  const { run: r } = await run(["example.org"], [], wrap);
  assert.ok(!r.results.some((x) => x.result === "error"), JSON.stringify(r.results.filter((x) => x.result === "error")));
  const shape = r.results.find((x) => x.id === "inbox.error-shape");
  assert.equal(shape.result, "fail");
  assert.match(shape.message, /`constructor` is not a registry code/);
  assert.equal(({}).polluted, undefined);
});

test("each broker entry gets its share of the request limit, and the report says how many checks the limit stopped", async () => {
  const fake = createFakeBroker();
  const main0 = fake.document.brokers[0];
  const doc = JSON.parse(JSON.stringify(fake.document));
  doc.brokers = Array.from({ length: 12 }, (_, i) => {
    const id = `https://b${i}.example.org`;
    return { ...main0, id, inbox: `${id}/federation/inbox`, jwks_uri: `${id}/.well-known/jwks.json`, mcp: `${id}/mcp`, rest: `${id}/rest`, principals: i === 0 ? "*" : [`alp:p${i}@example.org`] };
  });
  const wrap = (f) => async (url, init) => {
    if (url === "https://example.org/.well-known/alp.json") return new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } });
    const u = new URL(url);
    if (/^b\d+\.example\.org$/.test(u.hostname)) return f(`https://broker.example.org${u.pathname}${u.search}`, init);
    return f(url, init);
  };
  const { run: r, fake: seen } = await run(["example.org", "--no-inbox-probes"], [], wrap);
  assert.ok(r.requestCount <= MAX_REQUESTS);
  for (let i = 0; i < 12; i++) assert.ok(r.requests.some((x) => x.url.startsWith(`https://b${i}.example.org/`) && !x.outcome.startsWith("not contacted")), `entry ${i} was contacted`);
  assert.ok(r.results.some((x) => x.capped));
  assert.ok(!r.results.some((x) => x.capped && x.result !== "warn"), "the limit gives undecided results, never failures");
  assert.match(toText(r).replace(/\n/g, " "), /The request limit stopped \d+ check results?, reported as "could not decide"/);
  assert.ok(toJson(r).summary.stopped_by_request_limit > 0);
  assert.ok(seen.calls.length <= MAX_REQUESTS);
});

test("--only runs only the named checks and sends only what they need", async () => {
  const { run: r, fake } = await run(["example.org", "--only", "document.schema"]);
  assert.deepEqual([...new Set(r.results.map((x) => x.id))], ["document.schema"]);
  assert.deepEqual(fake.calls.map((c) => c.url), ["https://example.org/.well-known/alp.json"]);
  const v = await run(["example.org", "--only", "inbox.version"]);
  const posts = v.fake.calls.filter((c) => c.method === "POST");
  assert.equal(posts.length, 2, "one probe to each of the two entries' inboxes");
  assert.ok(posts.every((c) => JSON.parse(c.body).alp === "0.0"));
});

test("--no-inbox-probes sends nothing to the inbox", async () => {
  const { run: r, fake } = await run(["example.org", "--no-inbox-probes"]);
  assert.ok(!fake.calls.some((c) => c.url.endsWith("/federation/inbox")));
  for (const x of r.results.filter((y) => y.family === "inbox")) {
    assert.equal(x.result, "skip");
    assert.match(x.reason, /--no-inbox-probes/);
  }
  assert.equal(exitCode(r), 0);
});

test("--broker checks a Local-profile broker with no domain document", async () => {
  const id = "https://broker.example.org";
  const { run: r, fake } = await run(["--broker", id, "--mcp", `${id}/mcp`, "--rest", `${id}/rest`, "--inbox", `${id}/federation/inbox`, "--jwks", `${id}/.well-known/jwks.json`]);
  assert.ok(!fake.calls.some((c) => c.url.includes("alp.json")));
  const by = (k) => r.results.filter((x) => x.id === k);
  for (const k of CHECKS.filter((c) => c.family === "document" || c.family === "dns").map((c) => c.id)) assert.equal(by(k)[0].result, "skip", k);
  assert.equal(by("keys.current-key-pinned")[0].result, "skip");
  assert.equal(by("keys.no-unpinned-federation")[0].result, "skip");
  for (const k of ["keys.served", "keys.schema", "signin.prm", "signin.pkce-s256", "binding.mcp-challenge", "binding.rest-challenge", "inbox.version", "inbox.unknown-sender-domain"]) assert.equal(by(k)[0].result, "pass", k);
  const probe = JSON.parse(fake.calls.find((c) => c.method === "POST" && c.url.endsWith("/federation/inbox")).body);
  assert.match(probe.to.address, /@broker\.example\.org$/, "with no domain, probes go to an address on the broker's host");
  assert.equal(exitCode(r), 0);
  const observed = toJson(r).requirements_observed_in_part;
  for (const q of ["OB-6", "HB-5", "PB-2", "PB-7"]) assert.ok(!observed.includes(q), `a Local-profile run does not list ${q}`);
  assert.ok(observed.includes("BC-5") && observed.includes("BC-15"));
  assert.match(toText(r), /requirements that apply when a broker federates are not listed/);
});

test("with a development host map, the report says so first, and TLS and DNS are skipped, never passed", async () => {
  const devText = JSON.stringify({
    "https://example.org": "http://127.0.0.1:47201",
    "https://alp.example.org": "http://127.0.0.1:47202",
    "https://broker.example.org": "http://127.0.0.1:47203",
    "https://hosted.example.net": "http://127.0.0.1:47204",
  });
  const back = new Map([...parseDevMap(devText)].map(([k, v]) => [v, k]));
  const seen = [];
  const wrap = (f) => (url, init) => {
    seen.push(url);
    const u = new URL(url);
    assert.equal(u.protocol, "http:");
    return f(back.get(u.origin) + u.pathname + u.search, init);
  };
  let resolved = false;
  const fake = createFakeBroker();
  const r = await runChecks(parseArgs(["example.org", "--dev-map", devText]), { fetch: wrap(fake.fetch), resolveTxt: () => { resolved = true; return [["v=ALP1; id=42"]]; } });
  assert.ok(seen.length > 0 && seen.every((u) => u.startsWith("http://127.0.0.1:")));
  assert.equal(resolved, false, "DNS is not consulted");
  const tls = r.results.find((x) => x.id === "document.tls");
  assert.equal(tls.result, "skip");
  for (const x of r.results.filter((y) => y.family === "dns")) assert.equal(x.result, "skip");
  const text = toText(r);
  assert.match(text.split("\n")[0], /^Development host map in use/);
  assert.deepEqual(toJson(r).dev_map, Object.keys(JSON.parse(devText)));
  assert.equal(exitCode(r), 0);
});

test("a failure in the report quotes the requirement and says what was sent, received and expected", async () => {
  const { run: r } = await run(["example.org"], ["inbox-no-delegate-check"]);
  const text = toText(r);
  const block = text.split("\n").slice(text.split("\n").findIndex((l) => l.startsWith("FAIL  inbox.delegate-owner")), undefined).join("\n");
  const j0 = toJson(r).results.find((x) => x.id === "inbox.delegate-owner" && x.result === "fail");
  assert.equal(j0.level, "required");
  assert.deepEqual(j0.basis, { kind: "stated", maturity: "Experimental" });
  assert.match(j0.quote, /^`from\.delegate` and `to\.delegate`/);
  assert.ok(j0.requirements.includes("PB-2"));
  assert.match(text.replace(/\n +/g, " "), /FAIL  inbox\.delegate-owner \[https:\/\/broker\.example\.org\], required \(stated in Section 12\.2\.4, Experimental\): /);
  assert.match(block, /specification \(Section 12\.2\.4\): "`from\.delegate` and `to\.delegate`, when present/);
  assert.match(block, /sent: POST https:\/\/broker\.example\.org\/federation\/inbox with body:\s/);
  assert.match(block, /received: 503/);
  assert.match(block, /expected: refused with `bad_envelope`/);
  assert.ok(text.includes(NOT_CHECKED[0].slice(0, 60)), "the closing paragraph");
  assert.match(text, /2 required check results failed\./, "one per broker entry");
  const j = toJson(r);
  assert.equal(j.summary.exit_code, 1);
  assert.ok(j.requirements_observed_in_part.includes("PB-2"));
  assert.deepEqual(j.not_checked, NOT_CHECKED);
});

test("a hostile answer cannot write control characters to the terminal, and no field shows more than 400 characters of it", async () => {
  const hostile = "\u001b[2J" + "a".repeat(5000);
  const wrap = (f) => async (url, init) => {
    if (url === "https://example.org/.well-known/alp.json") {
      const entry = { id: "https://broker.example.org", inbox: "https://broker.example.org/federation/inbox", jwks_uri: "https://broker.example.org/.well-known/jwks.json", mcp: "https://outside.example/\u001b[31m" + "m".repeat(900), jkt: ["Qlbvmc8DWyTQ_pE2ysLApn4T03jw-c6Vq65LODOzGFk"], principals: "*" };
      return new Response(JSON.stringify({ alp: "0.1", domain: hostile, serial: 1, max_age: 60, mode: "enforce", brokers: [entry], security_contact: ["mailto:x@example.org"] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return f(url, init);
  };
  const { run: r } = await run(["example.org"], [], wrap);
  const text = toText(r);
  assert.ok(!text.includes("\u001b"), "no escape character reaches the output");
  assert.ok(!/a{401}/.test(text.replace(/\n\s*/g, "")), "no more than 400 characters of the body in one field");
  const json = JSON.stringify(toJson(r));
  // A raw ESC would be serialized as \u001b; the excerpt's escaped text is serialized as \\u001b.
  assert.ok(!/(^|[^\\])\\u001b/.test(json), "escaped as text, not passed through");
  assert.ok(!/a{401}/.test(json));
  assert.ok(!/m{401}/.test(text.replace(/\n\s*/g, "")), "a URL from the document is cut too");
  assert.ok(r.results.some((x) => x.subject && x.subject.includes("\\u001b")), "the hostile URL is shown escaped");
});

test("a body that stops arriving is a check that could not decide, never a failure", async () => {
  const stalled = (status) => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{"alp":"0.1","dom')); } }), { status, headers: { "content-type": "application/json" } });
  const wrap = (f) => async (url, init) => {
    // The stream neither ends nor listens to the abort signal: only alp-check's own timer can end the wait.
    if (url === "https://example.org/.well-known/alp.json" || url === "https://broker.example.org/.well-known/jwks.json") return stalled(200);
    return f(url, init);
  };
  const fake = createFakeBroker();
  const r = await runChecks(parseArgs(["example.org", "--timeout", "0.05", "--only", "document", "--only", "keys"]), { fetch: wrap(fake.fetch), resolveTxt: fake.resolveTxt });
  assert.ok(!r.results.some((x) => x.result === "fail"), JSON.stringify(r.results.filter((x) => x.result === "fail").map((x) => x.id)));
  assert.equal(r.results.find((x) => x.id === "document.found").inconclusive, true);
  assert.equal(exitCode(r), 4, "a required check could not be decided");
});

test("a DNS lookup that never answers is a check that could not decide", async () => {
  const fake = createFakeBroker();
  const r = await runChecks(parseArgs(["example.org", "--timeout", "0.05", "--only", "dns"]), { fetch: fake.fetch, resolveTxt: () => new Promise(() => {}) });
  const g = r.results.find((x) => x.id === "dns.txt-grammar");
  assert.equal(g.result, "warn");
  assert.equal(g.inconclusive, true);
});

test("hosts a document or metadata names that are internal are refused and reported, never contacted", async () => {
  const fake = createFakeBroker();
  const good = fake.document.brokers[0];
  const doc = JSON.parse(JSON.stringify(fake.document));
  const hostile = (id) => ({ id, inbox: `${id}/admin/reset`, jwks_uri: `${id}/.well-known/jwks.json`, mcp: `${id}/mcp`, rest: `${id}/rest`, jkt: good.jkt, principals: [`alp:x${doc.brokers.length}@example.org`] });
  doc.brokers = [good, hostile("https://intranet"), hostile("https://metadata.cloud.internal"), hostile("https://internal.example.org"), hostile("https://rebind.example.org")];
  const hostileFetch = async (url, init) => {
    if (url === "https://example.org/.well-known/alp.json") return new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } });
    if (url === "https://broker.example.org/.well-known/oauth-protected-resource/mcp") {
      return new Response(JSON.stringify({ resource: "https://broker.example.org/mcp", authorization_servers: ["https://localhost.:8443/x"], scopes_supported: ["read", "send"] }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return fake.fetch(url, init);
  };
  const t = stubTransport(hostileFetch, { "internal.example.org": ["10.0.0.5"], "rebind.example.org": ["11.22.33.44", "127.0.0.1"] });
  const r = await runChecks(parseArgs(["example.org"]), { transport: t, resolveTxt: fake.resolveTxt });
  const contacted = new Set(t.connections.map((c) => c.host));
  for (const h of ["intranet", "metadata.cloud.internal", "internal.example.org", "rebind.example.org", "localhost", "localhost."]) assert.ok(!contacted.has(h), `contacted ${h}`);
  assert.ok(!t.lookups.some((l) => ["intranet", "metadata.cloud.internal", "localhost"].includes(l.name)), "special names are refused before any lookup");
  const served = (subject) => r.results.find((x) => x.id === "keys.served" && x.subject === subject);
  for (const id of ["https://intranet", "https://metadata.cloud.internal"]) {
    assert.equal(served(id).result, "skip", `${id}: ${JSON.stringify(served(id))}`);
    assert.match(served(id).reason, /single-label|special-use/);
  }
  for (const id of ["https://internal.example.org", "https://rebind.example.org"]) {
    assert.equal(served(id).result, "skip", `${id}: ${JSON.stringify(served(id))}`);
    assert.match(served(id).reason, /not public/);
  }
  const as = r.results.filter((x) => x.id === "signin.as-metadata" && String(x.subject).includes("localhost"));
  assert.ok(as.length && as.every((x) => x.result === "skip" && /loopback/.test(x.reason)), JSON.stringify(as));
  for (const x of r.results.filter((y) => y.family === "inbox" && /intranet|internal|rebind/.test(String(y.subject)))) assert.equal(x.result, "skip", `${x.id} ${x.subject}`);
  assert.ok(contacted.has("broker.example.org"), "the well-behaved entry is still checked");
});

test("signin.as-metadata shows Section 5.6's stated sentence as its basis when no RFC 8414 metadata is served, and the issuer rule's basis when the issuer differs", async () => {
  const B = "https://broker.example.org";
  const H = "https://hosted.example.net";
  const { run: missing } = await run(["example.org"], ["as-metadata-missing"]);
  const m = toJson(missing).results.find((x) => x.id === "signin.as-metadata" && x.subject === B);
  assert.equal(m.result, "fail");
  assert.equal(m.basis.kind, "stated");
  assert.equal(m.basis_label, "required (stated in Section 5.6)");
  const missingText = toText(missing);
  assert.match(missingText, /^FAIL  signin\.as-metadata \[https:\/\/broker\.example\.org\], required \(stated in Section 5\.6\):/m);
  const { run: wrong } = await run(["example.org"], ["as-wrong-issuer"]);
  const w = toJson(wrong).results.find((x) => x.id === "signin.as-metadata" && x.subject === H);
  assert.equal(w.result, "fail");
  assert.equal(w.basis.kind, "reference");
  assert.match(w.basis_label, /^required \(the MCP authorization specification/);
  assert.match(toText(wrong), /rule \(the MCP authorization specification/);
});
