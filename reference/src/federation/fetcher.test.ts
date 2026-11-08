// SPDX-License-Identifier: FSL-1.1-ALv2
// The hardened fetcher, its network guard and the strict JSON parse. One scripted server on port 47150, reached
// only through the dev host map.

import { test, after, before } from "node:test";
import assert from "node:assert/strict";
import { FetchFailure, HardenedFetcher, isJsonContentType } from "./fetcher.ts";
import { checkDevHostMap, fetchTarget, isPublicAddress } from "./net-guard.ts";
import { StrictJsonError, parseStrictJson, parseStrictJsonBytes } from "./strict-json.ts";
import { ScriptedServer } from "./testing.ts";
import { FEDERATION_TEST_PORT_BASE } from "../test-ports.ts";

const PORT = FEDERATION_TEST_PORT_BASE;
const ORIGIN = "https://docs.example";
const srv = new ScriptedServer();
const dev = new HardenedFetcher({ devHosts: { [ORIGIN]: `http://127.0.0.1:${PORT}` }, timeoutMs: 400 });

before(async () => {
  await srv.listen(PORT);
});
after(async () => {
  await srv.close();
});

async function failure(p: Promise<unknown>): Promise<FetchFailure> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof FetchFailure, String(err));
    return err;
  }
  assert.fail("expected a FetchFailure");
}

test("address guard: loopback, private, shared, link-local, unique-local, multicast, reserved and IPv4-mapped addresses are refused", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255", "192.0.2.10", "198.18.0.1",
    "::1", "::", "::ffff:127.0.0.1", "::ffff:8.8.8.8", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1", "64:ff9b::7f00:1", "2002:7f00:1::1", "not-an-ip"]) {
    assert.equal(isPublicAddress(ip), false, ip);
  }
  for (const ip of ["8.8.8.8", "93.184.215.14", "1.1.1.1", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e"]) {
    assert.equal(isPublicAddress(ip), true, ip);
  }
});

test("URL rules: https on port 443 only, a DNS name, no user info; localhost only through the dev host map", () => {
  for (const url of ["http://example.org/x", "https://example.org:8443/x", "https://user:pw@example.org/x", "https://127.0.0.1/x", "https://[::1]/x", "https://localhost/x", "ftp://example.org/x", "not a url"]) {
    assert.throws(() => fetchTarget(url), Error, url);
  }
  assert.equal(fetchTarget("https://example.org:443/.well-known/alp.json").kind, "public");
  const mapped = fetchTarget(`${ORIGIN}/a?b=1`, { [ORIGIN]: `http://127.0.0.1:${PORT}` });
  assert.equal(mapped.kind === "dev" && mapped.url.href, `http://127.0.0.1:${PORT}/a?b=1`);
  assert.throws(() => checkDevHostMap({ "https://bank.com": "http://127.0.0.1:1" }), /RFC 2606/);
  assert.throws(() => checkDevHostMap({ "https://a.example": "http://10.0.0.5:80" }), /127\.0\.0\.1/);
  assert.throws(() => checkDevHostMap({ "https://a.example/path": "http://127.0.0.1:1" }), /origin/);
});

test("a public name that resolves to a private or loopback address is refused before any connection; no records means no_address", async () => {
  const toLoopback = new HardenedFetcher({ resolveHost: async () => [{ address: "127.0.0.1", family: 4 }] });
  const hitsBefore = srv.hits.length;
  assert.equal((await failure(toLoopback.getJson("https://evil.example/doc"))).kind, "refused");
  const mixed = new HardenedFetcher({ resolveHost: async () => [{ address: "8.8.8.8", family: 4 }, { address: "10.0.0.1", family: 4 }] });
  assert.equal((await failure(mixed.getJson("https://mixed.example/doc"))).kind, "refused", "every answer must be public");
  const none = new HardenedFetcher({ resolveHost: async () => { throw Object.assign(new Error("nx"), { code: "ENOTFOUND" }); } });
  assert.equal((await failure(none.getJson("https://nowhere.example/doc"))).kind, "no_address");
  const empty = new HardenedFetcher({ resolveHost: async () => [] });
  assert.equal((await failure(empty.getJson("https://empty.example/doc"))).kind, "no_address");
  assert.equal(srv.hits.length, hitsBefore, "nothing reached a local server");
});

test("getJson: 200 with a JSON type only; 404 is not_found; redirects are not followed; size and time are capped", async () => {
  srv.routes.set("/ok", { status: 200, body: { a: 1 } });
  assert.deepEqual(await dev.getJson(`${ORIGIN}/ok`), { a: 1 });
  assert.equal(srv.hits.at(-1)?.headers["cache-control"], "no-cache");
  assert.equal(srv.hits.at(-1)?.headers.host, "docs.example", "the published host goes in the Host header");

  srv.routes.set("/missing", { status: 404 });
  assert.equal((await failure(dev.getJson(`${ORIGIN}/missing`))).kind, "not_found");
  srv.routes.set("/gone", { status: 410 });
  assert.equal((await failure(dev.getJson(`${ORIGIN}/gone`))).kind, "not_found");

  srv.routes.set("/moved", { status: 301, headers: { location: `${ORIGIN}/ok` } });
  const okHits = srv.count("/ok");
  assert.equal((await failure(dev.getJson(`${ORIGIN}/moved`))).kind, "temporary");
  assert.equal(srv.count("/ok"), okHits, "the redirect target was never requested");

  srv.routes.set("/html", { status: 200, headers: { "content-type": "text/html" }, body: "<p>hi</p>" });
  assert.equal((await failure(dev.getJson(`${ORIGIN}/html`))).kind, "refused");
  srv.routes.set("/dup", { status: 200, body: '{"a":1,"a":2}' });
  assert.equal((await failure(dev.getJson(`${ORIGIN}/dup`))).kind, "refused", "duplicate member names are refused");
  srv.routes.set("/big", { status: 200, body: { pad: "x".repeat(70 * 1024) } });
  assert.match((await failure(dev.getJson(`${ORIGIN}/big`))).message, /size cap/);
  srv.routes.set("/slow", { status: 200, body: {}, delayMs: 1500 });
  assert.match((await failure(dev.getJson(`${ORIGIN}/slow`))).message, /timed out/);
  srv.routes.set("/err", { status: 500, body: { error: "secret stack trace" } });
  const e = await failure(dev.getJson(`${ORIGIN}/err`));
  assert.equal(e.kind, "temporary");
  assert.doesNotMatch(e.message, /secret/, "response bodies are never carried in the failure");
  assert.equal((await failure(dev.getJson("https://unmapped.example:8443/x"))).kind, "refused");
});

test("request() answers any status with its body, for the transport to map", async () => {
  srv.routes.set("/inbox", { status: 403, body: { error: { code: "broker_not_authorized", message: "no" } } });
  const res = await dev.request(`${ORIGIN}/inbox`, { method: "POST", headers: { "content-type": "application/json" }, body: Buffer.from("{}") });
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(res.body.toString()).error.code, "broker_not_authorized");
  assert.equal(srv.hits.at(-1)?.headers["content-length"], "2");
});

test("JSON content types", () => {
  for (const t of ["application/json", "application/json; charset=utf-8", "application/jwk-set+json", "Application/JSON"]) assert.equal(isJsonContentType(t), true, t);
  for (const t of ["text/json", "application/jsonp", "text/html", undefined]) assert.equal(isJsonContentType(t), false, String(t));
});

test("strict I-JSON: duplicate names (also when escaped), lone surrogates, a BOM, invalid UTF-8 and trailing text are refused", () => {
  assert.deepEqual(parseStrictJson('{"a":[1,{"b":"c"}],"d":null}'), { a: [1, { b: "c" }], d: null });
  for (const bad of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":{"y":1,"y":1}}', '"\\ud800"', "{} {}", "{'a':1}", "[1,]", "01", "1e999"]) {
    assert.throws(() => parseStrictJson(bad), StrictJsonError, bad);
  }
  assert.throws(() => parseStrictJson(`${"[".repeat(200)}${"]".repeat(200)}`), StrictJsonError);
  assert.throws(() => parseStrictJsonBytes(Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), StrictJsonError, "BOM");
  assert.throws(() => parseStrictJsonBytes(Buffer.from([0x22, 0xff, 0x22])), StrictJsonError, "invalid UTF-8");
  assert.deepEqual(parseStrictJsonBytes(Buffer.from('{"ok":true}')), { ok: true });
});
