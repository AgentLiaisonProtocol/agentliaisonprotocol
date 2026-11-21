// The safety rules of http.mjs (README "What it sends").
import "./guard.mjs";
import { test } from "node:test";
import { EventEmitter } from "node:events";
import assert from "node:assert/strict";
import { createHttp, createNodeFetch, requestOptions, guardedLookup, isPublicAddress, hostRefusal, parseDevMap, excerpt, isJsonType, parseChallenges, MAX_REQUESTS, MAX_BYTES } from "../http.mjs";
import { stubTransport, PUBLIC_ADDRESS } from "./transport-stub.mjs";
import { USER_AGENT } from "../catalog.mjs";

/** A recording fetch: `answer(url, init)` returns a Response (or a promise of one). */
function recorder(answer) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return answer(url, init);
  };
  return { fetch, calls };
}

test("a redirect is reported, never followed", async () => {
  const { fetch, calls } = recorder(() => new Response("", { status: 302, headers: { location: "https://broker.example.org/elsewhere" } }));
  const http = createHttp({ fetch });
  http.allowOrigin("https://broker.example.org");
  const r = await http.request({ url: "https://broker.example.org/.well-known/jwks.json" });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.redirect, "manual");
  assert.equal(r.status, 302);
  assert.equal(r.location, "https://broker.example.org/elsewhere");
});

test("at most 256 KiB of a response is read", async () => {
  const big = new Uint8Array(4 * 1024 * 1024).fill(0x61);
  let pulled = 0;
  const { fetch } = recorder(() => new Response(new ReadableStream({
    pull(c) { if (pulled >= big.length) return c.close(); c.enqueue(big.subarray(pulled, pulled + 65536)); pulled += 65536; },
  }), { status: 200 }));
  const http = createHttp({ fetch });
  http.allowOrigin("https://broker.example.org");
  const r = await http.request({ url: "https://broker.example.org/big" });
  assert.equal(r.truncated, true);
  assert.equal(r.size, null);
  assert.equal(r.bytes.length, MAX_BYTES);
  assert.ok(pulled < big.length, "the stream is cancelled, not read to the end");
});

test("a run makes at most 80 requests", async () => {
  const { fetch, calls } = recorder(() => new Response("{}", { status: 200 }));
  const http = createHttp({ fetch });
  http.allowOrigin("https://broker.example.org");
  const results = [];
  for (let i = 0; i < MAX_REQUESTS + 5; i++) results.push(await http.request({ method: "POST", url: "https://broker.example.org/federation/inbox", body: "{}" }));
  assert.equal(calls.length, MAX_REQUESTS);
  assert.equal(http.count, MAX_REQUESTS);
  assert.equal(results.filter((r) => r.error?.kind === "cap").length, 5);
});

test("requests go one at a time", async () => {
  let active = 0;
  let most = 0;
  const { fetch } = recorder(async () => {
    active++; most = Math.max(most, active);
    await new Promise((r) => setTimeout(r, 5));
    active--;
    return new Response("{}", { status: 200 });
  });
  const http = createHttp({ fetch });
  http.allowOrigin("https://broker.example.org");
  await Promise.all([1, 2, 3, 4, 5].map((i) => http.request({ method: "POST", url: `https://broker.example.org/p${i}`, body: "{}" })));
  assert.equal(most, 1);
});

test("nothing outside the allowed URLs and origins is contacted", async () => {
  const { fetch, calls } = recorder(() => new Response("{}", { status: 200 }));
  const http = createHttp({ fetch });
  http.allowOrigin("https://broker.example.org");
  http.allowUrl("https://example.org/.well-known/alp.json");
  for (const url of [
    "https://outside.example/anything",
    "https://example.org/.well-known/other.json",
    "https://broker.example.org.outside.example/x",
    "https://user:pw@broker.example.org/x",
    "http://broker.example.org/x",
    "file:///etc/hosts",
    "not a url",
  ]) {
    const r = await http.request({ url });
    assert.ok(r.error && ["not-allowed", "not-https"].includes(r.error.kind), url);
  }
  assert.equal(calls.length, 0);
  await http.request({ url: "https://example.org/.well-known/alp.json" });
  await http.request({ url: "https://broker.example.org/mcp" });
  assert.deepEqual(calls.map((c) => c.url), ["https://example.org/.well-known/alp.json", "https://broker.example.org/mcp"]);
});

test("IP addresses, loopback, single-label and special-use names are never contacted without the development host map", async () => {
  const { fetch, calls } = recorder(() => new Response("{}", { status: 200 }));
  const http = createHttp({ fetch });
  for (const origin of [
    "https://127.0.0.1", "https://10.0.0.8:8443", "https://[::1]", "https://[::ffff:7f00:1]", "https://0x7f000001", "https://2130706433", "https://0177.0.0.1",
    "https://localhost", "https://localhost.", "https://localhost.:8443", "https://broker.localhost", "https://broker.localhost.",
    "https://intranet", "https://intranet.", "https://metadata.cloud.internal", "https://printer.local", "https://router.home.arpa", "https://x.onion",
    "https://broker.partner.example", "https://broker.test", "https://broker.alp-check.invalid",
  ]) {
    http.allowOrigin(origin);
    const r = await http.request({ url: `${origin}/.well-known/jwks.json` });
    assert.equal(r.error?.kind, "not-allowed", origin);
  }
  assert.equal(calls.length, 0);
});

test("the address classifier refuses every address that is not public unicast", () => {
  const notPublic = [
    "0.0.0.0", "0.255.255.255", "10.0.0.1", "10.255.255.255", "100.64.0.1", "100.127.255.255", "127.0.0.1", "127.255.255.254",
    "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1",
    "198.19.255.255", "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
    "::", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.1.2.3", "::ffff:169.254.169.254", "::127.0.0.1", "::8.8.4.4",
    "64:ff9b::7f00:1", "64:ff9b::10.0.0.1", "64:ff9b:1::1", "2002:7f00:1::", "2002:a00:1::1", "fc00::1", "fd00::1",
    "fdff:ffff::1", "fe80::1", "febf::1", "fec0::1", "ff00::1", "ff02::1", "100::1", "2001::1", "2001:0:4136:e378::1",
    "2001:1ff::1", "2001:db8::1", "2001:db8:ffff::1", "3fff::1", "4000::1", "fe80::1%en0", "not an address", "", "1.2.3",
  ];
  for (const a of notPublic) assert.equal(isPublicAddress(a), false, a);
  const isPublic = [PUBLIC_ADDRESS, "1.1.1.1", "9.9.9.9", "100.63.255.255", "100.128.0.1", "172.15.255.255", "172.32.0.1", "192.0.1.1",
    "192.88.98.255", "192.169.0.1", "198.17.255.255", "198.20.0.1", "223.255.255.255", "::ffff:11.22.33.44", "64:ff9b::b16:212c",
    "2002:b16:212c::1", "2001:200::1", "2400:cb00::1", "2a00:1450::1", "3ffe::1"];
  for (const a of isPublic) assert.equal(isPublicAddress(a), true, a);
});

test("host names: one trailing dot is stripped before every test", () => {
  for (const h of ["localhost.", "x.localhost.", "intranet.", "printer.local.", "127.0.0.1"]) assert.ok(hostRefusal(h), h);
  for (const h of ["broker.example.org", "broker.example.org.", "alp.example.net"]) assert.equal(hostRefusal(h), null, h);
});

test("the guarded lookup resolves once, refuses a host with any non-public answer, and returns exactly what it checked", async () => {
  const answers = { "mixed.example.org": ["11.22.33.44", "10.0.0.5"], "v6.example.org": ["2400:cb00::1", "::ffff:127.0.0.1"], "ok.example.org": ["11.22.33.44", "2400:cb00::1"] };
  const calls = [];
  const resolve = (name, options, cb) => { calls.push({ name, options }); process.nextTick(cb, null, answers[name].map((address) => ({ address, family: address.includes(":") ? 6 : 4 }))); };
  const lookup = guardedLookup(resolve);
  assert.equal(lookup.guarded, true);
  const all = (name) => new Promise((done) => lookup(name, { all: true }, (err, list) => done({ err, list })));
  const one = (name) => new Promise((done) => lookup(name, {}, (err, address, family) => done({ err, address, family })));
  const oneNoOptions = (name) => new Promise((done) => lookup(name, (err, address, family) => done({ err, address, family })));
  for (const name of ["mixed.example.org", "v6.example.org"]) {
    const r = await all(name);
    assert.equal(r.err?.code, "ALP_CHECK_NOT_PUBLIC", name);
    assert.equal((await one(name)).err?.code, "ALP_CHECK_NOT_PUBLIC", name);
  }
  const r = await all("ok.example.org");
  assert.deepEqual(r.list, [{ address: "11.22.33.44", family: 4 }, { address: "2400:cb00::1", family: 6 }]);
  assert.deepEqual(await one("ok.example.org"), { err: null, address: "11.22.33.44", family: 4 });
  assert.deepEqual(await oneNoOptions("ok.example.org."), { err: null, address: "11.22.33.44", family: 4 });
  assert.equal(calls.length, 7, "one resolution per lookup");
  assert.ok(calls.every((c) => c.options.all === true && c.options.verbatim === true));
  assert.equal(calls.at(-1).name, "ok.example.org", "the trailing dot is stripped before resolving");
  const refused = await all("localhost.");
  assert.equal(refused.err?.code, "ALP_CHECK_NOT_PUBLIC");
  assert.equal(calls.length, 7, "a refused name is never resolved");
});

test("every request the transport builds carries the guarded lookup, no shared agent and TLS verification", async () => {
  const fake = (url) => new Response(`{"url":${JSON.stringify(url)}}`, { status: 200, headers: { "content-type": "application/json" } });
  const t = stubTransport(fake, { "broker.example.org": ["11.22.33.44"] });
  const http = createHttp({ transport: t });
  http.allowOrigin("https://broker.example.org");
  const r = await http.request({ url: "https://broker.example.org/.well-known/jwks.json" });
  await http.request({ method: "POST", url: "https://broker.example.org/federation/inbox", body: "{}" });
  assert.equal(r.status, 200);
  assert.equal(t.built.length, 2);
  for (const o of t.built) {
    assert.equal(o.lookup.guarded, true);
    assert.equal(o.agent, false);
    assert.equal(o.rejectUnauthorized, true);
    assert.equal(o.servername, "broker.example.org");
    assert.equal(o.headers["accept-encoding"], "identity");
  }
  assert.deepEqual(t.connections.map((c) => c.addresses), [["11.22.33.44"], ["11.22.33.44"]]);
  assert.throws(() => requestOptions("http://broker.example.org/x", {}, { lookup: () => {} }), /plain HTTP/);
  const plain = requestOptions("http://127.0.0.1:47201/x", {}, { lookup: () => {} });
  assert.equal(plain.lookup.guarded, true);
  assert.notEqual(plain.lookup, requestOptions("https://broker.example.org/x", {}, { lookup: guardedLookup() }).lookup);
});

test("a host that resolves to a non-public address is refused and never connected to", async () => {
  const t = stubTransport(() => new Response("{}", { status: 200 }), { "internal.example.org": ["11.22.33.44", "10.0.0.5"], "broker.example.org": ["fd00::7"] });
  const http = createHttp({ transport: t });
  http.allowOrigin("https://internal.example.org");
  http.allowOrigin("https://broker.example.org");
  for (const url of ["https://internal.example.org/x", "https://broker.example.org/y"]) {
    const r = await http.request({ url });
    assert.equal(r.status, null);
    assert.equal(r.error.kind, "not-allowed", url);
    assert.match(r.error.message, /not public/);
  }
  assert.equal(t.connections.length, 0);
});

test("each connection resolves the name afresh: a name that answers public, then private, is refused the second time", async () => {
  const fake = (url) => new Response(`{"url":${JSON.stringify(url)}}`, { status: 200, headers: { "content-type": "application/json" } });
  const t = stubTransport(fake);
  const answers = ["11.22.33.44", "10.0.0.5", "11.22.33.44"];
  const lookups = [];
  const resolve = (name, options, cb) => {
    const address = answers[lookups.length % answers.length];
    lookups.push({ name, address });
    process.nextTick(cb, null, [{ address, family: 4 }]);
  };
  const http = createHttp({ transport: { resolve, request: t.request } });
  http.allowOrigin("https://rebind.example.org");
  const first = await http.request({ url: "https://rebind.example.org/a" });
  const second = await http.request({ url: "https://rebind.example.org/b" });
  const third = await http.request({ method: "POST", url: "https://rebind.example.org/c", body: "{}" });
  assert.equal(first.status, 200);
  assert.equal(second.status, null);
  assert.equal(second.error.kind, "not-allowed");
  assert.match(second.error.message, /not public \(10\.0\.0\.5\)/);
  assert.equal(third.status, 200);
  assert.equal(lookups.length, 3, "one lookup per request, never a cached answer");
  assert.equal(lookups.length, t.built.length, "lookups equal requests");
  assert.equal(t.connections.length, 2, "the refused answer is never connected to");
});

test("the transport itself refuses an https URL whose host is an IP address, even without the allow-list", () => {
  for (const url of ["https://10.0.0.1/x", "https://127.0.0.1/x", "https://[::1]/x", "https://[fd00::1]:8443/x", "https://11.22.33.44/x"]) {
    assert.throws(() => requestOptions(url, {}, { lookup: guardedLookup() }), (e) => e.code === "ALP_CHECK_NOT_PUBLIC", url);
  }
  // Plain HTTP goes only to loopback literals (development host map targets), whatever the port.
  assert.equal(requestOptions("http://127.0.0.1/x", {}, { lookup: () => {} }).port, 80);
  assert.throws(() => requestOptions("http://10.0.0.1:8080/x", {}, { lookup: () => {} }), /plain HTTP/);
});

test("the node transport stops at the timeout, even while the lookup waits", async () => {
  const resolve = () => {}; // never answers
  const request = (options) => {
    const req = new EventEmitter();
    req.destroy = (err) => { process.nextTick(() => req.emit("error", err)); return req; };
    req.end = () => { options.lookup(options.hostname, { all: true }, () => {}); return req; };
    return req;
  };
  const http = createHttp({ transport: { resolve, request }, timeoutMs: 30 });
  http.allowOrigin("https://broker.example.org");
  const r = await http.request({ url: "https://broker.example.org/slow" });
  assert.equal(r.error.kind, "timeout");
});

test("an encoded answer is not read", async () => {
  const { fetch } = recorder(() => new Response("compressed", { status: 200, headers: { "content-encoding": "gzip", "content-type": "application/json" } }));
  const http = createHttp({ fetch });
  http.allowOrigin("https://broker.example.org");
  const r = await http.request({ url: "https://broker.example.org/x" });
  assert.equal(r.error.kind, "encoded");
  assert.equal(r.text, "");
});

test("a request for one broker entry goes only to that entry's own origin, within its share of the limit", async () => {
  const { fetch, calls } = recorder(() => new Response("{}", { status: 200 }));
  const http = createHttp({ fetch, maxRequests: 10 });
  http.allowOrigin("https://broker.example.org");
  http.allowOrigin("https://hosted.example.net");
  const off = await http.request({ url: "https://hosted.example.net/mcp", within: ["https://broker.example.org"] });
  assert.equal(off.error.kind, "not-allowed");
  assert.equal(calls.length, 0);
  http.shareAmong(2);
  const a = [];
  for (let i = 0; i < 7; i++) a.push(await http.request({ method: "POST", url: `https://broker.example.org/p${i}`, body: "{}", entry: "https://broker.example.org" }));
  assert.equal(a.filter((r) => r.status === 200).length, 5);
  assert.equal(a.filter((r) => r.error?.kind === "cap").length, 2);
  const b = await http.request({ method: "POST", url: "https://hosted.example.net/p", body: "{}", entry: "https://hosted.example.net" });
  assert.equal(b.status, 200, "the second entry still has its share");
  assert.equal(http.stopped, 2);
});

test("every request carries the User-Agent and no credentials", async () => {
  const { fetch, calls } = recorder(() => new Response("{}", { status: 200 }));
  const http = createHttp({ fetch });
  http.allowOrigin("https://broker.example.org");
  await http.request({ method: "POST", url: "https://broker.example.org/mcp", headers: { "content-type": "application/json" }, body: "{}" });
  const { headers, credentials } = calls[0].init;
  assert.equal(headers["user-agent"], USER_AGENT);
  assert.equal(credentials, "omit");
  for (const k of Object.keys(headers)) assert.ok(!/^(authorization|cookie|proxy-authorization)$/i.test(k), k);
});

test("a request that does not finish within the timeout is abandoned", async () => {
  const { fetch } = recorder((url, init) => new Promise((_, reject) => {
    init.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
  }));
  const http = createHttp({ fetch, timeoutMs: 30 });
  http.allowOrigin("https://broker.example.org");
  const r = await http.request({ url: "https://broker.example.org/slow" });
  assert.equal(r.error.kind, "timeout");
});

test("the timeout holds even when fetch ignores the abort signal", async () => {
  const { fetch } = recorder(() => new Promise(() => {}));
  const http = createHttp({ fetch, timeoutMs: 30 });
  http.allowOrigin("https://broker.example.org");
  const r = await http.request({ url: "https://broker.example.org/never" });
  assert.equal(r.error.kind, "timeout");
});

test("transport failures are classified", async () => {
  const fail = (code) => recorder(() => { throw Object.assign(new TypeError("fetch failed"), { cause: { code } }); }).fetch;
  for (const [code, kind] of [["ENOTFOUND", "dns"], ["CERT_HAS_EXPIRED", "tls"], ["ERR_TLS_CERT_ALTNAME_INVALID", "tls"], ["ECONNREFUSED", "network"]]) {
    const http = createHttp({ fetch: fail(code) });
    http.allowOrigin("https://broker.example.org");
    const r = await http.request({ url: "https://broker.example.org/x" });
    assert.equal(r.error.kind, kind, code);
  }
});

test("a GET of the same URL is sent once", async () => {
  const { fetch, calls } = recorder(() => new Response("{}", { status: 200 }));
  const http = createHttp({ fetch });
  http.allowOrigin("https://broker.example.org");
  await http.request({ url: "https://broker.example.org/a" });
  await http.request({ url: "https://broker.example.org/a" });
  assert.equal(calls.length, 1);
});

test("the development host map rewrites mapped origins and refuses the rest", async () => {
  const devMap = parseDevMap('{"https://example.org":"http://127.0.0.1:47201","https://broker.example.org":"http://127.0.0.1:47202"}');
  const { fetch, calls } = recorder(() => new Response("{}", { status: 200 }));
  const http = createHttp({ fetch, devMap });
  http.allowUrl("https://example.org/.well-known/alp.json");
  http.allowUrl("https://alp.example.org/.well-known/alp.json");
  http.allowOrigin("https://broker.example.org");
  await http.request({ url: "https://example.org/.well-known/alp.json" });
  await http.request({ url: "https://broker.example.org/federation/inbox?x=1", method: "POST", body: "{}" });
  const r = await http.request({ url: "https://alp.example.org/.well-known/alp.json" });
  assert.deepEqual(calls.map((c) => c.url), ["http://127.0.0.1:47201/.well-known/alp.json", "http://127.0.0.1:47202/federation/inbox?x=1"]);
  assert.equal(r.error.kind, "not-mapped");
});

test("the development host map takes only reserved names and loopback targets", () => {
  assert.throws(() => parseDevMap('{"https://agentliaisonprotocol.org":"http://127.0.0.1:8080"}'), /reserved name/);
  assert.throws(() => parseDevMap('{"https://example.org":"http://10.0.0.1:8080"}'), /127\.0\.0\.1/);
  assert.throws(() => parseDevMap('{"https://example.org":"https://127.0.0.1:8080"}'), /127\.0\.0\.1/);
  assert.throws(() => parseDevMap('{"http://example.org":"http://127.0.0.1:8080"}'), /https origin/);
  assert.throws(() => parseDevMap('{"https://example.org/path":"http://127.0.0.1:8080"}'), /https origin/);
  assert.throws(() => parseDevMap("[]"), /object/);
  assert.throws(() => parseDevMap("{}"), /empty/);
  assert.throws(() => parseDevMap('{"https://alp.example.org":"http://localhost:9000"}'), /127\.0\.0\.1/);
  assert.equal(parseDevMap('{"https://alp.example.org":"http://[::1]:9000"}').size, 1);
  // A target must be written as a URL parser writes its origin: no default port, no leading zeros, no port 0.
  for (const to of ["http://127.0.0.1:80", "http://127.0.0.1:0080", "http://127.0.0.1:0", "http://[::1]:80", "http://127.0.0.1:65536"]) {
    assert.throws(() => parseDevMap(JSON.stringify({ "https://example.org": to })), /127\.0\.0\.1/, to);
  }
});

test("an excerpt shows at most 400 characters and escapes control characters", () => {
  const e = excerpt("a".repeat(1000));
  assert.ok(e.startsWith("a".repeat(400) + " ["));
  assert.match(e, /600 more characters not shown/);
  assert.equal(excerpt("\u001b[31mred" + String.fromCharCode(0x202e)), "\\u001b[31mred\\u202e");
  // Every control (Cc) and format (Cf) character, not a hand list: U+061C, U+00AD and U+180E among them.
  assert.equal(excerpt("a\u061cb\u00adc\u180ed\u2028e\u{e0001}f\u0085"), "a\\u061cb\\u00adc\\u180ed\\u2028e\\u{e0001}f\\u0085");
});

test("JSON content types", () => {
  for (const t of ["application/json", "application/json; charset=utf-8", "Application/JSON", "application/jwk-set+json", "application/problem+json"]) assert.ok(isJsonType(t), t);
  for (const t of [null, "", "text/html", "text/json", "application/jsonp", "application/json-seq"]) assert.ok(!isJsonType(t), String(t));
});

test("WWW-Authenticate challenges are parsed", () => {
  const [b] = parseChallenges('Bearer resource_metadata="https://broker.example.org/.well-known/oauth-protected-resource/mcp", scope="read send"');
  assert.equal(b.scheme, "Bearer");
  assert.equal(b.params.resource_metadata, "https://broker.example.org/.well-known/oauth-protected-resource/mcp");
  assert.equal(b.params.scope, "read send");
  const two = parseChallenges('Basic realm="x", Bearer error="invalid_token", scope=read, resource_metadata="https://a.example/m"');
  assert.deepEqual(two.map((c) => c.scheme), ["Basic", "Bearer"]);
  assert.equal(two[1].params.scope, "read");
  assert.equal(two[1].params.resource_metadata, "https://a.example/m");
  assert.deepEqual(parseChallenges(""), []);
  assert.deepEqual(parseChallenges('Bearer realm="a\\"b"')[0].params.realm, 'a"b');
});
