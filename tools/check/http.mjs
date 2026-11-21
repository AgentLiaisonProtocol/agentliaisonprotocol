// The only place alp-check makes requests. Licensed under Apache-2.0.
//
// Safety rules (README "What it sends"):
// - HTTPS only, except through a development host map, which maps published https origins of reserved names to
//   http://127.0.0.1:<port> or http://[::1]:<port>; with a map, an origin the map doesn't name is not contacted and
//   no name is resolved.
// - Requests go out through node:https with a lookup of alp-check's own: the name is resolved once, the host is
//   refused if any address is not a public unicast address, and the connection is made only to the addresses that
//   were checked. No connection is reused between requests. TLS verification is never turned off.
// - Never follows a redirect: a 3xx answer is returned as it is, with its Location header.
// - Reads at most 256 KiB of a response, asks for no content encoding, and waits at most the timeout for the whole
//   exchange (lookup, connection, TLS and body).
// - At most 80 requests in a run, one at a time, each broker entry within its share once the entries are known.
//   A GET of the same URL is answered from the first response.
// - Sends no credentials and no cookies; every request carries the alp-check User-Agent.
// - Contacts only URLs the runner allowed: exact URLs (the domain's two well-known locations, an authorization
//   server's metadata) and origins (a broker entry's own origin, or URLs given on the command line); a request made
//   for one broker entry goes only to that entry's own origin.
import https from "node:https";
import http from "node:http";
import dns from "node:dns";
import net from "node:net";
import { Readable } from "node:stream";
import { USER_AGENT } from "./catalog.mjs";

export const MAX_REQUESTS = 80;
export const MAX_BYTES = 256 * 1024;
export const EXCERPT_CHARS = 400;

const RESERVED_HOST = /(^|\.)(example|test|invalid|localhost)$|(^|\.)example\.(com|net|org)$/;
const IP_LITERAL = /^[0-9.]+$/;
const LOOPBACK_TARGET = /^http:\/\/(127\.0\.0\.1|\[::1\]):([0-9]{1,5})$/;
// Special-use names that never name a public host (RFC 6761, RFC 6762, RFC 7686, RFC 8375, RFC 9476, and the
// widely used .internal). .example, .invalid and .test are reached only through the development host map.
const SPECIAL_USE = /(^|\.)(localhost|local|internal|home\.arpa|onion|alt|arpa|example|invalid|test)$/;

// ---------------------------------------------------------------- addresses

// IPv4 blocks that are not public unicast: [first address, prefix length].
const V4_BLOCKED = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
].map(([a, n]) => [v4Number(a), n]);

function v4Number(text) {
  const parts = text.split(".");
  if (parts.length !== 4 || !parts.every((p) => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255)) return null;
  return parts.reduce((n, p) => n * 256 + Number(p), 0);
}

function v4Public(n) {
  for (const [base, len] of V4_BLOCKED) {
    const shift = 32 - len;
    if (Math.floor(n / 2 ** shift) === Math.floor(base / 2 ** shift)) return false;
  }
  return true;
}

/** Eight 16-bit groups of an IPv6 address in text form, or null. */
function v6Groups(text) {
  if (text.includes("%")) return null; // a zone index: link-local by definition
  let s = text;
  const dotted = /^(.*:)([0-9.]+)$/.exec(s);
  if (dotted && dotted[2].includes(".")) {
    const v4 = v4Number(dotted[2]);
    if (v4 == null) return null;
    s = `${dotted[1]}${Math.floor(v4 / 65536).toString(16)}:${(v4 % 65536).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const read = (h) => (h === "" ? [] : h.split(":").map((g) => (/^[0-9a-f]{1,4}$/i.test(g) ? parseInt(g, 16) : NaN)));
  const head = read(halves[0]);
  const rest = halves.length === 2 ? read(halves[1]) : [];
  if (head.some(Number.isNaN) || rest.some(Number.isNaN)) return null;
  const fixed = head.length + rest.length;
  if (halves.length === 1 ? fixed !== 8 : fixed > 7) return null;
  return [...head, ...Array(8 - fixed).fill(0), ...rest];
}

/**
 * Whether an IP address (in the text form a resolver returns) is a public unicast address. IPv6 must be global
 * unicast (2000::/3) outside the blocks set aside for documentation, benchmarking and protocol use; an IPv4-mapped,
 * NAT64 (64:ff9b::/96) or 6to4 address is judged by the IPv4 address inside it; IPv4-compatible addresses (::/96)
 * and local-use NAT64 (64:ff9b:1::/48) are always refused.
 */
export function isPublicAddress(address) {
  if (typeof address !== "string") return false;
  const kind = net.isIP(address);
  if (kind === 4) {
    const n = v4Number(address);
    return n != null && v4Public(n);
  }
  if (kind !== 6) return false;
  const g = v6Groups(address);
  if (!g) return false;
  const v4At = (i) => g[i] * 65536 + g[i + 1];
  const zeros = (from, to) => g.slice(from, to).every((x) => x === 0);
  if (zeros(0, 5) && g[5] === 0xffff) return v4Public(v4At(6)); // ::ffff:a.b.c.d
  if (zeros(0, 6)) return false; // ::, ::1 and IPv4-compatible ::a.b.c.d
  if (g[0] === 0x64 && g[1] === 0xff9b && zeros(2, 6)) return v4Public(v4At(6)); // NAT64, 64:ff9b::/96
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return false; // local-use NAT64, 64:ff9b:1::/48
  if ((g[0] & 0xe000) !== 0x2000) return false; // not global unicast: fc00::/7, fe80::/10, ff00::/8, 100::/64 and the rest
  if (g[0] === 0x2001 && g[1] < 0x0200) return false; // 2001::/23, IETF protocol assignments (Teredo among them)
  if (g[0] === 0x2001 && g[1] === 0x0db8) return false; // 2001:db8::/32, documentation
  if (g[0] === 0x3fff && g[1] < 0x1000) return false; // 3fff::/20, documentation
  if (g[0] === 0x2002) return v4Public(g[1] * 65536 + g[2]); // 6to4 2002::/16
  return true;
}

/** Why a host name may not be contacted outside the development host map, or null. */
export function hostRefusal(hostname) {
  const h = String(hostname).toLowerCase().replace(/\.$/, "");
  if (h.startsWith("[") || net.isIP(h) || IP_LITERAL.test(h)) return "an IP address; alp-check contacts DNS names only (use --dev-map for a local broker)";
  if (h === "localhost" || h.endsWith(".localhost")) return "a loopback name; alp-check contacts public DNS names only (use --dev-map for a local broker)";
  if (!h.includes(".")) return "a single-label name, which names no public host";
  if (SPECIAL_USE.test(h)) return "a special-use name, which names no public host";
  return null;
}

const notPublic = (message) => Object.assign(new Error(message), { code: "ALP_CHECK_NOT_PUBLIC" });

/**
 * A lookup for node:net that resolves the name once, refuses the host if any answer is not a public unicast
 * address, and hands the connection exactly the addresses it checked. It answers both shapes Node asks for:
 * `all: true` gives [{ address, family }], otherwise (address, family). `resolve` has the shape of dns.lookup.
 */
export function guardedLookup(resolve = (...a) => dns.lookup(...a)) {
  const lookup = function lookup(hostname, options, callback) {
    if (typeof options === "function") { callback = options; options = {}; }
    else if (typeof options === "number") options = { family: options };
    else options = options ?? {};
    const name = String(hostname).replace(/\.$/, "");
    const refusal = hostRefusal(name);
    if (refusal) { process.nextTick(callback, notPublic(`${name} is ${refusal}`)); return; }
    const family = options.family === 4 || options.family === 6 ? options.family : 0;
    resolve(name, { all: true, verbatim: true, family }, (err, addresses) => {
      if (err) { callback(err); return; }
      const list = (Array.isArray(addresses) ? addresses : [{ address: addresses }]).map((a) => ({ address: a?.address, family: net.isIP(a?.address ?? "") }));
      if (!list.length) { callback(Object.assign(new Error(`${name} has no address records`), { code: "ENOTFOUND" })); return; }
      const bad = list.find((a) => !isPublicAddress(a.address));
      if (bad) { callback(notPublic(`${name} resolves to an address that is not public (${bad.address})`)); return; }
      if (options.all) callback(null, list);
      else callback(null, list[0].address, list[0].family);
    });
  };
  lookup.guarded = true;
  return lookup;
}

/** The lookup for development host map targets: loopback literals only, never DNS. */
function loopbackLookup(hostname, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  const h = String(hostname).replace(/^\[|\]$/g, "");
  if (h !== "127.0.0.1" && h !== "::1") { process.nextTick(callback, notPublic(`${h} is not a loopback address`)); return; }
  const a = { address: h, family: h === "::1" ? 6 : 4 };
  if (options?.all) callback(null, [a]);
  else callback(null, a.address, a.family);
}
loopbackLookup.guarded = true;

/**
 * Build the node:https (or, for a development host map target, node:http) request options for one request.
 * Exported for tests: every request carries a guarded lookup, no shared agent, and TLS verification.
 */
export function requestOptions(url, init, { lookup }) {
  const u = new URL(url);
  const plain = u.protocol === "http:";
  if (plain && u.hostname !== "127.0.0.1" && u.hostname !== "[::1]") throw notPublic("plain HTTP is used only for development host map targets on loopback");
  const host = u.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  // Node does not call the lookup for an IP literal, so the address rule could not run: refuse it here as well as
  // in the allow-list, whatever the caller.
  if (!plain && net.isIP(host)) throw notPublic(`${host} is an IP address; alp-check contacts DNS names only`);
  const options = {
    protocol: u.protocol,
    hostname: host,
    port: u.port ? Number(u.port) : plain ? 80 : 443,
    path: `${u.pathname}${u.search}`,
    method: init.method ?? "GET",
    headers: { ...(init.headers ?? {}) },
    agent: false,
    lookup: plain ? loopbackLookup : lookup,
  };
  if (!plain) Object.assign(options, { servername: host, rejectUnauthorized: true });
  return options;
}

/**
 * A function with the shape of fetch (as alp-check uses it) built on node:https. `resolve` replaces dns.lookup and
 * `request` replaces https.request and http.request (tests only; they never open a socket).
 */
export function createNodeFetch({ resolve, request } = {}) {
  const lookup = guardedLookup(resolve);
  return (url, init = {}) => new Promise((done, fail) => {
    let options;
    try { options = requestOptions(url, init, { lookup }); } catch (e) { fail(e); return; }
    const send = request ?? ((opts, cb) => (opts.protocol === "http:" ? http.request(opts, cb) : https.request(opts, cb)));
    let req;
    try {
      req = send(options, (res) => {
        const headers = new Headers();
        const raw = res.rawHeaders ?? [];
        for (let i = 0; i + 1 < raw.length; i += 2) { try { headers.append(raw[i], raw[i + 1]); } catch { /* a header Headers refuses is dropped */ } }
        const status = res.statusCode;
        if (!(status >= 200 && status <= 599)) { res.destroy?.(); fail(Object.assign(new Error(`status ${status}`), { code: "EBADSTATUS" })); return; }
        done({ status, headers, body: Readable.toWeb(res) });
      });
    } catch (e) { fail(e); return; }
    req.on("error", fail);
    const signal = init.signal;
    if (signal) {
      const abort = () => req.destroy(Object.assign(new Error("aborted"), { name: "AbortError" }));
      if (signal.aborted) abort(); else signal.addEventListener("abort", abort, { once: true });
    }
    if (init.body != null) req.end(init.body); else req.end();
  });
}

/** Validate a development host map given as JSON text. Returns a Map of origin to loopback base, or throws. */
export function parseDevMap(text) {
  let obj;
  try { obj = JSON.parse(text); } catch { throw new Error("--dev-map is not JSON"); }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) throw new Error("--dev-map must be a JSON object");
  const map = new Map();
  for (const [from, to] of Object.entries(obj)) {
    let u;
    try { u = new URL(from); } catch { throw new Error(`--dev-map: ${from} is not a URL`); }
    if (u.protocol !== "https:" || u.origin !== from) throw new Error(`--dev-map: ${from} must be an https origin, with no path or trailing slash`);
    if (!RESERVED_HOST.test(u.hostname)) throw new Error(`--dev-map: ${from} is not a reserved name (RFC 2606: .example, .test, .invalid, .localhost, example.com, example.net, example.org)`);
    let target = null;
    try { target = new URL(to); } catch { /* refused below */ }
    // Written exactly as a URL parser writes the origin, so the transport sees the same port: no port 80 (the default,
    // which the origin drops), no leading zeros, a port from 1 to 65535.
    if (typeof to !== "string" || !LOOPBACK_TARGET.test(to) || !target || target.origin !== to || Number(target.port) < 1) {
      throw new Error(`--dev-map: ${from} must map to http://127.0.0.1:<port> or http://[::1]:<port>, with a port from 1 to 65535 other than 80, written without leading zeros`);
    }
    map.set(from, to);
  }
  if (map.size === 0) throw new Error("--dev-map is empty");
  return map;
}

// Every Unicode control (Cc), format (Cf), line and paragraph separator (Zl, Zp) and lone surrogate (Cs)
// character: any of them can hide, reorder or rewrite text in a terminal.
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/gu;

const escapeChar = (c) => {
  const cp = c.codePointAt(0);
  return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, "0")}`;
};

/** A printable excerpt: at most `n` characters, with control and format characters shown as escapes. */
export function excerpt(text, n = EXCERPT_CHARS) {
  if (text == null) return "";
  const s = String(text);
  const cut = s.length > n ? s.slice(0, n) : s;
  const safe = cut.replace(UNPRINTABLE, escapeChar);
  return s.length > n ? `${safe} [${s.length - n} more characters not shown]` : safe;
}

/** A value from a target as text that is safe to put in a message: strings as they are, anything else as JSON. */
export function show(value) {
  if (typeof value === "string") return value;
  try { return JSON.stringify(value) ?? String(value); } catch { return "(a value alp-check cannot show)"; }
}

const TLS_CODE = /^(CERT_|ERR_TLS_|ERR_SSL_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_|HOSTNAME_)/;
// Certificate verification failures: expired, not yet valid, wrong host, untrusted or broken chain. Every client
// sees the same certificate, unlike a reset handshake or a protocol error, which may be the checker's own network.
const CERTIFICATE_CODE = /^(CERT_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_|HOSTNAME_|ERR_TLS_CERT_ALTNAME_INVALID$)/;

function classify(err) {
  let e = err;
  for (let i = 0; i < 4 && e; i++) {
    if (e.name === "AbortError" || e.name === "TimeoutError") return { kind: "timeout", message: "no complete answer within the timeout" };
    const code = e.code;
    if (code === "ALP_CHECK_NOT_PUBLIC") return { kind: "not-allowed", message: `not contacted: ${e.message}` };
    if (code === "ENOTFOUND" || code === "ENODATA") return { kind: "dns", noAddress: true, message: `the name has no address records (${code})` };
    if (code === "EAI_AGAIN") return { kind: "dns", noAddress: false, message: "the name could not be resolved now (EAI_AGAIN)" };
    if (typeof code === "string" && CERTIFICATE_CODE.test(code)) return { kind: "tls", certificate: true, code, message: `TLS failure: the certificate did not validate (${code})` };
    if (typeof code === "string" && TLS_CODE.test(code)) return { kind: "tls", certificate: false, code, message: `TLS failure (${code})` };
    if (typeof code === "string" && /^E[A-Z]+$/.test(code)) return { kind: "network", message: `network failure (${code})` };
    e = e.cause;
  }
  return { kind: "network", message: "network failure" };
}

/**
 * Create the request layer. `fetch` has the shape of the global fetch and replaces the node:https transport (tests
 * pass an in-memory one); `transport` passes { resolve, request } to the node:https transport instead (tests only).
 * `devMap` is the Map from parseDevMap, or null.
 */
export function createHttp({ fetch = null, transport = {}, timeoutMs = 10_000, devMap = null, maxRequests = MAX_REQUESTS, maxBytes = MAX_BYTES } = {}) {
  const send = fetch ?? createNodeFetch(transport);
  const allowedUrls = new Map();
  const allowedOrigins = new Map();
  const cache = new Map();
  const log = [];
  const perEntry = new Map();
  let share = null;
  let queue = Promise.resolve();
  let sent = 0;
  let stopped = 0;

  function allowUrl(url, why) { allowedUrls.set(new URL(url).href, why); }
  function allowOrigin(origin, why) { allowedOrigins.set(new URL(origin).origin, why); }

  /** Give each of `n` broker entries an equal share of the requests that are left. */
  function shareAmong(n) {
    if (n > 0) share = Math.max(1, Math.floor((maxRequests - sent) / n));
  }

  /**
   * Whether a URL may be contacted, and why not. `within` is the list of origins a request for one broker entry
   * may go to (that entry's own origin).
   */
  function permitted(url, within = null) {
    let u;
    try { u = new URL(url); } catch { return { ok: false, kind: "not-allowed", message: "not a URL" }; }
    if (u.username || u.password) return { ok: false, kind: "not-allowed", message: "the URL carries credentials; alp-check sends none" };
    if (u.protocol !== "https:") return { ok: false, kind: "not-https", message: "not an https URL; alp-check contacts https URLs only" };
    if (!devMap) {
      const refusal = hostRefusal(u.hostname);
      if (refusal) return { ok: false, kind: "not-allowed", message: `the host is ${refusal}` };
    }
    if (!allowedUrls.has(u.href) && !allowedOrigins.has(u.origin))
      return { ok: false, kind: "not-allowed", message: "not on an origin alp-check may contact (the domain's two well-known locations, a broker entry's own origin, the authorization server's metadata)" };
    if (within && !within.includes(u.origin)) return { ok: false, kind: "not-allowed", message: "not on the broker entry's own origin, so alp-check does not contact it for this entry" };
    if (devMap && !devMap.has(u.origin)) return { ok: false, kind: "not-mapped", message: "the development host map does not name this origin, so alp-check does not contact it" };
    return { ok: true, url: u };
  }

  async function perform({ method, url, headers, body, within, entry }) {
    const started = Date.now();
    const record = { method, url, status: null, headers: {}, location: null, bytes: Buffer.alloc(0), size: 0, truncated: false, text: "", error: null, elapsedMs: 0, sentBody: body == null ? null : excerpt(body) };
    const p = permitted(url, within);
    if (!p.ok) {
      record.error = { kind: p.kind, message: p.message };
      log.push({ method, url: excerpt(url), outcome: `not contacted: ${p.message}` });
      return record;
    }
    const used = entry ? perEntry.get(entry) ?? 0 : 0;
    if (sent >= maxRequests || (entry && share != null && used >= share)) {
      const whole = sent >= maxRequests;
      record.error = { kind: "cap", message: whole ? `the run reached its limit of ${maxRequests} requests` : `this broker entry used its share (${share}) of the run's limit of ${maxRequests} requests` };
      stopped++;
      log.push({ method, url: excerpt(url), outcome: "not contacted: request limit reached" });
      return record;
    }
    sent++;
    if (entry) perEntry.set(entry, used + 1);
    let target = p.url.href;
    if (devMap) target = devMap.get(p.url.origin) + p.url.pathname + p.url.search;
    const controller = new AbortController();
    // Every wait races this timer, so the limit holds even if a transport ignores the abort signal.
    let expire;
    const expired = new Promise((_, reject) => { expire = () => reject(Object.assign(new Error("timeout"), { name: "TimeoutError" })); });
    expired.catch(() => {});
    const timer = setTimeout(() => { controller.abort(); expire(); }, timeoutMs);
    const within_ = (x) => Promise.race([x, expired]);
    let reader = null;
    try {
      const res = await within_(send(target, {
        method,
        headers: { "user-agent": USER_AGENT, "accept-encoding": "identity", ...headers },
        body: body ?? undefined,
        redirect: "manual",
        credentials: "omit",
        signal: controller.signal,
      }));
      record.status = res.status;
      for (const [k, v] of res.headers) record.headers[k.toLowerCase()] = v;
      record.location = res.headers.get("location");
      const encoding = (record.headers["content-encoding"] ?? "").trim().toLowerCase();
      if (encoding && encoding !== "identity") {
        record.error = { kind: "encoded", message: `the answer is encoded (Content-Encoding: ${excerpt(encoding, 40)}) although alp-check asked for none, so it was not read` };
        if (res.body) await res.body.cancel().catch(() => {});
        log.push({ method, url: excerpt(url), outcome: `${record.status}, encoded (not read)` });
        return record;
      }
      const chunks = [];
      let total = 0;
      if (res.body) {
        reader = res.body.getReader();
        for (;;) {
          const { done, value } = await within_(reader.read());
          if (done) break;
          total += value.byteLength;
          if (total > maxBytes) {
            const keep = value.byteLength - (total - maxBytes);
            if (keep > 0) chunks.push(Buffer.from(value.buffer, value.byteOffset, keep));
            record.truncated = true;
            await reader.cancel().catch(() => {});
            break;
          }
          chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
        }
      }
      record.bytes = Buffer.concat(chunks);
      record.size = record.truncated ? null : record.bytes.length;
      record.text = record.bytes.toString("utf8");
      log.push({ method, url: excerpt(url), outcome: `${record.status}${record.truncated ? `, over ${maxBytes} bytes (read stopped)` : `, ${record.size} bytes`}` });
    } catch (err) {
      record.error = classify(err);
      controller.abort();
      if (reader) reader.cancel().catch(() => {});
      log.push({ method, url: excerpt(url), outcome: record.error.message });
    } finally {
      clearTimeout(timer);
      record.elapsedMs = Date.now() - started;
    }
    return record;
  }

  /**
   * Make one request, after every earlier one has finished. `within` limits it to a broker entry's own origins;
   * `entry` counts it against that entry's share of the request limit.
   */
  function request({ method = "GET", url, headers = {}, body = null, within = null, entry = null }) {
    const key = `${url} ${within ? within.join(",") : ""}`;
    if (method === "GET" && cache.has(key)) return cache.get(key);
    const run = queue.then(() => perform({ method, url, headers, body, within, entry }));
    queue = run.catch(() => {});
    if (method === "GET") cache.set(key, run);
    return run;
  }

  return {
    allowUrl,
    allowOrigin,
    permitted,
    request,
    shareAmong,
    get log() { return log; },
    get count() { return sent; },
    get stopped() { return stopped; },
    devMap,
  };
}

/** True when the content type is application/json or application/<name>+json, with any parameters. */
export function isJsonType(value) {
  if (!value) return false;
  const essence = value.split(";")[0].trim().toLowerCase();
  return essence === "application/json" || /^application\/[a-z0-9!#$&^_.-]+\+json$/.test(essence);
}

/**
 * Parse WWW-Authenticate (RFC 9110 Section 11.6.1) into [{ scheme, params }]. Several challenges may be joined by
 * commas in one header value. Unparseable input gives the challenges read so far.
 */
export function parseChallenges(value) {
  const out = [];
  if (!value) return out;
  let i = 0;
  const s = value;
  const ws = () => { while (i < s.length && (s[i] === " " || s[i] === "\t")) i++; };
  const token = () => { const m = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+/.exec(s.slice(i)); if (!m) return null; i += m[0].length; return m[0]; };
  const quoted = () => {
    if (s[i] !== '"') return null;
    let v = ""; i++;
    while (i < s.length && s[i] !== '"') { if (s[i] === "\\" && i + 1 < s.length) i++; v += s[i++]; }
    if (s[i] !== '"') return null;
    i++;
    return v;
  };
  for (;;) {
    ws();
    while (s[i] === ",") { i++; ws(); }
    if (i >= s.length) break;
    const scheme = token();
    if (!scheme) break;
    const ch = { scheme, params: {} };
    out.push(ch);
    ws();
    // auth-params: name = value, separated by commas; a token68 form is kept as `token68`.
    for (;;) {
      const save = i;
      ws();
      const name = token();
      if (!name) { i = save; break; }
      ws();
      if (s[i] !== "=") { i = save; break; } // the next challenge's scheme
      i++;
      if (s[i] === "=") { // token68 with padding
        while (s[i] === "=") i++;
        ch.token68 = name;
        break;
      }
      ws();
      const v = s[i] === '"' ? quoted() : token();
      if (v == null) return out;
      ch.params[name.toLowerCase()] = v;
      ws();
      if (s[i] === ",") { i++; continue; }
      break;
    }
  }
  return out;
}
