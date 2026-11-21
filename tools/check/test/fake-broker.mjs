// An in-memory ALP domain and brokers with the shape of `fetch`, for the checker's tests. No sockets.
//
// Written from the specification, not from the checker: it serves example.org's domain document (Section 4.2), each
// broker's JWKS (4.8), the client binding's protected resource metadata, authorization server metadata and 401
// challenges (5.6), and a federation inbox that runs acceptance steps 0 and 1 (12.2.4) with the responses of
// 12.2.3 and the statuses of 18.3. Steps 2 to 11 are outside its scope: an envelope that passes step 1 is answered
// `internal`. The world is the vector fixture's (vectors/world.json, TEST-ONLY keys).
//
// By default everything behaves as the specification says. Each fault switch changes one behaviour.
// Licensed under Apache-2.0.
import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parseStrict, canonicalize, jkt, verifyDetached } from "../../spec/lib.mjs";
import { REPO } from "../spec-text.mjs";

const world = JSON.parse(fs.readFileSync(path.join(REPO, "vectors", "world.json"), "utf8"));

/** Every fault the fake knows, with what it changes. */
export const FAULTS = {
  // domain document
  "document-missing": "both well-known locations answer 404",
  "location-1-redirects": "location 1 answers 301 to another host; location 2 serves the document",
  "location-1-forbidden": "location 1 answers 403; location 2 serves the document",
  "location-1-tls": "location 1 fails its TLS handshake (expired certificate); location 2 answers 404",
  "location-1-tls-location-2-serves": "location 1 fails its TLS handshake (expired certificate); location 2 serves the document",
  "location-1-tls-location-2-busy": "location 1 fails its TLS handshake (expired certificate); location 2 answers 503",
  "location-2-tls": "location 1 answers 404, so a peer goes on to location 2, which fails its TLS handshake (expired certificate)",
  "document-text-type": "the document is served as text/plain",
  "document-oversize": "the document is padded with whitespace to 70 KiB",
  "document-huge": "the document is padded with whitespace to 300 KiB, more than alp-check reads",
  "document-extra-member": "the document carries a member the schema doesn't have",
  "document-wrong-domain": "the document's `domain` is example.net",
  "document-duplicate-ids": "the second entry has the first entry's id",
  "document-two-wildcards": "both entries have \"principals\": \"*\"",
  "document-overlap": "an address is listed by both entries",
  "document-foreign-address": "an entry lists an address on partner.example",
  "document-url-off-origin": "an entry's jwks_uri is on another origin",
  "document-revoked-pinned": "revoked_jkt lists a thumbprint an entry still pins",
  // keys
  "jwks-missing": "broker.example.org's JWKS answers 404",
  "jwks-text-type": "the JWKS is served as text/plain",
  "jwks-oversize": "the JWKS is padded with whitespace to 70 KiB",
  "jwks-huge": "the JWKS is padded with whitespace to 300 KiB, more than alp-check reads",
  "jwks-private-member": "a key in the JWKS carries its private member `d`",
  "jwks-unpinned-federation": "the JWKS has a second federation key the domain doesn't pin",
  "jkt-unpublished": "broker.example.org's entry pins a thumbprint that is not in its JWKS",
  "kid-not-thumbprint": "a key's kid is not its thumbprint",
  // DNS
  "txt-extra-member": "the TXT record carries a uri member",
  "txt-two-records": "_alp.example.org has two TXT records",
  "txt-old-id": "the TXT record's id is 41 while the serial is 42",
  // sign-in metadata
  "prm-wrong-resource": "protected resource metadata names the origin instead of the endpoint",
  "prm-no-authorization-servers": "protected resource metadata names no authorization server",
  "prm-missing-send": "protected resource metadata lists only the read scope",
  "as-metadata-missing": "the RFC 8414 metadata answers 404 (OpenID Connect discovery still served)",
  "as-wrong-issuer": "the authorization server metadata names another issuer",
  "oidc-missing": "OpenID Connect discovery answers 404",
  "pkce-plain": "the metadata lists plain beside S256",
  "no-iss-parameter": "the metadata doesn't advertise the iss parameter",
  "no-cimd": "the metadata doesn't advertise client ID metadata documents",
  "no-revocation-endpoint": "the metadata names no revocation endpoint",
  // client binding without a token
  "mcp-challenge-no-resource-metadata": "the MCP 401 challenge has no resource_metadata",
  "rest-open": "the REST mirror answers 200 without a token",
  // inbox
  "inbox-version-after-schema": "the inbox checks the schema before the version, so an unknown version is bad_envelope",
  "inbox-lenient-json": "the inbox parses with JSON.parse, which keeps the last of duplicate members",
  "inbox-no-schema": "the inbox doesn't validate the envelope against its schema",
  "inbox-no-lifetime-limit": "the inbox doesn't limit the lifetime to 7 days",
  "inbox-no-clock-check": "the inbox doesn't check created_at against its clock",
  "inbox-no-delegate-check": "the inbox doesn't check that delegate ids belong to their addresses",
  "inbox-no-to-delegate-check": "the inbox checks from.delegate but not to.delegate",
  "inbox-no-expiry-order": "the inbox doesn't check that expires_at is after created_at",
  "inbox-accepts-unknown-domains": "the inbox answers 200 with a receipt for envelopes from domains with no document",
  "inbox-flat-errors": "the inbox answers errors as { \"error\": \"<code>\" }",
  "inbox-wrong-status": "the inbox answers bad_envelope with status 422",
  "inbox-error-with-receipt": "the inbox's unsigned errors carry a receipt member",
  "inbox-no-retry-after": "the inbox's 503 answers carry no Retry-After",
};

/**
 * Variants that the specification allows, or that alp-check cannot judge from one run (a rate limit, a temporary
 * failure): the checker must report no failure on any of them.
 */
export const VARIANTS = {
  "location-1-server-error": "location 1 answers 500 (a temporary failure for a peer, Section 4.3) and location 2 serves the document",
  "location-1-busy": "location 1 answers 503 with Retry-After and location 2 serves the document",
  "location-1-refused": "location 1 refuses the connection (perhaps only from the checker's network) and location 2 serves the document",
  "location-1-tls-handshake": "location 1's TLS handshake fails for a reason other than its certificate (a protocol error, perhaps only on the checker's network) and location 2 serves the document",
  "inbox-requires-signed-requests": "the inbox requires RFC 9421 request signatures (Section 12.2.2) and refuses unsigned requests with 401 bad_signature; alp-check skips the probe checks and exits 0",
  "inbox-signed-requests-plain-401": "the inbox requires signed requests and refuses unsigned ones with a plain-text 401 and Accept-Signature (Section 12.2.2 gives no form for this); alp-check skips the probe checks and exits 0",
  "inbox-401-on-unknown-sender": "the inbox refuses the step-0 probes as the specification says, but answers the well-formed envelope from a domain that cannot exist 401 bad_signature; alp-check leaves that probe undecided and exits 4",
  "inbox-rate-limited": "the inbox answers every request 429 rate_limited with Retry-After",
  "inbox-behind-busy-proxy": "a front server answers the inbox 503 with an HTML page and Retry-After",
  "metadata-rate-limited": "the JWKS, protected resource metadata and authorization server metadata answer 429 with Retry-After",
  "as-metadata-rate-limited": "only the authorization server's metadata (RFC 8414 and OpenID Connect discovery) answers 429 with Retry-After",
  "metadata-server-error": "the JWKS and the authorization server's metadata answer 500 (a server error, retried as 5xx, Section 10.2)",
  "inbox-internal-error": "the inbox answers every probe 500 `internal` (retryable, Section 18.3)",
  "endpoints-unavailable": "the MCP endpoint and the REST mirror answer 503 with Retry-After",
  "everything-unavailable": "every HTTP request, to the domain and to every broker, is answered 503 with Retry-After",
  "brokers-unavailable": "the domain document is served, and every request to a broker is answered 503 with Retry-After",
  "prm-offline-access": "protected resource metadata lists offline_access beside read and send (Section 5.6 item 7 issues refresh tokens for it)",
  "rest-prm-per-tool": "the REST mirror's challenge names metadata at the tool path, which names the REST base URL as its resource (Section 5.6 item 6)",
  "key-rotation": "broker.example.org publishes its current and its next federation key, and the domain pins both (Section 4.8 rule 4)",
  "rotation-old-key-unpinned": "after a rotation the domain has unpinned broker.example.org's old key, which the broker still publishes (the last step of Section 4.8 rule 4, done as written)",
  "document-at-location-2": "location 1 answers 404 and location 2 serves the document",
  "location-1-no-address": "location 1's name has no address records and location 2 serves the document",
  "unknown-domain-broker-not-authorized": "the inbox refuses a sender domain with no document with broker_not_authorized",
  "txt-none": "the domain publishes no TXT record",
  "txt-split-strings": "the TXT record is published as two character-strings, read joined",
};

const DOMAIN = "example.org";
const MESSAGE_TYPES = new Set(["request", "propose", "counter", "accept", "decline", "inform", "ask_human", "commit", "ack", "error"]);
const CONTROL_TYPES = new Set(["connection_request", "connection_response", "revoke"]);
const STATUS = {
  bad_envelope: 400, unsupported_version: 400, body_too_large: 413, discovery_failed: 503, broker_not_authorized: 403,
  bad_signature: 401, internal: 500, invalid_input: 400,
};

function loadValidators() {
  const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: false });
  addFormats(ajv);
  ajv.addKeyword({ keyword: "x-alp-text", schemaType: "string" });
  const dir = path.join(REPO, "schemas");
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) { if (e.name !== "client" && e.name !== "scopes") walk(p); }
      else if (e.name.endsWith(".schema.json")) ajv.addSchema(JSON.parse(fs.readFileSync(p, "utf8")));
    }
  };
  walk(dir);
  const base = "tag:agentliaisonprotocol.org,2026-11-08:spec/0.1/schemas/";
  return { envelope: ajv.getSchema(base + "envelope.schema.json"), control: ajv.getSchema(base + "control.schema.json") };
}
const validators = loadValidators();

const json = (status, value, headers = {}) => new Response(typeof value === "string" ? value : JSON.stringify(value), { status, headers: { "content-type": "application/json", ...headers } });
const notFound = () => new Response("not found", { status: 404, headers: { "content-type": "text/plain" } });
const pad = (text, kib = 70) => text + " ".repeat(kib * 1024);
const busy = (status, body = "busy", type = "text/plain") => new Response(body, { status, headers: { "content-type": type, "retry-after": "120" } });
const clone = (v) => JSON.parse(JSON.stringify(v));

/**
 * Create the fake. Options: `faults` (names from FAULTS or VARIANTS), `now` (a function giving milliseconds).
 * Returns { fetch, resolveTxt, calls, document, jwks }.
 */
export function createFakeBroker({ faults = [], now = () => Date.now() } = {}) {
  const on = new Set(faults);
  for (const f of on) if (!(f in FAULTS) && !(f in VARIANTS)) throw new Error(`unknown fault ${f}`);
  const calls = [];

  // ---------------------------------------------------------------- the domain document (Section 4.2)
  const document = clone(world.domain_documents["example.org@42"]);
  const jwks = {
    "https://broker.example.org": clone(world.jwks["https://broker.example.org/.well-known/jwks.json"]),
    "https://hosted.example.net": clone(world.jwks["https://hosted.example.net/.well-known/jwks.json"]),
  };
  const [main, hosted] = document.brokers;
  if (on.has("document-extra-member")) document.policy = { groups: {} };
  if (on.has("document-wrong-domain")) document.domain = "example.net";
  if (on.has("document-duplicate-ids")) {
    hosted.id = main.id;
    for (const k of ["inbox", "jwks_uri", "mcp", "rest"]) hosted[k] = main[k];
  }
  if (on.has("document-two-wildcards")) hosted.principals = "*";
  if (on.has("document-overlap")) main.principals = ["alp:ana@example.org", "alp:guest@example.org"];
  if (on.has("document-foreign-address")) hosted.principals = ["alp:guest@example.org", "alp:pat@partner.example"];
  if (on.has("document-url-off-origin")) hosted.jwks_uri = "https://cdn.example.net/hosted/jwks.json";
  if (on.has("document-revoked-pinned")) document.revoked_jkt = [{ jkt: main.jkt[0], compromised_since: "2026-11-01T00:00:00Z" }];
  if (on.has("jwks-private-member")) jwks[main.id].keys[0].d = "TEST-ONLY-not-a-real-private-key-value-000";
  if (on.has("jwks-unpinned-federation")) {
    const extra = clone(world.jwks["https://broker.partner.example/.well-known/jwks.json"].keys[0]);
    jwks[main.id].keys.push(extra);
  }
  if (on.has("jkt-unpublished")) main.jkt = [jkt(world.jwks["https://rogue.example/.well-known/jwks.json"].keys[0])];
  if (on.has("kid-not-thumbprint")) jwks[hosted.id].keys[0].kid = "hosted-key-1";
  if (on.has("rotation-old-key-unpinned")) {
    // The old key stays published; the domain now pins only the new one.
    const next = clone(world.jwks["https://broker.partner.example/.well-known/jwks.json"].keys[0]);
    jwks[main.id].keys.push(next);
    main.jkt = [jkt(next)];
  }
  if (on.has("key-rotation")) {
    const next = clone(world.jwks["https://broker.partner.example/.well-known/jwks.json"].keys[0]);
    jwks[main.id].keys.push(next);
    main.jkt = [...main.jkt, jkt(next)];
  }

  const documentText = () => {
    const text = JSON.stringify(document, null, 2);
    return on.has("document-huge") ? pad(text, 300) : on.has("document-oversize") ? pad(text) : text;
  };
  const serveDocument = () => new Response(documentText(), { status: 200, headers: { "content-type": on.has("document-text-type") ? "text/plain" : "application/json" } });

  function location1() {
    if (on.has("document-missing") || on.has("document-at-location-2") || on.has("location-2-tls")) return notFound();
    if (on.has("location-1-redirects")) return new Response("", { status: 301, headers: { location: "https://www.example.org/.well-known/alp.json" } });
    if (on.has("location-1-server-error")) return new Response("error", { status: 500, headers: { "content-type": "text/plain" } });
    if (on.has("location-1-busy")) return busy(503);
    if (on.has("location-1-forbidden")) return new Response("forbidden", { status: 403, headers: { "content-type": "text/plain" } });
    if (on.has("location-1-refused")) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });
    if (on.has("location-1-tls") || on.has("location-1-tls-location-2-serves") || on.has("location-1-tls-location-2-busy")) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "CERT_HAS_EXPIRED" } });
    if (on.has("location-1-tls-handshake")) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ERR_SSL_WRONG_VERSION_NUMBER" } });
    if (on.has("location-1-no-address")) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ENOTFOUND" } });
    return serveDocument();
  }
  function location2() {
    if (on.has("location-2-tls")) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "CERT_HAS_EXPIRED" } });
    if (on.has("location-1-tls-location-2-busy")) return busy(503);
    if (["document-at-location-2", "location-1-redirects", "location-1-server-error", "location-1-busy", "location-1-forbidden", "location-1-no-address", "location-1-tls-location-2-serves", "location-1-refused", "location-1-tls-handshake"].some((f) => on.has(f))) return serveDocument();
    return notFound();
  }

  // ---------------------------------------------------------------- broker surfaces
  const brokers = new Map([[main.id, main], [hosted.id, hosted]]);

  function serveJwks(id) {
    if (id === main.id && on.has("jwks-missing")) return notFound();
    const text = JSON.stringify(jwks[id]);
    return new Response(on.has("jwks-huge") ? pad(text, 300) : on.has("jwks-oversize") ? pad(text) : text, { status: 200, headers: { "content-type": on.has("jwks-text-type") ? "text/plain" : "application/jwk-set+json" } });
  }

  const prmUrl = (resource) => {
    const u = new URL(resource);
    const path = on.has("rest-prm-per-tool") && u.pathname === "/rest" ? "/rest/alp_whoami" : u.pathname;
    return `${u.origin}/.well-known/oauth-protected-resource${path}`;
  };
  function challenge(resource) {
    const params = [];
    if (!on.has("mcp-challenge-no-resource-metadata") || !resource.endsWith("/mcp")) params.push(`resource_metadata="${prmUrl(resource)}"`);
    params.push('scope="read send"');
    return `Bearer ${params.join(", ")}`;
  }
  function protectedResourceMetadata(origin, resource) {
    const body = {
      resource: on.has("prm-wrong-resource") ? origin : resource,
      authorization_servers: on.has("prm-no-authorization-servers") ? [] : [origin],
      scopes_supported: on.has("prm-missing-send") ? ["read"] : on.has("prm-offline-access") ? ["read", "send", "offline_access"] : ["read", "send"],
      bearer_methods_supported: ["header"],
    };
    return json(200, body, { "cache-control": "public, max-age=300" });
  }
  function asMetadata(origin) {
    const body = {
      issuer: on.has("as-wrong-issuer") ? "https://login.example.net" : origin,
      authorization_endpoint: `${origin}/oauth/authorize`,
      token_endpoint: `${origin}/oauth/token`,
      registration_endpoint: `${origin}/oauth/register`,
      revocation_endpoint: `${origin}/oauth/revoke`,
      jwks_uri: `${origin}/oauth/jwks`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
      scopes_supported: ["read", "send", "offline_access"],
      code_challenge_methods_supported: on.has("pkce-plain") ? ["S256", "plain"] : ["S256"],
      authorization_response_iss_parameter_supported: !on.has("no-iss-parameter"),
      client_id_metadata_document_supported: !on.has("no-cimd"),
    };
    if (on.has("no-revocation-endpoint")) delete body.revocation_endpoint;
    return body;
  }
  function unauthorized(resource) {
    return json(401, { error: "invalid_token", error_description: "sign-in required" }, { "www-authenticate": challenge(resource) });
  }

  // ---------------------------------------------------------------- the federation inbox (Section 12.2)
  function refuse(code, message) {
    const headers = {};
    if (code === "discovery_failed" && !on.has("inbox-no-retry-after")) headers["retry-after"] = "60";
    let status = STATUS[code];
    if (code === "bad_envelope" && on.has("inbox-wrong-status")) status = 422;
    let body = { error: { code, message } };
    if (on.has("inbox-flat-errors")) body = { error: code };
    if (on.has("inbox-error-with-receipt")) body.receipt = { status: "refused", code };
    return json(status, body, headers);
  }

  function inbox(id, init) {
    if (on.has("inbox-rate-limited")) return json(429, { error: { code: "rate_limited", message: "slow down" } }, { "retry-after": "120" });
    if (on.has("inbox-behind-busy-proxy")) return busy(503, "<html><body>Service unavailable</body></html>", "text/html");
    if (on.has("inbox-internal-error")) return refuse("internal", "try again later");
    const headers = init.headers ?? {};
    if (on.has("inbox-signed-requests-plain-401") && !Object.keys(headers).some((k) => k.toLowerCase() === "signature")) {
      return new Response("signature required", { status: 401, headers: { "content-type": "text/plain", "accept-signature": 'sig1=("@method" "@target-uri" "content-type" "content-digest");tag="alp-fed"' } });
    }
    if (on.has("inbox-requires-signed-requests") && !Object.keys(headers).some((k) => k.toLowerCase() === "signature")) return refuse("bad_signature", "this inbox requires signed requests");
    if ((init.method ?? "GET") !== "POST") return json(405, { error: { code: "invalid_input", message: "the inbox takes POST" } }, { allow: "POST" });
    const text = typeof init.body === "string" ? init.body : "";
    if (Buffer.byteLength(text) > 1024 * 1024) return refuse("bad_envelope", "the envelope is over 1 MiB");
    // Step 0: one strict parse, the version, the shape and its schema, delegate ids, lifetime, clock.
    let env;
    try { env = on.has("inbox-lenient-json") ? JSON.parse(text) : parseStrict(text); } catch { return refuse("bad_envelope", "not strict I-JSON"); }
    if (!env || typeof env !== "object" || Array.isArray(env)) return refuse("bad_envelope", "not an object");
    const schemaStep = () => {
      const validate = MESSAGE_TYPES.has(env.type) ? validators.envelope : CONTROL_TYPES.has(env.type) ? validators.control : null;
      if (!validate) return "unknown type";
      if (on.has("inbox-no-schema")) return null;
      return validate(env) ? null : "fails the schema";
    };
    if (on.has("inbox-version-after-schema")) {
      const bad = schemaStep();
      if (bad) return refuse("bad_envelope", bad);
      if (env.alp !== "0.1") return refuse("unsupported_version", "unknown protocol version");
    } else {
      if (env.alp !== "0.1") return refuse("unsupported_version", "unknown protocol version");
      const bad = schemaStep();
      if (bad) return refuse("bad_envelope", bad);
    }
    if (!on.has("inbox-no-delegate-check")) {
      if (env.from?.delegate && !String(env.from.delegate).startsWith(env.from.address + "/")) return refuse("bad_envelope", "from.delegate is not an agent of from.address");
      if (!on.has("inbox-no-to-delegate-check") && env.to?.delegate && !String(env.to.delegate).startsWith(env.to.address + "/")) return refuse("bad_envelope", "to.delegate is not an agent of to.address");
    }
    const created = Date.parse(env.created_at);
    const expires = Date.parse(env.expires_at);
    if (!on.has("inbox-no-expiry-order") && !(expires > created)) return refuse("bad_envelope", "expires_at is not after created_at");
    if (!on.has("inbox-no-lifetime-limit") && expires - created > 7 * 86400 * 1000) return refuse("bad_envelope", "lifetime over 7 days");
    if (!on.has("inbox-no-clock-check") && created > now() + 300 * 1000) return refuse("bad_envelope", "created_at is ahead of this broker's clock");
    const bodyTooLarge = () => Buffer.byteLength(canonicalize(env.body)) > 64 * 1024;
    if (bodyTooLarge()) return refuse("body_too_large", "the body is over 64 KiB");
    // Step 1: the sender's domain has a valid, current document that lists origin_broker, whose pinned key verifies.
    const senderDomain = String(env.from.address).split("@")[1];
    if (senderDomain !== DOMAIN) {
      if (on.has("inbox-accepts-unknown-domains")) return json(200, { receipt: { alp: "0.1", status: "accepted" } });
      if (on.has("inbox-401-on-unknown-sender")) return refuse("bad_signature", "the signature did not verify");
      if (on.has("unknown-domain-broker-not-authorized")) return refuse("broker_not_authorized", "the sender's broker is not authorized for its domain");
      return refuse("discovery_failed", "the sender's domain can't be checked now");
    }
    const entry = document.brokers.find((b) => b.id === env.origin_broker);
    if (!entry) return refuse("broker_not_authorized", "the sender's broker is not authorized for its domain");
    const keys = (jwks[entry.id]?.keys ?? []).filter((k) => k.alp_use === "federation" && entry.jkt.includes(jkt(k)));
    const typ = MESSAGE_TYPES.has(env.type) ? "alp-envelope+jws" : "alp-control+jws";
    if (!verifyDetached(env, typ, keys).ok) return refuse("bad_signature", "the signature did not verify");
    return refuse("internal", "steps 2 to 11 are not part of this fake");
  }

  // ---------------------------------------------------------------- routing
  async function fetch(url, init = {}) {
    calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body ?? null });
    const u = new URL(url);
    if (u.protocol !== "https:") throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });
    const method = init.method ?? "GET";
    if (on.has("everything-unavailable")) return busy(503);
    if (on.has("brokers-unavailable") && brokers.has(u.origin)) return busy(503);
    if (u.origin === "https://example.org" && u.pathname === "/.well-known/alp.json" && method === "GET") return location1();
    if (u.origin === "https://alp.example.org" && u.pathname === "/.well-known/alp.json" && method === "GET") return location2();
    const entry = brokers.get(u.origin);
    if (!entry) throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ENOTFOUND" } });
    const id = u.origin;
    const p = u.pathname;
    if (on.has("metadata-rate-limited") && method === "GET" && p.startsWith("/.well-known/")) return busy(429);
    const asPath = p === "/.well-known/oauth-authorization-server" || p === "/.well-known/openid-configuration";
    if (on.has("as-metadata-rate-limited") && method === "GET" && asPath) return busy(429);
    if (on.has("metadata-server-error") && method === "GET" && (asPath || p === "/.well-known/jwks.json")) return new Response("error", { status: 500, headers: { "content-type": "text/plain" } });
    if (on.has("endpoints-unavailable") && (p === "/mcp" || p.startsWith("/rest/"))) return busy(503);
    if (p === "/.well-known/jwks.json" && method === "GET") return serveJwks(id);
    if (p === "/.well-known/oauth-protected-resource/mcp" && method === "GET") return protectedResourceMetadata(id, `${id}/mcp`);
    if (p === "/.well-known/oauth-protected-resource/rest" && method === "GET" && !on.has("rest-prm-per-tool")) return protectedResourceMetadata(id, `${id}/rest`);
    if (p === "/.well-known/oauth-protected-resource/rest/alp_whoami" && method === "GET" && on.has("rest-prm-per-tool")) return protectedResourceMetadata(id, `${id}/rest`);
    if (p === "/.well-known/oauth-authorization-server" && method === "GET") return on.has("as-metadata-missing") ? notFound() : json(200, asMetadata(id));
    if (p === "/.well-known/openid-configuration" && method === "GET") return on.has("oidc-missing") ? notFound() : json(200, asMetadata(id));
    if (p === "/mcp") return unauthorized(`${id}/mcp`);
    if (p === "/rest/openapi.json" && method === "GET") return json(200, { openapi: "3.1.0" });
    if (p.startsWith("/rest/")) {
      if (on.has("rest-open")) return json(200, { id: "anonymous" });
      return json(401, { error: { code: "identity_mismatch", message: "sign-in required" } }, { "www-authenticate": challenge(`${id}/rest`) });
    }
    if (p === "/federation/inbox") return inbox(id, init);
    return notFound();
  }

  async function resolveTxt(name) {
    if (name !== `_alp.${DOMAIN}` || on.has("txt-none")) throw Object.assign(new Error(`queryTxt ENODATA ${name}`), { code: "ENODATA" });
    if (on.has("txt-extra-member")) return [["v=ALP1; id=42; uri=https://outside.example/doc.json"]];
    if (on.has("txt-two-records")) return [["v=ALP1; id=42"], ["v=ALP1; id=43"]];
    if (on.has("txt-old-id")) return [["v=ALP1; id=41"]];
    if (on.has("txt-split-strings")) return [["v=ALP1; ", "id=42"]];
    return [["v=ALP1; id=42"]];
  }

  return { fetch, resolveTxt, calls, document, jwks };
}
