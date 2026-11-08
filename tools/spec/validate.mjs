// Validates every ALP v0.1 schema and vector in the repository.
// Usage: node validate.mjs <repo>
import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  canonicalize, parseStrict, hashJson, jkt, verifyDetached, parseHeader, withoutSig, signDetached, ms, iso,
  leaves, prefixMatch, exactMatch, isTextLocation, covered, removeLeaves, sanitizeText, baselineDlp, parsePointer, publicJwk,
} from "./lib.mjs";

const repo = process.argv[2];
if (!repo) { console.error("usage: node validate.mjs <repo>"); process.exit(2); }
const R = (rel) => JSON.parse(fs.readFileSync(path.join(repo, rel), "utf8"));
let pass = 0, fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) pass++;
  else { fail++; failures.push(`${name}${detail ? ": " + detail : ""}`); }
}
const eq = (a, b) => canonicalize(a ?? null) === canonicalize(b ?? null);
const ERROR_CODES_LIST = JSON.parse(fs.readFileSync(path.join(repo, "schemas", "common.schema.json"), "utf8")).$defs.error_code.enum;

// ---------------------------------------------------------------- schemas
const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
addFormats(ajv);
ajv.addKeyword({ keyword: "x-alp-text", schemaType: "string" });
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
const schemaFiles = walk(path.join(repo, "schemas")).filter((f) => f.endsWith(".schema.json"));
for (const f of schemaFiles) ajv.addSchema(JSON.parse(fs.readFileSync(f, "utf8")));
const BASE = "tag:agentliaisonprotocol.org,2026-11-08:spec/0.1/schemas/";
const V = {};
for (const f of schemaFiles) {
  const s = JSON.parse(fs.readFileSync(f, "utf8"));
  const name = path.relative(path.join(repo, "schemas"), f).replace(/\.schema\.json$/, "");
  try { V[name] = ajv.getSchema(s.$id); check(`schema compiles: ${name}`, !!V[name]); }
  catch (e) { check(`schema compiles: ${name}`, false, e.message); }
  check(`schema $id under the tag base: ${name}`, s.$id === BASE + name + ".schema.json", s.$id);
  check(`schema dialect 2020-12: ${name}`, s.$schema === "https://json-schema.org/draft/2020-12/schema");
}
const valid = (name, obj) => { const ok = V[name](obj); return { ok, errors: V[name].errors }; };

// ---------------------------------------------------------------- scope definitions
const SCOPES = {};
const scopeDir = path.join(repo, "schemas", "scopes");
function lintScopeSchema(schema, where, out) {
  const visit = (s, p) => {
    if (!s || typeof s !== "object") return;
    if (s.pattern !== undefined) out.push(`${where}${p}: pattern is not allowed in scope schemas`);
    if (s.$ref !== undefined) out.push(`${where}${p}: $ref is not allowed in scope schemas`);
    if (s.type === "string" && s.enum === undefined && s.const === undefined && s.format === undefined && s.maxLength === undefined) out.push(`${where}${p}: unbounded string`);
    if (s.type === "object" && s.additionalProperties !== false) out.push(`${where}${p}: object not closed`);
    if (s["x-alp-text"] !== undefined && !(s["x-alp-text"] === "untrusted" && s.type === "string" && s.maxLength <= 280)) out.push(`${where}${p}: x-alp-text field must be an untrusted string of at most 280 characters`);
    if (s.type === "array" && s.maxItems === undefined) out.push(`${where}${p}: unbounded array`);
    if (s.properties) for (const [k, v] of Object.entries(s.properties)) visit(v, `${p}/properties/${k}`);
    if (s.items) visit(s.items, `${p}/items`);
  };
  visit(schema, "");
}
function schemaHasPath(schema, pointer) {
  const t = parsePointer(pointer);
  if (t[0] !== "body") return false;
  let s = schema;
  for (const tok of t.slice(1)) {
    if (!s) return false;
    if (s.type === "array") { if (tok !== "*" && !/^[0-9]+$/.test(tok)) return false; s = s.items; }
    else if (s.properties) s = s.properties[tok];
    else return false;
  }
  return !!s;
}
for (const f of fs.readdirSync(scopeDir)) {
  const def = JSON.parse(fs.readFileSync(path.join(scopeDir, f), "utf8"));
  const r = valid("scope-definition", def);
  check(`scope definition valid: ${f}`, r.ok, JSON.stringify(r.errors));
  check(`scope file name matches id: ${f}`, f === def.id.replace(/^[a-z]+\./, "").replace("/", "-") + ".json");
  const compiled = {};
  const lint = [];
  for (const [type, t] of Object.entries(def.types)) {
    try { compiled[type] = ajv.compile(t.schema); check(`scope type compiles: ${def.id} ${type}`, true); }
    catch (e) { check(`scope type compiles: ${def.id} ${type}`, false, e.message); }
    lintScopeSchema(t.schema, `${def.id} ${type}`, lint);
  }
  check(`scope schemas closed, bounded, no pattern: ${def.id}`, lint.length === 0, lint.join("; "));
  for (const p of Object.keys(def.classification)) check(`classification pointer exists: ${def.id} ${p}`, Object.values(def.types).some((t) => schemaHasPath(t.schema, p)));
  for (const [type, ptrs] of Object.entries(def.suggested ?? {})) for (const p of ptrs) check(`suggested pointer exists: ${def.id} ${type} ${p}`, !!def.types[type] && schemaHasPath(def.types[type].schema, p));
  for (const [from, tos] of Object.entries(def.replies)) for (const t of [from, ...tos]) check(`reply type known: ${def.id} ${t}`, !!def.types[t] || def.common_types.includes(t));
  for (const s of def.starts) check(`start type defined: ${def.id} ${s}`, !!def.types[s]);
  if (def.negotiable) for (const t of ["propose", "accept", "commit"]) check(`negotiable scope defines ${t}: ${def.id}`, !!def.types[t]);
  if (def.limits_schema) { try { ajv.compile(def.limits_schema); check(`limits schema compiles: ${def.id}`, true); } catch (e) { check(`limits schema compiles: ${def.id}`, false, e.message); } }
  SCOPES[def.id] = { def, compiled };
}
check("five core scopes", ["alp.availability/1", "alp.meeting/1", "alp.briefing/1", "alp.status/1", "alp.document_request/1"].every((s) => SCOPES[s]));

// ---------------------------------------------------------------- client binding tools
const toolsDoc = R("schemas/client/tools.json");
const toolNames = toolsDoc.tools.map((t) => t.name);
check("seven tools with the fixed names", eq(toolNames, ["alp_whoami", "alp_contacts", "alp_send", "alp_inbox", "alp_thread", "alp_ack", "alp_request_connection"]), toolNames.join(","));
check("tools.json has no $ref", !JSON.stringify(toolsDoc).includes('"$ref"'));
const READ_ONLY = ["alp_whoami", "alp_contacts", "alp_inbox", "alp_thread"];
for (const t of toolsDoc.tools) {
  check(`tool name syntax: ${t.name}`, /^[A-Za-z0-9_.-]{1,128}$/.test(t.name));
  check(`tool inputSchema is an object schema: ${t.name}`, t.inputSchema.type === "object");
  try { ajv.compile(t.inputSchema); ajv.compile(t.outputSchema); check(`tool schemas compile: ${t.name}`, true); }
  catch (e) { check(`tool schemas compile: ${t.name}`, false, e.message); }
  check(`tool annotation readOnlyHint: ${t.name}`, t.annotations.readOnlyHint === READ_ONLY.includes(t.name));
  check(`tool never destructive: ${t.name}`, t.annotations.destructiveHint === false);
}
const openapi = R("schemas/client/openapi.json");
check("OpenAPI 3.1 mirror lists every tool", openapi.openapi === "3.1.0" && toolNames.every((n) => openapi.paths["/" + n]?.post));
const sendOut = ajv.compile(toolsDoc.tools.find((t) => t.name === "alp_inbox").outputSchema);
check("inbox output example validates", sendOut({ items: [{ id: "01JC6Y0000000000000000000A", thread: "01JC6Y0000000000000000000A", received_at: "2026-11-09T14:00:00Z", acked: false, verified: { from: { address: "alp:ana@example.org", display: "ana@example.org", principal_id: "ana-7f3a9c41d2e8b605", delegate: "alp:ana@example.org/agent-a", attestation: "vendor", class: "business" }, scope: "alp.briefing/1", type: "request", thread_state: "open", decision: { outcome: "allowed", redacted: [], policy_ids: ["example.org#12"] }, origin_broker: "https://broker.example.org", testing: false, handling: "response_only" }, content: { kind: "untrusted", notice: toolsDoc.untrusted_notice, body: { topic: "x", depth: "headline" } } }], next_cursor: "c1", more: false }), JSON.stringify(sendOut.errors));

// alp_send's named examples in the OpenAPI document: each validates against the tool's input schema, carries no note,
// and its body validates against its scope's schema for the type, or the protocol's schema for a common type.
const sendIn = ajv.compile(toolsDoc.tools.find((t) => t.name === "alp_send").inputSchema);
const sendExamples = openapi.paths["/alp_send"].post.requestBody?.content?.["application/json"]?.examples ?? {};
check("OpenAPI alp_send has named examples", Object.keys(sendExamples).length >= 14, String(Object.keys(sendExamples).length));
// A commit's terms equal the accepted terms (spec 7.7, its terms_hash matches): the example commit repeats the accept's.
check("OpenAPI meeting_commit repeats meeting_accept's terms exactly", JSON.stringify(sendExamples.meeting_commit?.value?.body?.terms) === JSON.stringify(sendExamples.meeting_accept?.value?.body?.terms));
const COMMON_TYPES = ["ack", "decline", "error", "ask_human"];
for (const [name, ex] of Object.entries(sendExamples)) {
  const v = ex?.value;
  check(`OpenAPI alp_send example has a summary: ${name}`, typeof ex?.summary === "string" && ex.summary.length > 0);
  check(`OpenAPI alp_send example matches the tool's input schema: ${name}`, sendIn(v), JSON.stringify(sendIn.errors));
  check(`OpenAPI alp_send example uses typed fields only (no note): ${name}`, v && !("note" in v));
  const scope = SCOPES[v?.scope];
  check(`OpenAPI alp_send example names a core scope: ${name}`, !!scope, v?.scope);
  if (!scope) continue;
  const common = COMMON_TYPES.includes(v.type) && scope.def.common_types.includes(v.type);
  const validate = common ? V[`messages/${v.type}`] : scope.compiled[v.type];
  check(`OpenAPI alp_send example's type is defined for its scope: ${name}`, !!validate, `${v.scope} ${v.type}`);
  if (validate) check(`OpenAPI alp_send example's body matches its schema: ${name}`, validate(v.body), JSON.stringify(validate.errors));
}
for (const [p, item] of Object.entries(openapi.paths)) {
  for (const code of ["404", "500"]) check(`OpenAPI ${p} documents ${code}`, !!item.post.responses[code]);
  // The registry gives unreachable no HTTP status; the reference broker answers it with 502, and only alp_send delivers.
  if (p === "/alp_send") check(`OpenAPI ${p} documents 502 (the reference broker's status for unreachable)`, /unreachable/.test(item.post.responses["502"]?.description ?? ""));
  else check(`OpenAPI ${p} leaves 502 out (only alp_send can be unreachable)`, !item.post.responses["502"]);
}
check("OpenAPI description says 502 and the unknown tool's 404 aren't the registry's", /unreachable` with 502; the registry gives neither status/.test(openapi.info.description));
for (const code of ERROR_CODES_LIST) check(`OpenAPI error table lists ${code}`, openapi.info.description.includes(`| \`${code}\` |`));

// ---------------------------------------------------------------- world
const world = R("vectors/world.json");
const NOW = world.now;
const SKEW = world.clock_skew_seconds * 1000;
for (const [k, d] of Object.entries(world.domain_documents)) { const r = valid("domain-document", d); check(`world domain document valid: ${k}`, r.ok, JSON.stringify(r.errors)); }
for (const [u, j] of Object.entries(world.jwks)) { const r = valid("jwks", j); check(`world JWKS valid: ${u}`, r.ok, JSON.stringify(r.errors)); for (const k of j.keys) check(`kid is the RFC 7638 thumbprint: ${k.kid}`, k.kid === jkt(k)); }
for (const [d, p] of Object.entries(world.org_policies)) { const r = valid("org-policy", p); check(`world org policy valid: ${d}`, r.ok, JSON.stringify(r.errors)); }
const keysFile = R("vectors/keys/TEST-ONLY-private-keys.json");
check("test keys file is labeled TEST ONLY", /TEST KEYS ONLY/.test(keysFile.WARNING));
const PRIV = keysFile.keys;

// ---------------------------------------------------------------- JCS
for (const c of R("vectors/jcs/jcs.json").cases) {
  if (c.expected_error) { let err = null; try { parseStrict(c.input_text); } catch (e) { err = e.message; } check(`JCS refuses: ${c.name}`, err && err.includes(c.expected_error), err); }
  else check(`JCS: ${c.name}`, canonicalize(parseStrict(c.input_text)) === c.expected, canonicalize(parseStrict(c.input_text)));
}

// ---------------------------------------------------------------- signatures
for (const c of R("vectors/signatures/detached-jws.json").cases) {
  const pub = { ...publicJwk(PRIV[c.key]), kid: PRIV[c.key].kid, alg: PRIV[c.key].alg };
  if (c.verify_only) {
    const v = verifyDetached({ ...c.object, broker_sig: c.broker_sig }, c.typ, [pub]);
    check(`verify-only signature: ${c.name}`, v.ok, v.failure);
    continue;
  }
  const r = signDetached(c.object, c.typ, PRIV[c.key], PRIV[c.key].kid);
  check(`JCS of signed object: ${c.name}`, r.jcs === c.expected.jcs);
  check(`protected header: ${c.name}`, eq(r.header, c.expected.protected_header));
  check(`deterministic Ed25519 signature: ${c.name}`, r.sig === c.expected.broker_sig);
  const v = verifyDetached({ ...c.object, broker_sig: c.expected.broker_sig }, c.typ, [pub]);
  check(`signature verifies: ${c.name}`, v.ok, v.failure);
  if (c.expected.envelope_hash) check(`envelope hash: ${c.name}`, hashJson({ ...c.object, broker_sig: c.expected.broker_sig }) === c.expected.envelope_hash);
  const objName = c.typ === "alp-envelope+jws" ? "envelope" : "receipt";
  const sv = valid(objName, { ...c.object, broker_sig: c.expected.broker_sig });
  check(`signed object validates: ${c.name}`, sv.ok, JSON.stringify(sv.errors));
}
for (const c of R("vectors/signatures/jkt.json").cases) check(`jkt: ${c.name}`, jkt(c.jwk) === c.expected_jkt);

// ---------------------------------------------------------------- envelope validity (structure + semantics)
function structural(obj, now) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return { ok: false, code: "bad_envelope" };
  if (obj.alp !== "0.1") return { ok: false, code: "unsupported_version" };
  let schema;
  if (["request", "propose", "counter", "accept", "decline", "inform", "ask_human", "commit", "ack", "error"].includes(obj.type)) schema = "envelope";
  else if (["connection_request", "connection_response", "revoke"].includes(obj.type)) schema = "control";
  else return { ok: false, code: "bad_envelope" };
  const r = valid(schema, obj);
  if (!r.ok) return { ok: false, code: "bad_envelope", errors: r.errors };
  const c = ms(obj.created_at), e = ms(obj.expires_at);
  if (!(e > c) || e - c > 7 * 86400000) return { ok: false, code: "bad_envelope", semantic: "lifetime" };
  if (now && c > ms(now) + SKEW) return { ok: false, code: "bad_envelope", semantic: "future" };
  if (Buffer.byteLength(canonicalize(obj.body ?? {})) > 65536) return { ok: false, code: "body_too_large" };
  return { ok: true, schema };
}
for (const c of R("vectors/envelope/validity.json").cases) {
  let res;
  if (c.raw_text) { try { res = structural(parseStrict(c.raw_text)); } catch { res = { ok: false, code: "bad_envelope" }; } }
  else res = structural(c.object);
  check(`envelope validity: ${c.name}`, res.ok === c.expected.valid && (c.expected.valid || res.code === c.expected.code), JSON.stringify({ res: res.ok, code: res.code, errors: res.errors?.slice?.(0, 2) }));
}

// ---------------------------------------------------------------- scope bodies
for (const c of R("vectors/scopes/bodies.json").cases) {
  const v = SCOPES[c.scope].compiled[c.type];
  check(`scope body ${c.scope} ${c.type} ${c.valid ? "valid" : "invalid"}`, !!v && v(c.body) === c.valid, JSON.stringify(v?.errors));
}

// ---------------------------------------------------------------- domain documents and resolution
const domainOf = (addr) => addr.slice(addr.lastIndexOf("@") + 1);
const originOf = (u) => { const x = new URL(u); return x.origin; };
function docSemantics(doc) {
  const r = valid("domain-document", doc);
  if (!r.ok) return { ok: false, why: "schema" };
  const ids = new Set(), listed = new Set();
  for (const b of doc.brokers) {
    if (ids.has(b.id)) return { ok: false, why: "duplicate broker" };
    ids.add(b.id);
    for (const k of ["inbox", "jwks_uri", "mcp", "rest", "operator_statement"]) if (b[k] && originOf(b[k]) !== b.id) return { ok: false, why: "same-origin" };
    if (Array.isArray(b.principals)) for (const a of b.principals) {
      if (domainOf(a) !== doc.domain) return { ok: false, why: "foreign address" };
      if (listed.has(a)) return { ok: false, why: "overlapping authorizations" };
      listed.add(a);
    }
  }
  return { ok: true };
}
function homeBroker(doc, address) {
  if (domainOf(address) !== doc.domain) return null;
  const listedAt = doc.brokers.find((b) => Array.isArray(b.principals) && b.principals.includes(address));
  if (listedAt) return listedAt.id;
  const star = doc.brokers.find((b) => b.principals === "*");
  return star ? star.id : null;
}
function parseTxt(record) {
  const m = /^v=ALP1;[ ]?id=([A-Za-z0-9]{1,32})$/.exec(record);
  return m ? { valid: true, id: m[1] } : { valid: false };
}
const dres = R("vectors/domain/resolution.json");
for (const c of dres.documents) { const r = docSemantics(c.document); check(`domain document: ${c.name}`, r.ok === c.expected.valid && (!c.expected.semantic || r.why === c.expected.semantic), JSON.stringify(r)); }
for (const c of dres.resolution) { const doc = typeof c.document === "string" ? world.domain_documents[c.document] : c.document; check(`home broker of ${c.address} in ${doc.domain}@${doc.serial}`, homeBroker(doc, c.address) === c.expected_home, String(homeBroker(doc, c.address))); }
for (const c of dres.txt) { const r = parseTxt(c.record); check(`TXT record ${c.record}`, r.valid === c.valid && (!c.valid || r.id === c.id)); }

// ---------------------------------------------------------------- federation acceptance, steps 0-6
const TYP_FOR = { envelope: "alp-envelope+jws", control: "alp-control+jws" };
function accept(ctx, bodyText, now) {
  if (Buffer.byteLength(bodyText) > 1048576) return { result: "refused", code: "bad_envelope", step: 0 };
  let obj;
  try { obj = parseStrict(bodyText); } catch { return { result: "refused", code: "bad_envelope", step: 0 }; }
  const st = structural(obj, now);
  if (!st.ok) return { result: "refused", code: st.code, step: 0 };
  // step 0 also: a named delegate is one of the address it is named under (from the envelope alone)
  const ownedBy = (d, address) => d === undefined || d.slice(0, d.lastIndexOf("/")) === address;
  if (!ownedBy(obj.from.delegate, obj.from.address) || !ownedBy(obj.to.delegate, obj.to.address)) return { result: "refused", code: "bad_envelope", step: 0 };
  // step 1: signature with a key the sender's domain pins for origin_broker
  const sdom = domainOf(obj.from.address);
  const docKey = ctx.domain_documents[sdom];
  if (!docKey) return { result: "refused", code: "broker_not_authorized", step: 1 };
  const doc = world.domain_documents[docKey];
  if (!docSemantics(doc).ok || doc.domain !== sdom) return { result: "refused", code: "discovery_failed", step: 1 };
  if ((ctx.last_seen_serial?.[sdom] ?? 0) > doc.serial) return { result: "refused", code: "discovery_failed", step: 1 };
  const entry = doc.brokers.find((b) => b.id === obj.origin_broker);
  if (!entry) return { result: "refused", code: "broker_not_authorized", step: 1 };
  const revoked = new Set((doc.revoked_jkt ?? []).map((r) => r.jkt));
  const jwks = world.jwks[entry.jwks_uri];
  const keys = (jwks?.keys ?? []).filter((k) => k.alp_use === "federation" && entry.jkt.includes(jkt(k)) && !revoked.has(jkt(k)));
  const header = parseHeader(obj.broker_sig);
  if (!header) return { result: "refused", code: "bad_signature", step: 1 };
  const v = verifyDetached(obj, header.typ, keys);
  if (!v.ok) return { result: "refused", code: "bad_signature", step: 1 };
  // step 2: typ
  if (header.typ !== TYP_FOR[st.schema]) return { result: "refused", code: "bad_signature", step: 2 };
  // step 3: audience and recipient homed here
  if (obj.aud !== ctx.receiving_broker) return { result: "refused", code: "wrong_audience", step: 3 };
  const rdom = domainOf(obj.to.address);
  const rdocKey = ctx.domain_documents[rdom];
  const rhome = ctx.served_domains[rdom] && rdocKey ? homeBroker(world.domain_documents[rdocKey], obj.to.address) : null;
  if (rhome !== ctx.receiving_broker) return { result: "refused", code: "wrong_audience", step: 3 };
  // step 4: expiry
  if (ms(now) > ms(obj.expires_at) + SKEW) return { result: "refused", code: "expired", step: 4 };
  // step 5: replay window
  const seen = (ctx.seen ?? []).find((s) => s.origin_broker === obj.origin_broker && s.id === obj.id);
  if (seen) return seen.envelope_hash === hashJson(obj) ? { result: "duplicate" } : { result: "refused", code: "replay", step: 5 };
  // step 6: origin broker is the sender's home broker
  const home = homeBroker(doc, obj.from.address);
  if (home !== obj.origin_broker) return { result: "refused", code: "broker_not_authorized", step: 6 };
  return { result: "authenticated", typ: header.typ, home_broker: home };
}
const fed = R("vectors/federation/acceptance.json");
for (const c of fed.cases) {
  const r = accept(c.context, c.request_body, fed.now);
  check(`federation: ${c.name}`, eq(r, c.expected), JSON.stringify(r));
}

// ---------------------------------------------------------------- policy helpers
const ATT = ["self", "vendor", "native", "org-client", "tenant"], CLS = ["consumer", "business", "enterprise"];
function refMatches(policy, ref, address) {
  if (ref === "*") return true;
  if (ref === "@org") return policy.domains.includes(domainOf(address));
  if (ref.startsWith("group:")) {
    const g = policy.groups?.[ref.slice(6)];
    if (!g || !g.members) return false; // claim-based groups can't be evaluated for this principal: fail closed
    return g.members.some((m) => !m.startsWith("group:") && refMatches(policy, m, address));
  }
  if (ref.startsWith("alp:*@")) return domainOf(address) === ref.slice(5);
  return ref === address;
}
const anyRef = (policy, refs, address) => refs.some((r) => refMatches(policy, r, address));
/** Spec 6.5: an exact label, `x.*` (`x` and every label below it) or `*`. */
function labelMatch(pattern, label) {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) return label === pattern.slice(0, -2) || label.startsWith(pattern.slice(0, -1));
  return pattern === label;
}
function labelsOf(scopeId, policy, pointer) {
  if (pointer === "/note") return ["internal"];
  const out = new Set();
  const maps = [SCOPES[scopeId].def.classification, policy?.classification?.overrides?.[scopeId] ?? {}];
  for (const m of maps) for (const [p, ls] of Object.entries(m)) if (prefixMatch(p, pointer)) ls.forEach((l) => out.add(l));
  if (out.size === 0) out.add("internal");
  return [...out];
}
function domainPatternMatch(pat, domain) { return pat.startsWith("*.") ? domain.endsWith(pat.slice(1)) : pat === domain; }
function federationBlocked(policy, otherDomain) {
  if (!policy?.federation || policy.domains.includes(otherDomain)) return false;
  const listed = policy.federation.domains.some((d) => domainPatternMatch(d, otherDomain));
  return policy.federation.mode === "deny" ? listed : !listed;
}
function defaultTerms(policy, fromAddr, toAddr, scope) {
  for (const d of policy?.default_relationships ?? []) {
    const s = d.scopes[scope];
    if (!s) continue;
    const fwd = anyRef(policy, d.from, fromAddr) && anyRef(policy, d.to, toAddr);
    const rev = !!s.reverse && anyRef(policy, d.to, fromAddr) && anyRef(policy, d.from, toAddr);
    if (!fwd && !rev) continue;
    // Spec 6.6.1: forward, reverse, or both united when both apply.
    const parts = [...(fwd ? [s.forward] : []), ...(rev ? [s.reverse] : [])];
    return { id: d.id, terms: { may: [...new Set(parts.flatMap((p) => p.may))], fields: [...new Set(parts.flatMap((p) => p.fields))] }, rate_limit: d.rate_limit };
  }
  return null;
}
/** Spec 5.2: a grant bound to another holder of the counterparty's address (counterparty_principal_id) is void. */
const boundTo = (g, counterpartyId) => counterpartyId === undefined || g.counterparty_principal_id === undefined || g.counterparty_principal_id === counterpartyId;
function explicitGrant(grants, holder, counterparty, scope, now, counterpartyId) {
  return grants.find((g) => g.principal === holder && g.counterparty === counterparty && boundTo(g, counterpartyId) && g.status === "active" && g.scopes[scope] && (!g.expires_at || ms(g.expires_at) > ms(now)));
}
/** Spec 6.6.1: a narrowing grant that doesn't list a scope its default covers narrows that scope away. */
function narrowedAway(grants, holder, counterparty, scope, now, counterpartyId) {
  return grants.some((g) => g.principal === holder && g.counterparty === counterparty && boundTo(g, counterpartyId) && g.status === "active" && g.basis === "narrowing" && !g.scopes[scope] && (!g.expires_at || ms(g.expires_at) > ms(now)));
}
/**
 * Spec 6.5: labels a delegate may add are the ones the scope's map or the policy names exactly, plus the four baseline
 * ones; a pattern `x.*` names `x` but no label below it.
 */
function labelVocabulary(scopeId, policy) {
  const exact = new Set(["public", "internal", "confidential", "restricted"]);
  const add = (l) => { if (l === "*") return; exact.add(l.endsWith(".*") ? l.slice(0, -2) : l); };
  for (const ls of Object.values(SCOPES[scopeId]?.def.classification ?? {})) ls.forEach(add);
  for (const r of policy?.classification?.rules ?? []) r.labels.forEach(add);
  for (const byScope of Object.values(policy?.classification?.overrides ?? {})) for (const ls of Object.values(byScope)) ls.forEach(add);
  for (const m of policy?.delivery_minimums ?? []) m.labels.forEach(add);
  return (l) => exact.has(l);
}
function textLeaf(scopeId, type, pointer) {
  const t = SCOPES[scopeId].def.types[type];
  return isTextLocation(pointer, t?.schema ?? {});
}
const sortU = (a) => [...new Set(a)].sort();

// ---------------------------------------------------------------- sender-side evaluation (spec 6.6)
/** Spec 6.6: the common types that carry only ids and enumerations need no `may`. */
const NO_MAY = ["ack", "decline", "error"];
function evaluateSender(c, policy, now) {
  const { caller, draft } = c;
  const grants = c.grants ?? [];
  let to = String(draft.to).toLowerCase();
  if (!to.startsWith("alp:")) to = "alp:" + to;
  if (!/^alp:[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(to)) return { outcome: "rejected", code: "invalid_input" };
  if (draft.from !== undefined) { let f = String(draft.from).toLowerCase(); if (!f.startsWith("alp:")) f = "alp:" + f; if (f !== caller.principal) return { outcome: "rejected", code: "identity_mismatch" }; }
  if (draft.labels !== undefined) {
    const known = labelVocabulary(draft.scope, policy);
    if (!Array.isArray(draft.labels) || draft.labels.length > 4 || draft.labels.some((l) => !known(l))) return { outcome: "rejected", code: "invalid_input" };
  }
  const sc = SCOPES[draft.scope];
  if (!sc) return { outcome: "rejected", code: "unknown_scope" };
  const COMMON = sc.def.common_types;
  if (!sc.def.types[draft.type] && !COMMON.includes(draft.type)) return { outcome: "rejected", code: "unknown_type" };
  // S2 kill switches and client governance
  const bl = policy?.blocked ?? {};
  if ((bl.principals ?? []).includes(caller.principal) || (bl.delegates ?? []).includes(caller.delegate) || (bl.client_ids ?? []).includes(caller.client_id) || (bl.scopes ?? []).includes(draft.scope) || (bl.domains ?? []).some((d) => domainPatternMatch(d, domainOf(to)))) return { outcome: "rejected", code: "blocked" };
  if (policy?.clients?.mode === "enforce") {
    const cl = policy.clients.allowed.find((x) => x.client_id === caller.client_id);
    if (!cl || !cl.scopes.includes(draft.scope)) return { outcome: "rejected", code: "client_not_allowed" };
  }
  const env = { body: draft.body, ...(draft.note !== undefined ? { note: draft.note } : {}) };
  const L = leaves(env);
  // S3 org deny rules
  if (federationBlocked(policy, domainOf(to))) return { outcome: "rejected", code: "federation_blocked" };
  const toRedact = new Set();
  for (const rule of policy?.classification?.rules ?? []) {
    if (rule.mode !== "enforce" || rule.direction === "inbound") continue;
    if (anyRef(policy, rule.allow, to)) continue;
    const hits = L.filter((p) => labelsOf(draft.scope, policy, p).some((l) => rule.labels.some((pat) => labelMatch(pat, l))));
    if (!hits.length) continue;
    if (rule.action === "redact") hits.forEach((p) => toRedact.add(p));
    else return { outcome: "rejected", code: "org_policy", pointers: sortU(hits), rule: rule.id };
  }
  // S4 relationship and grant
  const G = explicitGrant(grants, caller.principal, to, draft.scope, now);
  const D = narrowedAway(grants, caller.principal, to, draft.scope, now) ? null : defaultTerms(policy, caller.principal, to, draft.scope);
  if (!G && !D) return { outcome: "rejected", code: "no_relationship" };
  const may = G && D ? G.scopes[draft.scope].may.filter((t) => D.terms.may.includes(t)) : G ? G.scopes[draft.scope].may : D.terms.may;
  // Spec 6.6: ack, decline and error need no may; every other type does.
  if (!NO_MAY.includes(draft.type) && !may.includes(draft.type)) return { outcome: "rejected", code: "type_not_allowed" };
  const redaction = G ? G.scopes[draft.scope].redaction : "reject";
  const notCovered = [];
  const commonType = ["ack", "decline", "error", "ask_human"].includes(draft.type);
  for (const p of L) {
    if (toRedact.has(p)) continue;
    if (commonType && p !== "/note") continue; // common-type bodies are exempt from field coverage
    const text = textLeaf(draft.scope, draft.type, p);
    const ok = (!G || covered(p, G.scopes[draft.scope].disclose, text)) && (!D || covered(p, D.terms.fields, text));
    if (!ok) notCovered.push(p);
  }
  if (notCovered.length) {
    if (redaction === "redact") notCovered.forEach((p) => toRedact.add(p));
    else return { outcome: "rejected", code: "not_disclosed", pointers: sortU(notCovered) };
  }
  // S5 apply redactions, S6 schema
  const out = removeLeaves(env, [...toRedact]);
  const typeSchema = sc.compiled[draft.type];
  if (typeSchema && !typeSchema(out.body)) return { outcome: "rejected", code: "schema_invalid", pointers: sortU(typeSchema.errors.map((e) => "/body" + e.instancePath)) };
  // S7 DLP on every free-text leaf
  const L2 = leaves(out);
  const cats = new Set([...(policy?.dlp?.categories ?? []), "payment_card", "private_key", "credential", "government_id"]);
  for (const p of L2) {
    if (!textLeaf(draft.scope, draft.type, p)) continue;
    const value = p === "/note" ? out.note : parsePointer(p).slice(1).reduce((v, k) => v?.[k], out.body);
    const hits = baselineDlp(String(value)).filter((h) => cats.has(h));
    if (hits.length) return { outcome: "rejected", code: "dlp_blocked", pointers: [p], categories: hits };
  }
  // S8 decision
  const labels = sortU([...L2.flatMap((p) => labelsOf(draft.scope, policy, p)), ...(draft.labels ?? [])]);
  let constraints = null;
  for (const m of policy?.delivery_minimums ?? []) {
    if (!labels.some((l) => m.labels.some((pat) => labelMatch(pat, l)))) continue;
    constraints ??= {};
    if (m.min_attestation || m.min_class) {
      constraints.deliver_to ??= {};
      if (m.min_attestation && (!constraints.deliver_to.min_attestation || ATT.indexOf(m.min_attestation) > ATT.indexOf(constraints.deliver_to.min_attestation))) constraints.deliver_to.min_attestation = m.min_attestation;
      if (m.min_class && (!constraints.deliver_to.min_class || CLS.indexOf(m.min_class) > CLS.indexOf(constraints.deliver_to.min_class))) constraints.deliver_to.min_class = m.min_class;
    }
    if (m.no_training) constraints.no_training = true;
    if (m.retention_max) constraints.retention_max = Math.min(constraints.retention_max ?? Infinity, m.retention_max);
  }
  const hold = (G && G.scopes[draft.scope].hold_for_review) || (policy?.hold_for_review?.scopes ?? []).includes(draft.scope);
  const res = { outcome: toRedact.size ? "redacted" : "allowed", grant: G ? G.id : "default:" + D.id, labels, redacted: sortU([...toRedact]), policy_ids: policy ? [`${policy.domains[0]}#${policy.serial}`] : [], status: hold ? "held_for_review" : "queued" };
  if (toRedact.size) res.body = out.body;
  if (constraints) res.constraints = constraints;
  return res;
}
const sv = R("vectors/policy/sender.json");
for (const c of sv.cases) {
  for (const g of c.grants) { const r = valid("grant", g); check(`sender vector grant valid: ${c.name}`, r.ok, JSON.stringify(r.errors)); }
  const got = evaluateSender(c, world.org_policies["example.org"], sv.now);
  check(`sender: ${c.name}`, eq(got, c.expected), JSON.stringify(got));
}

// ---------------------------------------------------------------- recipient-side evaluation (spec 6.7, steps 7-11)
function localParts(now, tz) {
  const f = new Intl.DateTimeFormat("en-US", { timeZone: tz, hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
  const parts = Object.fromEntries(f.formatToParts(new Date(now)).map((p) => [p.type, p.value]));
  return Number(parts.hour) * 60 + Number(parts.minute);
}
function inQuiet(nowMs, q) {
  const m = localParts(nowMs, q.tz);
  const [sh, sm] = q.start.split(":").map(Number), [eh, em] = q.end.split(":").map(Number);
  const s = sh * 60 + sm, e = eh * 60 + em;
  return s <= e ? m >= s && m < e : m >= s || m < e;
}
function quietEnd(nowMs, q) {
  let t = Math.floor(nowMs / 60000) * 60000;
  for (let k = 0; k < 24 * 60 + 1; k++, t += 60000) if (!inQuiet(t, q)) return iso(t);
  return null;
}
function evaluateRecipient(c, policy, now) {
  const e = c.envelope;
  const sc = SCOPES[e.scope];
  const S = e.from.address, Rp = c.recipient;
  const bl = policy?.blocked ?? {};
  // 7 org deny rules
  if ((bl.principals ?? []).includes(S) || (bl.domains ?? []).some((d) => domainPatternMatch(d, domainOf(S))) || (bl.brokers ?? []).includes(e.origin_broker) || (bl.scopes ?? []).includes(e.scope)) return { outcome: "refused", code: "not_accepted" };
  if (federationBlocked(policy, domainOf(S))) return { outcome: "refused", code: "not_accepted" };
  if (!sc) return { outcome: "refused", code: "unknown_scope" };
  const L = leaves(e);
  for (const rule of policy?.classification?.rules ?? []) {
    if (rule.mode !== "enforce" || rule.direction === "outbound") continue;
    if (anyRef(policy, rule.allow, S)) continue;
    const hit = L.some((p) => [...labelsOf(e.scope, policy, p), ...e.labels].some((l) => rule.labels.some((pat) => labelMatch(pat, l))));
    if (hit) return { outcome: "refused", code: "not_accepted" };
  }
  // 8 relationship and grant
  const G = explicitGrant(c.grants ?? [], Rp, S, e.scope, now, e.from.principal_id);
  const D = narrowedAway(c.grants ?? [], Rp, S, e.scope, now, e.from.principal_id) ? null : defaultTerms(policy, S, Rp, e.scope);
  if (!G && !D) return { outcome: "refused", code: "not_accepted", contact_attempt: true };
  const may = G && D ? G.scopes[e.scope].may.filter((t) => D.terms.may.includes(t)) : G ? G.scopes[e.scope].may : D.terms.may;
  if (!NO_MAY.includes(e.type) && !may.includes(e.type)) return { outcome: "refused", code: "not_accepted" };
  const commonType = ["ack", "decline", "error", "ask_human"].includes(e.type);
  for (const p of L) {
    if (commonType && p !== "/note") continue;
    const text = textLeaf(e.scope, e.type, p);
    const ok = (!G || covered(p, G.scopes[e.scope].receive, text)) && (!D || covered(p, D.terms.fields, text));
    if (!ok) return { outcome: "refused", code: "not_accepted" };
  }
  const rl = G?.rate_limit ?? D?.rate_limit;
  if (rl && (c.state?.recent ?? 0) >= rl.count) return { outcome: "refused", code: "rate_limited" };
  // 9 schema
  const ts = sc.compiled[e.type];
  if (ts && !ts(e.body)) return { outcome: "refused", code: "schema_invalid" };
  // 10 DLP (inbound by policy)
  if (policy?.dlp?.inbound) {
    for (const p of L) {
      if (!textLeaf(e.scope, e.type, p)) continue;
      const value = p === "/note" ? e.note : parsePointer(p).slice(1).reduce((v, k) => v?.[k], e.body);
      if (baselineDlp(String(value)).some((h) => (policy.dlp.categories ?? []).includes(h))) return { outcome: "refused", code: "not_accepted" };
    }
  }
  // 11 delivery constraints
  const cons = e.constraints;
  if (cons) {
    const caps = { deliver_to: true, no_training: true, retention_max: true, ...(c.broker_capabilities ?? {}) };
    for (const k of Object.keys(cons)) if (!caps[k]) return { outcome: "refused", code: "constraints_unsupported" };
  }
  // Who may receive it (spec 5.8, 6.7, 6.10): the recipient's agents that no kill switch blocks and whose client the
  // clients list allows; with to.delegate, only the agent it names. When to.delegate names none of them, or none of
  // them meets the constraints, the envelope is accepted and held for the person: never refused, never given to
  // another of the person's agents.
  const listed = (clientId) => policy?.clients?.mode !== "enforce" || policy.clients.allowed.some((x) => x.client_id === clientId);
  const agents = Object.entries(world.delegates)
    .filter(([id, d]) => d.principal === Rp && (e.to.delegate === undefined || e.to.delegate === id) && !(bl.delegates ?? []).includes(id) && !(bl.client_ids ?? []).includes(d.client_id) && listed(d.client_id))
    .map(([, d]) => d);
  if (e.to.delegate !== undefined && agents.length === 0) return { outcome: "accepted", delivery: "hold_for_web_view" };
  const meets = (d) =>
    (!cons.deliver_to?.min_attestation || ATT.indexOf(d.attestation) >= ATT.indexOf(cons.deliver_to.min_attestation)) &&
    (!cons.deliver_to?.min_class || CLS.indexOf(d.class) >= CLS.indexOf(cons.deliver_to.min_class)) &&
    (!cons.no_training || d.no_training === true) &&
    (!cons.retention_max || (d.retention_days != null && d.retention_days <= cons.retention_max));
  if (cons && !agents.some(meets)) return { outcome: "accepted", delivery: "hold_for_web_view" };
  const q = G?.quiet_hours;
  if (q && inQuiet(ms(now), q)) return { outcome: "accepted", delivery: "hold_until", hold_until: quietEnd(ms(now), q) };
  return { outcome: "accepted", delivery: "deliver" };
}
const rv = R("vectors/policy/recipient.json");
for (const c of rv.cases) {
  for (const g of c.grants) { const r = valid("grant", g); check(`recipient vector grant valid: ${c.name}`, r.ok, JSON.stringify(r.errors)); }
  const st = structural(c.envelope);
  check(`recipient vector envelope valid: ${c.name}`, st.ok, JSON.stringify(st));
  const got = evaluateRecipient(c, world.org_policies["example.org"], c.now ?? rv.now);
  check(`recipient: ${c.name}`, eq(got, c.expected), JSON.stringify(got));
}

// ---------------------------------------------------------------- connection requests: uniform answers (spec 6.2.2)
const crv = R("vectors/federation/connection-requests.json");
for (const c of crv.cases) {
  const a = accept(c.context, c.request_body, crv.now);
  check(`connection request passes steps 0-6: ${c.name}`, a.result === "authenticated", JSON.stringify(a));
  const env = JSON.parse(c.request_body);
  const anyKnown = (env.body.scopes ?? []).some((x) => SCOPES[x]);
  // Past steps 0-6 the answer doesn't depend on whether the address exists: accepted with no ledger hash, or the
  // same refusal for a request that names no known scope.
  const got = anyKnown ? { status: "accepted", ledger_hash: false } : { status: "refused", code: "unknown_scope" };
  check(`connection request answer: ${c.name}`, eq(got, c.expected), JSON.stringify(got));
}

// ---------------------------------------------------------------- what one agent may read (spec 6.11, 12.1.4)
const vis = R("vectors/delivery/visibility.json");
for (const c of vis.cases) {
  const r = c.reader;
  const meets = (cons) => !cons || (
    (!cons.deliver_to?.min_attestation || ATT.indexOf(r.attestation) >= ATT.indexOf(cons.deliver_to.min_attestation)) &&
    (!cons.deliver_to?.min_class || CLS.indexOf(r.class) >= CLS.indexOf(cons.deliver_to.min_class)) &&
    (!cons.no_training || r.client?.no_training === true) &&
    (cons.retention_max === undefined || (r.client?.retention_days != null && r.client.retention_days <= cons.retention_max)));
  // Before the reader's binding started, a message received for (stored_at), or signed for (created_at), this
  // delegate id was an earlier agent's.
  const before = (at) => r.since !== undefined && at !== undefined && ms(at) < ms(r.since);
  const visible = c.messages.filter((m) => {
    if (m.direction === "out") return m.from_delegate === undefined || (m.from_delegate === r.delegate && !before(m.created_at));
    if (m.to_delegate !== undefined && (m.to_delegate !== r.delegate || before(m.stored_at))) return false;
    if (m.status === "held" && (m.held_until === undefined || ms(m.held_until) > ms(vis.now))) return false;
    return meets(m.constraints);
  }).map((m) => m.id);
  check(`visibility: ${c.name}`, eq({ visible }, c.expected), JSON.stringify(visible));
}

// ---------------------------------------------------------------- thread: negotiation, ratification, commit
{
  const tv = R("vectors/threads/meeting-commit.json");
  const o = tv.objects;
  const orgKey = [world.jwks["https://broker.example.org/.well-known/jwks.json"].keys[0]];
  for (const [k, env] of Object.entries(o)) {
    if (k.startsWith("ratification")) continue;
    const st = structural(env, tv.now);
    check(`thread object valid: ${k}`, st.ok, JSON.stringify(st.errors?.slice(0, 2)));
    check(`thread object signature: ${k}`, verifyDetached(env, "alp-envelope+jws", orgKey).ok);
    const ts = SCOPES[env.scope].compiled[env.type];
    if (ts) check(`thread body valid: ${k}`, ts(env.body), JSON.stringify(ts.errors));
  }
  check("accept replies to propose by hash", o.accept.in_reply_to === o.propose.id && o.accept.in_reply_to_hash === hashJson(o.propose));
  check("ack replies to accept by hash", o.ack_ratified_lee.in_reply_to === o.accept.id && o.ack_ratified_lee.in_reply_to_hash === hashJson(o.accept));
  check("commit replies to ack by hash", o.commit.in_reply_to === o.ack_ratified_lee.id && o.commit.in_reply_to_hash === hashJson(o.ack_ratified_lee));
  const th = hashJson(o.accept.body.terms);
  check("terms_hash is SHA-256 of JCS(body.terms)", th === o.accept.terms_hash && th === tv.expected.terms_hash && o.commit.terms_hash === th && hashJson(o.commit.body.terms) === th);
  const t = o.accept.body.terms, p = o.propose.body;
  check("accepted terms are one proposed slot with the proposal's details", p.slots.some((s) => s.start === t.start && s.end === t.end) && t.title === p.title && t.duration_minutes === p.duration_minutes && t.timezone === p.timezone && eq(t.location, p.location));
  const recs = [o.ratification_ana, o.ack_ratified_lee.body.ratification];
  for (const r of recs) {
    check(`ratification record valid: ${r.address}`, valid("ratification", r).ok);
    check(`ratification record signature and typ: ${r.address}`, verifyDetached(r, "alp-ratification+jws", orgKey).ok);
    check(`ratification binds thread and terms: ${r.address}`, r.thread === o.propose.thread && r.terms_hash === th && r.iat === Math.floor(ms(r.created_at) / 1000));
  }
  check("ratification principals are the two participants", eq(sortU(recs.map((r) => r.address)), sortU([o.propose.from.address, o.propose.to.address])));
  check("ratified ack comes from the person, not an agent", !o.ack_ratified_lee.from.delegate);
  check("commit references both records", eq(o.commit.ratifications, sortU(recs.map(hashJson))) && eq(o.commit.ratifications, tv.expected.ratifications));
  check("one thread", [o.propose, o.accept, o.ack_ratified_lee, o.commit].every((e) => e.thread === o.propose.thread));
}

// ---------------------------------------------------------------- threads as conversations (spec 9.2, 9.3)
// An evaluator of its own, from the spec's state table, the replies maps, the follow-up rule, how threads end and the
// availability window rule (spec 7.8).
{
  const tv = R("vectors/threads/conversations.json");
  const TERMINAL = ["done", "expired", "cancelled"];
  // Spec 9.2: a thread takes at most 200 messages besides one that ends it.
  const MAX_MESSAGES = 200;
  check("conversations: the thread limit is the spec's", tv.max_thread_messages === MAX_MESSAGES, String(tv.max_thread_messages));
  // Spec 9.2: the types each state accepts. In a scope that negotiates, `open` takes propose instead of inform.
  const accepts = (def, state) => {
    const table = {
      open: ["request", def.negotiable ? "propose" : "inform", "ack", "decline", "ask_human", "error"],
      negotiating: ["counter", "accept", "decline", "ack", "ask_human", "error"],
      agreed: ["commit", "decline", "ack", "ask_human", "error"],
      committed: ["inform", "ack", "ask_human", "error"],
    };
    return (table[state] ?? []).filter((t) => !!def.types[t] || def.common_types.includes(t));
  };
  // Spec 9.3: a follow-up names no message; it is a request, an inform, an ask_human or an error, or a type in starts.
  const followUp = (def, type) => ["request", "inform", "ask_human", "error"].includes(type) || def.starts.includes(type);
  // Spec 9.2: a thread that is neither committed nor closed expires once its expiry has passed.
  const stateAt = (th, atMs) => (!th ? null : !TERMINAL.includes(th.state) && th.state !== "committed" && atMs >= ms(th.expires) ? "expired" : th.state);
  // Spec 7.8: the free intervals of an alp.availability/1 inform lie inside the window of the request it answers, when
  // its recipient sent that request, or otherwise of the latest request its recipient sent.
  const inWindow = (req, inform) => {
    if (!req) return false;
    const from = ms(req.body.window.start), to = ms(req.body.window.end);
    return inform.body.free.every((f) => ms(f.start) >= from && ms(f.end) <= to && ms(f.end) > ms(f.start));
  };
  for (const c of tv.cases) {
    const def = SCOPES[c.scope]?.def;
    check(`conversation scope installed: ${c.name}`, !!def);
    if (!def) continue;
    let th = null;
    const held = new Map();
    c.turns.forEach((t, i) => {
      if (t.body) {
        const v = SCOPES[c.scope].compiled[t.type];
        check(`conversation body valid: ${c.name}, turn ${i + 1}`, !v || v(t.body), JSON.stringify(v?.errors));
      }
      const atMs = ms(t.at);
      const refuse = (code = "thread_state") => ({ outcome: "refused", code });
      const state = stateAt(th, atMs);
      const answered = t.in_reply_to ? held.get(t.in_reply_to) : undefined;
      let r = null;
      if (th) {
        if (TERMINAL.includes(state)) r = refuse();
        else if (!accepts(def, state).includes(t.type)) r = refuse();
      } else if (!def.starts.includes(t.type) || t.in_reply_to) r = refuse();
      if (!r && t.in_reply_to) {
        if (!answered || !(def.replies[answered.type] ?? []).includes(t.type)) r = refuse();
        // Spec 9.2: an accept or a counter answers the latest proposal, and that proposal is the other party's.
        else if ((t.type === "accept" || t.type === "counter") && (answered.by === t.by || th.proposal !== t.in_reply_to)) r = refuse();
      } else if (!r && th && !followUp(def, t.type)) r = refuse();
      let next = th ? { ...th } : { state: "open", expires: t.expires_at, count: 0, first: t.id };
      if (!r) {
        switch (t.type) {
          case "propose": case "counter": next.state = "negotiating"; next.proposal = t.id; delete next.terms; delete next.proposer; break;
          case "accept": next.state = "agreed"; next.terms = t.terms; next.proposer = answered?.by; break;
          case "commit":
            if (t.terms !== th.terms) r = refuse();
            else if (!(t.ratified ?? []).includes("ana") || !(t.ratified ?? []).includes("lee")) r = refuse("needs_ratification");
            else if (t.ratified_until !== undefined && atMs >= ms(t.ratified_until)) r = refuse();
            else if (def.committer === "proposer" && t.by !== th.proposer) r = refuse();
            else next.state = "committed";
            break;
          // Spec 9.2: a decline of the thread's first message, of a proposal or of agreed terms closes the thread; one
          // of a later request turns down that request only.
          case "decline": if (t.in_reply_to === th.first || ["propose", "counter", "accept"].includes(answered?.type)) next.state = state === "agreed" ? "cancelled" : "done"; break;
          case "ack": if (t.status === "completed") { if (state === "agreed") r = refuse(); else next.state = "done"; } break;
          default: if (!th) next.state = "open";
        }
      }
      if (!r && th && th.count >= MAX_MESSAGES && !TERMINAL.includes(next.state)) r = refuse();
      if (!r && t.body && c.scope === "alp.availability/1" && t.type === "inform") {
        const theirs = t.by === "ana" ? "lee" : "ana";
        let req;
        if (answered?.type === "request") req = answered.by === theirs ? answered : undefined;
        else req = [...held.values()].filter((h) => h.type === "request" && h.by === theirs).pop();
        if (!inWindow(req, t)) r = refuse("schema_invalid");
      }
      let got;
      if (r) got = { ...r, state };
      else {
        // Spec 9.2: each message keeps the thread open as long as it lives itself; while terms are on the table or
        // agreed, only a proposal or an accept does.
        const prolongs = !["negotiating", "agreed"].includes(state) || ["propose", "counter", "accept"].includes(t.type);
        if (prolongs && ms(t.expires_at) > ms(next.expires)) next.expires = t.expires_at;
        next.count = (th?.count ?? 0) + 1;
        th = next;
        held.set(t.id, { type: t.type, by: t.by, body: t.body });
        got = { outcome: "accepted", state: th.state };
      }
      check(`conversation: ${c.name}, turn ${i + 1} (${t.by} ${t.type})`, eq(got, t.expected), JSON.stringify(got));
    });
  }
}

// ---------------------------------------------------------------- ledgers
{
  const lv = R("vectors/ledger/matching-ledgers.json");
  const envHash = hashJson(lv.envelope);
  const orgKey = world.jwks["https://broker.example.org/.well-known/jwks.json"].keys;
  check("receipt valid", valid("receipt", lv.receipt).ok, JSON.stringify(V.receipt.errors));
  check("receipt signature and typ", verifyDetached(lv.receipt, "alp-receipt+jws", orgKey).ok);
  check("receipt names the envelope hash", lv.receipt.envelope_hash === envHash && lv.receipt.envelope_id === lv.envelope.id);
  for (const [who, entries] of Object.entries(lv.ledgers)) {
    let prev = null;
    entries.forEach((e, i) => {
      check(`ledger entry valid: ${who} #${i}`, valid("ledger-entry", e).ok, JSON.stringify(V["ledger-entry"].errors));
      const { hash, ...rest } = e;
      check(`ledger hash: ${who} #${i}`, hash === hashJson(rest));
      check(`ledger chain: ${who} #${i}`, e.prev_hash === prev && e.seq === i);
      check(`ledger envelope hash: ${who} #${i}`, e.envelope_hash === envHash);
      // Spec 11.4: 16 to 64 random bytes of salt as unpadded base64url, so the hash a receipt hands the sender confirms
      // no guess of the entry.
      check(`ledger salt: ${who} #${i}`, typeof e.salt === "string" && /^[A-Za-z0-9_-]+$/.test(e.salt) && Buffer.from(e.salt, "base64url").length >= 16 && Buffer.from(e.salt, "base64url").length <= 64);
      prev = hash;
    });
  }
  const lee = lv.ledgers["alp:lee@example.org"][0], pat = lv.ledgers["alp:pat@partner.example"];
  check("receipt carries the recipient's ledger entry hash", lv.receipt.ledger_hash === lee.hash);
  check("sender's receipt entry cross-references", pat[1].receipt_hash === hashJson(lv.receipt) && pat[1].counterparty_ledger_hash === lee.hash);
}

// ---------------------------------------------------------------- delivery sanitizer
for (const c of R("vectors/delivery/sanitize.json").cases) {
  const got = sanitizeText(c.input);
  check(`sanitize: ${c.name}`, got === c.expected, JSON.stringify(got));
}

// ---------------------------------------------------------------- JSON examples embedded in the spec
{
  const specText = fs.readFileSync(path.join(repo, "spec", "alp-v0.1.md"), "utf8");
  const blocks = [...specText.matchAll(/```json\n([\s\S]*?)```/g)].map((m) => m[1]);
  const keysFor = (broker) => Object.values(world.jwks).flatMap((j) => j.keys).filter((k) => Object.entries(world.jwks).some(([u, j]) => u.startsWith(broker + "/") && j.keys.includes(k)));
  const toolByName = Object.fromEntries(toolsDoc.tools.map((t) => [t.name, t]));
  const inboxItemSchema = ajv.compile(toolsDoc.tools.find((t) => t.name === "alp_inbox").outputSchema.properties.items.items);
  // every signed object or ledger entry anywhere in the vectors, by hash
  const vectorHashes = new Set();
  const collect = (v) => { if (Array.isArray(v)) v.forEach(collect); else if (v && typeof v === "object") { if (v.broker_sig || v.hash) vectorHashes.add(hashJson(v)); Object.values(v).forEach(collect); } else if (typeof v === "string" && v.startsWith("{")) { try { collect(JSON.parse(v)); } catch {} } };
  for (const f of walk(path.join(repo, "vectors")).filter((f) => f.endsWith(".json"))) collect(JSON.parse(fs.readFileSync(f, "utf8")));
  for (const c of R("vectors/signatures/detached-jws.json").cases) if (c.expected?.broker_sig) vectorHashes.add(hashJson({ ...c.object, broker_sig: c.expected.broker_sig }));
  const fromVectors = (i, o) => check(`spec block ${i}: copied from the vectors`, vectorHashes.has(hashJson(o)));
  let n = 0;
  for (const [i, text] of blocks.entries()) {
    let obj; try { obj = parseStrict(text); } catch (e) { check(`spec JSON block ${i} parses`, false, e.message); continue; }
    n++;
    if (obj["…"] !== undefined) continue; // abbreviated on purpose
    const o = obj.receipt ?? obj;
    if (obj.name && obj.arguments) { const t = toolByName[obj.name]; const v = ajv.compile(t.inputSchema); check(`spec block ${i}: tool call arguments valid for ${obj.name}`, v(obj.arguments), JSON.stringify(v.errors)); continue; }
    if (obj.error && !obj.receipt) { check(`spec block ${i}: error code registered`, ERROR_CODES_LIST.includes(obj.error.code), obj.error.code); continue; }
    if (o.kind === "untrusted" || o.content?.kind === "untrusted") { const ok = inboxItemSchema(o); check(`spec block ${i}: inbox item shape`, ok || JSON.stringify(inboxItemSchema.errors).includes("pattern"), JSON.stringify(inboxItemSchema.errors)); continue; }
    if (o.brokers) { check(`spec block ${i}: domain document valid`, docSemantics(o).ok); check(`spec block ${i}: domain document equals the vector`, eq(o, world.domain_documents["example.org@42"])); continue; }
    if (o.kind && o.hash) { const { hash, ...rest } = o; check(`spec block ${i}: ledger entry valid and hashed`, valid("ledger-entry", o).ok && hash === hashJson(rest)); fromVectors(i, o); continue; }
    if (o.terms_hash && o.method) { check(`spec block ${i}: ratification record valid and signed`, valid("ratification", o).ok && verifyDetached(o, "alp-ratification+jws", keysFor(o.origin_broker)).ok); fromVectors(i, o); continue; }
    if (o.status && o.envelope_hash) { check(`spec block ${i}: receipt valid and signed`, valid("receipt", o).ok && verifyDetached(o, "alp-receipt+jws", keysFor(o.origin_broker)).ok); fromVectors(i, o); continue; }
    if (o.broker_sig && o.type) { const st = structural(o); const typ = st.schema === "control" ? "alp-control+jws" : "alp-envelope+jws"; check(`spec block ${i}: ${st.schema} valid and signed`, st.ok && verifyDetached(o, typ, keysFor(o.origin_broker)).ok, JSON.stringify(st)); fromVectors(i, o); continue; }
    check(`spec block ${i}: recognised`, false, text.slice(0, 80));
  }
  check("spec has JSON examples", n >= 10, String(n));
}

// ---------------------------------------------------------------- report
console.log(`checks passed: ${pass}, failed: ${fail}`);
if (fail) { for (const f of failures) console.log("FAIL " + f); process.exit(1); }
