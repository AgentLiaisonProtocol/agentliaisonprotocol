// Helpers shared by the check families. Licensed under Apache-2.0.
import fs from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parseStrict } from "../../spec/lib.mjs";
import { excerpt, isJsonType } from "../http.mjs";
import { REPO } from "../spec-text.mjs";

const BASE = "tag:agentliaisonprotocol.org,2026-11-08:spec/0.1/schemas/";
let validators = null;

/** Compiled validators for the schemas the checker uses (read from the repository's schemas/). */
export function schemas() {
  if (validators) return validators;
  const ajv = new Ajv2020({ strict: true, strictRequired: false, allErrors: true });
  addFormats(ajv);
  ajv.addKeyword({ keyword: "x-alp-text", schemaType: "string" });
  const dir = path.join(REPO, "schemas");
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".schema.json")) ajv.addSchema(JSON.parse(fs.readFileSync(p, "utf8")));
    }
  };
  walk(dir);
  const get = (n) => ajv.getSchema(BASE + n);
  validators = { document: get("domain-document.schema.json"), jwks: get("jwks.schema.json"), envelope: get("envelope.schema.json"), control: get("control.schema.json") };
  return validators;
}

/** Ajv errors as short readable lines. */
export function schemaErrors(validate, max = 5) {
  const errs = validate.errors ?? [];
  const lines = errs.slice(0, max).map((e) => `${e.instancePath || "(top level)"} ${e.message}${e.params?.additionalProperty ? ` (${e.params.additionalProperty})` : ""}`);
  if (errs.length > max) lines.push(`and ${errs.length - max} more`);
  return lines;
}

// ---------------------------------------------------------------- outcomes
// A check function returns one of these; the runner adds the id, level and subject.
export const pass = (details = {}) => ({ outcome: "pass", ...details });
/** The behaviour differs from the check's sentence: a failure for a required check, a warning for a recommended one. */
export const bad = (details = {}) => ({ outcome: "bad", ...details });
/** The checker could not decide (no usable answer, a rate limit, the request limit). Always a warning. */
export const inconclusive = (details = {}) => ({ outcome: "inconclusive", ...details });
/** alp-check itself failed while judging; reported apart from every other result, and the run exits 3. */
export const internalError = (message) => ({ outcome: "error", message });
/**
 * The check did not run, for `reason`. `after` lists the checks it depends on; when it is not given, the check ids a
 * reason names in "(see ...)" are taken. The summary uses it to count checks skipped because another could not decide.
 */
export const skip = (reason, after = null) => ({ outcome: "skip", reason, ...(after ? { after } : {}) });

// ---------------------------------------------------------------- describing requests and answers
export function describeSent(r) {
  if (!r) return undefined;
  const head = `${r.method} ${r.url}`;
  return r.sentBody == null ? head : `${head} with body: ${r.sentBody}`;
}

export function describeReceived(r) {
  if (!r) return undefined;
  if (r.error && r.status == null) return `no answer: ${r.error.message}`;
  const parts = [String(r.status)];
  if (r.headers["content-type"]) parts.push(r.headers["content-type"]);
  if (r.location) parts.push(`Location: ${excerpt(r.location)}`);
  if (r.headers["www-authenticate"]) parts.push(`WWW-Authenticate: ${excerpt(r.headers["www-authenticate"])}`);
  if (r.headers["retry-after"]) parts.push(`Retry-After: ${excerpt(r.headers["retry-after"])}`);
  parts.push(r.truncated ? "over 256 KiB (read stopped)" : `${r.size} bytes`);
  let s = parts.join(", ");
  if (r.text) s += `: ${excerpt(r.text)}`;
  if (r.error) s += ` (then: ${r.error.message})`;
  return s;
}

/** A request alp-check chose not to send: not allowed, not https, or not in the development host map. */
export const refusedLocally = (r) => !!r && r.status == null && !!r.error && ["not-allowed", "not-https", "not-mapped"].includes(r.error.kind);

/**
 * Statuses that say "not now" rather than anything about the request: a rate limit (429) or any server error (5xx,
 * 500 included, which Section 10.2 retries and Section 18.3 marks retryable as `internal`). One rule for every family.
 */
export const isTemporaryStatus = (status) => status === 429 || (Number.isInteger(status) && status >= 500 && status <= 599);

/** The ALP error code in an answer's body (`{ "error": { "code" } }`), or null. */
export function alpErrorCode(r) {
  if (!r || r.truncated || !r.text) return null;
  try {
    const v = JSON.parse(r.text);
    return isObject(v) && isObject(v.error) && typeof v.error.code === "string" ? v.error.code : null;
  } catch { return null; }
}

/** Why a record could not be judged, as a sentence. */
export function whyUnusable(r) {
  if (!r) return "no request was made";
  if (r.error?.kind === "cap") return r.error.message;
  if (r.error) return r.error.message;
  if (r.truncated) return "the answer is over 256 KiB, which alp-check does not read";
  if (r.status === 429) return "the answer was 429, a rate limit";
  if (isTemporaryStatus(r.status)) return `the answer was ${r.status}, a server error that may be temporary`;
  return `status ${r.status}`;
}

/**
 * The one rule every family applies before its own logic: whether an answer can be judged at all. Returns null when
 * it can. Otherwise it returns the result to report: a skip for a request alp-check refused to send, and "could not
 * decide" (never a failure) for a timeout, a connection or TLS failure, the request limit, an encoded or partial
 * body, a body over the size cap (unless `allowTruncated`), and a 429 or any 5xx, unless that answer is an
 * ALP error whose code is one of `judgeCodes`: codes that say the target judged the request itself (for an inbox
 * probe, the codes the probe allows, and `discovery_failed`, which for a sender on a domain that cannot exist can
 * only come from acceptance step 1).
 */
export function unusableOutcome(r, { judgeCodes = [], allowTruncated = false } = {}) {
  if (!r) return inconclusive({ message: "no request was made" });
  if (refusedLocally(r)) return skip(`alp-check did not contact ${r.url}: ${r.error.message}`);
  const details = { sent: describeSent(r), received: describeReceived(r) };
  if (r.error?.kind === "cap") return inconclusive({ message: r.error.message, capped: true, ...details });
  if (r.status == null || r.error) return inconclusive({ message: `alp-check could not decide: ${whyUnusable(r)}`, ...details });
  if (r.truncated && !allowTruncated) return inconclusive({ message: `alp-check could not decide: ${whyUnusable(r)}`, ...details });
  if (isTemporaryStatus(r.status)) {
    const code = alpErrorCode(r);
    if (code && judgeCodes.includes(code)) return null;
    const retry = r.headers["retry-after"] ? ` (Retry-After: ${excerpt(r.headers["retry-after"], 40)})` : "";
    return inconclusive({ message: `alp-check could not decide: ${whyUnusable(r)}${retry}; try again later`, ...details });
  }
  return null;
}

/** Parse a response body as JSON. Returns { value } or { error }; notes a duplicate member name separately. */
export function parseJson(r) {
  if (r.truncated) return { error: "the response is over 256 KiB, so alp-check did not parse it" };
  let value;
  try { value = JSON.parse(r.text); } catch (e) { return { error: `not JSON (${e.message})` }; }
  let strictNote = null;
  try { parseStrict(r.text); } catch (e) { strictNote = `a strict I-JSON parser refuses this body (${e.message})`; }
  return { value, strictNote };
}

export const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
export { isJsonType, excerpt };

/** The origin of an https URL, or null. */
export function httpsOrigin(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:" ? u.origin : null;
  } catch { return null; }
}
