// Inbox refusals before authentication (Sections 8.3, 12.2.3, 12.2.4 steps 0 and 1, 16).
//
// Every probe is an envelope the specification requires a broker to refuse before any person or relationship is
// involved: it fails acceptance step 0, or step 1 because its sender is on a domain that cannot exist (.invalid).
// Each is valid in every other respect, with fresh ids and timestamps, and is addressed to an address on the
// target's own domain that cannot exist (a long random local part). Its signature is 64 zero bytes: alp-check
// signs nothing. Licensed under Apache-2.0.
import crypto from "node:crypto";
import { canonicalize, b64url, ulid } from "../../spec/lib.mjs";
import { REGISTRY } from "../catalog.mjs";
import { pass, bad, skip, inconclusive, describeSent, describeReceived, parseJson, isObject, refusedLocally, unusableOutcome, alpErrorCode, isTemporaryStatus } from "./common.mjs";

const hex = (n) => crypto.randomBytes(n).toString("hex");
const iso = (ms) => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.000Z$/, "Z");
const unsignedSig = (typ) => `${b64url(Buffer.from(canonicalize({ alg: "Ed25519", kid: "alp-check-unsigned", typ }), "utf8"))}..${b64url(Buffer.alloc(64))}`;

/** The probes, each with the check it serves and the codes the specification allows for it. */
export const PROBES = [
  { check: "inbox.version", probe: "version", codes: ["unsupported_version"] },
  { check: "inbox.strict-json", probe: "strict-json", codes: ["bad_envelope"] },
  { check: "inbox.schema", probe: "schema", codes: ["bad_envelope"] },
  { check: "inbox.lifetime", probe: "lifetime", codes: ["bad_envelope"] },
  { check: "inbox.lifetime", probe: "expiry-order", codes: ["bad_envelope"] },
  { check: "inbox.created-ahead", probe: "created-ahead", codes: ["bad_envelope"] },
  { check: "inbox.delegate-owner", probe: "from-delegate", codes: ["bad_envelope"] },
  { check: "inbox.delegate-owner", probe: "to-delegate", codes: ["bad_envelope"] },
  { check: "inbox.unknown-sender-domain", probe: "unknown-sender-domain", codes: ["discovery_failed", "broker_not_authorized"] },
];

/**
 * A well-formed control envelope (connection_request) from a sender on a domain that cannot exist, to an address
 * that cannot exist on `targetDomain`, for broker `aud`. `now` is in milliseconds.
 */
export function baseControl({ aud, targetDomain, now }) {
  const senderDomain = `alp-check-${hex(8)}.invalid`;
  const created = now - 60_000;
  return {
    alp: "0.1",
    id: ulid(created, hex(16)),
    thread: ulid(created, hex(16)),
    from: { address: `alp:alp-check-${hex(8)}@${senderDomain}`, principal_id: b64url(crypto.randomBytes(16)) },
    to: { address: `alp:alp-check-${hex(20)}@${targetDomain}` },
    aud,
    type: "connection_request",
    body: { scopes: ["alp.availability/1"], purpose: "other", display_name: "alp-check probe" },
    created_at: iso(created),
    expires_at: iso(now + 86_400_000),
    origin_broker: `https://broker.${senderDomain}`,
    broker_sig: unsignedSig("alp-control+jws"),
  };
}

/**
 * A well-formed message envelope (an availability request from an agent of the sender) built on the same parts.
 * A control envelope's `to` has no `delegate`, so the `to.delegate` probe is a message.
 */
export function baseMessage(base) {
  const { body: _b, type: _t, broker_sig: _s, ...rest } = base;
  const start = Date.parse(base.expires_at);
  return {
    ...rest,
    from: { ...base.from, delegate: `${base.from.address}/agent`, attestation: "self", class: "consumer" },
    scope: "alp.availability/1",
    type: "request",
    body: { window: { start: iso(start), end: iso(start + 86_400_000) }, duration_minutes: 30 },
    grant: "default:alp-check",
    labels: [],
    decision: { outcome: "allowed", redacted: [], policy_ids: [] },
    broker_sig: unsignedSig("alp-envelope+jws"),
  };
}

/** The text to POST for one probe. */
export function probeText(probe, ctx) {
  const base = baseControl(ctx);
  const created = Date.parse(base.created_at);
  switch (probe) {
    case "version":
      return JSON.stringify({ ...base, alp: "0.0" });
    case "strict-json": {
      const text = JSON.stringify(base);
      return `{"alp":"0.1",${text.slice(1)}`; // `alp` twice, with the same value
    }
    case "schema": {
      const { broker_sig: _s, ...rest } = base;
      return JSON.stringify(rest);
    }
    case "lifetime":
      return JSON.stringify({ ...base, expires_at: iso(created + 7 * 86_400_000 + 3_600_000) });
    case "expiry-order": {
      // Created 60 seconds ahead (within the 300 seconds allowed), expiring 30 seconds before it was created.
      const at = ctx.now + 60_000;
      return JSON.stringify({ ...base, created_at: iso(at), expires_at: iso(at - 30_000) });
    }
    case "created-ahead": {
      const ahead = ctx.now + 3_600_000;
      return JSON.stringify({ ...base, created_at: iso(ahead), expires_at: iso(ahead + 86_400_000) });
    }
    case "from-delegate": {
      const other = base.from.address.replace("@", `-other-${hex(4)}@`);
      return JSON.stringify({ ...base, from: { ...base.from, delegate: `${other}/agent`, attestation: "self", class: "consumer" } });
    }
    case "to-delegate": {
      const message = baseMessage(base);
      const other = base.to.address.replace("@", "-other@");
      return JSON.stringify({ ...message, to: { ...message.to, delegate: `${other}/agent` } });
    }
    case "unknown-sender-domain":
      return JSON.stringify(base);
    default:
      throw new Error(`no probe ${probe}`);
  }
}

export const SIGNED_REQUESTS = "this inbox answers unsigned requests with 401; Section 12.2.2 lets a broker require signed requests, and alp-check does not sign requests";

/** Answers that are the inbox's refusal of the envelope itself: not a rate limit, not a front proxy's error page. */
export const isRefusal = (r) =>
  r.status != null && r.status >= 400 && r.status !== 429 && !r.error && !r.truncated && (!isTemporaryStatus(r.status) || alpErrorCode(r) != null);

function readError(r) {
  const parsed = parseJson(r);
  if (parsed.error) return { problem: `the body is ${parsed.error}` };
  const v = parsed.value;
  if (!isObject(v)) return { problem: "the body is not a JSON object" };
  if (!isObject(v.error)) return { problem: "the body has no `error` object", value: v };
  return { value: v, code: typeof v.error.code === "string" ? v.error.code : null };
}

export const FAMILY = "inbox";

export async function run(ctx) {
  const ids = ctx.idsOf("inbox");
  if (!ids.some((id) => ctx.wants(id))) return;
  const { entries, reason } = await ctx.entries();
  if (!entries.length) {
    for (const id of ids) await ctx.check(id, ctx.domain ?? null, () => skip(reason));
    return;
  }
  for (const entry of entries) {
    const subject = entry.id;
    if (!ctx.probes) {
      for (const id of ids) await ctx.check(id, subject, () => skip("--no-inbox-probes was given"));
      continue;
    }
    if (typeof entry.inbox !== "string") {
      for (const id of ids) await ctx.check(id, subject, () => skip(ctx.domain ? "the entry names no inbox" : "no --inbox URL was given"));
      continue;
    }
    const locally = ctx.http.permitted(entry.inbox, entry.origins);
    if (!locally.ok) {
      for (const id of ids) await ctx.check(id, subject, () => skip(`alp-check did not contact ${entry.inbox}: ${locally.message}`));
      continue;
    }
    const targetDomain = ctx.domain ?? new URL(entry.id).hostname;
    const send = (probe) =>
      ctx.memo(`probe ${probe} ${entry.id} ${entry.inbox}`, () =>
        ctx.http.request({
          method: "POST",
          url: entry.inbox,
          within: entry.origins,
          entry: entry.id,
          headers: { "content-type": "application/json", accept: "application/json" },
          body: probeText(probe, { aud: entry.id, targetDomain, now: ctx.now() }),
        }),
      );
    const answered = [];
    const wantShape = ctx.wants("inbox.error-shape") || ctx.wants("inbox.retry-after");
    const checks = [...new Set(PROBES.map((p) => p.check))].filter((check) => ctx.wants(check) || wantShape);
    // Every probe is sent before any is judged: what a 401 means depends on how the inbox answered the others.
    for (const check of checks) {
      for (const p of PROBES.filter((x) => x.check === check)) answered.push({ probe: p, r: await send(p.probe) });
    }
    const judgeCodesOf = (p) => [...p.codes, "discovery_failed"];
    // Section 12.2.2 lets an inbox require signed requests and gives no status, code or form for refusing an unsigned
    // one. An inbox that answers every unsigned probe 401 is read that way; a 401 among probes the same inbox judged
    // is not, and could be a refusal at acceptance step 1 with a code the specification does not give for it.
    const all401 = answered.length > 0 && answered.every(({ r }) => r.status === 401);
    const othersJudged = answered.some(({ probe, r }) => r.status !== 401 && !unusableOutcome(r, { judgeCodes: judgeCodesOf(probe) }));

    /** One probe's answer, judged against the codes the specification allows for it. */
    const judge = (p, r) => {
      const sent = describeSent(r);
      const received = describeReceived(r);
      const expected = p.codes.length === 1 ? `refused with \`${p.codes[0]}\`` : `refused with one of ${p.codes.map((c) => `\`${c}\``).join(", ")}`;
      const label = `the ${p.probe} probe`;
      // A 503 `discovery_failed` is judged, not set aside: for a sender on .invalid it can only come from step 1,
      // so it shows that the probe passed step 0.
      const unusable = unusableOutcome(r, { judgeCodes: judgeCodesOf(p) });
      if (unusable) return unusable.outcome === "skip" ? unusable : { ...unusable, message: `${label}: ${unusable.message}` };
      if (r.status === 401) {
        if (all401) return skip(SIGNED_REQUESTS);
        return inconclusive({
          message: `${label}: the inbox answered this probe with 401 while other unsigned probes to the same inbox were ${othersJudged ? "judged" : "not answered 401"}, so it is not read as an inbox that requires signed requests (Section 12.2.2), and the probe's own codes do not have status 401; alp-check could not decide`,
          sent,
          received,
        });
      }
      if (r.status < 400) return bad({ message: `${label} was answered ${r.status}, which is not a refusal`, sent, received, expected });
      const e = readError(r);
      if (!e.code) return bad({ message: `${label} was refused, but the code could not be read: ${e.problem ?? "\`error.code\` is not a string"}`, sent, received, expected });
      if (!p.codes.includes(e.code)) return bad({ message: `${label} was refused with \`${e.code}\``, sent, received, expected });
      return pass({ notes: [`${label}: refused with ${r.status} \`${e.code}\``] });
    };

    for (const check of checks) {
      const outcomes = answered.filter(({ probe }) => probe.check === check).map(({ probe, r }) => judge(probe, r));
      // A check with two probes passes only if both do; a failure of either is reported first.
      await ctx.check(check, subject, () =>
        outcomes.find((o) => o.outcome === "bad") ??
        outcomes.find((o) => o.outcome === "inconclusive") ??
        outcomes.find((o) => o.outcome === "skip") ??
        pass({ notes: outcomes.flatMap((o) => o.notes ?? []) }));
    }

    /** What is wrong with one refusal's shape, as phrases. */
    const shapeProblems = (probe, r) => {
      const problems = [];
      const notes = [];
      const e = readError(r);
      const where = `the ${probe.probe} probe: ${r.status}`;
      if (!e.value || !isObject(e.value.error)) return { problems: [`${where}, ${e.problem}`], notes };
      const { error, ...top } = e.value;
      if ("receipt" in top) problems.push(`${where}, carries a receipt, but an envelope that can't be authenticated gets an unsigned error`);
      if (typeof error.code !== "string") problems.push(`${where}, \`error.code\` is not a string`);
      else if (!Object.hasOwn(REGISTRY, error.code)) problems.push(`${where}, \`${error.code}\` is not a registry code (Section 18.3)`);
      else if (REGISTRY[error.code] !== r.status) problems.push(`${where}, but the registry's status for \`${error.code}\` is ${REGISTRY[error.code]}`);
      if (typeof error.message !== "string") problems.push(`${where}, \`error.message\` is not a string`);
      const extraTop = Object.keys(top).filter((k) => k !== "receipt");
      const extraErr = Object.keys(error).filter((k) => k !== "code" && k !== "message");
      if (extraTop.length || extraErr.length) notes.push(`the ${probe.probe} probe: members beyond the shape: ${[...extraTop, ...extraErr.map((k) => `error.${k}`)].join(", ")}`);
      return { problems, notes };
    };

    await ctx.check("inbox.error-shape", subject, () => {
      // Section 12.2.3's unsigned error is for an envelope that can't be authenticated at steps 0 and 1; Section
      // 12.2.2 gives no form for refusing an unsigned request, so a 401 is never judged here.
      if (all401) return skip(SIGNED_REQUESTS);
      const notes = [];
      const unjudged = answered.filter(({ r }) => r.status === 401 && isRefusal(r));
      // Said in the result line itself, so that a PASS never reads as covering answers it did not judge.
      const notJudged = unjudged.length ? `${unjudged.length} ${unjudged.length === 1 ? "answer" : "answers"} with 401 (${unjudged.map(({ probe }) => `the ${probe.probe} probe`).join(", ")}), since Section 12.2.2 gives no form for refusing an unsigned request` : undefined;
      for (const { probe, r } of unjudged) {
        const { problems, notes: more } = shapeProblems(probe, r);
        notes.push(`the ${probe.probe} probe: 401, not judged here (Section 12.2.2 gives no form for refusing an unsigned request)${problems.length ? `; it would differ from Section 12.2.3: ${problems.map((x) => x.replace(/^the [a-z-]+ probe: 401, /, "")).join("; ")}` : ""}`, ...more);
      }
      const refusals = answered.filter(({ r }) => isRefusal(r) && r.status !== 401);
      if (!refusals.length) return skip("no probe was answered with a refusal of the envelope (rate limits, error pages of a front server and 401 answers are not judged here)", [...new Set(answered.map(({ probe }) => probe.check))]);
      const problems = [];
      let first = null;
      for (const { probe, r } of refusals) {
        const out = shapeProblems(probe, r);
        problems.push(...out.problems);
        notes.push(...out.notes);
        if (out.problems.length) first ??= r;
      }
      if (!problems.length) return pass({ notes, notJudged });
      return bad({ message: problems.join("; "), sent: describeSent(first), received: describeReceived(first), expected: 'the HTTP status the registry gives for the code, a body { "error": { "code", "message" } }, and no receipt', notes, notJudged });
    });

    await ctx.check("inbox.retry-after", subject, () => {
      const busy = answered.filter(({ r }) => r.status === 429 || r.status === 503);
      if (!busy.length) return skip("no 429 or 503 answer was seen");
      const missing = busy.filter(({ r }) => !(r.headers["retry-after"] ?? "").trim());
      if (!missing.length) return pass({ notes: busy.map(({ probe, r }) => `the ${probe.probe} probe: ${r.status}, Retry-After: ${r.headers["retry-after"]}`) });
      return bad({ message: `no Retry-After on the answer to: ${missing.map(({ probe, r }) => `the ${probe.probe} probe (${r.status})`).join(", ")}`, sent: describeSent(missing[0].r), received: describeReceived(missing[0].r), expected: "a Retry-After header" });
    });
  }
}
