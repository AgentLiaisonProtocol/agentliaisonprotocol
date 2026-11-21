// Key checks (Section 4.8, and the fetcher rules of 4.3 as notes for peers). Licensed under Apache-2.0.
import { jkt } from "../../spec/lib.mjs";
import { pass, bad, skip, schemas, schemaErrors, describeSent, describeReceived, parseJson, isObject, isJsonType, refusedLocally, unusableOutcome } from "./common.mjs";
import { MAX_DOCUMENT_BYTES } from "./document.mjs";
import { show } from "../http.mjs";

const OVERSIZE = "the JWKS is over 256 KiB, which alp-check does not read (see keys.size)";

export function observeJwks(ctx, entry) {
  return ctx.memo(`jwks ${entry.id} ${entry.jwks_uri}`, async () => {
    const record = await ctx.http.request({ url: entry.jwks_uri, headers: { accept: "application/json, application/jwk-set+json", "cache-control": "no-cache" }, within: entry.origins, entry: entry.id });
    const parsed = record.status === 200 && !record.error ? parseJson(record) : null;
    return { record, parsed };
  });
}

function thumbprint(key) {
  try { return isObject(key) && typeof key.x === "string" && (key.kty === "OKP" || typeof key.y === "string") ? jkt(key) : null; } catch { return null; }
}

/** Thumbprints the domain pins for a broker id, over every entry with that id. */
function pinnedFor(entries, id) {
  const out = new Set();
  for (const e of entries) if (e.id === id && Array.isArray(e.jkt)) for (const t of e.jkt) if (typeof t === "string") out.add(t);
  return out;
}

export const FAMILY = "keys";

export async function run(ctx) {
  const { entries, reason } = await ctx.entries();
  if (!entries.length) {
    for (const id of ctx.idsOf("keys")) await ctx.check(id, ctx.domain ?? null, () => skip(reason));
    return;
  }
  for (const entry of entries) {
    const subject = entry.id;
    const pre = async () => {
      if (typeof entry.jwks_uri !== "string") return { why: skip(ctx.domain ? "the entry names no `jwks_uri`" : "no --jwks URL was given") };
      const j = await observeJwks(ctx, entry);
      if (refusedLocally(j.record)) return { why: skip(`alp-check did not fetch ${entry.jwks_uri}: ${j.record.error.message}`) };
      return { j };
    };
    const served = async () => {
      const p = await pre();
      if (p.why) return p;
      if (p.j.record.status !== 200 || p.j.record.error) return { why: skip("the JWKS was not served in full (see keys.served)") };
      return p;
    };
    const keysOf = async () => {
      const p = await served();
      if (p.why) return p;
      if (p.j.record.truncated) return { why: skip(OVERSIZE) };
      if (p.j.parsed.error || !isObject(p.j.parsed.value) || !Array.isArray(p.j.parsed.value.keys)) return { why: skip("the JWKS is not a JSON object with a `keys` list (see keys.schema)") };
      return { keys: p.j.parsed.value.keys.filter(isObject), j: p.j };
    };

    await ctx.check("keys.served", subject, async () => {
      const p = await pre();
      if (p.why) return p.why;
      const r = p.j.record;
      const unusable = unusableOutcome(r, { allowTruncated: true });
      if (unusable) return unusable;
      if (r.status === 200) return pass();
      const what = r.status != null && r.status >= 300 && r.status < 400 ? "a redirect, which peers do not follow" : r.status != null ? `status ${r.status}` : r.error.message;
      return bad({ message: `the jwks_uri answered with ${what}`, sent: describeSent(r), received: describeReceived(r), expected: "status 200 and a JWK Set" });
    });

    await ctx.check("keys.content-type", subject, async () => {
      const p = await served();
      if (p.why) return p.why;
      const ct = p.j.record.headers["content-type"];
      if (isJsonType(ct)) return pass({ notes: [`Content-Type: ${ct}`] });
      return bad({ message: `the content type is ${ct ? JSON.stringify(ct) : "missing"}`, received: describeReceived(p.j.record), expected: "application/json or application/<name>+json" });
    });

    await ctx.check("keys.size", subject, async () => {
      const p = await served();
      if (p.why) return p.why;
      const r = p.j.record;
      if (!r.truncated && r.size <= MAX_DOCUMENT_BYTES) return pass({ notes: [`${r.size} bytes`] });
      return bad({ message: r.truncated ? "the JWKS is over 256 KiB" : `the JWKS is ${r.size} bytes`, expected: `at most ${MAX_DOCUMENT_BYTES} bytes` });
    });

    await ctx.check("keys.schema", subject, async () => {
      const p = await served();
      if (p.why) return p.why;
      const { parsed, record } = p.j;
      if (record.truncated) return skip(OVERSIZE);
      if (parsed.error) return bad({ message: parsed.error, received: describeReceived(record), expected: "a JWK Set valid against schemas/jwks.schema.json" });
      const validate = schemas().jwks;
      const notes = parsed.strictNote ? [parsed.strictNote] : [];
      if (validate(parsed.value)) return pass({ notes });
      return bad({ message: `fails the schema: ${schemaErrors(validate).join("; ")}`, received: describeReceived(record), expected: "valid against schemas/jwks.schema.json", notes });
    });

    await ctx.check("keys.current-key-pinned", subject, async () => {
      if (!ctx.domain) return skip("no domain document pins keys for this broker (--broker mode)");
      const k = await keysOf();
      if (k.why) return k.why;
      const pinned = pinnedFor((await ctx.entries()).entries, entry.id);
      if (!pinned.size) return skip("the entry pins no thumbprints (see document.schema)");
      const federation = new Set(k.keys.filter((key) => key.alp_use === "federation").map(thumbprint).filter(Boolean));
      const all = new Map(k.keys.map((key) => [thumbprint(key), key]).filter(([t]) => t));
      const notes = [];
      for (const t of pinned) {
        if (federation.has(t)) continue;
        notes.push(all.has(t) ? `pinned ${t} is a key with alp_use ${JSON.stringify(all.get(t).alp_use)}, not federation` : `pinned ${t} is not in the JWKS (a next key not yet published, or a stale pin)`);
      }
      if ([...pinned].some((t) => federation.has(t))) return pass({ notes });
      return bad({ message: "no thumbprint the entry pins is a federation key in the JWKS, so no envelope this broker signs can be verified. Either the domain pins a stale or wrong thumbprint (the domain's document needs the broker's current key in `jkt`), or the broker does not publish its current federation key at `jwks_uri` (the broker's JWKS needs it)", expected: `a federation key whose RFC 7638 thumbprint is one of ${[...pinned].join(", ")}`, notes });
    });

    await ctx.check("keys.no-unpinned-federation", subject, async () => {
      if (!ctx.domain) return skip("no domain document pins keys for this broker (--broker mode)");
      const k = await keysOf();
      if (k.why) return k.why;
      const pinned = pinnedFor((await ctx.entries()).entries, entry.id);
      const unpinned = [];
      const unknown = [];
      for (const key of k.keys.filter((x) => x.alp_use === "federation")) {
        const t = thumbprint(key);
        if (!t) unknown.push(show(key.kid));
        else if (!pinned.has(t)) unpinned.push(`kid ${JSON.stringify(key.kid)} (thumbprint ${t})`);
      }
      const notes = unknown.length ? [`no thumbprint could be computed for: ${unknown.join(", ")} (see keys.schema)`] : [];
      if (!unpinned.length) return pass({ notes });
      return bad({ message: `federation keys this domain does not pin for ${entry.id}: ${unpinned.join("; ")}`, expected: "every federation key pinned in the entry's jkt", notes });
    });

    await ctx.check("keys.kid-thumbprint", subject, async () => {
      const k = await keysOf();
      if (k.why) return k.why;
      const other = [];
      for (const key of k.keys) {
        const t = thumbprint(key);
        if (t && key.kid !== t) other.push(`kid ${JSON.stringify(key.kid)} (thumbprint ${t})`);
      }
      return other.length ? bad({ message: `kid is not the thumbprint: ${other.join("; ")}` }) : pass();
    });
  }
}
