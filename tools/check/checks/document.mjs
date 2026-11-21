// Domain document checks (Sections 4.2, 4.2.1, 4.3, 4.8). Licensed under Apache-2.0.
import { pass, bad, inconclusive, skip, schemas, schemaErrors, describeSent, describeReceived, parseJson, isObject, isJsonType, refusedLocally, isTemporaryStatus, whyUnusable, httpsOrigin } from "./common.mjs";
import { show } from "../http.mjs";

export const MAX_DOCUMENT_BYTES = 64 * 1024;
const BROKER_ID = /^https:\/\/[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?$/;

export const locations = (domain) => [`https://${domain}/.well-known/alp.json`, `https://alp.${domain}/.well-known/alp.json`];

const absent = (r) => r.status === 404 || r.status === 410 || (r.status == null && r.error?.kind === "dns" && r.error.noAddress);
/**
 * A certificate that did not validate. Section 4.3 makes it a failure that stops a peer at that location, and every
 * peer sees the same certificate, so alp-check decides on it (unless its own network intercepts TLS), at whichever
 * location a peer uses: location 1, or location 2 after location 1 answered as absent.
 */
const certificateFailed = (r) => !!r && r.status == null && r.error?.kind === "tls" && !!r.error.certificate;
const INTERCEPT = "every peer sees the same certificate, unless the network alp-check runs on intercepts TLS with a certificate of its own";
/**
 * An answer alp-check can't take as the domain's own: a request it did not send, no answer (a timeout, a refused or
 * reset connection, a TLS failure other than the certificate, a name that can't be resolved now, the request limit),
 * a partial or encoded body, a 429, or a 5xx.
 */
const undecided = (r) => !!r && !absent(r) && !certificateFailed(r) && (refusedLocally(r) || r.status == null || !!r.error || isTemporaryStatus(r.status));
const answerOf = (r) =>
  certificateFailed(r) ? `a certificate that did not validate (${r.error.code})`
  : r.status == null ? whyUnusable(r)
  : r.status >= 300 && r.status < 400 ? `a redirect (${r.status})`
  : `status ${r.status}`;
const PEERS_STOP = "location 1 answered 200 with something that is not a domain document; a peer stops there and never reads location 2 (Section 4.3)";
export const OVERSIZE = "the domain document is over 256 KiB, which alp-check does not read (see document.size)";

/**
 * Fetch the domain document the way Section 4.3 tells a peer to, and also look at location 2 when location 1
 * failed in another way, so the report can say whether location 2 would have helped.
 */
export function observeDocument(ctx) {
  return ctx.memo("document", async () => {
    const [l1, l2] = locations(ctx.domain);
    const headers = { accept: "application/json", "cache-control": "no-cache" };
    const r1 = await ctx.http.request({ url: l1, headers });
    const r2 = r1.status === 200 ? null : await ctx.http.request({ url: l2, headers });
    const peerGoesOn = absent(r1);
    // A 200 whose body did not arrive in full (the timeout) is not used: alp-check can't judge a partial body.
    const whole = (r) => r && r.status === 200 && !r.error;
    const used = whole(r1) ? { location: 1, record: r1 } : r1.status !== 200 && whole(r2) ? { location: 2, record: r2 } : null;
    let parsed = null;
    if (used) parsed = parseJson(used.record);
    const isDocument = !!parsed && !parsed.error && isObject(parsed.value);
    return { r1, r2, peerGoesOn, used, parsed, isDocument, oversize: !!used?.record.truncated };
  });
}

/** The parsed document when it is a JSON object, else null. */
export async function documentObject(ctx) {
  const d = await observeDocument(ctx);
  return d.parsed && !d.parsed.error && isObject(d.parsed.value) ? d.parsed.value : null;
}

/**
 * Broker entries usable for the other families: objects whose `id` has the form of a broker id and parses as an
 * https origin. An id the schema's pattern allows but a URL parser refuses (a port over 65535, a numeric last label)
 * is left out here, never contacted, and reported by document.urls-on-origin.
 */
export async function documentEntries(ctx) {
  const doc = await documentObject(ctx);
  if ((await observeDocument(ctx)).oversize) return { entries: [], reason: OVERSIZE };
  if (!doc || !Array.isArray(doc.brokers)) return { entries: [], reason: "the domain document was not found, or has no `brokers` list (see document.found and document.schema)" };
  const entries = [];
  const ignored = [];
  doc.brokers.forEach((b, i) => {
    const origin = isObject(b) && typeof b.id === "string" && BROKER_ID.test(b.id) ? httpsOrigin(b.id) : null;
    if (origin) entries.push({ ...b, index: i, origin });
    else ignored.push(i);
  });
  return { entries, ignored, reason: entries.length ? null : "the domain document has no broker entry whose `id` is an https origin" };
}

const both = (d) => [d.r1, d.r2].filter(Boolean);
const sentBoth = (d) => both(d).map(describeSent).join("; then ");
const receivedBoth = (d) => both(d).map((r, i) => `location ${i + 1}: ${describeReceived(r)}`).join("; ");

export const FAMILY = "document";

export async function run(ctx) {
  const domain = ctx.domain;
  if (!domain) {
    for (const id of ctx.idsOf("document")) await ctx.check(id, null, () => skip("no domain was given (--broker mode, a Local-profile broker has no domain document; Section 3.3)"));
    return;
  }
  const need = () => observeDocument(ctx);
  const noDoc = () => skip("no domain document was found (see document.found)");

  await ctx.check("document.found", domain, async () => {
    const d = await need();
    const r1 = d.r1;
    const sent = sentBoth(d);
    const received = receivedBoth(d);
    if (d.used?.location === 1) return pass({ notes: [`served at location 1 (${r1.url})`, ...(d.isDocument || d.oversize ? [] : [PEERS_STOP])] });
    if (d.used?.location === 2 && d.peerGoesOn) return pass({ notes: [`served at location 2 (${d.r2.url}); location 1 answered as absent, so a peer goes on to location 2`] });
    const expected = "status 200 with the document at location 1, or 404 or 410 there (or no address records) and the document at location 2";
    if (d.used?.location === 2) {
      // Section 4.3: any failure at location 1 other than 404, 410 or no address records stops the peer there.
      const message = `location 2 serves the document, but location 1 answered with ${answerOf(r1)}, and a peer that follows Section 4.3 stops at location 1 and never reads location 2`;
      if (undecided(r1)) return inconclusive({ message: `${message}; that answer may be temporary, so alp-check could not decide`, sent, received });
      return bad({ message, sent, received, expected, notes: certificateFailed(r1) ? [INTERCEPT] : [] });
    }
    // The location a peer uses decides first: a certificate that does not validate there is decided, whatever the
    // other location answered.
    if (certificateFailed(r1)) return bad({ message: `location 1 (${r1.url}) answered with ${answerOf(r1)}, which stops a peer there, and location 2 does not serve the document either`, sent, received, expected, notes: [INTERCEPT] });
    if (d.peerGoesOn && certificateFailed(d.r2)) return bad({ message: `location 1 answered with ${answerOf(r1)}, so a peer goes on to location 2 (${d.r2.url}), which answered with ${answerOf(d.r2)}`, sent, received, expected, notes: [INTERCEPT] });
    if (both(d).some(undecided)) return inconclusive({ message: `no location served the document, and ${both(d).filter(undecided).map((r) => `${r.url} answered with ${answerOf(r)}`).join("; ")}, so alp-check could not decide`, sent, received });
    return bad({ message: "neither location served the document with status 200", sent, received, expected });
  });

  await ctx.check("document.fallback", domain, async () => {
    const d = await need();
    const r1 = d.r1;
    if (r1.status === 200 && !r1.error) {
      if (d.isDocument || d.oversize) return pass();
      return bad({ message: PEERS_STOP, sent: describeSent(r1), received: describeReceived(r1), expected: "the document at location 1, or 404 or 410 there so that peers go on to location 2" });
    }
    if (d.peerGoesOn) return pass({ notes: ["location 1 answered as absent, so a peer goes on to location 2"] });
    if (undecided(r1)) return inconclusive({ message: `location 1 answered with ${answerOf(r1)}, which may be temporary, so alp-check could not decide`, sent: describeSent(r1), received: describeReceived(r1) });
    const l2 = d.r2 && d.r2.status === 200 ? "Location 2 serves the document, but a peer never asks for it." : "Location 2 does not serve it either.";
    return bad({
      message: `location 1 answered with ${answerOf(r1)}; a peer stops there and treats the domain as unavailable. ${l2}`,
      sent: describeSent(r1),
      received: describeReceived(r1),
      expected: "status 200 with the document at location 1, or 404 or 410 (or no address records) so that peers go on to location 2",
      notes: certificateFailed(r1) ? [INTERCEPT] : [],
    });
  });

  await ctx.check("document.tls", domain, async () => {
    if (ctx.devMap) return skip("the development host map is in use, so TLS was not checked");
    const d = await need();
    const path = d.peerGoesOn ? both(d) : [d.r1];
    const refused = path.find(refusedLocally);
    if (refused) return skip(`alp-check did not contact ${refused.url}: ${refused.error.message}`);
    // A certificate that does not validate is decided: every peer sees the same certificate. Any other TLS failure
    // (a reset handshake, a protocol error) may be the checker's own network, so it is undecided, as everywhere else.
    const certificate = path.find((r) => r.error?.kind === "tls" && r.error.certificate);
    if (certificate) return bad({ message: `location ${certificate === d.r1 ? 1 : 2} (${certificate.url}) answered with ${answerOf(certificate)}`, sent: describeSent(certificate), received: describeReceived(certificate), expected: "a certificate valid for the host", notes: [INTERCEPT] });
    const handshake = path.find((r) => r.error?.kind === "tls");
    if (handshake) return inconclusive({ message: `alp-check could not decide: ${handshake.error.message}, which is not a certificate failure and may be the network alp-check runs on`, sent: describeSent(handshake), received: describeReceived(handshake) });
    // A handshake alone is not the document served over HTTPS: with no document, this check has nothing to judge.
    if (d.used && path.includes(d.used.record)) return pass({ notes: [`location ${d.used.location}`] });
    return skip("no location a peer would use served the document (see document.found)");
  });

  await ctx.check("document.content-type", domain, async () => {
    const d = await need();
    if (!d.used) return noDoc();
    const ct = d.used.record.headers["content-type"];
    if (isJsonType(ct)) return pass({ notes: [`Content-Type: ${ct}`] });
    return bad({ message: `the content type is ${ct ? JSON.stringify(ct) : "missing"}`, sent: describeSent(d.used.record), received: describeReceived(d.used.record), expected: "application/json or application/<name>+json" });
  });

  await ctx.check("document.size", domain, async () => {
    const d = await need();
    if (!d.used) return noDoc();
    const r = d.used.record;
    if (!r.truncated && r.size <= MAX_DOCUMENT_BYTES) return pass({ notes: [`${r.size} bytes`] });
    return bad({ message: r.truncated ? "the document is over 256 KiB" : `the document is ${r.size} bytes`, sent: describeSent(r), received: describeReceived(r), expected: `at most ${MAX_DOCUMENT_BYTES} bytes` });
  });

  await ctx.check("document.schema", domain, async () => {
    const d = await need();
    if (!d.used) return noDoc();
    const r = d.used.record;
    if (d.oversize) return skip(OVERSIZE);
    const stop = d.used.location === 1 && !d.isDocument ? [PEERS_STOP] : [];
    if (d.parsed.error) return bad({ message: d.parsed.error, sent: describeSent(r), received: describeReceived(r), expected: "a JSON object valid against schemas/domain-document.schema.json", notes: stop });
    const notes = d.parsed.strictNote ? [d.parsed.strictNote] : [];
    const validate = schemas().document;
    if (validate(d.parsed.value)) return pass({ notes });
    return bad({ message: `fails the schema: ${schemaErrors(validate).join("; ")}`, received: describeReceived(r), expected: "valid against schemas/domain-document.schema.json", notes });
  });

  const withDoc = async (fn) => {
    const d = await need();
    if (!d.used) return noDoc();
    if (d.oversize) return skip(OVERSIZE);
    const doc = await documentObject(ctx);
    if (!doc) return skip("the document is not a JSON object (see document.schema)");
    return fn(doc);
  };
  const withBrokers = (fn) => withDoc((doc) => (Array.isArray(doc.brokers) ? fn(doc, doc.brokers.filter(isObject)) : skip("the document has no `brokers` list (see document.schema)")));

  await ctx.check("document.domain-matches", domain, () => withDoc((doc) => {
    if (doc.domain === domain) return pass();
    return bad({ message: `\`domain\` is ${show(JSON.stringify(doc.domain))}`, expected: JSON.stringify(domain) });
  }));

  await ctx.check("document.unique-ids", domain, () => withBrokers((doc, brokers) => {
    const seen = new Map();
    for (const b of brokers) if (typeof b.id === "string") seen.set(b.id, (seen.get(b.id) ?? 0) + 1);
    const dup = [...seen].filter(([, n]) => n > 1).map(([id]) => id);
    return dup.length ? bad({ message: `more than one entry has the id ${dup.join(", ")}` }) : pass();
  }));

  await ctx.check("document.one-wildcard", domain, () => withBrokers((doc, brokers) => {
    const n = brokers.filter((b) => b.principals === "*").length;
    return n > 1 ? bad({ message: `${n} entries have "principals": "*"`, expected: "at most one" }) : pass();
  }));

  await ctx.check("document.no-overlap", domain, () => withBrokers((doc, brokers) => {
    const lists = new Map();
    for (const b of brokers) {
      if (!Array.isArray(b.principals)) continue;
      for (const a of new Set(b.principals.filter((x) => typeof x === "string"))) lists.set(a, [...(lists.get(a) ?? []), show(b.id)]);
    }
    const twice = [...lists].filter(([, ids]) => ids.length > 1);
    if (!twice.length) return pass();
    return bad({ message: `listed by more than one entry: ${twice.slice(0, 5).map(([a, ids]) => `${a} (${ids.join(", ")})`).join("; ")}${twice.length > 5 ? `; and ${twice.length - 5} more` : ""}` });
  }));

  await ctx.check("document.addresses-on-domain", domain, () => withBrokers((doc, brokers) => {
    if (typeof doc.domain !== "string") return skip("the document has no `domain` string to compare with (see document.schema)");
    const foreign = [];
    for (const b of brokers) {
      if (!Array.isArray(b.principals)) continue;
      for (const a of b.principals) if (typeof a === "string" && a.slice(a.lastIndexOf("@") + 1) !== doc.domain) foreign.push(a);
    }
    if (!foreign.length) return pass();
    return bad({ message: `not on ${doc.domain}: ${foreign.slice(0, 5).join(", ")}${foreign.length > 5 ? ` and ${foreign.length - 5} more` : ""}` });
  }));

  await ctx.check("document.urls-on-origin", domain, () => withBrokers((doc, brokers) => {
    const off = [];
    for (const b of brokers) {
      let origin = null;
      if (typeof b.id === "string") try { origin = new URL(b.id).origin; } catch { /* reported below */ }
      if (!origin) {
        off.push(`${show(b.id)}: the id is not an origin a URL parser accepts, so no URL is on it (alp-check does not contact this entry)`);
        continue;
      }
      for (const k of ["inbox", "jwks_uri", "mcp", "rest", "operator_statement"]) {
        if (!(k in b)) continue;
        let o = null;
        if (typeof b[k] === "string") try { o = new URL(b[k]).origin; } catch { /* not a URL */ }
        if (o !== origin) off.push(`${show(b.id)} ${k}: ${show(b[k])}`);
      }
    }
    if (!off.length) return pass();
    return bad({ message: `not on the entry's own origin: ${off.join("; ")}`, notes: ["alp-check does not contact a URL that is not on its entry's origin"] });
  }));

  await ctx.check("document.revoked-not-pinned", domain, () => withBrokers((doc, brokers) => {
    if (!Array.isArray(doc.revoked_jkt) || doc.revoked_jkt.length === 0) return pass({ notes: ["the document lists no revoked keys"] });
    const revoked = new Set(doc.revoked_jkt.filter(isObject).map((r) => r.jkt));
    const still = [];
    for (const b of brokers) if (Array.isArray(b.jkt)) for (const t of b.jkt) if (typeof t === "string" && revoked.has(t)) still.push(`${show(b.id)}: ${t}`);
    return still.length ? bad({ message: `revoked and still pinned: ${still.join("; ")}` }) : pass();
  }));
}
