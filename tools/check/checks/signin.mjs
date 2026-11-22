// Sign-in metadata (Section 5.6): protected resource metadata (RFC 9728) for the MCP endpoint and the REST mirror,
// and the authorization server's metadata (RFC 8414, OpenID Connect discovery). Licensed under Apache-2.0.
import { pass, bad, inconclusive, skip, describeSent, describeReceived, parseJson, isObject, httpsOrigin, refusedLocally, unusableOutcome } from "./common.mjs";
import { observeChallenge, bearerChallenge, restTool } from "./binding.mjs";
import { show } from "../http.mjs";

/** Where an MCP client looks for protected resource metadata, in order. */
function prmCandidates(resource, challengeUrl) {
  const u = new URL(resource);
  const out = [];
  if (challengeUrl && httpsOrigin(challengeUrl) === u.origin) out.push(challengeUrl);
  const p = u.pathname === "/" ? "" : u.pathname.replace(/\/+$/, "");
  out.push(`${u.origin}/.well-known/oauth-protected-resource${p}`);
  out.push(`${u.origin}/.well-known/oauth-protected-resource`);
  return [...new Set(out)];
}

/** Find the protected resource metadata of one endpoint. */
function observePrm(ctx, entry, kind) {
  const resource = kind === "mcp" ? entry.mcp : entry.rest;
  return ctx.memo(`prm ${entry.id} ${resource}`, async () => {
    const ch = await observeChallenge(ctx, entry, kind);
    const challengeUrl = bearerChallenge(ch)?.params.resource_metadata ?? null;
    const notes = [];
    const offOrigin = !!challengeUrl && httpsOrigin(challengeUrl) !== new URL(resource).origin;
    if (offOrigin) notes.push(`the challenge's resource_metadata ${challengeUrl} is not on the endpoint's origin, so alp-check did not fetch it`);
    const attempts = [];
    for (const url of prmCandidates(resource, challengeUrl)) {
      const r = await ctx.http.request({ url, headers: { accept: "application/json" }, within: entry.origins, entry: entry.id });
      attempts.push(r);
      if (r.status === 200 && !r.error) {
        const parsed = parseJson(r);
        if (!parsed.error && isObject(parsed.value)) return { resource, record: r, doc: parsed.value, attempts, notes, offOrigin, challengeUrl };
      }
    }
    return { resource, record: null, doc: null, attempts, notes, offOrigin };
  });
}

const WELL_KNOWN_PRM = "/.well-known/oauth-protected-resource";

/**
 * The `resource` values RFC 9728 Section 3.3 allows for metadata found at `found` (a URL), for an endpoint of
 * `kind` at `resource`: the identifier the well-known location was built from, and, when the challenge named the
 * location, the URL the request went to. For the REST mirror the REST base URL is accepted too (Section 5.6 item 6
 * binds tokens to it).
 */
export function acceptedResources(kind, resource, found, viaChallenge) {
  const out = [];
  const u = new URL(found);
  if (u.pathname === WELL_KNOWN_PRM || u.pathname === `${WELL_KNOWN_PRM}/`) out.push(u.origin, `${u.origin}/`);
  else if (u.pathname.startsWith(`${WELL_KNOWN_PRM}/`)) out.push(`${u.origin}${u.pathname.slice(WELL_KNOWN_PRM.length)}`);
  if (viaChallenge) out.push(kind === "mcp" ? resource : restTool(resource));
  if (kind === "rest") out.push(resource);
  return [...new Set(out)];
}

/** The authorization server's metadata documents for one issuer. */
function asLocations(issuer) {
  const u = new URL(issuer);
  const p = u.pathname === "/" ? "" : u.pathname.replace(/\/+$/, "");
  return { rfc8414: `${u.origin}/.well-known/oauth-authorization-server${p}`, oidc: `${u.origin}${p}/.well-known/openid-configuration` };
}

function observeAs(ctx, issuer, entryId) {
  return ctx.memo(`as ${issuer}`, async () => {
    const loc = asLocations(issuer);
    ctx.http.allowUrl(loc.rfc8414, "the authorization server named by protected resource metadata");
    ctx.http.allowUrl(loc.oidc, "the authorization server named by protected resource metadata");
    const get = async (url) => {
      const record = await ctx.http.request({ url, headers: { accept: "application/json" }, entry: entryId });
      const parsed = record.status === 200 && !record.error ? parseJson(record) : null;
      return { record, doc: parsed && !parsed.error && isObject(parsed.value) ? parsed.value : null, parsed };
    };
    return { loc, rfc8414: await get(loc.rfc8414), oidc: await get(loc.oidc) };
  });
}

const validIssuer = (s) => {
  if (typeof s !== "string") return false;
  try {
    const u = new URL(s);
    return u.protocol === "https:" && !u.search && !u.hash && !u.username && !u.password;
  } catch { return false; }
};

function judgeMetadataDoc(m, issuer, what) {
  const r = m.record;
  const unusable = unusableOutcome(r);
  if (unusable) return unusable;
  if (r.status !== 200) return bad({ message: `${what} answered ${r.status}`, sent: describeSent(r), received: describeReceived(r), expected: "status 200 and a JSON object", served: false });
  if (!m.doc) return bad({ message: `${what} is not a JSON object${m.parsed?.error ? ` (${m.parsed.error})` : ""}`, received: describeReceived(r), served: false });
  if (m.doc.issuer !== issuer) return bad({ message: `\`issuer\` is ${JSON.stringify(m.doc.issuer)}`, received: describeReceived(r), expected: JSON.stringify(issuer) });
  return pass({ notes: [r.url] });
}

export const FAMILY = "signin";

export async function run(ctx) {
  const all = ctx.idsOf("signin");
  if (!all.some((id) => ctx.wants(id))) return;
  const { entries, reason } = await ctx.entries();
  if (!entries.length) {
    for (const id of all) await ctx.check(id, ctx.domain ?? null, () => skip(reason));
    return;
  }
  const prmIds = ["signin.prm", "signin.prm-authorization-server", "signin.prm-scopes"];
  const asIds = all.filter((id) => !prmIds.includes(id));
  const wantAs = asIds.some((id) => ctx.wants(id));
  const issuers = new Map(); // issuer -> the endpoints whose metadata named it
  for (const entry of entries) {
    for (const kind of ["mcp", "rest"]) {
      const resource = kind === "mcp" ? entry.mcp : entry.rest;
      const subject = typeof resource === "string" ? resource : `${entry.id} (${kind})`;
      if (typeof resource !== "string") {
        for (const id of prmIds) await ctx.check(id, subject, () => skip(`the entry names no ${kind} endpoint`));
        continue;
      }
      const locally = ctx.http.permitted(resource, entry.origins);
      if (!locally.ok) {
        for (const id of prmIds) await ctx.check(id, subject, () => skip(`alp-check did not contact ${resource}: ${locally.message}`));
        continue;
      }
      const found = async () => {
        const m = await observePrm(ctx, entry, kind);
        return m.doc ? { m } : { why: skip("no protected resource metadata was found (see signin.prm)"), m };
      };

      await ctx.check("signin.prm", subject, async () => {
        const m = await observePrm(ctx, entry, kind);
        const sent = m.attempts.map(describeSent).join("; then ");
        const received = m.attempts.map(describeReceived).join("; ");
        if (!m.doc) {
          const tried = m.attempts.filter((r) => !refusedLocally(r));
          if (!tried.length) return skip(`alp-check did not contact any metadata location: ${m.attempts[0]?.error?.message ?? "none was allowed"}`);
          const undecided = tried.map((r) => unusableOutcome(r)).find((o) => o && o.outcome === "inconclusive");
          if (undecided) return inconclusive({ message: `a metadata location gave no usable answer (${undecided.message}), so alp-check could not decide`, sent, received, notes: m.notes, ...(undecided.capped ? { capped: true } : {}) });
          if (m.offOrigin) return inconclusive({ message: "the metadata the challenge names is on another origin, which alp-check does not fetch, and no well-known location on the endpoint's origin served it, so alp-check could not decide", sent, received, notes: m.notes });
          return bad({ message: "no location answered with protected resource metadata", sent, received, expected: "status 200 and a JSON object at the challenge's resource_metadata URL or an RFC 9728 well-known location", notes: m.notes });
        }
        const viaChallenge = m.record.url === m.challengeUrl;
        const accepted = acceptedResources(kind, resource, m.record.url, viaChallenge);
        const found = `found at ${m.record.url}${viaChallenge ? " (named by the challenge)" : ""}`;
        if (!accepted.includes(m.doc.resource)) {
          return bad({ message: `\`resource\` is ${JSON.stringify(m.doc.resource)}`, sent: describeSent(m.record), received: describeReceived(m.record), expected: accepted.map((a) => JSON.stringify(a)).join(" or "), notes: [found, ...m.notes] });
        }
        const notes = [found, ...m.notes];
        if (kind === "rest" && m.doc.resource !== resource) notes.push(`\`resource\` names ${m.doc.resource}, not the REST base URL that Section 5.6 item 6 binds tokens to; RFC 9728 ties it to where the metadata was found, and ALP's text does not settle which a REST mirror uses`);
        return pass({ notes });
      });

      await ctx.check("signin.prm-authorization-server", subject, async () => {
        const f = await found();
        if (f.why) return f.why;
        const as = f.m.doc.authorization_servers;
        if (Array.isArray(as) && as.length > 0 && as.every((s) => typeof s === "string" && s)) {
          return pass({ notes: as.length > 1 ? [`${as.length} authorization servers are named; alp-check checks the first`] : [] });
        }
        if (kind === "rest") return skip(`the REST mirror's metadata gives \`authorization_servers\` as ${show(as)}; RFC 9728 makes the member optional and the MCP authorization specification's rule covers the MCP endpoint, so this is a note, not a result`);
        return bad({ message: `\`authorization_servers\` is ${show(as)}`, received: describeReceived(f.m.record), expected: "a list of at least one authorization server" });
      });

      await ctx.check("signin.prm-scopes", subject, async () => {
        const f = await found();
        if (f.why) return f.why;
        const s = f.m.doc.scopes_supported;
        const ok = Array.isArray(s) && s.includes("read") && s.includes("send");
        if (ok) {
          const notes = [];
          if (s.indexOf("send") < s.indexOf("read")) notes.push("listed in the order send, read");
          const other = s.filter((x) => x !== "read" && x !== "send");
          if (other.length) notes.push(`also lists ${other.map(show).join(", ")}; Section 5.6 lists only read and send${other.includes("offline_access") ? ", and the MCP authorization specification says a server SHOULD NOT list offline_access there" : ""}`);
          return pass({ notes });
        }
        return bad({ message: `\`scopes_supported\` is ${show(s)}`, expected: 'a list that includes "read" and "send"' });
      });

      if (wantAs) {
        const m = await observePrm(ctx, entry, kind);
        const as = m.doc?.authorization_servers;
        if (Array.isArray(as) && typeof as[0] === "string" && as[0]) {
          if (!issuers.has(as[0])) issuers.set(as[0], { from: [], entry: entry.id });
          issuers.get(as[0]).from.push(resource);
        }
      }
    }
  }
  if (!wantAs) return;

  // The authorization server checks run once per issuer.
  if (!issuers.size) {
    for (const id of asIds) await ctx.check(id, ctx.domain ?? entries[0].id, () => skip("no protected resource metadata named an authorization server (see signin.prm-authorization-server)"));
    return;
  }
  for (const [issuer, { from, entry: entryId }] of issuers) {
    const subject = issuer;
    if (!validIssuer(issuer)) {
      for (const id of asIds) await ctx.check(id, subject, () => skip(`the authorization server ${JSON.stringify(issuer)} is not an https URL without query or fragment, so alp-check did not contact it`));
      continue;
    }
    const meta = () => observeAs(ctx, issuer, entryId);
    const members = async () => {
      const a = await meta();
      if (a.rfc8414.doc) return { doc: a.rfc8414.doc, notes: [] };
      if (a.oidc.doc) return { doc: a.oidc.doc, notes: ["read from OpenID Connect discovery, because RFC 8414 metadata was not served"] };
      return { why: skip("no authorization server metadata was found (see signin.as-metadata)") };
    };
    const forEndpoints = `named for ${from.join(", ")}`;

    await ctx.check("signin.as-metadata", subject, async () => {
      const out = judgeMetadataDoc((await meta()).rfc8414, issuer, "RFC 8414 metadata");
      if (out.outcome === "pass") return pass({ notes: [...out.notes, forEndpoints] });
      // Metadata that is not served fails Section 5.6's own sentence; a wrong `issuer` fails the issuer rule.
      return out.outcome === "bad" && out.served === false ? { ...out, basisKey: "not-served" } : out;
    });
    await ctx.check("signin.oidc-discovery", subject, async () => judgeMetadataDoc((await meta()).oidc, issuer, "OpenID Connect discovery"));

    const member = (id, test, expected) =>
      ctx.check(id, subject, async () => {
        const m = await members();
        if (m.why) return m.why;
        const { ok, value } = test(m.doc);
        if (ok) return pass({ notes: m.notes });
        return bad({ message: `found ${value === undefined ? "nothing" : JSON.stringify(value)}`, expected, notes: m.notes });
      });
    await member("signin.pkce-s256", (d) => ({ ok: Array.isArray(d.code_challenge_methods_supported) && d.code_challenge_methods_supported.length === 1 && d.code_challenge_methods_supported[0] === "S256", value: d.code_challenge_methods_supported }), 'code_challenge_methods_supported: ["S256"]');
    await member("signin.iss-parameter", (d) => ({ ok: d.authorization_response_iss_parameter_supported === true, value: d.authorization_response_iss_parameter_supported }), "authorization_response_iss_parameter_supported: true");
    await member("signin.cimd", (d) => ({ ok: d.client_id_metadata_document_supported === true, value: d.client_id_metadata_document_supported }), "client_id_metadata_document_supported: true");
    await member("signin.revocation", (d) => ({ ok: typeof d.revocation_endpoint === "string" && d.revocation_endpoint.length > 0, value: d.revocation_endpoint }), "a revocation_endpoint");
  }
}
