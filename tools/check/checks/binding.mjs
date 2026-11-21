// Client binding without a token (Sections 5.6 item 1, 12.1.5): an unauthenticated request is answered 401 with a
// Bearer challenge carrying resource_metadata and scope. Licensed under Apache-2.0.
import { parseChallenges } from "../http.mjs";
import { pass, bad, skip, describeSent, describeReceived, unusableOutcome } from "./common.mjs";

// The first request an MCP client sends under the initialization-based revision; with no token it must be refused.
const MCP_BODY = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "alp-check", version: "0.1" } },
});

export const restTool = (rest) => `${rest.replace(/\/+$/, "")}/alp_whoami`;

/** POST to the MCP endpoint, or to {rest}/alp_whoami, with no token. Shared with the sign-in family. */
export function observeChallenge(ctx, entry, kind) {
  const url = kind === "mcp" ? entry.mcp : restTool(entry.rest);
  return ctx.memo(`challenge ${kind} ${entry.id} ${url}`, () =>
    ctx.http.request({
      method: "POST",
      url,
      within: entry.origins,
      entry: entry.id,
      headers: kind === "mcp" ? { "content-type": "application/json", accept: "application/json, text/event-stream" } : { "content-type": "application/json", accept: "application/json" },
      body: kind === "mcp" ? MCP_BODY : "{}",
    }),
  );
}

/** The Bearer challenge of a 401, with its parameters, or null. */
export function bearerChallenge(r) {
  return parseChallenges(r?.headers?.["www-authenticate"]).find((c) => c.scheme.toLowerCase() === "bearer") ?? null;
}

async function judge(ctx, entry, kind) {
  const endpoint = kind === "mcp" ? entry.mcp : entry.rest;
  if (typeof endpoint !== "string") return skip(`the entry names no ${kind} endpoint`);
  const r = await observeChallenge(ctx, entry, kind);
  const unusable = unusableOutcome(r, { allowTruncated: true });
  if (unusable) return unusable;
  const sent = describeSent(r);
  const received = describeReceived(r);
  const expected = "401 with WWW-Authenticate: Bearer resource_metadata=\"...\", scope=\"...\"";
  if (r.status !== 401) return bad({ message: `answered ${r.status} to a request with no token`, sent, received, expected });
  const b = bearerChallenge(r);
  if (!b) return bad({ message: "the 401 has no Bearer challenge in WWW-Authenticate", sent, received, expected });
  const missing = ["resource_metadata", "scope"].filter((p) => typeof b.params[p] !== "string" || b.params[p] === "");
  if (missing.length) return bad({ message: `the Bearer challenge carries no ${missing.join(" and no ")}`, sent, received, expected });
  return pass({ notes: [`resource_metadata="${b.params.resource_metadata}", scope="${b.params.scope}"`] });
}

export const FAMILY = "binding";

export async function run(ctx) {
  const { entries, reason } = await ctx.entries();
  if (!entries.length) {
    for (const id of ctx.idsOf("binding")) await ctx.check(id, ctx.domain ?? null, () => skip(reason));
    return;
  }
  for (const entry of entries) {
    await ctx.check("binding.mcp-challenge", entry.id, () => judge(ctx, entry, "mcp"));
    await ctx.check("binding.rest-challenge", entry.id, () => judge(ctx, entry, "rest"));
  }
}
