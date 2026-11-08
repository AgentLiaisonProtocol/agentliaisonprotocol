// SPDX-License-Identifier: FSL-1.1-ALv2
// The REST mirror of the client binding (spec 12.1.9): the same seven tools as plain HTTPS JSON, for
// agents that write their own API connectors and for scripts. POST {rest}/{tool_name} with the tool's input; 200 returns
// its output; a refusal returns the registry's HTTP status (spec 18.3) and { "error": { ... } }, whose message carries
// the same advice an MCP client gets in its text, and a rate_limited refusal a Retry-After header. GET
// {rest}/openapi.json returns schemas/client/openapi.json with {rest} filled in; any other method on a tool's path is
// 405 (Allow: POST). Bearer tokens: an OAuth access token issued for the REST resource, or a personal access token.

import express from "express";
import type { Router } from "express";
import { bearerChallenge, metadataUrlFor } from "../oauth/resource.ts";
import type { AuthRemedy, ResourceGuard } from "../oauth/resource.ts";
import { runTool } from "./handlers.ts";
import type { ToolContext } from "./handlers.ts";

export interface RestRouterOptions {
  tools: ToolContext;
  guard: ResourceGuard;
  /** Canonical REST base URI (the public origin + /rest). */
  resource: string;
}

const CURLY_QUOTES = /[‘’“”]/;
const STRING = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/y;
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/**
 * Where a text that JSON.parse refused stops being JSON, and what the grammar expected there. Only offsets and the
 * grammar's own words: never a piece of the text.
 */
export function jsonSyntaxError(text: string): { at: number; expected: string } {
  let i = 0;
  const ws = (): void => {
    while (i < text.length && " \t\n\r".includes(text.charAt(i))) i++;
  };
  class Stop extends Error {
    readonly at: number;
    readonly expected: string;
    constructor(at: number, expected: string) {
      super(expected);
      this.at = at;
      this.expected = expected;
    }
  }
  const value = (depth: number): void => {
    if (depth > 512) throw new Stop(i, "less nesting");
    const c = text.charAt(i);
    if (c === "{") {
      i++;
      ws();
      if (text.charAt(i) === "}") {
        i++;
        return;
      }
      for (;;) {
        ws();
        STRING.lastIndex = i;
        const m = STRING.exec(text);
        if (!m) throw new Stop(i, text.charAt(i) === '"' ? "a valid string" : "a member name in double quotes");
        i += m[0].length;
        ws();
        if (text.charAt(i) !== ":") throw new Stop(i, "':' after the member name");
        i++;
        ws();
        value(depth + 1);
        ws();
        const d = text.charAt(i);
        if (d === "}") {
          i++;
          return;
        }
        if (d !== ",") throw new Stop(i, "',' or '}'");
        i++;
      }
    }
    if (c === "[") {
      i++;
      ws();
      if (text.charAt(i) === "]") {
        i++;
        return;
      }
      for (;;) {
        ws();
        value(depth + 1);
        ws();
        const d = text.charAt(i);
        if (d === "]") {
          i++;
          return;
        }
        if (d !== ",") throw new Stop(i, "',' or ']'");
        i++;
      }
    }
    if (c === '"') {
      STRING.lastIndex = i;
      const m = STRING.exec(text);
      if (!m) throw new Stop(i, "a valid string (closed, with control characters escaped)");
      i += m[0].length;
      return;
    }
    for (const lit of ["true", "false", "null"]) {
      if (text.startsWith(lit, i)) {
        i += lit.length;
        return;
      }
    }
    NUMBER.lastIndex = i;
    const m = NUMBER.exec(text);
    if (!m) throw new Stop(i, "a value (an object, array, string in double quotes, number, true, false or null)");
    i += m[0].length;
  };
  try {
    ws();
    value(0);
    ws();
    if (i < text.length) return { at: i, expected: "the end of the JSON text" };
  } catch (err) {
    if (err instanceof Stop) return { at: err.at, expected: err.expected };
    throw err;
  }
  return { at: text.length, expected: "valid JSON" };
}

/** The 400 message for a body that isn't JSON: line, column and character where it stops, and the curly-quote hint. */
function invalidJsonMessage(text: string): string {
  const { at, expected } = jsonSyntaxError(text);
  const before = text.slice(0, at);
  const line = before.split("\n").length;
  const column = at - before.lastIndexOf("\n");
  const where = at >= text.length ? "at the end of the body" : `at line ${line}, column ${column} (character ${at + 1})`;
  return `The request body isn't valid JSON: it stops being JSON ${where}, where ${expected} was expected.${CURLY_QUOTES.test(text) ? " It contains curly quotes: use straight quotes (\")." : ""}`.slice(0, 1000);
}

/** What the caller can do about a refused token, for the error message (WWW-Authenticate carries the OAuth error). */
function remedyText(remedy: AuthRemedy, resource: string): string {
  switch (remedy) {
    case "sign_in":
      return `Send Authorization: Bearer with an OAuth access token issued for ${resource}, or a personal access token from your person's broker page.`;
    case "renew":
      return `Refresh the access token (one issued for ${resource}; a token for another resource, such as the MCP endpoint, is refused here), or create a new personal access token on your person's broker page.`;
    case "admin":
      return "Your person's organization stopped this, or the person isn't active here: ask the organization's administrator.";
  }
}

export function restRouter(opts: RestRouterOptions): Router {
  const { tools, guard } = opts;
  const router = express.Router();
  const raw = express.raw({ limit: "1mb", type: () => true });

  router.get("/rest/openapi.json", (_req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.json(tools.catalog.openapi(opts.resource));
  });

  // A tool is called with POST only: say so, rather than an empty 404.
  router.all("/rest/:tool", (req, res, next) => {
    if (req.method === "POST" || req.method === "OPTIONS") {
      next();
      return;
    }
    const name = String(req.params["tool"] ?? "");
    if (!tools.catalog.byName.has(name)) {
      res.status(404).json({ error: { code: "invalid_input", message: `unknown tool: the tools are ${[...tools.catalog.byName.keys()].join(", ")}, each at POST ${opts.resource}/{tool}.` } });
      return;
    }
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: { code: "invalid_input", message: `Use POST: ${opts.resource}/${name} takes the tool's input as a JSON object in the request body (an empty object {} when it takes none).` } });
  });

  router.post("/rest/:tool", raw, (req, res, next) => {
    (async () => {
      const outcome = await guard.authenticate(req.headers.authorization, "rest");
      if (!outcome.ok) {
        res.setHeader("WWW-Authenticate", bearerChallenge({ resourceMetadata: metadataUrlFor(opts.resource), ...(outcome.error ? { error: outcome.error, description: outcome.description } : {}) }));
        // The registry's code list is closed: a token problem keeps identity_mismatch, and the message says what to do.
        res.status(401).json({ error: { code: "identity_mismatch", message: `${outcome.description}. ${remedyText(outcome.remedy, opts.resource)}` } });
        return;
      }
      const name = String(req.params["tool"] ?? "");
      if (!tools.catalog.byName.has(name)) {
        res.status(404).json({ error: { code: "invalid_input", message: `unknown tool: the tools are ${[...tools.catalog.byName.keys()].join(", ")}.` } });
        return;
      }
      const needed = tools.catalog.scopeFor(name);
      if (!outcome.ctx.scopes.includes(needed)) {
        res.setHeader("WWW-Authenticate", bearerChallenge({ resourceMetadata: metadataUrlFor(opts.resource), error: "insufficient_scope", description: `this tool needs the ${needed} scope`, scope: [...new Set([...outcome.ctx.scopes, needed])] }));
        res.status(403).json({ error: { code: "identity_mismatch", message: `This token lacks the ${needed} scope. Create a personal access token with ${needed} on your person's broker page, or connect the agent again asking for ${needed}.` } });
        return;
      }
      const bytes = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
      let body: unknown = {};
      if (bytes.length > 0) {
        // One leading byte order mark is dropped, as JSON parsers commonly do (Windows PowerShell 5.1 writes one with
        // Out-File and Set-Content -Encoding utf8).
        const decoded = bytes.toString("utf8");
        const text = decoded.charCodeAt(0) === 0xfeff ? decoded.slice(1) : decoded;
        try {
          body = JSON.parse(text);
        } catch {
          res.status(400).json({ error: { code: "invalid_input", message: invalidJsonMessage(text) } });
          return;
        }
        // A tool's input is an object: null, a string, a number or an array isn't one (an empty body means {}).
        if (body === null || typeof body !== "object" || Array.isArray(body)) {
          res.status(400).json({ error: { code: "invalid_input", message: "The request body must be a JSON object." } });
          return;
        }
      }
      const result = await runTool(tools, outcome.ctx, name, body);
      if (result.ok) {
        res.status(200).json(result.structured);
        return;
      }
      const err = result.structured?.["error"] ?? { code: result.code, message: result.message };
      const retry = (err as Record<string, unknown>)["retry_after"];
      if (typeof retry === "number") res.setHeader("Retry-After", String(retry));
      res.status(result.status).json({ error: err });
    })().catch(next);
  });

  router.use("/rest", (err: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    const status = typeof (err as { status?: unknown })?.status === "number" ? (err as { status: number }).status : 400;
    res.status(status === 413 ? 413 : 400).json({ error: { code: status === 413 ? "body_too_large" : "invalid_input", message: status === 413 ? "The request body is larger than 1 MB." : "The request body must be a JSON object." } });
  });

  return router;
}
