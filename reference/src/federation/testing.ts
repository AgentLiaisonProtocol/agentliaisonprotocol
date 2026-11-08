// SPDX-License-Identifier: FSL-1.1-ALv2
// Test support for src/federation (not a test file itself): a scriptable JSON server on a fixed loopback port,
// and a helper that POSTs raw bodies to a broker's inbox through the dev host map.

import http from "node:http";
import type { IncomingMessage } from "node:http";
import type { HardenedFetcher } from "./fetcher.ts";
import { closeServer, listenOn } from "./server.ts";

export interface Route {
  status: number;
  headers?: Record<string, string>;
  /** A string is sent as is; anything else as JSON. */
  body?: unknown;
  /** Delay before answering (timeouts). */
  delayMs?: number;
}

/** Answers each path from a route table that tests change as they go. Unknown paths answer 404. */
export class ScriptedServer {
  readonly routes = new Map<string, Route | ((req: IncomingMessage, body: Buffer) => Route)>();
  readonly hits: { method: string; path: string; headers: http.IncomingHttpHeaders; body: Buffer }[] = [];
  readonly server: http.Server;

  constructor() {
    this.server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const path = new URL(req.url ?? "/", "http://localhost").pathname;
        const body = Buffer.concat(chunks);
        this.hits.push({ method: req.method ?? "", path, headers: req.headers, body });
        const r = this.routes.get(path);
        const route: Route = typeof r === "function" ? r(req, body) : (r ?? { status: 404, body: { error: "not found" } });
        const text = typeof route.body === "string" ? route.body : JSON.stringify(route.body ?? {});
        const send = (): void => {
          if (res.destroyed) return;
          res.writeHead(route.status, { "content-type": "application/json", ...route.headers });
          res.end(text);
        };
        if (route.delayMs) setTimeout(send, route.delayMs).unref();
        else send();
      });
    });
  }

  listen(port: number): Promise<void> {
    return listenOn(this.server, port);
  }

  close(): Promise<void> {
    return closeServer(this.server);
  }

  count(path: string): number {
    return this.hits.filter((h) => h.path === path).length;
  }
}

/** POST a body (an object, or raw text) to a published inbox URL through the dev host map. */
export async function postRaw(
  fetcher: HardenedFetcher,
  inboxUrl: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<{ status: number; json: { receipt?: { id: string; status: string; code?: string }; error?: { code: string; message: string } } & Record<string, unknown> }> {
  const bytes = Buffer.from(typeof body === "string" ? body : JSON.stringify(body), "utf8");
  const res = await fetcher.request(inboxUrl, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: bytes });
  return { status: res.status, json: JSON.parse(res.body.toString("utf8") || "{}") };
}
