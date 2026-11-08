// SPDX-License-Identifier: FSL-1.1-ALv2
// The hardened fetcher (spec 4.3). Every fetch that inbound data can trigger goes through it:
// domain documents, JWKS, and (for the transport) POSTs to a federation inbox named in a domain document.
//  1. HTTPS on port 443 only, certificate checked against the host name (Node's default TLS verification).
//  2. Resolve the name once; refuse loopback, private, shared, link-local, unique-local, multicast, reserved and
//     IPv4-mapped addresses; connect only to the address that was checked (a pinned lookup, so no second DNS answer).
//  3. No redirects (Node's HTTP client never follows them); getJson accepts only 200 with a JSON content type.
//  4. At most 64 KiB per response and 5 seconds per fetch, DNS included. GETs send Cache-Control: no-cache.
//  5. Failures are FetchFailure values with internal detail. Callers never echo them to a remote party.
// Development: an explicit dev host map sends named RFC 2606 origins to loopback over plain HTTP. Nothing else
// reaches loopback.

import { lookup as dnsLookup } from "node:dns/promises";
import type { LookupAddress, LookupOptions } from "node:dns";
import http from "node:http";
import https from "node:https";
import { FETCH_LIMITS } from "../core/domain.ts";
import { errMessage } from "../core/errors.ts";
import { PROTOCOL } from "../core/protocol.ts";
import { checkDevHostMap, fetchTarget, isPublicAddress } from "./net-guard.ts";
import type { DevHostMap, FetchTarget } from "./net-guard.ts";
import { parseStrictJsonBytes } from "./strict-json.ts";

/**
 * Why a fetch failed. `not_found` (404 or 410) and `no_address` (the name has no address records) are the only
 * failures after which discovery tries the second document location; everything else is `temporary` or `refused`.
 */
export type FetchFailureKind = "not_found" | "no_address" | "refused" | "temporary";

export class FetchFailure extends Error {
  readonly kind: FetchFailureKind;
  readonly status: number | undefined;

  constructor(kind: FetchFailureKind, message: string, status?: number) {
    super(message);
    this.name = "FetchFailure";
    this.kind = kind;
    this.status = status;
  }
}

export interface HttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

export interface RequestInit {
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: Uint8Array;
  maxBytes?: number;
  timeoutMs?: number;
}

export type HostResolver = (host: string) => Promise<{ address: string; family: number }[]>;

export interface FetcherOptions {
  /** Development only. A production broker MUST NOT set it. */
  devHosts?: DevHostMap;
  /** DNS override (tests). Default: the system resolver, every address. */
  resolveHost?: HostResolver;
  timeoutMs?: number;
  maxBytes?: number;
}

export const USER_AGENT = `${PROTOCOL.id}-reference-broker/${PROTOCOL.version}`;

const systemResolve: HostResolver = async (host) => {
  const all: LookupAddress[] = await dnsLookup(host, { all: true, verbatim: true });
  return all.map((a) => ({ address: a.address, family: a.family }));
};

export function isJsonContentType(value: string | undefined): boolean {
  return typeof value === "string" && /^application\/(?:[a-z0-9.+-]*\+)?json\s*(?:;.*)?$/i.test(value.trim());
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/** A lookup that always answers with the one address already checked (both the single and the `all` form). */
function pinnedLookup(address: string, family: number) {
  return (_host: string, options: LookupOptions, cb: LookupCallback): void => {
    if (options?.all) cb(null, [{ address, family }]);
    else cb(null, address, family);
  };
}

function classifyNetworkError(err: unknown): FetchFailure {
  const code = (err as { code?: unknown })?.code;
  if (code === "ENOTFOUND" || code === "ENODATA" || code === "EAI_NONAME") return new FetchFailure("no_address", "the name has no address records");
  return new FetchFailure("temporary", `network failure${typeof code === "string" ? ` (${code})` : ""}`);
}

export class HardenedFetcher {
  readonly devHosts: DevHostMap | undefined;
  private readonly resolveHost: HostResolver;
  private readonly timeoutMs: number;
  private readonly maxBytes: number;

  constructor(opts: FetcherOptions = {}) {
    this.devHosts = opts.devHosts ? checkDevHostMap(opts.devHosts) : undefined;
    this.resolveHost = opts.resolveHost ?? systemResolve;
    this.timeoutMs = opts.timeoutMs ?? FETCH_LIMITS.timeoutMs;
    this.maxBytes = opts.maxBytes ?? FETCH_LIMITS.maxBytes;
  }

  /** Where a URL would be fetched from (throws FetchFailure `refused` for URLs the rules forbid). */
  target(url: string): FetchTarget {
    try {
      return fetchTarget(url, this.devHosts);
    } catch (err) {
      throw new FetchFailure("refused", errMessage(err));
    }
  }

  /** GET a JSON document: 200 only, a JSON content type, strict I-JSON, the size and time caps. */
  async getJson(url: string): Promise<unknown> {
    const res = await this.request(url, { method: "GET", headers: { accept: "application/json", "cache-control": "no-cache" } });
    if (res.status === 404 || res.status === 410) throw new FetchFailure("not_found", `HTTP ${res.status}`, res.status);
    if (res.status !== 200) throw new FetchFailure("temporary", `HTTP ${res.status}`, res.status);
    if (!isJsonContentType(res.headers["content-type"])) throw new FetchFailure("refused", "not a JSON content type", res.status);
    try {
      return parseStrictJsonBytes(res.body);
    } catch (err) {
      throw new FetchFailure("refused", errMessage(err), res.status);
    }
  }

  /** One request under the rules above. Answers any HTTP status; throws FetchFailure only when there is no answer. */
  async request(url: string, init: RequestInit): Promise<HttpResponse> {
    const target = this.target(url);
    const deadline = Date.now() + (init.timeoutMs ?? this.timeoutMs);
    const headers: Record<string, string> = { "user-agent": USER_AGENT, ...init.headers };
    if (target.kind === "dev") {
      // The published host goes in the Host header, so one loopback server can tell origins apart.
      return this.send(http.request, target.url, { ...headers, host: target.published.host }, undefined, init, deadline);
    }
    let addrs: { address: string; family: number }[];
    try {
      addrs = await withDeadline(this.resolveHost(target.host), deadline);
    } catch (err) {
      throw err instanceof FetchFailure ? err : classifyNetworkError(err);
    }
    if (addrs.length === 0) throw new FetchFailure("no_address", "the name has no address records");
    // Every answer must be public: a name that also points inside the network is refused outright.
    if (!addrs.every((a) => isPublicAddress(a.address))) throw new FetchFailure("refused", "the name resolves to an address that is not public");
    const first = addrs[0] as { address: string; family: number };
    return this.send(https.request, target.url, headers, pinnedLookup(first.address, first.family), init, deadline);
  }

  private send(
    requestFn: typeof http.request,
    url: URL,
    headers: Record<string, string>,
    lookup: ReturnType<typeof pinnedLookup> | undefined,
    init: RequestInit,
    deadline: number,
  ): Promise<HttpResponse> {
    const maxBytes = init.maxBytes ?? this.maxBytes;
    return new Promise<HttpResponse>((resolve, reject) => {
      let done = false;
      const finish = (err: FetchFailure | null, value?: HttpResponse): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (err) reject(err);
        else resolve(value as HttpResponse);
      };
      const body = init.body;
      const allHeaders = body ? { ...headers, "content-length": String(body.byteLength) } : headers;
      // agent: false gives one connection per request (no pooled sockets that outlive the call); no redirects are followed.
      const req = requestFn(url, { method: init.method, headers: allHeaders, agent: false, ...(lookup ? { lookup } : {}) }, (res) => {
        const status = res.statusCode ?? 0;
        const declared = Number(res.headers["content-length"]);
        // Record the failure before destroying: destroy() emits its own abort events synchronously.
        if (Number.isFinite(declared) && declared > maxBytes) {
          finish(new FetchFailure("refused", "response over the size cap", status));
          res.destroy();
          req.destroy();
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxBytes) {
            finish(new FetchFailure("refused", "response over the size cap", status));
            res.destroy();
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => finish(null, { status, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on("error", () => finish(new FetchFailure("temporary", "connection failed while reading the response", status)));
        res.on("aborted", () => finish(new FetchFailure("temporary", "the response was cut off", status)));
      });
      const timer = setTimeout(() => {
        finish(new FetchFailure("temporary", "timed out"));
        req.destroy();
      }, Math.max(1, deadline - Date.now()));
      req.on("error", (err) => finish(classifyNetworkError(err)));
      req.end(body ? Buffer.from(body) : undefined);
    });
  }
}

async function withDeadline<T>(p: Promise<T>, deadline: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new FetchFailure("temporary", "timed out resolving the name")), Math.max(1, deadline - Date.now()));
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(timer);
  }
}
