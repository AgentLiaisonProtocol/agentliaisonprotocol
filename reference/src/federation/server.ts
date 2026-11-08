// SPDX-License-Identifier: FSL-1.1-ALv2
// HTTP servers for federation:
//  - FederationServer: a broker's federation endpoints (spec 12.2.1): POST inbox and GET JWKS. v0.1 has no other
//    federation endpoint.
//  - DomainAuthorityServer: a domain's /.well-known/alp.json (in production, a static file on the domain's
//    own HTTPS site; the reference serves it for development, the demo and tests).
// Both speak plain HTTP on loopback in development (the dev host map points the published https origins at them).
// In production, run them behind TLS for the published host, or pass `tls` to listen on HTTPS directly.
// The handlers are plain Node (req, res) functions, so another server (the client binding's) can mount them;
// mount the inbox before any JSON body parser.

import http from "node:http";
import https from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import { checkDomainDocument } from "../core/domain.ts";
import { PROTOCOL } from "../core/protocol.ts";
import type { DomainDocument, Jwks } from "../core/types.ts";
import { checkEndpointOrigins } from "./domain-authority.ts";
import { createInboxHandler } from "./inbox.ts";
import type { InboxBroker, InboxLogEntry, InboxOptions } from "./inbox.ts";

/** One request a server saw (tests and transcripts; no bodies). */
export interface WireRecord {
  at: string;
  server: string;
  method: string;
  path: string;
  status: number;
  inbox?: InboxLogEntry;
}

export interface TlsOptions {
  key: string | Buffer;
  cert: string | Buffer;
}

function harden(server: http.Server): void {
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 2_000;
  server.maxHeadersCount = 64;
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": String(Buffer.byteLength(text)), "x-content-type-options": "nosniff", ...headers });
  res.end(text);
}

/** Listen on a fixed port; a port in use fails with a clear message instead of an unhandled error. */
export function listenOn(server: http.Server, port: number, host = "127.0.0.1"): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException): void => {
      server.off("listening", onListening);
      reject(err.code === "EADDRINUSE" ? new Error(`port ${port} on ${host} is already in use`) : err);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, host);
  });
}

/** Close a server and every connection it holds, so nothing keeps running. */
export function closeServer(server: http.Server): Promise<void> {
  return new Promise<void>((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
    server.closeAllConnections();
  });
}

/** Check that every port is free on the host (bind and release each). Throws naming the first busy port. */
export async function assertPortsFree(ports: number[], host = "127.0.0.1"): Promise<void> {
  for (const port of ports) {
    const probe = http.createServer();
    await listenOn(probe, port, host);
    await closeServer(probe);
  }
}

export interface FederationServerOptions extends Omit<InboxOptions, "broker" | "publicUrl" | "onLog"> {
  broker: InboxBroker & { jwks(): Jwks };
  /** The published URLs (as in the domain document); the server routes on their paths. */
  inboxUrl: string;
  jwksUrl: string;
  /** More public keys to publish next to the broker's federation keys (the `http` ring); all must be pinned. */
  extraKeys?: () => Jwks;
  /** Test hook (fault injection): answer before the inbox does, or return null to let it through. */
  intercept?: (req: IncomingMessage) => { status: number; headers?: Record<string, string>; body?: unknown } | null;
  tls?: TlsOptions;
}

export class FederationServer {
  readonly server: http.Server;
  /** Every request this server saw. */
  readonly requests: WireRecord[] = [];
  readonly name: string;
  private readonly opts: FederationServerOptions;
  private readonly inboxPath: string;
  private readonly jwksPath: string;
  private readonly inbox: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  private readonly records = new WeakMap<IncomingMessage, WireRecord>();

  constructor(opts: FederationServerOptions) {
    this.opts = opts;
    this.name = opts.broker.id;
    this.inboxPath = new URL(opts.inboxUrl).pathname;
    this.jwksPath = new URL(opts.jwksUrl).pathname;
    this.inbox = createInboxHandler({
      ...opts,
      publicUrl: opts.inboxUrl,
      onLog: (e: InboxLogEntry, req: IncomingMessage) => {
        const rec = this.records.get(req);
        if (rec) rec.inbox = e;
      },
    });
    const handler = (req: IncomingMessage, res: ServerResponse): void => void this.handle(req, res);
    this.server = opts.tls ? https.createServer({ key: opts.tls.key, cert: opts.tls.cert }, handler) : http.createServer(handler);
    harden(this.server);
  }

  /** The JWKS this broker publishes: its federation keys plus any extra (http) keys. */
  publishedJwks(): Jwks {
    const extra = this.opts.extraKeys?.().keys ?? [];
    return { keys: [...this.opts.broker.jwks().keys, ...extra] };
  }

  listen(port: number, host = "127.0.0.1"): Promise<void> {
    return listenOn(this.server, port, host);
  }

  close(): Promise<void> {
    return closeServer(this.server);
  }

  /**
   * The federation routes as a plain Node handler, to mount on another server (the broker's public app) instead of
   * listening on a port of their own. Mount it before any body parser.
   */
  handler(): { paths: string[]; handle: (req: IncomingMessage, res: ServerResponse) => void } {
    return { paths: [this.inboxPath, this.jwksPath], handle: (req, res) => void this.handle(req, res) };
  }

  /** Inbox POSTs seen (each with the inbox's own log line). */
  inboxRequests(): WireRecord[] {
    return this.requests.filter((r) => r.path === this.inboxPath && r.method === "POST");
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const rec: WireRecord = { at: new Date().toISOString(), server: this.name, method: req.method ?? "", path, status: 0 };
    this.records.set(req, rec);
    res.on("finish", () => {
      rec.status = res.statusCode;
      this.requests.push(rec);
    });
    const hooked = this.opts.intercept?.(req);
    if (hooked) {
      req.resume();
      sendJson(res, hooked.status, hooked.body ?? {}, hooked.headers ?? {});
      return;
    }
    if (path === this.inboxPath) {
      await this.inbox(req, res);
      return;
    }
    if (path === this.jwksPath) {
      if (req.method !== "GET" && req.method !== "HEAD") {
        sendJson(res, 405, { error: { code: "invalid_input", message: "GET only" } }, { allow: "GET, HEAD" });
        return;
      }
      sendJson(res, 200, this.publishedJwks(), { "content-type": "application/jwk-set+json", "cache-control": "max-age=300" });
      return;
    }
    req.resume();
    sendJson(res, 404, { error: { code: "invalid_input", message: "not found" } });
  }
}

/** Serves one domain's document at /.well-known/alp.json (both document locations route here in dev). */
export class DomainAuthorityServer {
  readonly server: http.Server;
  readonly domain: string;
  readonly requests: WireRecord[] = [];
  private doc: DomainDocument | null = null;
  private lastSerial: number | undefined;

  constructor(domain: string, tls?: TlsOptions) {
    this.domain = domain;
    const handler = (req: IncomingMessage, res: ServerResponse): void => this.handle(req, res);
    this.server = tls ? https.createServer({ key: tls.key, cert: tls.cert }, handler) : http.createServer(handler);
    harden(this.server);
  }

  /** Publish a document: checked like a fetched one, and its serial must be higher than the last one published. */
  publish(doc: DomainDocument): DomainDocument {
    const checked = checkDomainDocument(structuredClone(doc), this.domain, this.lastSerial);
    checkEndpointOrigins(checked);
    if (this.lastSerial !== undefined && checked.serial <= this.lastSerial) throw new Error("a new document needs a higher serial");
    this.doc = checked;
    this.lastSerial = checked.serial;
    return structuredClone(checked);
  }

  /** Stop publishing (the well-known path answers 404). */
  withdraw(): void {
    this.doc = null;
  }

  current(): DomainDocument | null {
    return this.doc ? structuredClone(this.doc) : null;
  }

  listen(port: number, host = "127.0.0.1"): Promise<void> {
    return listenOn(this.server, port, host);
  }

  close(): Promise<void> {
    return closeServer(this.server);
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const rec: WireRecord = { at: new Date().toISOString(), server: this.domain, method: req.method ?? "", path, status: 0 };
    res.on("finish", () => {
      rec.status = res.statusCode;
      this.requests.push(rec);
    });
    req.resume();
    // Answer only for this domain's two document hosts (and plain loopback, for a manual check); any other name
    // that reaches this server publishes nothing here.
    const host = (req.headers.host ?? "").replace(/:[0-9]+$/, "").toLowerCase();
    const ours = host === this.domain || host === `${PROTOCOL.hostLabel}.${this.domain}` || host === "127.0.0.1" || host === "localhost";
    if (!ours || path !== `/.well-known/${PROTOCOL.wellKnownFile}` || !this.doc) {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    if (req.method !== "GET" && req.method !== "HEAD") {
      sendJson(res, 405, { error: "GET only" }, { allow: "GET, HEAD" });
      return;
    }
    // Short shared-cache lifetime; brokers send Cache-Control: no-cache and keep their own max_age-bounded cache.
    sendJson(res, 200, this.doc, { "cache-control": "max-age=60" });
  }
}
