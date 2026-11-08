// SPDX-License-Identifier: FSL-1.1-ALv2
// Test support, not a test file: PGlite (Postgres compiled to WebAssembly, run in this process; a dev dependency)
// behind a Postgres wire-protocol socket on loopback, so the `postgres` client the Postgres stores use runs against
// it unchanged. No Postgres server is installed or started.
//
// PGlite is one backend session, so the bridge shares it between client connections the way a pooler in transaction
// mode would:
//  - one connection at a time owns the session, for a whole batch (up to Sync or a simple Query) and, when the batch
//    leaves a transaction open, until that transaction ends; others wait their turn;
//  - the first connection's startup goes to PGlite, and later connections get a copy of its startup reply;
//  - a connection's own `search_path` (a startup parameter, as the stores set it) is applied whenever it takes the
//    session from another connection;
//  - a connection that closes inside a transaction has it rolled back.
// Named prepared statements would be shared between connections; the stores use unnamed ones (`prepare: false`).
// Framing follows the protocol (startup, SSLRequest, CancelRequest, then type + length); the approach is the one
// @electric-sql/pglite-socket takes, written here without that package's extension peers.

import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { PGlite } from "@electric-sql/pglite";
import { onFreePorts } from "../test-ports.ts";

const PROTOCOL_3 = 196608;
const SSL_REQUEST = 80877103;
const GSSENC_REQUEST = 80877104;
const CANCEL_REQUEST = 80877102;

export interface PgliteBridge {
  /** postgres://... for the `postgres` client (the user and password are ignored). */
  url: string;
  db: PGlite;
  close(): Promise<void>;
}

interface Conn {
  socket: Socket;
  buffer: Buffer;
  started: boolean;
  searchPath: string | undefined;
  /** Messages run one after another, in order. */
  chain: Promise<void>;
  closed: boolean;
}

function startupParams(msg: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  const parts = msg.subarray(8, msg.length - 1).toString("utf8").split("\0");
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const k = parts[i];
    const v = parts[i + 1];
    if (k) out[k] = v ?? "";
  }
  return out;
}

/** The status byte of the last ReadyForQuery in a backend reply ('I' idle, 'T' in a transaction, 'E' failed one). */
function lastStatus(reply: Uint8Array): string | undefined {
  let status: string | undefined;
  let i = 0;
  const view = Buffer.from(reply.buffer, reply.byteOffset, reply.byteLength);
  while (i + 5 <= view.length) {
    const type = view[i];
    const len = view.readInt32BE(i + 1);
    if (len < 4) break;
    if (type === 0x5a && len === 5 && i + 5 < view.length) status = String.fromCharCode(view[i + 5] ?? 0);
    i += 1 + len;
  }
  return status;
}

function simpleQuery(sql: string): Uint8Array {
  const body = Buffer.from(`${sql}\0`, "utf8");
  const msg = Buffer.alloc(5 + body.length);
  msg[0] = 0x51;
  msg.writeInt32BE(4 + body.length, 1);
  body.copy(msg, 5);
  return msg;
}

/**
 * Starts a bridge on `port`, or (without one) on a free port from the tests' pool (src/test-ports.ts), trying new
 * ports when another test process takes one first.
 */
export async function startPgliteBridge(opts: { port?: number; host?: string; db?: PGlite } = {}): Promise<PgliteBridge> {
  if (opts.port !== undefined) return startOnPort({ ...opts, port: opts.port });
  const db = opts.db ?? new PGlite();
  try {
    const b = await onFreePorts(1, ([port]) => startOnPort({ ...opts, db, port: port ?? 0 }));
    return opts.db ? b : { ...b, close: async () => {
      await b.close();
      await db.close();
    } };
  } catch (err) {
    if (!opts.db) await db.close();
    throw err;
  }
}

async function startOnPort(opts: { port: number; host?: string; db?: PGlite }): Promise<PgliteBridge> {
  const host = opts.host ?? "127.0.0.1";
  const db = opts.db ?? new PGlite();
  await db.waitReady;

  let owner: Conn | null = null;
  let lastSession: Conn | null = null;
  let status = "I";
  let startupReply: Buffer | null = null;
  const waiting: (() => void)[] = [];
  const conns = new Set<Conn>();

  const run = async (msg: Uint8Array): Promise<Uint8Array> => db.runExclusive(() => db.execProtocolRaw(msg));

  const acquire = async (c: Conn): Promise<void> => {
    while (owner !== null && owner !== c) await new Promise<void>((resolve) => waiting.push(resolve));
    owner = c;
    if (lastSession !== c && c.searchPath !== undefined) {
      await run(simpleQuery(`select set_config('search_path', '${c.searchPath.replace(/'/g, "''")}', false)`));
    }
    lastSession = c;
  };
  const release = (c: Conn): void => {
    if (owner !== c) return;
    owner = null;
    waiting.shift()?.();
  };

  const handle = async (c: Conn, msg: Buffer, kind: "startup" | "message"): Promise<void> => {
    if (c.closed) return;
    if (kind === "startup") {
      const params = startupParams(msg);
      c.searchPath = params["search_path"];
      await acquire(c);
      try {
        if (!startupReply) {
          startupReply = Buffer.from(await run(msg));
          status = lastStatus(startupReply) ?? "I";
        }
        if (c.searchPath !== undefined) await run(simpleQuery(`select set_config('search_path', '${c.searchPath.replace(/'/g, "''")}', false)`));
        lastSession = c;
        if (!c.closed) c.socket.write(startupReply);
      } finally {
        release(c);
      }
      return;
    }
    const type = msg[0];
    if (type === 0x58) {
      // Terminate: never passed on (it would end the shared session).
      c.socket.end();
      return;
    }
    await acquire(c);
    const reply = await run(msg);
    status = lastStatus(reply) ?? status;
    if (!c.closed && reply.length) c.socket.write(Buffer.from(reply));
    if ((type === 0x53 || type === 0x51) && status === "I") release(c);
  };

  // A failure ends the connection; onClose then gives the session back (rolling back an open transaction).
  const enqueue = (c: Conn, msg: Buffer, kind: "startup" | "message"): void => {
    c.chain = c.chain.then(() => handle(c, msg, kind)).catch(() => {
      c.socket.destroy();
    });
  };

  const onData = (c: Conn, data: Buffer): void => {
    c.buffer = Buffer.concat([c.buffer, data]);
    for (;;) {
      const b = c.buffer;
      if (!c.started) {
        if (b.length < 8) return;
        const len = b.readInt32BE(0);
        const code = b.readInt32BE(4);
        if (len === 8 && (code === SSL_REQUEST || code === GSSENC_REQUEST)) {
          c.buffer = b.subarray(8);
          c.socket.write("N");
          continue;
        }
        if (len === 16 && code === CANCEL_REQUEST) {
          c.socket.end();
          return;
        }
        if (code !== PROTOCOL_3 || len < 8 || len > 10_000) {
          c.socket.destroy();
          return;
        }
        if (b.length < len) return;
        const msg = Buffer.from(b.subarray(0, len));
        c.buffer = b.subarray(len);
        c.started = true;
        enqueue(c, msg, "startup");
        continue;
      }
      if (b.length < 5) return;
      const len = b.readInt32BE(1);
      if (len < 4) {
        c.socket.destroy();
        return;
      }
      if (b.length < 1 + len) return;
      const msg = Buffer.from(b.subarray(0, 1 + len));
      c.buffer = b.subarray(1 + len);
      enqueue(c, msg, "message");
    }
  };

  const onClose = (c: Conn): void => {
    c.closed = true;
    conns.delete(c);
    c.chain = c.chain
      .then(async () => {
        if (owner === c) {
          if (status !== "I") {
            const reply = await run(simpleQuery("rollback"));
            status = lastStatus(reply) ?? "I";
          }
          release(c);
        }
      })
      .catch(() => {
        if (owner === c) release(c);
      });
  };

  const server: Server = createServer((socket) => {
    const c: Conn = { socket, buffer: Buffer.alloc(0), started: false, searchPath: undefined, chain: Promise.resolve(), closed: false };
    conns.add(c);
    socket.setNoDelay(true);
    socket.on("data", (d: Buffer) => onData(c, d));
    socket.on("error", () => socket.destroy());
    socket.on("close", () => onClose(c));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, host, () => resolve());
  });

  return {
    url: `postgres://postgres:not-a-secret@${host}:${opts.port}/postgres`,
    db,
    close: async () => {
      for (const c of conns) c.socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await Promise.all([...conns].map((c) => c.chain.catch(() => undefined)));
      if (!opts.db) await db.close();
    },
  };
}
