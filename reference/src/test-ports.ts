// SPDX-License-Identifier: FSL-1.1-ALv2
// Loopback ports for the tests and the demos. The defaults are the ranges ARCHITECTURE.md lists ("Ports"). A second
// checkout that runs its tests at the same time moves them: ALP_TEST_PORT_BASE moves the client-binding tests' pool
// (30 ports, which the Postgres tests' PGlite bridges and the hosted brokers also draw from) and, right after it, the
// federation tests' fixed ports (16); ALP_DEMO_PORT_BASE moves `npm run demo` (11) and, 14 above it,
// `npm run demo:federation` (6).

import { createServer } from "node:net";

function portEnv(name: string, fallback: number, span: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1024 || n + span > 65535) throw new Error(`${name} must be a port number from 1024 to ${65535 - span}`);
  return n;
}

/** The client-binding tests' pool: 30 ports from here (default 47120-47149). */
export const TEST_PORT_BASE = portEnv("ALP_TEST_PORT_BASE", 47120, 46);
export const TEST_PORT_COUNT = 30;
/** The federation tests' fixed ports: 16 from here, right after the pool (default 47150-47165). */
export const FEDERATION_TEST_PORT_BASE = TEST_PORT_BASE + TEST_PORT_COUNT;
/** `npm run demo`: 11 ports from here (default 47166-47176). */
export const DEMO_PORT_BASE = portEnv("ALP_DEMO_PORT_BASE", 47166, 20);
/** `npm run demo:federation`: 6 ports from here, 14 above the demo's (default 47180-47185). */
export const FEDERATION_DEMO_PORT_BASE = DEMO_PORT_BASE + 14;
/**
 * Two ports no pool user takes, in the gap between the demo's and demo:federation's (default 47177-47178): for a test
 * that stops a broker and starts it again on the same ports, where a pooled port could go to another test process in
 * between.
 */
export const RESTART_TEST_PORTS: [number, number] = [DEMO_PORT_BASE + 11, DEMO_PORT_BASE + 12];

function portFree(port: number): Promise<boolean> {
  return new Promise((done) => {
    const s = createServer();
    s.once("error", () => done(false));
    s.listen(port, "127.0.0.1", () => s.close(() => done(true)));
  });
}

const FIRST = TEST_PORT_BASE;
const COUNT = TEST_PORT_COUNT;
let nextCandidate = FIRST + (process.pid % 10) * 3;
/**
 * Free ports from the pool (47120-47149 unless ALP_TEST_PORT_BASE moves it). Another test process may take one
 * between this check and the listen: callers try again with new ports on EADDRINUSE.
 */
export async function freePorts(n: number): Promise<number[]> {
  const out: number[] = [];
  for (let tries = 0; tries < COUNT * 2 && out.length < n; tries++) {
    const p = FIRST + ((nextCandidate++ - FIRST) % COUNT);
    if (!out.includes(p) && (await portFree(p))) out.push(p);
  }
  if (out.length < n) throw new Error(`no free test ports in ${FIRST}-${FIRST + COUNT - 1}`);
  return out;
}

/** Runs `start` on ports from the pool, again on new ones when another test process took one first (EADDRINUSE). */
export async function onFreePorts<T>(n: number, start: (ports: number[]) => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    const ports = await freePorts(n);
    try {
      return await start(ports);
    } catch (err) {
      if (attempt >= 20 || !/EADDRINUSE/.test(String(err))) throw err;
    }
  }
}
