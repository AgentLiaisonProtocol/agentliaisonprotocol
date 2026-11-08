// SPDX-License-Identifier: FSL-1.1-ALv2
// What the hardened fetcher may connect to (spec 4.3). Every URL it fetches was chosen by
// whoever sent the data, so: HTTPS on port 443 only, a DNS name (never an IP literal), and only public addresses.
// The one exception is the explicit, opt-in development host map, which sends named RFC 2606 origins to loopback.
// A production broker MUST NOT configure it.

import { BlockList, isIP } from "node:net";
import { isDomain } from "../core/address.ts";

/**
 * Address ranges the fetcher refuses: loopback, private, shared, link-local, unique-local, multicast, reserved,
 * IPv4-mapped. Two lists, because Node's BlockList also matches IPv4 queries against IPv4-mapped IPv6 rules, so
 * one list holding ::ffff:0:0/96 would refuse every IPv4 address.
 */
const BLOCKED_V4 = new BlockList();
const BLOCKED_V6 = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // shared address space (CGN)
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // documentation (TEST-NET-1)
  ["192.88.99.0", 24], // 6to4 relay anycast (deprecated)
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // documentation (TEST-NET-2)
  ["203.0.113.0", 24], // documentation (TEST-NET-3)
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, and the broadcast address
] as const) {
  BLOCKED_V4.addSubnet(net, bits, "ipv4");
}
for (const [net, bits] of [
  ["::", 96], // unspecified, loopback and the deprecated IPv4-compatible block
  ["::ffff:0:0", 96], // IPv4-mapped
  ["64:ff9b::", 96], // NAT64 (embeds an IPv4 address)
  ["64:ff9b:1::", 48], // local-use NAT64
  ["100::", 64], // discard-only
  ["2001::", 23], // IETF protocol assignments (Teredo, ORCHID and others)
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4 (embeds an IPv4 address)
  ["fc00::", 7], // unique-local
  ["fe80::", 10], // link-local
  ["fec0::", 10], // site-local (deprecated)
  ["ff00::", 8], // multicast
] as const) {
  BLOCKED_V6.addSubnet(net, bits, "ipv6");
}

/** True when the fetcher may connect to this IP address. */
export function isPublicAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return !BLOCKED_V4.check(ip, "ipv4");
  if (family === 6) return !BLOCKED_V6.check(ip, "ipv6");
  return false;
}

/**
 * The development host map: an HTTPS origin (as published, e.g. `https://broker-a.example`) to the loopback
 * base URL that serves it in development (e.g. `http://127.0.0.1:47182`). Opt-in and explicit; never in production.
 */
export type DevHostMap = Readonly<Record<string, string>>;

const LOOPBACK_DEV_BASE = /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):[0-9]{2,5}$/;

/** Validate a dev host map: keys are https origins of RFC 2606 names; values are loopback http base URLs. */
export function checkDevHostMap(map: DevHostMap): DevHostMap {
  const out: Record<string, string> = {};
  for (const [origin, base] of Object.entries(map)) {
    let u: URL;
    try {
      u = new URL(origin);
    } catch {
      throw new Error(`dev host map: ${origin} is not a URL`);
    }
    if (u.protocol !== "https:" || u.origin !== origin) throw new Error(`dev host map: ${origin} must be an https origin`);
    if (!isReservedExampleName(u.hostname)) throw new Error(`dev host map: ${u.hostname} is not an RFC 2606 name`);
    if (!LOOPBACK_DEV_BASE.test(base)) throw new Error(`dev host map: ${base} must be http://127.0.0.1:<port>`);
    out[origin] = base;
  }
  return Object.freeze(out);
}

/** RFC 2606 / RFC 6761 names: `example`, `test`, `invalid` and `localhost` TLDs, and example.com/net/org. */
export function isReservedExampleName(host: string): boolean {
  return /(^|\.)(example|test|invalid|localhost)$/.test(host) || /(^|\.)example\.(com|net|org)$/.test(host);
}

export type FetchTarget =
  | { kind: "public"; url: URL; host: string }
  /** Development only: the URL rewritten onto loopback through the dev host map. */
  | { kind: "dev"; url: URL; published: URL };

/**
 * Decide where a URL may be fetched from, or throw. `https:` only, port 443, no user info, a DNS name (no IP
 * literal). A URL whose origin is in the dev host map goes to the mapped loopback base instead.
 */
export function fetchTarget(raw: string, devHosts?: DevHostMap): FetchTarget {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("not a URL");
  }
  if (url.protocol !== "https:") throw new Error("only https URLs are fetched");
  if (url.username || url.password) throw new Error("URLs with user info are refused");
  if (url.port !== "" && url.port !== "443") throw new Error("only port 443 is fetched");
  const mapped = devHosts?.[url.origin];
  if (mapped) {
    const dev = new URL(`${url.pathname}${url.search}`, mapped);
    return { kind: "dev", url: dev, published: url };
  }
  const host = url.hostname;
  if (isIP(host.replace(/^\[|\]$/g, "")) !== 0) throw new Error("IP literal hosts are refused");
  if (!isDomain(host)) throw new Error("not a valid host name");
  if (host === "localhost" || host.endsWith(".localhost")) throw new Error("localhost is reachable only through the dev host map");
  return { kind: "public", url, host };
}
