// SPDX-License-Identifier: FSL-1.1-ALv2
// Per-source limit keys. An IPv6 client usually holds a whole /64 (one subscriber's allocation), so every per-source
// limit a stranger shouldn't be able to multiply by changing addresses counts an IPv6 address by its /64 prefix: failed
// sign-ins (the connector page and the public web view), the connector page's requests, OIDC sign-in starts, dynamic
// registrations, client metadata fetches and the public web view's requests. The federation inbox's per-address limit
// counts the connection's address as it is.

import { isIP } from "node:net";

/** An IPv6 address as its /64 prefix (`2001:db8:1:2::/64`), an IPv4-mapped one as the IPv4 address, anything else as is. */
export function sourcePrefix(source: string): string {
  const raw = source.trim().toLowerCase();
  const s = raw.replace(/^\[(.*)\]$/, "$1").replace(/%.*$/, "");
  if (isIP(s) !== 6) return raw;
  // A trailing dotted IPv4 part is the last two groups.
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s);
  const text = v4 ? `${s.slice(0, v4.index)}${(Number(v4[1]) * 256 + Number(v4[2])).toString(16)}:${(Number(v4[3]) * 256 + Number(v4[4])).toString(16)}` : s;
  const [head = "", tail] = text.split("::");
  const front = head ? head.split(":") : [];
  const back = tail ? tail.split(":") : [];
  const groups = (tail === undefined ? front : [...front, ...Array<string>(Math.max(0, 8 - front.length - back.length)).fill("0"), ...back]).map((g) => g.replace(/^0+(?=.)/, ""));
  if (v4 && groups.slice(0, 5).every((g) => g === "0") && groups[5] === "ffff") return `${v4[1]}.${v4[2]}.${v4[3]}.${v4[4]}`;
  return `${groups.slice(0, 4).join(":")}::/64`;
}
