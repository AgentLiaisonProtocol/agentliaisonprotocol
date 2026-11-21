#!/usr/bin/env node
// Builds a domain document (Section 4.2) that names one broker and pins every key in that broker's own key set, for
// running alp-check against the reference broker in CI (run-against-reference.sh). The reference broker publishes
// no domain document itself: an operator publishes the entry it prints.
//
//   node tools/check/ci/domain-document.mjs <jwks file> <broker id> <domain>
//
// The document goes to standard output. Licensed under Apache-2.0.
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { jkt } from "../../spec/lib.mjs";

/** The most thumbprints one broker entry may pin (schemas/domain-document.schema.json). */
const MAX_PINS = 4;

/**
 * A domain document for `domain` with one broker entry for `brokerId`, serving every address on the domain
 * (`"principals": "*"`), at the paths the reference broker serves, pinning the RFC 7638 thumbprint of every key in
 * `jwks`. Throws if the key set is empty or holds more keys than an entry may pin.
 */
export function buildDomainDocument({ jwks, brokerId, domain, serial = 1 }) {
  const id = new URL(brokerId);
  if (id.protocol !== "https:" || id.origin !== brokerId) throw new Error(`${brokerId} is not an https origin`);
  const keys = jwks && Array.isArray(jwks.keys) ? jwks.keys : null;
  if (!keys || keys.length === 0) throw new Error("the key set holds no keys");
  const pins = [...new Set(keys.map((k) => jkt(k)))];
  if (pins.length > MAX_PINS) throw new Error(`the key set holds ${pins.length} keys; an entry pins at most ${MAX_PINS}`);
  return {
    alp: "0.1",
    domain,
    serial,
    max_age: 3600,
    mode: "enforce",
    brokers: [
      {
        id: brokerId,
        inbox: `${brokerId}/federation/inbox`,
        jwks_uri: `${brokerId}/.well-known/jwks.json`,
        mcp: `${brokerId}/mcp`,
        rest: `${brokerId}/rest`,
        jkt: pins,
        principals: "*",
      },
    ],
    security_contact: [`mailto:security@${domain}`],
  };
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const [file, brokerId, domain] = process.argv.slice(2);
  if (!file || !brokerId || !domain) {
    process.stderr.write("usage: node tools/check/ci/domain-document.mjs <jwks file> <broker id> <domain>\n");
    process.exit(2);
  }
  const jwks = JSON.parse(fs.readFileSync(file, "utf8"));
  process.stdout.write(`${JSON.stringify(buildDomainDocument({ jwks, brokerId, domain }), null, 2)}\n`);
}
