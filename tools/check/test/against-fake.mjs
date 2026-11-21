// Runs the checker's command, unchanged, against the in-memory fake broker instead of the network:
//   node tools/check/test/against-fake.mjs [--fault <name>]... [checker arguments, default: example.org]
// For trying the report out; it opens no socket. Licensed under Apache-2.0.
import "./guard.mjs";
import { main } from "../check.mjs";
import { createFakeBroker, FAULTS, VARIANTS } from "./fake-broker.mjs";

const argv = process.argv.slice(2);
const faults = [];
const rest = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--fault") faults.push(argv[++i]);
  else rest.push(argv[i]);
}
if (faults.some((f) => !(f in FAULTS) && !(f in VARIANTS))) {
  process.stderr.write(`faults: ${Object.keys(FAULTS).join(", ")}\nvariants: ${Object.keys(VARIANTS).join(", ")}\n`);
  process.exit(2);
}
// The fake's domain is example.org: add it when neither a domain nor --broker was given.
const TAKES_VALUE = new Set(["--only", "--timeout", "--dev-map", "--broker", "--mcp", "--rest", "--inbox", "--jwks"]);
let positional = 0;
for (let i = 0; i < rest.length; i++) {
  if (TAKES_VALUE.has(rest[i])) i++;
  else if (!rest[i].startsWith("-")) positional++;
}
if (!positional && !rest.includes("--broker")) rest.push("example.org");
const fake = createFakeBroker({ faults });
process.exitCode = await main(rest, { fetch: fake.fetch, resolveTxt: fake.resolveTxt });
