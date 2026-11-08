// SPDX-License-Identifier: FSL-1.1-ALv2
// `npm run hosted-keys -- <file>`: the two secrets a hosted broker reads from its environment, written to a new file
// (mode 0600) so they never pass through a terminal:
//   ALP_OAUTH_KEYS   the authorization server's signing keys (ES256 for access tokens, RS256 for ID tokens) and cookie
//                    keys, as JSON: every instance must sign and check with the same ones;
//   ALP_KEYRING_KEY  32 random bytes (base64url) that seal the broker's federation and request-signing keys in Postgres.
// Put each value in the host's secret store (on Vercel, a Sensitive environment variable), then delete the file. Neither
// belongs in the database or the repository.

import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { generateAuthServerKeys } from "./oauth/keys.ts";

async function main(): Promise<void> {
  const out = process.argv[2];
  if (!out) throw new Error("usage: npm run hosted-keys -- <new file>");
  const path = resolve(out);
  const values = { ALP_OAUTH_KEYS: JSON.stringify(await generateAuthServerKeys()), ALP_KEYRING_KEY: randomBytes(32).toString("base64url") };
  writeFileSync(path, `${JSON.stringify(values, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  console.log(`Wrote ALP_OAUTH_KEYS and ALP_KEYRING_KEY to ${path} (mode 0600). Copy them into the host's secret store, then delete the file.`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
