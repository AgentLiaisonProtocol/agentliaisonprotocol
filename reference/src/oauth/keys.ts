// SPDX-License-Identifier: FSL-1.1-ALv2
// The authorization server's own keys: an EC P-256 key (ES256) signs the JWT access tokens, an RSA key (RS256) signs
// ID tokens for clients that ask for OpenID (RS256 is the OpenID default), and two random keys sign its cookies.
// They are not the broker's envelope keys (src/core/keys.ts): those sign protocol objects; these only sign tokens.
// Kept in memory, or in <dataDir>/oauth-keys.json (mode 0600) so tokens and sessions survive a restart.

import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { calculateJwkThumbprint } from "jose";
import type { JWK } from "jose";

export interface AuthServerKeys {
  version: 1;
  /** Private JWKs (never served). */
  signing: JWK[];
  cookieKeys: string[];
}

async function withKid(jwk: JWK, alg: string): Promise<JWK> {
  const kid = await calculateJwkThumbprint(jwk, "sha256");
  return { ...jwk, kid, alg, use: "sig" };
}

export async function generateAuthServerKeys(): Promise<AuthServerKeys> {
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" }) as JWK;
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ format: "jwk" }) as JWK;
  return {
    version: 1,
    signing: [await withKid(ec, "ES256"), await withKid(rsa, "RS256")],
    cookieKeys: [randomBytes(32).toString("base64url"), randomBytes(32).toString("base64url")],
  };
}

/** Keys from JSON (a file, or ALP_OAUTH_KEYS for a hosted broker whose instances must all sign with the same keys). */
export function parseAuthServerKeys(json: string, where = "the authorization server keys"): AuthServerKeys {
  let k: AuthServerKeys;
  try {
    k = JSON.parse(json) as AuthServerKeys;
  } catch {
    throw new Error(`${where} are not JSON`);
  }
  if (k?.version !== 1 || !Array.isArray(k.signing) || k.signing.length < 2 || !Array.isArray(k.cookieKeys) || k.cookieKeys.length < 1) throw new Error(`malformed ${where}`);
  if (!k.signing.some((j) => j.alg === "ES256" && typeof j.d === "string") || !k.signing.some((j) => j.alg === "RS256" && typeof j.d === "string")) throw new Error(`${where} need an ES256 and an RS256 private key`);
  if (!k.cookieKeys.every((c) => typeof c === "string" && c.length >= 32)) throw new Error(`${where}: cookie keys must be at least 32 characters`);
  return k;
}

export async function loadAuthServerKeys(dir: string | undefined): Promise<AuthServerKeys> {
  if (!dir) return generateAuthServerKeys();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, "oauth-keys.json");
  if (existsSync(path)) return parseAuthServerKeys(readFileSync(path, "utf8"), path);
  const k = await generateAuthServerKeys();
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(k), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
  return k;
}

/** The public half of the signing keys, for verifying access tokens. */
export function publicJwks(keys: AuthServerKeys): { keys: JWK[] } {
  return {
    keys: keys.signing.map((k) => {
      const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...pub } = k;
      return pub;
    }),
  };
}
