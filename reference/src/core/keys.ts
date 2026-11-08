// SPDX-License-Identifier: FSL-1.1-ALv2
import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { calculateJwkThumbprint } from "jose";
import { AlpError } from "./errors.ts";
import type { Jwk, Jwks } from "./types.ts";

export type KeyUse = "federation" | "http" | "ledger" | "push";

/** Fully specified JWS algorithm for Ed25519 (RFC 9864). Verifiers also accept the older `EdDSA`. */
export const JWS_ALG = "Ed25519";

/** `next` is published (and pinned in the domain document) before it becomes active. */
export type KeyStatus = "next" | "active" | "retiring" | "retired";

export interface StoredKey {
  kid: string;
  public_jwk: Jwk;
  /** Private material. Never log it, never publish it. */
  private_jwk: Jwk;
  created_at: string;
  status: KeyStatus;
  /** When a retiring key stops being published. */
  retire_at?: string;
}

export interface StoredKeyRing {
  version: 1;
  keys: StoredKey[];
}

async function newKey(now: Date, use: KeyUse, status: KeyStatus = "active"): Promise<StoredKey> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "jwk" }) as Jwk;
  const priv = privateKey.export({ format: "jwk" }) as Jwk;
  const kid = await calculateJwkThumbprint({ kty: "OKP", crv: "Ed25519", x: String(pub.x) }, "sha256");
  return {
    kid,
    public_jwk: { kty: "OKP", crv: "Ed25519", x: String(pub.x), kid, alg: JWS_ALG, use: "sig", alp_use: use },
    private_jwk: { kty: "OKP", crv: "Ed25519", x: String(priv.x), d: String(priv.d), kid },
    created_at: now.toISOString(),
    status,
  };
}

function checkStoredKey(k: StoredKey): void {
  const ok =
    typeof k.kid === "string" &&
    k.public_jwk?.kty === "OKP" &&
    k.public_jwk.crv === "Ed25519" &&
    typeof k.public_jwk.x === "string" &&
    k.private_jwk?.kty === "OKP" &&
    typeof k.private_jwk.d === "string" &&
    k.private_jwk.x === k.public_jwk.x &&
    ["next", "active", "retiring", "retired"].includes(k.status);
  if (!ok) throw new AlpError("invalid_input", "stored key is malformed");
}

/**
 * A broker's Ed25519 signing keys for one purpose (`alp_use`). The kid is the RFC 7638 thumbprint, which is
 * also the `jkt` a domain document pins. One active key signs. A `next` key is published (so the domain can pin it)
 * before rotation; retiring keys stay published until `retire_at`; retired keys are kept to check old artifacts.
 */
export class KeyRing {
  private keys: StoredKey[];
  private readonly privCache = new Map<string, KeyObject>();
  readonly use: KeyUse;

  private constructor(keys: StoredKey[], use: KeyUse) {
    this.keys = keys;
    this.use = use;
  }

  static async generate(now: Date = new Date(), use: KeyUse = "federation"): Promise<KeyRing> {
    return new KeyRing([await newKey(now, use)], use);
  }

  static fromJSON(data: StoredKeyRing): KeyRing {
    if (data?.version !== 1 || !Array.isArray(data.keys)) throw new AlpError("invalid_input", "not a stored key ring");
    data.keys.forEach(checkStoredKey);
    if (data.keys.filter((k) => k.status === "active").length !== 1) {
      throw new AlpError("invalid_input", "a key ring needs exactly one active key");
    }
    const use = (data.keys[0]?.public_jwk.alp_use ?? "federation") as KeyUse;
    return new KeyRing(structuredClone(data.keys), use);
  }

  /** Includes private keys: persist it only to protected storage. */
  toJSON(): StoredKeyRing {
    return { version: 1, keys: structuredClone(this.keys) };
  }

  active(): StoredKey {
    const k = this.keys.find((x) => x.status === "active");
    if (!k) throw new AlpError("internal", "key ring has no active key");
    return k;
  }

  get kid(): string {
    return this.active().kid;
  }

  privateKey(kid: string): KeyObject {
    const cached = this.privCache.get(kid);
    if (cached) return cached;
    const k = this.keys.find((x) => x.kid === kid);
    if (!k) throw new AlpError("internal", "unknown key id");
    const key = createPrivateKey({ key: k.private_jwk as unknown as import("node:crypto").JsonWebKey, format: "jwk" });
    this.privCache.set(kid, key);
    return key;
  }

  publicKey(kid: string): KeyObject {
    const k = this.keys.find((x) => x.kid === kid);
    if (!k) throw new AlpError("internal", "unknown key id");
    return createPublicKey({ key: k.public_jwk as unknown as import("node:crypto").JsonWebKey, format: "jwk" });
  }

  /** Create and publish the next key now, so the domain document can pin it before rotation. */
  async prepareNext(now: Date): Promise<StoredKey> {
    const existing = this.keys.find((k) => k.status === "next");
    if (existing) return existing;
    const next = await newKey(now, this.use, "next");
    this.keys.push(next);
    return next;
  }

  /** Make the next key (created now if none) active; the previous one keeps verifying until `now + retireAfterSeconds`. */
  async rotate(now: Date, retireAfterSeconds: number): Promise<StoredKey> {
    const next = this.keys.find((k) => k.status === "next") ?? (await this.prepareNext(now));
    for (const k of this.keys) {
      if (k.status === "active") {
        k.status = "retiring";
        k.retire_at = new Date(now.getTime() + retireAfterSeconds * 1000).toISOString();
      }
    }
    next.status = "active";
    return next;
  }

  /** Thumbprints to pin in the domain document: next, active and retiring keys. */
  jkts(): string[] {
    return this.keys.filter((k) => k.status !== "retired").map((k) => k.kid);
  }

  /** Retire keys whose retire_at has passed. They leave the published JWKS. */
  prune(now: Date): void {
    for (const k of this.keys) {
      if (k.status === "retiring" && k.retire_at && Date.parse(k.retire_at) <= now.getTime()) k.status = "retired";
    }
  }

  /** The public JWKS document to publish: next, active and retiring keys. */
  jwks(): Jwks {
    return { keys: this.keys.filter((k) => k.status !== "retired").map((k) => ({ ...k.public_jwk })) };
  }

  /** Every public key ever used, for checking old artifacts. */
  historicJwks(): Jwks {
    return { keys: this.keys.map((k) => ({ ...k.public_jwk })) };
  }
}
