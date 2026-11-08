// SPDX-License-Identifier: FSL-1.1-ALv2
// Test support, not a test file: a software authenticator (an ES256 passkey held in memory) that answers the web
// view's WebAuthn options the way a browser and platform authenticator would: attestation "none", a discoverable
// credential, user presence and user verification flags, a signature counter. It builds the exact bytes the WebAuthn
// specification defines (authenticator data, clientDataJSON, a CBOR attestation object, a DER ECDSA signature), so
// @simplewebauthn/server verifies them as it would a real browser's.

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";

type Json = Record<string, unknown>;
type Cbor = Parameters<typeof isoCBOR.encode>[0];

const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
const sha256 = (b: Uint8Array | string): Buffer => createHash("sha256").update(b).digest();

export class SoftAuthenticator {
  readonly credentialId = randomBytes(32);
  private readonly key: KeyObject;
  private readonly x: Buffer;
  private readonly y: Buffer;
  private counter = 0;
  /** The origin the "browser" reports in clientDataJSON. */
  origin: string;
  /** Whether the person is verified (fingerprint, face, PIN). */
  userVerified = true;

  constructor(origin: string) {
    this.origin = origin;
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.key = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.x = Buffer.from(String(jwk.x), "base64url");
    this.y = Buffer.from(String(jwk.y), "base64url");
  }

  get id(): string {
    return b64u(this.credentialId);
  }

  private flags(extra = 0): number {
    return 0x01 | (this.userVerified ? 0x04 : 0) | extra;
  }

  private authData(rpId: string, flags: number, attested?: Buffer): Buffer {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(this.counter);
    return Buffer.concat([sha256(rpId), Buffer.from([flags]), count, ...(attested ? [attested] : [])]);
  }

  private clientData(type: "webauthn.create" | "webauthn.get", challenge: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }), "utf8");
  }

  /** navigator.credentials.create() for the server's options (as JSON). */
  register(options: Json): Json {
    const rp = options["rp"] as { id: string };
    const challenge = String(options["challenge"]);
    const cose = isoCBOR.encode(new Map<number, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(this.x)], [-3, new Uint8Array(this.y)]]));
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(this.credentialId.length);
    const attested = Buffer.concat([Buffer.alloc(16), idLen, this.credentialId, Buffer.from(cose)]);
    const authData = this.authData(rp.id, this.flags(0x40), attested);
    const attestationObject = isoCBOR.encode(new Map<string, Cbor>([["fmt", "none"], ["attStmt", new Map<string, Cbor>()], ["authData", new Uint8Array(authData)]]));
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
      response: { clientDataJSON: b64u(this.clientData("webauthn.create", challenge)), attestationObject: b64u(attestationObject), transports: ["internal"] },
    };
  }

  /** navigator.credentials.get() for the server's options (as JSON). */
  assert(options: Json): Json {
    const rpId = String(options["rpId"]);
    const challenge = String(options["challenge"]);
    this.counter += 1;
    const authData = this.authData(rpId, this.flags());
    const clientDataJSON = this.clientData("webauthn.get", challenge);
    const signature = sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), this.key);
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature) },
    };
  }
}
