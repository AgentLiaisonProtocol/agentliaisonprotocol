// SPDX-License-Identifier: FSL-1.1-ALv2
// Passkeys for the person's web view on a public origin (spec 12.5.2), with @simplewebauthn/server (MIT, pinned):
// - a passkey is registered right after the first sign-in with the invite secret, and nothing else works until then;
// - every later sign-in ends with a passkey assertion;
// - every approval, ratification, grant change, disconnection and token needs a fresh assertion whose challenge
//   carries the hash of what the page showed: 16 random bytes, then SHA-256 over the JCS form of the action, its
//   target, the person and the terms read from the broker's own state (spec 12.5.2). If the terms change between the page and
//   the approval, the hash no longer matches and the approval fails.
// User verification is required everywhere (`webauthn-uv` in ratification records). Attestation is not requested
// (`none`): the passkey proves the same person comes back, not which authenticator they use.

import { createHash, randomBytes } from "node:crypto";
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from "@simplewebauthn/server";
import { canonicalize } from "../core/jcs.ts";
import type { PasskeyRecord } from "../oauth/state.ts";

/** The relying party: the web view's own origin. */
export interface RelyingParty {
  /** The host name (the RP ID). */
  id: string;
  name: string;
  /** The exact origin browsers report (https://host[:port]). */
  origin: string;
}

export const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export function relyingParty(origin: string, name: string): RelyingParty {
  const u = new URL(origin);
  return { id: u.hostname, name, origin: u.origin };
}

/** SHA-256 (base64url) of the JCS form of what an approval covers. */
export function stepUpBinding(args: { origin: string; principal_id: string; action: string; terms: unknown }): string {
  return createHash("sha256").update(canonicalize({ v: 1, origin: args.origin, principal_id: args.principal_id, action: args.action, terms: args.terms ?? null })).digest("base64url");
}

/** A fresh challenge: 16 random bytes, then the binding's 32 bytes when there is one (else 32 random bytes). */
export function newChallenge(binding?: string): string {
  const tail = binding ? Buffer.from(binding, "base64url") : randomBytes(32);
  if (tail.length !== 32) throw new Error("a binding is a SHA-256");
  return Buffer.concat([randomBytes(16), tail]).toString("base64url");
}

/** The challenge a browser's response answers (from its clientDataJSON), or null. */
export function challengeOf(response: unknown): string | null {
  const cdj = (response as { response?: { clientDataJSON?: unknown } } | null)?.response?.clientDataJSON;
  if (typeof cdj !== "string" || cdj.length > 4096) return null;
  try {
    const c = (JSON.parse(Buffer.from(cdj, "base64url").toString("utf8")) as { challenge?: unknown }).challenge;
    return typeof c === "string" && /^[A-Za-z0-9_-]{20,128}$/.test(c) ? c : null;
  } catch {
    return null;
  }
}

/** Parse the hidden form field the page's script fills with the browser's answer. */
export function parseCredential(raw: unknown): Record<string, unknown> | null {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 16_384) return null;
  try {
    const v = JSON.parse(raw) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export async function registrationOptions(rp: RelyingParty, who: { principal_id: string; name: string; display: string }, existing: PasskeyRecord[], challenge: string): Promise<PublicKeyCredentialCreationOptionsJSON> {
  return generateRegistrationOptions({
    rpName: rp.name,
    rpID: rp.id,
    userName: who.name,
    userDisplayName: who.display,
    userID: new Uint8Array(createHash("sha256").update(`alp-user:${who.principal_id}`).digest()),
    challenge: new Uint8Array(Buffer.from(challenge, "base64url")),
    timeout: CHALLENGE_TTL_MS,
    attestationType: "none",
    excludeCredentials: existing.map((p) => ({ id: p.credential_id, ...(p.transports ? { transports: p.transports } : {}) })),
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    supportedAlgorithmIDs: [-7, -257],
  });
}

export async function authenticationOptions(rp: RelyingParty, passkeys: PasskeyRecord[], challenge: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
  return generateAuthenticationOptions({
    rpID: rp.id,
    allowCredentials: passkeys.map((p) => ({ id: p.credential_id, ...(p.transports ? { transports: p.transports } : {}) })),
    challenge: new Uint8Array(Buffer.from(challenge, "base64url")),
    timeout: CHALLENGE_TTL_MS,
    userVerification: "required",
  });
}

/** Verify a registration answer for `challenge`; the new passkey's record, or null. */
export async function verifyRegistration(rp: RelyingParty, response: Record<string, unknown>, challenge: string, principalId: string, at: string): Promise<PasskeyRecord | null> {
  try {
    const v = await verifyRegistrationResponse({
      response: response as unknown as RegistrationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.id,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7, -257],
    });
    if (!v.verified || !v.registrationInfo.userVerified) return null;
    const c = v.registrationInfo.credential;
    return {
      credential_id: c.id,
      principal_id: principalId,
      public_key: Buffer.from(c.publicKey).toString("base64url"),
      counter: c.counter,
      ...(c.transports?.length ? { transports: c.transports.filter((t) => typeof t === "string").slice(0, 8) } : {}),
      device_type: v.registrationInfo.credentialDeviceType,
      backed_up: v.registrationInfo.credentialBackedUp,
      created_at: at,
    };
  } catch {
    return null;
  }
}

/** Verify an assertion for `challenge` with a stored passkey; the new signature counter, or null. */
export async function verifyAssertion(rp: RelyingParty, response: Record<string, unknown>, challenge: string, passkey: PasskeyRecord): Promise<{ counter: number } | null> {
  if (response["id"] !== passkey.credential_id) return null;
  try {
    const v = await verifyAuthenticationResponse({
      response: response as unknown as AuthenticationResponseJSON,
      expectedChallenge: challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.id,
      credential: { id: passkey.credential_id, publicKey: new Uint8Array(Buffer.from(passkey.public_key, "base64url")), counter: passkey.counter, ...(passkey.transports ? { transports: passkey.transports } : {}) },
      requireUserVerification: true,
    });
    if (!v.verified || !v.authenticationInfo.userVerified) return null;
    return { counter: v.authenticationInfo.newCounter };
  } catch {
    return null;
  }
}

/** The script the pages load (same origin, under the CSP): runs the browser's WebAuthn call and submits the form. */
export const PASSKEY_JS = `// The web view's passkey helper: no inline script, no third-party code.
(() => {
  "use strict";
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
  const say = (form, text) => {
    const el = form.querySelector("[data-alp-status]");
    if (el) el.textContent = text;
  };
  async function run(form) {
    if (!window.PublicKeyCredential || !navigator.credentials) throw new Error("This browser can't use passkeys.");
    const body = new URLSearchParams(new FormData(form));
    body.set("alp_webauthn", "options");
    body.delete("credential");
    const r = await fetch(form.action, { method: "POST", body, credentials: "same-origin", headers: { accept: "application/json" } });
    const o = await r.json().catch(() => ({}));
    if (!r.ok || !o.publicKey) throw new Error(o.error || "The broker didn't start the passkey check.");
    const pk = o.publicKey;
    pk.challenge = dec(pk.challenge);
    let answer;
    if (o.kind === "create") {
      pk.user = { ...pk.user, id: dec(pk.user.id) };
      pk.excludeCredentials = (pk.excludeCredentials || []).map((c) => ({ ...c, id: dec(c.id) }));
      const c = await navigator.credentials.create({ publicKey: pk });
      answer = { id: c.id, rawId: enc(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment || undefined, clientExtensionResults: c.getClientExtensionResults(),
        response: { clientDataJSON: enc(c.response.clientDataJSON), attestationObject: enc(c.response.attestationObject), transports: c.response.getTransports ? c.response.getTransports() : [] } };
    } else {
      pk.allowCredentials = (pk.allowCredentials || []).map((c) => ({ ...c, id: dec(c.id) }));
      const c = await navigator.credentials.get({ publicKey: pk });
      answer = { id: c.id, rawId: enc(c.rawId), type: c.type, authenticatorAttachment: c.authenticatorAttachment || undefined, clientExtensionResults: c.getClientExtensionResults(),
        response: { clientDataJSON: enc(c.response.clientDataJSON), authenticatorData: enc(c.response.authenticatorData), signature: enc(c.response.signature), userHandle: c.response.userHandle ? enc(c.response.userHandle) : undefined } };
    }
    form.querySelector("input[name=credential]").value = JSON.stringify(answer);
    form.submit();
  }
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-alp-passkey")) return;
    e.preventDefault();
    say(form, "Waiting for your passkey...");
    run(form).catch((err) => say(form, (err && err.message) || "The passkey check didn't finish."));
  });
})();
`;
