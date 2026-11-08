// SPDX-License-Identifier: FSL-1.1-ALv2
import { timingSafeEqual } from "node:crypto";
import { parseAddress } from "./address.ts";
import type { Clock } from "./clock.ts";
import { systemClock } from "./clock.ts";
import { AlpError } from "./errors.ts";
import type { IdentityAssertion, IdentityVerifier, VerifiedIdentity } from "./interfaces.ts";
import type { Address } from "./types.ts";

export interface DevIdentity {
  username: string;
  address: string;
  display_name?: string;
  claims?: { issuer: string; name: string; value: string }[];
}

export const DEV_ISSUER = "https://dev-idp.invalid";

/**
 * The dev identity provider: fictional test identities only; it stands in for the organization's OIDC IdP.
 *
 * - `secret`: one per-session secret for every test identity, printed only to the operator's terminal. Whoever
 *   holds it can sign in as anyone listed, so it is for one person operating every test identity (the demo and the live
 *   proof), never for a broker more than one real person uses.
 * - `secrets`: a secret per identity (username → secret). Each person can then sign in only as themselves; a broker
 *   that more than one person uses with test identities (`npm start`) uses this.
 *
 * The subject is stable per test identity, as an IdP's `sub` would be.
 */
export class DevIdentityVerifier implements IdentityVerifier {
  readonly id = "dev";
  private readonly identities: Map<string, { address: Address; display_name?: string; claims?: DevIdentity["claims"] }>;
  private readonly secret: string | undefined;
  private readonly secrets: Map<string, string> | undefined;
  private readonly clock: Clock;

  constructor(identities: DevIdentity[], opts: { secret?: string; secrets?: Record<string, string>; clock?: Clock } = {}) {
    this.identities = new Map(identities.map((i) => [i.username.toLowerCase(), { address: parseAddress(i.address), ...(i.display_name ? { display_name: i.display_name } : {}), ...(i.claims ? { claims: i.claims } : {}) }]));
    this.secret = opts.secret;
    this.secrets = opts.secrets ? new Map(Object.entries(opts.secrets).map(([k, v]) => [k.toLowerCase(), v])) : undefined;
    this.clock = opts.clock ?? systemClock;
  }

  async verify(assertion: IdentityAssertion): Promise<VerifiedIdentity> {
    if (assertion.kind !== "dev") throw new AlpError("identity_mismatch", "the dev IdP only accepts dev sign-ins", { status: 401 });
    const username = assertion.username.toLowerCase();
    const who = this.identities.get(username);
    if (!who) throw new AlpError("identity_mismatch", "unknown test identity", { status: 401 });
    // With per-identity secrets, an identity without one can't sign in at all.
    const expected = this.secrets ? this.secrets.get(username) ?? null : this.secret;
    if (expected === null) throw new AlpError("identity_mismatch", "no secret is set for this identity", { status: 401 });
    if (expected !== undefined) {
      const a = Buffer.from(assertion.secret ?? "");
      const b = Buffer.from(expected);
      if (a.length !== b.length || !timingSafeEqual(a, b)) throw new AlpError("identity_mismatch", "wrong session secret", { status: 401 });
    }
    return {
      address: who.address,
      ...(who.display_name ? { display_name: who.display_name } : {}),
      method: "dev",
      iss: DEV_ISSUER,
      sub: `dev-${assertion.username.toLowerCase()}`,
      ...(who.claims ? { claims: who.claims } : {}),
      verified_at: this.clock.now().toISOString(),
    };
  }

  listTestIdentities(): { username: string; address: Address; display_name?: string }[] {
    return [...this.identities.entries()].map(([username, v]) => ({ username, address: v.address, ...(v.display_name ? { display_name: v.display_name } : {}) }));
  }
}

// OIDC sign-in through the organization's identity provider (Entra, Okta...) is src/oauth/oidc.ts
// (OidcRelyingParty, which also implements IdentityVerifier for an ID token and its nonce).
