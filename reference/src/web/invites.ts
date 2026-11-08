// SPDX-License-Identifier: FSL-1.1-ALv2
// Invite-only sign-in for a hosted broker (Postgres and the web view on the public origin; sign-in through
// the organization's identity provider isn't built for the public web view). The operator invites one person at a time
// (`npm run invite`): an invite names the person's sign-in name and address, carries a sign-in secret for them alone
// (192 random bits, shown once to the operator, stored only as a scrypt hash), expires, and can be revoked. A person
// can sign in only while one of their invites is live; revoking it also ends their open web sessions, and a sign-in
// that was checking the secret while the revocation landed is refused (the use is recorded only on a live invite). On
// the web view the secret only starts the first sign-in: a passkey is registered next and is needed for every later
// one (src/web/passkeys.ts).
//
// scrypt runs off the event loop (crypto.scrypt), so sign-in attempts can't stall the broker's other requests; the
// sign-in pages cap the attempts per source before any secret is checked.
//
// Principals bind to the broker's own invite issuer (`<broker origin>/invites`) and `invite:<name>`, never to the
// address: giving an address to someone else means a new name, and so a new principal (spec 5.2).

import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import type { ScryptOptions } from "node:crypto";
import { ulid } from "ulid";
import { parseAddress } from "../core/address.ts";
import type { Clock } from "../core/clock.ts";
import { systemClock } from "../core/clock.ts";
import { AlpError } from "../core/errors.ts";
import type { IdentityAssertion, IdentityVerifier, VerifiedIdentity } from "../core/interfaces.ts";
import type { BindingStore, InviteRecord } from "../oauth/state.ts";

const N = 16384;
const R = 8;
const P = 1;
const USERNAME = /^[a-z0-9][a-z0-9._-]{0,31}$/;
/** A secret's hash to compare against when the name is unknown, so both cases take the same time. */
const DUMMY = `scrypt$${N}$${R}$${P}$${Buffer.alloc(16).toString("base64url")}$${Buffer.alloc(32).toString("base64url")}`;

/** crypto.scrypt as a promise: it runs on libuv's thread pool, not on the event loop. */
function scryptAsync(secret: string, salt: Buffer, length: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((done, fail) => scrypt(secret, salt, length, options, (err, key) => (err ? fail(err) : done(key))));
}

export async function hashSecret(secret: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await scryptAsync(secret, salt, 32, { N, r: R, p: P, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${N}$${R}$${P}$${salt.toString("base64url")}$${hash.toString("base64url")}`;
}

export async function verifySecret(secret: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [n, r, p] = [Number(parts[1]), Number(parts[2]), Number(parts[3])];
  if (![n, r, p].every((x) => Number.isInteger(x) && x > 0) || n > 1 << 20 || r > 32 || p > 16) return false;
  const want = Buffer.from(parts[5] ?? "", "base64url");
  const got = await scryptAsync(secret, Buffer.from(parts[4] ?? "", "base64url"), want.length || 32, { N: n, r, p, maxmem: 256 * 1024 * 1024 });
  return want.length === got.length && timingSafeEqual(want, got);
}

export function inviteIssuer(brokerOrigin: string): string {
  return `${new URL(brokerOrigin).origin}/invites`;
}

export function isLive(i: InviteRecord, now: Date): boolean {
  return i.revoked_at === undefined && Date.parse(i.expires_at) > now.getTime();
}

export function checkUsername(username: string): string {
  const u = username.trim().toLowerCase();
  if (!USERNAME.test(u)) throw new Error("a sign-in name is 1 to 32 lower-case letters, digits, '.', '_' or '-', starting with a letter or digit");
  return u;
}

function checkEmail(email: string): string {
  const e = email.trim();
  if (e.length > 254 || !/^[^\s@<>()",;:]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(e)) throw new Error("not an email address");
  return e;
}

/** Create an invite; the secret is returned once and never stored. */
export async function createInvite(store: BindingStore, args: { username: string; address: string; display_name?: string; email?: string; days: number; now: Date }): Promise<{ invite: InviteRecord; secret: string }> {
  const username = checkUsername(args.username);
  const address = parseAddress(args.address);
  if (!Number.isFinite(args.days) || args.days < 1 || args.days > 90) throw new Error("an invite lasts 1 to 90 days");
  for (const other of await store.listInvites()) {
    if (other.address === address && other.username !== username && isLive(other, args.now)) throw new Error(`${address} has a live invite under another name; revoke it first`);
  }
  const secret = randomBytes(24).toString("base64url");
  const invite: InviteRecord = {
    id: ulid(args.now.getTime()),
    username,
    address,
    ...(args.display_name ? { display_name: args.display_name.slice(0, 80) } : {}),
    ...(args.email ? { email: checkEmail(args.email) } : {}),
    secret_hash: await hashSecret(secret),
    created_at: args.now.toISOString(),
    expires_at: new Date(args.now.getTime() + Math.floor(args.days) * 86400_000).toISOString(),
  };
  await store.putInvite(invite);
  return { invite, secret };
}

/**
 * Revoke an invite and end the person's web sessions (their connected agents keep their grants until revoked on the
 * page or by policy). Only `revoked_at` is written, so nothing read before it can put the invite back.
 */
export async function revokeInvite(store: BindingStore, id: string, now: Date, principalIdOf?: (address: string) => Promise<string | null>): Promise<InviteRecord | null> {
  const i = await store.revokeInvite(id, now.toISOString());
  if (!i) return null;
  const pid = principalIdOf ? await principalIdOf(i.address) : null;
  if (pid) await store.deleteWebSessionsOf(pid);
  return i;
}

/** Signs people in by their invite: a live invite under that name, and its secret. */
export class InviteIdentityVerifier implements IdentityVerifier {
  readonly id = "invites";
  readonly issuer: string;
  private readonly store: BindingStore;
  private readonly clock: Clock;

  constructor(store: BindingStore, brokerOrigin: string, clock: Clock = systemClock) {
    this.store = store;
    this.issuer = inviteIssuer(brokerOrigin);
    this.clock = clock;
  }

  async verify(assertion: IdentityAssertion): Promise<VerifiedIdentity> {
    if (assertion.kind !== "dev") throw new AlpError("identity_mismatch", "sign in with your invitation", { status: 401 });
    const now = this.clock.now();
    let username: string;
    try {
      username = checkUsername(assertion.username);
    } catch {
      await verifySecret(assertion.secret ?? "", DUMMY);
      throw new AlpError("identity_mismatch", "sign-in failed", { status: 401 });
    }
    const live = (await this.store.listInvites(username)).filter((i) => isLive(i, now));
    const secret = assertion.secret ?? "";
    let match: InviteRecord | undefined;
    for (const i of live) if (await verifySecret(secret, i.secret_hash)) match = i;
    if (live.length === 0) await verifySecret(secret, DUMMY);
    if (!match) throw new AlpError("identity_mismatch", "sign-in failed", { status: 401 });
    // Recorded only while the invite is live: a revocation that landed while the secret was being checked wins.
    if (!(await this.store.touchInvite(match.id, now.toISOString()))) throw new AlpError("identity_mismatch", "sign-in failed", { status: 401 });
    return {
      address: parseAddress(match.address),
      ...(match.display_name ? { display_name: match.display_name } : {}),
      method: "invite",
      iss: this.issuer,
      sub: `invite:${username}`,
      verified_at: now.toISOString(),
    };
  }

  /** The live invite a verified sign-in used (for the person's notice address). */
  async liveInvite(username: string): Promise<InviteRecord | null> {
    try {
      const u = checkUsername(username);
      return (await this.store.listInvites(u)).filter((i) => isLive(i, this.clock.now())).at(-1) ?? null;
    } catch {
      return null;
    }
  }

  /** Whether a name has a live invite (the sign-in limiter counts failures only for names that do). */
  async known(username: string): Promise<boolean> {
    try {
      const u = checkUsername(username);
      return (await this.store.listInvites(u)).some((i) => isLive(i, this.clock.now()));
    } catch {
      return false;
    }
  }
}
