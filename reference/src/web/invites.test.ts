// SPDX-License-Identifier: FSL-1.1-ALv2
// Invite sign-in (invites.ts): a revocation always wins over a sign-in that was checking the secret at the time.

import assert from "node:assert/strict";
import { test } from "node:test";
import { BindingState } from "../oauth/state.ts";
import { InviteIdentityVerifier, createInvite, revokeInvite } from "./invites.ts";

test("a revocation that lands while a sign-in checks the secret wins: that sign-in is refused, the invite stays revoked", async () => {
  const store = BindingState.memory();
  const { invite, secret } = await createInvite(store, { username: "kim", address: "alp:kim@example.org", days: 1, now: new Date() });
  const verifier = new InviteIdentityVerifier(store, "https://broker.example");
  const ok = await verifier.verify({ kind: "dev", username: "kim", secret });
  assert.equal(ok.address, "alp:kim@example.org");
  assert.ok((await store.getInvite(invite.id))?.last_used_at, "a sign-in is noted on the invite");
  // The sign-in reads the invite, then spends tens of milliseconds on scrypt (off the event loop); the revocation
  // lands meanwhile.
  const inFlight = verifier.verify({ kind: "dev", username: "kim", secret });
  await revokeInvite(store, invite.id, new Date());
  await assert.rejects(inFlight, /sign-in failed/);
  assert.ok((await store.getInvite(invite.id))?.revoked_at, "still revoked");
  await assert.rejects(verifier.verify({ kind: "dev", username: "kim", secret }), /sign-in failed/, "and no later sign-in either");
});

test("unknown names and wrong secrets are refused alike", async () => {
  const store = BindingState.memory();
  await createInvite(store, { username: "lee", address: "alp:lee@example.org", days: 1, now: new Date() });
  const verifier = new InviteIdentityVerifier(store, "https://broker.example");
  await assert.rejects(verifier.verify({ kind: "dev", username: "nobody", secret: "x" }), /sign-in failed/);
  await assert.rejects(verifier.verify({ kind: "dev", username: "lee", secret: "wrong" }), /sign-in failed/);
  await assert.rejects(verifier.verify({ kind: "dev", username: "Not A Name!", secret: "x" }), /sign-in failed/);
});
