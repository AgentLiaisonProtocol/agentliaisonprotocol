// SPDX-License-Identifier: FSL-1.1-ALv2
// Limits on starting sign-ins at the organization's identity provider (oidc-signin.ts allowStart): the public
// connector page and the web view never share a count, so strangers can't block anyone's approvals.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { OidcRelyingParty } from "./oidc.ts";
import { OidcSignIn } from "./oidc-signin.ts";
import { BindingState } from "./state.ts";

const signIn = (): OidcSignIn => new OidcSignIn({ rp: {} as unknown as OidcRelyingParty, state: BindingState.memory(), secret: "a-test-sealing-secret-of-32-chars-or-more", log: () => undefined });

test("connector sign-ins started from many addresses use up no one else's budget: approvals and web sign-ins still start", async () => {
  const s = signIn();
  let started = 0;
  for (let a = 0; a < 100; a++) for (let i = 0; i < 31; i++) if (await s.allowStart(`198.51.100.${a}`, "connector")) started++;
  assert.equal(started, 3000, "30 from each address");
  assert.equal(await s.allowStart("stepup|ana-principal-00001", "web"), true, "a person's approval step-up");
  assert.equal(await s.allowStart("signin|127.0.0.1", "web"), true, "a sign-in on the loopback web view");
  assert.equal(await s.allowStart("203.0.113.9", "connector"), true, "and a connector sign-in from another address: there is no total to use up");
});

test("one source gets 30 connector sign-in starts in 10 minutes, and every address of an IPv6 /64 is that one source", async () => {
  const s = signIn();
  for (let i = 0; i < 30; i++) assert.equal(await s.allowStart(`2001:db8:1:2::${(i + 1).toString(16)}`, "connector"), true);
  assert.equal(await s.allowStart("2001:db8:1:2:ffff::1", "connector"), false, "a new address in the same /64 is the same source");
  assert.equal(await s.allowStart("2001:db8:1:3::1", "connector"), true, "another /64 is another source");
});

test("the web view's budget: 30 starts per person or source in 10 minutes, counted apart from the connector page", async () => {
  const s = signIn();
  for (let i = 0; i < 30; i++) assert.equal(await s.allowStart("stepup|lee-principal-00001", "web"), true);
  assert.equal(await s.allowStart("stepup|lee-principal-00001", "web"), false);
  assert.equal(await s.allowStart("stepup|ana-principal-00001", "web"), true, "another person isn't affected");
  assert.equal(await s.allowStart("stepup|lee-principal-00001", "connector"), true, "nor the connector page");
});
