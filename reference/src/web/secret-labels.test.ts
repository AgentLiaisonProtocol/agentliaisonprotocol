// SPDX-License-Identifier: FSL-1.1-ALv2
// The dev sign-in's secret has the name the operator gave it: `npm run dev` prints one session secret for every test
// identity; `npm start` gives each test identity its own sign-in secret (SELF-HOST.md, "Evaluate on one machine"). The web
// view's sign-in, its confirmation on action forms and the connector sign-in page use the matching words.

import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { test } from "node:test";
import { Browser, TEST_SECRET, startTestBroker } from "../mcp/testkit.ts";

async function pages(secretKind?: "session" | "personal"): Promise<{ login: string; home: string; connector: string }> {
  const t = await startTestBroker(secretKind ? { secretKind } : {});
  try {
    const b = new Browser();
    const login = await (await b.request(`${t.web}/web`)).text();
    await b.request(`${t.web}/web/login`, { form: { username: "ana", secret: TEST_SECRET } });
    const home = await (await b.request(`${t.web}/web`)).text();
    const reg = (await (await fetch(`${t.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "Script", application_type: "native", redirect_uris: ["http://127.0.0.1:47199/callback"], token_endpoint_auth_method: "none" }) })).json()) as { client_id: string };
    const verifier = randomBytes(32).toString("base64url");
    const q = new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "http://127.0.0.1:47199/callback", code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", scope: "read send", resource: `${t.base}/mcp` });
    const cb = new Browser();
    const connector = await (await cb.follow(await cb.request(`${t.base}/oauth/authorize?${q}`), t.base)).res.text();
    return { login, home, connector };
  } finally {
    await t.close();
  }
}

test("npm start's per-identity secrets are named 'your sign-in secret'; npm run dev's shared one 'session secret'", async () => {
  const mine = await pages("personal");
  assert.match(mine.login, /<label>Your sign-in secret<br>/);
  assert.match(mine.home, /Confirm it's you: your sign-in secret <input/, "the token form asks for it again");
  assert.match(mine.connector, /<label>Your sign-in secret \(from the broker's operator\)<br>/);
  for (const page of [mine.login, mine.home, mine.connector]) assert.doesNotMatch(page, /[Ss]ession secret/);

  const shared = await pages();
  assert.match(shared.login, /<label>Session secret<br>/);
  assert.match(shared.home, /Confirm it's you: session secret <input/);
  assert.match(shared.connector, /Session secret \(printed in the broker operator's terminal\)/);
});
