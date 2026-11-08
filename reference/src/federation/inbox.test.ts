// SPDX-License-Identifier: FSL-1.1-ALv2
// The federation inbox's own checks before an envelope reaches the broker: here, that checking an optional request
// signature (spec 12.2.2) never spends the discovery allowance this broker's own sends use (spec 4.3 rule 6).

import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { DiscoveryError } from "./resolver.ts";
import type { DomainResolver, InboundResult } from "../core/interfaces.ts";
import type { DomainDocument, Jwks, Receipt } from "../core/types.ts";
import { onFreePorts } from "../test-ports.ts";
import { createInboxHandler } from "./inbox.ts";

/** Records the budget each discovery lookup is charged to; every domain is unknown. */
class RecordingResolver implements DomainResolver {
  readonly lookups: { domain: string; budget: string | undefined }[] = [];
  async domainDocument(domain: string, opts: { refresh?: boolean; budget?: string } = {}): Promise<DomainDocument> {
    this.lookups.push({ domain, budget: opts.budget });
    throw new DiscoveryError(false);
  }
  async jwks(): Promise<Jwks> {
    return { keys: [] };
  }
}

const resolver = new RecordingResolver();
let server: Server;
let base = "";
/** What the stand-in broker answers; a test may change it. */
let answer = async (): Promise<InboundResult> => ({ kind: "refused", status: 400, code: "bad_envelope", message: "not an envelope", step: 0 });

before(async () => {
  const handler = createInboxHandler({
    broker: { id: "https://broker.home.example", acceptInbound: () => answer() },
    publicUrl: "https://broker.home.example/federation/inbox",
    requestSignatures: "verify",
    resolver,
  });
  // Another test process may take a pooled port between the check and the listen: onFreePorts tries new ones.
  const port = await onFreePorts(1, async ([p]) => {
    const s = createServer((req, res) => void handler(req, res));
    await new Promise<void>((done, fail) => {
      s.once("error", fail);
      s.listen(p ?? 0, "127.0.0.1", () => done());
    });
    server = s;
    return (s.address() as AddressInfo).port;
  });
  base = `http://127.0.0.1:${port}`;
});
after(async () => {
  await new Promise<void>((done) => server.close(() => done()));
});

test("a request signature's key lookup is charged to the requester's discovery budget, never to the broker's own", async () => {
  for (let i = 0; i < 5; i++) {
    const r = await fetch(`${base}/federation/inbox`, {
      method: "POST",
      headers: { "content-type": "application/json", "signature-input": 'alp=("@method");created=1;keyid="k";tag="alp-fed"', signature: "alp=:AAAA:" },
      body: JSON.stringify({ from: { address: `alp:x@junk${i}.example` }, origin_broker: `https://broker.junk${i}.example` }),
    });
    await r.text();
  }
  assert.equal(resolver.lookups.length, 5, "each bogus signature header made a lookup");
  for (const l of resolver.lookups) assert.equal(l.budget, "127.0.0.1", `${l.domain}: charged to the requester, not to the unkeyed allowance`);
});

test("spec 9.3, 10.2: a thread_state refusal of a reply that overtook the message it answers carries Retry-After; other refusals don't", async () => {
  const receipt = { alp: "0.1", id: "01M709R0000000000000000000", envelope_id: "01M709R0000000000000000001", envelope_hash: "sha256:x", status: "refused", code: "thread_state" } as unknown as Receipt;
  const before = answer;
  const post = async (retryAfter: number | undefined): Promise<Response> => {
    answer = async () => ({ kind: "receipt", receipt, step: 8, ...(retryAfter !== undefined ? { retry_after: retryAfter } : {}) });
    const r = await fetch(`${base}/federation/inbox`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: "01M709R0000000000000000001" }) });
    await r.text();
    return r;
  };
  try {
    const early = await post(2);
    assert.equal(early.status, 409);
    assert.equal(early.headers.get("retry-after"), "2");
    const final = await post(undefined);
    assert.equal(final.status, 409);
    assert.equal(final.headers.get("retry-after"), null, "without the hint, thread_state is final");
  } finally {
    answer = before;
  }
});
