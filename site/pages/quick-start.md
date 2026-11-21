---
title: Quick start
---
# Quick start

Four ways to start, from the least to the most set-up. The first two need a developer and Node 22.18 or later; the third needs a broker that someone runs; the fourth is for building a broker or a client of your own.

## 1. Run the demo

The reference broker’s demo starts real HTTP servers on 127.0.0.1 and prints a numbered transcript: fictional people at fictional domains, agents that join as client-mode clients through the real OAuth flow, a confidential field stopped before it leaves, a rogue broker refused, and two ledgers that point at each other.

```sh
git clone https://github.com/AgentLiaisonProtocol/agentliaisonprotocol alp && cd alp/reference
npm ci                    # Node 22.18 or later
npm run demo              # the whole story over real HTTP on your machine
npm run demo:federation   # federation in detail: replays, a broker removed from its domain's document, revocation
npm test                  # the test suite, including every conformance vector in vectors/
```

To read the output without running it, see [what the demo prints](/docs/demo/).

## 2. Run a broker on one machine

To try the broker’s `npm start` with scripts before any TLS or identity provider is in place, follow [Evaluate on one machine](../../SELF-HOST.md#evaluate-on-one-machine). Everything stays on 127.0.0.1:

1. Start the broker with an evaluation configuration in a throwaway directory. It prints one sign-in secret per test person.
2. On the broker’s web page, sign in as a test person and create a personal access token, then do the same for a second person.
3. Call the REST mirror with those tokens: `alp_whoami`, then `alp_send` from one person and `alp_inbox` and `alp_ack` as the other.
4. On each person’s page, “Ledger” shows the exchange. Stop the broker and delete the directory.

The evaluation policy is for evaluation only. To run a broker for real people, read the rest of [Run a broker](../../SELF-HOST.md), including what isn’t built yet.

## 3. Connect an agent you already use

In client mode an agent you already use joins your home broker through one custom connector, with no work from its vendor. You need:

- your broker’s connector URL, from whoever runs your broker, for example `https://broker.example.org/mcp`;
- your address, which looks like an email address: `ana@example.org`;
- an agent that accepts a custom MCP connector (also called a custom connector or remote MCP server).

Then [the setup](../../bridge-kit/README.md#setup) has six steps: add the connector, sign in, allow its tools, add the instructions, set a recurring inbox check, and test it. [Connect an agent](../../bridge-kit/README.md) has a guide for each agent platform, with what was tested and what wasn’t.

## 4. Build it from the specification

[Implementing ALP](../../IMPLEMENTING.md) is a guide for anyone building a broker or a client from the specification. It adds no requirement of its own: it suggests an order for reading the specification, names the schemas, vectors and requirements that go with each part, and says what each way of checking in this repository tells you. Next to it:

- [Requirements and what tests them](../../CONFORMANCE.md) lists every numbered requirement of the specification’s Section 13, with the vector files that exercise it and the checks of `alp-check` that observe part of it from outside.
- The [conformance vectors](../../vectors/README.md) are how an implementation checks its own logic: you run them through your own code.
- [`alp-check`](../../tools/check/README.md) is the complement for a running broker. You point it at your domain, or at a broker in the Local profile, and it reports what it can observe from outside, with no credentials. It checks a part of the specification, and every report says which part; a report with no failures does not mean an implementation conforms.

```sh
cd tools/check
npm ci                     # Node 22.18 or later
node check.mjs example.org  # example.org stands for your own domain
```

Run it against domains and brokers you operate, or are allowed to test.
