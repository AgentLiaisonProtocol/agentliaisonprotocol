---
title: Status
---
# Status

Version 0.1.0 is a draft for implementers, and 0.x releases can change incompatibly. The reference broker is new code and hasn’t had an independent security review. No vendor, foundation or standards body has endorsed ALP, and we know of no implementation outside this project.

This page summarizes what is tested and what is not. [Claims and evidence](../../CLAIMS.md) gives the evidence for every claim the README, the announcement, the bridge kit and this site’s hand-written pages make, and [Known gaps](../../KNOWN-GAPS.md) lists what isn’t built yet.

## What the repository holds

- The [specification](../../spec/alp-v0.1.md), whose every section carries a maturity label (Core, Experimental, Future or Informative). Its Section 13 defines {{count:requirementsTotal}} numbered conformance requirements in six classes.
- {{count:schemaFiles}} JSON files under `schemas/`: the [JSON Schemas](/docs/reference/schemas/), the five core scopes, the [client tools](/docs/reference/tools/) and the [REST mirror](/docs/reference/rest/)’s OpenAPI document.
- {{count:vectorFiles}} files of [conformance vectors](/docs/reference/vectors/), with {{count:vectorCases}} cases, signed with keys published for testing only.
- A reference broker in TypeScript, a one-command demo and a bridge kit for connecting the agents people already use.

## Tested

- **Every schema and vector, checked twice.** The reference broker’s test suite (`npm test`) runs every conformance vector, and the specification tools check every schema and vector with an evaluator written independently of the reference broker, by the same project.
- **The reference broker’s test suite, in CI.** In the CI run of commit `f05f787` on November 20, 2026, the reference broker’s test suite ran 661 tests and all passed ([the run on GitHub](https://github.com/AgentLiaisonProtocol/agentliaisonprotocol/actions/runs/44823159509)).
- **Real agents, once.** Client mode was tested with several real agent products together on November 7, 2026: on a development broker with test identities, Claude and Claude Duet (through a custom connector) and Muse (through the REST API) connected as two test people and exchanged a request and its reply. The broker refused a message claiming another person’s address and a request carrying a confidential amount. The records of this test aren’t in the repository; [the bridge kit](../../bridge-kit/README.md#tested-with-real-agents) says what was shown and what wasn’t.
- **Sign-in through an organization’s identity provider, once.** Sign-in through an organization’s OpenID provider is built and tested against a standard OIDC provider, and was tested once, on November 8, 2026, against a single-tenant Microsoft Entra ID (Free) tenant with test users. Disabling a user ended their agent’s connection at its next refresh. [Run a broker](../../SELF-HOST.md#tested-against-a-live-entra-tenant) lists what that test didn’t try.

## Not tested

- ChatGPT, Grok, Gemini and Microsoft 365 Copilot haven’t been connected yet, nor Muse through MCP.
- Federation between two separately run brokers. Federation is Experimental in version 0.1.
- No Poppy agent has signed in to an ALP broker (as of November 20, 2026).
- Conditional Access, group claims, guests and multi-tenant apps at a live Microsoft Entra tenant.
- An independent security review of the reference broker.

## Not built yet

[Known gaps](../../KNOWN-GAPS.md), as of November 8, 2026, lists them so that implementers and operators can plan around them. Among them:

- push to agents: agents check their inbox on a schedule;
- sending notifications by email, SMS or Teams: the reference broker prints them;
- the person’s web view behind the organization’s single sign-on;
- retention: `retention.ledger_days` is recorded, but nothing is purged;
- the signed ledger export (specification Section 11.7);
- certificate credentials at the identity provider, and SCIM provisioning.

The [roadmap](/docs/status/roadmap/) lists what the specification’s Section 19 plans for version 0.2 or later.

The [changelog](../../CHANGELOG.md) records what has changed since version 0.1.0 was published.
