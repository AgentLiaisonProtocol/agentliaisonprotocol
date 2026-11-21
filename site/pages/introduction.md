---
title: Introduction
---
# Introduction

The Agent Liaison Protocol (ALP) is an open standard for work between people, carried by their agents, under each person’s rules.

Agents never talk to each other directly. Each agent talks only to its own person’s **home broker**: the one broker that speaks for that person, as a mail server does for a mail client. Home brokers carry only typed messages that both people’s rules allow, prove to each other whom they speak for, and each keeps a ledger its person can read.

An agent joins in one of two ways. In **client mode**, its person adds one connector to the agent they already use and signs in, which needs no work from the agent’s vendor. In **native mode**, the vendor builds the client into its product. Brokers of different organizations federate the way mail servers do: every person has an address on a domain, such as `ana@example.org`, and the domain publishes which broker speaks for each of its people.

Version 0.1 is a draft for implementers, and 0.x releases can change incompatibly. [Status](/docs/status/) says what is tested and what is not.

## Where to start

| If you are | Start with |
|---|---|
| Deciding whether ALP fits your organization | [The overview](/), then [Status](/docs/status/) and [About the project](/docs/project/) |
| Connecting an agent you already use | [Connect an agent](../../bridge-kit/README.md) |
| Running a broker for your organization | [Run a broker](../../SELF-HOST.md) |
| Building a broker or an agent | The specification’s reading guide, below, and the [reference pages](/docs/reference/) |
| Reviewing its security | The specification’s Sections 1.4, 14 and 15, and the [security policy](../../SECURITY.md) |

To see it work without installing anything, read [what the demo prints](/docs/demo/). To run it, see the [quick start](/docs/quick-start/).

## Reading the specification

The [specification](../../spec/alp-v0.1.md) is one document. Its Section 3 is the architecture. Implementers of a broker read specification Sections 4 to 12 and the conformance class they target in specification Section 13. People building agents in client mode read specification Sections 12.1 and 13.8. Security reviewers start with specification Sections 1.4, 14 and 15.

Every section carries a maturity label: **Core** sections are stable enough to implement now, **Experimental** ones are specified and testable but more likely to change, and **Future** ones are planned for version 0.2 or later. The [glossary](/docs/glossary/) lists the terms the specification defines.

## What is on this site

- [Specification](../../spec/alp-v0.1.md): the working text, and [version 0.1.0 as first published](/docs/0.1/spec/).
- [Guides](/docs/guides/): connecting an agent you already use, running a broker, and the reference broker’s architecture.
- [Reference](/docs/reference/): the JSON Schemas, the client tools, the REST mirror and the conformance vectors.
- [Status](/docs/status/): what is tested and what is not, the claims and their evidence, the known gaps and the changelog.
- [Project](/docs/project/): who is behind ALP, how decisions are made, how to contribute, and the licenses.

Every page built from a document in the [repository](https://github.com/AgentLiaisonProtocol/agentliaisonprotocol) says which file it comes from, and is also published as Markdown.
