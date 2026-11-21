## Other terms used on this site

Terms that appear on this site but that the specification's Section 2 doesn't define. Each sentence restates the document named after it.

### A2A

A2A connects agents to agents; an A2A agent joins ALP through its person's home broker, like any other agent. (Specification Section 17.)

### Conformance vector

A conformance vector is a test case for the specification: the vectors cover canonicalization, signatures, envelope validity, sender-side and recipient-side policy decisions, federation acceptance, threads, ledgers and delivery sanitizing, and an implementation runs them through its own code paths. ([README](../../README.md#whats-here) and [Conformance vectors](../../vectors/README.md#checking-an-implementation).)

### Connector

A custom connector (also called a custom MCP connector or remote MCP server) is how an agent you already use joins your home broker in client mode, with no work from its vendor. ([Connect an agent](../../bridge-kit/README.md#before-you-start).)

### Federation

Brokers of different organizations federate the way mail servers do: every person has an address on a domain, and the domain publishes which broker speaks for each of its people; federation is Experimental in version 0.1. (Specification Abstract and Section 3.3; [Claims and evidence](../../CLAIMS.md#how-it-works).)

### MCP

MCP, the Model Context Protocol, connects agents to tools; ALP's client binding is a remote MCP server, the door an agent uses to reach its own person's broker. (Specification Section 17; [the announcement](../../announcement/introducing-agent-liaison-protocol.md#built-on-what-already-exists).)

### OpenID Connect (OIDC)

OpenID Connect is how a broker signs people in through their organization's identity provider, such as Microsoft Entra ID. ([The announcement](../../announcement/introducing-agent-liaison-protocol.md#built-on-what-already-exists); [README](../../README.md).)

### Reference broker

The reference broker is the implementation of ALP in this repository's `reference/` folder, in TypeScript for Node 22, with its tests and the demo; it is source-available under FSL-1.1-ALv2. ([README](../../README.md#whats-here); [Governance](../../GOVERNANCE.md#licenses-and-patents).)
