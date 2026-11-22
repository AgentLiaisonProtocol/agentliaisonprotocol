---
title: About the project
---
# About the project

## Author and steward

The Agent Liaison Protocol (ALP) was written by Brien Collier at Lucaryin. Lucaryin is its initial steward: it maintains the specification, the schemas, the vectors, the registries and the reference implementation in the [repository](https://github.com/AgentLiaisonProtocol/agentliaisonprotocol). Lucaryin LLC also licenses the reference broker, whose copyright it holds.

Lucaryin intends to move the specification to a neutral foundation, so that no single company controls it. No foundation has agreed to host it yet, and no vendor, foundation or standards body has endorsed it. Until it moves, [Governance](../../GOVERNANCE.md) describes how decisions are made.

## Roles

- **Editors** maintain the specification text and the registries, and decide on normative changes. The initial editor is Brien Collier.
- **Maintainers** maintain the schemas, vectors, specification tools and reference implementation, and review changes to them.
- **Contributors** are everyone who opens an issue, comments or proposes a change.

People from any organization can become editors or maintainers. The steward appoints them and will publish the list in [Governance](../../GOVERNANCE.md#roles) as it grows.

## How decisions are made

Anyone can propose a change by opening an issue, and discussion happens in the open. Editors aim for rough consensus among contributors; when it isn’t reached, they decide and record why, and anyone who disagrees can ask the steward to review the decision. A normative change is complete only when the specification text, the schemas and the vectors agree, and changes to Core sections also need the reference implementation to follow. Decisions that change the protocol are recorded in the [changelog](../../CHANGELOG.md).

## Versions

The specification uses semantic versioning. While the major version is 0, a release may change things incompatibly; from 1.0 onward, a version stays supported for at least 6 months after its successor (specification Section 16).

## Taking part

- Read the [specification](../../spec/alp-v0.1.md), run the demo, implement it, and report what breaks. Issues and pull requests are welcome ([Contributing](../../CONTRIBUTING.md)).
- Questions go to hello@agentliaisonprotocol.org.
- Security vulnerabilities go privately to security@agentliaisonprotocol.org, not to a public issue. The [security policy](../../SECURITY.md) aims to acknowledge reports within 3 business days.
- Everyone taking part follows the [Code of Conduct](../../CODE_OF_CONDUCT.md).
