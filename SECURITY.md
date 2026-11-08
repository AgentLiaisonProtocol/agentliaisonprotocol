# Security policy

## Reporting a vulnerability

Please report security problems privately to **security@agentliaisonprotocol.org**, not in a public issue.

Include:

- what is affected: the specification (with the section), the schemas, the vectors or the reference implementation (with the version or commit);
- how to reproduce it, and what an attacker gains;
- whether you plan to publish, and when.

We aim to acknowledge reports within 3 business days and to agree a disclosure date with you, normally within 90 days. We credit reporters who want credit.

## Scope

In scope:

- design flaws in the protocol that break its stated guarantees (spec Section 1.4) or its threat mitigations (spec Section 14);
- bugs in the reference implementation, the schemas, the vectors or the specification tools.

Out of scope:

- the keys in `vectors/keys/`, which are TEST-ONLY and published on purpose;
- the limits the specification already states, such as prompt injection into a vendor's agent or what a compromised home broker can do (spec Sections 1.5 and 14). Better mitigations for them are welcome as ordinary issues;
- services run by any operator, including hosted brokers. Report those to the operator's own contact, named in its operator statement (spec Section 13.9).

## Supported versions

Version 0.1 is a draft for implementers. Fixes go into the latest 0.1.x draft and, where they change the protocol, into the next version.
