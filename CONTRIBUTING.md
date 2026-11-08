# Contributing

Thank you for helping. The Agent Liaison Protocol (ALP) is meant to become a shared standard, so reports from implementers and from organizations trying it out are the most useful contributions of all.

## Before you start

- **Security problems** go to [SECURITY.md](SECURITY.md), not to a public issue.
- **Problems** go in an issue. Say which part you mean (spec section, schema, vector or reference code) and what you expected. **Questions** can go in an issue too, or to hello@agentliaisonprotocol.org.
- Everyone follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Proposing a change to the protocol

Open an issue first for anything normative: a change to a MUST, a new field, message type or scope, or a change to an algorithm. Describe the problem before the solution. Then a pull request should change these together:

1. the specification text in `spec/`, using the BCP 14 key words only where you mean them normatively;
2. the schemas in `schemas/`;
3. the vectors, through `tools/spec/vectors.mjs` (expected outcomes are written by hand from the text);
4. the reference implementation in `reference/`, for Core sections (the maintainers can make this part).

Run the checks before you open the pull request:

```sh
cd tools/spec && npm ci && npm run vectors && npm run examples && npm run check
cd ../../reference && npm ci && npm run check
```

A change that a vector can't express usually needs more precise text.

## Smaller changes

Typo fixes, clearer wording and new vectors for existing behavior can go straight to a pull request.

## Writing style

Plain, specific English. Short sentences. Define a term before using it. Keep claims inside what the protocol actually guarantees (spec Section 1.4), and don't claim any vendor's support or endorsement. Examples use reserved domains (`example.org`, `*.example`), fictional people and the TEST-ONLY keys.

## Sign-off and licenses

Add a `Signed-off-by:` line to each commit to certify the Developer Certificate of Origin 1.1 (https://developercertificate.org). By contributing, you agree that contributions to the specification text and other documentation outside `reference/` are licensed under CC BY 4.0 ([LICENSE-SPEC](LICENSE-SPEC)), and contributions to code, schemas and vectors, including everything under `reference/`, under Apache-2.0 ([LICENSE](LICENSE)). Your sign-off certifies your right to submit under these licenses. Lucaryin LLC, ALP's initial steward, distributes the reference broker, with the contributions it accepts there, under FSL-1.1-ALv2 ([reference/LICENSE.md](reference/LICENSE.md)).

## How decisions are made

See [GOVERNANCE.md](GOVERNANCE.md).
