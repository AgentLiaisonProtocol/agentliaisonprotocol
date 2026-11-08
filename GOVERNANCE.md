# Governance

## Steward and author

The Agent Liaison Protocol (ALP) was written by Brien Collier at Lucaryin. Lucaryin is its initial steward: it maintains the specification, the schemas, the vectors, the registries and the reference implementation in this repository.

Lucaryin intends to move the specification to a neutral foundation, so that no single company controls it. No foundation has agreed to host it yet, and no vendor, foundation or standards body has endorsed it. Until it moves, this document describes how decisions are made.

## Roles

- **Editors** maintain the specification text and the registries (spec Section 18), and decide on normative changes. The initial editor is Brien Collier.
- **Maintainers** maintain the schemas, vectors, specification tools and reference implementation, and review changes to them.
- **Contributors** are everyone who opens an issue, comments or proposes a change.

The steward appoints editors and maintainers, and will publish the list in this file as it grows. People from any organization can become editors or maintainers.

## How decisions are made

1. Anyone can propose a change by opening an issue (see [CONTRIBUTING.md](CONTRIBUTING.md)).
2. Discussion happens in the open, in the issue or its pull request.
3. Editors aim for rough consensus among contributors. When consensus isn't reached, the editors decide and record why.
4. A normative change is complete only when the specification text, the schemas and the vectors agree. Changes to Core sections also need the reference implementation to follow.
5. Decisions that change the protocol are recorded in [CHANGELOG.md](CHANGELOG.md).
6. Anyone who disagrees with an editors' decision can ask the steward to review it, in the same issue.

## Versions

The specification uses semantic versioning. While the major version is 0, a release may change things incompatibly; from 1.0 onward, incompatible changes need a new major version, and a version stays supported for at least 6 months after its successor (spec Section 16). Each section of the specification carries a maturity label: Core, Experimental or Future.

## Registries

The editors maintain the registries in spec Section 18 (scopes, message types, error codes, labels, DLP categories, `typ` values and the others). A new core scope needs a definition that follows spec Section 7.3, vectors, and a reference implementation. Organizations don't need anyone's permission to define `org.<domain>.` scopes for domains they control.

## Licenses and patents

The specification text is licensed under CC BY 4.0, and the schemas, vectors, specification tools and other code outside `reference/` under Apache-2.0. Other documentation (the bridge kit, the agent instruction snippet, the announcement and the project's documents at the root, such as this one) is licensed under CC BY 4.0.

The reference broker, everything under `reference/`, is licensed by Lucaryin LLC, which holds its copyright and is ALP's initial steward, under the Functional Source License, Version 1.1, ALv2 Future License (FSL-1.1-ALv2, [reference/LICENSE.md](reference/LICENSE.md)). It is source-available, not open source: free for any organization to use, modify and run for itself, but not to be made available to others in a commercial product or service that substitutes for it or offers substantially similar functionality (in the license's words, a "Competing Use", which it defines in full), and each version becomes Apache-2.0 two years after it is first published. The [README](README.md#license) quotes the license's terms.

CC BY 4.0 grants no patent license; Apache-2.0 and FSL-1.1-ALv2 each include one, on their terms. Before version 1.0, the steward will decide on a patent commitment for the specification text, for example by adopting a specification license that includes one.

Implementing ALP needs no agreement with Lucaryin, including in a broker you build from the specification, schemas and vectors and then sell; nor does using, running or modifying the reference broker for any purpose its license permits. The licenses grant those rights, on their terms.

## Name

"Agent Liaison Protocol" names this specification. No trademark is claimed in it.

## Conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
