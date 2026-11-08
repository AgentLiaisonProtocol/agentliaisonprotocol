# Specification tools

Small Node scripts (Node 22 or later) that generate the conformance vectors, refresh the specification's worked examples from them, and check every schema and vector with an evaluator written independently of the reference broker. They are licensed under Apache-2.0.

```sh
cd tools/spec
npm ci                 # ajv 8.20.0 and ajv-formats 3.0.1, pinned
npm run vectors        # regenerate vectors/ (except vectors/README.md)
npm run examples       # refresh the worked examples in spec/alp-v0.1.md
npm run check          # compile every schema and check every vector
```

| Script | What it does |
|---|---|
| `vectors.mjs` | Writes `vectors/` from deterministic TEST-ONLY keys. Expected outcomes are written by hand from the specification; ids are derived from stable tags. |
| `examples.mjs` | Replaces each block between `<!-- example:NAME -->` and `<!-- /example -->` in the specification with the matching object from the vectors. |
| `validate.mjs` | Compiles every schema (JSON Schema 2020-12, Ajv strict mode except `strictRequired`); checks the scope body-schema rules (closed objects, bounded strings and arrays, no `pattern`, free text at most 280 characters); checks the tool list and OpenAPI mirror; recomputes JCS, signatures and thumbprints; runs its own implementation of acceptance steps 0 to 6, sender-side evaluation, recipient-side steps 7 to 11, home-broker resolution, the thread and ratification hashes, the thread state machine (replies, follow-ups, the types each state accepts, the accept and counter rule, the thread limit, how threads end, and the window an availability answer keeps to), the ledger chain and the sanitizer against every vector; and checks that every signed object in the specification's examples is copied from the vectors. |
| `lib.mjs` | Shared helpers: JCS, a strict I-JSON parser, detached JWS, thumbprints, ULIDs, pointer patterns, the sanitizer and the baseline DLP. |

The JSON files in `schemas/` are the source of the schemas; edit them directly and run `npm run check`.

The scripts need their two dependencies installed first, also when you run one from the repository root: `cd tools/spec && npm ci`, then `npm run check`, or `node tools/spec/validate.mjs .` from the root.

## After changing names or keys

Signatures cover protocol strings such as `typ` values, addresses and the `alp` member, so any rename or key change invalidates the signed vectors. After a find-and-replace across the repository (including these scripts):

```sh
npm run vectors && npm run examples && npm run check
```

Regeneration is byte-identical except for the ES256 cases: ES256 signatures are randomized, so their values change on every run while still verifying. Ed25519 signatures are deterministic.
