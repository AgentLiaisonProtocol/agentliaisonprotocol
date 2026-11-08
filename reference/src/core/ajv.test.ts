// SPDX-License-Identifier: FSL-1.1-ALv2
// How schema errors read (src/core/ajv.ts): one reason per pointer, from the schema and Ajv's params only.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createAjv, joinWithin, toSchemaErrors } from "./ajv.ts";
import { bodyErrors } from "./spec-schemas.ts";

test("an if/then artifact is dropped: an ack that says ratified is told only that ratification is missing", () => {
  const errors = bodyErrors("ack", { of: "01JC1111111111111111111111", status: "ratified" });
  assert.deepEqual(errors, [{ pointer: "/ratification", message: "is required and missing" }]);
  assert.ok(errors.every((e) => !/then|if/.test(e.message)));
});

test("const, pattern, uniqueItems and several problems at one pointer, each from the schema and never the value", () => {
  const ajv = createAjv();
  const v = ajv.compile({
    type: "object",
    additionalProperties: false,
    properties: {
      kind: { const: "link" },
      id: { type: "string", pattern: "^[a-z]+$", maxLength: 3 },
      tags: { type: "array", uniqueItems: true, minItems: 1 },
      n: { type: ["integer", "null"] },
    },
  });
  assert.equal(v({ kind: "SECRET-1", id: "SECRET-2", tags: ["SECRET-3", "SECRET-3"], n: "SECRET-4", extra: "SECRET-5" }), false);
  const errors = toSchemaErrors(v.errors);
  assert.deepEqual(errors, [
    { pointer: "/extra", message: "isn't a field here (fields: kind, id, tags, n)" },
    { pointer: "/kind", message: 'must be "link"' },
    { pointer: "/id", message: "must be at most 3 characters long; must match the pattern ^[a-z]+$" },
    { pointer: "/tags", message: "must not repeat an item" },
    { pointer: "/n", message: "must be an integer or null" },
  ]);
  assert.ok(!JSON.stringify(errors).includes("SECRET"), "no value is echoed");
});

test("joinWithin keeps whole sentences within the limit and counts what it left out", () => {
  assert.equal(joinWithin(["One.", "Two.", "Three."], 100), "One. Two. Three.");
  assert.equal(joinWithin(["One.", "Two.", "Three."], 20), "One. (and 2 more)");
  assert.equal(joinWithin(["x".repeat(50)], 10), `${"x".repeat(9)}…`);
  const long = joinWithin(Array.from({ length: 200 }, (_, i) => `Problem ${i} is described here.`), 1000);
  assert.ok(long.length <= 1000);
  assert.match(long, /\(and \d+ more\)$/);
  // Sentences the caller stopped collecting are counted with the ones left out here.
  assert.equal(joinWithin(["One.", "Two."], 100, " ", 5), "One. Two. (and 5 more)");
  assert.equal(joinWithin(["One.", "Two.", "Three."], 20, " ", 5), "One. (and 7 more)");
  assert.equal(joinWithin(["One."], 100, " ", 0), "One.");
});
