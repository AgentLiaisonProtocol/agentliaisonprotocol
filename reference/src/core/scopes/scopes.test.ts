// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { ScopeRegistry, freeTextPatterns, labelsOf, suggestedFields, validateBody } from "./index.ts";

const reg = ScopeRegistry.load();

test("the five core scopes load from the spec's schemas/scopes", () => {
  for (const id of ["alp.availability/1", "alp.briefing/1", "alp.document_request/1", "alp.meeting/1", "alp.status/1"]) assert.ok(reg.get(id), id);
});

test("bodies validate against the scope's schema; common types use the protocol's bodies", () => {
  const s = reg.require("alp.briefing/1");
  assert.deepEqual(validateBody(s, "request", { topic: "T", depth: "summary" }), []);
  assert.ok(validateBody(s, "request", { topic: "T", depth: "summary", extra: 1 }).some((e) => e.pointer === "/body/extra"));
  assert.ok(validateBody(s, "request", { depth: "summary" }).some((e) => e.pointer === "/body/topic"));
  assert.deepEqual(validateBody(s, "ack", { of: "01JC0000000000000000000000", status: "received" }), []);
  assert.ok(validateBody(s, "propose", {}).length > 0, "briefing does not negotiate");
});

test("free text is found from x-alp-text, labels from the classification map (org overrides first)", () => {
  const s = reg.require("alp.briefing/1");
  const ft = freeTextPatterns(s, "request");
  assert.ok(ft.includes("/body/topic"));
  assert.ok(ft.includes("/body/questions/*"));
  assert.ok(ft.includes("/body/context/project"));
  assert.deepEqual(labelsOf(s, "request", "/body/context/amount/value"), ["confidential.financial"]);
  // Spec 6.5: the union of the scope's map and the organization's overrides; a leaf nothing names is internal.
  assert.deepEqual(labelsOf(s, "request", "/body/context/amount/value", { "/body/context/amount": ["restricted.money"] }), ["confidential.financial", "restricted.money"]);
  assert.deepEqual(labelsOf(s, "ack", "/body/of"), ["internal"]);
  assert.deepEqual(labelsOf(s, "request", "/note"), ["internal"]);
  assert.ok(suggestedFields(s).includes("/body/topic"));
});

test("every leaf a scope schema defines is classified", () => {
  for (const id of reg.ids()) {
    const s = reg.require(id);
    for (const [type, v] of s.validators) {
      const walk = (schema: unknown, path: string[]): void => {
        const o = schema as Record<string, unknown>;
        const props = o["properties"] as Record<string, unknown> | undefined;
        if (props) for (const [k, sub] of Object.entries(props)) walk(sub, [...path, k]);
        else if (o["items"]) walk(o["items"], [...path, "0"]);
        else assert.ok(labelsOf(s, type, `/${path.join("/")}`), `${id} ${type} /${path.join("/")} has no label`);
      };
      walk(v.schema, ["body"]);
    }
  }
});
