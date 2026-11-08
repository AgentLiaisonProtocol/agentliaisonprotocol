// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  formatPointer,
  getAt,
  leafPointers,
  matchPattern,
  mostSpecific,
  parsePointer,
  removePointers,
} from "./pointers.ts";

test("parse and format follow RFC 6901 escaping", () => {
  assert.deepEqual(parsePointer(""), []);
  assert.deepEqual(parsePointer("/a~1b/c~0d/0"), ["a/b", "c~d", "0"]);
  assert.equal(formatPointer(["a/b", "c~d", "0"]), "/a~1b/c~0d/0");
  assert.throws(() => parsePointer("a/b"));
});

test("leaf pointers include primitives and empty containers below the root", () => {
  const body = { a: 1, b: { c: [1, { d: null }], e: {} }, f: [], "g/h": "x" };
  assert.deepEqual(leafPointers(body), ["/a", "/b/c/0", "/b/c/1/d", "/b/e", "/f", "/g~1h"]);
  assert.deepEqual(leafPointers({}), []);
});

test("patterns: * matches one token, and a pattern covers everything below it", () => {
  assert.equal(matchPattern("/context", "/context/summary"), true);
  assert.equal(matchPattern("/context/summary", "/context"), false);
  assert.equal(matchPattern("/questions/*", "/questions/3"), true);
  assert.equal(matchPattern("/figures/*/amount", "/figures/0/amount"), true);
  assert.equal(matchPattern("/figures/*/amount", "/figures/0/label"), false);
  assert.equal(matchPattern("", "/anything"), true);
  assert.equal(matchPattern("/topic", "/topics"), false);
});

test("most specific pattern wins", () => {
  const map: [string, string][] = [
    ["/context", "internal.general"],
    ["/context/financials", "confidential.financial"],
    ["/context/*/notes", "x.wild"],
    ["/context/financials/notes", "x.literal"],
  ];
  assert.equal(mostSpecific(map, "/context/summary"), "internal.general");
  assert.equal(mostSpecific(map, "/context/financials/figures/0/amount"), "confidential.financial");
  assert.equal(mostSpecific(map, "/context/financials/notes"), "x.literal");
  assert.equal(mostSpecific(map, "/other"), undefined);
});

test("removePointers removes leaves, prunes emptied containers, handles array indices", () => {
  const body = {
    topic: "t",
    context: { summary: "s", financials: { figures: [{ label: "a", amount: 1 }, { label: "b", amount: 2 }] } },
    list: ["x", "y", "z"],
    keep: {},
  };
  const out = removePointers(body, [
    "/context/financials/figures/0/label",
    "/context/financials/figures/0/amount",
    "/context/financials/figures/1/label",
    "/context/financials/figures/1/amount",
    "/list/0",
    "/list/2",
  ]);
  assert.deepEqual(out, { topic: "t", context: { summary: "s" }, list: ["y"], keep: {} });
  assert.equal(body.list.length, 3, "input is not mutated");
  assert.equal(getAt(body, "/context/financials/figures/1/label"), "b");
});
