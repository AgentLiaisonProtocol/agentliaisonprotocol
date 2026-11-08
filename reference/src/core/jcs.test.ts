// SPDX-License-Identifier: FSL-1.1-ALv2
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize, JcsError } from "./jcs.ts";

test("RFC 8785 §3.2.2 sample: literals, numbers and string escaping", () => {
  const input = JSON.parse(
    '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],' +
      '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
  );
  assert.equal(
    canonicalize(input),
    '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],' +
      '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
  );
});

test("RFC 8785 §3.2.3: members sorted by UTF-16 code units", () => {
  const input = {
    "€": "Euro Sign",
    "\r": "Carriage Return",
    "דּ": "Hebrew Letter Dalet With Dagesh",
    "1": "One",
    "😀": "Emoji: Grinning Face",
    "\u0080": "Control",
    "ö": "Latin Small Letter O With Diaeresis",
  };
  assert.equal(
    canonicalize(input),
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",' +
      '"€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
  );
});

test("RFC 8785 Appendix B: IEEE 754 number serialization", () => {
  const vectors: [string, string][] = [
    ["0000000000000000", "0"],
    ["8000000000000000", "0"],
    ["0000000000000001", "5e-324"],
    ["8000000000000001", "-5e-324"],
    ["7fefffffffffffff", "1.7976931348623157e+308"],
    ["ffefffffffffffff", "-1.7976931348623157e+308"],
    ["4340000000000000", "9007199254740992"],
    ["c340000000000000", "-9007199254740992"],
    ["4430000000000000", "295147905179352830000"],
    ["44b52d02c7e14af5", "9.999999999999997e+22"],
    ["44b52d02c7e14af6", "1e+23"],
    ["44b52d02c7e14af7", "1.0000000000000001e+23"],
    ["444b1ae4d6e2ef4e", "999999999999999700000"],
    ["444b1ae4d6e2ef4f", "999999999999999900000"],
    ["444b1ae4d6e2ef50", "1e+21"],
    ["3eb0c6f7a0b5ed8c", "9.999999999999997e-7"],
    ["3eb0c6f7a0b5ed8d", "0.000001"],
    ["41b3de4355555553", "333333333.3333332"],
    ["41b3de4355555554", "333333333.33333325"],
    ["41b3de4355555555", "333333333.3333333"],
    ["41b3de4355555556", "333333333.3333334"],
    ["41b3de4355555557", "333333333.33333343"],
    ["becbf647612f3696", "-0.0000033333333333333333"],
    ["43143ff3c1cb0959", "1424953923781206.2"],
  ];
  for (const [hex, expected] of vectors) {
    const n = Buffer.from(hex, "hex").readDoubleBE(0);
    assert.equal(canonicalize(n), expected, `0x${hex}`);
  }
});

test("rejects what I-JSON forbids", () => {
  assert.throws(() => canonicalize(Number.NaN), JcsError);
  assert.throws(() => canonicalize(Number.POSITIVE_INFINITY), JcsError);
  assert.throws(() => canonicalize({ a: "\ud800" }), JcsError);
  assert.throws(() => canonicalize({ ["\udc00"]: 1 }), JcsError);
  assert.throws(() => canonicalize([undefined]), JcsError);
  assert.throws(() => canonicalize({ d: new Date(0) }), JcsError);
  assert.throws(() => canonicalize({ n: 10n }), JcsError);
});

test("undefined object members are absent; nesting and arrays keep order", () => {
  assert.equal(canonicalize({ b: [3, { y: 1, x: 2 }], a: undefined, c: "" }), '{"b":[3,{"x":2,"y":1}],"c":""}');
  assert.equal(canonicalize({}), "{}");
  assert.equal(canonicalize([]), "[]");
});

test("canonical form is stable across key insertion order", () => {
  const a = { z: 1, a: { k: [1, 2], b: null }, m: "x" };
  const b = { m: "x", a: { b: null, k: [1, 2] }, z: 1 };
  assert.equal(canonicalize(a), canonicalize(b));
});
