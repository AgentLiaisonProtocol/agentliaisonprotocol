// The README's table of checks matches the catalogue, and the checker's public text follows CONTRIBUTING.md's
// wording rules: no certification claims and none of the words the project avoids.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { CHECKS, NOT_CHECKED, basisShort } from "../catalog.mjs";
import { USAGE } from "../check.mjs";
import { render } from "../requirements.mjs";
import { readSpec } from "../spec-text.mjs";

const readme = fs.readFileSync(new URL("../README.md", import.meta.url), "utf8");

test("the README lists every check with its level, basis and section, and no other", () => {
  const rows = readme.split("\n").filter((l) => /^\| `[a-z]+\.[a-z0-9-]+` \|/.test(l));
  const listed = rows.map((l) => l.split("|").map((c) => c.trim())).map((c) => ({ id: c[1].replace(/`/g, ""), level: c[2], basis: c[3], section: c[4] }));
  assert.deepEqual(listed, CHECKS.map((c) => ({ id: c.id, level: c.level, basis: basisShort(c), section: c.section })));
});

test("public text uses none of the words the project avoids", () => {
  const text = [readme, NOT_CHECKED.join(" "), USAGE, ...CHECKS.map((c) => `${c.title} ${c.note ?? ""}`)].join("\n");
  // "certificate" (TLS) is not a claim of certification.
  const banned = /\b(seamless|powerful|robust|revolutionary|leverage|unlock|cutting-edge|game-changing|best-in-class|world-class|effortless|blazing|supercharge|next-generation|enterprise-grade|certif(?:y|ies|ied|ication)|compliant|conformant|PAP)\b/i;
  const m = banned.exec(text);
  assert.equal(m, null, m && `found "${m[0]}"`);
  assert.ok(!text.includes("!"), "no exclamation marks");
});

test("the body limit is described without an order of acceptance steps the specification does not give", () => {
  // Section 12.2.4 names no step for the 64 KiB limit of Section 8.10, so no public text may say it comes after step 1.
  const conformance = render(readSpec());
  for (const [name, text] of [["README.md", readme], ["CONFORMANCE.md", conformance]]) {
    const flat = text.replace(/\s+/g, " ");
    assert.ok(!/before (any|the) (body )?limit (can|could) (apply|show)/.test(flat), `${name}: orders the body limit after step 1`);
    assert.match(flat, /does not say at which acceptance step the 64 KiB (body )?limit applies/, name);
    assert.match(flat, /cannot require `body_too_large`/, name);
  }
});
