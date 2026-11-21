import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Slugger, slugify } from "../lib/slug.mjs";
import { headingsOf } from "../lib/pages.mjs";
import { auditFragments } from "../lib/fragments.mjs";
import * as config from "../site.config.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

test("slugify follows GitHub's rule", () => {
  assert.equal(slugify("17. Relationship to other work"), "17-relationship-to-other-work");
  assert.equal(slugify("12.6 Poppy (the Personal Agent Protocol)"), "126-poppy-the-personal-agent-protocol");
  assert.equal(slugify("5.6 The OAuth 2.1 profile of the client binding"), "56-the-oauth-21-profile-of-the-client-binding");
  assert.equal(slugify("5.2 Principals and principal_id"), "52-principals-and-principal_id");
  assert.equal(slugify("What’s tested and what isn’t"), "whats-tested-and-what-isnt");
  assert.equal(slugify("[0.1.1] - Unreleased"), "011---unreleased");
  assert.equal(slugify("Sections 4.2–4.8"), "sections-4248");
  assert.equal(slugify("Ünïcode Wörds"), "ünïcode-wörds");
  assert.equal(slugify("  two  spaces "), "--two--spaces-");
});

test("repeats get -1, -2 like GitHub", () => {
  const s = new Slugger();
  assert.deepEqual(["Notes", "Notes", "Notes", "Notes-1"].map((t) => s.slug(t)), ["notes", "notes-1", "notes-2", "notes-1-1"]);
});

test("the specification's headings get the ids existing links use", () => {
  const md = fs.readFileSync(path.join(ROOT, "spec/alp-v0.1.md"), "utf8");
  const ids = new Set(headingsOf(md).map((h) => h.id));
  for (const id of ["abstract", "status-of-this-document", "15-non-goals", "17-relationship-to-other-work", "19-future-work",
    "56-the-oauth-21-profile-of-the-client-binding", "126-poppy-the-personal-agent-protocol", "1224-acceptance-checks",
    "appendix-a-worked-examples", "a4-a-rogue-broker-refused", "187-key-purposes-alp_use"]) {
    assert.ok(ids.has(id), `missing #${id}`);
  }
  const all = headingsOf(md).map((h) => h.id);
  assert.equal(new Set(all).size, all.length, "every heading id in the specification is unique");
});

test("every #fragment the repository's documents use resolves with this slug function", () => {
  const pagesByUrl = new Map(config.pages.filter((p) => p.source && p.source.endsWith(".md")).map((p) => [p.url, p.source]));
  const links = auditFragments(ROOT, pagesByUrl);
  assert.ok(links.length > 50, `expected the audit to find the repository's fragment links (found ${links.length})`);
  const broken = links.filter((l) => !l.ok).map((l) => `${l.from}:${l.line} ${l.href}`);
  assert.deepEqual(broken, []);
});
