import test from "node:test";
import assert from "node:assert/strict";
import { mirrorUrl, outPath, relUrl, resolveSitePath, splitUrl } from "../lib/urls.mjs";

test("relUrl makes links relative to the page", () => {
  assert.equal(relUrl("/docs/spec/", "/docs/guides/"), "../guides/");
  assert.equal(relUrl("/docs/spec/", "/"), "../../");
  assert.equal(relUrl("/", "/docs/spec/"), "docs/spec/");
  assert.equal(relUrl("/docs/spec/", "/docs/spec/#abstract"), "#abstract");
  assert.equal(relUrl("/docs/spec/", "/docs/spec/"), "./");
  assert.equal(relUrl("/docs/spec/", "/docs/spec.md"), "../spec.md");
  assert.equal(relUrl("/docs/guides/connect-an-agent/claude/", "/docs/guides/connect-an-agent/"), "../");
  assert.equal(relUrl("/docs/", "/assets/site.css?v=0123456789"), "../assets/site.css?v=0123456789");
  assert.equal(relUrl("/404.html", "/docs/"), "docs/");
  assert.equal(relUrl("/docs/0.1/spec/", "/docs/changelog/#011---unreleased"), "../../changelog/#011---unreleased");
});

test("relUrl offline adds index.html to folder links", () => {
  assert.equal(relUrl("/docs/spec/", "/docs/guides/", { offline: true }), "../guides/index.html");
  assert.equal(relUrl("/docs/spec/", "/", { offline: true }), "../../index.html");
  assert.equal(relUrl("/docs/spec/", "/docs/spec/#x", { offline: true }), "#x");
  assert.equal(relUrl("/docs/spec/", "/docs/spec.md", { offline: true }), "../spec.md");
});

test("resolveSitePath inverts relUrl", () => {
  const pages = ["/", "/docs/", "/docs/spec/", "/docs/guides/connect-an-agent/claude/", "/404.html"];
  for (const from of pages) for (const to of pages) {
    if (to === "/404.html" && from === to) continue;
    assert.equal(resolveSitePath(from, relUrl(from, to)).path, to, `${from} -> ${to}`);
  }
  assert.equal(resolveSitePath("/docs/", "../../x").path, null);
});

test("page paths, output files and mirrors", () => {
  assert.equal(outPath("/docs/spec/"), "docs/spec/index.html");
  assert.equal(outPath("/"), "index.html");
  assert.equal(outPath("/404.html"), "404.html");
  assert.equal(mirrorUrl("/docs/spec/"), "/docs/spec.md");
  assert.equal(mirrorUrl("/"), "/index.md");
  assert.deepEqual(splitUrl("a/b?x=1#f"), { path: "a/b", query: "?x=1", fragment: "#f" });
});
