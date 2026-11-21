import test from "node:test";
import assert from "node:assert/strict";
import { resolveLink } from "../lib/links.mjs";
import { rewriteMarkdownLinks } from "../lib/markdown.mjs";

const site = { repo: "https://github.com/AgentLiaisonProtocol/agentliaisonprotocol", branch: "main", origin: "https://agentliaisonprotocol.org" };
const files = { "SELF-HOST.md": "file", "reference/LICENSE.md": "file", "vectors": "dir", "bridge-kit/README.md": "file", "bridge-kit/claude.md": "file", "LICENSE": "file", "": "dir" };
const env = (ref = "main") => ({
  site,
  ref,
  pageForSource: new Map([["SELF-HOST.md", "/docs/guides/run-a-broker/"], ["bridge-kit/README.md", "/docs/guides/connect-an-agent/"]]),
  exists: (p) => files[p] ?? null,
});

test("a link to a document with a page becomes that page, keeping the fragment", () => {
  assert.deepEqual(resolveLink("../SELF-HOST.md#tested-against-a-live-entra-tenant", "bridge-kit/claude.md", env()),
    { kind: "page", url: "/docs/guides/run-a-broker/", fragment: "#tested-against-a-live-entra-tenant" });
  assert.deepEqual(resolveLink("README.md", "bridge-kit/claude.md", env()), { kind: "page", url: "/docs/guides/connect-an-agent/", fragment: "" });
});

test("a link to a file without a page goes to GitHub: blob for files, tree for folders", () => {
  const r = resolveLink("reference/LICENSE.md", "SELF-HOST.md", env());
  assert.equal(r.kind, "repo");
  assert.equal(r.href, `${site.repo}/blob/main/reference/LICENSE.md`);
  assert.equal(resolveLink("vectors/", "SELF-HOST.md", env()).href, `${site.repo}/tree/main/vectors`);
  assert.equal(resolveLink("../LICENSE", "bridge-kit/claude.md", env()).href, `${site.repo}/blob/main/LICENSE`);
  assert.equal(resolveLink("nope.md", "SELF-HOST.md", env()).missing, true);
});

test("on the published-version page, repository links go to GitHub at that commit", () => {
  const sha = "ff8d56102c29e493ec353ec6a0be5bd733b56140";
  const r = resolveLink("../SELF-HOST.md#x", "spec/alp-v0.1.md", env(sha));
  assert.equal(r.kind, "repo");
  assert.equal(r.href, `${site.repo}/blob/${sha}/SELF-HOST.md#x`);
});

test("links to the site become page links; fragments, other sites and mailto stay", () => {
  assert.deepEqual(resolveLink("https://agentliaisonprotocol.org/poppy/", "x.md", env()), { kind: "page", url: "/poppy/", fragment: "" });
  assert.deepEqual(resolveLink("https://agentliaisonprotocol.org", "x.md", env()), { kind: "page", url: "/", fragment: "" });
  assert.deepEqual(resolveLink("#try-it", "x.md", env()), { kind: "same", fragment: "#try-it" });
  assert.equal(resolveLink("https://example.org/a", "x.md", env()).kind, "external");
  assert.equal(resolveLink("mailto:security@agentliaisonprotocol.org", "x.md", env()).kind, "external");
  assert.ok(resolveLink("../../outside.md", "x.md", env()).problem);
});

test("the Markdown mirror rewrites link destinations only, byte for byte elsewhere", () => {
  const md = "See [the guide](SELF-HOST.md#a) and `[not](a link)`.\n\n```\n[x](SELF-HOST.md)\n```\n\n[ref]: bridge-kit/README.md\n";
  const out = rewriteMarkdownLinks(md, (d) => `<${d}>`);
  assert.equal(out, "See [the guide](<SELF-HOST.md#a>) and `[not](a link)`.\n\n```\n[x](SELF-HOST.md)\n```\n\n[ref]: <bridge-kit/README.md>\n");
});
