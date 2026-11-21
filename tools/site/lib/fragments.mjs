// An audit of every #fragment the repository's own documents use: links in Markdown (relative, or absolute
// to this repository on GitHub or to the site) and in the site's HTML sources. Used by the unit tests to
// prove the heading-id function matches GitHub's for every link the repository already has.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { analyzeMarkdown } from "./markdown.mjs";
import { headingsOf } from "./pages.mjs";
import { splitUrl } from "./urls.mjs";

const GH = /^https:\/\/github\.com\/AgentLiaisonProtocol\/agentliaisonprotocol\/blob\/main\/([^?#]+)(#.*)?$/;

/** Tracked files of the repository at `root` matching a pathspec. */
function tracked(root, spec) {
  return execFileSync("git", ["ls-files", "--", spec], { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean).sort();
}

/**
 * Every link with a fragment into a repository Markdown file: [{ from, line, href, target, fragment, ok }].
 * `pagesByUrl` maps site page URLs to their repository source, for links to https://agentliaisonprotocol.org.
 */
export function auditFragments(root, pagesByUrl = new Map()) {
  const ids = new Map();
  const idsOf = (p) => {
    if (!ids.has(p)) {
      let md = null;
      try { md = fs.readFileSync(path.join(root, p), "utf8"); } catch { md = null; }
      ids.set(p, md === null ? null : new Set(headingsOf(md).map((h) => h.id)));
    }
    return ids.get(p);
  };
  const out = [];
  const consider = (from, line, href) => {
    let target = null;
    let fragment = "";
    const gh = GH.exec(href);
    const site = /^https?:\/\/agentliaisonprotocol\.org(\/[^?#]*)?(#.*)?$/.exec(href);
    if (gh) { target = decodeURIComponent(gh[1]); fragment = gh[2] || ""; }
    else if (site) { target = pagesByUrl.get(site[1] || "/") || null; fragment = site[2] || ""; }
    else if (!/^[a-z][a-z0-9+.-]*:/i.test(href)) {
      const u = splitUrl(href);
      fragment = u.fragment;
      target = u.path === "" ? from : path.posix.normalize(path.posix.join(path.posix.dirname(from), decodeURIComponent(u.path)));
    }
    if (!target || !fragment || fragment === "#" || !target.endsWith(".md")) return;
    const set = idsOf(target);
    out.push({ from, line, href, target, fragment, ok: set !== null && set.has(decodeURIComponent(fragment.slice(1))) });
  };
  for (const f of tracked(root, "*.md")) {
    const md = fs.readFileSync(path.join(root, f), "utf8");
    for (const l of analyzeMarkdown(md).links) consider(f, l.line, l.dest);
    for (const m of md.matchAll(/https:\/\/github\.com\/AgentLiaisonProtocol\/agentliaisonprotocol\/blob\/main\/[^\s)<>"'`\]]+#[^\s)<>"'`\]]+/g)) {
      const line = md.slice(0, m.index).split("\n").length;
      if (!out.some((o) => o.from === f && o.line === line && o.href === m[0])) consider(f, line, m[0]);
    }
  }
  for (const f of [...tracked(root, "site/*.html"), ...tracked(root, "site/**/*.html"), ...tracked(root, "announcement/*.html")]) {
    const html = fs.readFileSync(path.join(root, f), "utf8");
    for (const m of html.matchAll(/href="([^"]+)"/g)) {
      const line = html.slice(0, m.index).split("\n").length;
      if (GH.test(m[1])) consider(f, line, m[1].replace(/&amp;/g, "&"));
    }
  }
  const seen = new Set();
  return out.filter((o) => { const k = `${o.from}:${o.line}:${o.href}`; if (seen.has(k)) return false; seen.add(k); return true; });
}
