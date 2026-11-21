// Link rewriting for pages rendered from repository documents.
//
//   - A relative link from one repository document to another becomes a link to that document's page when
//     the manifest has one (the fragment is kept), and otherwise a link to the file on GitHub (blob for
//     files, tree for folders).
//   - A link to https://agentliaisonprotocol.org/... becomes a link to that page.
//   - On the published-version page ("commit" mode) every repository link goes to GitHub at that commit.
//   - Fragment-only links, other sites and mailto: links are left as they are.
//
// The same resolution serves the HTML pages (links relative to the page) and the Markdown mirrors
// (absolute site URLs).

import path from "node:path";
import { splitUrl } from "./urls.mjs";

/**
 * Resolve one href found in `sourcePath`. Returns one of
 *   { kind: "same", fragment }                       a link within the document
 *   { kind: "page", url, fragment }                  a page of this site (url is a site path)
 *   { kind: "site", url }                            a file this site serves (from an absolute site link)
 *   { kind: "repo", href, repoPath, missing }        a repository file or folder on GitHub
 *   { kind: "external", href }                       anything else
 *
 * env: { site, pageForSource: Map(repoPath -> page url), exists(repoPath) -> "file" | "dir" | null,
 *        ref: "main" or a commit id, pagesInCommitMode: false }
 */
export function resolveLink(href, sourcePath, env) {
  const { site } = env;
  if (href.startsWith("#")) return { kind: "same", fragment: href };
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("//")) {
    const m = /^https?:\/\/agentliaisonprotocol\.org(\/[^?#]*)?([?#].*)?$/i.exec(href);
    if (m) {
      const p = m[1] || "/";
      const { fragment } = splitUrl(m[2] || "");
      return { kind: "page", url: p, fragment };
    }
    return { kind: "external", href };
  }
  const { path: rel, query, fragment } = splitUrl(href);
  if (rel === "") return { kind: "same", fragment };
  const baseDir = path.posix.dirname(sourcePath);
  const joined = rel.startsWith("/") ? rel.slice(1) : path.posix.join(baseDir, decodeURIComponent(rel));
  const repoPath = path.posix.normalize(joined).replace(/\/$/, "").replace(/^\.$/, "");
  if (repoPath.startsWith("..")) return { kind: "external", href, problem: `link ${href} leaves the repository` };
  if (env.ref === "main" && env.pageForSource.has(repoPath)) return { kind: "page", url: env.pageForSource.get(repoPath), fragment };
  const type = env.exists(repoPath);
  const ref = env.ref === "main" ? site.branch : env.ref;
  const href2 = `${site.repo}/${type === "dir" ? "tree" : "blob"}/${ref}/${repoPath.split("/").map(encodeURIComponent).join("/")}${query}${fragment}`;
  return { kind: "repo", href: href2, repoPath, fragment, missing: type === null };
}
