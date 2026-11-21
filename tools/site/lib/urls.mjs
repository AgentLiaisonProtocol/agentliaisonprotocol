// Site URLs. A page URL is a path from the site root: "/" or "/docs/spec/" for a page that is a folder
// (written as .../index.html), or "/404.html" for a file. Every link the site writes between its own pages
// is relative to the page it is on, so the output works under any path prefix.

/** Split "path?query#fragment" into its parts (query and fragment keep their leading "?" / "#"). */
export function splitUrl(u) {
  const h = u.indexOf("#");
  const frag = h === -1 ? "" : u.slice(h);
  const rest = h === -1 ? u : u.slice(0, h);
  const q = rest.indexOf("?");
  return { path: q === -1 ? rest : rest.slice(0, q), query: q === -1 ? "" : rest.slice(q), fragment: frag };
}

/** The output file for a page URL: "/docs/spec/" -> "docs/spec/index.html", "/404.html" -> "404.html". */
export function outPath(url) {
  if (!url.startsWith("/")) throw new Error(`page URL must start with "/": ${url}`);
  return (url.endsWith("/") ? url + "index.html" : url).slice(1);
}

/** The Markdown mirror of a page: "/docs/spec/" -> "/docs/spec.md", "/" -> "/index.md". */
export function mirrorUrl(url) {
  if (url === "/") return "/index.md";
  return url.replace(/\/$/, "") + ".md";
}

/**
 * A link from the page at `from` to the site path `to` (which may carry ?query and #fragment), relative
 * to `from`. With `offline`, a folder link gets an explicit index.html so the files work from disk.
 */
export function relUrl(from, to, { offline = false } = {}) {
  const { path, query, fragment } = splitUrl(to);
  if (!from.startsWith("/") || !path.startsWith("/")) throw new Error(`relUrl needs site paths: ${from} -> ${to}`);
  const fromDir = from.slice(0, from.lastIndexOf("/") + 1);
  if (path === from && !query) return fragment || (offline && path.endsWith("/") ? "index.html" : "./");
  const a = fromDir.split("/").filter(Boolean);
  const b = path.split("/").filter(Boolean);
  const isDir = path.endsWith("/");
  let i = 0;
  while (i < a.length && i < b.length - (isDir ? 0 : 1) && a[i] === b[i]) i++;
  let rel = "../".repeat(a.length - i) + b.slice(i).join("/") + (isDir && b.length > i ? "/" : "");
  if (offline && isDir) rel += "index.html";
  if (rel === "") rel = "./";
  return rel + query + fragment;
}

/** Resolve a relative link found on page `from` back to a site path (the inverse of relUrl). */
export function resolveSitePath(from, href) {
  const { path, fragment } = splitUrl(href);
  if (path.startsWith("/")) return { path: normalize(path), fragment };
  const fromDir = from.slice(0, from.lastIndexOf("/") + 1);
  return { path: normalize(fromDir + path), fragment };
}

function normalize(p) {
  const trailing = p.endsWith("/") || p.endsWith("/.") || p.endsWith("/..");
  const parts = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { if (parts.length === 0) return null; parts.pop(); continue; }
    parts.push(seg);
  }
  return "/" + parts.join("/") + (trailing && parts.length ? "/" : "");
}
