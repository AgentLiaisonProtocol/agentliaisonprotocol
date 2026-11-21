// The page shell: <head>, the top bar, the docs sidebar, the footer, and the two layouts (docs and
// article). Every link it writes goes through ctx.link(), which makes it relative to the page.

import { esc } from "./html.mjs";
import { navTree, neighbours } from "./nav.mjs";
import { mirrorUrl } from "./urls.mjs";

// connect-src 'self' lets "Copy page as Markdown" fetch the page's own mirror; nothing else is fetched.
export const CSP = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'";

const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

/** "2026-11-20" -> "November 20, 2026". */
export function longDate(iso) {
  const [y, m, d] = iso.split("-").map(Number);
  return `${MONTHS[m - 1]} ${d}, ${y}`;
}

// The four-dot brand mark of the existing pages, with classes instead of inline colours.
export const BRAND_MARK = '<svg class="mark" width="34" height="20" viewBox="0 0 34 20" aria-hidden="true" focusable="false"><path class="mark-line" d="M5 10h24" stroke-width="2"/><circle class="mark-a" cx="5" cy="10" r="4.2"/><circle class="mark-b" cx="29" cy="10" r="4.2"/><path class="mark-c" d="M13.6 6.2l3.8 3.8-3.8 3.8-3.8-3.8z"/><path class="mark-c" d="M20.4 6.2l3.8 3.8-3.8 3.8-3.8-3.8z"/></svg>';

function head(page, ctx, { title, mirror }) {
  const { site } = ctx.config;
  const canonical = site.origin + page.url;
  const fullTitle = page.url === "/" ? title : `${title} · ${site.name}`;
  const lines = [
    "<!doctype html>",
    `<html lang="en"${ctx.theme === "dark" ? ' data-theme="dark"' : ""}>`,
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    ctx.offline ? null : `<meta http-equiv="Content-Security-Policy" content="${CSP}">`,
    '<meta name="color-scheme" content="light dark">',
    `<title>${esc(fullTitle)}</title>`,
    `<meta name="description" content="${esc(page.description)}">`,
    `<link rel="canonical" href="${esc(canonical)}">`,
    mirror ? `<link rel="alternate" type="text/markdown" href="${esc(ctx.link(mirror))}" title="This page as Markdown">` : null,
    `<meta property="og:type" content="${page.group ? "article" : "website"}">`,
    `<meta property="og:site_name" content="${esc(site.name)}">`,
    `<meta property="og:title" content="${esc(title)}">`,
    `<meta property="og:description" content="${esc(page.description)}">`,
    `<meta property="og:url" content="${esc(canonical)}">`,
    `<meta property="og:image" content="${esc(site.origin + site.ogImage)}">`,
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    `<meta property="og:image:alt" content="${esc(site.ogImageAlt)}">`,
    '<meta name="twitter:card" content="summary_large_image">',
    `<meta name="twitter:title" content="${esc(title)}">`,
    `<meta name="twitter:description" content="${esc(page.description)}">`,
    `<meta name="twitter:image" content="${esc(site.origin + site.ogImage)}">`,
    `<link rel="icon" href="${esc(ctx.link("/assets/favicon.svg"))}" type="image/svg+xml">`,
    `<link rel="stylesheet" href="${esc(ctx.link(ctx.assetUrl("site.css")))}">`,
    ctx.noScript ? null : `<script src="${esc(ctx.link(ctx.assetUrl("site.js")))}" defer></script>`,
    "</head>",
  ];
  return lines.filter((l) => l !== null).join("\n");
}

function topbar(page, ctx) {
  const { topLinks, site } = ctx.config;
  const items = topLinks.map((l) => {
    const href = l.url ? ctx.link(l.url) : l.href;
    // Current by the page's docs group (the changelog is in Status although its URL isn't under /docs/status/).
    const current = l.url && (page.url === l.url || (Array.isArray(l.groups) && page.group != null && l.groups.includes(page.group)));
    return `<li><a href="${esc(href)}"${current ? ' aria-current="true"' : ""}>${esc(l.title)}</a></li>`;
  }).join("");
  const pill = `<a class="pill" href="${esc(ctx.link("/docs/changelog/"))}" title="Version 0.1 is a draft for implementers; see the changelog">${esc(site.versionLabel)}</a>`;
  return `<a class="skip" href="#content">Skip to content</a>
<div class="band" aria-hidden="true"></div>
<header class="topbar">
<div class="topbar-inner">
<a class="brand" href="${esc(ctx.link("/"))}">${BRAND_MARK}<span>${esc(site.name)}</span></a>
<nav class="top-nav" aria-label="Site"><ul>${items}</ul>${pill}</nav>
<details class="top-menu"><summary><span>Menu</span></summary><nav aria-label="Site menu"><ul>${items}</ul>${pill}</nav></details>
</div>
</header>`;
}

function footer(ctx) {
  const { site, text } = ctx.config;
  return `<footer class="site-footer">
<div class="footer-inner">
<p class="disclaimer">${esc(text.disclaimer)}</p>
<p>Specification <span class="lic">CC BY 4.0</span> · schemas, vectors and tools <span class="lic">Apache-2.0</span> · reference broker <span class="lic">FSL-1.1-ALv2</span>, source-available</p>
<p><a href="${esc(site.repo)}">GitHub</a> · Security reports: <a href="mailto:${esc(site.security)}">${esc(site.security)}</a></p>
<p>${esc(text.privacy)}</p>
</div>
</footer>`;
}

function outlineHtml(outline, filter) {
  if (!outline.length) return "";
  const items = [];
  let open = false;
  for (const h of outline) {
    const a = `<a href="#${esc(h.id)}">${esc(h.text)}</a>`;
    if (h.depth === 2) {
      if (open) items.push("</ul></li>");
      items.push(`<li>${a}<ul>`);
      open = true;
    } else {
      if (!open) { items.push("<li><ul>"); open = true; }
      items.push(`<li>${a}</li>`);
    }
  }
  if (open) items.push("</ul></li>");
  const html = items.join("").replace(/<ul><\/ul>/g, "");
  const box = filter ? '<div class="toc-filter" hidden><label for="toc-filter">Filter sections</label><input id="toc-filter" type="search" autocomplete="off" spellcheck="false" placeholder="Type / to filter"></div>' : "";
  return `<div class="toc" data-toc>
<p class="toc-title" id="toc-title">On this page</p>
${box}<ul class="toc-list" aria-labelledby="toc-title">${html}</ul>
<p class="toc-empty" hidden>No section matches.</p>
</div>`;
}

function sidebar(page, ctx, outline) {
  const { pages, groups } = ctx.config;
  const tree = navTree(pages, groups);
  const li = (p, extra = "") => {
    const cur = p.url === page.url;
    return `<li${cur ? ' class="current"' : ""}><a href="${esc(ctx.link(p.url))}"${cur ? ' aria-current="page"' : ""}>${esc(p.title)}</a>${extra}${cur ? outlineHtml(outline, outline.length > 20) : ""}</li>`;
  };
  const groupsHtml = tree.map(({ group, pages: items }) => {
    // A page marked `collapse` shows its children only on itself and on them (the schema pages are many).
    const shown = (p, children) => children.length && (!p.collapse || page.url === p.url || page.parent === p.url);
    const list = items.map(({ page: p, children }) => li(p, shown(p, children) ? `<ul class="side-children">${children.map((c) => li(c)).join("")}</ul>` : "")).join("");
    return `<div class="side-group"><p class="side-title">${esc(group.title)}</p><ul>${list}</ul></div>`;
  }).join("\n");
  return `<details class="sidebar" data-sidebar>
<summary><span>Documentation</span> <span class="summary-current">${esc(page.title)}</span></summary>
<nav class="side-nav" aria-label="Documentation">
${groupsHtml}
</nav>
</details>`;
}

function pager(page, ctx) {
  const { prev, next } = neighbours(ctx.config.pages, ctx.config.groups, page);
  if (!prev && !next) return "";
  const a = (p, rel, label) => p ? `<a class="pager-${rel}" href="${esc(ctx.link(p.url))}" rel="${rel}"><span class="pager-label">${label}</span><span class="pager-title">${esc(p.title)}</span></a>` : "<span></span>";
  return `<nav class="pager" aria-label="Previous and next page">${a(prev, "prev", "Previous")}${a(next, "next", "Next")}</nav>`;
}

/**
 * Source line, last-changed date, and the two Markdown actions, shown under a docs page's title.
 * meta: { sourcePath, sourceHref, date, mirror, copy }. With `copy`, "Copy page as Markdown" fetches the
 * mirror when clicked; site.js shows the button only where that can work (a page served over HTTP).
 */
function docMeta(ctx, meta) {
  if (!meta) return "";
  const parts = [];
  if (meta.sourcePath) parts.push(`<span>Source: <a href="${esc(meta.sourceHref)}"><code>${esc(meta.sourcePath)}</code></a></span>`);
  if (meta.date) parts.push(`<span>Last changed <time datetime="${meta.date}">${longDate(meta.date)}</time></span>`);
  const actions = [];
  if (meta.mirror) actions.push(`<a href="${esc(ctx.link(meta.mirror))}">View as Markdown</a>`);
  if (meta.copy && meta.mirror) actions.push(`<button type="button" class="copy-page" data-copy-page="${esc(ctx.link(meta.mirror))}" hidden>Copy page as Markdown</button>`);
  return `<div class="doc-meta">${parts.join("")}${actions.length ? `<span class="doc-actions">${actions.join("")}</span>` : ""}</div>`;
}

/**
 * A docs page. parts: { title (for <head>), h1 (HTML of the h1 element), notice (HTML), meta, body,
 * outline: [{ depth, id, text }], mirror (site path of the .md mirror or null), wide (bool) }
 */
export function docsPage(page, ctx, parts) {
  const h1 = parts.h1 || `<h1 id="top">${esc(page.title)}</h1>`;
  return `${head(page, ctx, { title: parts.title || page.title, mirror: parts.mirror })}
<body class="docs">
${topbar(page, ctx)}
<div class="docs-layout">
${sidebar(page, ctx, parts.outline || [])}
<main id="content" class="doc" tabindex="-1">
<article>
<header class="doc-head">
${h1}
${docMeta(ctx, parts.meta)}
${parts.notice || ""}
</header>
<div class="prose">
${parts.body || ""}
</div>
</article>
${pager(page, ctx)}
</main>
</div>
${footer(ctx)}
</body>
</html>
`;
}

/** An article page (the 720 px column; `wide` blocks can use .wide). parts: { title, body, mirror } */
export function articlePage(page, ctx, parts) {
  return `${head(page, ctx, { title: parts.title || page.title, mirror: parts.mirror })}
<body class="article-page">
${topbar(page, ctx)}
<main id="content" class="article" tabindex="-1">
${parts.body}
</main>
${footer(ctx)}
</body>
</html>
`;
}

export { mirrorUrl };
