// How each kind of page is made. A kind is a function (page, env) -> record:
//   { html, mirror: { url, text } | null, outline, expect: { headings, tables, code } | null,
//     date, sourceText (for the wording check) | null,
//     codeBlocks: { file, blocks } | null (the source's fenced blocks, lib/fences.mjs, for check 4) }
// A new kind is a function here, registered in KINDS at the bottom.

import fs from "node:fs";
import path from "node:path";
import { esc, textContent } from "./html.mjs";
import { analyzeMarkdown, renderMarkdown, rewriteMarkdownLinks, sha256 } from "./markdown.mjs";
import { fencedBlocks } from "./fences.mjs";
import { extractExamples, stripExampleMarkers } from "./examples.mjs";
import { resolveLink } from "./links.mjs";
import { parseFrontMatter } from "./frontmatter.mjs";
import { articlePage, docsPage, longDate } from "./shell.mjs";
import { headingsOf, sectionIds } from "./headings.mjs";
import { applyCounts } from "./counts.mjs";
import { lastChanged, showAt } from "./git.mjs";
import { mirrorUrl } from "./urls.mjs";
import { renderWalkthroughs } from "./walkthrough.mjs";
import { walkthroughs } from "../../../site/walkthroughs.mjs";

function figureHtml(env, mermaid) {
  const sha = sha256(mermaid);
  const fig = env.config.figures.find((f) => f.mermaidSha256 === sha);
  if (!fig) return null;
  const svg = fs.readFileSync(path.join(env.root, fig.file), "utf8").trim();
  return {
    html: `<figure class="figure figure-diagram" id="figure-${esc(fig.name)}">
<div class="figure-scroll" tabindex="0" role="group" aria-label="Figure: scroll sideways to see all of it">
${svg}
</div>
<figcaption>${esc(fig.caption)}</figcaption>
</figure>`,
  };
}

/** The link writer for a page: repository links per resolveLink, made relative (HTML) or absolute (mirror). */
export function linkWriters(page, env, sourcePath, ref) {
  const { site } = env.config;
  const linkEnv = { site, pageForSource: env.pageForSource, exists: (p) => env.exists(p, ref), ref };
  const file = ref === "main" ? sourcePath : `${sourcePath} at ${ref.slice(0, 7)}`;
  const resolve = (href) => {
    const r = resolveLink(href, sourcePath, linkEnv);
    if (r.problem) env.problems.push(`${file}: ${r.problem}`);
    if (r.kind === "repo" && r.missing) env.problems.push(`${file}: link ${href} points to ${r.repoPath}, which doesn't exist${ref === "main" ? "" : " at that commit"}`);
    if (r.kind === "repo" && r.fragment && env.repoAnchors) env.repoFragmentLinks.push({ from: file, href, repoPath: r.repoPath, fragment: r.fragment, ref });
    return r;
  };
  return {
    html: (href) => {
      const r = resolve(href);
      if (r.kind === "same") return r.fragment;
      if (r.kind === "page") return env.pageCtx(page).link(r.url + r.fragment);
      return r.href;
    },
    md: (href) => {
      const r = resolve(href);
      if (r.kind === "same") return r.fragment;
      if (r.kind === "page") return site.origin + r.url + r.fragment;
      return r.href;
    },
  };
}

/** A page rendered from a repository Markdown document (at the working tree, or at a commit). */
export function repoMarkdown(page, env, { md, sourcePath, ref, date, spec, append = null }) {
  const { site } = env.config;
  const problems = env.problems;
  const file = ref === "main" ? sourcePath : `${sourcePath} at ${ref.slice(0, 7)}`;
  const pctx = env.pageCtx(page);

  // Only the specification has example markers. They are read, then removed from the page and its mirror
  // (they mean nothing to a reader). In any other document the same text is kept as written.
  if (spec) extractExamples(md, file); // a malformed example fails here, before anything renders
  const stripped = spec ? stripExampleMarkers(md) : md;
  const facts = analyzeMarkdown(stripped);
  const allow = new Set(page.options?.allowRawHtml || []);
  for (const h of facts.html) {
    if (!allow.has(h.text)) problems.push(`${file}:${h.line}: raw HTML or an HTML comment outside code (${h.text.slice(0, 60)}); allow it for this file in site.config.mjs (options.allowRawHtml) only if it is meant as text`);
  }

  const links = linkWriters(page, env, sourcePath, ref);
  let sectionRefs;
  if (spec) {
    const ids = sectionIds(stripped);
    sectionRefs = { mode: "spec", hrefFor: (n) => (ids.has(n) ? `#${ids.get(n)}` : null) };
  } else {
    sectionRefs = { mode: "other", hrefFor: (n) => (env.specIds.has(n) ? `${pctx.link("/docs/spec/")}#${env.specIds.get(n)}` : null) };
  }

  // Both specification pages show each section's own maturity line as a label (only the working text's
  // lines are listed by --report).
  const r = renderMarkdown(stripped, { file, resolveHref: links.html, sectionRefs, maturity: Boolean(spec), figureFor: (m) => figureHtml(env, m), problems });
  if (spec === "working") env.report.maturity = r.maturityLines;
  const mirror = { url: mirrorUrl(page.url), text: rewriteMarkdownLinks(stripped, (dest) => links.md(dest)) + (append ? append.md : "") };
  const sourceHref = `${site.repo}/blob/${ref === "main" ? site.branch : ref}/${sourcePath}`;

  let notice = "";
  if (spec === "working") {
    notice = `<p class="notice">Working text. It includes the changes listed under 0.1.1 (unreleased) in the <a href="${esc(pctx.link("/docs/changelog/#011---unreleased"))}">changelog</a>. <a href="${esc(pctx.link("/docs/0.1/spec/"))}">Version 0.1.0 as first published</a> is also available.</p>`;
  } else if (spec === "published") {
    notice = `<p class="notice">Version 0.1.0 as first published (commit <code>${esc(site.published.commit.slice(0, 7))}</code>). The <a href="${esc(pctx.link("/docs/changelog/#010---2026-11-09-draft-for-implementers"))}">changelog</a> dates it ${esc(site.published.dateText)}. The <a href="${esc(pctx.link("/docs/spec/"))}">working text</a> has later changes.</p>`;
  }

  const outline = [...r.headings.filter((h) => h.depth === 2 || h.depth === 3), ...(append ? append.outline : [])];
  // A document outside the docs (the announcement) uses the article layout, with an optional notice above
  // its title (options.notice: HTML whose links are site paths).
  if (page.layout === "article") {
    const top = page.options?.notice ? `<p class="notice article-notice">${relinkFragment(page.options.notice, pctx)}</p>\n` : "";
    return {
      html: articlePage(page, pctx, { body: `<div class="wrap prose article-body">\n${top}${r.h1 || ""}\n${r.body}\n</div>`, mirror: mirror.url }),
      mirror,
      outline,
      expect: { headings: facts.counts.headings, tables: facts.counts.tables, code: facts.counts.code, mermaid: facts.counts.mermaid },
      date,
      sourceText: md,
      codeBlocks: { file, blocks: fencedBlocks(stripped) },
    };
  }
  const html = docsPage(page, pctx, {
    h1: r.h1,
    notice,
    meta: { sourcePath, sourceHref, date, mirror: mirror.url, copy: true },
    body: r.body + (append ? append.html : ""),
    outline,
    mirror: mirror.url,
  });
  return {
    html,
    mirror,
    outline,
    expect: { headings: facts.counts.headings + (append?.headings || 0), tables: facts.counts.tables + (append?.tables || 0), code: facts.counts.code + (append?.code || 0), mermaid: facts.counts.mermaid },
    date,
    sourceText: md,
    codeBlocks: { file, blocks: fencedBlocks(stripped) },
  };
}

function markdownKind(page, env) {
  const md = fs.readFileSync(path.join(env.root, page.source), "utf8");
  const spec = page.options?.spec || null;
  return repoMarkdown(page, env, { md, sourcePath: page.source, ref: "main", date: lastChanged(env.root, page.source), spec });
}

function specPublishedKind(page, env) {
  const { commit } = env.config.site.published;
  const md = showAt(env.root, commit, page.source);
  if (md === null) {
    env.problems.push(`${page.url}: can't read ${page.source} at ${commit} (is the git history there? CI needs fetch-depth: 0)`);
    return { html: docsPage(page, env.pageCtx(page), { body: "" }), mirror: null, outline: [], expect: null, date: null, sourceText: null };
  }
  // No "Last changed" date: the commit's date and the changelog's date differ, and the notice gives the latter.
  return repoMarkdown(page, env, { md, sourcePath: page.source, ref: commit, date: null, spec: "published" });
}

/** Rewrite site paths ("/docs/...") in a hand-written HTML fragment into links relative to the page. */
function relinkFragment(html, pctx) {
  return html.replace(/\b(href|src)="(\/[^"]*)"/g, (_m, attr, p) => `${attr}="${esc(pctx.link(p.replace(/&amp;/g, "&")))}"`);
}

/**
 * Placeholders a hand-written page may use, besides {{count:name}}: {{include:file}} (a file next to the page,
 * as it is, for example inside a code fence of a Markdown page), and in an HTML fragment {{figure:name}}
 * (site/figures/name.svg, inline) and {{walkthrough}} (every scenario of site/walkthroughs.mjs) or
 * {{walkthrough:id}} (one scenario). On a docs page a scenario's title is an h2, on an article page an h3.
 * An unknown placeholder, scenario or a missing file is a build problem.
 */
function applyIncludes(body, page, env, pctx) {
  const dir = path.dirname(page.source);
  const layout = page.layout || (page.group ? "docs" : "article");
  return body.replace(/\{\{(include|figure):([A-Za-z0-9._-]+)\}\}|\{\{walkthrough(?::([a-z0-9-]+))?\}\}/g, (m, kind, name, only) => {
    if (m.startsWith("{{walkthrough")) {
      if (!page.source.endsWith(".html")) { env.problems.push(`${page.source}: {{walkthrough}} works only in an HTML fragment`); return ""; }
      const list = only ? walkthroughs.filter((w) => w.id === only) : walkthroughs;
      if (!list.length) { env.problems.push(`${page.source}: ${m} names no scenario of site/walkthroughs.mjs`); return ""; }
      return renderWalkthroughs(list, env, pctx, page.url, { level: layout === "docs" ? 2 : 3 });
    }
    const file = kind === "include" ? path.join(dir, name) : path.join("site/figures", `${name}.svg`);
    try {
      const text = fs.readFileSync(path.join(env.root, file), "utf8");
      return kind === "include" ? text.replace(/\n$/, "") : text.trim();
    } catch {
      env.problems.push(`${page.source}: ${m} names ${file}, which doesn't exist`);
      return "";
    }
  });
}

/** A hand-written page in site/pages: Markdown or an HTML fragment, each with front matter. */
function pageKind(page, env) {
  const src = fs.readFileSync(path.join(env.root, page.source), "utf8");
  const parsed = parseFrontMatter(src, page.source);
  const data = parsed.data;
  const pctx = env.pageCtx(page);
  // {{count:name}} placeholders (lib/counts.mjs) are replaced before the body is read as Markdown or HTML.
  const body = applyIncludes(applyCounts(parsed.body, env.counts, page.source, env.problems), page, env, pctx);
  const layout = page.layout || (page.group ? "docs" : "article");
  for (const name of [].concat(data.examples || [])) env.useExample(page.url, name);
  if (page.source.endsWith(".html")) {
    const html = relinkFragment(body, pctx);
    // A docs page's outline: its h2 elements that have an id.
    const outline = layout === "docs" ? [...html.matchAll(/<h2\b[^>]*\bid="([^"]+)"[^>]*>([\s\S]*?)<\/h2>/g)].map((m) => ({ depth: 2, id: m[1], text: textContent(m[2]).trim() })) : [];
    const out = layout === "docs" ? docsPage(page, pctx, { body: html, outline, meta: { date: lastChanged(env.root, page.source) } }) : articlePage(page, pctx, { body: html });
    return { html: out, mirror: null, outline, expect: null, date: lastChanged(env.root, page.source), sourceText: null };
  }
  const facts = analyzeMarkdown(body);
  for (const h of facts.html) env.problems.push(`${page.source}:${h.line}: raw HTML or an HTML comment outside code (${h.text.slice(0, 60)})`);
  // In a hand-written page, a link that starts with "/" is a path on this site (check 1 makes sure it
  // exists); any other relative link is a repository path, resolved like a document's.
  const repoLinks = linkWriters(page, env, page.source, "main");
  const links = {
    html: (href) => (href.startsWith("/") && !href.startsWith("//") ? pctx.link(href) : repoLinks.html(href)),
    md: (href) => (href.startsWith("/") && !href.startsWith("//") ? env.config.site.origin + href : repoLinks.md(href)),
  };
  const sectionRefs = { mode: "other", hrefFor: (n) => (env.specIds.has(n) ? `${pctx.link("/docs/spec/")}#${env.specIds.get(n)}` : null) };
  const r = renderMarkdown(body, { file: page.source, resolveHref: links.html, sectionRefs, maturity: null, figureFor: (m) => figureHtml(env, m), problems: env.problems });
  const mirror = { url: mirrorUrl(page.url), text: rewriteMarkdownLinks(body, (d) => links.md(d)) };
  const outline = r.headings.filter((h) => h.depth === 2 || h.depth === 3);
  const date = lastChanged(env.root, page.source);
  const out = layout === "docs"
    ? docsPage(page, pctx, { h1: r.h1, body: r.body, outline, mirror: mirror.url, meta: { date, mirror: mirror.url, copy: true } })
    : articlePage(page, pctx, { body: `<div class="wrap prose">${r.h1 || ""}${r.body}</div>`, mirror: mirror.url });
  // sourceText stays null: a hand-written page is not a source document, so the wording check allows it
  // no "PAP" and no "open source" at all.
  return { html: out, mirror, outline, expect: { ...facts.counts }, date, sourceText: null, codeBlocks: { file: page.source, blocks: fencedBlocks(body) } };
}

/** The guides index: each guide in the manifest with its description. */
function guidesIndexKind(page, env) {
  const pctx = env.pageCtx(page);
  const { pages } = env.config;
  const guides = pages.filter((p) => p.group === "guides" && p.url !== page.url && !p.parent).sort((a, b) => a.order - b.order);
  const childrenOf = (p) => pages.filter((c) => c.parent === p.url).sort((a, b) => a.order - b.order);
  const body = `<p>${esc(page.description)}</p>
<ul class="guide-list">
${guides.map((g) => {
    const kids = childrenOf(g);
    return `<li><a class="guide-title" href="${esc(pctx.link(g.url))}">${esc(g.title)}</a><p>${esc(g.description)}</p>${kids.length ? `<ul class="guide-children">${kids.map((k) => `<li><a href="${esc(pctx.link(k.url))}">${esc(k.title)}</a> <span class="guide-desc">${esc(k.description)}</span></li>`).join("")}</ul>` : ""}</li>`;
  }).join("\n")}
</ul>`;
  const md = `# ${page.title}\n\n${page.description}\n\n${guides.map((g) => {
    const kids = childrenOf(g);
    return `- [${g.title}](${env.config.site.origin}${g.url}): ${g.description}${kids.map((k) => `\n  - [${k.title}](${env.config.site.origin}${k.url}): ${k.description}`).join("")}`;
  }).join("\n")}\n`;
  const mirror = { url: mirrorUrl(page.url), text: md };
  return { html: docsPage(page, pctx, { body, mirror: mirror.url, meta: { mirror: mirror.url, copy: true } }), mirror, outline: [], expect: null, date: null, sourceText: null };
}

export const KINDS = {
  markdown: markdownKind,
  "spec-published": specPublishedKind,
  page: pageKind,
  "guides-index": guidesIndexKind,
};

export { longDate, headingsOf, sectionIds };
