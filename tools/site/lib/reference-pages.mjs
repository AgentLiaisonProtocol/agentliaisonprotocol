// The kinds of page that are generated from the repository's schemas, vectors and specification:
//   schema, scope, tools, rest   one page for one file under schemas/
//   schemas-index                the index of those pages
//   vectors                      vectors/README.md with a generated index of the vector files
//   glossary                     the terms of specification Section 2, then the hand-written terms of
//                                options.append (a Markdown file under site/pages/)
//   roadmap                      the items of specification Section 19 ("Future work")
//   reference-index              the reference landing page
// Each returns the record the page kinds of lib/pages.mjs return, plus `coverage` (the keywords it accounted
// for, which test/reference.test.mjs checks against an independent walk of the file).

import fs from "node:fs";
import path from "node:path";
import { esc } from "./html.mjs";
import { docsPage } from "./shell.mjs";
import { lastChanged } from "./git.mjs";
import { headingsOf } from "./headings.mjs";
import { analyzeMarkdown, renderMarkdown, rewriteMarkdownLinks } from "./markdown.mjs";
import { mirrorUrl } from "./urls.mjs";
import { linkWriters, repoMarkdown } from "./pages.mjs";
import { requirementCounts, vectorCaseCount } from "./counts.mjs";
import {
  appendixBRows, glossaryMarkdown, glossaryTerms, loadSchemaFiles, makeResolver, outlineOf, restPage, schemaPage, schemasIndex, scopePage, toolsPage,
  vectorsIndex,
} from "./reference.mjs";

const heading = (level, id, inner) => `<h${level} id="${esc(id)}">${inner}<a class="anchor" href="#${esc(id)}" aria-label="Link to this section">#</a></h${level}>`;

/** Per-build data shared by the reference pages. */
function data(env) {
  if (env.referenceData) return env.referenceData;
  const files = loadSchemaFiles(env.root);
  const filePages = env.config.pages.filter((p) => p.options?.file);
  const urlFor = new Map(filePages.map((p) => [p.options.file, p.url]));
  for (const f of files) if (!urlFor.has(f.rel)) env.problems.push(`${f.rel}: has no page in site.config.mjs (every file under schemas/ needs one)`);
  for (const [file, url] of urlFor) if (!files.some((f) => f.rel === file)) env.problems.push(`site.config.mjs page ${url}: ${file} doesn't exist`);
  env.referenceData = { files, filePages, urlFor };
  return env.referenceData;
}

const sourceUrl = (env, rel) => `${env.config.site.repo}/blob/${env.config.site.branch}/${rel}`;
const servedAt = (env, rel) => env.config.site.origin + "/" + rel;

function fileRecord(page, env, file, built, extra = {}) {
  const pctx = env.pageCtx(page);
  const date = lastChanged(env.root, file.rel);
  for (const m of built.problems) env.problems.push(`${page.url}: ${m}`);
  env.coverage ??= new Map();
  env.coverage.set(page.url, { file: file.rel, cov: built.cov });
  const html = docsPage(page, pctx, {
    body: built.body,
    outline: built.outline,
    meta: { sourcePath: file.rel, sourceHref: sourceUrl(env, file.rel), date },
    ...extra,
  });
  return { html, mirror: null, outline: built.outline, expect: null, date, sourceText: null, rawUrl: "/" + file.rel };
}

function resolverFor(page, env, file) {
  const { files, urlFor } = data(env);
  const pctx = env.pageCtx(page);
  return makeResolver({ files, pageUrlFor: (rel) => urlFor.get(rel), currentFile: file.rel, link: (u) => pctx.link(u) });
}

function schemaKind(page, env) {
  const file = data(env).files.find((f) => f.rel === page.options.file);
  const built = schemaPage({ file, resolveRef: resolverFor(page, env, file), servedAt: servedAt(env, file.rel) });
  return fileRecord(page, env, file, built);
}

function scopeKind(page, env) {
  const file = data(env).files.find((f) => f.rel === page.options.file);
  const pctx = env.pageCtx(page);
  const built = scopePage({ file, resolveRef: resolverFor(page, env, file), servedAt: servedAt(env, file.rel), link: (u) => pctx.link(u) });
  return fileRecord(page, env, file, built);
}

function toolsKind(page, env) {
  const file = data(env).files.find((f) => f.rel === page.options.file);
  const pctx = env.pageCtx(page);
  const rest = env.config.pages.find((p) => p.kind === "rest");
  const built = toolsPage({ file, resolveRef: resolverFor(page, env, file), servedAt: servedAt(env, file.rel), restLink: rest ? pctx.link(rest.url) : null });
  return fileRecord(page, env, file, built);
}

function restKind(page, env) {
  const { files } = data(env);
  const file = files.find((f) => f.rel === page.options.file);
  const toolsPageEntry = env.config.pages.find((p) => p.kind === "tools");
  const toolsFile = toolsPageEntry ? files.find((f) => f.rel === toolsPageEntry.options.file) : null;
  const pctx = env.pageCtx(page);
  const markdown = (md) => {
    const r = renderMarkdown(md, {
      file: `${file.rel} (info.description)`,
      resolveHref: (h) => h,
      sectionRefs: { mode: "other", hrefFor: (n) => (env.specIds.has(n) ? `${pctx.link("/docs/spec/")}#${env.specIds.get(n)}` : null) },
      maturity: null,
      figureFor: () => null,
      problems: env.problems,
    });
    return r.body;
  };
  const built = restPage({
    file, tools: toolsFile ? toolsFile.json : null, resolveRef: resolverFor(page, env, file), servedAt: servedAt(env, file.rel),
    toolsLink: toolsPageEntry ? pctx.link(toolsPageEntry.url) : null, markdown,
  });
  return fileRecord(page, env, file, built);
}

function schemasIndexKind(page, env) {
  const pctx = env.pageCtx(page);
  const { files, filePages } = data(env);
  const entries = filePages
    .slice()
    .sort((a, b) => (a.options.file < b.options.file ? -1 : 1))
    .map((p) => {
      const f = files.find((x) => x.rel === p.options.file);
      const title = typeof f.json.title === "string" ? f.json.title : p.title;
      return { rel: f.rel, title, url: p.url };
    });
  const { html: table, problems } = schemasIndex({ entries, rows: appendixBRows(env.specText), link: (u) => pctx.link(u) });
  for (const m of problems) env.problems.push(`${page.url}: ${m}`);
  const body = `<p>Every JSON Schema of the specification has a page here: its members and their constraints, its definitions, and the file itself. The files are served as they are in the repository, under <a href="${esc(pctx.link("/schemas/envelope.schema.json"))}"><code>/schemas/</code></a>. A schema's <code>$id</code> is a <code>tag:</code> URI. It names the schema; it is not a web address, and this site leaves it as it is. The Defines column is the specification's <a href="${esc(pctx.link("/docs/spec/#appendix-b-schema-and-vector-index"))}">Appendix B</a>.</p>
${heading(2, "files", "Files")}
${table}
<p>The tools and the REST mirror are listed with the others because they are files under <code>schemas/</code>; their pages are <a href="${esc(pctx.link("/docs/reference/tools/"))}">Client tools</a> and <a href="${esc(pctx.link("/docs/reference/rest/"))}">REST mirror</a>.</p>`;
  const outline = outlineOf(body);
  return {
    html: docsPage(page, pctx, { body, outline, meta: { sourcePath: "schemas/", sourceHref: `${env.config.site.repo}/tree/${env.config.site.branch}/schemas` } }),
    mirror: null, outline, expect: null, date: null, sourceText: null,
  };
}

function vectorsKind(page, env) {
  const readme = fs.readFileSync(path.join(env.root, page.source), "utf8");
  const { site } = env.config;
  const pctx = env.pageCtx(page);
  // The index as HTML for the page (links relative) and as Markdown for the mirror (absolute links).
  const idx = vectorsIndex({
    root: env.root, readme, notes: env.config.vectorNotes,
    hrefHtml: (rel, keys) => (keys ? `${site.repo}/blob/${site.branch}/vectors/${rel}` : pctx.link(`/vectors/${rel}`)),
    hrefMd: (rel, keys) => (keys ? `${site.repo}/blob/${site.branch}/vectors/${rel}` : `${site.origin}/vectors/${rel}`),
  });
  for (const m of idx.problems) env.problems.push(`${page.url}: ${m}`);
  const htmlTable = idx.html;
  const intro = `<p>The vector files are served as they are in the repository, under <code>/vectors/</code>. ${idx.caseFiles} files of cases hold ${idx.totalCases} cases, counted from the files when the site is built: the entries of each file's top-level arrays, and one for a file that holds a single scenario. <code>world.json</code> is the shared fixture. The TEST-ONLY private keys are linked on GitHub, not served from this site.</p>`;
  const html = `${heading(2, "index-with-case-counts", "Index with case counts")}${intro}${htmlTable}`;
  const md = `\n\n## Index with case counts\n\n${idx.md}\n`;
  return repoMarkdown(page, env, {
    md: readme, sourcePath: page.source, ref: "main", date: lastChanged(env.root, page.source), spec: null,
    append: { html, md, headings: 1, tables: 1, code: 0, outline: [{ depth: 2, id: "index-with-case-counts", text: "Index with case counts" }] },
  });
}

function glossaryKind(page, env) {
  const pctx = env.pageCtx(page);
  const terms = glossaryTerms(env.specText);
  // Terms the site uses that Section 2 doesn't define: a hand-written Markdown file, rendered after the
  // generated terms (one rendering, so heading ids stay unique), its links resolved like a document's.
  const extraFile = page.options?.append || null;
  const extra = extraFile ? fs.readFileSync(path.join(env.root, extraFile), "utf8") : "";
  const links = extraFile ? linkWriters(page, env, extraFile, "main") : null;
  const md = glossaryMarkdown(terms) + (extra ? `\n${extra}` : "");
  const r = renderMarkdown(md, {
    file: extraFile ? `spec/alp-v0.1.md (Section 2) and ${extraFile}` : "spec/alp-v0.1.md (Section 2)",
    resolveHref: links ? links.html : (h) => h,
    sectionRefs: { mode: "spec", hrefFor: (n) => (env.specIds.has(n) ? `${pctx.link("/docs/spec/")}#${env.specIds.get(n)}` : null) },
    maturity: null,
    figureFor: () => null,
    problems: env.problems,
  });
  const intro = `<p>The terms the specification defines in its <a href="${esc(pctx.link("/docs/spec/#2-terminology"))}">Section 2</a>, in alphabetical order. The definitions are the specification's own words.${extra ? ` <a href="#other-terms-used-on-this-site">Other terms used on this site</a> follow them.` : ""}</p>`;
  const outline = r.headings.filter((h) => h.depth === 2 || h.depth === 3);
  const mirrorMd = links ? rewriteMarkdownLinks(md, (d) => links.md(d)) : md;
  const mirror = { url: mirrorUrl(page.url), text: `# ${page.title}\n\nThe terms the specification defines in its Section 2 (${env.config.site.origin}/docs/spec/#2-terminology), in alphabetical order.\n\n${mirrorMd}` };
  const date = lastChanged(env.root, "spec/alp-v0.1.md");
  return {
    html: docsPage(page, pctx, {
      body: intro + r.body, outline, mirror: mirror.url,
      meta: { sourcePath: "spec/alp-v0.1.md", sourceHref: `${env.config.site.repo}/blob/${env.config.site.branch}/spec/alp-v0.1.md`, date, mirror: mirror.url, copy: true },
    }),
    mirror, outline,
    expect: { headings: terms.length + 1 + (extra ? analyzeMarkdown(extra).counts.headings : 0), tables: 0, code: 0, mermaid: 0 },
    date,
    sourceText: glossarySource(env.specText),
  };
}

/**
 * The roadmap: the items of specification Section 19 ("Future work"), each by its own lead-in words, linked to
 * the section; the section's own maturity line first; then a pointer to the known gaps. Nothing is added to
 * the items, and the build fails when the section or its list can't be found.
 */
function roadmapKind(page, env) {
  const pctx = env.pageCtx(page);
  const spec = env.specText;
  const start = spec.indexOf("\n## 19. Future work");
  const end = start === -1 ? -1 : spec.indexOf("\n## ", start + 5);
  const id = env.specIds.get("19");
  if (start === -1 || end === -1 || !id) {
    env.problems.push(`${page.url}: specification Section 19 ("Future work") not found`);
    return { html: docsPage(page, pctx, { body: "" }), mirror: null, outline: [], expect: null, date: null, sourceText: null };
  }
  const section = spec.slice(start, end);
  const maturity = /^\*(Maturity: [^*]+)\*$/m.exec(section);
  const items = [...section.matchAll(/^- \*\*(.+?)\*\*(.*)$/gm)].map((m) => ({ lead: m[1], rest: m[2] }));
  if (!maturity) env.problems.push(`${page.url}: specification Section 19 has no maturity line`);
  if (!items.length) env.problems.push(`${page.url}: specification Section 19 has no list of items`);
  const listMd = items.map((it) => `- **${it.lead}**${it.rest}`).join("\n");
  const r = renderMarkdown(listMd, {
    file: "spec/alp-v0.1.md (Section 19)",
    resolveHref: (h) => h,
    sectionRefs: { mode: "spec", hrefFor: (n) => (env.specIds.has(n) ? `${pctx.link("/docs/spec/")}#${env.specIds.get(n)}` : null) },
    maturity: null,
    figureFor: () => null,
    problems: env.problems,
  });
  const secHref = `${pctx.link("/docs/spec/")}#${id}`;
  // Each item's lead-in words link to its place in the specification.
  const list = r.body.replace(/<li><strong>([\s\S]*?)<\/strong>/g, (_m, lead) => `<li><a href="${esc(secHref)}"><strong>${lead}</strong></a>`);
  const label = maturity ? maturity[1] : "";
  const word = (/^Maturity: (\w+)/.exec(label) || [])[1]?.toLowerCase() || "future";
  const gaps = pctx.link("/docs/status/known-gaps/");
  const body = `<p><span class="maturity maturity-${esc(word)}">${esc(label)}</span></p>
<p>The specification’s <a href="${esc(secHref)}">Section 19, Future work</a>, lists what is planned for version 0.2 or later, so implementers can see where the protocol is heading. Nothing here has a delivery date.</p>
${list}
<p>What isn’t built yet in version 0.1 and its reference broker is in <a href="${esc(gaps)}">Known gaps</a>, listed so that implementers and operators can plan around them. They are candidates for later versions, and none has a delivery date.</p>`;
  const o = env.config.site.origin;
  const mirror = { url: mirrorUrl(page.url), text: `# ${page.title}\n\n${label}\n\nThe specification’s Section 19, Future work (${o}/docs/spec/#${id}), lists what is planned for version 0.2 or later, so implementers can see where the protocol is heading. Nothing here has a delivery date.\n\n${listMd}\n\nWhat isn’t built yet in version 0.1 and its reference broker is in Known gaps (${o}/docs/status/known-gaps/), listed so that implementers and operators can plan around them. They are candidates for later versions, and none has a delivery date.\n` };
  const date = lastChanged(env.root, "spec/alp-v0.1.md");
  return {
    html: docsPage(page, pctx, {
      body, mirror: mirror.url,
      meta: { sourcePath: "spec/alp-v0.1.md", sourceHref: sourceUrl(env, "spec/alp-v0.1.md"), date, mirror: mirror.url, copy: true },
    }),
    mirror, outline: [], expect: null, date, sourceText: section,
  };
}

function glossarySource(specMd) {
  const start = specMd.indexOf("\n## 2. Terminology");
  return specMd.slice(start, specMd.indexOf("\n---", start));
}

const CLASS_ROWS = [["13.3", "BC"], ["13.4", "OB"], ["13.5", "HB"], ["13.6", "NC"], ["13.7", "PB"], ["13.8", "CD"]];

function referenceIndexKind(page, env) {
  const pctx = env.pageCtx(page);
  const heads = headingsOf(env.specText);
  const byNumber = new Map(heads.filter((h) => h.number).map((h) => [h.number, h]));
  const req = requirementCounts(env.specText);
  const own = env.config.pages.filter((p) => p.group === "reference" && p.url !== page.url && !p.parent).sort((a, b) => a.order - b.order);
  const list = own.map((p) => `<li><a class="guide-title" href="${esc(pctx.link(p.url))}">${esc(p.title)}</a><p>${esc(p.description)}</p></li>`).join("\n");
  const specLink = (n) => `${pctx.link("/docs/spec/")}#${byNumber.get(n).id}`;
  const classRows = CLASS_ROWS.map(([n, cls]) => {
    const h = byNumber.get(n);
    return `<tr><td><a href="${esc(specLink(n))}">${esc(h.text.replace(/^\d+(?:\.\d+)*\s+/, ""))}</a></td><td><code>${cls}-1</code> to <code>${cls}-${req[cls]}</code></td><td>${req[cls]}</td></tr>`;
  }).join("");
  const total = Object.values(req).reduce((a, b) => a + b, 0);
  const registries = [...byNumber.values()].filter((h) => /^18\.\d+$/.test(h.number)).map((h) => `<li><a href="${esc(specLink(h.number))}">${esc(h.text)}</a></li>`).join("");
  const body = `<p>${esc(page.description)}</p>
<ul class="guide-list">
${list}
</ul>
${heading(2, "in-the-specification", "In the specification")}
${heading(3, "conformance-classes", "Conformance classes")}
<p>An implementation claims one or more classes, names the protocol version, and passes the vectors that apply to it (<a href="${esc(specLink("13"))}">Section 13</a>). The classes hold ${total} numbered requirements.</p>
<div class="table-wrap" tabindex="0" role="region" aria-label="Conformance classes">
<table><thead><tr><th>Class</th><th>Requirement ids</th><th>Requirements</th></tr></thead><tbody>${classRows}</tbody></table>
</div>
${heading(3, "registries", "Registries")}
<p>The specification's <a href="${esc(specLink("18"))}">Section 18</a> holds the registries.</p>
<ul>${registries}</ul>`;
  const outline = outlineOf(body);
  return { html: docsPage(page, pctx, { body, outline }), mirror: null, outline, expect: null, date: null, sourceText: null };
}

export const REFERENCE_KINDS = {
  schema: schemaKind,
  scope: scopeKind,
  tools: toolsKind,
  rest: restKind,
  "schemas-index": schemasIndexKind,
  vectors: vectorsKind,
  glossary: glossaryKind,
  roadmap: roadmapKind,
  "reference-index": referenceIndexKind,
};

export { rewriteMarkdownLinks, vectorCaseCount };
