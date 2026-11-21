#!/usr/bin/env node
// Builds agentliaisonprotocol.org from the repository's own files, then checks the result.
//
//   node tools/site/build.mjs                 build into _site/ at the repository root, then run every check
//   node tools/site/build.mjs --out <dir>     build into <dir> instead
//   node tools/site/build.mjs --check         build into a temporary folder and only report
//   node tools/site/build.mjs --offline       for previews opened from disk: folder links end in index.html,
//                                             and the Content-Security-Policy tag is left out (never deployed)
//   node tools/site/build.mjs --theme dark    preview only: data-theme="dark" on every page
//   node tools/site/build.mjs --no-script     preview only: pages without site.js (to see the plain view)
//   node tools/site/build.mjs --report        also print the derived maturity labels and the wording notes
//
// Exits non-zero when any check fails. See tools/site/README.md.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import * as config from "./site.config.mjs";
import { KINDS, headingsOf, sectionIds } from "./lib/pages.mjs";
import { REFERENCE_KINDS } from "./lib/reference-pages.mjs";
import { computeCounts, filesUnder } from "./lib/counts.mjs";
import { validateManifest, navTree } from "./lib/nav.mjs";
import { outPath, relUrl } from "./lib/urls.mjs";
import { extractExamples } from "./lib/examples.mjs";
import { treeAt } from "./lib/git.mjs";
import { runChecks } from "./lib/checks.mjs";
import { llmsTxt, robotsTxt, sitemapXml } from "./lib/outputs.mjs";

const ALL_KINDS = { ...KINDS, ...REFERENCE_KINDS };

/** The raw files the site serves as they are: [{ from (repository path), to (site path) }]. */
export function rawFileList(root) {
  const out = [];
  for (const r of config.rawFiles) {
    for (const f of filesUnder(root, r.from)) {
      if (!f.endsWith(r.ext) || r.exclude.includes(f)) continue;
      out.push({ from: f, to: r.to + f.slice(r.from.length) });
    }
  }
  return out;
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..");

function parseArgs(argv) {
  const o = { out: null, check: false, offline: false, theme: null, noScript: false, report: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") o.out = argv[++i];
    else if (a === "--check") o.check = true;
    else if (a === "--offline") o.offline = true;
    else if (a === "--theme") o.theme = argv[++i];
    else if (a === "--no-script") o.noScript = true;
    else if (a === "--report") o.report = true;
    else throw new Error(`unknown option ${a}`);
  }
  if (o.theme && o.theme !== "dark" && o.theme !== "light") throw new Error("--theme takes dark or light");
  if (!o.out && (o.offline || o.theme || o.noScript) && !o.check) throw new Error("--offline, --theme and --no-script are for previews: give --out <dir> too");
  return o;
}

/**
 * Empty the output folder first, but only when it is safe: it doesn't exist yet, is empty, is _site at the
 * repository root, or holds a previous build of this site (llms.txt, sitemap.xml and assets/site.css).
 */
function prepareOut(dir) {
  if (fs.existsSync(dir)) {
    const entries = fs.readdirSync(dir);
    const ours = path.resolve(dir) === path.join(ROOT, "_site") || ["llms.txt", "sitemap.xml", "assets/site.css"].every((f) => fs.existsSync(path.join(dir, f)));
    if (entries.length && !ours) throw new Error(`${dir} exists and doesn't hold a build of this site; choose another --out`);
    fs.rmSync(dir, { recursive: true, force: true });
  }
  fs.mkdirSync(dir, { recursive: true });
}

function write(dir, rel, content) {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

const hash10 = (buf) => crypto.createHash("sha256").update(buf).digest("hex").slice(0, 10);

/** Build the whole site into `outDir`. Returns { records, env }. */
export function buildSite({ root = ROOT, outDir, offline = false, theme = null, noScript = false }) {
  const problems = [];
  problems.push(...validateManifest(config.pages, config.groups));

  const css = fs.readFileSync(path.join(root, "site/assets/site.css"));
  const js = fs.readFileSync(path.join(root, "site/assets/site.js"));
  const assetVersions = { "site.css": hash10(css), "site.js": hash10(js) };

  const working = fs.readFileSync(path.join(root, "spec/alp-v0.1.md"), "utf8");
  const trees = new Map();
  const env = {
    root,
    config,
    offline,
    problems,
    report: { maturity: [] },
    specText: working,
    counts: computeCounts(root, working),
    examples: extractExamples(working),
    usedExamples: [],
    useExample(page, name) { this.usedExamples.push({ page, name }); },
    specIds: sectionIds(working),
    // A link in a repository document to a file that has a page goes to the page: the Markdown documents, the
    // schema files (to their reference pages) and the vector files (to the raw files this site serves).
    pageForSource: new Map([
      ...config.pages.filter((p) => p.kind === "markdown" || p.kind === "vectors").map((p) => [p.source, p.url]),
      ...config.pages.filter((p) => p.options?.file).map((p) => [p.options.file, p.url]),
      ...rawFileList(root).filter((r) => r.from.startsWith("vectors/")).map((r) => [r.from, r.to]),
    ]),
    repoAnchors: true,
    repoFragmentLinks: [],
    notFoundRootRelative: !offline,
    exists(repoPath, ref) {
      if (ref === "main") {
        try { return fs.statSync(path.join(root, repoPath)).isDirectory() ? "dir" : "file"; } catch { return null; }
      }
      if (!trees.has(ref)) trees.set(ref, treeAt(root, ref));
      const t = trees.get(ref);
      if (!t) return "file";
      if (repoPath === "") return "dir";
      if (!t.has(repoPath)) return null;
      for (const x of t) if (x.startsWith(repoPath + "/")) return "dir";
      return "file";
    },
    pageCtx(page) {
      const rootRelative = page.options?.notFound && !offline;
      return {
        config,
        offline,
        theme,
        noScript,
        link: (to) => (rootRelative ? to : relUrl(page.url, to, { offline })),
        assetUrl: (name) => `/assets/${name}?v=${assetVersions[name]}`,
      };
    },
  };

  const records = new Map();
  for (const page of config.pages) {
    const kind = ALL_KINDS[page.kind];
    if (!kind) { problems.push(`site.config.mjs page ${page.url}: unknown kind "${page.kind}"`); continue; }
    if (page.source && page.kind !== "spec-published" && !fs.existsSync(path.join(root, page.source))) {
      problems.push(`site.config.mjs page ${page.url}: source ${page.source} doesn't exist`);
      continue;
    }
    const rec = kind(page, env);
    rec.page = page;
    records.set(page.url, rec);
  }

  prepareOut(outDir);
  for (const rec of records.values()) {
    write(outDir, outPath(rec.page.url), rec.html);
    if (rec.mirror) write(outDir, rec.mirror.url.slice(1), rec.mirror.text);
  }
  write(outDir, "assets/site.css", css);
  write(outDir, "assets/site.js", js);
  for (const a of config.assets) write(outDir, a.to.slice(1), fs.readFileSync(path.join(root, a.from)));
  for (const a of rawFileList(root)) write(outDir, a.to.slice(1), fs.readFileSync(path.join(root, a.from)));
  const tree = navTree(config.pages, config.groups);
  write(outDir, "llms.txt", llmsTxt(config, tree, records, working));
  write(outDir, "sitemap.xml", sitemapXml(config, records));
  write(outDir, "robots.txt", robotsTxt(config));

  // Links from rendered documents into repository Markdown that has no page: check the fragment exists.
  env.brokenRepoFragments = [];
  const anchorCache = new Map();
  for (const l of env.repoFragmentLinks) {
    if (!l.repoPath.endsWith(".md")) continue;
    const key = `${l.ref}:${l.repoPath}`;
    if (!anchorCache.has(key)) {
      let md = null;
      try { md = l.ref === "main" ? fs.readFileSync(path.join(root, l.repoPath), "utf8") : null; } catch { md = null; }
      anchorCache.set(key, md === null ? null : new Set(headingsOf(md).map((h) => h.id)));
    }
    const set = anchorCache.get(key);
    if (set && !set.has(decodeURIComponent(l.fragment.slice(1)))) env.brokenRepoFragments.push(l);
  }
  for (const l of env.brokenRepoFragments) {
    const known = config.knownBrokenLinks.some((k) => k.source === l.from && k.href === l.href);
    if (!known) problems.push(`${l.from}: link ${l.href} points to ${l.repoPath}${l.fragment}, which has no such heading`);
  }
  return { records, env };
}

function filesOf(dir) {
  const out = [];
  const rec = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) rec(p);
      else out.push(path.relative(dir, p));
    }
  };
  rec(dir);
  return out.sort();
}

/** The names of files that differ between two output folders (missing on either side counts). */
export function compareDirs(a, b) {
  const fa = filesOf(a), fb = filesOf(b);
  const all = [...new Set([...fa, ...fb])].sort();
  return all.filter((f) => {
    const pa = path.join(a, f), pb = path.join(b, f);
    if (!fs.existsSync(pa) || !fs.existsSync(pb)) return true;
    return !fs.readFileSync(pa).equals(fs.readFileSync(pb));
  });
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const tmpBase = fs.mkdtempSync(path.join(os.tmpdir(), "alp-site-"));
  const outDir = opts.check ? path.join(tmpBase, "site") : path.resolve(opts.out || path.join(ROOT, "_site"));
  const shared = { offline: opts.offline, theme: opts.theme, noScript: opts.noScript };
  let failed = false;
  try {
    const { records, env } = buildSite({ outDir, ...shared });
    const { problems, notes } = runChecks(outDir, records, env);
    const all = [...new Set([...env.problems, ...problems])];

    // 7. Two consecutive builds are byte-identical.
    const again = path.join(tmpBase, "again");
    buildSite({ outDir: again, ...shared });
    for (const f of compareDirs(outDir, again)) all.push(`${f}: differs between two builds of the same tree`);

    const pages = records.size;
    if (opts.report) {
      console.log("Maturity lines of the working specification, shown as labels (section, class, the line):");
      for (const m of env.report.maturity) console.log(`  ${String(m.section ?? "").padEnd(7)} ${(m.label || "(none)").padEnd(13)} ${m.text}`);
      console.log(`"open source" on the site (${notes.openSource.length}):`);
      for (const n of notes.openSource) console.log(`  ${n.where}: …${n.context}…`);
      console.log(`"PAP" on the site (${notes.pap.length}):`);
      for (const n of notes.pap) console.log(`  ${n.where}: …${n.context}…`);
      if (env.brokenRepoFragments.length) {
        console.log("Links in repository documents that were already broken:");
        for (const l of env.brokenRepoFragments) console.log(`  ${l.from}: ${l.href}`);
      }
    }
    if (all.length) {
      failed = true;
      console.error(`site: ${all.length} problem(s):`);
      for (const p of all) console.error(`  ${p}`);
    } else {
      console.log(`site: ${pages} pages built${opts.check ? " (check only)" : ` into ${outDir}`}; every check passed; two builds are identical.`);
    }
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
  process.exit(failed ? 1 : 0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    console.error(`site: ${e.message}`);
    process.exit(2);
  }
}
