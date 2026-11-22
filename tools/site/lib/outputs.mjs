// Machine-readable outputs: llms.txt, sitemap.xml and robots.txt.

import { esc } from "./html.mjs";

/** The specification's abstract, as one paragraph of Markdown. */
export function abstractOf(specMd) {
  const m = /^## Abstract\n+([\s\S]*?)\n+## /m.exec(specMd);
  if (!m) throw new Error("spec/alp-v0.1.md: no Abstract section");
  return m[1].trim().replace(/\s*\n\s*/g, " ");
}

/**
 * llms.txt: a title, the specification's abstract, then the pages grouped as in the navigation, each as a
 * link to its Markdown mirror with its one-sentence description.
 */
export function llmsTxt(config, tree, records, specMd) {
  const { site } = config;
  const line = (p) => {
    const rec = records.get(p.url);
    const href = rec?.mirror ? site.origin + rec.mirror.url : rec?.rawUrl ? site.origin + rec.rawUrl : site.origin + p.url;
    return `- [${p.title}](${href}): ${p.description}`;
  };
  const parts = [`# ${site.name}`, "", `> ${abstractOf(specMd)}`, ""];
  for (const { group, pages } of tree) {
    parts.push(`## ${group.title}`, "");
    for (const { page, children } of pages) {
      parts.push(line(page));
      for (const c of children) parts.push(line(c));
    }
    parts.push("");
  }
  const others = config.pages.filter((p) => !p.group && !p.options?.notFound);
  if (others.length) {
    parts.push("## Optional", "");
    for (const p of others) parts.push(line(p));
    parts.push("");
  }
  return parts.join("\n");
}

/** sitemap.xml: every HTML page except the 404 page, with lastmod when the source's date is known. */
export function sitemapXml(config, records) {
  const urls = [...records.values()]
    .filter((r) => !r.page.options?.notFound && r.page.url.endsWith("/"))
    .sort((a, b) => (a.page.url < b.page.url ? -1 : 1))
    .map((r) => `  <url><loc>${esc(config.site.origin + r.page.url)}</loc>${r.date ? `<lastmod>${r.date}</lastmod>` : ""}</url>`);
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join("\n")}\n</urlset>\n`;
}

export function robotsTxt(config) {
  return `User-agent: *\nAllow: /\n\nSitemap: ${config.site.origin}/sitemap.xml\n`;
}
