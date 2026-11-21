// The docs navigation, built from the manifest: groups in their order, pages by `order`, child pages
// under their parent. Also the reading order for the previous/next links.

/** Check the manifest's shape; returns a list of problems (empty when it is sound). */
export function validateManifest(pages, groups) {
  const problems = [];
  const urls = new Set();
  const groupIds = new Set(groups.map((g) => g.id));
  for (const p of pages) {
    const where = `site.config.mjs page ${p.url}`;
    if (!/^\/(?:[a-z0-9.-]+\/)*(?:[a-z0-9-]+\.html)?$/.test(p.url)) problems.push(`${where}: URL must be a lower-case path ending in "/" or ".html"`);
    if (urls.has(p.url)) problems.push(`${where}: URL appears twice`);
    urls.add(p.url);
    for (const k of ["kind", "title", "description"]) if (!p[k]) problems.push(`${where}: missing ${k}`);
    if (p.description && !/[.!?]$/.test(p.description.trim())) problems.push(`${where}: description must be one sentence ending in a full stop`);
    if (p.group !== null && p.group !== undefined && !groupIds.has(p.group)) problems.push(`${where}: unknown group "${p.group}"`);
    if (p.group && typeof p.order !== "number") problems.push(`${where}: a page in a group needs a numeric order`);
  }
  for (const p of pages) {
    if (!p.parent) continue;
    const parent = pages.find((q) => q.url === p.parent);
    if (!parent) problems.push(`site.config.mjs page ${p.url}: parent ${p.parent} is not a page`);
    else if (parent.group !== p.group) problems.push(`site.config.mjs page ${p.url}: parent ${p.parent} is in another group`);
    else if (parent.parent) problems.push(`site.config.mjs page ${p.url}: navigation is two levels deep at most`);
  }
  const sources = new Map();
  for (const p of pages) {
    if (p.kind !== "markdown" || !p.source) continue;
    if (sources.has(p.source)) problems.push(`site.config.mjs: ${p.source} is the source of both ${sources.get(p.source)} and ${p.url}`);
    sources.set(p.source, p.url);
  }
  return problems;
}

/** [{ group, pages: [{ page, children: [page] }] }] for the docs groups, in order. */
export function navTree(pages, groups) {
  const byOrder = (a, b) => a.order - b.order || (a.url < b.url ? -1 : 1);
  return groups.map((group) => {
    const inGroup = pages.filter((p) => p.group === group.id).sort(byOrder);
    const top = inGroup.filter((p) => !p.parent);
    return {
      group,
      pages: top.map((page) => ({ page, children: inGroup.filter((c) => c.parent === page.url) })),
    };
  }).filter((g) => g.pages.length);
}

/** The docs pages in reading order (each group in turn; a parent, then its children). */
export function readingOrder(pages, groups) {
  const out = [];
  for (const g of navTree(pages, groups)) for (const { page, children } of g.pages) out.push(page, ...children);
  return out;
}

/** { prev, next } pages around `page` in reading order (either may be null). */
export function neighbours(pages, groups, page) {
  const order = readingOrder(pages, groups);
  const i = order.findIndex((p) => p.url === page.url);
  if (i === -1) return { prev: null, next: null };
  return { prev: order[i - 1] ?? null, next: order[i + 1] ?? null };
}
