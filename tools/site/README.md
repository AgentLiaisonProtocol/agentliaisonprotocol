# Site build

`tools/site` builds https://agentliaisonprotocol.org from this repository's own files, then checks what it built. The specification, the guides and the project's documents are rendered from their Markdown sources, so the site and the repository can't drift; the build fails when a link, an anchor or an example is broken. It is a small Node program (Node 22.18 or later, ES modules) with two pinned dependencies, `micromark` 4.0.2 and `micromark-extension-gfm` 3.0.0, and no template engine or bundler. It is licensed under Apache-2.0.

```sh
cd tools/site
npm ci             # the two pinned dependencies
npm test           # unit tests (node --test); from the repository root: node --test tools/site
npm run build      # builds _site/ at the repository root, then runs every check
npm run check      # builds into a temporary folder and only reports
```

`node build.mjs` takes these options:

| Option | What it does |
|---|---|
| `--out <dir>` | Build into `<dir>` instead of `_site/`. An existing folder is emptied only if it is empty or holds an earlier build of this site. |
| `--check` | Build into a temporary folder, run the checks, report, and remove the folder. |
| `--offline` | For previews opened from disk: folder links end in `index.html`, and the Content-Security-Policy tag is left out. Never deployed. |
| `--theme dark` | Preview only: `data-theme="dark"` on every page, to see the dark tokens (headless browsers don't emulate the media query). |
| `--no-script` | Preview only: pages without `site.js`, to see what a reader without JavaScript gets. |
| `--report` | Also print every maturity line of the working specification shown as a label, every use of "open source" and "PAP" on the site, and any link in the repository's documents that was already broken. |

The build is deterministic: two runs on the same tree give byte-identical output (the build checks this itself). Nothing reads the clock; "last changed" dates come from `git log -1 --format=%cs -- <source>`, and are left out when git or the history is missing. The published-version page needs the history too (`git show <commit>:spec/alp-v0.1.md`), so CI checks out with `fetch-depth: 0`.

## Layout

| Path | What it is |
|---|---|
| `build.mjs` | The entry point: options, the build, the checks, the second build that proves the output is deterministic. |
| `site.config.mjs` | The page manifest (the single list of pages), the docs groups, the top bar's links, the figures, the copied files, and the site's constants. |
| `lib/pages.mjs` | One function per kind of page (see below). |
| `lib/markdown.mjs` | micromark with GFM, then the passes over its output: heading ids, permalinks, link rewriting, section references, maturity labels, JSON highlighting, the Mermaid figure, table and code containers. Also the source analysis (raw HTML, counts, link positions) and the Markdown mirror's link rewriting. |
| `lib/links.mjs` | How a link in a repository document resolves: to a page of the site, to GitHub, or left alone. |
| `lib/sections.mjs` | Section numbers, section references in running text, and the sections' own maturity lines. |
| `lib/slug.mjs` | Heading ids that match GitHub's. |
| `lib/highlight.mjs` | The JSON tokenizer for ```` ```json ```` blocks. |
| `lib/fences.mjs` | A line scanner of its own that finds every fenced code block in a source (for check 4), and the one change made to a source before rendering (below). |
| `lib/examples.mjs` | The specification's named examples (`<!-- example:NAME -->`). |
| `lib/shell.mjs` | The page shell: `<head>`, top bar, sidebar, footer, the docs and article layouts, the CSP. |
| `lib/nav.mjs` | Manifest validation, the navigation tree and the reading order (previous and next). |
| `lib/outputs.mjs` | `llms.txt`, `sitemap.xml`, `robots.txt`. |
| `lib/checks.mjs` | The checks below. |
| `lib/fragments.mjs` | An audit of every `#fragment` the repository's documents use (the tests run it). |
| `lib/walkthrough.mjs` | The overview's walkthrough, from `site/walkthroughs.mjs`: the scenarios, their diagrams, and the objects with their marked members. |
| `lib/html.mjs`, `lib/urls.mjs`, `lib/frontmatter.mjs`, `lib/git.mjs` | Helpers. |
| `test/*.test.mjs` | Unit tests, and `test/site.test.mjs`, which builds the site once into a temporary folder and checks particular pages. `tests.mjs` loads them all when Node is given the folder (`node --test tools/site`); a file that fails to load is reported as a failing test named after it. |

The site's own sources are in `site/`: `site/assets/` (`site.css`, `site.js`, the Open Graph image, published at `/og-image.png`, and the favicon), `site/pages/` (hand-written pages, among them the overview `overview.html` and the Poppy page `poppy.html`), `site/figures/` (inline SVG figures) and `site/walkthroughs.mjs` (the walkthrough's steps). Every other page comes from a Markdown file that stays where it is and stays readable on GitHub.

## Adding a page

Add an entry to `pages` in `site.config.mjs`:

```js
{ url: "/docs/guides/example/", kind: "markdown", source: "docs/EXAMPLE.md", title: "Example",
  group: "guides", order: 50, description: "One sentence that restates what the source says." },
```

| Field | Meaning |
|---|---|
| `url` | The page's path from the site root. A folder path (`/docs/spec/`) is written as `…/index.html`. |
| `kind` | How the page is made (below). |
| `source` | The repository file it comes from. |
| `title` | Its name in the navigation and in `<title>`. |
| `description` | One sentence for `<meta name="description">`, the guides index and `llms.txt`. It must restate what the source says: no new facts (CONTRIBUTING.md, "Writing style"). |
| `group`, `order` | Its docs group (`start`, `specification`, `guides`, `reference`, `status`, `project`) and position in it; `group: null` puts a page outside the docs, in the article layout. |
| `parent` | For a child page in the navigation, the parent's `url` (one level only). |
| `layout` | `"docs"` (the default for grouped pages) or `"article"`. |
| `options` | Kind-specific settings, such as `allowRawHtml: ["<your tenant>"]` for a document whose text has something that looks like an HTML tag. |

Kinds (in `lib/pages.mjs`):

- **`markdown`**: a repository document, rendered as described below, with a Markdown mirror. Relative links from other documents to its source now point to this page. With `layout: "article"` (the announcement) it uses the article layout, and `options.notice` (HTML whose links are site paths) puts a notice above its title.
- **`spec-published`**: the specification as it was at `site.published.commit`. Links to repository files go to GitHub at that commit; section references stay within the page.
- **`glossary`** with `options.append`: after the terms of the specification's Section 2, a hand-written Markdown file (`site/pages/glossary-other.md`, "Other terms used on this site"), whose links resolve like a document's.
- **`roadmap`**: the items of the specification's Section 19 ("Future work"), each by its own lead-in words linked to the section, after the section's own maturity line, then a pointer to the known gaps. A missing section, maturity line or list fails the build.
- **`page`**: a hand-written page in `site/pages/`, Markdown (`.md`) or an HTML fragment (`.html`), each starting with a small front-matter block (`lib/frontmatter.mjs` says what it accepts). In an HTML fragment, write links to the site as site paths (`href="/docs/spec/#abstract"`); the build makes them relative to the page. List the specification examples a page shows in its front matter (`examples: [a1_envelope]`), so the build checks they exist. Markdown pages get mirrors; HTML fragments don't. In a Markdown page, a link that starts with `/` is a path on this site and any other relative link a repository path, resolved like a document's. Besides `{{count:name}}` (below), a page can use `{{include:file}}` (a file next to it, as it is, for example inside a code fence: the demo transcript), and an HTML fragment `{{figure:name}}` (`site/figures/name.svg`, inline) and `{{walkthrough}}` (below).
- **`guides-index`**: the guides index, generated from the manifest's descriptions.

Generated reference kinds (`lib/reference-pages.mjs`, built by `lib/reference.mjs` and `lib/schemas.mjs`), each from files under `schemas/`, `vectors/` or the specification, so nothing is retyped:

- **`schema`** and **`scope`**: one page for a JSON Schema file or a scope definition (`options: { file: "schemas/envelope.schema.json" }`). Identity, a members table (name, type, required, constraints, description; one level of nesting inline, deeper objects as "Members of" subsections), rules (`allOf`, `oneOf`, `if`/`then`/`else`, `dependentRequired` and the rest), each `$defs` entry as a subsection, "Other keywords", and the full file. `$ref` values become links. A `collapse: true` parent shows its children in the sidebar only on itself and on them.
- **`tools`** (`schemas/client/tools.json`) and **`rest`** (`schemas/client/openapi.json`); **`schemas-index`** (the table from the specification's Appendix B); **`vectors`** (`vectors/README.md` plus a generated index with case counts); **`glossary`** (specification Section 2, alphabetical); **`reference-index`**.
- Raw files: every `.json` under `schemas/` and `vectors/` is served at the same path (`rawFiles` in the manifest), except the TEST-ONLY keys file, which is linked on GitHub. A link in a repository document to a schema file goes to its reference page, to a vector file to the raw file.
- **Faithfulness.** `describe()` in `lib/schemas.mjs` handles every JSON Schema 2020-12 keyword it knows, and lists any other under "Other keywords". It records each keyword it was given in a `Coverage`; `test/reference.test.mjs` walks every file with its own walker and fails if a keyword is neither shown nor listed, or if a pattern, constant, enum value or bound is missing from the page text. A new file under `schemas/` needs a page in the manifest, or the build fails.
- **Counts for hand-written pages.** `{{count:name}}` in a `page` body (Markdown or HTML) is replaced by a number computed from the repository: `schemaFiles`, `vectorFiles`, `vectorCases`, `requirementsBC`, `requirementsOB`, `requirementsHB`, `requirementsNC`, `requirementsPB`, `requirementsCD`, `requirementsTotal` (`lib/counts.mjs` says what each counts). An unknown name fails the build.

A new kind is a function `(page, env) => record` added to `KINDS` in `lib/pages.mjs`. The record is `{ html, mirror: { url, text } | null, outline, expect, date, sourceText }`: `expect` (counts of headings, tables, code blocks and Mermaid blocks in the source) turns on check 4 for the page, and `sourceText` lets the wording check compare the page with its source. Use `docsPage` or `articlePage` from `lib/shell.mjs` for the shell, and `env.pageCtx(page).link(sitePath)` for every link, so it is relative to the page.

## The walkthrough

`{{walkthrough}}` renders `site/walkthroughs.mjs` with `lib/walkthrough.mjs`: four scenarios from the specification's Appendix A, each with a small diagram of its parties and four to six steps. `{{walkthrough:<id>}}` renders one scenario, without tabs or a number: the overview shows the first, and `/docs/walkthroughs/` (`site/pages/walkthroughs.html`) shows all four. On a docs page a scenario's title is an h2 and its steps' titles h3, and the page's outline lists the scenarios; on an article page they are h3 and h4. A step has a title, one to three sentences, what each side sees (`a`, teal, the sender's side; `b`, orange, the other person's; `c`, anyone else), the specification sections it comes from (`refs`, linked; a section that doesn't exist fails the build), the hops of the diagram it marks, and the objects it shows behind "Show the object". An object is never typed into the data: it is a named example of the specification (`{ example: "a2_receipt" }`) or a value in a vector file (`{ vector: "vectors/threads/meeting-commit.json", path: "objects.commit" }`; `cases.name=…` picks an array entry by name), and `mark` lists the members the step talks about, by path (`receipt.ledger_hash`, `brokers.0.jkt`). A missing example, vector value or member fails the build; `test/walkthrough.test.mjs` checks the data and that marking keeps the JSON text exactly.

Each step's sentences must restate Appendix A or the section the step names, and nothing else. Inline text can use `` `code` `` and `[text](glossary:id)`, `[text](spec:6.6)` or `[text](/site/path/)`.

Without JavaScript every scenario and step is visible in order, as ordered lists. `site.js` (`walkthrough()`) makes the scenarios tabs (when there is more than one) and shows one step at a time, with Previous and Next, step markers, arrow keys, a polite live region, and a short fade that `prefers-reduced-motion` removes; the current step's hops are marked in the diagram by class. A link to `#wt-<scenario>-<n>` opens that step, and `#wt-<scenario>` or `#wt-<scenario>-title` that scenario, when the page loads or when the link is followed on the page. Each diagram is drawn twice from the same data, the second turned a quarter for screens under 600 px. A turned drawing of two or more columns keeps its 12px labels, so on a phone too narrow for it, it scrolls sideways inside its own frame, with a line under it that says so. A scenario can carry a `maturity` line (`{ label, text }`), shown under its title in the style of the specification's maturity labels: the scenario between two organizations says that federation between brokers is Experimental.

## How Markdown is rendered

- **Raw HTML stays escaped.** micromark runs with its defaults, so an HTML tag in a document shows as text. Any HTML comment or tag outside code fails the build with the file and line, unless the page's `options.allowRawHtml` lists it. The specification's example markers are the exception: they are read, then removed.
- **Heading ids match GitHub's** (`lib/slug.mjs`): lower-case, drop everything but letters, digits, spaces, hyphens and underscores, spaces to hyphens, `-1`, `-2` for repeats. A test checks every `#fragment` the repository's documents use. h2 to h4 get a permalink.
- **Links.** A relative link to a document that has a page goes to that page, keeping the fragment; any other repository path goes to GitHub (`blob/main/…`, or `tree/main/…` for a folder), and a path that doesn't exist fails the build. Links to `https://agentliaisonprotocol.org/…` become relative links. Mirrors get absolute site URLs instead.
- **Section references.** On the specification's pages, "Section 6.6", "Sections 4.2–4.8", "Section 12.2.4" and "Appendix A" in running text link to that heading; references that cite another document ("RFC 6749, Section 3.3", "[Poppy], Section 4.1") are left alone. On other pages, "spec Section 5.3", "specification Section 5.3", "the specification's Section 5.4" and the short form "Spec 6.6" or "spec 6.14" (each number of a list such as "Spec 4.2, 4.3 and 12.6") link into `/docs/spec/`. A reference to a section that doesn't exist fails the build.
- **Maturity labels.** A section of the specification states its maturity in its own text, in a paragraph that starts with an emphasised line such as "*Maturity: Core.*" or "*Informative.*". On both specification pages (the working text and version 0.1.0 as first published) that line is shown as a label, word for word, styled by the first label word in it (Core, Experimental, Future or Informative); anything after it in the paragraph stays as text. Nothing is derived from the status section's table. `--report` lists every such line with its section.
- **Code.** ```` ```json ```` blocks are highlighted by `lib/highlight.mjs`, whose output has exactly the source as its text (tested). Long paths in code spans may break after a slash.
- **One change before rendering.** A fenced block that is indented inside a list item and directly follows a line of text gets a blank line before it (`normalizeFences` in `lib/fences.mjs`). The source is valid CommonMark, and the block's text is the same either way, but micromark 4.0.2's HTML compiler drops every line ending inside such a block when the list is tight. With the blank line the list is loose and the block keeps its lines. The source file itself is not changed.
- **Figures.** A Mermaid block is replaced by the figure in `site.config.mjs` `figures` whose `mermaidSha256` matches the block's source, so a changed diagram fails the build until its figure is redrawn. Figures are inline SVG in `site/figures/`, styled by classes in `site.css` (no inline styles), with `role="img"`, a `<title>` and a `<desc>`.
- **Under the title** of each docs page: the source file on GitHub, the last-changed date, "View as Markdown" (the mirror) and "Copy page as Markdown" (a button that fetches the mirror from the same site when clicked; the Content Security Policy allows exactly that with `connect-src 'self'`, and `site.js` shows the button only on a page served over HTTP, so not on a page opened from disk).

## Outputs

- Every page is a folder: `/docs/spec/` is `_site/docs/spec/index.html`. All links between pages are relative, so the output works under any path prefix; canonical, Open Graph and sitemap URLs use `site.origin`. The 404 page is the exception: GitHub Pages serves it at any missing path, so its links start at the root.
- A Markdown mirror next to each page rendered from Markdown: `/docs/spec/` has `/docs/spec.md`.
- `llms.txt` (the specification's abstract, then every page in navigation order, linking to its mirror), `sitemap.xml`, `robots.txt`.
- `assets/site.css` and `assets/site.js`, referenced with `?v=` and the first 10 hex digits of their SHA-256, the favicon, and `/og-image.png`.

## The checks

`node build.mjs` fails, naming the file and the problem, when:

1. an internal link doesn't resolve to a built page or file, or its fragment to an id on that page (in HTML pages, and for absolute site URLs in the mirrors and `llms.txt`);
2. a page loads anything from another origin (`src`, stylesheet and icon links, `srcset`, `poster`, `<object>`, `<embed>`, `<iframe>`, `url()` in CSS), has an inline style, script or event handler, or lacks the CSP tag; `site.js` uses storage or cookies, or any network call but the one `fetch` of "Copy page as Markdown";
3. a page lacks exactly one h1, a title, a description, a canonical URL or `lang="en"`, skips a heading level going down, or has an image or figure without a text alternative;
4. a page rendered from Markdown has a different number of headings, tables or code blocks than its source (a Mermaid block counts as its figure), or contains an HTML comment, a raw Mermaid block or source HTML; or a fenced code block of its source, found by `lib/fences.mjs` rather than by the renderer, has no `<pre>` on the page whose text is exactly the block's text, in the same order (a Mermaid block, replaced by its figure, is the one exception);
5. a page uses a specification example that doesn't exist, or an example isn't valid JSON (or a `sha256:` hash for an inline value);
6. a page contains a banned word (CONTRIBUTING.md, "Writing style"), "PAP" more often than its source document has it, or "open source" more often than its source has it (`--report` lists each use);
7. two consecutive builds differ.

## Stylesheet and script

`site/assets/site.css` holds the tokens of the existing pages (light, and dark both by `prefers-color-scheme` and by `data-theme="dark"`), the docs layout (a 272 px sidebar and a content column of at most 780 px, centred in at most 1180 px; under 960 px the sidebar is a `<details>` above the content), the article layout (720 px and 940 px columns) with the components of the announcement and Poppy pages, JSON and badge tokens (each at 4.5:1 or better), print and reduced-motion rules. Teal (`--a`) is the sender's or "your" side and orange (`--b`) the other person's side, everywhere; don't use them for decoration.

`site/assets/site.js` only adds conveniences, and every page is complete without it: the sidebar stays open on wide screens, copy buttons on code blocks, "Copy page as Markdown", the "Filter sections" box on pages with more than 20 headings (`/` focuses it), the current section in the outline (`aria-current="location"`), and closing the small-screen menu. It uses no storage or cookies; its one network request is "Copy page as Markdown" fetching the page's own mirror. It sets state with classes and attributes, never inline styles. Add a feature as a function called from `init()`.

## Looking at the result

Build an offline copy (`node tools/site/build.mjs --offline --out /tmp/site-preview`) and open its files in a browser, or take screenshots with headless Chrome (`--headless=new --screenshot=… --window-size=1280,2400 file:///tmp/site-preview/docs/spec/index.html`). For dark mode build a second copy with `--theme dark`; for the plain view, `--no-script`.
