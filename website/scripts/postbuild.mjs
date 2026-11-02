// After `astro build`: the files search engines and LLM tools read, and a link check.
//
// - a Markdown copy of every page at <page>/index.md (each page links it as an alternate)
// - llms.txt (an index of those copies) and llms-full.txt (all of them in one file)
// - robots.txt
// - redirects from the old mdBook addresses (/docs/<page>.html)
// - every internal link in the built site must resolve, or the build fails

import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { BASE, SITE } from "../astro.config.mjs";

const site = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const content = join(site, "src", "content", "docs");
const dist = join(site, "dist");
const root = `${SITE}${BASE}`;

function files(dir, test) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return files(path, test);
    return test(name) ? [path] : [];
  });
}

// ---- Markdown copies ----

function frontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/);
  const yaml = m ? m[1] : "";
  const field = (key) => {
    const v = yaml.match(new RegExp(`^${key}:\\s*(.+)$`, "m"))?.[1]?.trim();
    return v?.startsWith('"') ? JSON.parse(v) : v;
  };
  const order = Number(yaml.match(/^\s+order:\s*(\d+)/m)?.[1] ?? 99);
  const tagline = yaml.match(/^\s+tagline:\s*(.+)$/m)?.[1];
  return { title: field("title"), description: field("description"), order, tagline, body: m ? text.slice(m[0].length) : text };
}

/** Page body as plain Markdown: no run markers, no MDX imports or components. */
function plain(body) {
  return body
    .replace(/^(<!--|\{\/\*) \/?run.*(-->|\*\/\})\n/gm, "")
    .replace(/^import .*\n/gm, "")
    .replace(/<Card title="([^"]+)"[^>]*>\s*([\s\S]*?)\s*<\/Card>/g, (_, t, d) => `### ${t}\n\n${d.replace(/\n\s+/g, " ")}\n`)
    .replace(/<LinkCard title="([^"]+)"(?: description="([^"]*)")? href="([^"]+)"(?: description="([^"]*)")? \/>/g,
      (_, t, d1, h, d2) => `- [${t}](${h})${d1 || d2 ? `: ${d1 || d2}` : ""}`)
    .replace(/<TabItem label="([^"]+)">/g, "**$1**\n")
    .replace(/<div class="fr-stat"><strong>(.*?)<\/strong><span>(.*?)<\/span><\/div>/g, "- **$1** $2")
    .replace(/<\/?(Tabs|TabItem|CardGrid|div)[^>]*>\n?/g, "")
    .replace(/<\/?code>/g, "`")
    .replace(/^ {4}/gm, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

const pages = files(content, (n) => /\.mdx?$/.test(n)).map((path) => {
  const rel = relative(content, path).replace(/\.mdx?$/, "");
  const id = rel === "index" ? "" : rel.replace(/\/index$/, "");
  const fm = frontmatter(readFileSync(path, "utf8"));
  const url = `${root}/${id ? id + "/" : ""}`;
  const description = fm.description ?? "";
  const md = `# ${fm.title}\n\n> ${description}\n\n${plain(fm.body)}\n`
    .replaceAll(`](${BASE}/`, `](${root}/`);
  const out = join(dist, id, "index.md");
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, md);
  return { id, title: fm.title, description, order: fm.order, url, md };
});

// ---- llms.txt ----

const sections = [
  ["Getting started", (id) => id === "docs" || id.startsWith("docs/getting-started/")],
  ["Guides", (id) => id.startsWith("docs/guides/")],
  ["Integrations", (id) => id.startsWith("docs/integrations/")],
  ["Ecosystems", (id) => id.startsWith("docs/ecosystems")],
  ["Concepts", (id) => id.startsWith("docs/concepts/")],
  ["Reference", (id) => id.startsWith("docs/reference/")],
  ["Use cases", (id) => id.startsWith("use-cases/")],
  ["Compare", (id) => id.startsWith("compare/")],
  ["Examples", (id) => id.startsWith("examples/")],
  ["Optional", (id) => id === "docs/faq" || id === "docs/changelog"],
];
const sorted = [...pages].sort((a, b) => a.id.split("/").length - b.id.split("/").length || a.order - b.order || a.id.localeCompare(b.id));
const landing = pages.find((p) => p.id === "");
const llms = [
  "# fleetreach",
  "",
  `> ${landing.description}`,
  "",
  "fleetreach is an open-source CLI (MIT or Apache-2.0) that audits many repositories in one run across 12 ecosystems (Rust, Go, npm, PyPI, RubyGems, Packagist, NuGet, Maven, GitHub Actions, Swift, Hex, Julia). It reads lockfiles without running package code, matches them against OSV and RustSec, ranks fixes by how many repos they clear, adds CISA KEV, EPSS and SSVC, opens verified fix pull requests, records history and SLAs, and writes SARIF, OpenVEX, CycloneDX and SPDX. It fails closed: exit 0 clean, 1 findings, 2 something could not be read.",
  "",
  `Every page below is Markdown. The HTML version is the same URL without \`index.md\`. All pages in one file: ${root}/llms-full.txt`,
  "",
  ...sections.flatMap(([name, test]) => {
    const list = sorted.filter((p) => test(p.id));
    return list.length ? [`## ${name}`, "", ...list.map((p) => `- [${p.title}](${p.url}index.md): ${p.description}`), ""] : [];
  }),
].join("\n");
writeFileSync(join(dist, "llms.txt"), llms);
writeFileSync(
  join(dist, "llms-full.txt"),
  [landing, ...sorted.filter((p) => p.id !== "")].map((p) => `<!-- ${p.url} -->\n${p.md}`).join("\n---\n\n"),
);

// ---- robots.txt ----

writeFileSync(join(dist, "robots.txt"), `User-agent: *\nAllow: /\n\nSitemap: ${root}/sitemap-index.xml\n`);

// ---- Redirects from the mdBook site ----

// docs/index.html is not here: it is the Overview page itself, and /docs/index.html serves it.
const moved = {
  "introduction.html": "docs/",
  "installation.html": "docs/getting-started/installation/",
  "quickstart.html": "docs/getting-started/first-scan/",
  "configuration.html": "docs/reference/fleet-toml/",
  "ecosystems.html": "docs/ecosystems/",
  "ci.html": "docs/integrations/github-actions/",
  "context.html": "docs/guides/prioritise-with-kev-epss-and-ssvc/",
  "views.html": "docs/getting-started/reading-the-report/",
  "fix.html": "docs/guides/plan-and-apply-fixes/",
  "history.html": "docs/guides/track-history-and-slas/",
  "licenses.html": "docs/guides/enforce-a-license-policy/",
  "reachability.html": "docs/guides/check-reachability/",
  "sbom.html": "docs/guides/generate-sboms/",
  "print.html": "docs/",
};
for (const [from, to] of Object.entries(moved)) {
  const target = `${BASE}/${to}`;
  const file = join(dist, "docs", from);
  // A redirect must never replace a real page, or the page becomes a redirect to itself.
  if (existsSync(file)) throw new Error(`postbuild: redirect ${from} would overwrite a built page`);
  writeFileSync(
    file,
    `<!doctype html><meta charset="utf-8"><title>Moved</title><link rel="canonical" href="${root}/${to}"><meta name="robots" content="noindex"><meta http-equiv="refresh" content="0; url=${target}"><p>Moved to <a href="${target}">${root}/${to}</a>.</p>\n`,
  );
}

// ---- Link check ----

const exists = (p) => {
  try {
    return statSync(p).isFile() || statSync(join(p, "index.html")).isFile();
  } catch {
    return false;
  }
};
const broken = [];
for (const file of files(dist, (n) => n.endsWith(".html"))) {
  const html = readFileSync(file, "utf8");
  for (const [, href] of html.matchAll(/(?:href|src)="([^"#?]+)/g)) {
    if (!href.startsWith(`${BASE}/`)) continue;
    if (!exists(join(dist, decodeURI(href.slice(BASE.length))))) broken.push(`${relative(dist, file)} -> ${href}`);
  }
}
for (const p of pages) {
  for (const [, href] of p.md.matchAll(/\]\((https?:\/\/[^)]+)\)/g)) {
    if (!href.startsWith(`${root}/`)) continue;
    const path = href.slice(root.length).split("#")[0];
    if (!exists(join(dist, path))) broken.push(`${p.id || "index"}.md -> ${href}`);
  }
}
console.error(`postbuild: ${pages.length} Markdown copies, llms.txt, llms-full.txt, robots.txt, ${Object.keys(moved).length} redirects`);
if (broken.length) {
  console.error(`broken internal links:\n  ${[...new Set(broken)].join("\n  ")}`);
  process.exit(1);
}
