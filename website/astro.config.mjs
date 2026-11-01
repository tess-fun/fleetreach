// The fleetreach website: landing page, docs, use cases, comparisons and examples, one site.
// SITE and BASE are the only places the public address lives; change them together with
// the canonical URL in scripts/postbuild.mjs if the site moves to its own domain.
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export const SITE = "https://tess-fun.github.io";
export const BASE = "/fleetreach";

export default defineConfig({
  site: SITE,
  base: BASE,
  trailingSlash: "always",
  telemetry: false,
  integrations: [
    starlight({
      title: "fleetreach",
      description:
        "Fleet-wide dependency security audit: scan many repositories at once, across 12 ecosystems, and fix what clears the most repos first.",
      logo: {
        light: "./src/assets/fleetreach-logo.svg",
        dark: "./src/assets/fleetreach-logo-inverse.svg",
        replacesTitle: true,
      },
      favicon: "/favicon.svg",
      social: [
        { icon: "github", label: "GitHub", href: "https://github.com/tess-fun/fleetreach" },
      ],
      editLink: {
        baseUrl: "https://github.com/tess-fun/fleetreach/edit/main/website/",
      },
      lastUpdated: true,
      customCss: ["./src/styles/fleetreach.css"],
      components: {
        Head: "./src/components/Head.astro",
      },
      head: [
        { tag: "meta", attrs: { property: "og:image", content: `${SITE}${BASE}/og-image.png` } },
        { tag: "meta", attrs: { name: "twitter:card", content: "summary_large_image" } },
        { tag: "link", attrs: { rel: "alternate", type: "text/plain", title: "llms.txt", href: `${BASE}/llms.txt` } },
      ],
      sidebar: [
        {
          label: "Getting started",
          items: [
            { slug: "docs" },
            { slug: "docs/getting-started/installation" },
            { slug: "docs/getting-started/first-scan" },
            { slug: "docs/getting-started/reading-the-report" },
          ],
        },
        { label: "Guides", items: [{ autogenerate: { directory: "docs/guides" } }] },
        { label: "Integrations", items: [{ autogenerate: { directory: "docs/integrations" } }] },
        { label: "Ecosystems", collapsed: true, items: [{ autogenerate: { directory: "docs/ecosystems" } }] },
        { label: "Concepts", items: [{ autogenerate: { directory: "docs/concepts" } }] },
        { label: "Reference", collapsed: true, items: [{ autogenerate: { directory: "docs/reference" } }] },
        { label: "Use cases", collapsed: true, items: [{ autogenerate: { directory: "use-cases" } }] },
        { label: "Compare", collapsed: true, items: [{ autogenerate: { directory: "compare" } }] },
        { label: "Examples", collapsed: true, items: [{ autogenerate: { directory: "examples" } }] },
        { slug: "docs/faq" },
        { slug: "docs/changelog" },
      ],
    }),
  ],
});
