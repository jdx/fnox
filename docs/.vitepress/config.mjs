import { sidebar } from "./navigation.mjs";
import { socialCard, writeSocialCard } from "./social-images.mjs";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitepress";
import spec from "../cli/commands.json" with { type: "json" };

/**
 * @typedef {Object} Command
 * @property {Record<string, Command & { hide?: boolean; full_cmd: string[] }>} subcommands
 */

/**
 * @param {Command} cmd
 * @returns {string[][]}
 */
function getCommands(cmd) {
  const commands = [];
  for (const [name, sub] of Object.entries(cmd.subcommands)) {
    if (sub.hide) continue;
    commands.push(sub.full_cmd);
    commands.push(...getCommands(sub));
  }
  return commands;
}

const commands = getCommands(spec.cmd);
const configDir = dirname(fileURLToPath(import.meta.url));
const cargoToml = readFileSync(resolve(configDir, "../../Cargo.toml"), "utf8");
const versionMatch = cargoToml.match(
  /^\[workspace\.package\][\s\S]*?^\s*version\s*=\s*"([^"]+)"/m,
);
if (!versionMatch) {
  console.warn("Unable to find package version in Cargo.toml");
}
const latestVersion = versionMatch?.[1] ?? "0.0.0";
const siteUrl = "https://fnox.jdx.dev";
const siteDescription =
  "Manage development secrets with encrypted files or cloud providers, fast local sync, shell integration, profiles, and hardware-backed keys.";

export default defineConfig({
  title: "fnox",
  description: siteDescription,
  base: "/",
  appearance: "dark",
  sitemap: { hostname: siteUrl },
  srcExclude: ["README.md"],

  themeConfig: {
    logo: "/logo.svg",
    outline: { level: [2, 3], label: "On this page" },
    editLink: {
      pattern: ({ relativePath }) =>
        relativePath.startsWith("cli/")
          ? "https://github.com/jdx/fnox/blob/main/docs/README.md#generated-reference"
          : `https://github.com/jdx/fnox/edit/main/docs/${relativePath}`,
      text: "Improve this page",
    },

    nav: [
      { text: "Guide", link: "/guide/quick-start" },
      { text: "Providers", link: "/providers/overview" },
      {
        text: "Leases",
        link: "/guide/leases",
        activeMatch: "/leases/|/guide/leases",
      },
      {
        text: "Reference",
        items: [
          { text: "Commands", link: "/cli/" },
          { text: "Configuration", link: "/reference/configuration" },
          { text: "Environment variables", link: "/reference/environment" },
        ],
      },
      {
        text: `v${latestVersion}`,
        link: "https://github.com/jdx/fnox/releases",
      },
    ],

    sidebar: sidebar(commands),

    socialLinks: [{ icon: "github", link: "https://github.com/jdx/fnox" }],

    footer: false,

    search: {
      provider: "local",
    },
  },
  head: [
    [
      "script",
      {},
      `(function () {
  try {
    var d = document.documentElement;
    var c = JSON.parse(localStorage.getItem("jdx-banner-cache") || "null");
    var expires = c && c.expires ? Date.parse(c.expires) : NaN;
    var now = Date.now();
    var metadataValid =
      c &&
      typeof c.id === "string" &&
      typeof c.height === "string" &&
      /^[1-9]\\d*(?:\\.\\d+)?px$/.test(c.height) &&
      Number.isFinite(c.width) &&
      typeof c.fontSize === "string" &&
      Number.isFinite(c.pixelRatio) &&
      Number.isFinite(c.cachedAt) &&
      c.cachedAt <= now &&
      now - c.cachedAt < 300000 &&
      (!c.expires || (typeof c.expires === "string" && Number.isFinite(expires) && now < expires));
    var contextMatches =
      metadataValid &&
      c.width === innerWidth &&
      c.fontSize === getComputedStyle(d).fontSize &&
      c.pixelRatio === devicePixelRatio;
    if (contextMatches && localStorage.getItem("jdx-banner-dismissed") !== c.id)
      d.style.setProperty("--vp-layout-top-height", c.height);
    else if (c && !metadataValid)
      localStorage.removeItem("jdx-banner-cache");
  } catch (e) {}
})();`,
    ],
    ["link", { rel: "icon", href: "/favicon.ico", sizes: "any" }],
    [
      "link",
      {
        rel: "icon",
        href: "/favicon-16x16.png",
        type: "image/png",
        sizes: "16x16",
      },
    ],
    [
      "link",
      {
        rel: "icon",
        href: "/favicon-32x32.png",
        type: "image/png",
        sizes: "32x32",
      },
    ],
    ["link", { rel: "icon", href: "/favicon.svg", type: "image/svg+xml" }],
    [
      "link",
      {
        rel: "apple-touch-icon",
        href: "/apple-touch-icon.png",
        sizes: "180x180",
      },
    ],
    ["link", { rel: "manifest", href: "/site.webmanifest" }],
    ["meta", { name: "theme-color", content: "#0b1018" }],
    ["meta", { property: "og:site_name", content: "fnox" }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:locale", content: "en_US" }],
    ["meta", { property: "og:image:width", content: "1200" }],
    ["meta", { property: "og:image:height", content: "630" }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
    ["meta", { name: "twitter:site", content: "@jdxcode" }],
  ],
  transformHead({ pageData, title, description, siteConfig }) {
    const heading =
      pageData.relativePath === "index.md"
        ? "Encrypted and remote secrets"
        : pageData.title || "fnox";
    const card = socialCard(heading);
    writeSocialCard(siteConfig.outDir, card);
    const image = new URL(card.path, `${siteUrl}/`).toString();
    const imageAlt = `${heading} — fnox docs`;
    const url = `${siteUrl}/${pageData.relativePath}`
      .replace(/index\.md$/, "")
      .replace(/\.md$/, ".html");

    return [
      ["link", { rel: "canonical", href: url }],
      ["meta", { property: "og:url", content: url }],
      ["meta", { property: "og:image", content: image }],
      ["meta", { property: "og:image:alt", content: imageAlt }],
      ["meta", { name: "twitter:image", content: image }],
      ["meta", { name: "twitter:image:alt", content: imageAlt }],
      ["meta", { property: "og:title", content: title }],
      ["meta", { property: "og:description", content: description }],
      ["meta", { name: "twitter:title", content: title }],
      ["meta", { name: "twitter:description", content: description }],
      [
        "script",
        { type: "application/ld+json" },
        JSON.stringify({
          "@context": "https://schema.org",
          "@type": "WebPage",
          name: title,
          description,
          url,
          isPartOf: { "@type": "WebSite", name: "fnox", url: siteUrl },
        }),
      ],
    ];
  },
});
