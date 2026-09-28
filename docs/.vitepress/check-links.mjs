// Check rendered links, including fragments and links inside Vue components.
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, resolve, relative } from "node:path";

const root = resolve(process.argv[2] || "docs/.vitepress/dist");
const walk = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
  );
const files = walk(root).filter((file) => file.endsWith(".html"));
const pages = new Map(files.map((file) => [file, readFileSync(file, "utf8")]));
const errors = new Set();
const checked = new Set();
const decode = (s) =>
  s
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
let links = 0;
for (const [file, html] of pages) {
  const base = new URL(relative(root, file), "https://fnox.jdx.dev/");
  for (const [, raw] of html.matchAll(/<a\b[^>]*\bhref="([^"]+)"/g)) {
    const href = decode(raw);
    const url = new URL(href, base);
    if (url.origin !== base.origin) continue;
    links++;
    const key = `${file}:${url.pathname}${url.hash}`;
    if (checked.has(key)) continue;
    checked.add(key);
    let path = join(root, decodeURIComponent(url.pathname));
    if (existsSync(path) && statSync(path).isDirectory())
      path = join(path, "index.html");
    if (!existsSync(path) && !/\.[^/]+$/.test(path)) path += ".html";
    if (!existsSync(path)) {
      errors.add(`${relative(root, file)}: missing page ${href}`);
      continue;
    }
    if (url.hash && pages.has(path)) {
      const ids = new Set(
        [...pages.get(path).matchAll(/\bid="([^"]+)"/g)].map(([, id]) =>
          decode(id),
        ),
      );
      if (!ids.has(decodeURIComponent(url.hash.slice(1))))
        errors.add(`${relative(root, file)}: missing anchor ${href}`);
    }
  }
}
if (errors.size) {
  console.error([...errors].sort().join("\n"));
  process.exitCode = 1;
} else {
  console.log(
    `Checked ${links} internal links across ${files.length} built pages, including anchors.`,
  );
}
