// Run after usage-cli generation, before formatting. Never edit generated pages by hand.
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";
import examples from "./cli-examples.json" with { type: "json" };

const root = fileURLToPath(new URL("../cli/", import.meta.url));
const start = "<!-- fnox examples:start -->";
const end = "<!-- fnox examples:end -->";
const walk = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
  );
const labels = {
  "/guide/shell-integration": "Shell integration",
  "/guide/troubleshooting": "Troubleshooting",
  "/guide/missing-secrets": "Missing secrets and defaults",
  "/guide/hierarchical-config": "Config files and overrides",
  "/reference/environment#editor": "Editor selection",
  "/cli/set": "Set a secret",
  "/guide/how-it-works": "How fnox works",
  "/guide/profiles": "Profiles",
  "/guide/import-export": "Import and export",
  "/reference/configuration#env-1": "Secret injection settings",
  "/cli/check": "Check secret access",
  "/guide/quick-start": "Quick start",
  "/cli/tui": "Terminal dashboard",
  "/guide/mcp": "MCP server",
  "/providers/overview": "Provider catalog",
  "/guide/golden-path": "Connect a vault",
  "/providers/age#adding-a-new-team-member": "Update age recipients",
  "/providers/plain": "Plaintext defaults",
  "/reference/configuration#as-file": "File secrets",
  "/contributing": "Contributing",
  "/guide/sync": "Sync a local cache",
  "/guide/tui": "Terminal dashboard",
  "/guide/daemon": "Daemon caching",
  "/guide/leases": "Credential leases",
  "/guide/leases#how-caching-works": "Lease caching",
  "/guide/leases#supported-backends": "Lease backend capabilities",
  "/guide/proxy": "Credential proxy",
};
const seen = new Set();
for (const file of walk(root).filter((file) => file.endsWith(".md"))) {
  const slug = relative(root, file).replaceAll("\\", "/").replace(/\.md$/, "");
  let source = readFileSync(file, "utf8");
  const marker = source.indexOf(start);
  if (marker !== -1) {
    const finish = source.indexOf(end, marker);
    if (finish === -1) throw new Error(`Unclosed examples block: ${file}`);
    source = source.slice(0, marker) + source.slice(finish + end.length);
  }
  source = source.replace(/^---\n[\s\S]*?\n---\n\n/, "");
  let extra;
  let description;
  if (slug === "index") {
    description =
      "Find fnox commands for reading secrets, running applications, configuring providers, and managing caches and temporary credentials.";
    extra = `## Choose a command\n\n| Task | Commands |\n| --- | --- |\n| Read and run | [get](/cli/get), [list](/cli/list), [exec](/cli/exec), [check](/cli/check) |\n| Store or migrate | [set](/cli/set), [import](/cli/import), [export](/cli/export), [sync](/cli/sync) |\n| Configure | [init](/cli/init), [provider](/cli/provider), [profiles](/cli/profiles), [config-files](/cli/config-files) |\n| Diagnose | [doctor](/cli/doctor), [scan](/cli/scan) |\n| Cache and broker | [daemon](/cli/daemon), [lease](/cli/lease), [proxy](/cli/proxy), [mcp](/cli/mcp) |\n\nNew to fnox? Follow the [quick start](/guide/quick-start). Put fnox options before the \`--\` separator in commands such as \`fnox exec -- npm start\`.`;
  } else if (slug === "configuration") {
    description =
      "Generated runtime settings for fnox, including profile selection, missing-secret behavior, and key-file settings.";
    extra =
      "## Configuration file reference\n\nThis page describes generated runtime settings. For the structure of `fnox.toml`, see the [configuration reference](/reference/configuration). For authentication and runtime overrides, see [environment variables](/reference/environment).";
  } else {
    const example = examples[slug];
    if (!example)
      throw new Error(`Add documentation examples for fnox ${slug}`);
    seen.add(slug);
    description = `Usage and examples for fnox ${slug.replaceAll("/", " ")}. ${example.note.split(". ")[0].replace(/\.$/, "")}.`;
    extra = `## Examples\n\n${example.note}\n\n\`\`\`sh\n${example.commands}\n\`\`\`\n\n## Related\n\n${example.links
      .map((link) => {
        if (!labels[link]) throw new Error(`Missing label for ${link}`);
        return `- [${labels[link]}](${link})`;
      })
      .join(
        "\n",
      )}\n- [Global options](/cli/#global-flags), including profile selection and non-interactive mode.`;
  }
  const block = `${start}\n\n${extra}\n\n${end}`;
  const body =
    slug === "index"
      ? source.replace(/\n## /, `\n${block}\n\n## `)
      : `${source.trimEnd()}\n\n${block}`;
  writeFileSync(
    file,
    `---\ndescription: ${JSON.stringify(description)}\n---\n\n${body.trimEnd()}\n`,
  );
}
for (const slug of Object.keys(examples)) {
  if (!seen.has(slug))
    throw new Error(`Examples reference a missing CLI page: ${slug}`);
}
console.log(
  `Enriched ${seen.size} CLI command pages and two reference indexes.`,
);
