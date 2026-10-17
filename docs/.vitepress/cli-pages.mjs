// Finish the pages `usage g markdown` writes to docs/cli. Run by `mise run render:usage`.
// Help text and examples live in src/commands; this only adapts the output to the site:
// a frontmatter description, a language on code fences, and links for "See also" lists.
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import spec from "../cli/commands.json" with { type: "json" };

const root = fileURLToPath(new URL("../cli/", import.meta.url));
const walk = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
  );
const command = (path) =>
  path.reduce((cmd, name) => cmd?.subcommands?.[name], spec.cmd);

for (const file of walk(root).filter((file) => file.endsWith(".md"))) {
  const slug = relative(root, file).replaceAll("\\", "/").replace(/\.md$/, "");
  let description;
  let body = readFileSync(file, "utf8");
  if (slug === "index") {
    description = `${spec.about}. Find the fnox command for each task, with global flags.`;
    // The index template leaves out the root command's long help, examples, and footer.
    const examples = spec.examples
      .map(({ header, code }) => `**${header}**\n\n\`\`\`\n${code}\n\`\`\``)
      .join("\n\n");
    // Link the command names in the "Commands by task" list.
    const about = spec.about_long.replace(
      /^ - (.+?): ([a-z, -]+)$/gm,
      (_, task, names) =>
        `- ${task}: ${names
          .split(", ")
          .map((name) => `[${name}](/cli/${name})`)
          .join(", ")}`,
    );
    body = body.replace(/^(- \*\*Usage:\*\* .*)$/m, `$1\n\n${about}`);
    body = `${body.trimEnd()}\n\n## Examples\n\n${examples}\n\n${spec.after_help_long}\n`;
  } else if (slug === "configuration") {
    description =
      "Runtime settings for fnox that come from global flags and environment variables.";
    body = body.replace(
      /^# Configuration\n/m,
      "# Configuration\n\nThese settings come from global flags and environment variables, not from `fnox.toml`. For the config file format, see the [configuration reference](/reference/configuration).\n",
    );
  } else {
    const cmd = command(slug.split("/"));
    if (!cmd?.help) throw new Error(`No help text for fnox ${slug}`);
    description = `${cmd.help}. Usage, flags, and examples for fnox ${slug.replaceAll("/", " ")}.`;
  }
  let fence = false;
  body = body
    .split("\n")
    .map((line) => {
      if (line.startsWith("```")) {
        if (!fence && line === "```") line = "```sh";
        fence = !fence;
        return line;
      }
      if (fence) return line;
      if (line === "See also:") return "## See also\n";
      return line.replace(
        /^- (.+?): (https?:\/\/\S+)$/,
        (_, name, url) => `- [${name}](${url.replace(/^https:\/\/fnox\.jdx\.dev\//, "/")})`,
      );
    })
    .join("\n");
  writeFileSync(
    file,
    `---\ndescription: ${JSON.stringify(description)}\n---\n\n${body.trimEnd()}\n`,
  );
}
