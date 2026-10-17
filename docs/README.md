# Documentation contributor guide

The public site is built with VitePress and deployed at [fnox.jdx.dev](https://fnox.jdx.dev). Run the commands below from the repository root. This README is for contributors and is excluded from the published site.

## Local development

Install the project tools with `mise install`, then:

```sh
aube install
aube run docs:dev
```

Open the URL printed by VitePress. If the default port is occupied, VitePress chooses another port.

## Build and preview

```sh
aube run docs:build
aube run docs:preview
```

The production build validates local links and anchors, generates page-specific social images, and checks their metadata. Check the affected pages at desktop and mobile widths, in light and dark themes. For UI changes, verify keyboard focus, navigation, search, and code copying.

## Where content belongs

| Path                                           | Purpose                                                        |
| ---------------------------------------------- | -------------------------------------------------------------- |
| `index.md` and `.vitepress/theme/HomePage.vue` | Product landing page and interactive example                   |
| `guide/`                                       | Setup walkthroughs and task-oriented guides                    |
| `providers/`                                   | Provider authentication, configuration, references, and limits |
| `leases/`                                      | Temporary-credential backend setup and behavior                |
| `reference/`                                   | Configuration fields and environment variables                 |
| `cli/`                                         | Generated command and runtime-settings reference               |
| `.vitepress/navigation.mjs`                    | Section-specific sidebar organization                          |
| `.vitepress/theme/style.css`                   | Shared typography, themes, and responsive landing styles       |
| `public/schema.json`                           | Generated configuration schema                                 |

## Writing conventions

Lead with the task or behavior, then prerequisites and a working example. Explain what a command reads, writes, or prints when that distinction matters. Link to shared explanations instead of repeating them on every provider page.

- Use sentence case for prose headings; preserve product names and literal config keys.
- Add a concise `description` in page frontmatter for search and social previews.
- Use root-relative site links such as `/guide/quick-start` in public pages. Keep established paths and anchors, or update every inbound link when changing them.
- Give every code fence a language (`sh`, `toml`, `json`, or `text` for output).
- Make TOML blocks valid syntax, including fragments. Do not repeat the same key to show alternatives in one block.
- Label abbreviated ciphertext and recipients. Prefer `fnox set KEY` with hidden input over examples containing realistic credentials.
- State setup prerequisites and distinguish complete workflows from excerpts.
- Link to vendor pricing instead of maintaining dated price tables.

## Generated reference

The CLI pages in `cli/` come from the Rust command definitions, the same source as `fnox <command> --help`. `mise run render:usage` writes the usage spec (`fnox.usage.kdl`), renders one page per command with `usage g markdown`, and runs `.vitepress/cli-pages.mjs`, which adds each page's frontmatter `description`, gives code fences a language, and turns "See also" lists into site links. Formatting runs last.

```sh
mise run build
mise run render:usage
```

Edit help text in `src/commands/`, on the struct that defines each command:

- The doc comment's first line is the short description shown in `fnox --help` and the start of the page description. Use a verb phrase in sentence case with no trailing period.
- Later paragraphs are the long help: what the command reads, writes, and prints. Indent list items by one space (`///  - item`) so they keep their line breaks.
- `#[usage(example("fnox ...", header = "..."))]` adds an example to `--help` and the page. Every public command needs at least one.
- `after_long_help = "See also:\n- Page name: https://fnox.jdx.dev/path"` adds related links.
- Field doc comments are flag and argument help. Do not repeat a default that `default = "..."` already declares.

Runtime settings on `cli/configuration.md` come from the doc comments and `#[usage(...)]` attributes on `SettingsData` in `crates/fnox-core/src/settings.rs`. Do not hand-edit generated Markdown: regeneration replaces it. A new public command also needs a place in the CLI sidebar (`commandGroups` in `.vitepress/navigation.mjs`).

Regenerate the configuration schema with `mise run render:schema`, or both sets of artifacts with `mise run render`. CI checks that generation produces no diff.

The changelog is also generated. Preserve published release history; update the release tooling when its format needs to change.

## Deployment

[The docs workflow](../.github/workflows/docs.yml) builds and deploys GitHub Pages on pushes to `main` or a manual workflow dispatch. Local builds do not publish the site.

For social image maintenance, see [.vitepress/SOCIAL-IMAGES.md](.vitepress/SOCIAL-IMAGES.md). The bundled font and license are described in [.vitepress/fonts/README.md](.vitepress/fonts/README.md).
