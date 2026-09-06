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

`mise run render:usage` regenerates the CLI pages from the Rust command definitions and the usage specification. It then runs `.vitepress/enrich-cli.mjs` to add maintained examples and related links from `.vitepress/cli-examples.json`, followed by formatting.

```sh
mise run render:usage
```

Edit command descriptions and flags in `src/commands/` or the corresponding usage source. Edit examples and context in `.vitepress/cli-examples.json`. Do not hand-edit generated Markdown: regeneration will replace it. New public commands need an examples entry and a place in the CLI sidebar.

Regenerate the configuration schema with `mise run render:schema`, or both sets of artifacts with `mise run render`. CI checks that generation produces no diff.

The changelog is also generated. Preserve published release history; update the release tooling when its format needs to change.

## Deployment

[The docs workflow](../.github/workflows/docs.yml) builds and deploys GitHub Pages on pushes to `main` or a manual workflow dispatch. Local builds do not publish the site.

For social image maintenance, see [.vitepress/SOCIAL-IMAGES.md](.vitepress/SOCIAL-IMAGES.md). The bundled font and license are described in [.vitepress/fonts/README.md](.vitepress/fonts/README.md).
