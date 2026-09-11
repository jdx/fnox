# Fnox Development Guide

## mbx build cache

`mise install` installs the mbx version pinned in `mise.toml`. `mise run` activates the project's transparent
Cargo wrapper, so compilation-heavy mise tasks and hk checks use ordinary
`cargo` commands. Standalone Cargo commands require an activated mise shell. If
the wrapper fails or creates a development papercut, rerun the exact equivalent
command from `CONTRIBUTING.md` with `MBX_DISABLE=1`; this unblocks work without
weakening the check. If bypassed Cargo succeeds, surface the mismatch and recommend a
[mr-boxington Discussion](https://github.com/jdx/mr-boxington/discussions) with
the repository and commit, OS, `mbx --version`, `mbx doctor`, and both commands
and outputs. Redact secrets, absolute cache paths, remote URLs, namespaces, and
other sensitive or identifying details. Do not permanently disable the wrapper,
and do not post externally without user authorization.

## Conventional Commits

PR titles must use `<type>[optional scope][optional !]: <description>`. Intermediate commit
subjects should use the same format. Start the description with a lowercase
character and use imperative mood.

**Types:** `feat`, `fix`, `refactor`, `docs`, `style`, `perf`, `test`, `chore`, `ci`, `revert`, `security`

**Scopes:** command names (`get`, `set`, `exec`, `list`, `provider`), provider names (`age`, `1password`, `bitwarden`, `bitwarden-sm`, `aws-kms`, `aws-sm`, `aws-ps`, `keychain`, `keepass`, `infisical`, `passwordstate`, `pass`, `proton-pass`), subsystems (`config`, `encryption`, `env`, `deps`)

Examples: `fix(aws-sm): handle pagination for large secret lists`, `feat(exec): add --no-inherit flag`

CI validates the pull request title and re-runs when it is edited. Intermediate
commit subjects are not checked because pull requests are squash-merged. CI
mechanically checks the allowed type, syntax, and lowercase-leading description;
imperative mood remains a review rule.

## Minimum Supported Rust Version (MSRV)

`rust-version` in the workspace `Cargo.toml` is kept **behind** the latest stable
Rust on purpose. fnox is built from source by packagers that provide their own,
often older, rustc — Linux distro packages (`cargo install` against a
distro-provided toolchain) and nixpkgs (one shared, conservative rustc for the
whole tree). Raising the MSRV can make fnox unbuildable there.

**Do not raise the MSRV to satisfy a dependency.** If a dependency bump requires
a newer rustc than our declared MSRV (the `msrv` CI job, `cargo msrv verify`,
will fail), pin that dependency to its last MSRV-compatible version instead.
`.cargo/config.toml` sets `resolver.incompatible-rust-versions = "fallback"` so
`cargo update`/`cargo add` prefer MSRV-compatible versions automatically.

## Dependency Updates

- Use the lowest compatibility-significant specificity in `Cargo.toml` (for example, `"1"` for stable 1.x dependencies).
- When the existing manifest requirement accepts a routine dependency update, change only `Cargo.lock`.
- Keep lockfile updates focused and avoid unrelated transitive dependency churn.

## Build & Test

```bash
mise run build          # Build (debug mode, never use --release)
mise run test           # Run all tests (cargo + bats)
mise run test:cargo     # Cargo tests only
mise run test:bats      # Bats tests only (run build first)
mise run test:bats -- test/init.bats  # Specific bats test file
mise run ci             # Full CI: build + test + lint
mise run lint           # Lint (hk)
mise run lint-fix       # Auto-fix lint issues
```

**Provider test requirements** (all skip gracefully if credentials unavailable):

- 1Password: `OP_SERVICE_ACCOUNT_TOKEN` env var
- Bitwarden: `BW_SESSION` env var (use `source ./test/setup-bitwarden-test.sh` for local vaultwarden)
- Infisical: `INFISICAL_TOKEN` env var
- KeePass: `KEEPASS_PASSWORD` env var (self-contained, no external services)
- Passwordstate: `PASSWORDSTATE_BASE_URL`, `PASSWORDSTATE_API_KEY`, `PASSWORDSTATE_LIST_ID` env vars

## Code Style

- **Error handling:** `anyhow::Result` in commands, `thiserror`/`FnoxError` for domain errors
- **Logging:** `tracing` (not `println!`)
- **Naming:** modules `snake_case`, structs `PascalCase`, functions `snake_case`, constants `SCREAMING_SNAKE_CASE`, CLI args `kebab-case`
- **Async:** all commands and provider methods are async, `tokio::main` entry point

## Code Organization

```text
src/commands/                    # One file per command
crates/fnox-core/src/providers/  # Provider implementations and encryption
crates/fnox-core/src/config.rs   # Config parsing and layering
crates/fnox-core/src/env.rs      # Centralized FNOX_* environment handling
```

- Use `mod.rs` for module exports
- Import env vars via `use crate::env;` / `env::FNOX_*` — avoid direct `std::env::` calls
- CLI flags: `-P, --profile`, `-p, --provider`, `-d, --description`, `-k, --key-name`

## Environment Variables

- `FNOX_PROFILE` — profile to use (default: "default")
- `FNOX_CONFIG_DIR` — config directory (default: `~/.config/fnox`)
- `FNOX_AGE_KEY` — age encryption key
- `FNOX_PROMPT_AUTH` — enable/disable auth prompting in TTY (default: true)

## Config Structure

**Loading order** (later overrides earlier):

1. `~/.config/fnox/config.toml` (global)
2. Parent directory `fnox.toml` files (recursion, closer = higher priority)
3. `fnox.toml` (project)
4. `fnox.$FNOX_PROFILE.toml` (profile-specific, if not "default")
5. `fnox.local.toml` (local overrides, gitignored)

Steps 3-5 apply at each discovered directory, from outermost to innermost. A closer directory overrides its parent, including parent-local values.

An explicit `-c/--config` path skips steps 2-5 (no directory recursion, no local
overrides) but still loads the global config and the file's own `import`s.

**Secret options:**

- `if_missing`: `"error"` | `"warn"` (default) | `"ignore"`
- `as_file = true`: write to temp file instead of env var

**Auth prompting:** on provider auth failure in TTY, fnox prompts to run the provider's auth command (e.g., `aws sso login`, `op signin`). Disable with `prompt_auth = false` in config or `FNOX_PROMPT_AUTH=false`.

## Provider Types

Encryption providers store ciphertext in `fnox.toml`; remote and local storage providers store references there. The plain provider returns unencrypted values. See `crates/fnox-core/src/providers/` for implementations and `docs/providers/overview.md` for the complete provider catalog.

| Type                | Config `type`    | Storage                   | Key crate/CLI            |
| ------------------- | ---------------- | ------------------------- | ------------------------ |
| Age                 | `age`            | Encrypted in config       | `age` crate              |
| 1Password           | `1password`      | 1Password vault           | `op` CLI                 |
| Bitwarden           | `bitwarden`      | Bitwarden vault           | `bw` CLI                 |
| Bitwarden SM        | `bitwarden-sm`   | Bitwarden Secrets Manager | `bws` CLI                |
| AWS KMS             | `aws-kms`        | Encrypted in config       | `aws-sdk-kms`            |
| AWS Secrets Manager | `aws-sm`         | AWS SM                    | `aws-sdk-secretsmanager` |
| AWS Parameter Store | `aws-ps`         | AWS SSM                   | `aws-sdk-ssm`            |
| Keychain            | `keychain`       | OS keychain               | `keyring` crate          |
| KeePass             | `keepass`        | `.kdbx` file              | `keepass-rs` crate       |
| Infisical           | `infisical`      | Infisical                 | `infisical` CLI          |
| Passwordstate       | `passwordstate`  | Passwordstate server      | `reqwest` HTTP           |
| password-store      | `password-store` | GPG files                 | `pass` CLI               |
| Proton Pass         | `proton-pass`    | Proton Pass vault         | `pass-cli` CLI           |

**Provider fields:** `type` is required. Fields such as `prefix`, `region`, and `vault` depend on the provider type; use its schema and guide for supported fields and reference formats.

## PR titles and descriptions are release-note inputs

PR titles and descriptions are source material for release notes, including those
generated by Communique. Write them for a fnox user who has not read the diff
or this conversation.

- **Describe the final result.** Before requesting review and again after feedback
  changes the implementation, compare the title and body with the complete current
  diff. Rewrite both when the scope changes. Remove abandoned approaches, stale
  requirements, and claims that the final code or validation no longer supports.
- **Lead with the user-visible change.** Keep the conventional commit format, but
  name the affected behavior and outcome in the title. Open the body with the
  problem or use case and what users can now do. Avoid titles such as "address
  feedback" or "fix CI" when the PR's actual purpose is a feature or behavior fix.
  For internal-only work, explain the concrete maintainer or contributor benefit
  without inventing a user-facing impact.
- **Make the change concrete.** For new configuration, commands, or APIs, include
  a small, valid example and explain its result. For a bug fix, describe the trigger
  and before/after behavior. For visible UI or output changes, include actual
  before/after screenshots or a short recording when they help reviewers assess the
  change; CLI input/output snippets are often clearer than terminal screenshots.
  Use measured results for performance claims and state how they were measured.
- **Keep the essential facts in text.** Caption screenshots and explain examples.
  A reader or release-note generator should understand the change without opening
  an image, following an external link, or reading the diff. Do not fabricate
  screenshots, output, measurements, or validation results.
- **State adoption details when relevant.** Include new flags or settings, defaults,
  supported platforms, experimental status, required dependency versions, and any
  compatibility changes or migration steps that affect using the feature. Distinguish
  current behavior from planned follow-ups; do not advertise unfinished work.
- **Keep review details proportionate.** Summarize meaningful validation and its
  limitations. Include implementation details only when they explain behavior or a
  tradeoff reviewers need to assess. Omit agent work logs, intermediate commit
  summaries, and exhaustive test-command lists. A small fix can be a short paragraph
  and a test result; screenshots and sections are not mandatory for every PR.

For a hypothetical fix, prefer `fix(get): resolve secrets from the selected profile`
over `fix: address review feedback`. Its description should show a profile selection that previously returned the wrong secret and describe the corrected lookup; use redacted output.
These rules supplement the repository's existing commit, release, and disclosure
requirements.

## GitHub Interactions

Pull request titles must follow the same Conventional Commit format as commits: `<type>[optional scope][optional !]: <description>` in lowercase imperative mood. Do not prefix PR titles with agent/tool labels such as `[codex]` or `[claude]`.

Do not modify version numbers or changelogs in non-release pull requests.

When AI contributes GitHub content—including a pull request description, review, pull request
comment, or discussion post—append this disclosure:

`*AI-assisted — Tool: <tool>; model: <provider>/<model>; version: <version-or-unavailable>.*`

Use the exact model and version identifiers exposed by the runtime. Never infer or guess them; use
`unavailable` when either value is not exposed.
