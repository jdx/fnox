# Fnox Development Guide

## Conventional Commits

Format: `<type>(<scope>): <description>` (lowercase, imperative mood)

**Types:** `feat`, `fix`, `refactor`, `docs`, `style`, `perf`, `test`, `chore`, `security`

**Scopes:** command names (`get`, `set`, `exec`, `list`, `provider`), provider names (`age`, `1password`, `bitwarden`, `bitwarden-sm`, `aws-kms`, `aws-sm`, `aws-ps`, `keychain`, `keepass`, `infisical`, `passwordstate`, `pass`), subsystems (`config`, `encryption`, `env`, `deps`)

Examples: `fix(aws-sm): handle pagination for large secret lists`, `feat(exec): add --no-inherit flag`

## Build & Test

```bash
mise run build          # Build (debug mode, never use --release)
mise run test           # Run all tests (cargo + bats)
mise run test:cargo     # Cargo tests only
mise run test:bats      # Bats tests only (depends on build)
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

```
src/commands/       # One file per command
src/providers/      # Implement Provider trait
src/encryption/     # Encryption methods
src/config.rs       # Config parsing
src/env.rs          # Centralized env var handling (LazyLock, FNOX_* prefix)
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

**Secret options:**

- `if_missing`: `"error"` | `"warn"` (default) | `"ignore"`
- `as_file = true`: write to temp file instead of env var

**Auth prompting:** on provider auth failure in TTY, fnox prompts to run the provider's auth command (e.g., `aws sso login`, `op signin`). Disable with `prompt_auth = false` in config or `FNOX_PROMPT_AUTH=false`.

## Provider Types

All providers follow the same pattern: config in `fnox.toml` stores references/names, actual secrets live in the provider. See `src/providers/` for implementations.

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

**Common provider config fields:** `type` (required), `prefix` (optional namespace), `region` (AWS providers). Most providers support `value` as item name, `item/field` for specific fields.
