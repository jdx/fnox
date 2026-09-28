---
description: "Reference for fnox environment variables, authentication inputs, configuration paths, missing-secret behavior, and precedence."
---

# Environment variables

Use environment variables for runtime overrides and provider authentication. CLI flags take precedence for corresponding settings such as profile selection and missing-secret handling. Provider-specific credential precedence is documented in each provider guide.

## Configuration variables

### `FNOX_PROFILE`

Active profile name. Supports multiple profiles as a comma-separated
list for ordered overlay composition.

```bash
# Single profile
export FNOX_PROFILE=production

# Multiple profiles (later ones override earlier ones)
export FNOX_PROFILE=aws,prod
```

**Default:** `default`

**Usage:**

```bash
# Use production profile for all commands
export FNOX_PROFILE=production
fnox get DATABASE_URL
fnox exec -- ./deploy.sh

# Compose aws + prod profiles
export FNOX_PROFILE=aws,prod
fnox exec -- ./app
```

### `FNOX_NO_DEFAULTS`

When set to `true`, do not merge top-level secrets into the selected profile.

```bash
export FNOX_NO_DEFAULTS=true
fnox exec --profile production -- ./deploy.sh
```

### `FNOX_CONFIG_DIR`

Configuration directory path.

```bash
export FNOX_CONFIG_DIR=~/.config/fnox
```

**Default:** `$XDG_CONFIG_HOME/fnox` if set, otherwise `~/.config/fnox` on Unix and `%USERPROFILE%\AppData\Local\fnox` on Windows

**Usage:**

```bash
# Use custom config directory
export FNOX_CONFIG_DIR=/opt/fnox
fnox get DATABASE_URL
```

### `FNOX_STATE_DIR`

State directory path. fnox stores the credential lease ledger under
`$FNOX_STATE_DIR/leases/`.

```bash
export FNOX_STATE_DIR=/opt/fnox/state
```

**Default:** `$XDG_STATE_HOME/fnox` if set, otherwise `~/.local/state/fnox` on Unix and `%USERPROFILE%\AppData\Local\fnox` on Windows

### `FNOX_PROMPT_AUTH`

Whether to prompt to run a provider's auth command (e.g., `aws sso login`,
`op signin`) when provider authentication fails in a TTY. Overrides the
`prompt_auth` config setting.

```bash
export FNOX_PROMPT_AUTH=false
```

**Default:** `true`

### `FNOX_NON_INTERACTIVE`

Disable prompts and browser-based auth flows; only cached or non-interactive
auth is used. Equivalent to the `--non-interactive` flag.

```bash
export FNOX_NON_INTERACTIVE=1
fnox exec -- ./deploy.sh
```

### `FNOX_HTTP_TIMEOUT`

HTTP request timeout for lease backend API calls (Vault, GCP IAM, etc.). Set to
`0` to disable the timeout (not recommended).

```bash
export FNOX_HTTP_TIMEOUT=60s
```

**Default:** `30s`

## Encryption keys

### `FNOX_AGE_KEY`

Inline age identity contents. This takes precedence over the age provider's `identity` and `key_file` settings; unset it if you intend to use a different provider-specific identity.

```bash
export FNOX_AGE_KEY="AGE-SECRET-KEY-1..."
```

**Usage:**

```bash
# Set age key from file
export FNOX_AGE_KEY="$(cat ~/.config/fnox/age.txt)"

# Or set directly
export FNOX_AGE_KEY="AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTUVWXYZ..."
```

**Use when:** You want to provide the key directly (CI/CD, scripts).

### `FNOX_AGE_KEY_FILE`

Path to age private key file (or SSH key file).

```bash
export FNOX_AGE_KEY_FILE=~/.config/fnox/age.txt
# Or SSH key:
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519
```

**Usage:**

```bash
# Use age key file
export FNOX_AGE_KEY_FILE=~/.config/fnox/age.txt

# Use SSH key
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519

# Use in shell profile
echo 'export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519' >> ~/.bashrc
```

**Use when:** You want a process-wide key file. For provider-specific keys, prefer `key_file` in the age provider. See the full [identity selection order](/providers/age#set-decryption-key).

## Missing secret handling

### `FNOX_IF_MISSING`

Runtime override for missing secret behavior.

```bash
export FNOX_IF_MISSING=error  # or warn, ignore
```

**Values:**

- `error` - Fail if secret is missing
- `warn` - Print warning and continue (default)
- `ignore` - Silently skip missing secrets

**Priority:** Overrides config file settings, but CLI flags take precedence.

**Usage:**

```bash
# Strict mode (fail on missing secrets)
export FNOX_IF_MISSING=error
fnox exec -- ./deploy.sh

# Lenient mode (ignore missing secrets)
export FNOX_IF_MISSING=ignore
fnox exec -- npm test

# Per-command override
FNOX_IF_MISSING=error fnox exec -- ./critical-task.sh
```

### `FNOX_IF_MISSING_DEFAULT`

Base default for missing secret behavior when not configured anywhere.

```bash
export FNOX_IF_MISSING_DEFAULT=error  # or warn, ignore
```

**Default:** `warn`

**Priority:** Lowest priority. Only applies when:

- CLI flag not set
- `FNOX_IF_MISSING` not set
- Secret-level `if_missing` not set
- Top-level `if_missing` not set in config

**Usage:**

```bash
# Make all projects strict by default
export FNOX_IF_MISSING_DEFAULT=error
echo 'export FNOX_IF_MISSING_DEFAULT=error' >> ~/.bashrc

# Now all fnox commands default to error mode
fnox exec -- ./any-command.sh
```

## Shell integration

### `FNOX_DAEMON`

Enable or disable daemon-backed resolution.

```bash
export FNOX_DAEMON=on   # enable daemon mode
export FNOX_DAEMON=off  # force direct resolution
```

**Values:**

- `on`, `true`, `yes`, `1` - Enable daemon-backed resolution
- `off`, `false`, `no`, `0` - Disable daemon-backed resolution

When set, this overrides the `[daemon].enabled` config setting. When enabled, supported read commands auto-start the per-user daemon and fail closed if the daemon cannot be used. The `--no-daemon` flag disables daemon use for a single invocation.

See [Per-User Daemon](/guide/daemon).

### `FNOX_SHELL_OUTPUT`

Control shell integration output verbosity.

```bash
export FNOX_SHELL_OUTPUT=normal  # or none, debug
```

**Values:**

- `none` - Silent mode (no output)
- `normal` - Show count and secret names (default)
- `debug` - Verbose debugging output

**Usage:**

```bash
# Silent mode
export FNOX_SHELL_OUTPUT=none
cd my-app  # No output

# Normal mode (default)
export FNOX_SHELL_OUTPUT=normal
cd my-app
# fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET

# Debug mode
export FNOX_SHELL_OUTPUT=debug
cd my-app
# fnox: Loading config from /path/to/fnox.toml
# fnox: Active profile: default
# fnox: Resolved 3 secrets
# fnox: +3 DATABASE_URL, API_KEY, JWT_SECRET
```

## Provider-specific variables

Provider configuration may override environment credentials. Follow the linked guide for precedence, scopes, and setup. Not every provider uses the same naming or authentication rules.

| Provider                  | Common variables                                                                               | Guide                                                             |
| ------------------------- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| AWS                       | `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION` | [AWS credentials](/providers/aws-sm#configure-aws-credentials)    |
| Azure                     | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`                                    | [Azure authentication](/providers/azure-sm#authentication)        |
| Google Cloud              | `GOOGLE_APPLICATION_CREDENTIALS`                                                               | [Google Cloud authentication](/providers/gcp-sm#authentication)   |
| 1Password                 | `FNOX_OP_SERVICE_ACCOUNT_TOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`                                    | [1Password](/providers/1password#authentication)                  |
| Bitwarden                 | `FNOX_BW_SESSION`, `BW_SESSION`                                                                | [Bitwarden](/providers/bitwarden)                                 |
| Bitwarden Secrets Manager | `FNOX_BWS_ACCESS_TOKEN`, `BWS_ACCESS_TOKEN`, `BWS_PROJECT_ID`                                  | [Bitwarden SM](/providers/bitwarden-sm#environment-variables)     |
| Doppler                   | `FNOX_DOPPLER_TOKEN`, `DOPPLER_TOKEN`                                                          | [Doppler](/providers/doppler#token-management)                    |
| FOKS                      | `FOKS_BOT_TOKEN`, `FOKS_HOST`, `FOKS_HOME` and `FNOX_` equivalents                             | [FOKS](/providers/foks#cicd)                                      |
| Infisical                 | `INFISICAL_TOKEN`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` and `FNOX_` equivalents    | [Infisical](/providers/infisical)                                 |
| KeePass                   | `FNOX_KEEPASS_PASSWORD`, `KEEPASS_PASSWORD`                                                    | [KeePass](/providers/keepass#authentication)                      |
| Keeper Secrets Manager    | `FNOX_KEEPER_CONFIG`, `KSM_CONFIG`, `FNOX_KEEPER_TOKEN`, `KSM_TOKEN`                           | [Keeper SM](/providers/keeper-sm#authentication)                  |
| Passwordstate             | `FNOX_PASSWORDSTATE_API_KEY`, `PASSWORDSTATE_API_KEY`                                          | [Passwordstate](/providers/passwordstate)                         |
| password-store            | `PASSWORD_STORE_DIR`, `PASSWORD_STORE_GPG_OPTS` and `FNOX_` equivalents                        | [password-store](/providers/password-store#environment-variables) |
| Proton Pass               | `PROTON_PASS_PERSONAL_ACCESS_TOKEN`, `PROTON_PASS_AGENT_REASON` and `FNOX_` equivalents        | [Proton Pass](/providers/proton-pass#session-and-key-storage)     |
| Vault                     | `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE` and `FNOX_` equivalents                         | [Vault](/providers/vault)                                         |

Lease backends may consume the same cloud credentials or additional variables, such as `FNOX_GITHUB_APP_PRIVATE_KEY`. See the [lease backend guides](/guide/leases#supported-backends) for their inputs and output variable names.

## Editor

### `EDITOR`

Editor used by `fnox edit`. If `EDITOR` is unset, fnox falls back to `VISUAL`.

```bash
export EDITOR=vim
fnox edit
```

**Default:** `vi`

## Examples

### Development environment

```bash
# ~/.bashrc or ~/.zshrc

# fnox configuration
export FNOX_PROFILE=default
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519
export FNOX_SHELL_OUTPUT=normal
export FNOX_IF_MISSING=warn

# Enable shell integration
eval "$(fnox activate bash)"
```

### Production environment

```bash
# CI/CD or production server

# Strict mode
export FNOX_PROFILE=production
export FNOX_IF_MISSING=error

# AWS credentials (or use IAM role)
export AWS_REGION=us-east-1

# Age key from secret
export FNOX_AGE_KEY="${CI_SECRET_AGE_KEY}"
```

### CI/CD environment

```yaml
# .github/workflows/deploy.yml
env:
  FNOX_PROFILE: production
  FNOX_IF_MISSING: error
  FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

## Priority order

This ordering applies to runtime settings with equivalent CLI and environment options. Provider credential selection and age identity selection have their own documented precedence.

When multiple configuration methods exist, fnox uses this priority (highest to lowest):

1. **CLI flags** (`--profile`, `--if-missing`)
2. **Environment variables** (`FNOX_PROFILE`, `FNOX_IF_MISSING`)
3. **Configuration file** (`fnox.toml`)
4. **Base defaults** (`FNOX_IF_MISSING_DEFAULT`)
5. **Built-in defaults**

## Next steps

- [CLI Reference](/cli/) - All available commands
- [Configuration Reference](/reference/configuration) - Configuration file format
- [Quick Start](/guide/quick-start) - Get started with fnox
