# Environment Variables

fnox uses environment variables for configuration and runtime behavior.

## Configuration Variables

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

**Default:** `$XDG_CONFIG_HOME/fnox` if set, otherwise `~/.config/fnox`

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

**Default:** `$XDG_STATE_HOME/fnox` if set, otherwise `~/.local/state/fnox`

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

## Encryption Keys

### `FNOX_AGE_KEY`

Age private key (directly as string).

```bash
export FNOX_AGE_KEY="AGE-SECRET-KEY-1..."
```

**Usage:**

```bash
# Set age key from file
export FNOX_AGE_KEY=$(grep "AGE-SECRET-KEY" ~/.config/fnox/age.txt)

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

**Use when:** You want to point to a key file (development, personal use).

## Missing Secret Handling

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

## Shell Integration

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

## Provider-Specific Variables

### AWS

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-east-1"
export AWS_PROFILE="myapp"
```

Used by AWS providers (`aws-sm`, `aws-ps`, `aws-kms`) and the `aws-sts` lease backend.

### Azure

```bash
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_TENANT_ID="..."
```

Used by Azure providers (`azure-sm`, `azure-ac`, `azure-kms`) and the `azure-token` lease backend.

### Google Cloud

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
```

Used by GCP providers (`gcp-sm`, `gcp-kms`) and the `gcp-iam` lease backend.

### 1Password

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."  # Or FNOX_OP_SERVICE_ACCOUNT_TOKEN
```

Used by the 1Password provider.

### Bitwarden

```bash
export BW_SESSION="..."  # Or FNOX_BW_SESSION
```

Used by the Bitwarden provider.

### HashiCorp Vault

```bash
export VAULT_ADDR="https://vault.example.com:8200"   # Or FNOX_VAULT_ADDR
export VAULT_TOKEN="hvs.CAESIJ..."                # Or FNOX_VAULT_TOKEN
export VAULT_NAMESPACE="admin/my-team"            # Or FNOX_VAULT_NAMESPACE
```

Used by the Vault provider and the `vault` lease backend. `FNOX_` prefixed variables take precedence over standard Vault environment variables.

## Editor

### `EDITOR`

Editor used by `fnox edit`. If `EDITOR` is unset, fnox falls back to `VISUAL`.

```bash
export EDITOR=vim
fnox edit
```

**Default:** `vi`

## Examples

### Development Environment

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

### Production Environment

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

### CI/CD Environment

```yaml
# .github/workflows/deploy.yml
env:
  FNOX_PROFILE: production
  FNOX_IF_MISSING: error
  FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

## Priority Order

When multiple configuration methods exist, fnox uses this priority (highest to lowest):

1. **CLI flags** (`--profile`, `--if-missing`)
2. **Environment variables** (`FNOX_PROFILE`, `FNOX_IF_MISSING`)
3. **Configuration file** (`fnox.toml`)
4. **Base defaults** (`FNOX_IF_MISSING_DEFAULT`)
5. **Built-in defaults**

## Next Steps

- [CLI Reference](/cli/) - All available commands
- [Configuration Reference](/reference/configuration) - Configuration file format
- [Quick Start](/guide/quick-start) - Get started with fnox
