# Environment Variables

fnox uses environment variables for configuration and runtime behavior.

## Configuration Variables

### `FNOX_PROFILE`

Active profile name.

```bash
export FNOX_PROFILE=production
```

**Default:** `default`

**Usage:**

```bash
# Use production profile for all commands
export FNOX_PROFILE=production
fnox get DATABASE_URL
fnox exec -- ./deploy.sh
```

### `FNOX_CONFIG_DIR`

Configuration directory path.

```bash
export FNOX_CONFIG_DIR=~/.config/fnox
```

**Default:** `~/.config/fnox`

**Usage:**

```bash
# Use custom config directory
export FNOX_CONFIG_DIR=/opt/fnox
fnox get DATABASE_URL
```

## Encryption Keys

### `FNOX_AGE_KEY`

Age private key (directly as string).

```bash
export FNOX_AGE_KEY="AGE-SECRET-KEY-1..."
```

**Usage:**

```bash
# Set age key from file
export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")

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

Used by AWS providers (`aws-sm`, `aws-kms`).

### Azure

```bash
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_TENANT_ID="..."
```

Used by Azure providers (`azure-sm`, `azure-kms`).

### Google Cloud

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
```

Used by GCP providers (`gcp-sm`, `gcp-kms`).

### 1Password

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
```

Used by 1Password provider.

### Bitwarden

```bash
export BW_SESSION="..."
```

Used by Bitwarden provider.

### HashiCorp Vault

```bash
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="hvs.CAESIJ..."
```

Used by Vault provider.

## Editor

### `EDITOR`

Editor used by `fnox edit`.

```bash
export EDITOR=vim
fnox edit
```

**Default:** System default editor (`vi`, `nano`, etc.)

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

- [Commands Reference](/reference/commands) - All available commands
- [Configuration Reference](/reference/configuration) - Configuration file format
- [Quick Start](/guide/quick-start) - Get started with fnox
