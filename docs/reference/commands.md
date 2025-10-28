# Commands Reference

Complete reference for all fnox commands.

## Core Commands

### `fnox init`

Initialize fnox.toml in the current directory.

```bash
fnox init
```

Creates a basic `fnox.toml` file.

### `fnox get <KEY>`

Get a secret value.

```bash
# Get a secret
fnox get DATABASE_URL

# Use with specific profile
fnox get DATABASE_URL --profile production

# Quiet mode (only value, no formatting)
fnox get DATABASE_URL --quiet
```

**Options:**

- `-p, --profile <PROFILE>` - Profile to use
- `-q, --quiet` - Output only the value

### `fnox set <KEY> [VALUE]`

Set a secret (encrypts if provider supports it).

```bash
# Interactive (prompts for value)
fnox set DATABASE_URL

# Provide value directly
fnox set DATABASE_URL "postgresql://localhost/mydb"

# From stdin
echo "secret-value" | fnox set API_KEY

# With provider
fnox set DATABASE_URL "postgresql://..." --provider age

# With description
fnox set API_KEY "sk_..." --provider age --description "Production API key"

# With profile
fnox set DATABASE_URL "..." --profile production --provider aws
```

**Options:**

- `-p, --profile <PROFILE>` - Profile to use
- `-P, --provider <PROVIDER>` - Provider to use for encryption
- `-d, --description <DESC>` - Description for the secret

### `fnox list`

List all secrets.

```bash
# List secrets (values hidden)
fnox list

# List with specific profile
fnox list --profile production

# Show values (dangerous!)
fnox list --show-values
```

**Options:**

- `-p, --profile <PROFILE>` - Profile to use
- `--show-values` - Display actual values (use with caution)

### `fnox remove <KEY>`

Remove a secret from configuration.

```bash
# Remove a secret
fnox remove DATABASE_URL

# Remove from specific profile
fnox remove DATABASE_URL --profile production
```

**Options:**

- `-p, --profile <PROFILE>` - Profile to use

### `fnox exec -- <COMMAND>`

Run a command with secrets loaded as environment variables.

```bash
# Run command with secrets
fnox exec -- npm start

# With profile
fnox exec --profile production -- ./deploy.sh

# Control missing secret behavior
fnox exec --if-missing error -- ./critical-task.sh
fnox exec --if-missing warn -- ./deploy.sh
fnox exec --if-missing ignore -- npm test
```

**Options:**

- `-p, --profile <PROFILE>` - Profile to use
- `--if-missing <MODE>` - How to handle missing secrets (`error`, `warn`, `ignore`)

### `fnox export`

Export secrets in various formats.

```bash
# Export as .env (default)
fnox export

# Export as JSON
fnox export --format json

# Export as YAML
fnox export --format yaml

# Export as TOML
fnox export --format toml

# Export to file
fnox export > .env
fnox export --format json > secrets.json

# Export specific profile
fnox export --profile production
```

**Options:**

- `-p, --profile <PROFILE>` - Profile to use
- `--format <FORMAT>` - Output format (`env`, `json`, `yaml`, `toml`)

### `fnox import`

Import secrets from files.

```bash
# Import from .env file
fnox import -i .env

# Import from stdin
cat .env | fnox import

# Import with provider
fnox import -i .env --provider age

# Import with filters
fnox import -i .env --filter "^DATABASE_"

# Import with prefix
fnox import -i .env --prefix "MYAPP_"

# Import different formats
fnox import -i secrets.json json
fnox import -i secrets.yaml yaml
fnox import -i secrets.toml toml
```

**Options:**

- `-i, --input <FILE>` - Input file
- `-P, --provider <PROVIDER>` - Provider for encryption
- `--filter <REGEX>` - Only import secrets matching regex
- `--prefix <PREFIX>` - Add prefix to all imported secrets

## Management Commands

### `fnox provider list`

List all configured providers.

```bash
fnox provider list
```

### `fnox provider test <NAME>`

Test provider connection.

```bash
# Test a provider
fnox provider test age
fnox provider test aws
fnox provider test onepass
```

### `fnox profiles`

List all available profiles.

```bash
fnox profiles
```

Output:

```
default (active)
staging
production
```

### `fnox edit`

Open configuration in your default editor.

```bash
# Edit config
fnox edit

# Edit with specific editor
EDITOR=vim fnox edit
```

## Diagnostic Commands

### `fnox doctor`

Show diagnostic information.

```bash
fnox doctor
```

Displays:

- fnox version
- Configuration paths
- Active profile
- Provider status
- Environment variables

### `fnox check`

Verify all secrets are configured correctly.

```bash
# Check all secrets
fnox check

# Check specific profile
fnox check --profile production
```

### `fnox scan`

Scan for plaintext secrets in code.

```bash
# Scan current directory
fnox scan

# Scan specific directory
fnox scan src/

# Interactive fix mode
fnox scan --fix
```

## Shell Integration

### `fnox activate <SHELL>`

Generate shell activation code.

```bash
# Bash
eval "$(fnox activate bash)"

# Zsh
eval "$(fnox activate zsh)"

# Fish
fnox activate fish | source
```

**Shells:**

- `bash`
- `zsh`
- `fish`

### `fnox hook-env`

Internal command used by shell hooks. Do not call directly.

### `fnox completion <SHELL>`

Generate shell completions.

```bash
# Bash
fnox completion bash > /usr/local/etc/bash_completion.d/fnox

# Zsh
fnox completion zsh > /usr/local/share/zsh/site-functions/_fnox

# Fish
fnox completion fish > ~/.config/fish/completions/fnox.fish
```

## Developer Tools

### `fnox ci-redact`

Mask secrets in CI logs.

```bash
# Redact secrets from command output
./my-script.sh 2>&1 | fnox ci-redact
```

This ensures secrets aren't leaked in CI logs.

## Global Options

Available on all commands:

- `-c, --config <PATH>` - Path to config file (default: `fnox.toml`)
- `-h, --help` - Show help
- `-V, --version` - Show version
- `-v, --verbose` - Verbose output
- `-q, --quiet` - Minimal output

## Environment Variables

See [Environment Variables Reference](/reference/environment) for details.

## Exit Codes

- `0` - Success
- `1` - General error
- `2` - Configuration error
- `3` - Secret not found
- `4` - Provider error

## Next Steps

- [Environment Variables](/reference/environment) - Environment variable reference
- [Configuration](/reference/configuration) - Configuration file reference
- [Quick Start](/guide/quick-start) - Get started with fnox
