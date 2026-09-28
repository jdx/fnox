---
description: "Import secrets from environment files or structured data, export resolved values, and migrate between providers."
---

# Import and export

Import existing values into an encryption provider, or export resolved secrets for another tool. Exported values are plaintext; fnox does not turn them into dummy examples.

Import requires an encryption provider (`-p`/`--provider`), such as `age`, so that
imported values are encrypted before they are written to the config file. Remote
storage providers (1Password, AWS Secrets Manager, etc.) are not yet supported as
import targets.

## Import from files

### From .env files

```bash
# Import from .env file, encrypting with the "age" provider
fnox import -i .env --provider age

# Preview without writing anything
fnox import -i .env --provider age --dry-run
```

**Example .env file:**

```bash
DATABASE_URL=postgresql://localhost/mydb
API_KEY=sk_test_abc123
JWT_SECRET=super-secret-jwt-key
```

### From stdin

When reading from stdin, pass `--force` (or `--dry-run`): the confirmation prompt
cannot read from stdin because the secrets are being read from it.

```bash
# Pipe from another source
cat .env | fnox import --provider age --force

# Using here-doc
fnox import --provider age --force << 'EOF'
DATABASE_URL=postgresql://localhost/mydb
API_KEY=sk_test_abc123
EOF
```

### From different formats

```bash
# JSON
fnox import -i secrets.json json --provider age

# YAML
fnox import -i secrets.yaml yaml --provider age

# TOML
fnox import -i secrets.toml toml --provider age
```

**Example secrets.json:**

```json
{
  "DATABASE_URL": "postgresql://localhost/mydb",
  "API_KEY": "sk_test_abc123"
}
```

**Example secrets.yaml:**

```yaml
DATABASE_URL: postgresql://localhost/mydb
API_KEY: sk_test_abc123
```

## Import options

### With provider

The provider encrypts secrets during import. It must be an encryption provider
defined in your config (for example `age`, `aws-kms`, or a hardware-backed
`yubikey`/`fido2` provider):

```bash
# Import and encrypt with age
fnox import -i .env --provider age

# Import and encrypt with an aws-kms provider named "kms"
fnox import -i .env --provider kms
```

### With filters

Import only specific secrets:

```bash
# Import only secrets starting with "DATABASE_"
fnox import -i .env --provider age --filter "^DATABASE_"

# Import only API keys
fnox import -i .env --provider age --filter "^API_"
```

### With prefix

Add a prefix to all imported secrets:

```bash
# Add "MYAPP_" prefix to all secrets
fnox import -i .env --provider age --prefix "MYAPP_"

# DATABASE_URL becomes MYAPP_DATABASE_URL
# API_KEY becomes MYAPP_API_KEY
```

### Combining options

```bash
# Import DB secrets with encryption and prefix
fnox import -i .env \
  --filter "^DATABASE_" \
  --prefix "PROD_" \
  --provider age

# DATABASE_URL → PROD_DATABASE_URL (encrypted with age)
# DATABASE_PASSWORD → PROD_DATABASE_PASSWORD (encrypted with age)
```

## Export secrets

### Export formats

```bash
# Export as .env format (default)
fnox export

# Export as sourceable POSIX shell
fnox export --format shell

# Export as JSON
fnox export --format json

# Export as YAML
fnox export --format yaml

# Export as TOML
fnox export --format toml

# Include metadata comments in env/shell output
fnox export --header
```

JSON, YAML, and TOML exports wrap the values in a `secrets` object and include `metadata` with the profile, export time, and count. Imports expect a flat name-to-value map instead. To produce JSON that can be imported again, extract the values with [jq](https://jqlang.org/manual/):

```sh
fnox export --format json | jq '.secrets'
```

For `as_file = true` secrets, export returns paths to temporary files rather than their contents. Export is therefore not a complete backup of configuration or file secrets.

### Save to file

Create private output files and keep them out of version control. In a POSIX shell, `umask 077` restricts permissions on newly created files:

```sh
umask 077
```

```bash
# Export to file
fnox export > .env
fnox export --format shell > secrets.sh
fnox export --format json > secrets.json
fnox export --format yaml > secrets.yaml
fnox export --format toml > secrets.toml
```

`--dry-run` suppresses writing only when you also provide `--output`. Without an output path, export still prints the resolved values to stdout.

### Export with profile

```bash
# Export production secrets
fnox export --profile production > .env.production

# Export staging secrets as JSON
fnox export --profile staging --format json > staging.json
```

## Migration workflows

### From .env to fnox

First [configure an age provider](/guide/quick-start), then preview and import:

```sh
fnox import -i .env --provider age --dry-run
fnox import -i .env --provider age
fnox check --all
fnox exec -- npm start
```

Review the encrypted configuration before committing. Keep `.env` ignored, and remove the plaintext file when the application no longer needs it.

### From a remote provider to local encryption

To retain remote references and make a personal cache, use [`fnox sync`](/guide/sync).

To migrate values into an encryption provider permanently, export and import through a pipe in Bash or Zsh:

```sh
fnox export --profile production --format json |
  jq '.secrets' |
  fnox import json --provider age --force
```

This example requires `jq` and an age provider in the destination profile. It writes into the import command's active profile. Select `--profile` explicitly on each command when source and destination differ. Export follows shell injection settings; add `--all` only when you intend to include `env = false` and `env = "exec"` secrets.

### Create an onboarding template

Write dummy values explicitly. `fnox export` returns real resolved values, even if the output filename contains `example`:

```json
{
  "DATABASE_URL": "postgresql://localhost/example",
  "API_KEY": "replace-me"
}
```

A teammate can fill in a private copy and import it with `fnox import -i secrets.json json --provider age`.

## CI/CD integration

The examples below assume fnox, the target encryption provider, and the destination tools are already configured.

### GitHub Actions secrets → fnox

```yaml
# .github/workflows/setup-secrets.yml
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - name: Create secrets file
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          API_KEY: ${{ secrets.API_KEY }}
        run: |
          cat > secrets.env << EOF
          DATABASE_URL=$DATABASE_URL
          API_KEY=$API_KEY
          EOF

      - name: Import to fnox
        run: fnox import -i secrets.env --provider age --force
```

### fnox → Docker Compose

For Compose environment interpolation, you can avoid a plaintext file with `fnox exec -- docker compose up`. If your service explicitly uses `env_file`, create that file with restricted permissions:

```bash
# Export for docker-compose
fnox export > .env

# Use in docker-compose.yml
# env_file:
#   - .env
```

### fnox → Kubernetes secrets

```bash
# Create Kubernetes secret from .env-format output
kubectl create secret generic app-secrets \
  --from-env-file=<(fnox export)
```

## Next steps

- [Providers](/providers/overview) - Choose providers for your secrets
- [Profiles](/guide/profiles) - Organize secrets by environment
- [Real-World Example](/guide/real-world-example) - Complete project setup
