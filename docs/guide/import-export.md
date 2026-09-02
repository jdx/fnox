# Import / Export

fnox can import secrets from various formats and export them for use in other tools.

Import requires an encryption provider (`-p`/`--provider`), such as `age`, so that
imported values are encrypted before they are written to the config file. Remote
storage providers (1Password, AWS Secrets Manager, etc.) are not yet supported as
import targets.

## Import from Files

### From .env Files

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

### From Different Formats

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

## Import Options

### With Provider

The provider encrypts secrets during import. It must be an encryption provider
defined in your config (for example `age`, `aws-kms`, or a hardware-backed
`yubikey`/`fido2` provider):

```bash
# Import and encrypt with age
fnox import -i .env --provider age

# Import and encrypt with an aws-kms provider named "kms"
fnox import -i .env --provider kms
```

### With Filters

Import only specific secrets:

```bash
# Import only secrets starting with "DATABASE_"
fnox import -i .env --provider age --filter "^DATABASE_"

# Import only API keys
fnox import -i .env --provider age --filter "^API_"
```

### With Prefix

Add a prefix to all imported secrets:

```bash
# Add "MYAPP_" prefix to all secrets
fnox import -i .env --provider age --prefix "MYAPP_"

# DATABASE_URL becomes MYAPP_DATABASE_URL
# API_KEY becomes MYAPP_API_KEY
```

### Combining Options

```bash
# Import DB secrets with encryption and prefix
fnox import -i .env \
  --filter "^DATABASE_" \
  --prefix "PROD_" \
  --provider age

# DATABASE_URL → PROD_DATABASE_URL (encrypted with age)
# DATABASE_PASSWORD → PROD_DATABASE_PASSWORD (encrypted with age)
```

## Export Secrets

### Export Formats

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

### Save to File

```bash
# Export to file
fnox export > .env
fnox export --format shell > secrets.sh
fnox export --format json > secrets.json
fnox export --format yaml > secrets.yaml
fnox export --format toml > secrets.toml
```

### Export with Profile

```bash
# Export production secrets
fnox export --profile production > .env.production

# Export staging secrets as JSON
fnox export --profile staging --format json > staging.json
```

## Migration Workflows

### From .env to fnox with Encryption

```bash
# 1. Set up age provider
cat >> fnox.toml << 'EOF'
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
EOF

# 2. Import and encrypt all secrets
fnox import -i .env --provider age

# 3. Remove .env file (secrets now encrypted in fnox.toml)
rm .env
```

### From fnox to .env (for legacy tools)

```bash
# Export current secrets to .env
fnox export > .env
```

### Between Providers

```bash
# 1. Export from AWS Secrets Manager
fnox export --profile production --format json > prod-secrets.json

# 2. Switch to age provider
cat >> fnox.toml << 'EOF'
[providers.age]
type = "age"
recipients = ["age1..."]
EOF

# 3. Re-import with new provider
fnox import -i prod-secrets.json json --provider age

# 4. Verify
fnox list
```

### Team Onboarding

```bash
# 1. Export example secrets (with dummy values)
fnox export --format json > secrets.example.json

# 2. Team member fills in real values
cp secrets.example.json secrets.json
# Edit secrets.json with real credentials

# 3. Import with encryption
fnox import -i secrets.json json --provider age

# 4. Delete plaintext file
rm secrets.json
```

## CI/CD Integration

### GitHub Actions Secrets → fnox

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

```bash
# Export for docker-compose
fnox export > .env

# Use in docker-compose.yml
# env_file:
#   - .env
```

### fnox → Kubernetes Secrets

```bash
# Create Kubernetes secret from .env-format output
kubectl create secret generic app-secrets \
  --from-env-file=<(fnox export)
```

## Next Steps

- [Providers](/providers/overview) - Choose providers for your secrets
- [Profiles](/guide/profiles) - Organize secrets by environment
- [Real-World Example](/guide/real-world-example) - Complete project setup
