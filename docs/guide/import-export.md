# Import / Export

fnox can import secrets from various formats and export them for use in other tools.

## Import from Files

### From .env Files

```bash
# Import from .env file
fnox import -i .env

# Import and specify provider
fnox import -i .env --provider age
```

**Example .env file:**

```bash
DATABASE_URL=postgresql://localhost/mydb
API_KEY=sk_test_abc123
JWT_SECRET=super-secret-jwt-key
```

### From stdin

```bash
# Pipe from another source
cat .env | fnox import

# Using here-doc
fnox import << 'EOF'
DATABASE_URL=postgresql://localhost/mydb
API_KEY=sk_test_abc123
EOF
```

### From Different Formats

```bash
# JSON
fnox import -i secrets.json json

# YAML
fnox import -i secrets.yaml yaml

# TOML
fnox import -i secrets.toml toml
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

Encrypt secrets during import:

```bash
# Import and encrypt with age
fnox import -i .env --provider age

# Import and store in AWS Secrets Manager
fnox import -i .env --provider aws
```

### With Filters

Import only specific secrets:

```bash
# Import only secrets starting with "DATABASE_"
fnox import -i .env --filter "^DATABASE_"

# Import only API keys
fnox import -i .env --filter "^API_"
```

### With Prefix

Add a prefix to all imported secrets:

```bash
# Add "MYAPP_" prefix to all secrets
fnox import -i .env --prefix "MYAPP_"

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

# Export as JSON
fnox export --format json

# Export as YAML
fnox export --format yaml

# Export as TOML
fnox export --format toml
```

### Save to File

```bash
# Export to file
fnox export > .env
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
fnox exec env | grep -v '^_' > .env

# Or use export command
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
        run: fnox import -i secrets.env --provider age
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
# Export as YAML
fnox export --format yaml > secrets.yaml

# Create Kubernetes secret
kubectl create secret generic app-secrets \
  --from-env-file=<(fnox export)
```

## Best Practices

1. **Always use providers when importing sensitive data:**

   ```bash
   fnox import -i .env --provider age  # Good
   fnox import -i .env                 # Bad (stores as plaintext)
   ```

2. **Delete plaintext files after import:**

   ```bash
   fnox import -i .env --provider age
   rm .env  # Remove plaintext
   ```

3. **Use filters for selective import:**

   ```bash
   # Import only production secrets
   fnox import -i all-secrets.env --filter "^PROD_"
   ```

4. **Verify imports:**

   ```bash
   fnox import -i .env --provider age
   fnox list  # Check imported secrets
   ```

5. **Export to non-version-controlled files:**
   ```bash
   echo ".env" >> .gitignore
   fnox export > .env
   ```

## Example: Migrating from direnv

```bash
# 1. Export from direnv .envrc
cat .envrc | grep '^export' | sed 's/^export //' > .env

# 2. Import to fnox with encryption
fnox import -i .env --provider age

# 3. Verify
fnox list

# 4. Update .envrc to use fnox
cat > .envrc << 'EOF'
eval "$(fnox activate bash)"
EOF

# 5. Clean up
rm .env
```

## Next Steps

- [Providers](/providers/overview) - Choose providers for your secrets
- [Profiles](/guide/profiles) - Organize secrets by environment
- [Real-World Example](/guide/real-world-example) - Complete project setup
