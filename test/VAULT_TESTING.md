# HashiCorp Vault Testing

This directory contains tools for testing fnox's HashiCorp Vault integration using a local Vault dev server.

## Quick Start

```bash
# 1. Start the local Vault dev server
source ./test/setup-vault-test.sh

# 2. Run the tests
mise run test:bats -- test/vault.bats
```

## What is HashiCorp Vault?

[HashiCorp Vault](https://www.vaultproject.io/) is a secrets management solution that provides secure storage and access control for secrets, encryption keys, and sensitive data. Vault's dev server mode is perfect for:

- Local development and testing
- Learning Vault features
- Integration testing without production infrastructure

The Vault CLI works seamlessly with both dev and production Vault servers.

## Files

- `docker-compose.vault.yml` - Docker Compose configuration for Vault dev server
- `setup-vault-test.sh` - Helper script to start server and configure environment
- `vault.bats` - Integration tests for Vault provider

## Manual Setup

If you prefer to set things up manually:

```bash
# Start Vault dev server
docker compose -f test/docker-compose.vault.yml up -d

# Export environment variables
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="fnox-test-token"

# Verify connection
vault status

# Run tests
mise run test:bats -- test/vault.bats
```

## Dev Server Features

The Vault dev server:

- Runs in-memory (data is not persisted)
- Automatically unsealed and initialized
- KV v2 secrets engine mounted at `secret/`
- Root token: `fnox-test-token`
- Listens on: `http://localhost:8200`

**⚠️ WARNING:** Dev mode is for testing only. Never use dev mode in production!

## Vault Secrets Structure

Vault uses a Key-Value (KV) secrets engine. In KV v2:

```bash
# Create a secret with multiple fields
vault kv put secret/myapp \
  password="secret123" \
  username="admin" \
  api_key="xyz789"

# Get specific field
vault kv get -field=password secret/myapp
# Output: secret123

# Get all fields as JSON
vault kv get -format=json secret/myapp
```

## fnox Configuration

### Basic Configuration

```toml
[providers.vault]
type = "vault"
address = "http://localhost:8200"

[secrets.DATABASE_PASSWORD]
provider = "vault"
value = "myapp"  # Gets the "value" field by default
```

### With Specific Field

```toml
[secrets.DATABASE_USER]
provider = "vault"
value = "myapp/username"  # Gets the "username" field
```

### With Custom Path Prefix

```toml
[providers.vault]
type = "vault"
address = "http://localhost:8200"
path = "secret/data/production"  # Custom mount path

[secrets.API_KEY]
provider = "vault"
value = "service1"  # Will read from secret/data/production/service1
```

### With Token in Config (Not Recommended)

```toml
[providers.vault]
type = "vault"
address = "http://localhost:8200"
token = "hvs.CAESIAabc123..."  # Better to use environment variable

[secrets.MY_SECRET]
provider = "vault"
value = "myapp"
```

**Best Practice:** Use `VAULT_TOKEN` environment variable instead of storing token in config:

```bash
export VAULT_TOKEN=$(vault login -token-only -method=userpass username=myuser)
fnox get MY_SECRET
```

## Usage Examples

### Creating Secrets

```bash
# Create a secret with default field
vault kv put secret/database value="postgres://localhost/mydb"

# Create a secret with multiple fields
vault kv put secret/api \
  token="abc123" \
  endpoint="https://api.example.com" \
  timeout="30s"
```

### Using with fnox

```bash
# Get secret
fnox get DATABASE_PASSWORD

# Use in command
fnox exec -- ./my-app

# Export to environment
eval "$(fnox export)"
echo $DATABASE_PASSWORD
```

## Cleanup

```bash
# Stop the server (data is lost anyway in dev mode)
docker compose -f test/docker-compose.vault.yml down

# View logs if needed
docker compose -f test/docker-compose.vault.yml logs
```

## CI/CD Integration

The project includes automated Vault testing in GitHub Actions using the official Vault dev server.

### How it works

On **all agents** (Linux via Docker, macOS via `vault server -dev`):

1. Buildkite starts Vault in dev mode (Docker on Linux, native on macOS)
2. Environment variables are exported via `BUILDKITE_ENV_FILE`:
   - `VAULT_ADDR=http://localhost:8200`
   - `VAULT_TOKEN=fnox-test-token`
3. Tests run with full Vault integration
4. Each test creates/deletes its own secrets

### Buildkite Setup

The pipeline starts Vault per OS in `.buildkite/scripts/setup-services.sh`:

```bash
# Linux agents
docker run -d --name vault --cap-add=IPC_LOCK \
  -p 8200:8200 \
  -e VAULT_DEV_ROOT_TOKEN_ID=fnox-test-token \
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
  hashicorp/vault:latest

# macOS agents
vault server -dev \
  -dev-root-token-id=fnox-test-token \
  -dev-listen-address=127.0.0.1:8200 &

echo "export VAULT_ADDR=http://localhost:8200" >> "$BUILDKITE_ENV_FILE"
echo "export VAULT_TOKEN=fnox-test-token" >> "$BUILDKITE_ENV_FILE"
```

### Testing CI changes locally

You can simulate the CI environment locally:

```bash
# Start Vault
docker compose -f test/docker-compose.vault.yml up -d

# Export environment
source ./test/setup-vault-test.sh

# Run tests
mise run test:bats -- test/vault.bats

# Cleanup
docker compose -f test/docker-compose.vault.yml down
```

## Troubleshooting

### "VAULT_TOKEN not available"

Make sure you've:

1. Started Vault: `docker compose -f test/docker-compose.vault.yml up -d`
2. Exported environment: `source ./test/setup-vault-test.sh`

Or manually:

```bash
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="fnox-test-token"
```

### "Cannot authenticate with Vault"

Check if Vault is running:

```bash
docker compose -f test/docker-compose.vault.yml ps
curl http://localhost:8200/v1/sys/health
```

### "vault CLI not installed"

Install via mise:

```bash
mise install vault
```

Or download from [releases](https://developer.hashicorp.com/vault/downloads):

```bash
# macOS
brew tap hashicorp/tap
brew install hashicorp/tap/vault

# Linux
wget https://releases.hashicorp.com/vault/1.15.0/vault_1.15.0_linux_amd64.zip
unzip vault_1.15.0_linux_amd64.zip
sudo mv vault /usr/local/bin/
```

### Docker not running

Make sure Docker Desktop is running:

```bash
docker info
```

## Production Usage

For production Vault instances:

```toml
[providers.vault]
type = "vault"
address = "https://vault.example.com"

[secrets.PROD_SECRET]
provider = "vault"
value = "production/database/password"
```

Authenticate using:

```bash
# Using token
export VAULT_TOKEN=$(vault login -token-only -method=userpass username=myuser)

# Or store encrypted token in fnox with age provider
fnox set VAULT_TOKEN "hvs.CAESIAabc..." --provider age
export VAULT_TOKEN=$(fnox get VAULT_TOKEN)

# Then use fnox
fnox get PROD_SECRET
```

## Comparison with Other Providers

| Feature                 | Vault  | 1Password  | Bitwarden            | AWS SM |
| ----------------------- | ------ | ---------- | -------------------- | ------ |
| Self-hosted             | ✅ Yes | ❌ No      | ✅ Yes (vaultwarden) | ❌ No  |
| Open source             | ✅ Yes | ❌ No      | ✅ Yes               | ❌ No  |
| Free tier               | ✅ Yes | ❌ Limited | ✅ Yes               | ✅ Yes |
| Enterprise features     | ✅ Yes | ✅ Yes     | ✅ Yes               | ✅ Yes |
| Dev mode                | ✅ Yes | ❌ No      | ✅ Yes               | ❌ No  |
| KV storage              | ✅ Yes | ✅ Yes     | ✅ Yes               | ✅ Yes |
| Dynamic secrets         | ✅ Yes | ❌ No      | ❌ No                | ❌ No  |
| Encryption as a Service | ✅ Yes | ❌ No      | ❌ No                | ✅ KMS |

## Security Best Practices

1. **Never store tokens in config files** - Use environment variables or fnox with age encryption
2. **Use short-lived tokens** - Enable token TTL and renewal
3. **Enable TLS in production** - Use HTTPS for Vault address
4. **Use least privilege** - Create tokens with minimal required policies
5. **Rotate tokens regularly** - Implement token rotation
6. **Enable audit logging** - Track all secret access
7. **Use namespaces** - Isolate different environments/teams

## References

- [Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Vault CLI Reference](https://developer.hashicorp.com/vault/docs/commands)
- [KV Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/kv)
- [Vault Dev Server](https://developer.hashicorp.com/vault/docs/concepts/dev-server)
