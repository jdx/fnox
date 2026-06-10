# HashiCorp Vault

HashiCorp Vault provides advanced secret management with dynamic secrets, leasing, and fine-grained access control.

## Prerequisites

- Vault server running (self-hosted or HCP Vault)
- Vault CLI installed
- Vault token with appropriate policies

## Installation

```bash
# macOS
brew install vault

# Linux
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault
```

## Configuration

```toml
[providers]
vault = { type = "vault", path = "secret/myapp" } # address and token are optional
```

- **address**: (Optional) The Vault server address. Falls back to `FNOX_VAULT_ADDR` or `VAULT_ADDR`.
- **path**: (Required) The base path for secrets in Vault (e.g., `secret/myapp`).
- **token**: (Optional) Vault token. Falls back to `FNOX_VAULT_TOKEN` or `VAULT_TOKEN`.
- **namespace**: (Optional) Vault namespace. Falls back to `FNOX_VAULT_NAMESPACE` or `VAULT_NAMESPACE`.
- **credential_command**: (Optional) Shell command that prints a Vault token to stdout when no token is configured. The command is rendered as a Tera template and receives `address`, `path`, and `namespace`.

### Provider-scoped Login

Use `credential_command` when different Vault/OpenBao providers need different tokens:

```toml
[providers.vault_team_a]
type = "vault"
address = "https://vault.example.com"
namespace = "team-a"
path = "secret/team-a"
credential_command = "vault login -method=oidc -token-only"
```

fnox sets `VAULT_ADDR` and `VAULT_NAMESPACE` for the command from the provider config. The command runs through the platform shell, so shell features like pipes and redirects work. Output is cached briefly for the current fnox process so resolving multiple secrets from the same provider does not repeat the login.

## Setup

### 1. Configure Vault Access

```bash
# Set Vault address
export VAULT_ADDR="https://vault.example.com:8200"

# Login and get token
vault login -method=userpass username=myuser

# Or export existing token
export VAULT_TOKEN="hvs.CAESIJ..."
```

### 2. Create Policy

```hcl
# policy.hcl
path "secret/data/myapp/*" {
  capabilities = ["read"]
}

path "secret/metadata/myapp/*" {
  capabilities = ["list"]
}
```

```bash
vault policy write fnox-policy policy.hcl
```

### 3. Store Secrets in Vault

```bash
# KV v2 engine
vault kv put secret/myapp/database url="postgresql://prod.example.com/db"
vault kv put secret/myapp/api-key value="sk_live_abc123"
```

### 4. Reference in fnox

```toml
[secrets]
DATABASE_URL = { provider = "vault", value = "database/url" }  # → secret/myapp/database/url
API_KEY = { provider = "vault", value = "api-key/value" }  # → secret/myapp/api-key/value
```

## Usage

```bash
# Set token
export VAULT_TOKEN="hvs.CAESIJ..."

# Get secrets
fnox get DATABASE_URL

# Run commands
fnox exec -- ./app
```

## Pros

- ✅ Advanced features (dynamic secrets, leasing)
- ✅ Fine-grained access policies
- ✅ Audit logging
- ✅ Multi-cloud support
- ✅ Self-hosted option

## Cons

- ❌ Complex to set up and operate
- ❌ Requires Vault infrastructure
- ❌ Token management

## Next Steps

- [Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [AWS Secrets Manager](/providers/aws-sm) - Simpler cloud alternative
