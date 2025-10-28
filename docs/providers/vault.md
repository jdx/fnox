# HashiCorp Vault

HashiCorp Vault provides advanced secret management with dynamic secrets, leasing, and fine-grained access control.

## When to Use

- ✅ Already running Vault
- ✅ Need dynamic secrets
- ✅ Multi-cloud support required
- ✅ Complex access policies
- ✅ Secret leasing/rotation

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
[providers.vault]
type = "vault"
address = "https://vault.example.com:8200"
path = "secret/myapp"  # KV v2 mount path
# token = "hvs.CAESIJ..."  # Optional, can use VAULT_TOKEN env var
```

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
[secrets.DATABASE_URL]
provider = "vault"
value = "database/url"  # → secret/myapp/database/url

[secrets.API_KEY]
provider = "vault"
value = "api-key/value"  # → secret/myapp/api-key/value
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
