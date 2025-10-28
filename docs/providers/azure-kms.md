# Azure Key Vault Keys

Azure Key Vault Keys encrypts secrets using Azure-managed keys. The encrypted ciphertext is stored in your `fnox.toml` file.

## When to Use

- ✅ Secrets in git (encrypted)
- ✅ Azure-managed encryption keys
- ✅ Azure RBAC integration
- ✅ Azure infrastructure

::: info Storage Mode
This is **local encryption** - the encrypted ciphertext lives in `fnox.toml`. Azure Key Vault is only called to encrypt/decrypt.
:::

## Quick Start

```bash
# 1. Create Key Vault with key
az keyvault key create --vault-name "myapp-vault" --name "encryption-key" --protection software

# 2. Configure provider
cat >> fnox.toml << 'EOF'
[providers.azurekms]
type = "azure-kms"
vault_url = "https://myapp-vault.vault.azure.net/"
key_name = "encryption-key"
EOF

# 3. Encrypt a secret
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider azurekms

# 4. Get secret (decrypts via Azure)
fnox get DATABASE_URL
```

## Permissions

Grant crypto permissions:

```bash
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee "user@example.com" \
  --scope "/subscriptions/.../vaults/myapp-vault"
```

## Configuration

```toml
[providers.azurekms]
type = "azure-kms"
vault_url = "https://myapp-vault.vault.azure.net/"
key_name = "encryption-key"
```

## How It Works

Similar to [AWS KMS](/providers/aws-kms):

1. **Encryption:** Calls Azure Key Vault, stores ciphertext in fnox.toml
2. **Decryption:** Calls Azure Key Vault to recover plaintext

## Pros

- ✅ Secrets in git (version control)
- ✅ Azure-managed keys
- ✅ Azure RBAC integration

## Cons

- ❌ Requires Azure subscription
- ❌ Costs money
- ❌ Network access required

## Next Steps

- [Azure Key Vault Secrets](/providers/azure-sm) - Remote storage alternative
- [Age Encryption](/providers/age) - Free local encryption
