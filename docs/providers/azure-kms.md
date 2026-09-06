---
description: "Encrypt values in fnox.toml with Azure Key Vault keys and decrypt them through the Azure API."
---

# Azure Key Vault keys

Azure Key Vault Keys encrypts secrets using Azure-managed keys. The encrypted ciphertext is stored in your `fnox.toml` file.

## Quick start

Authenticate to Azure and create a Key Vault before following this example. The identity running fnox needs permission to encrypt and decrypt with the key.

```sh
# Create a key in an existing Key Vault
az keyvault key create --vault-name "myapp-vault" --name "encryption-key" --protection software
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
azurekms = { type = "azure-kms", vault_url = "https://myapp-vault.vault.azure.net/", key_name = "encryption-key" }
```

```sh
# Encrypt a secret
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider azurekms

# Get secret (decrypts via Azure)
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
[providers]
azurekms = { type = "azure-kms", vault_url = "https://myapp-vault.vault.azure.net/", key_name = "encryption-key" }
```

## How it works

Similar to [AWS KMS](/providers/aws-kms):

1. **Encryption:** Calls Azure Key Vault, stores ciphertext in fnox.toml
2. **Decryption:** Calls Azure Key Vault to recover plaintext

## Usage notes

Ciphertext lives in your config. Decryption still requires network access and permission to use the Azure key. Keep the key available for all ciphertext that depends on it.

## Next steps

- [Azure Key Vault Secrets](/providers/azure-sm) - Remote storage alternative
- [Age Encryption](/providers/age) - Free local encryption
