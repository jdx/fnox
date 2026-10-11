---
description: "Read Azure Key Vault secrets with fnox. Configure vault access, authentication, prefixes, and profiles."
---

# Azure Key Vault secrets

Azure Key Vault Secrets provides centralized secret management for Azure workloads.

## Quick start

```sh
# Create Key Vault
az keyvault create --name "myapp-vault" --resource-group "myapp-rg"
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
azure = { type = "azure-sm", vault_url = "https://myapp-vault.vault.azure.net/", prefix = "myapp-" }
```

```sh
# Create secret
az keyvault secret set --vault-name "myapp-vault" --name "myapp-database-url" --value "postgresql://..."
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[secrets]
DATABASE_URL = { provider = "azure", value = "database-url" }
```

```sh
# Get secret
fnox get DATABASE_URL
```

## Authentication

By default, fnox uses a service principal when `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` are all set, and otherwise uses your Azure CLI or Azure Developer CLI login:

```bash
# Service principal (CI/CD, or anywhere the CLI login is unavailable)
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."

# Azure CLI or Azure Developer CLI (development)
az login
azd auth login
```

The three service principal variables can also be fnox secrets stored with another provider. `fnox exec` resolves them before it uses the Azure provider. For a single `fnox get`, export them in the environment first.

A service principal signs in through the public-cloud authority, `https://login.microsoftonline.com`. For Azure Government or Azure China, set `AZURE_AUTHORITY_HOST` to that cloud's authority, such as `https://login.microsoftonline.us` or `https://login.chinacloudapi.cn`. The Azure CLI uses the cloud selected with `az cloud set` instead.

On an Azure host, set `auth = "managed-identity"` to use the host's managed identity instead:

```toml
[providers]
azure = { type = "azure-sm", vault_url = "https://myapp-vault.vault.azure.net/", auth = "managed-identity" }

# A user-assigned identity, selected by its client ID
azure-uami = { type = "azure-sm", vault_url = "https://myapp-vault.vault.azure.net/", auth = "managed-identity", managed_identity_client_id = "00000000-0000-0000-0000-000000000000" }
```

Without `managed_identity_client_id`, the system-assigned identity is used. Managed identity is never tried automatically: it is selected only by `auth = "managed-identity"`, so machines outside Azure do not wait on the instance metadata endpoint.

Managed identity works on Azure VMs and virtual machine scale sets, and on App Service, Azure Functions and Container Apps. The Azure SDK for Rust does not support the Azure Arc, Service Fabric, Cloud Shell or Azure Machine Learning managed identity endpoints.

The same `auth` and `managed_identity_client_id` settings apply to the [Azure Key Vault Keys](/providers/azure-kms) and [Azure App Configuration](/providers/azure-ac) providers.

## Permissions

Grant access via RBAC:

```bash
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "user@example.com" \
  --scope "/subscriptions/SUB-ID/resourceGroups/myapp-rg/providers/Microsoft.KeyVault/vaults/myapp-vault"
```

## Configuration

```toml
[providers]
azure = { type = "azure-sm", vault_url = "https://myapp-vault.vault.azure.net/", prefix = "myapp-" }  # prefix is optional
```

| Field                        | Required | Description                                                                                 |
| ---------------------------- | -------- | ------------------------------------------------------------------------------------------- |
| `vault_url`                  | Yes      | Key Vault URL                                                                               |
| `prefix`                     | No       | Prepended to every secret name                                                              |
| `auth`                       | No       | `default` (service principal variables, then Azure CLI/Developer CLI) or `managed-identity` |
| `managed_identity_client_id` | No       | Client ID of a user-assigned managed identity. Requires `auth = "managed-identity"`         |

## Usage notes

The config stores a secret name. Keep the configured prefix consistent with the actual name in Key Vault, and refresh any fnox cache after a value changes.

## Next steps

- [Azure Key Vault Keys](/providers/azure-kms) - Encryption alternative
- [AWS Secrets Manager](/providers/aws-sm) - AWS equivalent
