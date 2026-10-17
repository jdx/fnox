---
description: "Read and write Azure Key Vault secrets with fnox using Azure CLI login, a service principal, or managed identity."
---

# Azure Key Vault secrets

Store secrets in Azure Key Vault and keep only their names in `fnox.toml`. The provider reads and writes: `fnox set` creates the secret or adds a new version.

|                     |                                                       |
| ------------------- | ----------------------------------------------------- |
| Config type         | `azure-sm`                                            |
| Storage             | Remote service                                        |
| Writes (`fnox set`) | Yes                                                   |
| Requires            | Azure credentials and network access to the Key Vault |

## Quick start

Sign in with `az login`, then add a provider and store a value through the hidden prompt:

```toml
[providers.azure]
type = "azure-sm"
vault_url = "https://myapp-vault.vault.azure.net/"
```

Key Vault secret names allow only letters, digits and `-`, so choose the remote name with `--key-name`:

```sh
fnox set DATABASE_URL --provider azure --key-name database-url
```

This creates the secret `database-url` in the vault and adds the reference to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "azure", value = "database-url" }
```

```sh
fnox provider test azure
fnox exec -- ./start-server.sh
```

## Authentication

By default, fnox uses a service principal when `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` are all set, and otherwise uses your Azure CLI or Azure Developer CLI login:

```sh
# Local development
az login          # or: azd auth login

# CI, or anywhere a CLI login is unavailable
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
```

The three service principal variables can also be fnox secrets stored with another provider. `fnox exec` resolves them before it uses the Azure provider. For a single `fnox get`, export them in the environment first.

A service principal signs in through the public-cloud authority, `https://login.microsoftonline.com`. For Azure Government or Azure China, set `AZURE_AUTHORITY_HOST` to that cloud's authority, such as `https://login.microsoftonline.us` or `https://login.chinacloudapi.cn`. The Azure CLI uses the cloud selected with `az cloud set` instead.

When authentication fails in an interactive terminal, fnox offers to run `az login`. Change that command with [`auth_command`](/reference/configuration#auth-command).

### Managed identity

On an Azure host, set `auth = "managed-identity"` to use the host's managed identity:

```toml
[providers.azure]
type = "azure-sm"
vault_url = "https://myapp-vault.vault.azure.net/"
auth = "managed-identity"
managed_identity_client_id = "00000000-0000-0000-0000-000000000000" # omit for the system-assigned identity
```

Managed identity is never tried automatically: it is selected only by `auth = "managed-identity"`, so machines outside Azure do not wait on the instance metadata endpoint.

Managed identity works on Azure VMs and virtual machine scale sets, and on App Service, Azure Functions and Container Apps. The Azure SDK for Rust does not support the Azure Arc, Service Fabric, Cloud Shell or Azure Machine Learning managed identity endpoints.

The same `auth` and `managed_identity_client_id` settings apply to the [Azure Key Vault Keys](/providers/azure-kms) and [Azure App Configuration](/providers/azure-ac) providers.

## Configuration

| Field                        | Required | Default   | Description                                                                                     |
| ---------------------------- | -------- | --------- | ----------------------------------------------------------------------------------------------- |
| `vault_url`                  | Yes      |           | Key Vault URL, such as `https://myapp-vault.vault.azure.net/`.                                  |
| `prefix`                     | No       |           | Prepended to every secret name, for reads and for `fnox set`.                                   |
| `auth`                       | No       | `default` | `default` (service principal variables, then Azure CLI or Developer CLI) or `managed-identity`. |
| `managed_identity_client_id` | No       |           | Client ID of a user-assigned managed identity. Requires `auth = "managed-identity"`.            |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

## Reference formats

A secret's `value` is the Key Vault secret name. fnox prepends the provider's `prefix` and reads the latest version.

| Provider `prefix` | `value`              | Secret fnox reads    |
| ----------------- | -------------------- | -------------------- |
| (none)            | `myapp-database-url` | `myapp-database-url` |
| `myapp-`          | `database-url`       | `myapp-database-url` |

A secret that holds JSON can be narrowed with [`json_path`](/reference/configuration#json-path).

## Permissions

With Azure RBAC, grant the identity a data-plane role on the vault:

| Operation                          | Role                      |
| ---------------------------------- | ------------------------- |
| Read secrets, `fnox provider test` | Key Vault Secrets User    |
| `fnox set`                         | Key Vault Secrets Officer |

```sh
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee "user@example.com" \
  --scope "/subscriptions/SUB-ID/resourceGroups/myapp-rg/providers/Microsoft.KeyVault/vaults/myapp-vault"
```

For a vault that uses access policies, grant secret `Get`, and `Set` for `fnox set`. fnox never lists secrets: `fnox provider test` requests a secret named `fnox-test-secret` and treats "not found" as a successful connection.

## Troubleshooting

### Access denied

The identity authenticated but lacks a data-plane role. Management roles such as Owner or Contributor do not grant secret access. Check which identity fnox used: the service principal when all three `AZURE_*` variables are set, otherwise `az account show`.

### Secret not found

Check the composed name: the provider's `prefix` followed by the secret's `value`.

```sh
az keyvault secret show --vault-name myapp-vault --name myapp-database-url --query id
```

## See also

- [Azure Key Vault Keys](/providers/azure-kms): keep ciphertext in `fnox.toml` instead of a remote store.
- [Azure App Configuration](/providers/azure-ac): read non-secret configuration with the same credentials.
- [Azure token](/leases/azure-token): lease short-lived Azure access tokens to commands.
