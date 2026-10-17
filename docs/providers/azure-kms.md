---
description: "Encrypt values in fnox.toml with an Azure Key Vault RSA key. Configure Azure CLI, service principal, or managed identity authentication."
---

# Azure Key Vault keys

The `azure-kms` provider encrypts values into `fnox.toml` with an RSA key in Azure Key Vault. The ciphertext lives in your config, but both `fnox set` and every decryption call the Key Vault API.

|                     |                                                   |
| ------------------- | ------------------------------------------------- |
| Config type         | `azure-kms`                                       |
| Storage             | Encrypted in config                               |
| Writes (`fnox set`) | Yes                                               |
| Requires            | Azure credentials and network access to Key Vault |

To keep values out of git entirely, use [Azure Key Vault secrets](/providers/azure-sm).

## Quick start

Create an RSA key in an existing vault:

```sh
az keyvault key create --vault-name myapp-vault --name fnox-key --kty RSA --size 2048
```

Add the provider:

```toml
[providers.azurekms]
type = "azure-kms"
vault_url = "https://myapp-vault.vault.azure.net/"
key_name = "fnox-key"
```

Store a value through the hidden prompt, then use it:

```sh
fnox set DATABASE_URL --provider azurekms
fnox provider test azurekms
fnox exec -- npm start
```

## Authentication

By default (`auth` unset or `"default"`), fnox uses a service principal from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` when all three are set. Otherwise it uses your Azure CLI or Azure Developer CLI login.

### Local development

Run `az login`. When authentication fails in an interactive terminal, fnox offers to run `az login`; override it with [`auth_command`](/reference/configuration#auth-command).

### CI and Azure hosts

Set the three service principal variables from your CI secret store, or run on an Azure host with a managed identity:

```toml
[providers.azurekms]
type = "azure-kms"
vault_url = "https://myapp-vault.vault.azure.net/"
key_name = "fnox-key"
auth = "managed-identity"
```

Without `managed_identity_client_id`, fnox uses the system-assigned identity. See [CI/CD](/guide/ci) for pipeline patterns.

## Configuration

| Field                        | Required | Default     | Description                                                                          |
| ---------------------------- | -------- | ----------- | ------------------------------------------------------------------------------------ |
| `vault_url`                  | Yes      | None        | Vault URL, such as `https://myapp-vault.vault.azure.net/`.                           |
| `key_name`                   | Yes      | None        | Name of the RSA key. fnox uses its current version.                                  |
| `auth`                       | No       | `"default"` | `"default"` (service principal or developer CLI) or `"managed-identity"`.            |
| `managed_identity_client_id` | No       | None        | Client ID of a user-assigned managed identity. Requires `auth = "managed-identity"`. |

All fields accept `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

## How values are stored

`fnox set` encrypts the value with the key using RSA-OAEP-256 and stores the base64-encoded ciphertext as the secret's `value`:

```toml
[secrets]
DATABASE_URL = { provider = "azurekms", value = "kX9fQ2..." } # ciphertext, abbreviated
```

RSA-OAEP-256 encrypts the value in a single block, so it is limited by key size: up to 190 bytes with a 2048-bit key, 318 bytes with 3072, and 446 bytes with 4096. Encrypt longer values with [age](/providers/age) instead.

Decryption asks Key Vault to decrypt with the current key version. Rotating the key to a new version leaves values encrypted under the old version undecryptable, so re-encrypt them through a provider that still works before rotating.

## Permissions

The identity needs the `encrypt`, `decrypt`, and `get` key operations; `get` is used by `fnox provider test`. With Azure RBAC, the built-in Key Vault Crypto User role covers them:

```sh
az role assignment create \
  --role "Key Vault Crypto User" \
  --assignee "user@example.com" \
  --scope "/subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.KeyVault/vaults/myapp-vault"
```

## Troubleshooting

### `Forbidden` or `Unauthorized`

The identity lacks key permissions, or fnox is using a different identity than you expect. Check which one is active with `az account show`, and whether the service principal variables are set in the fnox process.

### `managed_identity_client_id requires auth = "managed-identity"`

Set `auth = "managed-identity"` on the provider, or remove `managed_identity_client_id`.

### Key not found

Check `vault_url` and `key_name`:

```sh
az keyvault key show --vault-name myapp-vault --name fnox-key
```

## See also

- [Azure Key Vault secrets](/providers/azure-sm): store values in Key Vault instead of in config.
- [Azure token lease](/leases/azure-token): mint short-lived Azure access tokens.
- [age](/providers/age): encryption in config without a cloud dependency.
