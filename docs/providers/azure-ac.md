---
description: "Read Azure App Configuration key-values with fnox, including label selection, key prefixes, and Azure authentication."
---

# Azure App Configuration

Read key-values from an Azure App Configuration store, so configuration your infrastructure owns, such as endpoints and tuning values, resolves at run time instead of being hardcoded in `fnox.toml`. The provider is read-only. Use [Azure Key Vault Secrets](/providers/azure-sm) for anything sensitive.

|                     |                                                   |
| ------------------- | ------------------------------------------------- |
| Config type         | `azure-ac`                                        |
| Storage             | Remote service                                    |
| Writes (`fnox set`) | No (read-only)                                    |
| Requires            | Azure credentials and network access to the store |

## Quick start

Sign in with `az login` and create a key-value in the store:

```sh
az appconfig kv set --name myapp-config --key api-url --value "https://api.example.com"
```

Add the provider and a reference:

```toml
[providers.appconfig]
type = "azure-ac"
endpoint = "https://myapp-config.azconfig.io"

[secrets]
API_URL = { provider = "appconfig", value = "api-url" }
```

```sh
fnox provider test appconfig
fnox exec -- ./start-server.sh
```

## Authentication

The provider authenticates the same way as [Azure Key Vault Secrets](/providers/azure-sm#authentication):

- A service principal when `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` are all set.
- Otherwise your Azure CLI (`az login`) or Azure Developer CLI (`azd auth login`) session.
- With `auth = "managed-identity"`, the managed identity of the Azure host. Add `managed_identity_client_id` for a user-assigned identity.

```toml
[providers.appconfig]
type = "azure-ac"
endpoint = "https://myapp-config.azconfig.io"
auth = "managed-identity"
```

## Configuration

| Field                        | Required | Default   | Description                                                                                     |
| ---------------------------- | -------- | --------- | ----------------------------------------------------------------------------------------------- |
| `endpoint`                   | Yes      |           | Store endpoint, such as `https://myapp-config.azconfig.io`.                                     |
| `label`                      | No       | No label  | Label to select. Without it, fnox reads the key-value that has no label.                        |
| `prefix`                     | No       |           | Prepended to every key.                                                                         |
| `auth`                       | No       | `default` | `default` (service principal variables, then Azure CLI or Developer CLI) or `managed-identity`. |
| `managed_identity_client_id` | No       |           | Client ID of a user-assigned managed identity. Requires `auth = "managed-identity"`.            |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

Set `endpoint` to your store's endpoint, `https://<store>.azconfig.io` in the public cloud, `https://<store>.azconfig.azure.us` in Azure Government, or `https://<store>.azconfig.azure.cn` in Azure China. The token audience follows the cloud, so sovereign-cloud stores work without extra configuration.

Because the endpoint is where fnox sends your Entra token, fnox rejects any host outside the App Configuration domains. Besides the store domains above, the validation also accepts the `appconfig.azure.com`, `appconfig.azure.us`, and `appconfig.azure.cn` domains.

## Reference formats

A secret's `value` is the key. fnox prepends the provider's `prefix` and selects the configured `label`.

| Provider `prefix` | `label` | `value`   | Key-value fnox reads            |
| ----------------- | ------- | --------- | ------------------------------- |
| (none)            | (none)  | `api-url` | `api-url` with no label         |
| `myapp/`          | (none)  | `api-url` | `myapp/api-url` with no label   |
| `myapp/`          | `prod`  | `api-url` | `myapp/api-url` labelled `prod` |

fnox returns the stored value as-is. A Key Vault reference comes back as its JSON reference document rather than the secret it points to; reference the secret through [Azure Key Vault Secrets](/providers/azure-sm) instead. For JSON values, select a field with [`json_path`](/reference/configuration#json-path).

## Labels and profiles

One key can carry a value per label, which maps onto fnox [profiles](/guide/profiles):

```toml
[providers.appconfig]
type = "azure-ac"
endpoint = "https://myapp-config.azconfig.io"
label = "dev"

[profiles.prod.providers.appconfig]
type = "azure-ac"
endpoint = "https://myapp-config.azconfig.io"
label = "prod"
```

## Permissions

Grant the identity the **App Configuration Data Reader** role on the store:

```sh
az role assignment create \
  --role "App Configuration Data Reader" \
  --assignee "user@example.com" \
  --scope "/subscriptions/SUB-ID/resourceGroups/myapp-rg/providers/Microsoft.AppConfiguration/configurationStores/myapp-config"
```

`fnox provider test` lists key-values filtered to the key `fnox-connection-test`, so it confirms access without needing any particular key to exist.

## Troubleshooting

### Access denied (401 or 403)

Check that the identity has App Configuration Data Reader on the store, and that the store's network access rules allow your client.

### Key not found

Check the composed key and the label. Without `label`, only the unlabelled key-value matches.

```sh
az appconfig kv list --name myapp-config --key "myapp/*" --label "*" --query "[].{key:key,label:label}"
```

### Endpoint is not an App Configuration domain

The endpoint must be the store's own `https://` URL. Custom domains and proxies are rejected.

## See also

- [Azure Key Vault Secrets](/providers/azure-sm): store sensitive values with the same credentials.
- [Profiles](/guide/profiles): select a label per environment.
