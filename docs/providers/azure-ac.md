---
description: "Load Azure App Configuration values with fnox, including label selection, prefixes, and Azure authentication."
---

# Azure App Configuration

Azure App Configuration is the Azure store for non-secret configuration: endpoints, feature toggles, tuning values. This provider reads key-values from it, so configuration your infrastructure owns can be resolved instead of hardcoded in `fnox.toml`.

Read-only. Use [Azure Key Vault Secrets](/providers/azure-sm) for anything sensitive.

## Quick start

```sh
# Create the store
az appconfig create --name "myapp-config" --resource-group "myapp-rg" --location westeurope
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
appconfig = { type = "azure-ac", endpoint = "https://myapp-config.azconfig.io" }
```

```sh
# Set a key-value
az appconfig kv set --name "myapp-config" --key "api-url" --value "https://api.example.com"
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[secrets]
API_URL = { provider = "appconfig", value = "api-url" }
```

```sh
# Get value
fnox get API_URL
```

## Authentication

```bash
# Azure CLI
az login

# Azure Developer CLI
azd auth login
```

## Permissions

Grant read access via RBAC:

```bash
az role assignment create \
  --role "App Configuration Data Reader" \
  --assignee "user@example.com" \
  --scope "/subscriptions/SUB-ID/resourceGroups/myapp-rg/providers/Microsoft.AppConfiguration/configurationStores/myapp-config"
```

## Configuration

```toml
[providers]
appconfig = { type = "azure-ac", endpoint = "https://myapp-config.azconfig.io", label = "dev", prefix = "myapp/" }  # label and prefix are optional
```

A key in App Configuration can carry several values distinguished by a label, so `label` maps naturally onto profiles:

```toml
[profiles.dev.providers]
appconfig = { type = "azure-ac", endpoint = "https://myapp-config.azconfig.io", label = "dev" }

[profiles.prod.providers]
appconfig = { type = "azure-ac", endpoint = "https://myapp-config.azconfig.io", label = "prod" }
```

Without `label`, the key-value with no label is returned.

The `endpoint` must be an HTTPS App Configuration domain: `*.azconfig.io`, or `*.azconfig.azure.us` and `*.azconfig.azure.cn` for Azure Government and Azure China. Anything else is rejected, since the endpoint is where fnox sends your Entra token. The audience follows the domain, so sovereign stores work without extra configuration.

## Usage notes

This provider is read-only and intended for non-secret configuration. Use labels to select environment-specific values and Azure Key Vault Secrets for sensitive values.

## Next steps

- [Azure Key Vault Secrets](/providers/azure-sm) - For actual secrets
- [Profiles](/guide/profiles) - Per-environment labels
