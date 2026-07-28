# Azure App Configuration

Azure App Configuration is the Azure store for non-secret configuration: endpoints, feature toggles, tuning values. This provider reads key-values from it, so configuration your infrastructure owns can be resolved instead of hardcoded in `fnox.toml`.

Read-only. Use [Azure Key Vault Secrets](/providers/azure-sm) for anything sensitive.

## Quick Start

```bash
# 1. Create the store
az appconfig create --name "myapp-config" --resource-group "myapp-rg" --location westeurope

# 2. Configure provider
cat >> fnox.toml << 'EOF'
[providers]
appconfig = { type = "azure-ac", endpoint = "https://myapp-config.azconfig.io" }
EOF

# 3. Set a key-value
az appconfig kv set --name "myapp-config" --key "api-url" --value "https://api.example.com"

# 4. Reference in fnox
cat >> fnox.toml << 'EOF'
[secrets]
API_URL = { provider = "appconfig", value = "api-url" }
EOF

# 5. Get value
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

## Pros

- ✅ Keeps non-secret configuration out of Key Vault
- ✅ One key serves every environment via labels
- ✅ Integrated with Azure RBAC

## Cons

- ❌ Read-only: write key-values with `az appconfig kv set`, not `fnox set`
- ❌ Values are not secrets: anyone with Data Reader sees them
- ❌ Requires Azure subscription

## Next Steps

- [Azure Key Vault Secrets](/providers/azure-sm) - For actual secrets
- [Profiles](/guide/profiles) - Per-environment labels
