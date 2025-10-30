# Azure Key Vault Secrets

Azure Key Vault Secrets provides centralized secret management for Azure workloads.

## Quick Start

```bash
# 1. Create Key Vault
az keyvault create --name "myapp-vault" --resource-group "myapp-rg"

# 2. Configure provider
cat >> fnox.toml << 'EOF'
[providers]
azure = { type = "azure-sm", vault_url = "https://myapp-vault.vault.azure.net/", prefix = "myapp/" }
EOF

# 3. Create secret
az keyvault secret set --vault-name "myapp-vault" --name "myapp-database-url" --value "postgresql://..."

# 4. Reference in fnox
cat >> fnox.toml << 'EOF'
[secrets]
DATABASE_URL = { provider = "azure", value = "database-url" }
EOF

# 5. Get secret
fnox get DATABASE_URL
```

## Authentication

Choose one:

```bash
# Azure CLI (development)
az login

# Service Principal (CI/CD)
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_TENANT_ID="..."

# Managed Identity (automatic on Azure VMs/Functions)
# No configuration needed!
```

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
azure = { type = "azure-sm", vault_url = "https://myapp-vault.vault.azure.net/", prefix = "myapp/" }  # prefix is optional
```

## Pros

- ✅ Integrated with Azure RBAC
- ✅ Audit logs
- ✅ Managed rotation

## Cons

- ❌ Requires Azure subscription
- ❌ Costs money
- ❌ Network access required

## Next Steps

- [Azure Key Vault Keys](/providers/azure-kms) - Encryption alternative
- [AWS Secrets Manager](/providers/aws-sm) - AWS equivalent
