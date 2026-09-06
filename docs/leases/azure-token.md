---
description: "Acquire temporary Azure access tokens for a resource scope and pass them to commands that accept bearer tokens."
---

# Azure token

The `azure-token` lease backend obtains a short-lived OAuth2 bearer token from Microsoft Entra ID (formerly Azure Active Directory) using either a service principal or the Azure CLI session.

## Configuration

```toml
[leases.azure]
type = "azure-token"
scope = "https://management.azure.com/.default"
```

| Field      | Required | Description                                                               |
| ---------- | -------- | ------------------------------------------------------------------------- |
| `scope`    | Yes      | Azure resource scope (e.g., `"https://management.azure.com/.default"`)    |
| `env_var`  | No       | Environment variable name for the token (default: `"AZURE_ACCESS_TOKEN"`) |
| `duration` | No       | Ignored — Azure controls token lifetime (~1 hour)                         |

## Prerequisites

The backend needs Azure credentials. fnox looks for them in this order:

1. Service principal environment variables: `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID` (all three required)
2. Azure CLI session (requires the `az` CLI to be installed and logged in)

If none are found, fnox prints:

```text
Azure credentials not found. Run 'az login' or set AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID.
```

## Credentials produced

| Environment Variable | Description         |
| -------------------- | ------------------- |
| `AZURE_ACCESS_TOKEN` | OAuth2 bearer token |

The env var name is configurable via the `env_var` field.

## Limits

- **Max duration:** ~1 hour (Azure controls token lifetime, not configurable by the caller)
- **Revocation:** No-op — tokens expire automatically

## Examples

### With stored credentials

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
AZURE_CLIENT_ID = { provider = "op", value = "Azure SP/client id", env = false }
AZURE_CLIENT_SECRET = { provider = "op", value = "Azure SP/client secret", env = false }
AZURE_TENANT_ID = { provider = "op", value = "Azure SP/tenant id", env = false }

[leases.azure]
type = "azure-token"
scope = "https://management.azure.com/.default"
```

```bash
fnox exec -- sh -c 'curl -fsS -H "Authorization: Bearer $AZURE_ACCESS_TOKEN" "https://management.azure.com/subscriptions?api-version=2022-12-01"'
```

The example explicitly passes the leased token to the [Azure subscriptions API](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list?view=rest-resources-2022-12-01). Client tools must consume the configured token variable; creating `AZURE_ACCESS_TOKEN` does not make every Azure tool use it automatically.

### With Azure CLI login

```bash
az login

# fnox picks up the CLI session automatically
fnox exec -- sh -c 'curl -fsS -H "Authorization: Bearer $AZURE_ACCESS_TOKEN" "https://management.azure.com/subscriptions?api-version=2022-12-01"'
```

### Custom env var name

```toml
[leases.azure]
type = "azure-token"
scope = "https://graph.microsoft.com/.default"
env_var = "GRAPH_TOKEN"
```

### Common scopes

| Scope                                   | Use case               |
| --------------------------------------- | ---------------------- |
| `https://management.azure.com/.default` | Azure Resource Manager |
| `https://graph.microsoft.com/.default`  | Microsoft Graph API    |
| `https://database.windows.net/.default` | Azure SQL Database     |
| `https://storage.azure.com/.default`    | Azure Storage          |

## See also

- [Credential Leases](/guide/leases) — overview and approaches
- [Azure Key Vault Secrets provider](/providers/azure-sm) — for storing secrets in Azure
