---
description: "Get a short-lived Microsoft Entra ID access token for an Azure resource scope with fnox, from a service principal or Azure CLI login."
---

# Azure token

The `azure-token` lease backend gets an OAuth2 access token from Microsoft Entra ID for one resource scope and injects it into `fnox exec`. Use it for tools and API calls that accept a bearer token.

|              |                                                    |
| ------------ | -------------------------------------------------- |
| Config type  | `azure-token`                                      |
| Produces     | `AZURE_ACCESS_TOKEN` (configurable with `env_var`) |
| Max duration | 1 hour; Azure sets the actual lifetime             |
| Revocation   | None; tokens expire on their own                   |
| Needs        | A service principal secret, or an Azure CLI login  |

## Quick start

```toml
[leases.azure]
type = "azure-token"
scope = "https://management.azure.com/.default"
duration = "1h"
```

```sh
az login
fnox exec -- sh -c 'curl -fsS -H "Authorization: Bearer $AZURE_ACCESS_TOKEN" "https://management.azure.com/subscriptions?api-version=2022-12-01"'
```

Tools must read the token from the variable you configure; setting `AZURE_ACCESS_TOKEN` does not make every Azure tool use it.

## Bootstrap credentials

fnox uses the first source available:

1. A service principal, when `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` are all set and non-empty.
2. The Azure CLI or Azure Developer CLI login. Before creating a lease, fnox checks that `az` is on `PATH`.

Managed identity is not supported by this backend. To keep a service principal in a provider, define secrets with the same names; fnox resolves them for lease creation, and `env = false` keeps them out of the command:

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
AZURE_TENANT_ID = { provider = "op", value = "Azure SP/tenant id", env = false }
AZURE_CLIENT_ID = { provider = "op", value = "Azure SP/client id", env = false }
AZURE_CLIENT_SECRET = { provider = "op", value = "Azure SP/client secret", env = false }
```

`fnox lease create -i azure` prompts for the three values when none of the sources is available.

## Configuration

| Field      | Required | Default                | Description                                                                                                        |
| ---------- | -------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `scope`    | Yes      | none                   | Resource scope, for example `https://management.azure.com/.default`.                                               |
| `env_var`  | No       | `"AZURE_ACCESS_TOKEN"` | Variable that receives the token.                                                                                  |
| `duration` | No       | `"15m"`                | Must be at most `"1h"`. Azure sets the real lifetime, so shorter values log a warning and are ignored; use `"1h"`. |

Common scopes:

| Scope                                   | Service                |
| --------------------------------------- | ---------------------- |
| `https://management.azure.com/.default` | Azure Resource Manager |
| `https://graph.microsoft.com/.default`  | Microsoft Graph        |
| `https://database.windows.net/.default` | Azure SQL Database     |
| `https://storage.azure.com/.default`    | Azure Storage          |

For a second scope, add a second lease with its own `env_var`:

```toml
[leases.graph]
type = "azure-token"
scope = "https://graph.microsoft.com/.default"
env_var = "GRAPH_TOKEN"
```

## Troubleshooting

### Azure credentials not found

No complete service principal is set and `az` is not on `PATH`. Run `az login`, or set all three `AZURE_*` variables. Under `fnox exec`, the lease is skipped with this warning unless a cached lease is still valid.

### Failed to acquire Azure token

The identity cannot get a token for the scope: the secret is wrong or expired, the CLI session has expired, or the scope is misspelled. Check the CLI session with `az account show`.

### Lease duration exceeds maximum

`duration` is longer than one hour. Remove it or set it to `"1h"` or less.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [Azure Key Vault Secrets](/providers/azure-sm): store secrets in Azure and read them with the same identity.
- [Lease commands](/cli/lease): create, list and revoke leases.
