---
description: "Push fnox secrets to Azure Container Apps environment variables through the ARM REST API, with one write per push."
---

# Azure Container Apps

The `azure-container-apps` target sets environment variables on a container in an [Azure Container App](https://learn.microsoft.com/azure/container-apps/) through the Azure Resource Manager API. It reads the app, sets or replaces the pushed variables in the container's `env`, and writes the containers back. Variables fnox does not push are left alone.

|                     |                                                   |
| ------------------- | ------------------------------------------------- |
| Config type         | `azure-container-apps`                            |
| Requires            | An identity that can update the container app     |
| Readable afterwards | Yes, anyone who can read the app can see the vars |

## Quick start

```toml
[targets.api]
type = "azure-container-apps"
subscription = "00000000-0000-0000-0000-000000000000"
resource_group = "rg-dev"
app = "ca-api-dev"

[secrets]
DATABASE_URL = { provider = "kv", value = "database-url", push = ["api"] }
LOG_LEVEL = { default = "info", push = ["api"] }
```

```sh
fnox -P dev push --target api --force
```

## Configuration

| Field                        | Default            | Description                                                                      |
| ---------------------------- | ------------------ | -------------------------------------------------------------------------------- |
| `subscription`               | required           | Subscription ID that holds the container app.                                    |
| `resource_group`             | required           | Resource group that holds the container app.                                     |
| `app`                        | required           | Container app name.                                                              |
| `container`                  | the only container | Container to set the variables in. Required when the app has several.            |
| `auth`                       | `"default"`        | `"default"` or `"managed-identity"`.                                             |
| `managed_identity_client_id` | none               | Client ID of a user-assigned managed identity, with `auth = "managed-identity"`. |

## Authentication

The same credential chain as the [`azure-sm`](/providers/azure-sm) and [`azure-ac`](/providers/azure-ac) providers: a service principal from `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`, otherwise the `az` or `azd` login, or the host's managed identity with `auth = "managed-identity"`. The identity needs permission to update the app, such as the Contributor role on it. Values go to the API over HTTPS, not onto a command line.

## Notes

- **One revision per push.** Every env change creates a new revision, so fnox writes all of a target's variables in a single request. A push whose values already match writes nothing.
- **fnox does not wait.** The write returns once Azure accepts it. Rolling the image and waiting for the revision to become ready stays in your deploy script.
- **Plain variables only.** A pushed variable is stored as a plain `value`, replacing an existing variable of that name even if it used a `secretRef`. The app's `secrets` are not touched.
- **Public cloud only.** The target talks to `management.azure.com`.
- A failed batch marks every variable in it as failed.
