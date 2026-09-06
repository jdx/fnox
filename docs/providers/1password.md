---
description: "Read 1Password vault items with fnox. Set up local or service-account authentication, field references, and an optional local cache."
---

# 1Password

Read vault items with the 1Password CLI (`op`). Your `fnox.toml` contains item references; values remain in 1Password.

For a complete team setup with offline reads, follow [connect a vault and cache locally](/guide/golden-path).

## Prerequisites

- A 1Password account with access to the vault and items you need.
- The [1Password CLI](https://developer.1password.com/docs/cli/) installed and available as `op`.

## Quick start

Authenticate with the CLI's interactive or desktop-app integration, then add an existing vault item to your config:

```toml
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
```

```sh
fnox provider test op
fnox get DATABASE_URL
fnox exec -- npm start
```

`fnox get` prints the value. Use `fnox check --all` when you only need to verify that it resolves.

## Authentication

### Local development

Use the [CLI's supported sign-in methods](https://developer.1password.com/docs/cli/get-started/), including integration with the desktop app. Verify access with `op vault list` before running fnox.

A service account is not required for an interactive developer session. Authentication prompts and session lifetime depend on your 1Password setup.

### CI and automation

Create a [1Password service account](https://developer.1password.com/docs/service-accounts/) with access to the required vaults. Supply its token through your CI secret store as `OP_SERVICE_ACCOUNT_TOKEN`. fnox also accepts `FNOX_OP_SERVICE_ACCOUNT_TOKEN`, which takes precedence.

This workflow step assumes fnox and `op` are installed:

```yaml
- name: Run tests with secrets
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
  run: fnox --non-interactive exec --if-missing error -- npm test
```

Scope the service account to the vaults and operations the job needs. Do not put the token in committed plaintext configuration.

## Configuration

```toml
[providers.op]
type = "1password"
vault = "Engineering"
account = "my.1password.com" # Optional account selector
```

`op` is the fnox provider instance name. Use it in secret definitions and commands such as `fnox provider test op`.

## Reference formats

| Reference                            | What fnox reads                       |
| ------------------------------------ | ------------------------------------- |
| `Database`                           | The item's password field             |
| `Database/username`                  | A named field in the configured vault |
| `op://Engineering/Database/password` | A full 1Password secret reference     |

```toml
[secrets]
DB_PASSWORD = { provider = "op", value = "Database" }
DB_USER = { provider = "op", value = "Database/username" }
API_KEY = { provider = "op", value = "op://Engineering/Service/api-key" }
```

Use the field names in your items. Full `op://` references can be copied from 1Password and are useful when a project reads from several vaults.

## Create and update items

Create or update items in the 1Password app or with the `op` CLI, then add their references to `fnox.toml`. For custom fields, use the exact field name in the reference.

The configuration can be committed because it contains references. Vault names, item names, and field names are still visible to anyone who can read the repository.

## Separate environments

Override the provider and references with a profile:

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }

[profiles.production.providers.op]
type = "1password"
vault = "Production"

[profiles.production.secrets]
DATABASE_URL = { provider = "op", value = "Database/url", if_missing = "error" }
```

```sh
fnox exec --profile production -- ./deploy.sh
```

Profiles choose configuration, not authorization. The identity used by `op` must have access to the selected vault.

## Store a bootstrap token with age

If you need to keep a service account token locally, first configure [age](/providers/age), then store the token through the hidden prompt:

```sh
fnox set OP_SERVICE_ACCOUNT_TOKEN --provider age
```

Before resolving 1Password references in a new session:

```sh
export OP_SERVICE_ACCOUNT_TOKEN="$(fnox get OP_SERVICE_ACCOUNT_TOKEN)"
```

For interactive work, using your own 1Password sign-in avoids sharing a service account token across the team.

## Cache for local use

Use [`fnox sync`](/guide/sync) to store an encrypted snapshot under a personal age key, or enable the [daemon](/guide/daemon) for in-memory caching. Refresh caches when the vault value changes.

## Troubleshooting

### Authentication required

Check the CLI's sign-in state and the selected account. For automation, confirm the service account token is available in the environment of the fnox process.

### Item or vault not found

Check the vault name, item name, field name, and account. Verify that the authenticated user or service account has vault access:

```sh
op vault list
op item list --vault Engineering
fnox provider test op
```

Item listings expose names and metadata. Review output before including it in an issue.

## Next steps

- [Connect a vault](/guide/golden-path): set up a personal age cache.
- [Profiles](/guide/profiles): compose environment settings.
- [1Password CLI documentation](https://developer.1password.com/docs/cli/): account setup and reference syntax.
