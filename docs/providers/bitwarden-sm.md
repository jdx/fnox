---
description: "Read and write Bitwarden Secrets Manager secrets with fnox through the bws CLI and a machine-account access token."
---

# Bitwarden Secrets Manager

Read and write secrets in a [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) project through the `bws` CLI. `fnox.toml` holds secret key names; values stay in Bitwarden. This is a separate product from Bitwarden Password Manager, which uses the [`bitwarden`](/providers/bitwarden) provider.

|                     |                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------ |
| Config type         | `bitwarden-sm`                                                                             |
| Storage             | Remote service                                                                             |
| Writes (`fnox set`) | Yes                                                                                        |
| Requires            | [`bws` CLI](https://bitwarden.com/help/secrets-manager-cli/) on `PATH` and an access token |

## Quick start

Create a machine account with access to a project, generate an access token for it, and export the token:

```sh
export BWS_ACCESS_TOKEN="..."
```

```toml
[providers.bws]
type = "bitwarden-sm"
project_id = "00000000-0000-0000-0000-000000000000"

[secrets]
DATABASE_URL = { provider = "bws", value = "database-url" }
```

```sh
fnox provider test bws
fnox exec -- npm start
```

`database-url` is the secret's key name in the project.

## Authentication

fnox reads the access token from `FNOX_BWS_ACCESS_TOKEN`, then `BWS_ACCESS_TOKEN`, and passes it to `bws`. There is no interactive login.

For local use, store the token as a fnox secret with another provider, such as [age](/providers/age):

```sh
fnox set BWS_ACCESS_TOKEN --provider age
```

`fnox exec` resolves `BWS_ACCESS_TOKEN` before it uses the Bitwarden provider. For a single `fnox get`, export the token in the environment first.

In CI, supply the token from the CI secret store:

```yaml
- name: Deploy with secrets
  env:
    BWS_ACCESS_TOKEN: ${{ secrets.BWS_ACCESS_TOKEN }}
  run: fnox exec -- ./deploy.sh
```

## Configuration

| Field        | Required | Default          | Description                                                                                   |
| ------------ | -------- | ---------------- | --------------------------------------------------------------------------------------------- |
| `project_id` | No       | `BWS_PROJECT_ID` | Project to read from and create secrets in. Required from one of the two sources.             |
| `profile`    | No       |                  | `bws` CLI profile, passed as `--profile`. Use it for self-hosted servers or several accounts. |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

### Environment variables

| Variable                | Description                                              |
| ----------------------- | -------------------------------------------------------- |
| `FNOX_BWS_ACCESS_TOKEN` | Access token. Takes priority over `BWS_ACCESS_TOKEN`.    |
| `BWS_ACCESS_TOKEN`      | Access token.                                            |
| `BWS_PROJECT_ID`        | Project ID when `project_id` is not set in the provider. |

## Reference formats

A secret's `value` is the key name of a secret in the project, optionally followed by a field.

| `value`             | What fnox reads       |
| ------------------- | --------------------- |
| `database-url`      | The secret's value    |
| `database-url/note` | The secret's note     |
| `database-url/key`  | The secret's key name |

Only the `value`, `note` and `key` fields are supported. If several secrets in the project share a key name, fnox uses the first one `bws` returns.

Every lookup runs `bws secret list <project_id>` once and matches key names locally, so resolving many secrets from one project costs a single CLI call.

## Write secrets

`fnox set` lists the project, edits the secret whose key name matches, and creates it in the project otherwise. The remote key name is the fnox key unless you pass `--key-name`:

```sh
fnox set DATABASE_URL --provider bws --key-name database-url
```

fnox passes the value to `bws` as a command-line argument, so other users on the same machine may see it in the process list while the command runs.

## Troubleshooting

### Access token not found

Neither `FNOX_BWS_ACCESS_TOKEN` nor `BWS_ACCESS_TOKEN` is set in the fnox process environment.

### Project ID not configured

Set `project_id` in the provider or export `BWS_PROJECT_ID`.

### Secret not found

Check the key name in the project the token can access:

```sh
bws secret list "$BWS_PROJECT_ID" --output json | jq -r '.[].key'
```

## See also

- [Bitwarden](/providers/bitwarden): read Bitwarden Password Manager vault items.
- [Age](/providers/age): encrypt the access token for local bootstrap.
- [CI/CD](/guide/ci): supply tokens to non-interactive jobs.
