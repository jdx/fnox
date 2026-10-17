---
description: "Read 1Password items and Environments with fnox through the op CLI, using desktop sign-in locally and a service account in CI."
---

# 1Password

Read vault items and 1Password Environments through the 1Password CLI (`op`). `fnox.toml` stores references; values stay in 1Password. The provider is read-only: create and edit items in 1Password, not with `fnox set`.

|                     |                                                                 |
| ------------------- | --------------------------------------------------------------- |
| Config type         | `1password`                                                     |
| Storage             | Remote service (1Password vault)                                |
| Writes (`fnox set`) | No (read-only)                                                  |
| Requires            | [`op` CLI](https://developer.1password.com/docs/cli/) on `PATH` |

## Quick start

Sign in with `op` (the desktop-app integration works), then reference an existing item:

```toml
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
```

```sh
fnox provider test op
fnox exec -- npm start
```

`op` is the provider instance name; any name works. For a team setup with offline reads, follow [use an existing vault](/guide/existing-vault).

## Authentication

fnox runs `op` and uses whatever session `op` has. It adds `--account` when `account` is set.

### Local development

Use any [`op` sign-in method](https://developer.1password.com/docs/cli/get-started/), including the desktop-app integration. Check access with `op vault list`. When `op` reports that you are not signed in, fnox offers to run `op signin` in a terminal.

### CI

Create a [service account](https://developer.1password.com/docs/service-accounts/) with access to the vaults the job reads. fnox passes the first token it finds to `op` as `OP_SERVICE_ACCOUNT_TOKEN`:

1. The provider's `token` field
2. `FNOX_OP_SERVICE_ACCOUNT_TOKEN`
3. `OP_SERVICE_ACCOUNT_TOKEN`

```yaml
- run: fnox --non-interactive exec --if-missing error -- npm test
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
```

To keep a token on a workstation, store it with another provider and point `token` at it:

```toml
[providers.op]
type = "1password"
vault = "Engineering"
token = { secret = "OP_SERVICE_ACCOUNT_TOKEN" }

[secrets]
OP_SERVICE_ACCOUNT_TOKEN = { provider = "age", value = "YWdl...", env = false } # ciphertext, abbreviated
```

## Configuration

| Field     | Required | Default        | Description                                                                                      |
| --------- | -------- | -------------- | ------------------------------------------------------------------------------------------------ |
| `vault`   | No       | none           | Vault for `item` and `item/field` references. Those forms fail without it.                       |
| `account` | No       | `op`'s default | Account passed to `op --account`, for example `my.1password.com`.                                |
| `token`   | No       | env vars       | Service account token. Overrides `FNOX_OP_SERVICE_ACCOUNT_TOKEN` and `OP_SERVICE_ACCOUNT_TOKEN`. |

Each field accepts `{ secret = "NAME" }` to read its value from another secret. Fields shared by all providers, such as `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration).

## Reference formats

| `value`                              | What fnox reads                                                      |
| ------------------------------------ | -------------------------------------------------------------------- |
| `Database`                           | `op://<vault>/Database/password`                                     |
| `Database/username`                  | `op://<vault>/Database/username`                                     |
| `op://Engineering/Database/password` | That secret reference as written; `vault` is ignored                 |
| `environment://<id>/DATABASE_URL`    | One variable from a [1Password Environment](#1password-environments) |

Copy full `op://` references from 1Password when a project reads from several vaults. Field names are the labels shown on the item.

To add a reference without editing TOML, pass it as the value. For a read-only provider, `fnox set` records the value as the reference:

```sh
fnox set DB_USER "Database/username" --provider op
```

When several secrets use the same provider, fnox resolves them with one `op inject` call, and falls back to one `op read` per secret if that call fails.

## 1Password Environments {#1password-environments}

[1Password Environments](https://developer.1password.com/docs/environments/) are named sets of environment variables. Reference one variable with `environment://<environment-id>/<VARIABLE>`:

```toml
[providers.op]
type = "1password"

[secrets]
DATABASE_URL = { provider = "op", value = "environment://blgexucrwfr2dtsxe2q4uu7dp4/DATABASE_URL" }
STRIPE_KEY = { provider = "op", value = "environment://blgexucrwfr2dtsxe2q4uu7dp4/STRIPE_KEY" }
```

- fnox runs `op environment read <id>` once per Environment and serves every variable that references it from that read.
- Environment references ignore `vault` and can sit next to vault item references in the same provider.
- A variable missing from the Environment is an error, not an empty value.
- This needs an `op` build that includes `op environment`, currently on the beta channel (2.33.0-beta.02 or later). Authenticate as usual: the desktop app, or a service account that can access the Environment.

## Troubleshooting

### Authentication required

`op` is not signed in to the selected account, or the service account token is not in fnox's environment. Check the session `op` sees:

```sh
op whoami
```

### Unknown secret vault

A short reference (`Item` or `Item/field`) needs `vault` in the provider config. Set it, or use a full `op://vault/item/field` reference.

### Item or vault not found

Check the vault, item and field names, and that the signed-in identity can access the vault. Item listings show names and metadata, so review output before sharing it.

```sh
op item list --vault Engineering
fnox provider test op
```

### `unknown command` for an `environment://` reference

Your `op` build does not include `op environment`. Install a beta build that does.

## See also

- [Use an existing vault](/guide/existing-vault): reference 1Password items and keep a personal offline cache.
- [CI/CD](/guide/ci): supply the service account token in a pipeline.
- [Provider catalog](/providers/overview): compare 1Password with other providers.
