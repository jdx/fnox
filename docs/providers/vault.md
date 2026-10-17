---
description: "Read and write HashiCorp Vault KV secrets with fnox: address, token or login command, namespace, mount path, and field selection."
---

# HashiCorp Vault

Read and write secrets in a HashiCorp Vault KV secrets engine through the `vault` CLI. `fnox.toml` holds secret names and fields; values stay in Vault. For dynamic credentials, such as database or cloud logins, use the [Vault lease backend](/leases/vault) instead.

|                     |                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------- |
| Config type         | `vault`                                                                                  |
| Storage             | Remote service                                                                           |
| Writes (`fnox set`) | Yes                                                                                      |
| Requires            | [`vault` CLI](https://developer.hashicorp.com/vault/install) on `PATH` and a Vault token |

## Quick start

Export the server address and a token, and store a secret in Vault:

```sh
export VAULT_ADDR="https://vault.example.com:8200"
export VAULT_TOKEN="$(vault login -method=oidc -token-only)"
vault kv put secret/myapp/database url="postgresql://db.example.com/app"
```

```toml
[providers.vault]
type = "vault"
path = "secret/myapp"

[secrets]
DATABASE_URL = { provider = "vault", value = "database/url" }
```

```sh
fnox provider test vault
fnox exec -- ./app
```

`database/url` reads field `url` of the secret at `secret/myapp/database`.

## Authentication

fnox passes the address, token and namespace to the `vault` CLI. Each comes from the provider field first, then the environment:

| Setting   | Sources, in order                                                                |
| --------- | -------------------------------------------------------------------------------- |
| Address   | `address`, `FNOX_VAULT_ADDR`, `VAULT_ADDR`. Required.                            |
| Token     | `token`, `FNOX_VAULT_TOKEN`, `VAULT_TOKEN`, then `credential_command`. Required. |
| Namespace | `namespace`, `FNOX_VAULT_NAMESPACE`, `VAULT_NAMESPACE`                           |

The token is not read from the CLI's token helper (`~/.vault-token`). After `vault login`, export `VAULT_TOKEN`, or configure `credential_command` so fnox logs in itself.

When authentication fails in an interactive terminal, fnox offers to run its `auth_command`, `vault login` by default. fnox doesn't capture that command's output, so the retry still fails unless `VAULT_TOKEN` or `credential_command` provides a token. For on-demand login, use `credential_command` (below). Change the prompt's command with [`auth_command`](/reference/configuration#auth-command).

### Provider-scoped login

Use `credential_command` when different providers need different tokens, or to log in on demand:

```toml
[providers.vault_team_a]
type = "vault"
address = "https://vault.example.com"
namespace = "team-a"
path = "secret/team-a"
credential_command = "vault login -method=oidc -token-only"
```

The command runs only when no token is configured in the provider or environment. It must print the token to stdout and finish within 30 seconds. fnox sets `VAULT_ADDR` and `VAULT_NAMESPACE` for the command from the provider settings. The command runs through the platform shell, so pipes and redirects work, and it is rendered as a Tera template with `address`, `path` and `namespace` available. Its output is cached for up to five minutes within one fnox process, so resolving several secrets does not repeat the login.

### CI

Supply a token from the CI secret store, or use `credential_command` with a CI-friendly auth method such as JWT/OIDC:

```yaml
- run: fnox exec -- ./deploy.sh
  env:
    VAULT_ADDR: https://vault.example.com:8200
    VAULT_TOKEN: ${{ secrets.VAULT_TOKEN }}
```

## Configuration

| Field                | Required | Default                                        | Description                                                |
| -------------------- | -------- | ---------------------------------------------- | ---------------------------------------------------------- |
| `address`            | No       | `FNOX_VAULT_ADDR`, then `VAULT_ADDR`           | Vault server URL. Must be set here or in the environment.  |
| `path`               | No       | `secret`                                       | Mount and base path that secret names are appended to.     |
| `token`              | No       | `FNOX_VAULT_TOKEN`, then `VAULT_TOKEN`         | Vault token.                                               |
| `namespace`          | No       | `FNOX_VAULT_NAMESPACE`, then `VAULT_NAMESPACE` | Vault Enterprise or HCP Vault namespace.                   |
| `credential_command` | No       |                                                | Shell command that prints a token when none is configured. |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

## Reference formats

A reference is `secret` or `secret/field`. fnox appends the secret name to `path` and runs `vault kv get -field=<field>`.

| Provider `path`    | `value`        | What fnox reads                         |
| ------------------ | -------------- | --------------------------------------- |
| (default `secret`) | `api-key`      | Field `value` of `secret/api-key`       |
| `secret/myapp`     | `api-key`      | Field `value` of `secret/myapp/api-key` |
| `secret/myapp`     | `database/url` | Field `url` of `secret/myapp/database`  |

Without a field, fnox reads the field named `value`. A reference has at most one `/`, so put deeper directories in the provider's `path`. A field that holds JSON can be narrowed further with [`json_path`](/reference/configuration#json-path).

## Write secrets

`fnox set` writes the value on standard input, never on the command line. What it changes depends on the remote key:

- A key without a field, such as `fnox set API_KEY --provider vault`, runs `vault kv put` with the single field `value`. This replaces any other fields stored in that secret.
- A key with a field, such as `fnox set DB_PASSWORD --provider vault --key-name database/password`, patches only that field. If the secret does not exist, or its current version is deleted, fnox creates it.

## Policy

On a KV version 2 mount, grant `read` on the data path for reads:

```hcl
path "secret/data/myapp/*" {
  capabilities = ["read"]
}
```

For `fnox set`, also grant `create`, `update` and `patch` on the data path, and `read` on `secret/metadata/myapp/*`, which fnox checks before recreating a deleted secret. On a KV version 1 mount, the paths have no `data/` or `metadata/` segment.

## Troubleshooting

### VAULT_TOKEN not set

fnox found no token in the provider, `FNOX_VAULT_TOKEN` or `VAULT_TOKEN`, and no `credential_command`. Export the token from `vault login`, or configure `credential_command`.

### Permission denied

The token's policy does not cover the path. KV version 2 policies must include `data/` in the path, as shown in [Policy](#policy). Check with the same token:

```sh
vault kv get -field=url secret/myapp/database
```

### Invalid secret reference format

The reference has more than one `/` or an empty part. Move directories into the provider's `path`.

## See also

- [HashiCorp Vault lease](/leases/vault): issue dynamic credentials from Vault secret engines.
- [FOKS](/providers/foks): an end-to-end encrypted, self-hostable alternative.
- [CI/CD](/guide/ci): authenticate non-interactive jobs.
