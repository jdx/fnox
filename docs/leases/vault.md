---
description: "Request dynamic credentials from HashiCorp Vault with fnox, map response fields to environment variables, and revoke the Vault lease."
---

# HashiCorp Vault

The `vault` lease backend reads a dynamic secret from a HashiCorp Vault secrets engine, such as `aws`, `database` or `pki`, and injects the fields you map into `fnox exec`. fnox revokes the Vault lease when you revoke the fnox lease.

|              |                                                            |
| ------------ | ---------------------------------------------------------- |
| Config type  | `vault`                                                    |
| Produces     | The variables named in `env_map`                           |
| Max duration | 24 hours requested; the Vault role decides the actual TTL  |
| Revocation   | Yes, through `sys/leases/revoke`                           |
| Needs        | A Vault address and a token (or a command that prints one) |

## Quick start

```toml
[leases.db]
type = "vault"
address = "https://vault.example.com:8200"
secret_path = "database/creds/readonly"
duration = "1h"

[leases.db.env_map]
username = "DB_USER"
password = "DB_PASSWORD"
```

```sh
export VAULT_TOKEN="$(vault print token)"
fnox exec -- sh -c 'PGPASSWORD="$DB_PASSWORD" psql -h db.example.com -U "$DB_USER" mydb'
```

Each `env_map` key is a field in the Vault response's `data`; each value is the variable fnox sets.

## Bootstrap credentials

fnox calls the Vault HTTP API directly; it does not need the `vault` CLI. It resolves each setting from the first source that is set:

| Setting   | Sources, in order                                                     |
| --------- | --------------------------------------------------------------------- |
| Address   | `address`, `FNOX_VAULT_ADDR`, `VAULT_ADDR`                            |
| Token     | `token`, `FNOX_VAULT_TOKEN`, `VAULT_TOKEN`, then `credential_command` |
| Namespace | `namespace`, `FNOX_VAULT_NAMESPACE`, `VAULT_NAMESPACE`                |

To keep a token in a provider, define a secret named `VAULT_TOKEN`; fnox resolves it for lease creation, and `env = false` keeps it out of the command:

```toml
[secrets]
VAULT_TOKEN = { provider = "op", value = "Vault/token", env = false }
```

### Credential command

`credential_command` logs in on demand when no token is configured:

```toml
[leases.db]
type = "vault"
address = "https://vault.example.com"
namespace = "team-a"
credential_command = "vault login -method=oidc -token-only"
secret_path = "database/creds/readonly"

[leases.db.env_map]
username = "DB_USER"
password = "DB_PASSWORD"
```

- fnox runs the command through the platform shell and uses its trimmed stdout as the token.
- The command is a [Tera](https://keats.github.io/tera/) template with `address`, `secret_path` and `namespace` variables. fnox also sets `VAULT_ADDR` and, when configured, `VAULT_NAMESPACE` in its environment.
- The token is reused for five minutes within one fnox process and discarded early if Vault rejects it.
- The command must finish within 30 seconds.

## Configuration

| Field                | Required | Default  | Description                                                                |
| -------------------- | -------- | -------- | -------------------------------------------------------------------------- |
| `secret_path`        | Yes      | none     | API path after `/v1/`, for example `aws/creds/my-role`.                    |
| `env_map`            | Yes      | none     | Table of response field to variable name. Needs at least one entry.        |
| `address`            | No       | env vars | Vault server URL.                                                          |
| `token`              | No       | env vars | Vault token. Prefer an environment variable or `credential_command`.       |
| `credential_command` | No       | none     | Shell command that prints a token, used when no token is configured.       |
| `namespace`          | No       | env vars | Namespace for Vault Enterprise or HCP Vault, sent as `X-Vault-Namespace`.  |
| `method`             | No       | `"get"`  | `"get"`, or `"post"` for engines that issue on write, such as `pki/issue`. |
| `duration`           | No       | `"15m"`  | TTL sent to Vault as `ttl`, at most `"24h"`.                               |

### Response handling

- **TTL is advisory.** Many engines (database, pki, rabbitmq) ignore the requested `ttl` and use the role's TTL. fnox records the `lease_duration` Vault returns and logs a warning when it differs from `duration` by more than 30 seconds.
- **KV v2 is unwrapped.** When `data` contains a nested `data` object, fnox reads fields from the inner one.
- **No expiry when `lease_duration` is 0.** Static KV secrets have no Vault lease, so the fnox lease stays active until you revoke it.
- **Missing fields.** A mapped field missing from the response is skipped with a warning. If none of the mapped fields is present, lease creation fails.

### Examples

AWS dynamic credentials:

```toml
[leases.aws]
type = "vault"
secret_path = "aws/creds/my-role"

[leases.aws.env_map]
access_key = "AWS_ACCESS_KEY_ID"
secret_key = "AWS_SECRET_ACCESS_KEY"
security_token = "AWS_SESSION_TOKEN"
```

A PKI certificate. With `method = "post"`, fnox sends only `{"ttl": ...}` as the request body, so the role must be able to issue without fields such as `common_name`. Use a [custom command](/leases/command) when the request needs them.

```toml
[leases.pki]
type = "vault"
secret_path = "pki/issue/my-role"
method = "post"
duration = "24h"

[leases.pki.env_map]
certificate = "TLS_CERT"
private_key = "TLS_KEY"
issuing_ca = "TLS_CA"
```

## Permissions

The token needs `read` on `secret_path` (or `update` for `method = "post"`). To revoke leases from fnox, it also needs `update` on `sys/leases/revoke`:

```text
path "sys/leases/revoke" {
  capabilities = ["update"]
}
```

## Troubleshooting

### Vault address and token not found

None of the address or token sources is set. Set `VAULT_ADDR` and `VAULT_TOKEN`, or configure `address` and `credential_command`. Under `fnox exec`, the lease is skipped with this warning unless a cached lease is still valid.

### HTTP 403 when creating the lease

The token lacks access to `secret_path`, or has expired. With `credential_command`, fnox discards the cached token so the next attempt logs in again.

### No configured env_map keys found in Vault response data

The `env_map` keys do not match the response fields. Inspect the response with `vault read <secret_path>` and use the field names under `data`.

### HTTP 403 when revoking

Add the `sys/leases/revoke` policy shown in [Permissions](#permissions).

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [HashiCorp Vault provider](/providers/vault): read static KV secrets.
- [Lease commands](/cli/lease): create, list and revoke leases.
