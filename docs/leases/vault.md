# HashiCorp Vault

The `vault` lease backend reads dynamic secrets from a HashiCorp Vault secret engine. This works with any Vault dynamic secret backend — AWS, database, PKI, etc. You configure which Vault response fields map to which environment variables.

## Configuration

```toml
[leases.vault-db]
type = "vault"
secret_path = "database/creds/my-role"
duration = "1h"

[leases.vault-db.env_map]
username = "DB_USER"
password = "DB_PASSWORD"
```

| Field                | Required | Description                                                         |
| -------------------- | -------- | ------------------------------------------------------------------- |
| `secret_path`        | Yes      | Vault API path for the dynamic secret                               |
| `env_map`            | Yes      | Map of Vault response field names to environment variables          |
| `address`            | No       | Vault server URL (falls back to `VAULT_ADDR`)                       |
| `token`              | No       | Vault auth token (falls back to `VAULT_TOKEN`)                      |
| `credential_command` | No       | Shell command that prints a Vault token when no token is configured |
| `namespace`          | No       | Vault namespace (for Vault Enterprise / HCP Vault)                  |
| `duration`           | No       | Requested lease TTL (e.g., `"1h"`, `"30m"`)                         |
| `method`             | No       | HTTP method: `"get"` (default) or `"post"` (for pki/issue)          |

## Prerequisites

The backend needs a Vault address and token. fnox resolves them in this order:

1. `address` / `token` fields in config
2. `FNOX_VAULT_ADDR` / `FNOX_VAULT_TOKEN` environment variables
3. `VAULT_ADDR` / `VAULT_TOKEN` environment variables
4. `credential_command` for the token

If the address or token is missing, fnox prints one of:

```
Vault address and token not found. Set VAULT_ADDR and VAULT_TOKEN.
Vault address not found. Set VAULT_ADDR.
Vault token not found. Set VAULT_TOKEN.
```

When `credential_command` is configured, fnox runs it through the platform shell and uses trimmed stdout as the token. The command is rendered as a Tera template with `address`, `secret_path`, and `namespace`, and fnox sets `VAULT_ADDR` and `VAULT_NAMESPACE` for the command from the lease config. Output is cached briefly for the current fnox process so repeated lease operations do not repeat the login.

## Credentials Produced

Determined by the `env_map` configuration. The keys are field names from the Vault response, and the values are the environment variable names to inject.

## Limits

- **Max duration:** 24 hours
- **Revocation:** Full support — calls `PUT /v1/sys/leases/revoke` on the Vault server

## Examples

### AWS dynamic secrets

```toml
[leases.vault-aws]
type = "vault"
address = "https://vault.example.com:8200"
secret_path = "aws/creds/my-role"
duration = "1h"

[leases.vault-aws.env_map]
access_key = "AWS_ACCESS_KEY_ID"
secret_key = "AWS_SECRET_ACCESS_KEY"
security_token = "AWS_SESSION_TOKEN"
```

### Database credentials

```toml
[leases.vault-db]
type = "vault"
secret_path = "database/creds/readonly"
duration = "30m"

[leases.vault-db.env_map]
username = "DB_USER"
password = "DB_PASSWORD"
```

```bash
fnox exec -- psql -h db.example.com -U "$DB_USER" mydb
```

### PKI certificates

PKI and some other engines require POST requests. Set `method = "post"`:

```toml
[leases.vault-pki]
type = "vault"
secret_path = "pki/issue/my-role"
method = "post"
duration = "24h"

[leases.vault-pki.env_map]
certificate = "TLS_CERT"
private_key = "TLS_KEY"
issuing_ca = "TLS_CA"
```

### With stored token

```toml
[providers.op]
type = "1password"
vault = "Infrastructure"

[secrets]
VAULT_TOKEN = { provider = "op", value = "Vault/token" }

[leases.vault-aws]
type = "vault"
address = "https://vault.example.com:8200"
secret_path = "aws/creds/my-role"

[leases.vault-aws.env_map]
access_key = "AWS_ACCESS_KEY_ID"
secret_key = "AWS_SECRET_ACCESS_KEY"
security_token = "AWS_SESSION_TOKEN"
```

### With namespace (Enterprise / HCP)

```toml
[leases.vault-db]
type = "vault"
namespace = "admin/my-team"
secret_path = "database/creds/app-role"

[leases.vault-db.env_map]
username = "DB_USER"
password = "DB_PASSWORD"
```

### With credential command

```toml
[leases.vault-db]
type = "vault"
address = "https://vault.example.com"
namespace = "team-a"
credential_command = "vault login -method=oidc -token-only"
secret_path = "database/creds/readonly"
method = "post"

[leases.vault-db.env_map]
username = "DB_USER"
password = "DB_PASSWORD"
```

## Notes

- **TTL is advisory.** The `duration` field is sent to Vault as a TTL hint, but many engines (database, pki, rabbitmq) ignore it and use the role's configured default TTL instead. fnox warns if the actual `lease_duration` returned by Vault differs significantly from the requested value.
- **GET vs POST.** Most Vault dynamic secret engines use GET (e.g., `aws/creds`, `database/creds`). Some engines like `pki/issue` require POST — set `method = "post"` for those.

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
- [HashiCorp Vault provider](/providers/vault) — for reading static KV secrets
