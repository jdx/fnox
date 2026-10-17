---
description: "Give commands short-lived cloud credentials instead of long-lived keys. Configure a lease backend, choose where its bootstrap credential lives, and manage active leases."
---

# Credential leases

A lease is a short-lived credential that fnox creates on demand. Instead of handing your command a long-lived AWS access key, fnox uses that key once to request temporary credentials from AWS STS, and injects only the temporary ones. If a command or log leaks them, they stop working within the hour.

```toml
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev"
duration = "1h"
```

```sh
fnox exec -- aws s3 ls
```

`fnox exec` creates the lease if there isn't a usable one, injects `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`, and reuses the lease for later commands until it is about to expire.

## Backends {#supported-backends}

| Backend                              | Type           | Produces                                               | Max duration | Revocation              |
| ------------------------------------ | -------------- | ------------------------------------------------------ | ------------ | ----------------------- |
| [AWS STS](/leases/aws-sts)           | `aws-sts`      | AWS session credentials                                | 12 hours     | Expires on its own      |
| [GCP IAM](/leases/gcp-iam)           | `gcp-iam`      | OAuth2 access token                                    | 1 hour       | Expires on its own      |
| [Azure Token](/leases/azure-token)   | `azure-token`  | Entra ID access token                                  | ~1 hour      | Expires on its own      |
| [HashiCorp Vault](/leases/vault)     | `vault`        | Dynamic secrets, such as database or cloud credentials | 24 hours     | Vault lease revocation  |
| [Cloudflare](/leases/cloudflare)     | `cloudflare`   | Scoped API token                                       | 24 hours     | Token deleted           |
| [GitHub App](/leases/github-app)     | `github-app`   | Installation token                                     | 1 hour       | Token revoked           |
| [GitHub OAuth](/leases/github-oauth) | `github-oauth` | User access token                                      | ~8 hours     | Expires on its own      |
| [Custom command](/leases/command)    | `command`      | Whatever your command prints                           | 24 hours     | Optional revoke command |

The service or your account policy can impose a shorter lifetime.

## The bootstrap credential

Every backend needs _something_ to create a lease with: a long-lived key, a token, or an existing login. Where you keep it is the main decision.

### In a provider

Store it as a secret with `env = false`, so it's available to the lease backend but never injected into your command:

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "op", value = "AWS IAM/access key", env = false }
AWS_SECRET_ACCESS_KEY = { provider = "op", value = "AWS IAM/secret key", env = false }

[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev"
```

Any provider works. A password manager adds its own unlock prompt; the [OS keychain](/providers/keychain) is unlocked when you log in; age keeps it encrypted in git.

### Behind a hardware key

Store the bootstrap credential with the [`yubikey`](/providers/yubikey) or [`fido2`](/providers/fido2) provider, so decrypting it needs a touch. Keep the provider and secrets in your gitignored `fnox.local.toml`, and the shared lease config in `fnox.toml`:

```toml
# fnox.local.toml
[providers.secure]
type = "yubikey"
challenge = "a1b2..." # written by `fnox provider add`
slot = "2"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "secure", env = false }
AWS_SECRET_ACCESS_KEY = { provider = "secure", env = false }
```

```sh
fnox -c fnox.local.toml provider add secure yubikey
fnox -c fnox.local.toml set AWS_ACCESS_KEY_ID --provider secure
fnox -c fnox.local.toml set AWS_SECRET_ACCESS_KEY --provider secure
```

You touch the key once when a lease is created; cached leases are reused without a touch.

### Nowhere: paste it when needed

On a shared server, or anywhere you don't want the credential stored at all, configure only the lease and paste the credential when you start working:

```text
$ fnox lease create aws -i
AWS_ACCESS_KEY_ID (AWS access key): AKIA...
AWS_SECRET_ACCESS_KEY (AWS secret key): ...
AWS_SESSION_TOKEN (AWS session token (optional)):

✓ Lease 'aws' created (expires in 1h0m)
```

fnox uses what you pasted once and keeps only the temporary credentials. `fnox exec` then uses the cached lease until it expires.

### An existing login

Some backends can use credentials already in your environment, such as an `aws sso login` session. If no bootstrap credential is found, `fnox exec` skips that lease with a hint, and still runs the command with your other secrets.

## Manage leases

```sh
fnox lease list --active
fnox lease create aws --duration 15m   # create one now, with a custom duration
fnox lease revoke <lease-id>
fnox lease cleanup                     # revoke expired leases that need it (Vault, Cloudflare)
```

## How caching works {#how-caching-works}

Leases are recorded in a per-project ledger under `~/.local/state/fnox/leases/`. A cached lease is reused until:

- it is within 5 minutes of expiring,
- the lease's configuration changes (for example, a different role ARN), or
- you revoke it.

Entries that expired or were revoked more than 24 hours ago are pruned automatically. Revoking a ledger entry for a backend that "expires on its own" doesn't invalidate the credential early.

## Leases in profiles

Define `[profiles.<name>.leases.<lease>]` to use a different role or account per environment. See the [configuration reference](/reference/configuration#lease-backend-settings).

## See also

- [Lease backends](/leases/aws-sts): setup for each backend.
- [`fnox lease` reference](/cli/lease): every subcommand.
- [Credential proxy](/guide/proxy): keep credentials out of the child process entirely.
