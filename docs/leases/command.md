---
description: "Create fnox leases from your own script: the JSON it must print, the variables it receives, and optional revocation."
---

# Custom command

The `command` lease backend runs your own script to create credentials, and optionally another to revoke them. Use it for systems without a built-in backend, or when a built-in backend cannot send the request you need.

|              |                                                          |
| ------------ | -------------------------------------------------------- |
| Config type  | `command`                                                |
| Produces     | Whatever keys the script returns in `credentials`        |
| Max duration | 24 hours requested; the script decides the real expiry   |
| Revocation   | Only if `revoke_command` is set                          |
| Needs        | Whatever your script needs; fnox checks nothing up front |

## Quick start

```toml
[leases.k8s]
type = "command"
create_command = "./scripts/get-k8s-token.sh"
duration = "1h"
```

```sh
#!/bin/sh
# scripts/get-k8s-token.sh
set -eu
# -o json returns the TokenRequest, including the expiry the API server actually granted
response=$(kubectl create token my-service-account --duration="${FNOX_LEASE_DURATION}s" -o json)
printf '%s\n' "$response" |
  jq '{credentials: {KUBE_TOKEN: .status.token}, expires_at: .status.expirationTimestamp}'
```

The API server may grant a shorter or longer lifetime than requested, so the script reports `.status.expirationTimestamp` rather than computing an expiry from `FNOX_LEASE_DURATION`.

```sh
fnox exec -- sh -c 'kubectl --token "$KUBE_TOKEN" get pods'
```

## Bootstrap credentials

The script runs with fnox's environment, which includes every secret fnox resolved for the command. Because fnox cannot know what a script reads, a `command` lease makes fnox resolve the whole profile, including secrets with `env = false`. Store the script's own credentials as secrets and read them as environment variables:

```toml
[secrets]
INTERNAL_AUTH = { provider = "op", value = "Creds API/token", env = false }
```

## Create command

fnox runs `create_command` with `sh -c` and sets:

| Variable              | Value                                                                                                    |
| --------------------- | -------------------------------------------------------------------------------------------------------- |
| `FNOX_LEASE_DURATION` | Requested duration in seconds                                                                            |
| `FNOX_LEASE_LABEL`    | Lease label: `fnox-exec-<lease name>` under `fnox exec`, `fnox-lease` by default for `fnox lease create` |

The script must exit 0 and print one JSON object on stdout. Send diagnostics to stderr.

```json
{
  "credentials": {
    "MY_TOKEN": "tok-abc123",
    "MY_SECRET": "sec-xyz789"
  },
  "expires_at": "2030-01-15T10:00:00Z",
  "lease_id": "my-custom-lease-1"
}
```

| Field         | Required | Description                                                                                   |
| ------------- | -------- | --------------------------------------------------------------------------------------------- |
| `credentials` | Yes      | Variable name to value. Values must be strings; others are skipped. At least one is required. |
| `expires_at`  | No       | RFC 3339 expiry. Without it, or if it does not parse, the lease never expires in fnox.        |
| `lease_id`    | No       | ID passed to `revoke_command`. Generated if omitted.                                          |

Compute `expires_at` from the real credential, not from `duration`; fnox reuses a cached lease until 5 minutes before that time.

## Revoke command

`fnox lease revoke` and `fnox lease cleanup` run `revoke_command` with `sh -c` and set `FNOX_LEASE_ID` to the lease ID. Without `revoke_command`, revoking only marks the lease revoked in fnox.

```toml
[leases.api]
type = "command"
create_command = "./scripts/get-creds.sh"
revoke_command = "my-tool revoke-token \"$FNOX_LEASE_ID\""
```

## Configuration

| Field            | Required | Default | Description                                          |
| ---------------- | -------- | ------- | ---------------------------------------------------- |
| `create_command` | Yes      | none    | Shell command that prints the JSON above.            |
| `revoke_command` | No       | none    | Shell command that revokes `FNOX_LEASE_ID`.          |
| `duration`       | No       | `"15m"` | Passed as `FNOX_LEASE_DURATION`, at most `"24h"`.    |
| `timeout`        | No       | `"30s"` | Time limit for each command run, for example `"2m"`. |

`fnox get` cannot read a key produced by a `command` lease, because fnox does not know the key names until the script runs. Use `fnox exec`.

## Examples

Wrap `aws sts assume-role` and reshape its output:

```sh
#!/bin/sh
set -eu
aws sts assume-role \
  --role-arn "arn:aws:iam::123456789012:role/my-role" \
  --role-session-name "$FNOX_LEASE_LABEL" \
  --duration-seconds "$FNOX_LEASE_DURATION" \
| jq '{
    credentials: {
      AWS_ACCESS_KEY_ID: .Credentials.AccessKeyId,
      AWS_SECRET_ACCESS_KEY: .Credentials.SecretAccessKey,
      AWS_SESSION_TOKEN: .Credentials.SessionToken
    },
    expires_at: .Credentials.Expiration
  }'
```

Convert `KEY=value` output to the expected JSON:

```sh
my-tool get-creds --format=env | jq -Rn '
  [inputs | capture("^(?<key>[^=]+)=(?<value>.*)$") | {(.key): .value}] | add |
  { credentials: . }
'
```

## Troubleshooting

### create_command exited with a non-zero status

fnox shows the script's stderr. Run the command yourself with `FNOX_LEASE_DURATION=900` set to reproduce it.

### Invalid JSON output, or output missing 'credentials' object

Something other than the JSON object reached stdout. Redirect progress messages to stderr (`>&2`).

### create_command timed out

The script ran longer than `timeout`. Raise `timeout`, for example to `"2m"` for an interactive login.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [HashiCorp Vault](/leases/vault): a built-in backend for Vault dynamic secrets.
- [Lease commands](/cli/lease): create, list and revoke leases.
