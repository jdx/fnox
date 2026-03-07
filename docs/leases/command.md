# Custom Command

The `command` lease backend runs an arbitrary script or command to create (and optionally revoke) credentials. Use this for systems that fnox doesn't natively support.

## Configuration

```toml
[leases.custom]
type = "command"
create_command = "./scripts/get-creds.sh"
revoke_command = "./scripts/revoke-creds.sh"  # optional
duration = "1h"
```

| Field            | Required | Description                            |
| ---------------- | -------- | -------------------------------------- |
| `create_command` | Yes      | Shell command to create credentials    |
| `revoke_command` | No       | Shell command to revoke credentials    |
| `duration`       | No       | Lease duration (e.g., `"1h"`, `"30m"`) |

## Prerequisites

None — fnox can't validate prerequisites without running the command.

## Create Command

Your script receives these environment variables:

| Variable              | Description                         |
| --------------------- | ----------------------------------- |
| `FNOX_LEASE_DURATION` | Requested duration in seconds       |
| `FNOX_LEASE_LABEL`    | Lease label (default: `fnox-lease`) |

The script must output JSON on stdout:

```json
{
  "credentials": {
    "MY_TOKEN": "tok-abc123",
    "MY_SECRET": "sec-xyz789"
  },
  "expires_at": "2024-01-15T10:00:00Z",
  "lease_id": "my-custom-lease-1"
}
```

| Field         | Required | Description                                                 |
| ------------- | -------- | ----------------------------------------------------------- |
| `credentials` | Yes      | Key-value map of env var name to credential value           |
| `expires_at`  | No       | Expiry timestamp (RFC3339). Omit for never-expiring leases. |
| `lease_id`    | No       | Unique lease ID. Auto-generated if omitted.                 |

## Revoke Command

If `revoke_command` is set, it's called when you run `fnox lease revoke` or `fnox lease cleanup`. It receives:

| Variable        | Description        |
| --------------- | ------------------ |
| `FNOX_LEASE_ID` | Lease ID to revoke |

## Limits

- **Max duration:** 24 hours
- **Revocation:** Only if `revoke_command` is configured

## Examples

### Basic script

```bash
#!/bin/bash
# scripts/get-creds.sh

# Call your internal API
RESPONSE=$(curl -s https://creds.internal/api/token \
  --header "Authorization: Bearer $INTERNAL_AUTH" \
  --data "ttl=$FNOX_LEASE_DURATION")

# Output JSON
echo "$RESPONSE"
```

### Generate JSON from CLI output with jq

Many CLIs output credentials in non-JSON formats. Use `jq` to reshape the output:

```bash
#!/bin/bash
# scripts/get-k8s-token.sh

TOKEN=$(kubectl create token my-service-account \
  --duration="${FNOX_LEASE_DURATION}s" 2>/dev/null)

EXPIRY=$(date -u -d "+${FNOX_LEASE_DURATION} seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -v+${FNOX_LEASE_DURATION}S +%Y-%m-%dT%H:%M:%SZ)

jq -n \
  --arg token "$TOKEN" \
  --arg exp "$EXPIRY" \
  '{
    credentials: { KUBE_TOKEN: $token },
    expires_at: $exp
  }'
```

```toml
[leases.k8s]
type = "command"
create_command = "./scripts/get-k8s-token.sh"
duration = "1h"
```

### With revocation

```bash
#!/bin/bash
# scripts/get-creds.sh

LEASE_ID="custom-$(date +%s)"
TOKEN=$(my-tool create-token --ttl "$FNOX_LEASE_DURATION")

jq -n \
  --arg token "$TOKEN" \
  --arg id "$LEASE_ID" \
  '{
    credentials: { API_TOKEN: $token },
    lease_id: $id
  }'
```

```bash
#!/bin/bash
# scripts/revoke-creds.sh

my-tool revoke-token "$FNOX_LEASE_ID"
```

### Wrapping `aws sts` directly

```bash
#!/bin/bash
# scripts/assume-role.sh

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

### Parsing key=value output

```bash
#!/bin/bash
# scripts/get-creds.sh

# Some tools output key=value pairs
OUTPUT=$(my-tool get-creds --format=env)

# Parse into JSON with jq
echo "$OUTPUT" | jq -Rn '
  [inputs | split("=") | {(.[0]): .[1]}] | add |
  { credentials: . }
'
```

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
