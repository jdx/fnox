# Cloudflare

The `cloudflare` lease backend creates short-lived, scoped Cloudflare API tokens using the [Cloudflare API Tokens API](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/create/). A parent token with the **API Tokens: Edit** permission creates child tokens that are scoped to only the permissions you specify and automatically expire.

## Configuration

```toml
[leases.cf]
type = "cloudflare"
account_id = "abc123def456"
duration = "1h"

[[leases.cf.policies]]
effect = "allow"
resources = { "com.cloudflare.api.account.abc123def456" = "*" }

[[leases.cf.policies.permission_groups]]
id = "c8fed203ed3043cba015a93ad1616f1f"
name = "Zone Read"
```

| Field        | Required | Description                                                                          |
| ------------ | -------- | ------------------------------------------------------------------------------------ |
| `account_id` | No       | Cloudflare account ID. Substituted into `{account_id}` placeholders in resource keys |
| `policies`   | Yes      | Array of permission policies (see below)                                             |
| `env_var`    | No       | Environment variable name for the token (default: `"CLOUDFLARE_API_TOKEN"`)          |
| `duration`   | No       | Token lifetime (e.g., `"1h"`, `"30m"`, default: backend max of 24h)                  |

### Policy fields

| Field               | Required | Description                                                           |
| ------------------- | -------- | --------------------------------------------------------------------- |
| `effect`            | No       | `"allow"` (default) or `"deny"`                                       |
| `permission_groups` | Yes      | Array of `{ id, name }` objects (name is optional, for documentation) |
| `resources`         | Yes      | Resource scope map (e.g., `{ "com.cloudflare.api.account.*" = "*" }`) |

To find permission group IDs, use the [Cloudflare API](https://developers.cloudflare.com/api/resources/user/subresources/tokens/subresources/permission_groups/methods/list/) or run:

```bash
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/user/tokens/permission_groups" | jq '.result[]'
```

## Prerequisites

The backend needs a parent API token that can create other tokens. fnox looks for it in environment variables:

1. `CLOUDFLARE_API_TOKEN`
2. `CF_API_TOKEN`

The parent token must have the **API Tokens: Edit** permission. If not found, fnox prints:

```
Cloudflare API token not found. Set CLOUDFLARE_API_TOKEN with a token that has 'API Tokens: Edit' permission.
```

## Credentials Produced

| Environment Variable   | Description                  |
| ---------------------- | ---------------------------- |
| `CLOUDFLARE_API_TOKEN` | Short-lived scoped API token |

The env var name is configurable via the `env_var` field.

## Limits

- **Max duration:** 24 hours
- **Revocation:** Supported — fnox deletes the token via `DELETE /user/tokens/{id}`

## Examples

### With stored credentials

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
CLOUDFLARE_API_TOKEN = { provider = "op", value = "Cloudflare/api token" }

[leases.cf]
type = "cloudflare"
account_id = "abc123def456"
duration = "1h"

[[leases.cf.policies]]
effect = "allow"
resources = { "com.cloudflare.api.account.abc123def456" = "*" }

[[leases.cf.policies.permission_groups]]
id = "c8fed203ed3043cba015a93ad1616f1f"
name = "Zone Read"

[[leases.cf.policies.permission_groups]]
id = "82e64a83756745bbbb1c9c2701bf816b"
name = "DNS Read"
```

```bash
fnox exec -- wrangler deploy
```

### Using {account_id} placeholder

If you set `account_id`, you can use `{account_id}` in resource keys to avoid repeating it:

```toml
[leases.cf]
type = "cloudflare"
account_id = "abc123def456"
duration = "2h"

[[leases.cf.policies]]
resources = { "com.cloudflare.api.account.{account_id}" = "*" }

[[leases.cf.policies.permission_groups]]
id = "e086da7e2179491d91ee5f35b3c14571"
name = "Workers Scripts Write"
```

### Custom env var name

```toml
[leases.cf]
type = "cloudflare"
env_var = "CF_TOKEN"
duration = "30m"

[[leases.cf.policies]]
resources = { "com.cloudflare.api.account.*" = "*" }

[[leases.cf.policies.permission_groups]]
id = "c8fed203ed3043cba015a93ad1616f1f"
name = "Zone Read"
```

### Common permission groups

| Permission Group      | ID                                 |
| --------------------- | ---------------------------------- |
| Zone Read             | `c8fed203ed3043cba015a93ad1616f1f` |
| Zone Settings Write   | `e17beae8b8cb423a99571f9c20b2b9fc` |
| DNS Read              | `82e64a83756745bbbb1c9c2701bf816b` |
| DNS Write             | `4755a26eedb94da69e1066d98aa820be` |
| Workers Scripts Write | `e086da7e2179491d91ee5f35b3c14571` |
| Workers Routes Write  | `28f4b596e7d643029c524985477ae49a` |

Use the permission groups API to find the full list for your account.

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
