---
description: "Create short-lived, scoped Cloudflare API tokens with fnox from a parent token, as user or account tokens, and delete them on revoke."
---

# Cloudflare

The `cloudflare` lease backend uses a parent API token to create a child token that expires on its own, and injects the child into `fnox exec`. By default the child inherits the parent's permissions; set `policies` to narrow them.

|              |                                                         |
| ------------ | ------------------------------------------------------- |
| Config type  | `cloudflare`                                            |
| Produces     | `CLOUDFLARE_API_TOKEN` (configurable with `env_var`)    |
| Max duration | 24 hours                                                |
| Revocation   | Yes; fnox deletes the child token                       |
| Needs        | A parent token with the **API Tokens: Edit** permission |

## Quick start

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
CLOUDFLARE_API_TOKEN = { provider = "op", value = "Cloudflare/api token", env = false }

[leases.cf]
type = "cloudflare"
duration = "1h"
```

```sh
fnox exec -- sh -c 'curl -fsS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" https://api.cloudflare.com/client/v4/zones'
```

The command sees the child token in `CLOUDFLARE_API_TOKEN`; the parent token stays out of its environment.

## Bootstrap credentials

fnox reads the parent token from `CLOUDFLARE_API_TOKEN`, then `CF_API_TOKEN`. Store it as a secret with one of those names, as in the quick start, or export it. `fnox lease create -i cf` prompts for it when neither is set.

The parent needs **API Tokens: Edit** plus every permission the child should have. Cloudflare does not let a child token manage tokens, so the API Tokens permission groups are never passed on.

## Configuration

| Field        | Required         | Default                  | Description                                                                                         |
| ------------ | ---------------- | ------------------------ | --------------------------------------------------------------------------------------------------- |
| `token_type` | No               | `"user"`                 | `"user"` creates the token under `/user/tokens`; `"account"` under `/accounts/<account_id>/tokens`. |
| `account_id` | With `"account"` | none                     | Account ID. Also replaces `{account_id}` in policy resource keys.                                   |
| `policies`   | No               | parent's policies        | Policies for the child token. See [Policies](#policies).                                            |
| `env_var`    | No               | `"CLOUDFLARE_API_TOKEN"` | Variable that receives the child token.                                                             |
| `duration`   | No               | `"15m"`                  | Token lifetime, sent as `expires_on`. At most `"24h"`.                                              |

[Account-owned tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/) are not tied to a person, which suits CI and shared setups. Child tokens are named `fnox-lease-<label>`, such as `fnox-lease-fnox-exec-cf`, so you can find them in the dashboard.

### Policies

Without `policies`, fnox reads the parent token's policies, drops the API Tokens permission groups, and gives the child the rest. A parent that has only API Tokens permissions cannot be inherited from; configure `policies` instead.

Each policy has:

| Field               | Required | Description                                                                      |
| ------------------- | -------- | -------------------------------------------------------------------------------- |
| `effect`            | No       | `"allow"` (default) or `"deny"`.                                                 |
| `resources`         | Yes      | Resource scope map, for example `{ "com.cloudflare.api.account.zone.*" = "*" }`. |
| `permission_groups` | Yes      | At least one `{ id, name }` table. `name` is optional and only for readability.  |

```toml
[leases.cf]
type = "cloudflare"
account_id = "abc123def456"
duration = "2h"

[[leases.cf.policies]]
effect = "allow"
resources = { "com.cloudflare.api.account.{account_id}" = "*" }

[[leases.cf.policies.permission_groups]]
id = "e086da7e2179491d91ee5f35b3c14571"
name = "Workers Scripts Write"
```

Look up permission group IDs with the [permission groups API](https://developers.cloudflare.com/api/resources/user/subresources/tokens/subresources/permission_groups/methods/list/):

```sh
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/user/tokens/permission_groups" | jq '.result[] | {id, name}'
```

## Troubleshooting

### Cloudflare API token not found

Neither `CLOUDFLARE_API_TOKEN` nor `CF_API_TOKEN` is set when the lease is created. Under `fnox exec`, the lease is skipped with this warning unless a cached lease is still valid.

### Parent token only has 'API Tokens' permissions

Inheritance left the child with nothing. Add the permissions the child needs to the parent token, or configure `policies`.

### HTTP 401 or 403

The parent token is invalid or lacks **API Tokens: Edit**. With `token_type = "account"`, fnox verifies the parent against `/accounts/<account_id>/tokens`, so it must be valid for that account.

### Resource key contains '{account_id}' placeholder

A policy uses `{account_id}` but `account_id` is not set. Set it on the lease.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [Lease commands](/cli/lease): revoke a child token early with `fnox lease revoke`.
- [Custom command](/leases/command): wrap another token API with your own script.
