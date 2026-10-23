---
description: "Create short-lived, tagged Tailscale auth keys with fnox from an OAuth client or API key, for CI runners and containers, and delete them on revoke."
---

# Tailscale

The `tailscale` lease backend creates a Tailscale [auth key](https://tailscale.com/kb/1085/auth-keys) through the Tailscale API and injects it into `fnox exec`. Use it to join CI runners and containers to your tailnet without keeping a long-lived key.

|              |                                                                          |
| ------------ | ------------------------------------------------------------------------ |
| Config type  | `tailscale`                                                              |
| Produces     | `TS_AUTHKEY` (configurable with `env_var`)                               |
| Max duration | 90 days, set by Tailscale                                                |
| Revocation   | Yes; fnox deletes the key                                                |
| Needs        | An OAuth client with the `auth_keys` write scope, or an API access token |

## Quick start

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
TAILSCALE_OAUTH_CLIENT_ID = { provider = "op", value = "Tailscale/oauth client id", env = false }
TAILSCALE_OAUTH_CLIENT_SECRET = { provider = "op", value = "Tailscale/oauth client secret", env = false }

[leases.ts]
type = "tailscale"
tags = ["tag:ci"]
duration = "1h"
```

```sh
fnox exec -- sh -c 'tailscale up --auth-key "$TS_AUTHKEY" --hostname "ci-$(hostname)"'
```

The key is ephemeral and pre-authorized by default, so the device joins without approval and disappears from the tailnet shortly after it goes offline.

## Bootstrap credentials

fnox needs one of these, checked in this order:

1. `TAILSCALE_API_KEY`, an API access token. It acts as the user who created it and expires within 90 days.
2. `TAILSCALE_OAUTH_CLIENT_ID` and `TAILSCALE_OAUTH_CLIENT_SECRET`, an [OAuth client](https://tailscale.com/kb/1215/oauth-clients) with the `auth_keys` write scope. OAuth clients are not tied to a person, so prefer one for CI. Tailscale requires every key an OAuth client creates to carry `tags` that the client owns.

Store them as secrets with `env = false`, as in the quick start, or export them. `fnox lease create -i ts` prompts for the OAuth client when none is set.

## Configuration

| Field           | Required | Default                       | Description                                                                              |
| --------------- | -------- | ----------------------------- | ---------------------------------------------------------------------------------------- |
| `tags`          | No       | none                          | ACL tags applied to devices that use the key, such as `["tag:ci"]`. Required with OAuth. |
| `tailnet`       | No       | `"-"`                         | Tailnet name. `"-"` is the tailnet the credentials belong to.                            |
| `ephemeral`     | No       | `true`                        | Devices are removed from the tailnet after they go offline.                              |
| `preauthorized` | No       | `true`                        | Devices join without manual approval.                                                    |
| `reusable`      | No       | `false`                       | Allow more than one device to register with the key.                                     |
| `env_var`       | No       | `"TS_AUTHKEY"`                | Variable that receives the key. The Tailscale container image reads `TS_AUTHKEY`.        |
| `api_base`      | No       | `"https://api.tailscale.com"` | API base URL.                                                                            |
| `duration`      | No       | `"15m"`                       | How long the key can register devices. At most `"90d"`.                                  |

`duration` limits when the key can be _used to register a device_. A device that has already joined stays on the tailnet after the key expires.

## Troubleshooting

### Tailscale credentials not found

None of `TAILSCALE_API_KEY`, or `TAILSCALE_OAUTH_CLIENT_ID` with `TAILSCALE_OAUTH_CLIENT_SECRET`, is set when the lease is created. Under `fnox exec`, the lease is skipped with this warning unless a cached lease is still valid.

### requested tags are invalid or not permitted

The key needs `tags`, and an OAuth client can only apply tags it owns. Add the tags to the OAuth client in the Tailscale admin console, and to `tagOwners` in your ACL.

### HTTP 401 or 403

The credentials are invalid or cannot write auth keys. For an OAuth client, check that it has the `auth_keys` write scope.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [Lease commands](/cli/lease): revoke a key early with `fnox lease revoke`.
- [Custom command](/leases/command): wrap another API with your own script.
