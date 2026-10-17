---
description: "Get short-lived GitHub user access tokens with fnox through the OAuth device flow, cached and refreshed in the OS keyring."
---

# GitHub OAuth

The `github-oauth` lease backend gets a GitHub App user access token through the OAuth device flow and injects it into `fnox exec`. The token acts as the signed-in user, so local `gh` and API calls stay attributed to you without a personal access token on disk.

|              |                                                                     |
| ------------ | ------------------------------------------------------------------- |
| Config type  | `github-oauth`                                                      |
| Produces     | `GITHUB_TOKEN` (configurable with `env_var`)                        |
| Max duration | 8 hours; GitHub sets the actual lifetime                            |
| Revocation   | None; tokens expire on their own                                    |
| Needs        | A GitHub App client ID with device flow enabled, and a browser once |

## Quick start

```toml
[leases.github]
type = "github-oauth"
client_id = "Iv1.0123456789abcdef"
env_var = "GH_TOKEN"
```

```sh
fnox exec -- gh pr list
```

On first use fnox prints a verification URL and a one-time code, and opens the URL in your browser. Approve the request; later runs reuse or refresh the cached token without prompting.

## Bootstrap credentials

This backend needs no stored secret. The client ID is public, so the config can be committed and shared; there is no app private key or client secret to distribute. Create a GitHub App, enable **device flow** in its settings, and use its client ID.

fnox caches the access token, and the refresh token when GitHub issues one, in the OS keyring under `keyring_service`. On each lease it:

1. Reuses the cached token if it is valid for at least 5 more minutes.
2. Otherwise refreshes it with the refresh token, if that has not expired.
3. Otherwise starts the device flow again.

In non-interactive mode (`--non-interactive` or `FNOX_NON_INTERACTIVE`), fnox fails instead of starting the device flow. Authorize once with `fnox lease create github` from a terminal, then rerun the non-interactive job on the same machine.

## Configuration

| Field             | Required | Default                            | Description                                                                                   |
| ----------------- | -------- | ---------------------------------- | --------------------------------------------------------------------------------------------- |
| `client_id`       | Yes      | none                               | GitHub App client ID.                                                                         |
| `scope`           | No       | `"repo read:org workflow"`         | Scope string sent with the device code request.                                               |
| `env_var`         | No       | `"GITHUB_TOKEN"`                   | Variable that receives the token.                                                             |
| `keyring_service` | No       | `"fnox-github-oauth"`              | OS keyring service for cached tokens.                                                         |
| `keyring_cache`   | No       | `true`                             | Set to `false` to skip the OS keyring and run the device flow whenever a new lease is needed. |
| `open_browser`    | No       | `true`                             | Try to open the verification URL in a browser.                                                |
| `auth_base`       | No       | `"https://github.com/login/oauth"` | OAuth base URL. The device code endpoint is derived from it.                                  |
| `api_base`        | No       | `"https://api.github.com"`         | API base URL, used to look up the signed-in user.                                             |
| `duration`        | No       | `"15m"`                            | Must be at most `"8h"`. Otherwise ignored; GitHub sets the lifetime.                          |

The keyring entry is keyed by `client_id`, `scope`, `auth_base` and `api_base`, so changing any of them starts a fresh authorization. With `keyring_cache = false`, fnox still reuses active leases from its lease ledger for the current project.

## Troubleshooting

### Interactive auth required

The cached token is missing or expired and fnox is running non-interactively. Run `fnox lease create <lease-name>` in a terminal, then retry.

### Device authorization expired or denied

The code was not approved in time, or the request was declined. Run the command again for a new code.

### Failed to cache GitHub OAuth token in keyring

fnox could not write to the OS keyring, as on a headless Linux machine without Secret Service. The lease still works, but the next lease needs the device flow again. Set `keyring_cache = false` to stop the warning.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [GitHub App](/leases/github-app): installation tokens for CI and automation.
- [Lease commands](/cli/lease): create, list and revoke leases.
