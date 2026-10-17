---
description: "Create one-hour GitHub App installation tokens with fnox, scoped to permissions and repositories, from the app's private key."
---

# GitHub App

The `github-app` lease backend signs a JWT with a GitHub App's private key, exchanges it for an [installation access token](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app), and injects the token into `fnox exec`. Use it in CI and automation instead of a long-lived personal access token.

|              |                                                                  |
| ------------ | ---------------------------------------------------------------- |
| Config type  | `github-app`                                                     |
| Produces     | `GITHUB_TOKEN` (configurable with `env_var`)                     |
| Max duration | 1 hour, set by GitHub                                            |
| Revocation   | Yes, with `DELETE /installation/token` when the token was cached |
| Needs        | The app's private key                                            |

::: tip
For local, user-attributed access, [`github-oauth`](/leases/github-oauth) needs only the app's client ID, so there is no private key to distribute.
:::

## Quick start

```toml
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "~/.config/fnox/github-app.pem"

[leases.github.permissions]
contents = "read"
pull_requests = "write"
```

```sh
fnox exec -- gh pr list
```

The app ID is on the app's settings page. The installation ID is the number at the end of the installation's settings URL, `https://github.com/settings/installations/<installation_id>` (or the organization equivalent).

## Bootstrap credentials

fnox reads the PEM-encoded RSA private key from the first source available:

1. `FNOX_GITHUB_APP_PRIVATE_KEY`, containing the PEM text
2. The file at `private_key_file` (`~` is expanded)

To keep the key in a provider instead of a file, store it as a secret with that name. fnox resolves it for lease creation, and `env = false` keeps it out of the command:

```toml
[providers.op]
type = "1password"
vault = "Infrastructure"

[secrets]
FNOX_GITHUB_APP_PRIVATE_KEY = { provider = "op", value = "GitHub App/private key", env = false }

[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
```

Generate a key under **Private keys** in the app's settings.

## Configuration

| Field              | Required | Default                       | Description                                                                                 |
| ------------------ | -------- | ----------------------------- | ------------------------------------------------------------------------------------------- |
| `app_id`           | Yes      | none                          | GitHub App ID, used as the JWT issuer.                                                      |
| `installation_id`  | Yes      | none                          | Installation to create the token for.                                                       |
| `private_key_file` | No\*     | none                          | Path to the app's PEM private key.                                                          |
| `permissions`      | No       | all installation permissions  | Table of permission name to `"read"`, `"write"` or `"admin"`.                               |
| `repositories`     | No       | all installation repositories | Repository names (without owner) to limit the token to.                                     |
| `env_var`          | No       | `"GITHUB_TOKEN"`              | Variable that receives the token. Use `"GH_TOKEN"` for `gh` if you prefer.                  |
| `api_base`         | No       | `"https://api.github.com"`    | API base URL, for example `https://github.example.com/api/v3` for GitHub Enterprise Server. |
| `duration`         | No       | `"15m"`                       | Must be at most `"1h"`. Otherwise ignored; tokens always last about an hour.                |

\* Required unless `FNOX_GITHUB_APP_PRIVATE_KEY` is set.

`permissions` can only narrow what the installation already has. Names follow GitHub's [installation token API](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app), for example `contents`, `pull_requests`, `issues`, `actions` and `metadata`.

```toml
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "~/.config/fnox/github-app.pem"
repositories = ["api", "frontend"]

[leases.github.permissions]
contents = "read"
```

## Revocation

`fnox lease revoke <lease-id>` deletes the token on GitHub immediately. GitHub authenticates that call with the token itself, so fnox can only revoke tokens whose credentials it cached in the lease ledger. `fnox lease cleanup` handles expired tokens, which need no remote call.

## Troubleshooting

### GitHub App private key not found

`FNOX_GITHUB_APP_PRIVATE_KEY` is unset and `private_key_file` is missing or points to a file that does not exist. Under `fnox exec`, the lease is skipped with this warning unless a cached lease is still valid.

### Invalid RSA private key

The value is not a PEM RSA key. Use the `.pem` file GitHub generated, including its `BEGIN` and `END` lines.

### HTTP 401 or 403

Check `app_id` and that the key belongs to that app.

### HTTP 404

The `installation_id` is wrong, or the app is not installed on that account or organization.

### HTTP 422

`permissions` asks for more than the installation grants, or `repositories` names a repository the installation cannot access.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [GitHub OAuth](/leases/github-oauth): user access tokens through the device flow.
- [Lease commands](/cli/lease): create, list and revoke leases.
