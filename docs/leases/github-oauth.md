# GitHub OAuth

The `github-oauth` lease backend creates GitHub App user access tokens with OAuth device flow. It is useful for local automation where you want `GITHUB_TOKEN` or `GH_TOKEN` to be short-lived and tied to the signed-in GitHub user, without storing a personal access token in `fnox.toml`.

Unlike `github-app`, this backend only needs the GitHub App client ID. It does not require an app private key or app client secret, so the config can be shared safely across a team.

Tokens are cached in the OS keyring by default and refreshed when GitHub returns a refresh token.

## Configuration

```toml
[leases.github]
type = "github-oauth"
client_id = "Iv1.yourgithubappclientid"
scope = "repo read:org workflow"
duration = "8h"
```

| Field             | Required | Description                                                                 |
| ----------------- | -------- | --------------------------------------------------------------------------- |
| `client_id`       | Yes      | GitHub App client ID; no app secret or private key is required              |
| `scope`           | No       | OAuth scopes to request (default: `"repo read:org workflow"`)               |
| `env_var`         | No       | Environment variable name for the token (default: `"GITHUB_TOKEN"`)         |
| `keyring_service` | No       | OS keyring service for cached tokens (default: `"fnox-github-oauth"`)       |
| `keyring_cache`   | No       | Cache access/refresh tokens in the OS keyring (default: `true`)             |
| `open_browser`    | No       | Try to open the device verification URL in a browser (default: `true`)      |
| `auth_base`       | No       | OAuth token endpoint base URL (default: `"https://github.com/login/oauth"`) |
| `api_base`        | No       | GitHub API base URL (default: `"https://api.github.com"`)                   |
| `duration`        | No       | Requested duration; GitHub controls the actual token lifetime               |

## Prerequisites

Create a GitHub App with device flow enabled and use its client ID. On first use, fnox prints a GitHub device verification URL and user code:

```bash
fnox exec -- gh pr list
```

Approve the device prompt in your browser. Subsequent runs reuse the cached token while it remains valid.

## Credentials Produced

| Environment Variable | Description              |
| -------------------- | ------------------------ |
| `GITHUB_TOKEN`       | GitHub user access token |

The env var name is configurable via the `env_var` field.

## Examples

### GitHub CLI

```toml
[leases.github]
type = "github-oauth"
client_id = "Iv1.yourgithubappclientid"
env_var = "GH_TOKEN"
```

```bash
fnox exec -- gh pr checkout 123
```

### Disable OS keyring cache

```toml
[leases.github]
type = "github-oauth"
client_id = "Iv1.yourgithubappclientid"
keyring_cache = false
```

With keyring caching disabled, fnox still caches active lease credentials in its lease ledger for the current project.

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
- [GitHub App](/leases/github-app) — installation access tokens for automation
