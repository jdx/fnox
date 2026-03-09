# GitHub App

The `github-app` lease backend creates short-lived [GitHub App installation access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) using a GitHub App's private key. Installation tokens expire after 1 hour (GitHub's hard limit) and can be scoped to specific permissions and repositories.

This is ideal for CI/CD pipelines and automation workflows where you need scoped, short-lived GitHub access instead of long-lived personal access tokens.

## Configuration

```toml
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "~/.config/fnox/github-app.pem"
duration = "1h"

[leases.github.permissions]
contents = "read"
pull_requests = "write"
```

| Field              | Required | Description                                                                          |
| ------------------ | -------- | ------------------------------------------------------------------------------------ |
| `app_id`           | Yes      | GitHub App ID (found in the app's settings page)                                     |
| `installation_id`  | Yes      | Installation ID (from the app's installation URL or API)                             |
| `private_key_file` | No\*     | Path to the GitHub App's PEM private key file (supports `~` expansion)               |
| `env_var`          | No       | Environment variable name for the token (default: `"GITHUB_TOKEN"`)                  |
| `permissions`      | No       | Map of permission names to access levels (omit to use all installation permissions)  |
| `repositories`     | No       | Array of repository names to scope the token to (omit for all installed repos)       |
| `api_base`         | No       | GitHub API base URL (default: `"https://api.github.com"`; set for GitHub Enterprise) |
| `duration`         | No       | Ignored — GitHub controls token lifetime (always 1 hour)                             |

\* Required unless `FNOX_GITHUB_APP_PRIVATE_KEY` is set.

### Permission values

Permissions use GitHub's [installation token permission names](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app). Each permission maps to an access level:

| Access Level | Description         |
| ------------ | ------------------- |
| `"read"`     | Read-only access    |
| `"write"`    | Read and write      |
| `"admin"`    | Full administrative |

## Prerequisites

The backend needs a GitHub App private key. fnox looks for it in order:

1. `FNOX_GITHUB_APP_PRIVATE_KEY` environment variable (PEM contents)
2. `private_key_file` config option (path to PEM file)

If neither is found, fnox prints:

```
GitHub App private key not found. Set FNOX_GITHUB_APP_PRIVATE_KEY or configure private_key_file pointing to a PEM file.
```

### Getting the app ID and installation ID

1. **App ID**: Go to your GitHub App's settings page (`Settings > Developer settings > GitHub Apps > Your App`). The App ID is shown near the top.

2. **Installation ID**: After installing the app on an organization or account, the installation ID is in the URL: `https://github.com/settings/installations/{installation_id}`. You can also find it via the API:

```bash
# List installations for your app (requires JWT auth)
curl -H "Authorization: Bearer $JWT" \
  https://api.github.com/app/installations
```

### Generating a private key

In your GitHub App settings, scroll to "Private keys" and click "Generate a private key". Save the downloaded PEM file to a secure location.

## Credentials Produced

| Environment Variable | Description                           |
| -------------------- | ------------------------------------- |
| `GITHUB_TOKEN`       | Short-lived installation access token |

The env var name is configurable via the `env_var` field.

## Limits

- **Max duration:** 1 hour (enforced by GitHub)
- **Revocation:** Not supported — tokens auto-expire. GitHub's revocation API requires the token itself (not a lease ID), so fnox relies on the short TTL.

## Examples

### Minimal

```toml
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "~/.config/fnox/github-app.pem"
```

The token gets all permissions and repository access granted to the installation.

```bash
fnox exec -- gh pr list
```

### Scoped to specific permissions

```toml
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "~/.config/fnox/github-app.pem"

[leases.github.permissions]
contents = "read"
pull_requests = "write"
issues = "write"
```

### Scoped to specific repositories

```toml
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "~/.config/fnox/github-app.pem"
repositories = ["my-org/api", "my-org/frontend"]

[leases.github.permissions]
contents = "read"
```

### With stored private key

Instead of a file, store the private key in a provider:

```toml
[providers.op]
type = "1password"
vault = "Infrastructure"

[secrets]
FNOX_GITHUB_APP_PRIVATE_KEY = { provider = "op", value = "GitHub App/private key" }

[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
```

fnox resolves the secret first, then the lease backend picks it up from the environment.

### Custom env var

```toml
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "~/.config/fnox/github-app.pem"
env_var = "GH_TOKEN"
```

### GitHub Enterprise

```toml
[leases.github]
type = "github-app"
app_id = "12345"
installation_id = "67890"
private_key_file = "~/.config/fnox/github-app.pem"
api_base = "https://github.example.com/api/v3"
```

### Common permissions

| Permission          | Description                            |
| ------------------- | -------------------------------------- |
| `contents`          | Repository contents, commits, branches |
| `pull_requests`     | Pull requests                          |
| `issues`            | Issues and comments                    |
| `actions`           | GitHub Actions workflows               |
| `packages`          | GitHub Packages                        |
| `deployments`       | Deployment statuses                    |
| `environments`      | Deployment environments                |
| `metadata`          | Repository metadata (always read-only) |
| `administration`    | Repository settings                    |
| `members`           | Organization members                   |
| `organization_plan` | Organization billing info              |

See the [GitHub API docs](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app) for the full list.

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
