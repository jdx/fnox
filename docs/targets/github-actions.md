---
description: "Push fnox secrets to GitHub Actions, Dependabot and Codespaces secrets with gh secret set, for a repository, environment or organization."
---

# GitHub Actions

The `github-actions` target sets [GitHub Actions secrets](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions) with [`gh secret set`](https://cli.github.com/manual/gh_secret_set), which handles GitHub's encryption. It can also set Dependabot and Codespaces secrets.

|                     |                                                                        |
| ------------------- | ---------------------------------------------------------------------- |
| Config type         | `github-actions`                                                       |
| Requires            | `gh`, logged in with `gh auth login` as someone who can manage secrets |
| Readable afterwards | No. GitHub stores secrets encrypted and never returns them             |

## Quick start

```toml
[targets.gh-prod]
type = "github-actions"
repo = "acme/api"
environment = "production"

[secrets]
STRIPE_KEY = { provider = "op", value = "Stripe/secret key", push = ["gh-prod"] }
```

```sh
fnox push --dry-run
fnox push
```

Without `repo`, `gh` uses the repository of the current directory.

## Configuration

| Field         | Default            | Description                                                                          |
| ------------- | ------------------ | ------------------------------------------------------------------------------------ |
| `repo`        | current repository | Repository as `owner/name`.                                                          |
| `environment` | none               | Deployment environment to set the secret in, instead of the repository.              |
| `org`         | none               | Organization to set the secret in. Conflicts with `repo` and `environment`.          |
| `visibility`  | GitHub's default   | For an org secret: `"all"`, `"private"`, or `"selected"` repositories.               |
| `repos`       | none               | For `visibility = "selected"`: the repositories that can use the secret.             |
| `app`         | `"actions"`        | `"actions"`, `"dependabot"`, or `"codespaces"`. Environments exist only for Actions. |

```toml
[targets.org-deps]
type = "github-actions"
org = "acme"
visibility = "selected"
repos = ["api", "web"]
app = "dependabot"
```

## Notes

- The secret name is the fnox key. GitHub rejects names that start with `GITHUB_` or a digit.
