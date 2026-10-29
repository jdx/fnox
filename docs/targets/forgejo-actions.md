---
description: "Push fnox secrets to Forgejo, Gitea and Codeberg Actions secrets through the REST API, for a repository or organization."
---

# Forgejo and Gitea

The `forgejo-actions` target sets Actions secrets on a [Forgejo](https://forgejo.org/docs/latest/user/actions/) or Gitea instance, such as Codeberg, with `PUT /api/v1/repos/{owner}/{repo}/actions/secrets/{name}`.

|                     |                                                     |
| ------------------- | --------------------------------------------------- |
| Config type         | `forgejo-actions`                                   |
| Requires            | An access token in `FORGEJO_TOKEN` or `GITEA_TOKEN` |
| Readable afterwards | No                                                  |

## Quick start

```toml
[targets.codeberg]
type = "forgejo-actions"
url = "https://codeberg.org"
repo = "acme/api"

[secrets]
DEPLOY_KEY = { provider = "age", value = "YWdl...", push = ["codeberg"] }
```

```sh
FORGEJO_TOKEN=... fnox push
```

## Configuration

| Field  | Default  | Description                                                            |
| ------ | -------- | ---------------------------------------------------------------------- |
| `url`  | required | Base URL of the instance. Must be https, except for localhost.         |
| `repo` | none     | Repository as `owner/name`.                                            |
| `org`  | none     | Organization to set the secret in. Set exactly one of `repo` or `org`. |

## Authentication

fnox reads the token from `FORGEJO_TOKEN`, then `GITEA_TOKEN`. It needs the `write:repository` scope for a repository secret, or `write:organization` for an organization secret. To keep the token in fnox too, run `fnox exec -- fnox push` with the token defined as a secret.
