---
description: "Create short-lived GitLab project or group access tokens with fnox from a parent token, on GitLab.com or self-hosted, and delete them on revoke."
---

# GitLab

The `gitlab` lease backend uses a parent token to create a [project or group access token](https://docs.gitlab.com/user/project/settings/project_access_tokens/) with the scopes and role you choose, and injects it into `fnox exec`. The child token is named `fnox-lease-<label>` so you can find it in GitLab, and fnox deletes it when you revoke the lease.

|              |                                                                                     |
| ------------ | ----------------------------------------------------------------------------------- |
| Config type  | `gitlab`                                                                            |
| Produces     | `GITLAB_TOKEN` (configurable with `env_var`)                                        |
| Max duration | 24 hours; GitLab expiry has one-day granularity                                     |
| Revocation   | Yes; fnox deletes the token                                                         |
| Needs        | A parent token with the `api` scope and the Maintainer role on the project or group |

## Quick start

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
GITLAB_TOKEN = { provider = "op", value = "GitLab/automation token", env = false }

[leases.gl]
type = "gitlab"
project = "platform/api"
scopes = ["read_api", "read_repository"]
duration = "1h"
```

```sh
fnox exec -- sh -c 'curl -fsS -H "PRIVATE-TOKEN: $GITLAB_TOKEN" https://gitlab.com/api/v4/projects/platform%2Fapi'
```

The command sees the child token in `GITLAB_TOKEN`; the parent token stays out of its environment.

## Bootstrap credentials

fnox reads the parent token from `GITLAB_TOKEN`. Store it as a secret with that name, as in the quick start, or export it. `fnox lease create -i gl` prompts for it when it is not set.

The parent needs the `api` scope and a role that may create access tokens on the project or group (Maintainer or Owner). GitLab does not let a token grant a role higher than its creator's. Whether project and group access tokens are available depends on your GitLab plan and instance settings.

## Configuration

Set exactly one of `project` or `group`.

| Field          | Required   | Default                | Description                                                                                                             |
| -------------- | ---------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `project`      | One of two | none                   | Project ID or full path, such as `platform/api`. Creates a project access token.                                        |
| `group`        | One of two | none                   | Group ID or full path. Creates a group access token.                                                                    |
| `url`          | No         | `"https://gitlab.com"` | Base URL of a self-hosted GitLab. Must use https; http is accepted only for localhost. Redirects are not followed.      |
| `scopes`       | No         | `["read_api"]`         | [Token scopes](https://docs.gitlab.com/user/project/settings/project_access_tokens/#scopes-for-a-project-access-token). |
| `access_level` | No         | `"developer"`          | Role of the token: `"guest"`, `"reporter"`, `"developer"`, `"maintainer"` or `"owner"`.                                 |
| `env_var`      | No         | `"GITLAB_TOKEN"`       | Variable that receives the child token.                                                                                 |
| `duration`     | No         | `"15m"`                | Lease length. At most `"24h"`.                                                                                          |

### Expiry has one-day granularity

GitLab only accepts an expiry _date_, and a token stops working at the start of that day. fnox sends the day after the lease ends, so the token always outlives the lease, by up to a day. fnox stops reusing it when the lease expires, but the token stays valid until you revoke it or GitLab expires it.

To close that window, revoke when you are done:

```sh
fnox lease revoke <lease-id>   # one lease
fnox lease cleanup             # every expired lease
```

## Troubleshooting

### GitLab token not found

`GITLAB_TOKEN` is not set when the lease is created. Under `fnox exec`, the lease is skipped with this warning unless a cached lease is still valid.

### HTTP 401 or 403

The parent token is invalid, lacks the `api` scope, or its role on the project or group cannot create a token with the requested `access_level`.

### Set exactly one of 'project' or 'group'

The lease has both, or neither. Remove one.

### url must use https

The parent token is sent to `url`, so fnox refuses `http://` except for `localhost`, `127.0.0.1` and `::1`, and does not follow redirects. Point `url` at the final address.

### HTTP 404

The `project` or `group` does not exist or the parent token cannot see it. A path with slashes is fine; fnox encodes it.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [Lease commands](/cli/lease): revoke or clean up tokens with `fnox lease revoke` and `fnox lease cleanup`.
- [GitHub App](/leases/github-app): the equivalent for GitHub.
- [Custom command](/leases/command): wrap another token API with your own script.
