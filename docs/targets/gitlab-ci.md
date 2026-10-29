---
description: "Push fnox secrets to GitLab CI/CD project and group variables with glab, including masked, protected and environment-scoped variables."
---

# GitLab CI/CD

The `gitlab-ci` target sets [GitLab CI/CD variables](https://docs.gitlab.com/ci/variables/) with [`glab variable set`](https://gitlab.com/gitlab-org/cli/-/blob/main/docs/source/variable/set.md). If the variable already exists, `set` fails and fnox runs `glab variable update` instead.

|                     |                                                                                  |
| ------------------- | -------------------------------------------------------------------------------- |
| Config type         | `gitlab-ci`                                                                      |
| Requires            | `glab`, logged in with `glab auth login` as a maintainer of the project or group |
| Readable afterwards | Yes, by maintainers in the project's CI/CD settings                              |

## Quick start

```toml
[targets.gitlab-prod]
type = "gitlab-ci"
repo = "acme/api"
environment = "production"
masked = true
protected = true

[secrets]
DEPLOY_TOKEN = { provider = "age", value = "YWdl...", push = ["gitlab-prod"] }
```

Without `repo` or `group`, `glab` uses the project of the current directory.

## Configuration

| Field           | Default          | Description                                                                   |
| --------------- | ---------------- | ----------------------------------------------------------------------------- |
| `repo`          | current project  | Project as `group/name`.                                                      |
| `group`         | none             | Group to set the variable in, instead of a project. Conflicts with `repo`.    |
| `environment`   | all environments | Environment scope of a project variable.                                      |
| `masked`        | GitLab's default | Hide the value in job logs. GitLab rejects values it cannot mask.             |
| `protected`     | GitLab's default | Expose the variable only to protected branches and tags.                      |
| `raw`           | GitLab's default | Do not expand `$` references in the value.                                    |
| `variable_type` | `"env_var"`      | `"env_var"` for the value itself, `"file"` for the path of a file holding it. |
| `description`   | none             | Description shown in GitLab.                                                  |

`masked`, `protected`, and `raw` are passed only when set, so on an update an unset field keeps its current value in GitLab.

## Notes

- A failed push shows the errors from both `set` and `update`, since fnox cannot tell "already exists" from other failures.
