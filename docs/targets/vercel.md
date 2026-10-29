---
description: "Push fnox secrets to Vercel project environment variables with vercel env add, for production, preview, development or custom environments."
---

# Vercel

The `vercel` target sets [Vercel environment variables](https://vercel.com/docs/environment-variables) with [`vercel env add`](https://vercel.com/docs/cli/env), once per environment, and replaces an existing variable with `--force`.

|                     |                                                                                   |
| ------------------- | --------------------------------------------------------------------------------- |
| Config type         | `vercel`                                                                          |
| Requires            | `vercel`, logged in, and `fnox push` run in a directory linked with `vercel link` |
| Readable afterwards | No when `sensitive = true`; otherwise yes, by team members                        |

## Quick start

```toml
[targets.vercel]
type = "vercel"
environments = ["production", "preview"]
sensitive = true

[secrets]
DATABASE_URL = { provider = "op", value = "Neon/url", push = ["vercel"] }
```

## Configuration

| Field          | Default             | Description                                                                              |
| -------------- | ------------------- | ---------------------------------------------------------------------------------------- |
| `environments` | required            | Environments to set: `production`, `preview`, `development`, or a custom environment.    |
| `git_branch`   | all branches        | Git branch for a preview variable. Requires `environments = ["preview"]`.                |
| `sensitive`    | Vercel's default    | `true` stores the value so it cannot be read back; `false` stores it as readable config. |
| `scope`        | linked project team | Team that owns the project.                                                              |

## Notes

- The project is the one linked in the current directory, so run `fnox push` from the project root.
- Vercel does not allow sensitive variables in `development`.
