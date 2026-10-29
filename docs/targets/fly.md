---
description: "Push fnox secrets to Fly.io app secrets with fly secrets import, optionally staged without a redeploy."
---

# Fly.io

The `fly` target sets [Fly.io app secrets](https://fly.io/docs/apps/secrets/) with [`fly secrets import`](https://fly.io/docs/flyctl/secrets-import/), which reads `NAME=VALUE` lines from stdin.

|                     |                                                 |
| ------------------- | ----------------------------------------------- |
| Config type         | `fly`                                           |
| Requires            | `fly` (flyctl), logged in with `fly auth login` |
| Readable afterwards | No. Fly shows only a digest                     |

## Quick start

```toml
[targets.fly]
type = "fly"
app = "acme-api"

[secrets]
DATABASE_URL = { provider = "op", value = "Postgres/url", push = ["fly"] }
```

## Configuration

| Field   | Default           | Description                                                        |
| ------- | ----------------- | ------------------------------------------------------------------ |
| `app`   | app in `fly.toml` | App to set the secret on.                                          |
| `stage` | `false`           | Set the secret without redeploying; it applies on the next deploy. |

## Notes

- Without `stage`, each push redeploys the app's Machines.
- flyctl's import format strips comments and quotes, so fnox wraps each value in `"""`, which flyctl keeps verbatim. fnox refuses the few values that would still change: a carriage return, a line ending in `"""` before the last line, a `#` in the first line after an odd number of `"`, or a line over 60 KiB.
