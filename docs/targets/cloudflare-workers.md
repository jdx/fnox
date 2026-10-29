---
description: "Push fnox secrets to Cloudflare Workers secrets with wrangler secret put, for a named Worker and Wrangler environment."
---

# Cloudflare Workers

The `cloudflare-workers` target sets [Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/) with [`wrangler secret put`](https://developers.cloudflare.com/workers/wrangler/commands/workers/), which creates or replaces the secret.

|                     |                                                       |
| ------------------- | ----------------------------------------------------- |
| Config type         | `cloudflare-workers`                                  |
| Requires            | `wrangler` on `PATH`, logged in with `wrangler login` |
| Readable afterwards | No                                                    |

## Quick start

```toml
[targets.worker]
type = "cloudflare-workers"
worker = "api"

[secrets]
STRIPE_KEY = { provider = "op", value = "Stripe/secret key", push = ["worker"] }
```

## Configuration

| Field         | Default                     | Description                                     |
| ------------- | --------------------------- | ----------------------------------------------- |
| `worker`      | name in the Wrangler config | Worker to set the secret on.                    |
| `environment` | none                        | Wrangler environment, as with `wrangler --env`. |

## Notes

- Each push deploys a new version of the Worker.
- If Wrangler is only a project dependency, put it on `PATH`, for example with `mise use npm:wrangler`.
- Cloudflare Pages secrets are not supported yet.
