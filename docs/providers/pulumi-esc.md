# Pulumi ESC

Integrate with [Pulumi ESC](https://www.pulumi.com/product/esc/) (Environments, Secrets, and Configuration) to retrieve values and dynamic credentials from your Pulumi environments. fnox talks to the Pulumi Cloud REST API directly — no `esc` CLI required at runtime.

## Quick Start

```bash
# 1. Get a Pulumi access token (either way works):
#    - Create a token in https://app.pulumi.com/account/tokens and export it:
export PULUMI_ACCESS_TOKEN="pul-xxxx"
#    - OR run `esc login` once on this machine (writes ~/.pulumi/credentials.json)

# 2. Configure the provider
cat >> fnox.toml << 'EOF'
[providers]
pulumi-esc = { type = "pulumi-esc", organization = "my-org", project = "my-project", environment = "dev" }

[secrets]
DATABASE_URL = { provider = "pulumi-esc", value = "database.url" }
EOF

# 3. Use it
fnox get DATABASE_URL
```

## Prerequisites

- [Pulumi Cloud account](https://app.pulumi.com/)
- A Pulumi access token (interactive developer login via `esc login`, or a service-account token for CI)

The `esc` CLI is **not** required — fnox calls the Pulumi Cloud REST API (`/api/esc/environments/{ref}/open` + `/open/{id}`) directly via HTTP.

## Configuration

### Authentication

fnox resolves the access token in this order:

1. `token` field in the provider config
2. `FNOX_PULUMI_ACCESS_TOKEN` environment variable
3. `PULUMI_ACCESS_TOKEN` environment variable
4. `$PULUMI_HOME/credentials.json` (default: `~/.pulumi/credentials.json`) — written by `esc login`

The credentials file's `current` field also determines the API base URL, so self-hosted Pulumi Cloud works without extra config. The env-var path honors `PULUMI_BACKEND_URL` (default `https://api.pulumi.com`).

For CI, create a team or personal access token in the Pulumi Cloud console and set `PULUMI_ACCESS_TOKEN` on the runner.

```toml
[providers]
pulumi-esc = { type = "pulumi-esc", organization = "my-org", project = "my-project", environment = "dev" }
```

**Options:**

- `organization` (required) — Pulumi organization name.
- `project` (optional) — Pulumi project name. Omit for legacy `<org>/<env>` environments.
- `environment` (required) — ESC environment name.
- `token` (optional) — access token. Overrides `PULUMI_ACCESS_TOKEN`.

## Referencing Secrets

The `value` of each secret is a [property path](https://www.pulumi.com/docs/esc/environments/working-with-environments/) into the ESC environment's resolved values, using dot notation.

```toml
[secrets]
DATABASE_URL = { provider = "pulumi-esc", value = "database.url" }
API_KEY      = { provider = "pulumi-esc", value = "apiKey" }
```

For every `fnox get` call (single or batch via `fnox exec`), fnox opens the environment once via the REST API and extracts each path from the resolved `properties` tree locally.

## Usage

```bash
# Get a single secret
fnox get DATABASE_URL

# Run commands with secrets injected
fnox exec -- ./deploy.sh
```

## Leases

Pulumi ESC can mint short-lived credentials for AWS, GCP, Azure, Vault, and more via OIDC. fnox exposes these through the lease system — see [Pulumi ESC lease backend](/leases/pulumi-esc) for configuration details. Short example:

```toml
[leases.aws-dev]
type = "pulumi-esc"
organization = "my-org"
project = "my-project"
environment = "aws-dev"
env_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
duration = "1h"

[secrets]
AWS_ACCESS_KEY_ID     = { lease = "aws-dev" }
AWS_SECRET_ACCESS_KEY = { lease = "aws-dev" }
AWS_SESSION_TOKEN     = { lease = "aws-dev" }
```

When fnox needs an env var backed by this lease, it opens the ESC environment once, caches the resulting credentials in the lease ledger, and reuses them until the configured duration elapses.

## CI/CD Example

### GitHub Actions

```yaml
name: Deploy
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v3

      - name: Deploy
        env:
          PULUMI_ACCESS_TOKEN: ${{ secrets.PULUMI_ACCESS_TOKEN }}
        run: |
          fnox exec -- ./deploy.sh
```

## Pros

- ✅ Composable environments (import and merge across projects)
- ✅ Built-in OIDC for short-lived AWS, GCP, Azure, and Vault credentials
- ✅ Centralised audit log on Pulumi Cloud
- ✅ Works well alongside Pulumi IaC without requiring it
- ✅ No runtime CLI dependency — pure HTTP against the Pulumi Cloud API

## Cons

- ❌ Requires Pulumi Cloud (or a self-managed equivalent)
- ❌ Paid beyond the free tier

## Troubleshooting

### "Unauthorized" / "invalid access token"

```bash
# Refresh login
esc login
# or rotate the access token
export PULUMI_ACCESS_TOKEN=pul-xxxx
```

### "environment not found"

Verify the organization / project / environment in your `fnox.toml` matches what's in Pulumi Cloud. If you have the `esc` CLI handy:

```bash
esc env ls
esc env get my-org/my-project/dev
```

Otherwise, open the environment in the Pulumi Cloud web console.

### "path not found"

The dot-path in your secret config didn't resolve. Inspect the environment's resolved values and confirm the path exists:

```bash
esc env open my-org/my-project/dev
```

## Next Steps

- [Doppler](/providers/doppler) - Alternative cloud secrets manager
- [HashiCorp Vault](/providers/vault) - Self-hosted alternative
- [Leases](/leases/overview) - Short-lived dynamic credentials
