# Pulumi ESC

Integrate with [Pulumi ESC](https://www.pulumi.com/product/esc/) (Environments, Secrets, and Configuration) to retrieve values and dynamic credentials from your Pulumi environments.

## Quick Start

```bash
# 1. Install the Pulumi ESC CLI
brew install pulumi/tap/esc

# 2. Authenticate
esc login
# ...or set a token
export PULUMI_ACCESS_TOKEN="pul-xxxx"

# 3. Configure the provider
cat >> fnox.toml << 'EOF'
[providers]
pulumi-esc = { type = "pulumi-esc", organization = "my-org", project = "my-project", environment = "dev" }

[secrets]
DATABASE_URL = { provider = "pulumi-esc", value = "database.url" }
EOF

# 4. Use it
fnox get DATABASE_URL
```

## Prerequisites

- [Pulumi Cloud account](https://app.pulumi.com/)
- [`esc` CLI](https://www.pulumi.com/docs/esc/download-install/)

## Installation

```bash
# macOS
brew install pulumi/tap/esc

# Linux / macOS (install script)
curl -fsSL https://get.pulumi.com/esc/install.sh | sh
```

## Authentication

fnox resolves the access token in this order:

1. `token` field in the provider config
2. `FNOX_PULUMI_ACCESS_TOKEN` environment variable
3. `PULUMI_ACCESS_TOKEN` environment variable
4. Interactive login session (from `esc login`)

For CI, create a team or personal access token in the Pulumi Cloud console and set
`PULUMI_ACCESS_TOKEN` on the runner.

## Configuration

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

For a single `fnox get` call, fnox runs `esc env get <env> <path> --value string --show-secrets`.
When fetching multiple secrets at once (e.g. `fnox exec`), fnox calls `esc env open <env> --format json` once and extracts each path locally.

## Leases (dynamic credentials)

Pulumi ESC can mint short-lived credentials for AWS, GCP, Azure, Vault, and more via OIDC. fnox exposes these through the lease system:

```toml
[lease_backends.aws-dev]
type = "pulumi-esc"
organization = "my-org"
project = "my-project"
environment = "aws-dev"
# Optional: filter which environmentVariables are surfaced.
env_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
duration = "1h"

[secrets]
AWS_ACCESS_KEY_ID     = { lease = "aws-dev" }
AWS_SECRET_ACCESS_KEY = { lease = "aws-dev" }
AWS_SESSION_TOKEN     = { lease = "aws-dev" }
```

When fnox needs an env var backed by this lease, it runs `esc env open` once, caches the resulting credentials in the lease ledger, and reuses them until the configured duration elapses.

**Lease options:**

- `organization`, `project`, `environment`, `token` — same semantics as the provider.
- `env_vars` (optional list) — only surface these keys from the ESC environment's `environmentVariables` block. When omitted, all env vars are surfaced but `fnox get` cannot auto-route individual keys through the lease.
- `duration` (optional) — advisory lease TTL; actual credential lifetime is bounded by the underlying cloud integration (typically ≤ 1 hour).

## CI/CD Example

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

## Cons

- ❌ Requires Pulumi Cloud (or a self-managed equivalent)
- ❌ Paid beyond the free tier

## Troubleshooting

### "Unauthorized" / "invalid access token"

```bash
esc login
# or rotate the access token
export PULUMI_ACCESS_TOKEN=pul-xxxx
```

### "environment not found"

```bash
esc env ls
esc env get my-org/my-project/dev
```

### "path not found"

List the environment's resolved values and verify the path:

```bash
esc env open my-org/my-project/dev
```

## Next Steps

- [Doppler](/providers/doppler) - Alternative cloud secrets manager
- [HashiCorp Vault](/providers/vault) - Self-hosted alternative
- [Leases](/leases/overview) - Short-lived dynamic credentials
