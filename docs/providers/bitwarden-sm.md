---
description: "Read Bitwarden Secrets Manager values with the bws CLI, a machine-account access token, and secret UUIDs."
---

# Bitwarden Secrets Manager

Integrate with [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) to retrieve secrets via the `bws` CLI. This is a separate product from Bitwarden Password Manager — it's designed for DevOps and infrastructure secrets.

## Quick start

Create a project and access token in Bitwarden Secrets Manager first. This provider uses `bws`, not the password manager's `bw` CLI.

```sh
# Install bws CLI (see Installation below)
brew install bws

# Set access token
export BWS_ACCESS_TOKEN="your-access-token"
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
bws = { type = "bitwarden-sm", project_id = "your-project-id" }
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[secrets]
DATABASE_URL = { provider = "bws", value = "database-url" }
```

```sh
# Use it
fnox get DATABASE_URL
fnox exec -- npm start
```

## Prerequisites

- [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/) account
- [Bitwarden Secrets Manager CLI](https://bitwarden.com/help/secrets-manager-cli/) (`bws`)
- Access token (machine account or personal)

## Installation

Install the `bws` CLI:

```bash
# macOS
brew install bws

# Or download from GitHub releases
# https://github.com/bitwarden/sdk-sm/releases
```

## Setup

### 1. Create an access token

In the Bitwarden Secrets Manager web console:

1. Go to **Machine accounts** (or **Service accounts**)
2. Create a new machine account
3. Generate an access token
4. Note the project ID you want to access

### 2. Set the access token

```bash
# Set directly
export BWS_ACCESS_TOKEN="your-access-token"

# Or store encrypted with age for bootstrap
fnox set BWS_ACCESS_TOKEN "<your-access-token>" --provider age
```

### 3. Configure the provider

```toml
[providers]
bws = { type = "bitwarden-sm", project_id = "your-project-id" }
```

The `project_id` can also be provided via the `BWS_PROJECT_ID` environment variable instead of in the config file.

## Referencing secrets

Secrets are referenced by their key name in Bitwarden Secrets Manager:

```toml
[secrets]
DATABASE_URL = { provider = "bws", value = "database-url" }
API_KEY = { provider = "bws", value = "stripe-api-key" }
```

### Field access

By default, the secret's `value` field is returned. You can also access `key` and `note` fields:

```toml
[secrets]
# Gets the secret value (default)
MY_SECRET = { provider = "bws", value = "my-secret-name" }

# Gets the secret's note
MY_NOTE = { provider = "bws", value = "my-secret-name/note" }

# Gets the secret's key name
MY_KEY = { provider = "bws", value = "my-secret-name/key" }
```

Supported fields: `value` (default), `key`, `note`

## Provider configuration

```toml
[providers]
bws = { type = "bitwarden-sm", project_id = "...", profile = "..." }
```

| Field        | Required | Description                                           |
| ------------ | -------- | ----------------------------------------------------- |
| `project_id` | No       | BSM project ID (or set `BWS_PROJECT_ID` env var)      |
| `profile`    | No       | bws CLI profile (for self-hosted or multiple servers) |

## Environment variables

| Variable                | Description                            |
| ----------------------- | -------------------------------------- |
| `BWS_ACCESS_TOKEN`      | Bitwarden Secrets Manager access token |
| `FNOX_BWS_ACCESS_TOKEN` | Alternative (takes priority)           |
| `BWS_PROJECT_ID`        | Project ID fallback (if not in config) |

## Usage

```bash
# Get a secret
fnox get DATABASE_URL

# Run commands with secrets loaded
fnox exec -- npm start

# List configured secrets
fnox list

# Set a secret (creates or updates in BSM)
fnox set NEW_SECRET "secret-value" --provider bws --key-name "my-new-secret"
```

## Multi-environment example

```toml
[providers]
age = { type = "age", recipients = ["age1..."] }
bws = { type = "bitwarden-sm", project_id = "dev-project-id" }

[secrets]
BWS_ACCESS_TOKEN = { provider = "age", value = "encrypted-token..." }
DATABASE_URL = { provider = "bws", value = "dev-database-url" }

[profiles.production.providers]
bws = { type = "bitwarden-sm", project_id = "prod-project-id" }

[profiles.production.secrets]
DATABASE_URL = { provider = "bws", value = "prod-database-url" }
```

## CI/CD example

### GitHub Actions

```yaml
name: Deploy
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v4

      - name: Deploy with secrets
        env:
          BWS_ACCESS_TOKEN: ${{ secrets.BWS_ACCESS_TOKEN }}
        run: |
          fnox exec -- ./deploy.sh
```

## Bitwarden sm vs Bitwarden password manager

| Feature | Bitwarden SM (`bitwarden-sm`) | Bitwarden PM (`bitwarden`) |
| ------- | ----------------------------- | -------------------------- |
| CLI     | `bws`                         | `bw`                       |
| Auth    | Access token                  | Session token              |
| Purpose | DevOps / machine secrets      | Personal passwords         |
| Model   | Key-value secrets in projects | Vault items with fields    |

## Troubleshooting

### "Access token not found"

```bash
export BWS_ACCESS_TOKEN=<your-token>
# Or: export FNOX_BWS_ACCESS_TOKEN=<your-token>
```

### "Project ID not configured"

Either set it in the provider config:

```toml
[providers]
bws = { type = "bitwarden-sm", project_id = "your-project-id" }
```

Or via environment variable:

```bash
export BWS_PROJECT_ID=<your-project-id>
```

### "Secret not found"

Check the secret exists in your project:

```bash
bws secret list <project-id> --output json | jq '.[].key'
```

### "bws CLI not found"

```bash
brew install bws
```

## Next steps

- [Bitwarden Password Manager](/providers/bitwarden) - For personal vault secrets
- [AWS Secrets Manager](/providers/aws-sm) - AWS alternative
- [HashiCorp Vault](/providers/vault) - Self-hosted alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
