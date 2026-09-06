---
description: "Load Doppler secrets with fnox using a project, config, and local login or service token."
---

# Doppler

Integrate with [Doppler](https://www.doppler.com/) to retrieve secrets from your Doppler projects and configs.

## Quick start

```sh
# Install Doppler CLI
brew install dopplerhq/cli/doppler

# Login to Doppler
doppler login
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
doppler = { type = "doppler", project = "my-project", config = "prd" }

[secrets]
DATABASE_URL = { provider = "doppler", value = "DATABASE_URL" }
```

```sh
# Use it
fnox get DATABASE_URL
```

## Prerequisites

- [Doppler account](https://www.doppler.com/)
- [Doppler CLI](https://docs.doppler.com/docs/cli)

## Installation

```bash
# macOS
brew install dopplerhq/cli/doppler

# Linux
curl -sLf --retry 3 --tlsv1.2 --proto "=https" 'https://packages.doppler.com/public/cli/gpg.DE2A7741A397C129.key' | sudo gpg --dearmor -o /usr/share/keyrings/doppler-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/doppler-archive-keyring.gpg] https://packages.doppler.com/public/cli/deb/debian any-version main" | sudo tee /etc/apt/sources.list.d/doppler-cli.list
sudo apt-get update && sudo apt-get install -y doppler

# Or install via mise
mise use -g "github:DopplerHQ/cli"
```

## Setup

### 1. Authentication

#### Option A: interactive login (local development)

```bash
doppler login
```

#### Option B: service token (CI/CD)

Create a service token in the Doppler dashboard scoped to a specific project and config:

```bash
export DOPPLER_TOKEN="dp.st.prd.xxxx"
```

### 2. Configure Doppler provider

```toml
[providers]
doppler = { type = "doppler", project = "my-project", config = "prd" }
```

**Configuration Options:**

All fields are optional. If not specified, the Doppler CLI will use its own defaults (from `doppler setup` or environment variables):

- `project` - Doppler project name. If omitted, uses the project configured via `doppler setup`.
- `config` - Doppler config (environment) name (e.g., "dev", "stg", "prd"). If omitted, uses the config configured via `doppler setup`.
- `token` - Service token for authentication. If omitted, uses the `FNOX_DOPPLER_TOKEN` or `DOPPLER_TOKEN` environment variable (in that order), or the interactive login session.

## Referencing secrets

```toml
[secrets]
DATABASE_URL = { provider = "doppler", value = "DATABASE_URL" }
API_KEY = { provider = "doppler", value = "API_KEY" }
```

The `value` is the secret key name in Doppler. The provider configuration determines the project and config scope.

## Usage

```bash
# Get a single secret
fnox get DATABASE_URL

# Run commands with secrets injected
fnox exec -- npm start
```

## Multi-environment example

Use named provider instances to pull secrets from different Doppler projects or configs:

```toml
[providers]
app-prod = { type = "doppler", project = "my-app", config = "prd" }
app-dev = { type = "doppler", project = "my-app", config = "dev" }
infra = { type = "doppler", project = "infra", config = "prd" }

[secrets]
PROD_DB_URL = { provider = "app-prod", value = "DATABASE_URL" }
DEV_DB_URL = { provider = "app-dev", value = "DATABASE_URL" }
AWS_KEY = { provider = "infra", value = "AWS_ACCESS_KEY_ID" }
```

Or use fnox profiles:

```toml
[providers]
doppler = { type = "doppler", project = "my-app", config = "dev" }

[secrets]
DATABASE_URL = { provider = "doppler", value = "DATABASE_URL" }

[profiles.staging.providers]
doppler = { type = "doppler", project = "my-app", config = "stg" }

[profiles.production.providers]
doppler = { type = "doppler", project = "my-app", config = "prd" }
```

Usage:

```bash
# Development (default)
fnox exec -- npm start

# Staging
fnox exec --profile staging -- npm start

# Production
fnox exec --profile production -- ./deploy.sh
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

      - name: Deploy
        env:
          DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
        run: |
          fnox exec -- ./deploy.sh
```

**Setup:**

1. Create a service token in the Doppler dashboard for the target project/config
2. Add the token to GitHub Secrets as `DOPPLER_TOKEN`

## Token management

### Environment variables

fnox checks for tokens in this order:

1. Provider config `token` field
2. `FNOX_DOPPLER_TOKEN` environment variable
3. `DOPPLER_TOKEN` environment variable
4. Interactive login session (from `doppler login`)

### Bootstrap pattern

Store the Doppler token encrypted for easy bootstrap:

```bash
# Store token encrypted with age
fnox set DOPPLER_TOKEN "dp.st.prd.xxxx" --provider age

# Bootstrap from fnox
export DOPPLER_TOKEN=$(fnox get DOPPLER_TOKEN)
fnox exec -- npm start
```

## Usage notes

A provider instance selects a Doppler project and config. Use separate instances or fnox profiles when environments differ. For automation, scope the service token to the intended config.

## Troubleshooting

### "Unauthorized" or "Invalid service token"

```bash
# Re-login interactively
doppler login

# Or check your service token
echo $DOPPLER_TOKEN
```

### "Could not find project" or "Could not find config"

Verify your project and config exist:

```bash
doppler projects
doppler configs --project my-project
```

### "Secret not found"

Check the secret exists in the correct project/config:

```bash
doppler secrets --project my-project --config prd
```

## Next steps

- [Infisical](/providers/infisical) - Alternative cloud secrets manager
- [HashiCorp Vault](/providers/vault) - Self-hosted alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
