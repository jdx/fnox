---
description: "Load Infisical secrets with fnox using service tokens or universal authentication, project environments, and secret paths."
---

# Infisical

Integrate with Infisical to retrieve secrets from your Infisical projects and environments.

## Quick start

```sh
# Install Infisical CLI
brew install infisical/get-cli/infisical

# Authenticate with a service token or a machine identity
# Option A: Service token (from Infisical dashboard)
export INFISICAL_TOKEN="your-service-token"

# Option B: Universal auth (machine identity)
export INFISICAL_CLIENT_ID="your-client-id"
export INFISICAL_CLIENT_SECRET="your-client-secret"

# Store token (optional, for bootstrap)
fnox set INFISICAL_TOKEN "your-service-token" --provider age
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
infisical = { type = "infisical", project_id = "your-project-id", environment = "dev", path = "/" }
```

```sh
# Add secrets to Infisical
infisical secrets set DATABASE_PASSWORD "secret-password"
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[secrets]
DATABASE_PASSWORD = { provider = "infisical", value = "DATABASE_PASSWORD" }
```

```sh
# Use it
fnox get DATABASE_PASSWORD
```

## Prerequisites

- [Infisical account](https://infisical.com) (or self-hosted instance)
- Infisical CLI

## Installation

```bash
# macOS
brew install infisical/get-cli/infisical

# Linux
curl -1sLf 'https://dl.cloudsmith.io/public/infisical/infisical-cli/setup.deb.sh' | sudo -E bash
sudo apt-get update && sudo apt-get install -y infisical

# Windows
scoop bucket add infisical https://github.com/Infisical/scoop-infisical.git
scoop install infisical

# Or download from https://infisical.com/docs/cli/overview
```

## Setup

### 1. Login to Infisical

```bash
# Cloud Infisical
infisical login

# Self-hosted
infisical login --domain=https://infisical.example.com
```

`infisical login` sets up the CLI for manual commands such as `infisical secrets set`. fnox itself does not use this login session; it authenticates with the token or machine identity credentials from the next step.

### 2. Get authentication token

#### Option A: service token (recommended for CI/CD)

1. Go to your Infisical project settings
2. Navigate to "Service Tokens"
3. Create a new service token with appropriate permissions
4. Copy the token

```bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
```

#### Option B: Universal Auth (machine identity)

```bash
# Provide the machine identity credentials. fnox runs
# `infisical login --method=universal-auth` for you and caches the
# resulting token for the rest of the process.
export INFISICAL_CLIENT_ID="your-client-id"
export INFISICAL_CLIENT_SECRET="your-client-secret"
```

`FNOX_INFISICAL_CLIENT_ID` and `FNOX_INFISICAL_CLIENT_SECRET` are also accepted and take priority over the unprefixed variables.

### 3. Store token (bootstrap)

Optionally, store the token encrypted for easy bootstrap:

```bash
# Store token encrypted with age
fnox set INFISICAL_TOKEN "st.xxx.yyy.zzz" --provider age

# Next time, bootstrap from fnox:
export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)
```

### 4. Configure Infisical provider

```toml
[providers]
infisical = { type = "infisical", project_id = "your-project-id", environment = "dev", path = "/" }
```

**Configuration Options:**

All fields are optional. If not specified, the Infisical CLI will use its own defaults:

- `project_id` - Infisical project ID to scope secret lookups. If omitted, uses the default project associated with your authentication credentials.
- `environment` - Environment slug (e.g., "dev", "staging", "prod"). If omitted, CLI defaults to "dev".
- `path` - Secret path within the project. If omitted, CLI defaults to "/".

## Adding secrets to Infisical

### Via Infisical web dashboard

1. Go to your Infisical dashboard
2. Select your project
3. Choose the environment (dev, staging, prod)
4. Click "+ Add Secret"
5. Enter secret name and value
6. Save

### Via Infisical CLI

```bash
# Set authentication
export INFISICAL_TOKEN="st.xxx.yyy.zzz"

# Set a secret
infisical secrets set DATABASE_PASSWORD "secret-password" \
  --projectId="your-project-id" \
  --env="dev" \
  --path="/"

# Set multiple secrets
infisical secrets set API_KEY "sk-abc123" \
  DATABASE_URL "postgresql://localhost/mydb" \
  --projectId="your-project-id" \
  --env="dev"

# List secrets
infisical secrets list
```

## Referencing secrets

Add references to `fnox.toml`:

```toml
[secrets]
DATABASE_PASSWORD = { provider = "infisical", value = "DATABASE_PASSWORD" }
API_KEY = { provider = "infisical", value = "API_KEY" }
DATABASE_URL = { provider = "infisical", value = "DATABASE_URL" }
```

## Reference format

```toml
[secrets]
MY_SECRET = { provider = "infisical", value = "SECRET_NAME" }
```

The `value` is the secret key name in Infisical. The provider configuration determines the project, environment, and path scope.

## Usage

```bash
# Set authentication token (once per session)
export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)

# Get secrets
fnox get DATABASE_PASSWORD

# Run commands
fnox exec -- npm start
```

## Multi-environment example

```toml
# Bootstrap token (encrypted in git)
[providers]
age = { type = "age", recipients = ["age1..."] }
infisical = { type = "infisical", project_id = "abc123", environment = "dev", path = "/" }

[secrets]
INFISICAL_TOKEN = { provider = "age", value = "encrypted-token..." }
DATABASE_URL = { provider = "infisical", value = "DATABASE_URL" }

# Staging: Different environment
[profiles.staging.providers]
infisical = { type = "infisical", project_id = "abc123", environment = "staging", path = "/" }

[profiles.staging.secrets]
DATABASE_URL = { provider = "infisical", value = "DATABASE_URL" }

# Production: Different environment
[profiles.production.providers]
infisical = { type = "infisical", project_id = "abc123", environment = "prod", path = "/" }

[profiles.production.secrets]
DATABASE_URL = { provider = "infisical", value = "DATABASE_URL" }
```

Usage:

```bash
# Development
fnox exec -- npm start

# Staging
fnox exec --profile staging -- npm start

# Production
fnox exec --profile production -- ./deploy.sh
```

## Secret paths

Organize secrets with paths:

```toml
# Provider with specific path
[providers]
infisical-api = { type = "infisical", project_id = "abc123", environment = "dev", path = "/api" }
infisical-db = { type = "infisical", project_id = "abc123", environment = "dev", path = "/database" }

[secrets]
API_KEY = { provider = "infisical-api", value = "API_KEY" }  # → /api/API_KEY
DATABASE_URL = { provider = "infisical-db", value = "DATABASE_URL" }  # → /database/DATABASE_URL
```

## CI/CD example

### GitHub Actions

```yaml
name: Test
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v4

      - name: Setup Infisical token
        env:
          INFISICAL_TOKEN: ${{ secrets.INFISICAL_TOKEN }}
        run: |
          # Token is already in environment
          echo "Infisical configured"

      - name: Run tests
        env:
          INFISICAL_TOKEN: ${{ secrets.INFISICAL_TOKEN }}
        run: |
          fnox exec -- npm test
```

**Setup:**

1. Create a service token in Infisical with read permissions
2. Add the token to GitHub Secrets as `INFISICAL_TOKEN`
3. The workflow will automatically use it

## Self-hosted Infisical

Configure the CLI to use your self-hosted instance:

```bash
# Configure server
infisical login --domain=https://infisical.example.com

# Or set environment variable (FNOX_INFISICAL_API_URL also works)
export INFISICAL_API_URL=https://infisical.example.com/api

# Use normally with fnox
fnox get DATABASE_PASSWORD
```

## Token management

The `INFISICAL_TOKEN` is typically a service token or machine identity token. `FNOX_INFISICAL_TOKEN` is also accepted and takes priority over `INFISICAL_TOKEN`.

### Option 1: set each time

```bash
#!/bin/bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
fnox exec -- npm start
```

### Option 2: store encrypted (bootstrap)

```bash
# Store once
fnox set INFISICAL_TOKEN "st.xxx.yyy.zzz" --provider age

# Use repeatedly
export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)
fnox exec -- npm start
```

## Service token vs Universal Auth

### Service token (simple)

- **Best for:** CI/CD, simple automation
- **Pros:** Easy to set up, just one token
- **Cons:** Manual rotation, less granular permissions

```bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
```

### Universal Auth (advanced)

- **Best for:** Machine identities, advanced use cases
- **Pros:** Automatic rotation, better audit logs, fine-grained permissions
- **Cons:** More complex setup

```bash
export INFISICAL_CLIENT_ID="..."
export INFISICAL_CLIENT_SECRET="..."
```

## Usage notes

fnox uses a token or machine identity credentials, rather than the CLI's interactive login session. Set the project, environment, and path explicitly when one identity can access several environments.

## Troubleshooting

### "You are not logged in"

fnox does not use the CLI's login session. Set a service token or machine identity credentials:

```bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
# Or universal auth credentials
export INFISICAL_CLIENT_ID="..."
export INFISICAL_CLIENT_SECRET="..."
```

### "Secret not found"

Check the secret exists:

```bash
infisical secrets list --projectId="your-project-id" --env="dev"
```

Verify your configuration matches:

```toml
[providers]
infisical = { type = "infisical", project_id = "your-project-id", environment = "dev" }
```

### "Invalid token"

Regenerate service token in Infisical dashboard and update:

```bash
fnox set INFISICAL_TOKEN "new-token" --provider age
```

## Next steps

- [1Password](/providers/1password) - Alternative password manager
- [Vault](/providers/vault) - More established alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
