# Infisical

Integrate with Infisical to retrieve secrets from your Infisical projects and environments.

## Quick Start

```bash
# 1. Install Infisical CLI
brew install infisical/get-cli/infisical

# 2. Login to Infisical
infisical login

# 3. Configure Infisical provider
cat >> fnox.toml << 'EOF'
[providers]
infisical = { type = "infisical", project_id = "your-project-id", environment = "dev", path = "/" }
EOF

# 4. Add secrets to Infisical
infisical secrets set DATABASE_PASSWORD "secret-password"

# 5. Reference in fnox
cat >> fnox.toml << 'EOF'
[secrets]
DATABASE_PASSWORD = { provider = "infisical", value = "DATABASE_PASSWORD" }
EOF

# 6. Use it
fnox get DATABASE_PASSWORD
```

With just `infisical login`, fnox uses the CLI's cached session automatically. No
environment variables needed for local development. For CI/CD or machine identities, see
[Authentication](#2-get-authentication-token) below.

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

### 2. Get authentication token

fnox tries authentication in this order:

1. `INFISICAL_TOKEN` / `FNOX_INFISICAL_TOKEN` environment variable (explicit token, used as-is)
2. `INFISICAL_CLIENT_ID` + `INFISICAL_CLIENT_SECRET` (universal auth login, token cached)
3. CLI session fallback (no env vars needed; the CLI uses its own cached session from `infisical login`)

#### Option A: CLI session (simplest)

If you have already run `infisical login`, fnox uses the CLI's cached session with no extra
configuration. This is the easiest option for local development.

```bash
infisical login
# That's it. fnox will use the session automatically.
```

#### Option B: Service token (recommended for CI/CD)

1. Go to your Infisical project settings
2. Navigate to "Service Tokens"
3. Create a new service token with appropriate permissions
4. Copy the token

```bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
```

#### Option C: Universal auth (machine identity)

```bash
export INFISICAL_CLIENT_ID="your-client-id"
export INFISICAL_CLIENT_SECRET="your-client-secret"

# fnox will run `infisical login --method=universal-auth` automatically and cache the token.
```

### 3. Store token (bootstrap)

Optionally, store a service token encrypted for easy bootstrap:

```bash
# Store once
fnox set INFISICAL_TOKEN "st.xxx.yyy.zzz" --provider age

# Use repeatedly
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

## Adding Secrets to Infisical

### Via Infisical Web Dashboard

1. Go to your Infisical dashboard
2. Select your project
3. Choose the environment (dev, staging, prod)
4. Click "+ Add Secret"
5. Enter secret name and value
6. Save

### Via Infisical CLI

```bash
# Set a secret (uses CLI session auth, or set INFISICAL_TOKEN if needed)
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

## Referencing Secrets

Add references to `fnox.toml`:

```toml
[secrets]
DATABASE_PASSWORD = { provider = "infisical", value = "DATABASE_PASSWORD" }
API_KEY = { provider = "infisical", value = "API_KEY" }
DATABASE_URL = { provider = "infisical", value = "DATABASE_URL" }
```

## Reference Format

```toml
[secrets]
MY_SECRET = { provider = "infisical", value = "SECRET_NAME" }
```

The `value` is the secret key name in Infisical. The provider configuration determines the project, environment, and path scope.

## Usage

```bash
# If using CLI session auth, just run commands directly:
fnox get DATABASE_PASSWORD
fnox exec -- npm start

# If using a stored service token instead:
export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)
fnox exec -- npm start
```

## Multi-Environment Example

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

## Secret Paths

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

## CI/CD Example

### GitHub Actions

```yaml
name: Test
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v3

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

## Self-Hosted Infisical

Configure the CLI to use your self-hosted instance:

```bash
# Configure server
infisical login --domain=https://infisical.example.com

# Or set environment variable
export INFISICAL_API_URL=https://infisical.example.com/api

# Use normally with fnox
fnox get DATABASE_PASSWORD
```

## Token management

For local development, `infisical login` is usually sufficient. fnox uses the CLI's cached
session automatically, so no token management is needed.

For CI/CD or automation where interactive login isn't possible, you need an explicit token:

### Option 1: Set each time

```bash
#!/bin/bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
fnox exec -- npm start
```

### Option 2: Store encrypted (bootstrap)

```bash
# Store once
fnox set INFISICAL_TOKEN "st.xxx.yyy.zzz" --provider age

# Use repeatedly
export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)
fnox exec -- npm start
```

## Authentication methods compared

### CLI session (simplest)

- Best for local development
- Just run `infisical login`; fnox handles the rest
- No env vars needed

### Service token

- Best for CI/CD and simple automation
- Easy to set up (one token)
- Manual rotation, less granular permissions

```bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
```

### Universal auth (machine identity)

- Best for machine identities and advanced use cases
- Automatic rotation, better audit logs, fine-grained permissions
- More complex setup

```bash
export INFISICAL_CLIENT_ID="..."
export INFISICAL_CLIENT_SECRET="..."
```

## Pros

- ✅ Modern, developer-friendly UI
- ✅ Open source (self-hosting option)
- ✅ Good API and CLI
- ✅ Secret versioning and audit logs
- ✅ Point-in-time recovery
- ✅ Integrations with many platforms

## Cons

- ❌ Requires network access (unless self-hosted)
- ❌ Relatively new compared to Vault or cloud providers

## Troubleshooting

### "You are not logged in"

```bash
# Re-authenticate with the CLI
infisical login

# Or set a token directly
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
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

## Best Practices

1. **Use CLI session auth for local dev** - Just `infisical login`, no env vars needed
2. **Use service tokens for automation** - Create read-only tokens for CI/CD
3. **Organize with paths** - Use paths to logically group secrets
4. **Leverage environments** - Use dev/staging/prod environments
5. **Store token encrypted** - Use age to encrypt `INFISICAL_TOKEN` for bootstrap
6. **Self-host for sensitive workloads** - Full control over your secrets
7. **Use secret versioning** - Track changes and rollback if needed

## Next Steps

- [1Password](/providers/1password) - Alternative password manager
- [Vault](/providers/vault) - More established alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
