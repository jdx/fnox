# Infisical

Integrate with Infisical to retrieve secrets from your Infisical projects and environments.

## Quick Start

```bash
# 1. Install Infisical CLI
brew install infisical/get-cli/infisical

# 2. Login to Infisical
infisical login

# 3. Get a service token or universal auth token
# Option A: Service token (from Infisical dashboard)
export INFISICAL_TOKEN="your-service-token"

# Option B: Universal auth (machine identity)
infisical login --method=universal-auth

# 4. Store token (optional, for bootstrap)
fnox set INFISICAL_TOKEN "your-service-token" --provider age

# 5. Configure Infisical provider
cat >> fnox.toml << 'EOF'
[providers]
infisical = { type = "infisical", project_id = "your-project-id", environment = "dev", path = "/" }
EOF

# 6. Add secrets to Infisical
infisical secrets set DATABASE_PASSWORD "secret-password"

# 7. Reference in fnox
cat >> fnox.toml << 'EOF'
[secrets]
DATABASE_PASSWORD = { provider = "infisical", value = "DATABASE_PASSWORD" }
EOF

# 8. Use it
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

### 2. Get Authentication Token

#### Option A: Service Token (Recommended for CI/CD)

1. Go to your Infisical project settings
2. Navigate to "Service Tokens"
3. Create a new service token with appropriate permissions
4. Copy the token

```bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
```

#### Option B: Universal Auth (Machine Identity)

```bash
# Configure universal auth
infisical login --method=universal-auth \
  --client-id="your-client-id" \
  --client-secret="your-client-secret"

# Token is automatically managed
```

### 3. Store Token (Bootstrap)

Optionally, store the token encrypted for easy bootstrap:

```bash
# Store token encrypted with age
fnox set INFISICAL_TOKEN "st.xxx.yyy.zzz" --provider age

# Next time, bootstrap from fnox:
export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)
```

### 4. Configure Infisical Provider

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
# Set authentication token (once per session)
export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)

# Get secrets
fnox get DATABASE_PASSWORD

# Run commands
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

## Token Management

The `INFISICAL_TOKEN` is typically a service token or machine identity token.

### Option 1: Set Each Time

```bash
#!/bin/bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
fnox exec -- npm start
```

### Option 2: Store Encrypted (Bootstrap)

```bash
# Store once
fnox set INFISICAL_TOKEN "st.xxx.yyy.zzz" --provider age

# Use repeatedly
export INFISICAL_TOKEN=$(fnox get INFISICAL_TOKEN)
fnox exec -- npm start
```

## Service Token vs Universal Auth

### Service Token (Simple)

- **Best for:** CI/CD, simple automation
- **Pros:** Easy to set up, just one token
- **Cons:** Manual rotation, less granular permissions

```bash
export INFISICAL_TOKEN="st.xxx.yyy.zzz"
```

### Universal Auth (Advanced)

- **Best for:** Machine identities, advanced use cases
- **Pros:** Automatic rotation, better audit logs, fine-grained permissions
- **Cons:** More complex setup

```bash
infisical login --method=universal-auth \
  --client-id="..." \
  --client-secret="..."
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
infisical login
# Or set token directly
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

1. **Use service tokens for automation** - Create read-only tokens for CI/CD
2. **Organize with paths** - Use paths to logically group secrets
3. **Leverage environments** - Use dev/staging/prod environments
4. **Store token encrypted** - Use age to encrypt `INFISICAL_TOKEN`
5. **Self-host for sensitive workloads** - Full control over your secrets
6. **Use secret versioning** - Track changes and rollback if needed

## Next Steps

- [1Password](/providers/1password) - Alternative password manager
- [Vault](/providers/vault) - More established alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
