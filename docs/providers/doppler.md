# Doppler

Integrate with [Doppler](https://www.doppler.com/) to retrieve secrets from your Doppler projects and configs.

## Quick Start

```bash
# 1. Install Doppler CLI
brew install dopplerhq/cli/doppler

# 2. Login to Doppler
doppler login

# 3. Configure Doppler provider
cat >> fnox.toml << 'EOF'
[providers]
doppler = { type = "doppler", project = "my-project", config = "prd" }

[secrets]
DATABASE_URL = { provider = "doppler", value = "DATABASE_URL" }
EOF

# 4. Use it
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

### 1. Login to Doppler

```bash
doppler login
```

### 2. Authentication

#### Option A: Interactive Login (Local Development)

```bash
doppler login
```

#### Option B: Service Token (CI/CD)

Create a service token in the Doppler dashboard scoped to a specific project and config:

```bash
export DOPPLER_TOKEN="dp.st.prd.xxxx"
```

### 3. Configure Doppler Provider

```toml
[providers]
doppler = { type = "doppler", project = "my-project", config = "prd" }
```

**Configuration Options:**

All fields are optional. If not specified, the Doppler CLI will use its own defaults (from `doppler setup` or environment variables):

- `project` - Doppler project name. If omitted, uses the project configured via `doppler setup`.
- `config` - Doppler config (environment) name (e.g., "dev", "stg", "prd"). If omitted, uses the config configured via `doppler setup`.
- `token` - Service token for authentication. If omitted, uses `DOPPLER_TOKEN` or `FNOX_DOPPLER_TOKEN` environment variable, or interactive login session.

## Referencing Secrets

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

## Multi-Environment Example

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
          DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
        run: |
          fnox exec -- ./deploy.sh
```

**Setup:**

1. Create a service token in the Doppler dashboard for the target project/config
2. Add the token to GitHub Secrets as `DOPPLER_TOKEN`

## Token Management

### Environment Variables

fnox checks for tokens in this order:

1. Provider config `token` field
2. `FNOX_DOPPLER_TOKEN` environment variable
3. `DOPPLER_TOKEN` environment variable
4. Interactive login session (from `doppler login`)

### Bootstrap Pattern

Store the Doppler token encrypted for easy bootstrap:

```bash
# Store token encrypted with age
fnox set DOPPLER_TOKEN "dp.st.prd.xxxx" --provider age

# Bootstrap from fnox
export DOPPLER_TOKEN=$(fnox get DOPPLER_TOKEN)
fnox exec -- npm start
```

## Pros

- ✅ Developer-friendly dashboard and CLI
- ✅ Simple project/config/environment model
- ✅ Automatic secret syncing across environments
- ✅ Good integrations (GitHub, Vercel, AWS, etc.)
- ✅ Secret referencing and inheritance between configs
- ✅ Audit logs and access controls
- ✅ Free tier available

## Cons

- ❌ Requires network access (cloud-only, no self-hosted option)
- ❌ No open source option

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

## Next Steps

- [Infisical](/providers/infisical) - Alternative cloud secrets manager
- [HashiCorp Vault](/providers/vault) - Self-hosted alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
