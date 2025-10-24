# 1Password Provider for Fnox

This document explains how to use the 1Password provider in Fnox to securely fetch secrets from your 1Password vaults.

## Overview

The 1Password provider integrates with the 1Password CLI (`op`) to fetch secrets from your 1Password vaults at runtime. This allows you to:

- Store sensitive credentials in 1Password instead of in config files
- Use 1Password's security features (MFA, audit logs, etc.)
- Centralize secret management across your team
- Bootstrap authentication using encrypted service account tokens

## Prerequisites

1. **1Password CLI**: Install the 1Password CLI

   ```bash
   brew install 1password-cli
   # or visit: https://developer.1password.com/docs/cli/get-started/
   ```

2. **1Password Account**: You need either:
   - A 1Password user account (for interactive use)
   - A 1Password service account token (for automation/CI)

## Configuration

### Basic Configuration

Add the 1Password provider to your `fnox.toml`:

```toml
[providers.onepass]
type = "1password"
```

### With Vault Parameter

If you want to specify a vault to allow for shorthand syntax, add it to the provider configuration:

```toml
[providers.onepass]
type = "1password"
vault = "your-vault-name"
```

### With Account Parameter

If you have multiple accounts, specify which one to use:

```toml
[providers.onepass]
type = "1password"
vault = "your-vault-name"
account = "my.1password.com"
```

## Authentication

The 1Password provider reads authentication from the `OP_SERVICE_ACCOUNT_TOKEN` environment variable. There are two main authentication methods:

### Method 1: Interactive Authentication (Development)

```bash
# Sign in to 1Password interactively
op signin

# Use fnox normally
fnox get MY_SECRET
```

### Method 2: Service Account Token (CI/Automation)

#### Step 1: Store the Service Account Token

Store your 1Password service account token as an encrypted secret in fnox:

```bash
# Get your service account token from 1Password
# Then encrypt it with fnox
fnox set OP_SERVICE_ACCOUNT_TOKEN

# This stores it encrypted in fnox.toml
```

#### Step 2: Bootstrap Authentication

Before using 1Password secrets, export the service account token:

```bash
# Decrypt and export the service account token
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)

# Now you can fetch secrets from 1Password
fnox get MY_1PASSWORD_SECRET
```

## Usage

### Defining Secrets

In your `fnox.toml`, reference secrets from 1Password:

```toml
[secrets.DATABASE_PASSWORD]
description = "Production database password"
provider = "onepass"
value = "my-db-item"  # Item name in 1Password

[secrets.API_KEY]
description = "External API key"
provider = "onepass"
value = "api-credentials/api_key"  # Fetch specific field
```

### Secret Reference Formats

The `value` field supports three formats:

1. **Item name only** (requires `vault` in provider config) - fetches the password field

   ```toml
   value = "my-item"
   # Resolves to: op://vault/my-item/password
   ```

2. **Item and field** (requires `vault` in provider config) - fetches a specific field

   ```toml
   value = "my-item/username"
   # Resolves to: op://vault/my-item/username
   ```

3. **Full op:// reference** - direct reference
   ```toml
   value = "op://vault/my-item/custom_field"
   # Used as-is
   ```

### Fetching Secrets

```bash
# Get a single secret
fnox get DATABASE_PASSWORD

# List all secrets
fnox list

# Run a command with secrets
fnox exec -- ./deploy.sh

# Export secrets to environment
eval $(fnox export --format shell)
```

## Example Workflow

### Development Setup

```bash
# 1. Sign in to 1Password
op signin

# 2. Create a test item in 1Password
op item create --category=password \
  --title="test-secret" \
  --vault="fnox" \
  password="my-secret-value"

# 3. Add to fnox.toml
cat >> fnox.toml << 'EOF'
[secrets.TEST_SECRET]
provider = "onepass"
value = "test-secret"
EOF

# 4. Fetch the secret
fnox get TEST_SECRET
```

### CI/CD Setup

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy:
    steps:
      # 1. Decrypt fnox secrets (including OP_SERVICE_ACCOUNT_TOKEN)
      - name: Setup 1Password authentication
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
        run: |
          echo "$FNOX_AGE_KEY" > ~/.config/fnox/age.txt
          export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
          echo "OP_SERVICE_ACCOUNT_TOKEN=$OP_SERVICE_ACCOUNT_TOKEN" >> $GITHUB_ENV

      # 2. Now you can fetch 1Password secrets
      - name: Deploy with secrets
        run: fnox exec -- ./deploy.sh
```

## Troubleshooting

### "op command not found"

Install the 1Password CLI:

```bash
brew install 1password-cli
```

### "You are not currently signed in"

Authenticate with 1Password:

```bash
# Interactive
op signin

# Or with service account token
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
```

### "Item not found"

Verify the item exists in your vault:

```bash
op item list --vault=your-vault-name
op item get "your-item-name" --vault=your-vault-name
```

### "Invalid secret reference format"

Ensure your value follows one of these formats:

- `"item-name"`
- `"item-name/field-name"`
- `"op://vault/item/field"`

### "Unknown secret vault"

Ensure you have the `vault` parameter set in your provider configuration, or use the full `op://` reference format.

## Testing

Run the bats test suite:

```bash
# Set up authentication
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)

# Run tests
bats test/onepassword.bats
```

## Security Notes

1. **Service Account Tokens**: Always encrypt service account tokens with age/KMS before committing
2. **Environment Variables**: The `OP_SERVICE_ACCOUNT_TOKEN` is only set in the shell environment, not stored in fnox config
3. **Audit Logging**: Use 1Password's audit logs to track secret access
4. **Key Rotation**: Rotate service account tokens regularly
5. **Least Privilege**: Use vault-specific service accounts when possible

## Implementation Details

- **Provider**: `src/providers/onepassword.rs`
- **Tests**: `test/onepassword.bats`
- **Config**: `fnox.toml`

The provider uses the `op read` command to fetch secrets, which supports the `op://vault/item/field` reference format.
