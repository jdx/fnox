# Bitwarden

Integrate with Bitwarden (or self-hosted Vaultwarden) to retrieve secrets from your vault.

## Quick Start

```bash
# 1. Install Bitwarden CLI (auto-installed via mise)
# Already available!

# 2. Login to Bitwarden
bw login

# 3. Unlock and get session token
export BW_SESSION=$(bw unlock --raw)

# 4. Store session token (optional, for bootstrap)
fnox set BW_SESSION "$(bw unlock --raw)" --provider age

# 5. Configure Bitwarden provider
cat >> fnox.toml << 'EOF'
[providers]
bitwarden = { type = "bitwarden" }
EOF

# 6. Add secrets to Bitwarden
bw create item --name "Database" \
  --username "admin" \
  --password "secret-password"

# 7. Reference in fnox
cat >> fnox.toml << 'EOF'
[secrets]
DATABASE_PASSWORD = { provider = "bitwarden", value = "Database" }
EOF

# 8. Use it
fnox get DATABASE_PASSWORD
```

## Prerequisites

- [Bitwarden account](https://bitwarden.com) (or self-hosted Vaultwarden)
- Bitwarden CLI (automatically installed via mise)

## Installation

The Bitwarden CLI is installed automatically when using fnox via mise. Manual installation:

```bash
# macOS
brew install bitwarden-cli

# Linux
npm install -g @bitwarden/cli

# Windows
choco install bitwarden-cli
```

## Setup

### 1. Login to Bitwarden

```bash
# Cloud Bitwarden
bw login

# Self-hosted Vaultwarden
bw config server https://vault.example.com
bw login
```

### 2. Unlock and Get Session Token

```bash
# Unlock vault
export BW_SESSION=$(bw unlock --raw)

# Or if already unlocked
bw unlock
# Copy the session token from output
```

### 3. Store Session Token (Bootstrap)

Optionally, store the session encrypted for easy bootstrap:

```bash
# Store token encrypted with age
fnox set BW_SESSION "$(bw unlock --raw)" --provider age

# Next time, bootstrap from fnox:
export BW_SESSION=$(fnox get BW_SESSION)
```

### 4. Configure Bitwarden Provider

```toml
[providers]
bitwarden = { type = "bitwarden", collection = "my-collection-id", organization_id = "my-org-id" }  # both optional
```

## Adding Secrets to Bitwarden

### Via Bitwarden Web Vault

1. Go to [vault.bitwarden.com](https://vault.bitwarden.com)
2. Click + Add Item
3. Choose type (Login, Card, Identity, Secure Note)
4. Fill in details
5. Save

### Via Bitwarden CLI

```bash
# Unlock first
export BW_SESSION=$(bw unlock --raw)

# Create a login item
bw create item \
  --name "Database" \
  --username "admin" \
  --password "secret-password" \
  --url "https://db.example.com"

# Create with JSON
echo '{
  "type": 1,
  "name": "API Key",
  "login": {
    "password": "sk_live_abc123xyz789"
  }
}' | bw encode | bw create item

# List items
bw list items
```

## Referencing Secrets

Add references to `fnox.toml`:

```toml
[secrets]
DATABASE_PASSWORD = { provider = "bitwarden", value = "Database" }  # Item name (fetches 'password' field)
DB_USERNAME = { provider = "bitwarden", value = "Database/username" }  # Specific field
API_KEY = { provider = "bitwarden", value = "API Key" }
```

## Reference Formats

### 1. Item Name (Gets Password Field)

```toml
[secrets]
MY_SECRET = { provider = "bitwarden", value = "My Item" }  # → Gets the 'password' field
```

### 2. Item Name + Field

```toml
[secrets]
USERNAME = { provider = "bitwarden", value = "Database/username" }
PASSWORD = { provider = "bitwarden", value = "Database/password" }
TOTP = { provider = "bitwarden", value = "Database/totp" }
```

Supported fields: `username`, `password`, `notes`, `uri`, `totp`

::: info Custom Fields
Custom field extraction is not yet implemented. Use standard fields for now.
:::

## Usage

```bash
# Unlock Bitwarden (once per session)
export BW_SESSION=$(bw unlock --raw)
# Or bootstrap: export BW_SESSION=$(fnox get BW_SESSION)

# Get secrets
fnox get DATABASE_PASSWORD

# Run commands
fnox exec -- npm start
```

## Multi-Environment Example

```toml
# Bootstrap session token (encrypted in git)
[providers]
age = { type = "age", recipients = ["age1..."] }
bitwarden = { type = "bitwarden" }

[secrets]
BW_SESSION = { provider = "age", value = "encrypted-session..." }
DATABASE_URL = { provider = "bitwarden", value = "Dev Database" }

# Production: Different Bitwarden organization
[profiles.production.providers]
bitwarden = { type = "bitwarden", organization_id = "prod-org-id" }

[profiles.production.secrets]
DATABASE_URL = { provider = "bitwarden", value = "Prod Database" }
```

## Self-Hosted Vaultwarden

Vaultwarden is a lightweight, open-source Bitwarden-compatible server:

```bash
# Configure Bitwarden CLI to use Vaultwarden
bw config server https://vault.example.com

# Login
bw login

# Unlock
export BW_SESSION=$(bw unlock --raw)

# Use normally with fnox
fnox get DATABASE_PASSWORD
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

      - name: Setup Bitwarden session
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
        run: |
          # Bootstrap session from fnox (if stored)
          export BW_SESSION=$(fnox get BW_SESSION)

      - name: Run tests
        env:
          BW_SESSION: ${{ secrets.BW_SESSION }} # Or set directly from GitHub Secrets
        run: |
          fnox exec -- npm test
```

## Session Token Management

The `BW_SESSION` token expires after a period of inactivity.

### Option 1: Unlock Each Time

```bash
#!/bin/bash
export BW_SESSION=$(bw unlock --raw)
fnox exec -- npm start
```

### Option 2: Store Encrypted (Bootstrap)

```bash
# Store once
fnox set BW_SESSION "$(bw unlock --raw)" --provider age

# Use repeatedly
export BW_SESSION=$(fnox get BW_SESSION)
fnox exec -- npm start
```

::: warning Token Expiration
Bitwarden session tokens expire. You'll need to unlock periodically:

```bash
export BW_SESSION=$(bw unlock --raw)
```

:::

## Collections and Organizations

Filter secrets by collection or organization:

```toml
[providers]
bitwarden = { type = "bitwarden", collection = "abc123-collection-id", organization_id = "org-id" }
```

Get collection ID:

```bash
bw list collections | jq '.[] | {name, id}'
```

Get organization ID:

```bash
bw list organizations | jq '.[] | {name, id}'
```

## Testing with Vaultwarden

For local development without a Bitwarden account:

```bash
# Start local vaultwarden server
source ./test/setup-bitwarden-test.sh

# Follow on-screen instructions:
# 1. Create account at https://localhost:8080 (accept self-signed certificate)
# 2. Login: export NODE_TLS_REJECT_UNAUTHORIZED=0 && bw login
# 3. Unlock: export BW_SESSION=$(bw unlock --raw)

# Run tests
mise run test:bats -- test/bitwarden.bats
```

See `test/BITWARDEN_TESTING.md` for details.

## Pros

- ✅ Open source
- ✅ Free for personal use
- ✅ Self-hosting option (Vaultwarden)
- ✅ Good audit logs
- ✅ Cross-platform

## Cons

- ❌ UI less polished than 1Password
- ❌ Session token expires (need to unlock regularly)
- ❌ Requires network access (unless self-hosted locally)

## Troubleshooting

### "You are not logged in"

```bash
bw login
```

### "Vault is locked"

```bash
export BW_SESSION=$(bw unlock --raw)
```

### "Item not found"

Check the item exists:

```bash
bw list items | jq '.[] | {name, id}'
```

### "Session token expired"

Re-unlock:

```bash
export BW_SESSION=$(bw unlock --raw)
```

## Best Practices

1. **Store session token encrypted** - Use age to encrypt `BW_SESSION`
2. **Use collections for organization** - Group secrets logically
3. **Self-host for full control** - Consider Vaultwarden
4. **Unlock before long operations** - Session won't expire mid-operation
5. **Use organizations for teams** - Better access control

## Next Steps

- [1Password](/providers/1password) - Commercial alternative
- [OS Keychain](/providers/keychain) - Local alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
