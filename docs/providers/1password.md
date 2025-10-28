# 1Password

Integrate with 1Password to retrieve secrets from your vaults using the 1Password CLI.

## When to Use

- ✅ Your team already uses 1Password
- ✅ You want a polished password manager experience
- ✅ Need audit logs and access control
- ✅ Great UI and mobile apps
- ✅ Team-friendly

## Quick Start

```bash
# 1. Install 1Password CLI
brew install 1password-cli

# 2. Create service account and get token
# (via 1Password web interface)

# 3. Store token (bootstrap with age)
fnox set OP_SERVICE_ACCOUNT_TOKEN "ops_YOUR_TOKEN" --provider age

# 4. Configure 1Password provider
cat >> fnox.toml << 'EOF'
[providers.onepass]
type = "1password"
vault = "Development"
EOF

# 5. Add secrets to 1Password (via app or CLI)
op item create --category=login \
  --title="Database" \
  --vault="Development" \
  password="super-secret-password"

# 6. Reference in fnox
cat >> fnox.toml << 'EOF'
[secrets.DATABASE_PASSWORD]
provider = "onepass"
value = "Database"
EOF

# 7. Use it
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
fnox get DATABASE_PASSWORD
```

## Prerequisites

- [1Password account](https://1password.com)
- [1Password CLI](https://developer.1password.com/docs/cli) installed

## Installation

```bash
# macOS
brew install 1password-cli

# Linux
curl -sS https://downloads.1password.com/linux/keys/1password.asc | \
  sudo gpg --dearmor --output /usr/share/keyrings/1password-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/$(dpkg --print-architecture) stable main" | \
  sudo tee /etc/apt/sources.list.d/1password.list
sudo apt update && sudo apt install 1password-cli

# Windows (via Scoop)
scoop install 1password-cli
```

## Setup

### 1. Create a Service Account

1. Go to your [1Password account](https://my.1password.com)
2. Navigate to Settings → Integrations → Service Accounts
3. Click "Create Service Account"
4. Give it a name (e.g., "fnox-dev")
5. Grant access to your vault
6. Copy the `OP_SERVICE_ACCOUNT_TOKEN` (starts with `ops_`)

### 2. Store the Token (Bootstrap)

Use age encryption to store the token:

```bash
# First, set up age provider (if not already done)
cat >> fnox.toml << 'EOF'
[providers.age]
type = "age"
recipients = ["age1..."]
EOF

# Store the 1Password token encrypted in fnox
fnox set OP_SERVICE_ACCOUNT_TOKEN "ops_YOUR_TOKEN_HERE" --provider age
```

Now you can bootstrap the token:

```bash
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
```

### 3. Configure 1Password Provider

```toml
[providers.onepass]
type = "1password"
vault = "Development"  # Your vault name
account = "my.1password.com"  # Optional
```

## Adding Secrets to 1Password

### Via 1Password App

1. Open 1Password app
2. Select your vault (e.g., "Development")
3. Click + to create new item
4. Choose category (Login, Password, etc.)
5. Fill in details
6. Save

### Via 1Password CLI

```bash
# Export token first
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)

# Create a login item
op item create --category=login \
  --title="Database" \
  --vault="Development" \
  username="admin" \
  password="super-secret-password"

# Create an API credential
op item create --category=password \
  --title="Stripe API Key" \
  --vault="Development" \
  password="sk_live_abc123xyz789"

# Create with custom fields
op item create --category=login \
  --title="AWS Credentials" \
  --vault="Development" \
  "Access Key=AKIAIOSFODNN7EXAMPLE" \
  "Secret Key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

## Referencing Secrets

Add references to `fnox.toml`:

```toml
[secrets.DATABASE_PASSWORD]
provider = "onepass"
value = "Database"  # Item name (fetches 'password' field)

[secrets.DB_USERNAME]
provider = "onepass"
value = "Database/username"  # Specific field

[secrets.API_KEY]
provider = "onepass"
value = "op://Development/API Keys/credential"  # Full op:// URI
```

## Reference Formats

fnox supports multiple ways to reference 1Password items:

### 1. Item Name (Gets Password Field)

```toml
[secrets.MY_SECRET]
provider = "onepass"
value = "My Item"  # → Gets the 'password' field
```

### 2. Item Name + Field

```toml
[secrets.USERNAME]
provider = "onepass"
value = "Database/username"  # → Gets 'username' field

[secrets.PASSWORD]
provider = "onepass"
value = "Database/password"  # → Gets 'password' field
```

Common fields: `username`, `password`, `url`, `notes`

### 3. Full op:// URI

```toml
[secrets.API_KEY]
provider = "onepass"
value = "op://Development/API Keys/credential"
```

Format: `op://VAULT/ITEM/FIELD`

## Usage

```bash
# Export token (once per session)
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)

# Get secrets
fnox get DATABASE_PASSWORD
fnox get DB_USERNAME

# Run commands
fnox exec -- npm start
```

## Multi-Environment Example

```toml
# Bootstrap token (encrypted in git)
[providers.age]
type = "age"
recipients = ["age1..."]

[secrets.OP_SERVICE_ACCOUNT_TOKEN]
provider = "age"
value = "encrypted-token..."

# Development: 1Password
[providers.onepass]
type = "1password"
vault = "Development"

[secrets.DATABASE_URL]
provider = "onepass"
value = "Dev Database"

# Production: Different 1Password vault
[profiles.production.providers.onepass]
type = "1password"
vault = "Production"

[profiles.production.secrets.DATABASE_URL]
provider = "onepass"
value = "Prod Database"
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

      - name: Setup fnox age key
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
        run: echo "Age key configured"

      - name: Deploy with 1Password secrets
        run: |
          # Bootstrap 1Password token from fnox
          export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)

          # Now we can access 1Password secrets
          fnox exec --profile production -- ./deploy.sh
```

## Team Workflow

1. **Admin creates service account** in 1Password
2. **Admin stores token** encrypted in fnox:
   ```bash
   fnox set OP_SERVICE_ACCOUNT_TOKEN "ops_..." --provider age
   git add fnox.toml && git commit -m "Add 1Password token"
   ```
3. **Admin creates items** in 1Password vault
4. **Admin adds references** to fnox.toml:
   ```toml
   [secrets.DATABASE_URL]
   provider = "onepass"
   value = "Database"
   ```
5. **Team members pull and use**:
   ```bash
   git pull
   export FNOX_AGE_KEY=...
   export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
   fnox exec -- npm start
   ```

## Service Account vs Personal Token

### Service Account (Recommended)

- ✅ Designed for CI/CD and automation
- ✅ Doesn't expire
- ✅ No MFA required
- ✅ Scoped access to specific vaults

```bash
# Use service account token
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
```

### Personal Token (Not Recommended)

- ❌ Requires interactive login
- ❌ Subject to MFA
- ❌ Session expires

```bash
# Personal login (interactive)
op signin
eval $(op signin)
```

::: warning
Always use service accounts for fnox, not personal tokens.
:::

## Pros

- ✅ Beautiful UI and mobile apps
- ✅ Excellent audit logs and access control
- ✅ No encryption key management
- ✅ Team-friendly
- ✅ Multi-factor authentication
- ✅ Service accounts for CI/CD

## Cons

- ❌ Requires 1Password subscription
- ❌ Requires network access
- ❌ Service account token management
- ❌ Not free (starts at $7.99/user/month for teams)

## Troubleshooting

### "Authentication required"

Set the token:

```bash
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
```

### "Item not found"

Check:

- Vault name is correct in fnox.toml
- Item exists in that vault
- Service account has access to the vault

```bash
# List items in vault
op item list --vault "Development"

# Get item details
op item get "Database" --vault "Development"
```

### "Vault not found"

Verify vault name:

```bash
# List all vaults
op vault list
```

## Best Practices

1. **Use service accounts** - Not personal tokens
2. **One service account per environment** - Separate dev, staging, prod
3. **Grant minimal access** - Only vaults the service account needs
4. **Store token encrypted** - Use age provider to encrypt `OP_SERVICE_ACCOUNT_TOKEN`
5. **Rotate tokens periodically** - Create new service account, update fnox.toml
6. **Use descriptive item names** - Makes referencing easier

## Next Steps

- [Bitwarden](/providers/bitwarden) - Open source alternative
- [Real-World Example](/guide/real-world-example) - Complete setup
- [Profiles](/guide/profiles) - Multi-environment configuration
