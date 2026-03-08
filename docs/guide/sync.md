# Syncing Secrets Locally

`fnox sync` fetches secrets from remote providers (1Password, AWS Secrets Manager, etc.) and re-encrypts them with a local encryption provider (age, YubiKey via age plugin, AWS KMS, etc.). The encrypted values are stored in `fnox.local.toml` (gitignored) so that subsequent access is instant and offline — no remote calls needed.

## Why Sync?

A typical team setup stores secrets in a shared provider like 1Password:

```toml
# fnox.toml (committed)
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
STRIPE_KEY = { provider = "op", value = "Stripe/secret-key" }
SENDGRID_KEY = { provider = "op", value = "Stripe/api-key" }
```

This works, but every time you `cd` into the project (with [shell integration](/guide/shell-integration)), fnox calls 1Password to fetch each secret. This is slow and requires network access.

With `fnox sync`, you pull those values once and cache them locally with a fast, offline encryption provider:

```bash
fnox sync --provider age --config fnox.local.toml
```

Now entering the directory is instant — secrets are decrypted locally from age without any remote calls.

## How It Works

1. fnox reads all secrets from your merged config
2. It resolves each secret's plaintext value from the original remote provider
3. It encrypts each value with the target provider (e.g., age)
4. It writes the encrypted cache into your config as a `sync` field on each secret

When fnox resolves secrets, it checks for a `sync` field first and uses that instead of calling the original provider.

## Basic Usage

```bash
# Set up an age provider if you haven't already
fnox set --provider age  # or add [providers.age] to your config

# Sync everything to fnox.local.toml
fnox sync --provider age --config fnox.local.toml
```

### Preview what would be synced

```bash
fnox sync --provider age --config fnox.local.toml --dry-run
```

### Sync specific secrets

```bash
fnox sync --provider age --config fnox.local.toml DATABASE_URL STRIPE_KEY
```

### Sync only secrets from a specific source

```bash
fnox sync --provider age --config fnox.local.toml --source op
```

### Filter by regex pattern

```bash
fnox sync --provider age --config fnox.local.toml --filter "^DB_"
```

## What It Looks Like

After syncing, your files look like this:

**fnox.toml** (committed — the source of truth):

```toml
[providers.op]
type = "1password"
vault = "Engineering"

[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
STRIPE_KEY = { provider = "op", value = "Stripe/secret-key" }
SENDGRID_KEY = { provider = "op", value = "SendGrid/api-key" }
```

**fnox.local.toml** (gitignored — your local cache):

```toml
[secrets]
DATABASE_URL = { provider = "op", value = "Database/url", sync = { provider = "age", value = "YWdlLWVuY3J5cHRpb24..." } }
STRIPE_KEY = { provider = "op", value = "Stripe/secret-key", sync = { provider = "age", value = "YWdlLWVuY3J5cHRpb24..." } }
SENDGRID_KEY = { provider = "op", value = "SendGrid/api-key", sync = { provider = "age", value = "YWdlLWVuY3J5cHRpb24..." } }
```

When you `cd` into the project, fnox sees the `sync` field and decrypts with age locally — no 1Password calls.

## Using a YubiKey

If you use a YubiKey with the [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey), syncing works the same way. Your age provider just uses the YubiKey identity:

```toml
[providers.age]
type = "age"
recipients = ["age1yubikey1q..."]  # YubiKey recipient
```

```bash
fnox sync --provider age --config fnox.local.toml
```

Secrets are encrypted to your YubiKey's age identity. Decryption requires the YubiKey to be plugged in, adding hardware-based security to your local cache.

## Refreshing the Cache

When secrets change in the remote provider, re-run sync to update the local cache:

```bash
fnox sync --provider age --config fnox.local.toml --force
```

The `--force` flag skips the confirmation prompt. fnox re-fetches from the original provider and re-encrypts.

## Full Workflow Example

```bash
# 1. Clone a project with 1Password secrets in fnox.toml
git clone https://github.com/myorg/my-api && cd my-api

# 2. Make sure fnox.local.toml is gitignored
echo "fnox.local.toml" >> .gitignore

# 3. Set up your age key (one-time)
age-keygen -o ~/.config/fnox/age.txt
export FNOX_AGE_KEY=$(grep "AGE-SECRET-KEY" ~/.config/fnox/age.txt)

# 4. Add age provider to your config
cat >> fnox.toml << 'EOF'
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
EOF

# 5. Sync all 1Password secrets to local age encryption
fnox sync --provider age --config fnox.local.toml

# 6. Done — entering the directory is now instant
cd .. && cd my-api
# Secrets load from local age cache, no 1Password calls
```

## Next Steps

- [Import/Export](/guide/import-export) - Migrate secrets between formats
- [Shell Integration](/guide/shell-integration) - Auto-load secrets on `cd`
- [Hierarchical Config](/guide/hierarchical-config) - Organize configs across directories
- [Providers](/providers/overview) - All available providers
