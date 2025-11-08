# Configuration Reference

Complete reference for the `fnox.toml` configuration file.

## File Location

fnox looks for configuration files in this order:

1. Path specified via `-c, --config` flag
2. `fnox.toml` in current directory
3. `fnox.toml` in parent directories (hierarchical search)
4. `fnox.local.toml` alongside each `fnox.toml` (for local overrides)

## Basic Structure

```toml
# Top-level settings
if_missing = "warn"  # Global default for missing secrets
import = ["./shared/secrets.toml"]  # Import other configs

# Provider definitions
[providers]
PROVIDER_NAME = { type = "PROVIDER_TYPE" }  # ... provider-specific config ...

# Secret definitions
[secrets]
SECRET_NAME = { provider = "PROVIDER_NAME", value = "...", default = "...", if_missing = "error", description = "..." }

# Profile definitions
[profiles.PROFILE_NAME]
# ... same structure as top-level ...
```

## Top-Level Settings

### `if_missing`

Global default behavior when secrets cannot be resolved.

```toml
if_missing = "error"  # or "warn", "ignore"
```

**Values:**

- `"error"` - Fail if secret is missing
- `"warn"` - Print warning and continue (default)
- `"ignore"` - Silently skip missing secrets

**Priority:** Lowest (overridden by secret-level, env vars, CLI flags).

### `imports`

List of config files to import.

```toml
import = ["./shared/base.toml", "./envs/dev.toml"]
```

**Usage:**

- Paths relative to current config file
- Imported files merged into current config
- Later imports override earlier ones

## Provider Configuration

```toml
[providers.PROVIDER_NAME]
type = "PROVIDER_TYPE"
# ... provider-specific fields ...
```

### Common Provider Types

#### Age Encryption

```toml
[providers.age]
type = "age"
recipients = [
  "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQs..."
]
```

#### AWS Secrets Manager

```toml
[providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }  # prefix is optional
```

#### AWS KMS

```toml
[providers]
kms = { type = "aws-kms", key_id = "arn:aws:kms:us-east-1:123456789012:key/...", region = "us-east-1" }
```

#### Azure Key Vault Secrets

```toml
[providers]
azure = { type = "azure-sm", vault_url = "https://myapp-vault.vault.azure.net/", prefix = "myapp/" }  # prefix is optional
```

#### Azure Key Vault Keys

```toml
[providers]
azurekms = { type = "azure-kms", vault_url = "https://myapp-vault.vault.azure.net/", key_name = "encryption-key" }
```

#### GCP Secret Manager

```toml
[providers]
gcp = { type = "gcp-sm", project = "my-project-id", prefix = "myapp/" }  # prefix is optional
```

#### GCP Cloud KMS

```toml
[providers.gcpkms]
type = "gcp-kms"
project = "my-project-id"
location = "us-central1"
keyring = "fnox-keyring"
key = "fnox-key"
```

#### 1Password

```toml
[providers]
onepass = { type = "1password", vault = "Development", account = "my.1password.com" }  # account is optional
```

#### Bitwarden

```toml
[providers]
bitwarden = { type = "bitwarden", collection = "collection-id", organization_id = "org-id" }  # both optional
```

#### HashiCorp Vault

```toml
[providers]
vault = { type = "vault", address = "https://vault.example.com:8200", path = "secret/myapp", token = "hvs.CAESIJ..." }  # token optional, can use VAULT_TOKEN env var
```

#### OS Keychain

```toml
[providers]
keychain = { type = "keychain", service = "fnox", prefix = "myapp/" }  # prefix is optional
```

## Secret Configuration

```toml
[secrets]
SECRET_NAME = { provider = "PROVIDER_NAME", value = "...", default = "...", if_missing = "error", description = "..." }
```

### Fields

#### `provider`

Provider to use for this secret.

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted..." }
```

**Required:** Unless using only `default` (plain text).

#### `value`

Provider-specific value:

- **Encryption providers** (age, aws-kms, etc.): Encrypted ciphertext
- **Remote providers** (aws-sm, 1password, etc.): Secret name/reference

```toml
[secrets]
# Encrypted ciphertext (age)
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }

# Remote reference (AWS)
DATABASE_URL = { provider = "aws", value = "database-url" }  # Secret name in AWS Secrets Manager
```

#### `default`

Fallback value if secret cannot be resolved.

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted...", default = "postgresql://localhost/dev" }  # Fallback for local dev
```

**Use for:**

- Non-sensitive defaults
- Local development fallbacks
- Optional configuration

#### `if_missing`

Behavior when secret cannot be resolved.

```toml
[secrets]
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }  # Fail if missing (critical secret)
ANALYTICS_KEY = { provider = "aws", value = "analytics-key", if_missing = "ignore" }  # Silently skip if missing (optional)
```

**Values:** `"error"`, `"warn"`, `"ignore"`

**Priority:** Overrides top-level `if_missing`, but overridden by env vars and CLI flags.

#### `description`

Human-readable description.

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted...", description = "Production database connection string" }
```

## Profile Configuration

Profiles allow environment-specific configuration:

```toml
# Default profile (no prefix)
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted-dev..." }

# Production profile
[profiles.production]

[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }
```

### Profile Structure

```toml
[profiles.PROFILE_NAME]
if_missing = "error"  # Profile-specific default

[profiles.PROFILE_NAME.providers]
PROVIDER_NAME = { type = "PROVIDER_TYPE" }  # ... provider config ...

[profiles.PROFILE_NAME.secrets]
SECRET_NAME = { provider = "PROVIDER_NAME", value = "..." }  # ... secret config ...
```

### Profile Inheritance

Profiles inherit top-level secrets and providers:

```toml
# Top-level (inherited by all profiles)
[secrets]
LOG_LEVEL = { default = "info" }
DATABASE_URL = { provider = "age", value = "encrypted-dev..." }

# Production profile
[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "prod-db" }  # Overrides top-level DATABASE_URL
# Inherits LOG_LEVEL="info" from top-level
```

## Complete Example

```toml
# Global settings
if_missing = "warn"
import = ["./shared/common.toml"]

# Providers
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }

# Default profile secrets
[secrets]
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC...", default = "postgresql://localhost/dev", description = "Database connection string" }
JWT_SECRET = { provider = "age", value = "encrypted...", if_missing = "error" }
LOG_LEVEL = { default = "info" }

# Production profile
[profiles.production]
if_missing = "error"

[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp-prod/" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url", description = "Production database" }
JWT_SECRET = { provider = "aws", value = "jwt-secret" }
# Inherits LOG_LEVEL from top-level
```

## Local Overrides

Create `fnox.local.toml` alongside `fnox.toml` for local overrides:

```toml
# fnox.local.toml (gitignored)

[secrets]
DATABASE_URL = { default = "postgresql://localhost/mylocal" }  # Override for local development
DEBUG_MODE = { default = "true" }
```

**Important:** Add to `.gitignore`:

```gitignore
fnox.local.toml
```

## Profile-Specific Config Files

You can create environment-specific config files that load based on the `FNOX_PROFILE` environment variable:

```bash
# Directory structure
project/
├── fnox.toml              # Base config
├── fnox.production.toml   # Production overrides
├── fnox.staging.toml      # Staging overrides
├── fnox.development.toml  # Development overrides
└── fnox.local.toml        # Local overrides (gitignored)
```

Example usage:

```bash
# Use default config (fnox.toml only)
fnox exec -- npm start

# Use production config (fnox.toml + fnox.production.toml)
FNOX_PROFILE=production fnox exec -- ./deploy.sh

# Use staging config (fnox.toml + fnox.staging.toml)
FNOX_PROFILE=staging fnox exec -- ./deploy.sh
```

**Key differences:**

- `fnox.$FNOX_PROFILE.toml` files are **committed to git** (environment-specific, but shared with team)
- `fnox.local.toml` is **gitignored** (machine-specific, personal overrides)
- Profile-specific files work with the default profile's secrets, not `[profiles.xxx]` sections
- `fnox.default.toml` is **not loaded** (use `fnox.toml` instead)

## Hierarchical Configuration

fnox searches parent directories for `fnox.toml` files:

```
project/
├── fnox.toml              # Root config
└── services/
    └── api/
        └── fnox.toml      # API config (inherits from root)
```

Merge order (lowest to highest priority):

1. Root `fnox.toml`
2. Root `fnox.$FNOX_PROFILE.toml` (if `FNOX_PROFILE` is set and not "default")
3. Root `fnox.local.toml`
4. Child `fnox.toml`
5. Child `fnox.$FNOX_PROFILE.toml` (if `FNOX_PROFILE` is set and not "default")
6. Child `fnox.local.toml`

## Next Steps

- [CLI Reference](/cli/) - All available commands
- [Environment Variables](/reference/environment) - Environment variable reference
- [Providers Overview](/providers/overview) - Available providers
