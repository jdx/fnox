# Plain Text

Store secrets as plain text (for default values only!).

## Usage

Plain text is the default when no provider is specified:

```toml
[secrets]
NODE_ENV = { default = "development" }  # ← Plain text, safe for non-sensitive defaults
LOG_LEVEL = { default = "info" }  # ← Plain text
API_TIMEOUT = { default = "30" }  # ← Plain text
```

## When Plain Text is Appropriate

### 1. Non-Sensitive Defaults

```toml
[secrets]
PORT = { default = "3000" }
HOST = { default = "localhost" }
NODE_ENV = { default = "development" }
LOG_LEVEL = { default = "info" }
```

### 2. Public Configuration

```toml
[secrets]
PUBLIC_API_URL = { default = "https://api.example.com" }
CDN_URL = { default = "https://cdn.example.com" }
```

### 3. Development Fallbacks

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted-production-db...", default = "postgresql://localhost/dev_db" }  # ← Fallback for local dev
```

If the encrypted value can't be decrypted (e.g., missing key), falls back to the plaintext default.

## ❌ When NOT to Use Plain Text

### Never for Passwords

```toml
# ❌ BAD - Never do this!
[secrets]
DATABASE_PASSWORD = { default = "super-secret-password" }

# ✅ GOOD - Use encryption
[secrets]
DATABASE_PASSWORD = { provider = "age", value = "encrypted..." }
```

### Never for API Keys

```toml
# ❌ BAD
[secrets]
STRIPE_KEY = { default = "sk_live_abc123xyz789" }

# ✅ GOOD
[secrets]
STRIPE_KEY = { provider = "age", value = "encrypted..." }
```

### Never for Tokens

```toml
# ❌ BAD
[secrets]
JWT_SECRET = { default = "my-secret-key" }

# ✅ GOOD
[secrets]
JWT_SECRET = { provider = "age", value = "encrypted..." }
```

## Mixing Plain and Encrypted

It's common to mix plain text defaults with encrypted values:

```toml
[providers]
age = { type = "age", recipients = ["age1..."] }

[secrets]
DATABASE_PASSWORD = { provider = "age", value = "encrypted...", default = "dev-password" }  # Encrypted sensitive values, fallback for local dev
DATABASE_HOST = { default = "localhost" }  # Plain text non-sensitive defaults
DATABASE_PORT = { default = "5432" }
LOG_LEVEL = { default = "info" }
```

## Security Best Practices

1. **Never commit sensitive data as plain text**
2. **Use encryption for anything that shouldn't be public**
3. **Use plain text only for truly non-sensitive defaults**
4. **Review `.gitignore`** - Ensure sensitive files aren't tracked
5. **Use** `fnox scan` **to detect secrets** - Scans for accidentally committed secrets

## Scan for Secrets

fnox can scan your codebase for accidentally committed secrets:

```bash
# Scan for potential secrets
fnox scan

# Scan specific directory
fnox scan src/

# Scan and fix (interactive)
fnox scan --fix
```

## Examples

### Safe Plain Text Usage

```toml
# Application settings (non-sensitive)
[secrets]
APP_NAME = { default = "My Application" }
APP_VERSION = { default = "1.0.0" }
ENVIRONMENT = { default = "development" }
DEBUG_MODE = { default = "true" }
TIMEOUT_MS = { default = "5000" }
PUBLIC_SITE_URL = { default = "https://example.com" }  # Public URLs
DOCS_URL = { default = "https://docs.example.com" }
```

### Mixed Usage (Plain + Encrypted)

```toml
[providers]
age = { type = "age", recipients = ["age1..."] }

[secrets]
# Sensitive (encrypted)
DATABASE_URL = { provider = "age", value = "encrypted-connection-string..." }
API_KEY = { provider = "age", value = "encrypted-key..." }

# Non-sensitive (plain)
DATABASE_POOL_SIZE = { default = "10" }
CACHE_TTL_SECONDS = { default = "3600" }
FEATURE_FLAG_NEW_UI = { default = "false" }
```

## Remember

- ✅ Plain text is fine for public, non-sensitive configuration
- ✅ Use defaults for fallback values
- ❌ Never use plain text for passwords, keys, or tokens
- ✅ Use [age](/providers/age) or other providers for sensitive data
- ✅ Run `fnox scan` to catch accidental secrets

## Next Steps

- [Age Encryption](/providers/age) - Encrypt sensitive secrets
- [Providers Overview](/providers/overview) - Choose the right provider
- [Configuration Reference](/reference/configuration) - Learn more about fnox.toml
