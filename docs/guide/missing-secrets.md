# Handling Missing Secrets

Control what happens when a secret can't be resolved using the `if_missing` setting. This is especially useful for CI environments or when some secrets are optional.

## Available Modes

- **`error`** - Fail the command if a secret cannot be resolved (strictest)
- **`warn`** - Print a warning and continue (default)
- **`ignore`** - Silently skip missing secrets

## Priority Chain

You can set `if_missing` at multiple levels. fnox uses the first match:

1. **CLI flag** (highest priority): `--if-missing error`
2. **Environment variable**: `FNOX_IF_MISSING=warn`
3. **Secret-level config**: `[secrets.MY_SECRET]` with `if_missing = "error"`
4. **Top-level config**: Global default for all secrets
5. **Base default environment variable**: `FNOX_IF_MISSING_DEFAULT=error`
6. **Default**: `warn` (lowest priority)

## Per-Secret Configuration

Set different behaviors for different secrets:

```toml
# Critical secrets must exist
[secrets.DATABASE_URL]
provider = "aws"
value = "database-url"
if_missing = "error"  # Fail if missing

# Optional secrets
[secrets.ANALYTICS_KEY]
provider = "aws"
value = "analytics-key"
if_missing = "ignore"  # Continue silently if missing

# Warn about missing secrets (default)
[secrets.CACHE_URL]
provider = "aws"
value = "cache-url"
if_missing = "warn"  # Print warning if missing
```

## Top-Level Default

Set a default for all secrets:

```toml
# Make all secrets strict by default
if_missing = "error"

[secrets.DATABASE_URL]
provider = "age"
value = "encrypted..."
# ↑ Inherits if_missing = "error"

[secrets.API_KEY]
provider = "age"
value = "encrypted..."
# ↑ Inherits if_missing = "error"

# Override for specific secret
[secrets.OPTIONAL_FEATURE_FLAG]
default = "false"
if_missing = "ignore"  # This one can be missing
```

## Runtime Override with CLI

Override config settings at runtime:

```bash
# Override to be lenient (useful in CI with missing secrets)
fnox exec --if-missing ignore -- npm test

# Override to be strict (ensure all secrets are present)
fnox exec --if-missing error -- ./deploy.sh

# Use warnings (default)
fnox exec --if-missing warn -- npm start
```

## Runtime Override with Environment Variable

```bash
# Set globally for a session
export FNOX_IF_MISSING=warn
fnox exec -- npm start

# Or inline
FNOX_IF_MISSING=error fnox exec -- ./critical-task.sh
```

## Base Default Behavior

Set a default behavior when `if_missing` is not configured anywhere:

```bash
# Change the default from "warn" to "error"
export FNOX_IF_MISSING_DEFAULT=error

# Now all secrets without explicit if_missing will fail if missing
fnox exec -- ./my-app
```

This is useful for:

- Making your entire project strict by default
- CI/CD environments where you want failures by default
- Development environments where you want warnings by default

**Priority:** This has the lowest priority and only applies when `if_missing` is not set in:

- CLI flags
- `FNOX_IF_MISSING` env var
- Secret-level config
- Top-level config

## CI/CD Examples

### Forked PRs (Secrets Unavailable)

```yaml
# .github/workflows/test.yml
name: Test
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run tests (some secrets may be missing in forks)
        env:
          FNOX_IF_MISSING: ignore # Don't fail on missing secrets
        run: |
          fnox exec -- npm test
```

### Production Deployment (Strict)

```yaml
# .github/workflows/deploy.yml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4

      - name: Deploy to production
        env:
          FNOX_IF_MISSING: error # Fail if any secret is missing
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          fnox exec --profile production -- ./deploy.sh
```

### Staging (Warn on Missing)

```yaml
# .github/workflows/staging.yml
jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to staging
        env:
          FNOX_IF_MISSING: warn # Print warnings but continue
        run: |
          fnox exec --profile staging -- ./deploy.sh
```

## Use Cases

### Optional Analytics/Monitoring

```toml
# Won't break the app if missing
[secrets.SENTRY_DSN]
provider = "aws"
value = "sentry-dsn"
if_missing = "ignore"

[secrets.DATADOG_API_KEY]
provider = "aws"
value = "datadog-key"
if_missing = "ignore"
```

### Required Database

```toml
# Must exist or fail
[secrets.DATABASE_URL]
provider = "aws"
value = "database-url"
if_missing = "error"
```

### Development Defaults

```toml
# Warn if missing, but provide a default
[secrets.REDIS_URL]
default = "redis://localhost:6379"
if_missing = "warn"
```

## Behavior Summary

| Mode     | Behavior                | Use Case                                  |
| -------- | ----------------------- | ----------------------------------------- |
| `error`  | Fail command            | Required secrets (database, API keys)     |
| `warn`   | Print warning, continue | Optional but recommended secrets          |
| `ignore` | Silent skip             | Truly optional features (analytics, etc.) |

## Tips

- **Start strict, relax as needed:** Use `if_missing = "error"` by default, then explicitly mark optional secrets as `"warn"` or `"ignore"`
- **CI environments:** Use `FNOX_IF_MISSING=ignore` for tests in forked PRs
- **Production:** Use `--if-missing error` or `FNOX_IF_MISSING=error` to ensure all secrets are available
- **Development:** Use `"warn"` (default) to know when secrets are missing but not block local dev

## Next Steps

- [Profiles](/guide/profiles) - Different secrets per environment
- [Import/Export](/guide/import-export) - Migrate secrets between systems
- [Real-World Example](/guide/real-world-example) - Complete setup with error handling
