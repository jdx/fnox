---
description: "Choose whether missing secrets fail, warn, or stay silent, and supply non-sensitive defaults when appropriate."
---

# Handling missing secrets

Use the `if_missing` setting to control what happens when a secret can't be resolved. This is especially useful for CI environments or when some secrets are optional.

## Available modes

These policies apply when a command resolves multiple secrets. An explicit `fnox get KEY` may still return a provider error directly. A configured `default` is tried as a fallback before a value is considered missing.

- **`error`** - Fail the command if a secret cannot be resolved (strictest)
- **`warn`** - Print a warning and continue (default)
- **`ignore`** - Silently skip missing secrets

## Priority chain

You can set `if_missing` at multiple levels. fnox uses the first match:

1. **CLI flag** (highest priority): `--if-missing error`
2. **Environment variable**: `FNOX_IF_MISSING=warn`
3. **Secret-level config**: `[secrets.MY_SECRET]` with `if_missing = "error"`
4. **Top-level config**: Global default for all secrets
5. **Base default environment variable**: `FNOX_IF_MISSING_DEFAULT=error`
6. **Default**: `warn` (lowest priority)

## Per-secret configuration

Set different behaviors for different secrets:

```toml
[secrets]
# Critical secrets must exist
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }  # Fail if missing

# Optional secrets
ANALYTICS_KEY = { provider = "aws", value = "analytics-key", if_missing = "ignore" }  # Continue silently if missing

# Warn about missing secrets (default)
CACHE_URL = { provider = "aws", value = "cache-url", if_missing = "warn" }  # Print warning if missing
```

## Top-level default

Set a default for all secrets:

```toml
# Make all secrets strict by default
if_missing = "error"

[secrets]
DATABASE_URL = { provider = "age", value = "encrypted..." }  # Inherits if_missing = "error"
API_KEY = { provider = "age", value = "encrypted..." }  # Inherits if_missing = "error"
OPTIONAL_FEATURE_FLAG = { default = "false", if_missing = "ignore" }  # Override - this one can be missing
```

## Runtime override with CLI

Override config settings at runtime:

```bash
# Override to be lenient (useful in CI with missing secrets)
fnox exec --if-missing ignore -- npm test

# Override to be strict (ensure all secrets are present)
fnox exec --if-missing error -- ./deploy.sh

# Use warnings (default)
fnox exec --if-missing warn -- npm start
```

## Runtime override with environment variable

```bash
# Set globally for a session
export FNOX_IF_MISSING=warn
fnox exec -- npm start

# Or inline
FNOX_IF_MISSING=error fnox exec -- ./critical-task.sh
```

## Base default behavior

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

## CI/CD examples

These workflow excerpts assume fnox and any provider CLI have been installed. Supply provider credentials for tests that require real secrets.

### Forked PRs (secrets unavailable)

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

### Production deployment (strict)

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

### Staging (warn on missing)

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

## Use cases

### Optional analytics/monitoring

```toml
[secrets]
# Won't break the app if missing
SENTRY_DSN = { provider = "aws", value = "sentry-dsn", if_missing = "ignore" }
DATADOG_API_KEY = { provider = "aws", value = "datadog-key", if_missing = "ignore" }
```

### Required database

```toml
[secrets]
DATABASE_URL = { provider = "aws", value = "database-url", if_missing = "error" }  # Must exist or fail
```

### Development defaults

```toml
[secrets]
REDIS_URL = { provider = "aws", value = "redis-url", default = "redis://localhost:6379", if_missing = "warn" }  # Fall back to the local URL if the provider lookup fails
```

## Behavior summary

| Mode     | Behavior                | Use Case                                  |
| -------- | ----------------------- | ----------------------------------------- |
| `error`  | Fail command            | Required secrets (database, API keys)     |
| `warn`   | Print warning, continue | Optional but recommended secrets          |
| `ignore` | Silent skip             | Truly optional features (analytics, etc.) |

## Next steps

- [Profiles](/guide/profiles) - Different secrets per environment
- [Import/Export](/guide/import-export) - Migrate secrets between systems
- [Real-World Example](/guide/real-world-example) - Complete setup with error handling
