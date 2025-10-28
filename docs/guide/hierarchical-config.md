# Hierarchical Configuration

fnox searches parent directories for `fnox.toml` files and merges them. This is perfect for monorepos and multi-service projects.

## How It Works

fnox walks up the directory tree from your current location and merges all `fnox.toml` files it finds:

```
project/
├── fnox.toml              # Root config
└── services/
    ├── api/
    │   └── fnox.toml      # API config
    └── worker/
        └── fnox.toml      # Worker config
```

When you run fnox from `project/services/api/`:

1. Loads `project/fnox.toml` (parent)
2. Loads `project/services/api/fnox.toml` (current)
3. Merges them (child overrides parent)

## Example Setup

### Root Config (Common Secrets)

```toml
# project/fnox.toml

# Shared age provider
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

# Shared secrets
[secrets.LOG_LEVEL]
default = "info"

[secrets.ENVIRONMENT]
default = "development"

[secrets.JWT_SECRET]
provider = "age"
value = "encrypted-shared-jwt..."
```

### API Service Config

```toml
# project/services/api/fnox.toml

# API-specific secrets
[secrets.API_PORT]
default = "3000"

[secrets.DATABASE_URL]
provider = "age"
value = "encrypted-api-db..."

# Override shared secret for API
[secrets.LOG_LEVEL]
default = "debug"  # More verbose for API during dev
```

### Worker Service Config

```toml
# project/services/worker/fnox.toml

# Worker-specific secrets
[secrets.QUEUE_URL]
provider = "age"
value = "encrypted-queue-url..."

[secrets.WORKER_CONCURRENCY]
default = "4"
```

## Resulting Secrets

From `project/services/api/`:

```bash
fnox list
# ENVIRONMENT=development       (from root)
# JWT_SECRET=***                (from root)
# LOG_LEVEL=debug               (from api, overrides root)
# API_PORT=3000                 (from api)
# DATABASE_URL=***              (from api)
```

From `project/services/worker/`:

```bash
fnox list
# ENVIRONMENT=development       (from root)
# JWT_SECRET=***                (from root)
# LOG_LEVEL=info                (from root)
# QUEUE_URL=***                 (from worker)
# WORKER_CONCURRENCY=4          (from worker)
```

## Monorepo Pattern

A typical monorepo setup:

```
monorepo/
├── fnox.toml                  # Global: age provider, shared secrets
├── apps/
│   ├── web/
│   │   └── fnox.toml          # Web app secrets
│   └── mobile/
│       └── fnox.toml          # Mobile app secrets
└── services/
    ├── api/
    │   └── fnox.toml          # API service secrets
    └── workers/
        ├── fnox.toml          # Shared worker config
        ├── email/
        │   └── fnox.toml      # Email worker secrets
        └── analytics/
            └── fnox.toml      # Analytics worker secrets
```

### Root Config

```toml
# monorepo/fnox.toml

[providers.age]
type = "age"
recipients = [
  "age1alice...",
  "age1bob...",
  "age1charlie..."
]

# Shared across all services
[secrets.SENTRY_DSN]
provider = "age"
value = "encrypted-sentry..."

[secrets.LOG_LEVEL]
default = "info"
```

Each subdirectory inherits the age provider and shared secrets, then adds its own.

## Local Config with Hierarchy

Both `fnox.toml` and `fnox.local.toml` are merged at each level:

```
project/
├── fnox.toml
├── fnox.local.toml            # Local overrides for root
└── services/
    └── api/
        ├── fnox.toml
        └── fnox.local.toml    # Local overrides for api
```

Merge order (lowest to highest priority):

1. `project/fnox.toml`
2. `project/fnox.local.toml`
3. `project/services/api/fnox.toml`
4. `project/services/api/fnox.local.toml`

## Imports vs Hierarchy

**Hierarchy** (automatic):

- Walks up directory tree
- Merges all `fnox.toml` files found
- Child overrides parent

**Imports** (explicit):

```toml
# Explicit file imports
imports = ["./shared/secrets.toml", "./envs/dev.toml"]
```

Use hierarchy for location-based config (monorepos). Use imports for cross-cutting concerns (shared secret bundles).

## Tips

- **Keep root config minimal:** Only shared providers and secrets
- **Service-specific secrets in subdirectories:** Each service manages its own
- **Use local overrides for development:** Personal config without affecting team
- **Profile inheritance works too:** Each level can define profile-specific overrides

## Next Steps

- [Local Overrides](/guide/local-overrides) - Per-developer customization
- [Profiles](/guide/profiles) - Multi-environment management
- [Real-World Example](/guide/real-world-example) - See it all together
