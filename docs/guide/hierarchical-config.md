# Hierarchical Configuration

fnox searches parent directories for `fnox.toml` (or `.fnox.toml`) files and merges them. This is perfect for monorepos and multi-service projects.

## How It Works

fnox builds configuration by merging multiple sources, starting with the global config and walking up the directory tree:

```
project/
├── fnox.toml              # Root config
├── fnox.local.toml        # Root local overrides (optional)
└── services/
    ├── api/
    │   ├── fnox.toml      # API config
    │   └── fnox.local.toml # API local overrides (optional)
    └── worker/
        ├── fnox.toml      # Worker config
        └── fnox.local.toml # Worker local overrides (optional)
```

When you run fnox from `project/services/api/`, the merge order is (lowest to highest priority):

1. Loads `~/.config/fnox/config.toml` (global config, if exists)
2. Loads `project/fnox.toml` (parent)
3. Loads `project/fnox.local.toml` (parent local, if exists)
4. Loads `project/services/api/fnox.toml` (current)
5. Loads `project/services/api/fnox.local.toml` (current local, if exists)

Each level merges both the main config and local overrides, with child configs taking precedence over parent configs, and local configs taking precedence over main configs at the same level. Global config provides the base layer available to all projects.

## Example Setup

### Root Config (Common Secrets)

```toml
# project/fnox.toml

[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }

[secrets]
LOG_LEVEL = { default = "info" }
ENVIRONMENT = { default = "development" }
JWT_SECRET = { provider = "age", value = "encrypted-shared-jwt..." }
```

### API Service Config

```toml
# project/services/api/fnox.toml

[secrets]
API_PORT = { default = "3000" }
DATABASE_URL = { provider = "age", value = "encrypted-api-db..." }
LOG_LEVEL = { default = "debug" }  # Override shared secret - more verbose for API during dev
```

### Worker Service Config

```toml
# project/services/worker/fnox.toml

[secrets]
QUEUE_URL = { provider = "age", value = "encrypted-queue-url..." }
WORKER_CONCURRENCY = { default = "4" }
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

## Imports vs Hierarchy

**Hierarchy** (automatic):

- Walks up directory tree
- Merges all `fnox.toml` and `fnox.local.toml` files found
- Child configs override parent configs
- Local configs override main configs at the same level

**Imports** (explicit):

```toml
# Explicit file imports
import = ["./shared/secrets.toml", "./envs/dev.toml"]
```

Use hierarchy for location-based config (monorepos). Use imports for cross-cutting concerns (shared secret bundles).

## Local Overrides

Use `fnox.local.toml` for user-specific overrides without committing to version control:

```bash
# Add to .gitignore
echo "fnox.local.toml" >> .gitignore

# Create local overrides
cat > fnox.local.toml << 'EOF'
[secrets.DATABASE_URL]
default = "postgresql://localhost/mylocal"

[secrets.DEBUG_MODE]
default = "true"
EOF
```

**Common use cases:**

- Override team secrets for local development
- Personal API keys and tokens
- Machine-specific configuration (laptop vs desktop)
- Testing different providers locally

**Tips:**

- Always add `fnox.local.toml` to `.gitignore`
- Provide a `fnox.local.toml.example` (committed) for team guidance
- Use explicit paths to bypass local overrides: `fnox -c ./fnox.toml get SECRET`

## Global Configuration

For machine-wide secrets that apply to all projects, use the global config:

```bash
# Initialize global config
fnox init --global

# Add secrets to global config
fnox set GITHUB_TOKEN "ghp_..." --global
fnox set NPM_TOKEN "npm_..." --global

# Add providers to global config
fnox provider add age age --global
```

**Location**: `~/.config/fnox/config.toml` (customizable via `FNOX_CONFIG_DIR`)

**Use cases**:

- Personal API tokens (GitHub, npm, etc.)
- Machine-specific credentials
- Default encryption provider available everywhere

**Note**: Global config is always loaded, even when `root = true` stops parent directory recursion.

## Tips

- **Keep root config minimal:** Only shared providers and secrets
- **Service-specific secrets in subdirectories:** Each service manages its own
- **Use `fnox.local.toml` for development:** Personal overrides without affecting team
- **Use global config for personal tokens:** Machine-wide secrets like `GITHUB_TOKEN`
- **Profile inheritance works too:** Each level can define profile-specific overrides
- **Use `root = true` to stop recursion:** Prevents searching parent directories (but not global config)
- **Use dotfiles to declutter:** `.fnox.toml` works the same as `fnox.toml` (same for `.fnox.local.toml`, `.fnox.staging.toml`, etc.)

## Next Steps

- [Profiles](/guide/profiles) - Multi-environment management
- [Real-World Example](/guide/real-world-example) - See it all together
