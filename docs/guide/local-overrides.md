# Local Configuration Overrides

Use `fnox.local.toml` for user-specific or machine-specific overrides without committing them to version control.

## Quick Start

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

## How It Works

- `fnox.local.toml` is loaded automatically alongside `fnox.toml` in the same directory
- Local config takes precedence over `fnox.toml` values
- Perfect for personal development settings, machine-specific credentials, or testing
- Works with profiles and config recursion

## File Structure

```
project/
├── fnox.toml              # Committed (team secrets)
├── fnox.local.toml        # Gitignored (personal overrides)
└── .gitignore             # Contains: fnox.local.toml
```

## Example Use Cases

### Override Team Secrets for Local Development

**Team config (committed):**

```toml
# fnox.toml
[providers.age]
type = "age"
recipients = ["age1team..."]

[secrets.DATABASE_URL]
provider = "age"
value = "encrypted-team-db..."  # Points to shared dev DB

[secrets.API_KEY]
provider = "age"
value = "encrypted-api-key..."
```

**Your local override (gitignored):**

```toml
# fnox.local.toml
[secrets.DATABASE_URL]
default = "postgresql://localhost/mylocal"  # Use local DB instead

[secrets.DEBUG_MODE]
default = "true"  # Enable debugging for yourself
```

### Personal API Keys

```toml
# fnox.local.toml
[secrets.GITHUB_TOKEN]
default = "ghp_YourPersonalToken"

[secrets.OPENAI_API_KEY]
default = "sk-your-key"
```

### Testing Different Providers

```toml
# fnox.local.toml

# Test keychain provider locally
[providers.keychain]
type = "keychain"
service = "fnox-test"

[secrets.TEST_SECRET]
provider = "keychain"
value = "test-key"
```

### Machine-Specific Configuration

```toml
# fnox.local.toml (on laptop)
[secrets.DATABASE_URL]
default = "postgresql://laptop-db/mydb"

[secrets.REDIS_URL]
default = "redis://localhost:6379"
```

```toml
# fnox.local.toml (on desktop)
[secrets.DATABASE_URL]
default = "postgresql://desktop-db/mydb"

[secrets.REDIS_URL]
default = "redis://192.168.1.100:6379"
```

## Merge Priority

When both files exist, fnox merges them with local taking priority:

```toml
# fnox.toml (committed)
[secrets.API_URL]
default = "https://api.production.com"

[secrets.DATABASE_URL]
provider = "age"
value = "encrypted..."

[secrets.LOG_LEVEL]
default = "info"
```

```toml
# fnox.local.toml (gitignored)
[secrets.API_URL]
default = "http://localhost:3000"  # Overrides fnox.toml

[secrets.DEBUG_MODE]
default = "true"  # New secret, only in local
```

Result:

```bash
fnox list
# API_URL=http://localhost:3000       (from local)
# DATABASE_URL=***                     (from fnox.toml)
# LOG_LEVEL=info                       (from fnox.toml)
# DEBUG_MODE=true                      (from local)
```

## Hierarchical Configs with Local Overrides

Both `fnox.toml` and `fnox.local.toml` are merged at each directory level:

```
project/
├── fnox.toml
├── fnox.local.toml          # Local overrides for root
└── services/
    └── api/
        ├── fnox.toml
        └── fnox.local.toml  # Local overrides for api
```

Merge order (lowest to highest priority):

1. `project/fnox.toml`
2. `project/fnox.local.toml`
3. `project/services/api/fnox.toml`
4. `project/services/api/fnox.local.toml`

## Profiles in Local Config

You can override profile-specific secrets:

```toml
# fnox.local.toml

# Override staging profile
[profiles.staging.secrets.DATABASE_URL]
default = "postgresql://localhost/staging-test"

# Override production profile (e.g., point to local mock)
[profiles.production.secrets.API_URL]
default = "http://localhost:8080"
```

## Bypassing Local Overrides

To explicitly use only `fnox.toml` (skip `fnox.local.toml`), use an explicit path:

```bash
# Uses both fnox.toml and fnox.local.toml
fnox get DATABASE_URL

# Only uses fnox.toml (skips fnox.local.toml)
fnox -c ./fnox.toml get DATABASE_URL
```

## Team Workflow

1. **Create `fnox.local.toml.example`** (committed) to document available overrides:

```toml
# fnox.local.toml.example
# Copy this to fnox.local.toml and customize for your environment

[secrets.DATABASE_URL]
# default = "postgresql://localhost/your_db"

[secrets.API_PORT]
# default = "3000"
```

2. **Add to `.gitignore`:**

```gitignore
fnox.local.toml
```

3. **Document in README:**

````markdown
## Local Development

Copy `fnox.local.toml.example` to `fnox.local.toml` and customize:

```bash
cp fnox.local.toml.example fnox.local.toml
```
````

````

## Tips

- **Always add to `.gitignore`:** Never commit `fnox.local.toml`
- **Provide examples:** Include `fnox.local.toml.example` for team guidance
- **Use for temporary testing:** Test provider configs without affecting team
- **Personal credentials:** Store personal tokens and keys safely
- **Per-machine differences:** Handle laptop vs desktop vs server configs

## Common Patterns

### Local Database Override
```toml
# fnox.local.toml
[secrets.DATABASE_URL]
default = "postgresql://localhost/dev_db"
````

### Debug Mode

```toml
# fnox.local.toml
[secrets.DEBUG]
default = "true"

[secrets.LOG_LEVEL]
default = "debug"
```

### Local Service URLs

```toml
# fnox.local.toml
[secrets.API_URL]
default = "http://localhost:3000"

[secrets.REDIS_URL]
default = "redis://localhost:6379"

[secrets.ELASTICSEARCH_URL]
default = "http://localhost:9200"
```

## Next Steps

- [Hierarchical Config](/guide/hierarchical-config) - Multi-directory config management
- [Profiles](/guide/profiles) - Environment-specific configs
- [Real-World Example](/guide/real-world-example) - Complete setup with local overrides
