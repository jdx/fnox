# Profiles

Profiles let you manage secrets for different environments (dev, staging, production) in a single `fnox.toml` file.

## Basic Usage

Define environment-specific secrets using profiles:

```toml
# Default profile (development)
[secrets]
API_URL = { default = "http://localhost:3000" }
DATABASE_URL = { provider = "age", value = "encrypted-dev-db..." }

# Staging profile
[profiles.staging.secrets]
API_URL = { default = "https://staging.example.com" }
DATABASE_URL = { provider = "age", value = "encrypted-staging-db..." }

# Production profile
[profiles.production.secrets]
API_URL = { default = "https://api.example.com" }
DATABASE_URL = { provider = "aws", value = "prod-database-url" }  # Stored in AWS Secrets Manager
```

## Using Profiles

### Via Command Line

```bash
# Use default profile
fnox get API_URL

# Use specific profile
fnox get API_URL --profile staging
fnox exec --profile production -- ./deploy.sh
```

### Via Environment Variable

```bash
# Set once for the session
export FNOX_PROFILE=production

# All commands use production profile
fnox get DATABASE_URL
fnox exec -- node server.js
```

### With Shell Integration

```bash
# Enable shell integration
eval "$(fnox activate bash)"

# Switch profiles
export FNOX_PROFILE=production
cd my-app  # Loads production secrets

export FNOX_PROFILE=staging
# fnox detects the change on the next prompt automatically
```

## Composing Multiple Profiles

You can activate multiple profiles at the same time as an ordered overlay
stack. Later profiles override earlier ones on key conflicts, with the
top-level config as the base.

### Via Command Line

```bash
# Repeatable flags
fnox -P aws -P prod exec -- ./app

# Comma-separated
fnox -P aws,prod exec -- ./app
```

### Via Environment Variable

```bash
export FNOX_PROFILE=aws,prod
fnox exec -- ./app
```

### How Overlay Works

The effective configuration is built as:

```
top-level config
+ profiles.aws
+ profiles.prod
```

Each layer contributes its own providers, secrets, leases, and
`default_provider`. When a key exists in multiple layers, the **last**
profile wins.

```toml
# Top-level base
[providers.base]
type = "plain"

[secrets]
SHARED = { default = "base-value" }
BASE_ONLY = { default = "base-only" }

# aws profile: adds a provider, overrides SHARED
[profiles.aws.providers.aws_plain]
type = "plain"

[profiles.aws.secrets]
SHARED = { default = "aws-value" }
AWS_ONLY = { default = "aws-only" }

# prod profile: overrides SHARED again, adds prod-only secret
[profiles.prod.secrets]
SHARED = { default = "prod-value" }
PROD_ONLY = { default = "prod-only" }
```

With `fnox -P aws -P prod get SHARED`, the resolved value is `prod-value`
(the last profile wins). `AWS_ONLY` and `PROD_ONLY` are both visible, and
`BASE_ONLY` is inherited from the top level.

### Where Writes Go

When multiple profiles are active, write commands (`set`, `remove`,
`import`, `sync`, `provider add`) target the **last** active profile by
default. For example:

```bash
# Writes to fnox.prod.toml (or [profiles.prod] section)
fnox -P aws -P prod set NEW_SECRET "value"
```

### When to Use Composition

Composition is useful when concerns are split across profiles:

- `aws` provides cloud provider configuration
- `prod` provides production secret mappings
- `ci` adds CI-only secrets
- `local` overrides a few values for local development

## Profile Inheritance

Profiles automatically inherit secrets from the top level:

```toml
# Define once - all profiles inherit
[secrets]
LOG_LEVEL = { default = "info" }
API_TIMEOUT = { default = "30" }
DATABASE_URL = { provider = "age", value = "encrypted-dev-db..." }

# Staging inherits all top-level secrets
[profiles.staging]
# Automatically gets: LOG_LEVEL, API_TIMEOUT, DATABASE_URL

# Production overrides specific secrets, inherits the rest
[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "prod-db" }  # Overrides DATABASE_URL
LOG_LEVEL = { default = "warn" }  # Overrides LOG_LEVEL
# Still inherits API_TIMEOUT="30" from top level
```

This reduces duplication for secrets shared across environments.

## Profile-Specific Providers

Each profile can have its own providers:

```toml
# Default providers (for development)
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }

# Production profile with AWS providers
[profiles.production]

[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }
```

## Secret References in Provider Config

Provider configuration properties can reference secrets using `{ secret = "NAME" }`. This enables bootstrap scenarios where provider credentials are themselves managed as secrets:

```toml
[providers.age]
type = "age"
recipients = ["age1..."]

[providers.vault]
type = "vault"
address = "http://vault.example.com:8200"
token = { secret = "VAULT_TOKEN" }  # Resolved from secrets or env var

[secrets]
VAULT_TOKEN = { provider = "age", value = "AGE-ENCRYPTED-TOKEN..." }
DATABASE_URL = { provider = "vault", value = "database/creds/myapp" }
```

Resolution order: config secrets first, then environment variables. fnox detects circular dependencies and errors if found.

## List Profiles

See all available profiles:

```bash
fnox profiles
```

Output:

```
default (active)
staging
production
```

## Common Patterns

### Development + Production

```toml
# Development (default): encrypted in git
[providers]
age = { type = "age", recipients = ["age1..."] }

[secrets]
DATABASE_URL = { provider = "age", value = "encrypted..." }

# Production: AWS Secrets Manager
[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }
```

### Multi-Region Production

```toml
[profiles.production-us.providers]
aws = { type = "aws-sm", region = "us-east-1" }

[profiles.production-eu.providers]
aws = { type = "aws-sm", region = "eu-west-1" }
```

### Per-Developer Profiles

```toml
[profiles.alice]

[profiles.alice.secrets]
DATABASE_URL = { default = "postgresql://localhost/alice_db" }

[profiles.bob]

[profiles.bob.secrets]
DATABASE_URL = { default = "postgresql://localhost/bob_db" }
```

```bash
export FNOX_PROFILE=alice
fnox exec -- npm start
```

## CI/CD Example

```yaml
# .github/workflows/deploy.yml
jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    steps:
      - run: fnox exec --profile staging -- ./deploy.sh

  deploy-production:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - run: fnox exec --profile production -- ./deploy.sh
```

## Next Steps

- [Hierarchical Config](/guide/hierarchical-config) - Organize configs across directories (includes local overrides)
- [Real-World Example](/guide/real-world-example) - Complete multi-environment setup
