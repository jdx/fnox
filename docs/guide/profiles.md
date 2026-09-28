---
description: "Define development and production secrets, inherit shared settings, compose profiles, and choose a write target."
---

# Profiles

Profiles let you manage secrets for different environments (dev, staging, production) in a single `fnox.toml` file.

## Basic usage

Define environment-specific secrets using profiles. The examples that follow assume the named providers are configured; ciphertext is abbreviated. See the [complete setup](/guide/real-world-example) for provider definitions.

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

## Using profiles

### Via command line

```bash
# Use default profile
fnox get API_URL

# Use specific profile
fnox get API_URL --profile staging
fnox exec --profile production -- ./deploy.sh
```

### Via environment variable

```bash
# Set once for the session
export FNOX_PROFILE=production

# All commands use production profile
fnox get DATABASE_URL
fnox exec -- node server.js
```

### With shell integration

```bash
# Enable shell integration
eval "$(fnox activate bash)"

# Switch profiles
export FNOX_PROFILE=production
cd my-app  # Loads production secrets

export FNOX_PROFILE=staging
# fnox detects the change on the next prompt automatically
```

## Composing multiple profiles

You can activate multiple profiles at the same time as an ordered overlay
stack. Later profiles override earlier ones on key conflicts, with the
top-level config as the base.

```bash
# Repeatable flags or comma-separated
fnox -P aws -P prod exec -- ./app
fnox -P aws,prod exec -- ./app

# Via environment variable
export FNOX_PROFILE=aws,prod
```

When multiple profiles are active, write commands (`set`, `remove`,
`import`, `sync`, `provider add/remove`) require an explicit
`--write-profile <NAME>` to choose the write target:

```bash
# Reads from aws + prod overlay, writes to prod
fnox -P aws -P prod --write-profile prod set DATABASE_URL "value"
```

With a single active profile, the write target defaults to that profile
and `--write-profile` is not needed.

### When to use composition

Composition is useful when concerns are split across profiles:

- `aws` provides cloud provider configuration
- `prod` provides production secret mappings
- `ci` adds CI-only secrets
- `local` overrides a few values for local development

## Profile inheritance

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

Named profiles can also inherit other profiles. Inherited profiles are applied
in list order, followed by the profile itself, so later entries and direct
profile settings take precedence:

```toml
[profiles.openai.secrets]
OPENAI_API_KEY = { provider = "age", value = "encrypted-key..." }

[profiles.database-local.secrets]
DATABASE_PASSWORD = { provider = "age", value = "encrypted-password..." }

[profiles.api-local]
inherits = ["openai", "database-local"]

[profiles.openai-john.secrets]
OPENAI_API_KEY = { provider = "age-john", value = "encrypted-john-key..." }

[profiles.api-local-john]
inherits = ["api-local", "openai-john"]
```

The application can then select its complete secret set with one stable name:

```bash
fnox -P api-local exec -- ./api
fnox -P api-local-john exec -- ./api
```

Inheritance includes secrets, providers, lease backends, and the default
provider. Nested inheritance is supported; cycles and unknown inherited
profiles are reported as configuration errors. `--no-defaults` still controls
whether top-level secrets are included.

Use `--no-defaults` to exclude top-level secrets while keeping the selected profiles and their inheritance. It does not remove top-level provider definitions.

## Profile-specific providers

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

## Secret references in provider config

Provider configuration properties can reference secrets using `{ secret = "NAME" }`. This enables bootstrap scenarios where provider credentials are themselves managed as secrets:

```toml
[providers.age]
type = "age"
recipients = ["age1..."]

[providers.vault]
type = "vault"
address = "https://vault.example.com:8200"
token = { secret = "VAULT_TOKEN" }  # Resolved from secrets or env var

[secrets]
VAULT_TOKEN = { provider = "age", value = "AGE-ENCRYPTED-TOKEN..." }
DATABASE_URL = { provider = "vault", value = "database/password" }
```

Resolution order: config secrets first, then environment variables. fnox detects circular dependencies and errors if found.

## List profiles

See all available profiles:

```bash
fnox profiles
```

Output:

```text
Available profiles:
  default (2 secrets)
  staging (2 secrets)
  production (2 secrets)
```

## Common patterns

### Development + production

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

### Multi-region production

```toml
[profiles.production-us.providers]
aws = { type = "aws-sm", region = "us-east-1" }

[profiles.production-eu.providers]
aws = { type = "aws-sm", region = "eu-west-1" }
```

### Per-developer profiles

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

## CI/CD example

These job excerpts assume checkout, fnox installation, and provider authentication steps are already in place.

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

## Next steps

- [Hierarchical Config](/guide/hierarchical-config) - Organize configs across directories (includes local overrides)
- [Real-World Example](/guide/real-world-example) - Complete multi-environment setup
