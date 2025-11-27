# Secret References in Provider Config

Provider configuration properties can reference secrets using the `{ secret = "NAME" }` syntax. This enables powerful bootstrap scenarios where provider credentials themselves can be managed as secrets.

## Why Use Secret Refs?

Consider this common problem: You want to use HashiCorp Vault for secrets, but where do you store the Vault token? With secret refs, you can:

1. Store the Vault token encrypted with age (which only needs a public key)
2. Reference that encrypted token in your Vault provider config
3. fnox automatically resolves the chain when you access secrets

## Basic Syntax

Any provider configuration property that accepts a string can use either syntax:

```toml
# Literal string (traditional)
[providers.vault]
type = "vault"
address = "http://localhost:8200"
token = "hvs.my-vault-token"

# Secret reference (new)
[providers.vault]
type = "vault"
address = "http://localhost:8200"
token = { secret = "VAULT_TOKEN" }

[secrets]
VAULT_TOKEN = { provider = "age", value = "AGE-ENCRYPTED-TOKEN..." }
```

## Resolution Order

When fnox encounters `{ secret = "NAME" }`, it resolves the value in this order:

1. **Config secrets** - Looks for `NAME` in the secrets section (same profile)
2. **Environment variable** - Falls back to `$NAME` environment variable

This means you can:

- Store credentials in config (encrypted or via another provider)
- Override via environment variables in CI/CD
- Use a mix of both approaches

## Common Patterns

### Bootstrap: Vault Token Encrypted with Age

Store your Vault token encrypted in git, decrypt it to initialize Vault:

```toml
[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[providers.vault]
type = "vault"
address = "http://vault.example.com:8200"
token = { secret = "VAULT_TOKEN" }

[secrets]
# Token stored encrypted - safe to commit
VAULT_TOKEN = { provider = "age", value = "AGE-SECRET-KEY-1..." }

# Application secrets from Vault
DATABASE_URL = { provider = "vault", value = "database/creds/myapp" }
API_KEY = { provider = "vault", value = "kv/myapp/api-key" }
```

### Bootstrap: 1Password Token from Keychain

Store your 1Password service account token in OS keychain:

```toml
[providers.keychain]
type = "keychain"
service = "fnox"

[providers.onepass]
type = "1password"
vault = "Engineering"

[secrets]
# 1Password token stored in OS keychain
OP_SERVICE_ACCOUNT_TOKEN = { provider = "keychain", value = "op-token" }

# Application secrets from 1Password
DATABASE_URL = { provider = "onepass", value = "Database/password" }
```

### Dynamic Provider Config from Secrets

Reference any config property, not just credentials:

```toml
[providers.aws]
type = "aws-sm"
region = { secret = "AWS_REGION" }
prefix = { secret = "SECRET_PREFIX" }

[secrets]
AWS_REGION = { default = "us-east-1" }
SECRET_PREFIX = { default = "myapp/prod/" }
```

### Environment Variable Override

Secret refs automatically fall back to environment variables:

```toml
[providers.vault]
type = "vault"
address = { secret = "VAULT_ADDR" }
token = { secret = "VAULT_TOKEN" }

[secrets]
# No VAULT_ADDR or VAULT_TOKEN defined in config
# They'll be read from environment variables
```

```bash
# CI/CD or local override
export VAULT_ADDR="http://vault.internal:8200"
export VAULT_TOKEN="hvs.ci-token"
fnox exec -- ./deploy.sh
```

## Cycle Detection

fnox detects circular dependencies and fails with a clear error:

```toml
# This would create a cycle - fnox will error
[providers.vault_a]
type = "vault"
token = { secret = "TOKEN_A" }

[providers.vault_b]
type = "vault"
token = { secret = "TOKEN_B" }

[secrets]
TOKEN_A = { provider = "vault_b", value = "token-a" }  # vault_b needs TOKEN_B
TOKEN_B = { provider = "vault_a", value = "token-b" }  # vault_a needs TOKEN_A -> cycle!
```

Error:

```
Error: Provider config cycle detected: vault_a -> vault_b -> vault_a
```

## Supported Properties

All string properties in provider configs support secret refs:

| Provider       | Properties Supporting Secret Refs                       |
| -------------- | ------------------------------------------------------- |
| vault          | `address`, `token`, `path`                              |
| aws-sm         | `region`, `prefix`                                      |
| aws-ps         | `region`, `prefix`                                      |
| aws-kms        | `region`, `key_id`                                      |
| azure-sm       | `vault_url`, `prefix`                                   |
| azure-kms      | `vault_url`, `key_name`                                 |
| gcp-sm         | `project`, `prefix`                                     |
| gcp-kms        | `project`, `location`, `keyring`, `key`                 |
| 1password      | `vault`, `account`                                      |
| bitwarden      | `collection`, `organization_id`, `profile`              |
| infisical      | `project_id`, `environment`, `path`                     |
| keychain       | `service`, `prefix`                                     |
| keepass        | `database`, `keyfile`, `password`                       |
| password-store | `prefix`, `store_dir`, `gpg_opts`                       |
| age            | `key_file` (note: `recipients` array not yet supported) |

## Best Practices

### 1. Use Age for Bootstrap Credentials

Age encryption only needs a public key to encrypt, making it ideal for storing other providers' credentials:

```toml
[providers.age]
type = "age"
recipients = ["age1..."]  # Public key - safe to share

[secrets]
VAULT_TOKEN = { provider = "age", value = "..." }  # Encrypted with public key
```

### 2. Keep Resolution Chains Short

Avoid deep chains of secret refs. One level of indirection is usually sufficient:

```toml
# Good: Single level
VAULT_TOKEN = { provider = "age", value = "..." }

# Avoid: Multiple levels (harder to debug)
VAULT_TOKEN = { provider = "keychain", value = "vault-token" }
# where keychain provider itself has secret refs...
```

### 3. Use Environment Variables for CI/CD

Let CI/CD systems inject credentials via environment:

```toml
[providers.vault]
token = { secret = "VAULT_TOKEN" }
# No VAULT_TOKEN in [secrets] - comes from CI environment
```

### 4. Document Your Bootstrap Chain

Add comments explaining how credentials are resolved:

```toml
# Bootstrap chain:
# 1. age provider uses FNOX_AGE_KEY from environment (set by ops)
# 2. VAULT_TOKEN decrypted by age
# 3. vault provider initialized with decrypted token
# 4. Application secrets fetched from Vault

[providers.age]
type = "age"
recipients = ["age1..."]

[providers.vault]
type = "vault"
token = { secret = "VAULT_TOKEN" }

[secrets]
VAULT_TOKEN = { provider = "age", value = "..." }
```

## Next Steps

- [Profiles](/guide/profiles) - Use different credentials per environment
- [Hierarchical Config](/guide/hierarchical-config) - Organize configs across directories
- [Providers Overview](/providers/overview) - Available providers
