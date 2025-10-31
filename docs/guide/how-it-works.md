# How It Works

fnox uses a simple TOML config file (`fnox.toml`) that you check into git.

## Two Storage Modes

Secrets can be stored in two ways:

### 1. Encrypted Inline

The encrypted ciphertext lives directly in the config file:

```toml
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }

[secrets]
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC4uLg==" }  # ← encrypted, safe to commit
```

**Providers:** age, aws-kms, azure-kms, gcp-kms

### 2. Remote References

The config contains only a reference to a secret stored remotely:

```toml
[providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }

[secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # ← Just a reference, actual secret in AWS
```

**Providers:** aws-sm, azure-sm, gcp-sm, vault, 1password, bitwarden, keychain

## Secret Resolution Order

When fnox resolves a secret, it checks in this order:

1. **Encrypted value** (`provider = "age"`, `value = "encrypted..."`)
2. **Provider reference** (`provider = "aws"`, `value = "secret-name"`)
3. **Environment variable** (if already set in shell)
4. **Default value** (`default = "fallback"`)

First match wins!

## Example Config

```toml
# Provider definitions
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }
aws = { type = "aws-sm", region = "us-east-1" }

[secrets]
JWT_SECRET = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC4uLg==" }  # Encrypted secret (in git)
DATABASE_URL = { provider = "aws", value = "prod-database-url" }  # Remote secret (in AWS)
NODE_ENV = { default = "development" }  # Default value (fallback)
```

## Execution Flow

When you run `fnox exec -- <command>`:

1. fnox reads `fnox.toml` from current directory (or parent directories)
2. Resolves all secrets based on the active profile
3. Decrypts encrypted secrets or fetches remote secrets
4. Exports all secrets as environment variables
5. Executes your command with those env vars

## Next Steps

- [Profiles](/guide/profiles) - Manage multiple environments
- [Providers](/providers/overview) - Choose the right provider for your needs
- [Shell Integration](/guide/shell-integration) - Auto-load secrets in your shell
