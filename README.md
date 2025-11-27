# 🔐 fnox

**Fort Knox for your secrets.**

[![CI](https://github.com/jdx/fnox/actions/workflows/ci.yml/badge.svg)](https://github.com/jdx/fnox/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Manage secrets with encryption or cloud providers—or both! fnox gives you a unified interface to work with secrets across development, CI, and production.

## Quick Start

```bash
# Install via mise (recommended)
mise use -g fnox

# Initialize in your project
fnox init

# Set a secret (encrypted by default)
fnox set DATABASE_URL "postgresql://localhost/mydb"

# Get a secret
fnox get DATABASE_URL

# Run commands with secrets loaded
fnox exec -- npm start

# Enable shell integration (auto-load on cd)
eval "$(fnox activate bash)"  # or zsh, fish
```

## What is fnox?

fnox lets you store secrets in two ways:

1. **Encrypted in git** - Using age, AWS KMS, Azure KMS, or GCP KMS
2. **Remote in cloud** - Using AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, 1Password, Bitwarden, Infisical, or HashiCorp Vault

Your `fnox.toml` config file either contains encrypted secrets or references to remote secrets. Use `fnox exec` to run commands with secrets loaded, or enable shell integration to auto-load secrets when you `cd` into a directory.

## Supported Providers

### 🔐 Encryption (secrets in git, encrypted)

- [**age**](https://fnox.jdx.dev/providers/age) - Modern encryption (works with SSH keys!)
- [**aws-kms**](https://fnox.jdx.dev/providers/aws-kms) - AWS Key Management Service
- [**azure-kms**](https://fnox.jdx.dev/providers/azure-kms) - Azure Key Vault encryption
- [**gcp-kms**](https://fnox.jdx.dev/providers/gcp-kms) - Google Cloud KMS

### ☁️ Cloud Secret Storage (remote, centralized)

- [**aws-ps**](https://fnox.jdx.dev/providers/aws-ps) - AWS Parameter Store
- [**aws-sm**](https://fnox.jdx.dev/providers/aws-sm) - AWS Secrets Manager
- [**azure-sm**](https://fnox.jdx.dev/providers/azure-sm) - Azure Key Vault Secrets
- [**gcp-sm**](https://fnox.jdx.dev/providers/gcp-sm) - Google Cloud Secret Manager
- [**vault**](https://fnox.jdx.dev/providers/vault) - HashiCorp Vault

### 🔑 Password Managers & Secret Services

- [**1password**](https://fnox.jdx.dev/providers/1password) - 1Password CLI
- [**bitwarden**](https://fnox.jdx.dev/providers/bitwarden) - Bitwarden/Vaultwarden
- [**infisical**](https://fnox.jdx.dev/providers/infisical) - Infisical secrets management

### 💻 Local Storage

- [**keychain**](https://fnox.jdx.dev/providers/keychain) - OS Keychain (macOS/Windows/Linux)
- [**keepass**](https://fnox.jdx.dev/providers/keepass) - KeePass database files (.kdbx)
- [**password-store**](https://fnox.jdx.dev/providers/password-store) - GPG-encrypted password store (Unix pass)
- [**plain**](https://fnox.jdx.dev/providers/plain) - Plain text (for defaults only!)

## Documentation

**📚 [Complete Documentation](https://fnox.jdx.dev/)**

### Quick Links

- [Installation](https://fnox.jdx.dev/guide/installation)
- [Quick Start Guide](https://fnox.jdx.dev/guide/quick-start)
- [How It Works](https://fnox.jdx.dev/guide/how-it-works)
- [Shell Integration](https://fnox.jdx.dev/guide/shell-integration)
- [Providers Overview](https://fnox.jdx.dev/providers/overview)
- [Real-World Example](https://fnox.jdx.dev/guide/real-world-example)

### Provider Guides

- [Age Encryption](https://fnox.jdx.dev/providers/age) - Simple, free, works with SSH keys
- [AWS Secrets Manager](https://fnox.jdx.dev/providers/aws-sm) - Centralized AWS secret management
- [1Password](https://fnox.jdx.dev/providers/1password) - Integrate with 1Password CLI
- [Bitwarden](https://fnox.jdx.dev/providers/bitwarden) - Open source password manager

[**View all providers →**](https://fnox.jdx.dev/providers/overview)

### Reference

- [CLI Reference](https://fnox.jdx.dev/cli/)
- [Environment Variables](https://fnox.jdx.dev/reference/environment)
- [Configuration File](https://fnox.jdx.dev/reference/configuration)

## Example

```toml
# fnox.toml

[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }

[secrets]
# Development secrets (encrypted in git)
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }  # ← encrypted, safe to commit
API_KEY = { default = "dev-key-12345" }  # ← plain default for local dev

[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # ← reference to AWS secret
```

```bash
# Development (uses encrypted secrets)
fnox exec -- npm start

# Production (uses AWS Secrets Manager)
fnox exec --profile production -- ./deploy.sh
```

## Why fnox?

- **Flexible** - Mix and match encryption and cloud providers
- **Team-friendly** - Encrypted secrets in git, everyone can decrypt
- **Multi-environment** - Different providers for dev, staging, prod
- **Shell integration** - Auto-load secrets on directory change
- **Developer-focused** - Simple config, powerful features
- **No vendor lock-in** - Switch providers anytime

## Installation

### Using mise (recommended)

```bash
mise use -g fnox
```

### Using Cargo

```bash
cargo install fnox
```

### From Source

```bash
git clone https://github.com/jdx/fnox
cd fnox
cargo install --path .
```

## Development

See [CLAUDE.md](./CLAUDE.md) for development guidelines.

```bash
# Build
mise run build

# Run tests
mise run test

# Run specific tests
mise run test:cargo
mise run test:bats

# Lint
mise run lint

# Full CI check
mise run ci
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [Documentation](https://fnox.jdx.dev/)
- [GitHub Repository](https://github.com/jdx/fnox)
- [Issue Tracker](https://github.com/jdx/fnox/issues)
- [mise](https://mise.jdx.dev) - Recommended installation method
