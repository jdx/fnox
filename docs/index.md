---
layout: home

hero:
  name: fnox
  text: Fort Knox for your secrets
  tagline: Manage secrets with encryption or cloud providers - or both!
  image:
    src: /logo.svg
    alt: fnox
  actions:
    - theme: brand
      text: Get Started
      link: /guide/what-is-fnox
    - theme: alt
      text: View on GitHub
      link: https://github.com/jdx/fnox

features:
  - icon: 🔐
    title: Multiple Provider Support
    details: Works with age, AWS KMS/SM, Azure, GCP, 1Password, Bitwarden, Infisical, password-store, HashiCorp Vault, and more.
  - icon: 📝
    title: Secrets in Git (Encrypted)
    details: Store encrypted secrets in version control with age, AWS KMS, Azure KMS, or GCP KMS.
  - icon: ☁️
    title: Cloud Secret Storage
    details: Reference secrets stored in AWS Secrets Manager, AWS Parameter Store, Azure Key Vault, GCP Secret Manager, or Vault.
  - icon: 🔄
    title: Shell Integration
    details: Automatically load secrets when you cd into a directory with a fnox.toml file.
  - icon: 🎯
    title: Multi-Environment Support
    details: Use profiles to manage different secrets for dev, staging, and production.
  - icon: 🛠️
    title: Developer Friendly
    details: Simple TOML config, easy CLI, and smooth integration with your existing workflow.
---

## Quick Example

```bash
# Initialize fnox in your project
fnox init

# Set a secret (stores it encrypted in fnox.toml)
fnox set DATABASE_URL "postgresql://localhost/mydb"

# Get a secret
fnox get DATABASE_URL

# Run commands with secrets loaded as env vars
fnox exec -- npm start

# Enable shell integration (auto-load secrets on cd)
eval "$(fnox activate bash)"  # or zsh, fish
```

## How It Works

fnox uses a simple TOML config file (`fnox.toml`) that you check into git. Secrets are either:

1. **Encrypted inline** - The encrypted ciphertext lives in the config file
2. **Remote references** - The config contains a reference (like "my-db-password") that points to a secret in AWS/1Password/etc.

You configure providers (encryption methods or cloud services), then assign each secret to a provider. fnox handles the rest.

```toml
# fnox.toml
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }

[secrets]
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24uLi4=" }  # ← encrypted ciphertext, safe to commit
API_KEY = { default = "dev-key-12345" }  # ← plain default value for local dev
```

## Supported Providers

### 🔐 Encryption (secrets in git, encrypted)

- **age** - Modern encryption (works with SSH keys!)
- **aws-kms** - AWS Key Management Service
- **azure-kms** - Azure Key Vault encryption
- **gcp-kms** - Google Cloud KMS

### ☁️ Cloud Secret Storage (remote, centralized)

- **aws-ps** - AWS Parameter Store
- **aws-sm** - AWS Secrets Manager
- **azure-sm** - Azure Key Vault Secrets
- **gcp-sm** - Google Cloud Secret Manager
- **vault** - HashiCorp Vault

### 🔑 Password Managers & Secret Services

- **1password** - 1Password CLI
- **bitwarden** - Bitwarden/Vaultwarden
- **infisical** - Infisical secrets management

### 💻 Local Storage

- **keychain** - OS Keychain (macOS/Windows/Linux)
- **password-store** - GPG-encrypted password store (Unix pass)
- **plain** - Plain text (for defaults only!)
