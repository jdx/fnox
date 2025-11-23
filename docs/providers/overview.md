# Providers Overview

fnox supports multiple secret storage and encryption providers. Choose the ones that fit your workflow.

## Provider Categories

### 🔐 Encryption (secrets in git, encrypted)

Store encrypted secrets in your `fnox.toml` file. The encrypted ciphertext is safe to commit to version control.

| Provider                          | Description                              | Best For                                  |
| --------------------------------- | ---------------------------------------- | ----------------------------------------- |
| [age](/providers/age)             | Modern encryption (works with SSH keys!) | Development secrets, open source projects |
| [AWS KMS](/providers/aws-kms)     | AWS Key Management Service               | AWS-based projects requiring IAM control  |
| [Azure KMS](/providers/azure-kms) | Azure Key Vault encryption               | Azure-based projects                      |
| [GCP KMS](/providers/gcp-kms)     | Google Cloud KMS                         | GCP-based projects                        |

### ☁️ Cloud Secret Storage (remote, centralized)

Store secrets remotely in cloud providers. Your `fnox.toml` contains only references to secret names.

| Provider                                       | Description              | Best For                       |
| ---------------------------------------------- | ------------------------ | ------------------------------ |
| [AWS Secrets Manager](/providers/aws-sm)       | AWS centralized secrets  | Production AWS workloads       |
| [Azure Key Vault Secrets](/providers/azure-sm) | Azure secret storage     | Production Azure workloads     |
| [GCP Secret Manager](/providers/gcp-sm)        | Google Cloud secrets     | Production GCP workloads       |
| [HashiCorp Vault](/providers/vault)            | Self-hosted or HCP Vault | Multi-cloud, advanced features |

### 🔑 Password Managers & Secret Services

Integrate with password managers and secret services you already use.

| Provider                          | Description               | Best For                              |
| --------------------------------- | ------------------------- | ------------------------------------- |
| [1Password](/providers/1password) | 1Password CLI integration | Teams already using 1Password         |
| [Bitwarden](/providers/bitwarden) | Bitwarden/Vaultwarden     | Open source preference, self-hosting  |
| [Infisical](/providers/infisical) | Infisical secrets         | Modern secret management, open source |

### 💻 Local Storage

Store secrets locally on your machine.

| Provider                                    | Description                           | Best For                                |
| ------------------------------------------- | ------------------------------------- | --------------------------------------- |
| [OS Keychain](/providers/keychain)          | macOS/Windows/Linux credential stores | Local development, personal projects    |
| [password-store](/providers/password-store) | GPG-encrypted local password store    | CLI users, git-based sync, Unix systems |
| [Plain](/providers/plain)                   | Plaintext (default values only)       | Non-sensitive defaults                  |

## Mixing Providers

You can use multiple providers in the same project:

```toml
# Age for development
[providers]
age = { type = "age", recipients = ["age1..."] }
aws = { type = "aws-sm", region = "us-east-1" }

# Development secrets (encrypted in git)
[secrets]
DATABASE_URL = { provider = "age", value = "encrypted..." }

# Production secrets (in AWS)
[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }
```

## Feature Comparison

| Feature        | age    | AWS KMS | AWS SM | 1Password | Vault |
| -------------- | ------ | ------- | ------ | --------- | ----- |
| Offline        | ✅     | ❌      | ❌     | ❌        | ❌    |
| In Git         | ✅     | ✅      | ❌     | ❌        | ❌    |
| Free           | ✅     | 💰      | 💰     | 💰        | ✅\*  |
| Audit Logs     | ❌     | ✅      | ✅     | ✅        | ✅    |
| Access Control | ❌     | ✅      | ✅     | ✅        | ✅    |
| Rotation       | Manual | Manual  | ✅     | Manual    | ✅    |
| Team-Friendly  | ✅     | ✅      | ✅     | ✅        | ✅    |

\*Self-hosted Vault is free, HCP Vault is paid

## Next Steps

Choose a provider and get started:

- [Age Encryption](/providers/age) - Simple, free, works with SSH keys
- [AWS Secrets Manager](/providers/aws-sm) - For AWS production workloads
- [1Password](/providers/1password) - Leverage existing 1Password setup
- [Complete Example](/guide/real-world-example) - See providers in action
