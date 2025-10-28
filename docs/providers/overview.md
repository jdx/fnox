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

**Pros:**

- Secrets live in git (version control, code review)
- Works offline
- No monthly per-secret charges
- Fast (no network calls to decrypt)

**Cons:**

- Key rotation requires re-encrypting secrets
- No centralized access control
- No audit logs

### ☁️ Cloud Secret Storage (remote, centralized)

Store secrets remotely in cloud providers. Your `fnox.toml` contains only references to secret names.

| Provider                                       | Description              | Best For                       |
| ---------------------------------------------- | ------------------------ | ------------------------------ |
| [AWS Secrets Manager](/providers/aws-sm)       | AWS centralized secrets  | Production AWS workloads       |
| [Azure Key Vault Secrets](/providers/azure-sm) | Azure secret storage     | Production Azure workloads     |
| [GCP Secret Manager](/providers/gcp-sm)        | Google Cloud secrets     | Production GCP workloads       |
| [HashiCorp Vault](/providers/vault)            | Self-hosted or HCP Vault | Multi-cloud, advanced features |

**Pros:**

- Centralized secret management
- IAM/RBAC access control
- Audit logs
- Automatic rotation (some providers)
- Secrets never in git

**Cons:**

- Requires network access
- Costs money
- Slower (network latency)
- Vendor lock-in

### 🔑 Password Managers

Integrate with password managers you already use.

| Provider                          | Description               | Best For                             |
| --------------------------------- | ------------------------- | ------------------------------------ |
| [1Password](/providers/1password) | 1Password CLI integration | Teams already using 1Password        |
| [Bitwarden](/providers/bitwarden) | Bitwarden/Vaultwarden     | Open source preference, self-hosting |

**Pros:**

- Leverage existing password manager
- Great UI and mobile apps
- Team management features
- Audit logs

**Cons:**

- Requires subscription (1Password)
- Session token management
- Requires network access

### 💻 Local Storage

Store secrets locally on your machine.

| Provider                           | Description                           | Best For                             |
| ---------------------------------- | ------------------------------------- | ------------------------------------ |
| [OS Keychain](/providers/keychain) | macOS/Windows/Linux credential stores | Local development, personal projects |
| [Plain](/providers/plain)          | Plaintext (default values only)       | Non-sensitive defaults               |

**Pros:**

- OS-managed encryption (keychain)
- No external dependencies
- Free
- Simple

**Cons:**

- Per-machine (not for teams)
- Requires GUI session (keychain)
- Not suitable for production

## Choosing a Provider

### For Open Source Projects

Use **[age](/providers/age)**:

- Encrypted secrets in git
- Works with SSH keys
- Simple setup
- Free forever

### For Development Teams

Use **[age](/providers/age)** for development + cloud provider for production:

- Dev/staging: age encrypted in git (team can clone and run)
- Production: AWS/Azure/GCP Secrets Manager (centralized)

### For AWS Infrastructure

- **Development:** [age](/providers/age) (encrypted in git)
- **Production:** [AWS Secrets Manager](/providers/aws-sm) (centralized)
- **Alternative:** [AWS KMS](/providers/aws-kms) (encrypted in git, AWS keys)

### For Azure Infrastructure

- **Development:** [age](/providers/age)
- **Production:** [Azure Key Vault Secrets](/providers/azure-sm)
- **Alternative:** [Azure KMS](/providers/azure-kms) (encrypted in git)

### For Google Cloud Infrastructure

- **Development:** [age](/providers/age)
- **Production:** [GCP Secret Manager](/providers/gcp-sm)
- **Alternative:** [GCP KMS](/providers/gcp-kms) (encrypted in git)

### For Multi-Cloud

Use **[HashiCorp Vault](/providers/vault)**:

- Works across all clouds
- Advanced features (dynamic secrets, leasing)
- Self-hosted or managed (HCP Vault)

### For Existing 1Password Users

Use **[1Password](/providers/1password)**:

- Leverage existing infrastructure
- Great for small teams
- Nice UI and mobile apps

### For Personal Projects

Use **[age](/providers/age)** or **[OS Keychain](/providers/keychain)**:

- Simple setup
- Free
- No cloud dependencies

## Mixing Providers

You can use multiple providers in the same project:

```toml
# Age for development
[providers.age]
type = "age"
recipients = ["age1..."]

# AWS for production
[providers.aws]
type = "aws-sm"
region = "us-east-1"

# Development secrets (encrypted in git)
[secrets.DATABASE_URL]
provider = "age"
value = "encrypted..."

# Production secrets (in AWS)
[profiles.production.secrets.DATABASE_URL]
provider = "aws"
value = "database-url"
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
