---
description: "Encrypt values in fnox.toml with AWS KMS. Configure credentials, IAM permissions, keys, and key migration."
---

# AWS KMS

AWS Key Management Service (KMS) encrypts secrets using AWS-managed keys. The encrypted ciphertext is stored in your `fnox.toml` file.

## Comparison: KMS vs Secrets Manager

| Feature        | AWS KMS                        | AWS Secrets Manager  |
| -------------- | ------------------------------ | -------------------- |
| Storage        | Local (encrypted in fnox.toml) | Remote (in AWS)      |
| Secrets in git | Yes (encrypted)                | No (references only) |
| Rotation       | Manual                         | Automatic            |
| Offline        | No (needs AWS API)             | No (needs AWS API)   |

**Use KMS when:** You want secrets in git with AWS-managed keys.

**Use Secrets Manager when:** You want centralized storage without secrets in git.

## Quick start

```sh
# Create KMS key
aws kms create-key --description "fnox secrets encryption"
# Note the KeyId
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers.kms]
type = "aws-kms"
key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
region = "us-east-1"
```

```sh
# Encrypt a secret
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider kms

# Get secret (decrypts via KMS)
fnox get DATABASE_URL
```

## Prerequisites

- AWS account
- AWS credentials configured
- KMS key created
- IAM permissions

## IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"
    }
  ]
}
```

## Setup

### 1. Create KMS key

Via AWS CLI:

```bash
aws kms create-key \
  --description "fnox secrets encryption" \
  --key-usage ENCRYPT_DECRYPT

# Output includes KeyId - copy this
```

Or use [AWS Console](https://console.aws.amazon.com/kms/) → KMS → Create Key.

### 2. Configure AWS credentials

Same as [AWS Secrets Manager](/providers/aws-sm#configure-aws-credentials).

### 3. Configure fnox provider

```toml
[providers.kms]
type = "aws-kms"
key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
region = "us-east-1"
```

The `key_id` can be:

- Full ARN: `arn:aws:kms:us-east-1:123456789012:key/...`
- Key ID: `12345678-1234-1234-1234-123456789012`
- Alias: `alias/my-key`

### Credentials

| Field      | Required | Description                                                                                       |
| ---------- | -------- | ------------------------------------------------------------------------------------------------- |
| `profile`  | No       | AWS CLI profile name from `~/.aws/config`. Falls back to the default credential chain if omitted. |
| `role_arn` | No       | IAM role to assume before calling KMS                                                             |

With `role_arn` set, fnox calls `sts:AssumeRole` and uses the resulting credentials for encrypt and decrypt. The credentials from `profile` (or the default chain) are the source credentials for that call, which covers the SOPS pattern of an SSO profile plus a key-holding role in another account:

```toml
[providers.kms]
type = "aws-kms"
key_id = "alias/my-key"
region = "eu-west-1"
profile = "sso-dev"
role_arn = "arn:aws:iam::123456789012:role/kms-user"
```

## Usage

### Encrypt and store

```bash
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider kms
```

Result in `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "kms", value = "AQICAHhw...base64...ciphertext..." }  # ← Encrypted, safe to commit!
```

### Decrypt and get

```bash
fnox get DATABASE_URL
```

## How it works

1. **Encryption (`fnox set`):**
   - Calls AWS KMS `Encrypt` API
   - Stores base64 ciphertext in fnox.toml

2. **Decryption (`fnox get`):**
   - Calls AWS KMS `Decrypt` API
   - Returns plaintext

## Multi-environment example

```toml
# Development: age encryption (free)
[providers]
age = { type = "age", recipients = ["age1..."] }

[secrets]
DATABASE_URL = { provider = "age", value = "encrypted-dev..." }

# Production: AWS KMS
[profiles.production.providers]
kms = { type = "aws-kms", key_id = "arn:aws:kms:us-east-1:123456789012:key/...", region = "us-east-1" }

[profiles.production.secrets]
DATABASE_URL = { provider = "kms", value = "AQICAHhw..." }  # ← KMS encrypted ciphertext
```

## Key rotation

Rotating key material within the same KMS key is different from switching to a new key ID. The fnox provider supplies `key_id` when decrypting, so changing it before migrating values can prevent the old ciphertext from decrypting.

To move to another KMS key, keep the old provider configured and add a second provider for the new key. Resolve each value through the old definition and store it with the new provider:

```sh
fnox get DATABASE_URL | fnox set DATABASE_URL --provider new-kms
```

Repeat for the affected secrets and profiles, verify access, then remove the old provider when it is no longer used. Rotate the underlying application secret separately if its plaintext may have been exposed.

## Costs

Charges depend on region, storage, key type or tier, and API usage. Consult the [service pricing](https://aws.amazon.com/kms/pricing/) for current rates. fnox does not change the provider's billing model.

## Usage notes

Ciphertext lives in your config, but both encryption and decryption require AWS access. IAM policies and the KMS key policy must permit the operation. Rotating the KMS key material is distinct from changing the application secret.

## Next steps

- [AWS Secrets Manager](/providers/aws-sm) - Remote storage alternative
- [Age Encryption](/providers/age) - Free local encryption
- [Real-World Example](/guide/real-world-example) - Complete AWS setup
