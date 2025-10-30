# AWS KMS

AWS Key Management Service (KMS) encrypts secrets using AWS-managed keys. The encrypted ciphertext is stored in your `fnox.toml` file.

## Comparison: KMS vs Secrets Manager

| Feature        | AWS KMS                                | AWS Secrets Manager  |
| -------------- | -------------------------------------- | -------------------- |
| Storage        | Local (encrypted in fnox.toml)         | Remote (in AWS)      |
| Secrets in git | Yes (encrypted)                        | No (references only) |
| Pricing        | $1/key/month (one key for all secrets) | $0.40/secret/month   |
| Rotation       | Manual                                 | Automatic            |
| Offline        | No (needs AWS API)                     | No (needs AWS API)   |

**Use KMS when:** You want secrets in git with AWS-managed keys.

**Use Secrets Manager when:** You want centralized storage without secrets in git.

## Quick Start

```bash
# 1. Create KMS key
aws kms create-key --description "fnox secrets encryption"
# Note the KeyId

# 2. Configure provider
cat >> fnox.toml << 'EOF'
[providers.kms]
type = "aws-kms"
key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
region = "us-east-1"
EOF

# 3. Encrypt a secret
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider kms

# 4. Get secret (decrypts via KMS)
fnox get DATABASE_URL
```

## Prerequisites

- AWS account
- AWS credentials configured
- KMS key created
- IAM permissions

## IAM Permissions

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

### 1. Create KMS Key

Via AWS CLI:

```bash
aws kms create-key \
  --description "fnox secrets encryption" \
  --key-usage ENCRYPT_DECRYPT

# Output includes KeyId - copy this
```

Or use [AWS Console](https://console.aws.amazon.com/kms/) → KMS → Create Key.

### 2. Configure AWS Credentials

Same as [AWS Secrets Manager](/providers/aws-sm#configure-aws-credentials).

### 3. Configure fnox Provider

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

## Usage

### Encrypt and Store

```bash
fnox set DATABASE_URL "postgresql://prod.example.com/db" --provider kms
```

Result in `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "kms", value = "AQICAHhw...base64...ciphertext..." }  # ← Encrypted, safe to commit!
```

### Decrypt and Get

```bash
fnox get DATABASE_URL
```

## How It Works

1. **Encryption (`fnox set`):**
   - Calls AWS KMS `Encrypt` API
   - Stores base64 ciphertext in fnox.toml

2. **Decryption (`fnox get`):**
   - Calls AWS KMS `Decrypt` API
   - Returns plaintext

## Multi-Environment Example

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

## Key Rotation

When rotating KMS keys:

1. Create new KMS key
2. Update fnox.toml with new `key_id`
3. Re-encrypt all secrets:
   ```bash
   fnox set DATABASE_URL "$(fnox get DATABASE_URL)" --provider kms
   fnox set API_KEY "$(fnox get API_KEY)" --provider kms
   ```

## Costs

AWS KMS pricing (as of 2024):

- **$1.00 per key per month**
- **$0.03 per 10,000 operations**

Example:

- 1 KMS key = $1.00/month
- 1,000 deployments × 10 secrets × 10 decrypt calls = $0.30/month
- **Total: ~$1.30/month**

Much cheaper than Secrets Manager for many secrets!

## Pros

- ✅ Secrets in git (version control)
- ✅ AWS-managed encryption keys
- ✅ IAM access control
- ✅ CloudTrail audit logs
- ✅ Cheaper than Secrets Manager (one key for all secrets)
- ✅ No per-secret charges

## Cons

- ❌ Requires AWS account and network access
- ❌ Costs money ($1/key/month)
- ❌ More complex than age encryption
- ❌ Manual rotation (vs automatic in Secrets Manager)

## Next Steps

- [AWS Secrets Manager](/providers/aws-sm) - Remote storage alternative
- [Age Encryption](/providers/age) - Free local encryption
- [Real-World Example](/guide/real-world-example) - Complete AWS setup
