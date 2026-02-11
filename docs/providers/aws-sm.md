# AWS Secrets Manager

AWS Secrets Manager provides centralized secret management with IAM access control, audit logs, and automatic rotation.

## Quick Start

```bash
# 1. Configure provider in fnox.toml
cat >> fnox.toml << 'EOF'
[providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }
EOF

# 2. Create secret in AWS
aws secretsmanager create-secret \
  --name "myapp/database-url" \
  --secret-string "postgresql://prod.example.com/db"

# 3. Reference in fnox.toml
cat >> fnox.toml << 'EOF'
[secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # With prefix, fetches "myapp/database-url"
EOF

# 4. Fetch secret
fnox get DATABASE_URL
```

## Prerequisites

- AWS account
- AWS credentials configured (CLI, environment variables, or IAM role)
- IAM permissions (see below)

## IAM Permissions

### Read-Only Access (Minimum)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListSecrets",
      "Effect": "Allow",
      "Action": "secretsmanager:ListSecrets",
      "Resource": "*"
    },
    {
      "Sid": "ReadSecrets",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:REGION:ACCOUNT:secret:myapp/*"
    }
  ]
}
```

::: warning ListSecrets Permission
The `secretsmanager:ListSecrets` action **must** use `"Resource": "*"` and cannot be scoped to specific ARNs.
:::

### Full Access (For Testing)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListSecretsPermission",
      "Effect": "Allow",
      "Action": "secretsmanager:ListSecrets",
      "Resource": "*"
    },
    {
      "Sid": "SecretsManagerPermissions",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:PutSecretValue",
        "secretsmanager:CreateSecret",
        "secretsmanager:UpdateSecret",
        "secretsmanager:DeleteSecret"
      ],
      "Resource": ["arn:aws:secretsmanager:REGION:ACCOUNT:secret:myapp/*"]
    }
  ]
}
```

## Configuration

### Configure AWS Credentials

Choose one:

#### Option 1: Environment Variables

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-east-1"
```

#### Option 2: AWS CLI Profile

```bash
aws configure

# Or use named profile
export AWS_PROFILE=myapp
```

#### Option 3: IAM Role (Automatic on AWS)

If running on EC2, ECS, Lambda, or other AWS services:

```bash
# No configuration needed!
# Credentials are automatic via instance metadata
```

### Configure fnox Provider

```toml
[providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }  # prefix is optional
```

## Creating Secrets

### Via AWS CLI

```bash
# Create a secret
aws secretsmanager create-secret \
  --name "myapp/database-url" \
  --secret-string "postgresql://prod.db.example.com/mydb"

# Create with description
aws secretsmanager create-secret \
  --name "myapp/api-key" \
  --description "Production API key for external service" \
  --secret-string "sk_live_abc123xyz789"

# Create JSON secret
aws secretsmanager create-secret \
  --name "myapp/db-creds" \
  --secret-string '{"username":"admin","password":"secret123"}'
```

### Via AWS Console

1. Go to [AWS Secrets Manager Console](https://console.aws.amazon.com/secretsmanager/)
2. Click "Store a new secret"
3. Choose "Other type of secret"
4. Enter key/value pairs or plaintext
5. Name it with your prefix (e.g., `myapp/database-url`)
6. Configure rotation (optional)
7. Store

## Referencing Secrets

Add references to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # → Fetches "myapp/database-url"
API_KEY = { provider = "aws", value = "api-key" }  # → Fetches "myapp/api-key"
# Without prefix in provider, use full name like: value = "myapp/api-key"
```

## Usage

### Get a Secret

```bash
fnox get DATABASE_URL
```

### Run Commands

```bash
# Fetches all secrets from AWS
fnox exec -- ./start-server.sh
```

### Use Different Profiles

```bash
# Different profile for different environments
fnox exec --profile production -- ./deploy.sh
```

## Prefix Behavior

The `prefix` is prepended to the `value`:

```toml
[providers]
aws = { prefix = "myapp/" }

[secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # → Fetches "myapp/database-url"
API_KEY = { provider = "aws", value = "api-key" }  # → Fetches "myapp/api-key"
```

Without prefix:

```toml
[providers]
aws = { }  # No prefix

[secrets]
DATABASE_URL = { provider = "aws", value = "myapp/database-url" }  # → Fetches "myapp/database-url"
```

## Multi-Environment Example

```toml
# Development: age encryption
[providers]
age = { type = "age", recipients = ["age1..."] }

[secrets]
DATABASE_URL = { provider = "age", value = "encrypted-dev-db..." }

# Staging: AWS Secrets Manager (us-east-1)
[profiles.staging.providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp-staging/" }

[profiles.staging.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # → myapp-staging/database-url

# Production: AWS Secrets Manager (us-west-2)
[profiles.production.providers]
aws = { type = "aws-sm", region = "us-west-2", prefix = "myapp-prod/" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # → myapp-prod/database-url
```

```bash
# Development (local)
fnox get DATABASE_URL

# Staging
fnox get DATABASE_URL --profile staging

# Production
fnox get DATABASE_URL --profile production
```

## JSON Secrets

AWS Secrets Manager supports JSON secrets:

```bash
# Create JSON secret
aws secretsmanager create-secret \
  --name "myapp/db-credentials" \
  --secret-string '{"host":"db.example.com","port":"5432","username":"admin","password":"secret"}'
```

By default, `fnox` returns the entire JSON string. Use `json_path` to extract specific fields:

```toml
[providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }

[secrets]
DB_CREDENTIALS = { provider = "aws", value = "db-credentials" }
DB_PASS = { provider = "aws", value = "db-credentials", json_path = "password" }
```

```bash
fnox get DB_CREDENTIALS
# Output: {"host":"db.example.com","port":"5432","username":"admin","password":"secret"}

fnox get DB_PASS
# Output: secret
```

This also supports nested JSON paths using dot notation.

Literal dots need to be escaped (`\.`).
In TOML, either literal strings have to be used (`'\.'`) or the backslash itself has to be escaped (`"\\."`):

```bash
# Create nested JSON secret
aws secretsmanager create-secret \
  --name "myapp/config" \
  --secret-string '{"database":{"host":"db.example.com","cache.key":"foo"}}'
```

```toml
[providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }

[secrets]
DB_HOST = { provider = "aws", value = "config", json_path = "database.host" }
DB_CACHE_KEY = { provider = "aws", value = "config", json_path = 'database.cache\.key' }
```

## Secret Rotation

AWS Secrets Manager supports automatic rotation:

```bash
# Enable rotation via AWS CLI
aws secretsmanager rotate-secret \
  --secret-id "myapp/database-url" \
  --rotation-lambda-arn "arn:aws:lambda:..."
```

fnox always fetches the current version, so rotation is transparent.

## Costs

AWS Secrets Manager pricing (as of 2024):

- **$0.40 per secret per month**
- **$0.05 per 10,000 API calls**

Example:

- 10 secrets × $0.40 = $4.00/month
- 1,000 deployments × 10 secrets × $0.05/10k = $0.50/month
- **Total: ~$4.50/month**

::: tip Cost Optimization
Use age encryption for development/staging secrets to reduce AWS Secrets Manager costs. Reserve AWS SM for production-only secrets.
:::

## CI/CD Example

### GitHub Actions

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1

      - name: Deploy with secrets
        run: |
          fnox exec --profile production -- ./deploy.sh
```

## Pros

- ✅ Centralized secret management
- ✅ IAM access control
- ✅ CloudTrail audit logs
- ✅ Automatic rotation support
- ✅ Secrets never in git
- ✅ Easy key rotation (no re-encryption needed)
- ✅ Versioning included

## Cons

- ❌ Requires AWS account and network access
- ❌ Costs money ($0.40/secret/month + API calls)
- ❌ More complex setup than encryption
- ❌ Slower (network latency)
- ❌ AWS vendor lock-in

## Comparison: AWS Secrets Manager vs AWS KMS

| Feature        | AWS Secrets Manager  | AWS KMS                                |
| -------------- | -------------------- | -------------------------------------- |
| Storage        | Remote (AWS)         | Local (encrypted in fnox.toml)         |
| Secrets in git | No (references only) | Yes (encrypted ciphertext)             |
| Pricing        | $0.40/secret/month   | $1/key/month (all secrets use one key) |
| Rotation       | Automatic            | Manual                                 |
| Offline        | No                   | No (needs AWS to encrypt/decrypt)      |
| Access Control | IAM policies         | IAM policies                           |

**Use AWS SM when:** You want centralized storage, rotation, and don't want secrets in git.

**Use AWS KMS when:** You want secrets in git (version control) but with AWS-managed keys.

## Troubleshooting

### "AccessDeniedException"

Check IAM permissions:

```bash
# Test access
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id "myapp/database-url"
```

### "ResourceNotFoundException"

Secret doesn't exist. Check:

```bash
# List all secrets
aws secretsmanager list-secrets

# Check if prefix is correct in fnox.toml
cat fnox.toml | grep prefix
```

### "Invalid Region"

Verify region matches:

```bash
# Check fnox.toml region
cat fnox.toml | grep region

# Check AWS credentials region
echo $AWS_REGION
```

## Next Steps

- [AWS KMS](/providers/aws-kms) - Alternative with secrets in git
- [Real-World Example](/guide/real-world-example) - Complete AWS setup
- [Profiles](/guide/profiles) - Multi-environment configuration
