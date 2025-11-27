# AWS Parameter Store

AWS Systems Manager Parameter Store provides hierarchical secret storage with path-based organization. It's a cost-effective alternative to AWS Secrets Manager for simpler use cases.

## Quick Start

```bash
# 1. Configure provider in fnox.toml
cat >> fnox.toml << 'EOF'
[providers]
ps = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/prod/" }
EOF

# 2. Create parameter in AWS
aws ssm put-parameter \
  --name "/myapp/prod/database-url" \
  --value "postgresql://prod.example.com/db" \
  --type "SecureString"

# 3. Reference in fnox.toml
cat >> fnox.toml << 'EOF'
[secrets]
DATABASE_URL = { provider = "ps", value = "database-url" }  # With prefix, fetches "/myapp/prod/database-url"
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
      "Sid": "DescribeParameters",
      "Effect": "Allow",
      "Action": "ssm:DescribeParameters",
      "Resource": "*"
    },
    {
      "Sid": "ReadParameters",
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParameters"],
      "Resource": "arn:aws:ssm:REGION:ACCOUNT:parameter/myapp/*"
    }
  ]
}
```

::: warning DescribeParameters Permission
The `ssm:DescribeParameters` action **must** use `"Resource": "*"` and cannot be scoped to specific ARNs.
:::

### Full Access (For Testing)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeParameters",
      "Effect": "Allow",
      "Action": "ssm:DescribeParameters",
      "Resource": "*"
    },
    {
      "Sid": "ParameterStorePermissions",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:PutParameter",
        "ssm:DeleteParameter"
      ],
      "Resource": ["arn:aws:ssm:REGION:ACCOUNT:parameter/myapp/*"]
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
ps = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/prod/" }  # prefix is optional
```

## Creating Parameters

### Via AWS CLI

```bash
# Create a SecureString parameter (encrypted)
aws ssm put-parameter \
  --name "/myapp/prod/database-url" \
  --value "postgresql://prod.db.example.com/mydb" \
  --type "SecureString"

# Create with description
aws ssm put-parameter \
  --name "/myapp/prod/api-key" \
  --description "Production API key for external service" \
  --value "sk_live_abc123xyz789" \
  --type "SecureString"

# Update existing parameter
aws ssm put-parameter \
  --name "/myapp/prod/api-key" \
  --value "sk_live_newkey456" \
  --type "SecureString" \
  --overwrite
```

### Via fnox

```bash
# Store a secret directly via fnox
fnox set DATABASE_URL "postgresql://prod.db.example.com/mydb" --provider ps
```

### Via AWS Console

1. Go to [AWS Systems Manager Console](https://console.aws.amazon.com/systems-manager/parameters)
2. Click "Create parameter"
3. Name it with your path (e.g., `/myapp/prod/database-url`)
4. Choose "SecureString" for sensitive values
5. Enter the value
6. Create

## Referencing Parameters

Add references to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "ps", value = "database-url" }  # → Fetches "/myapp/prod/database-url"
API_KEY = { provider = "ps", value = "api-key" }  # → Fetches "/myapp/prod/api-key"
# Without prefix in provider, use full path like: value = "/myapp/prod/api-key"
```

## Usage

### Get a Secret

```bash
fnox get DATABASE_URL
```

### Run Commands

```bash
# Fetches all secrets from Parameter Store
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
ps = { type = "aws-ps", prefix = "/myapp/prod/" }

[secrets]
DATABASE_URL = { provider = "ps", value = "database-url" }  # → Fetches "/myapp/prod/database-url"
API_KEY = { provider = "ps", value = "api-key" }  # → Fetches "/myapp/prod/api-key"
```

Without prefix:

```toml
[providers]
ps = { type = "aws-ps" }  # No prefix

[secrets]
DATABASE_URL = { provider = "ps", value = "/myapp/prod/database-url" }  # → Full path
```

## Hierarchical Organization

Parameter Store supports path-based organization:

```
/myapp/
  prod/
    database/
      url
      password
    api/
      key
      secret
  staging/
    database/
      url
      password
```

```toml
[providers]
prod = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/prod/" }
staging = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/staging/" }

[secrets]
DATABASE_URL = { provider = "prod", value = "database/url" }

[profiles.staging.secrets]
DATABASE_URL = { provider = "staging", value = "database/url" }
```

## Multi-Environment Example

```toml
# Development: age encryption
[providers]
age = { type = "age", recipients = ["age1..."] }

[secrets]
DATABASE_URL = { provider = "age", value = "encrypted-dev-db..." }

# Staging: AWS Parameter Store
[profiles.staging.providers]
ps = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/staging/" }

[profiles.staging.secrets]
DATABASE_URL = { provider = "ps", value = "database/url" }

# Production: AWS Parameter Store
[profiles.production.providers]
ps = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/prod/" }

[profiles.production.secrets]
DATABASE_URL = { provider = "ps", value = "database/url" }
```

```bash
# Development (local)
fnox get DATABASE_URL

# Staging
fnox get DATABASE_URL --profile staging

# Production
fnox get DATABASE_URL --profile production
```

## Costs

AWS Parameter Store pricing:

- **Standard parameters**: Free (up to 10,000 parameters)
- **Advanced parameters**: $0.05 per parameter per month
- **API calls**: Free for standard tier

::: tip Cost Optimization
Parameter Store standard tier is free for most use cases. Use it for configuration values and simple secrets. Reserve AWS Secrets Manager for secrets that need automatic rotation.
:::

## Comparison: Parameter Store vs Secrets Manager

| Feature       | Parameter Store               | Secrets Manager           |
| ------------- | ----------------------------- | ------------------------- |
| Cost          | Free (standard tier)          | $0.40/secret/month        |
| Max Size      | 4KB (8KB advanced)            | 64KB                      |
| Rotation      | Manual                        | Automatic                 |
| Versioning    | Limited                       | Full versioning           |
| Organization  | Hierarchical paths (`/a/b/c`) | Flat with tags            |
| Cross-account | Via Resource policies         | Via Resource policies     |
| Best For      | Config values, simple secrets | Complex secrets, rotation |

**Use Parameter Store when:**

- You have simple secrets or configuration values
- Cost is a concern
- You want hierarchical organization
- You don't need automatic rotation

**Use Secrets Manager when:**

- You need automatic secret rotation
- You have complex JSON secrets
- You need full versioning history

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

- ✅ Free for standard tier (up to 10,000 parameters)
- ✅ Hierarchical path-based organization
- ✅ IAM access control
- ✅ CloudTrail audit logs
- ✅ Secrets never in git
- ✅ Simple and straightforward

## Cons

- ❌ No automatic rotation (use Secrets Manager for that)
- ❌ Limited versioning
- ❌ Smaller size limit (4KB standard, 8KB advanced)
- ❌ Requires AWS account and network access
- ❌ AWS vendor lock-in

## Troubleshooting

### "AccessDeniedException"

Check IAM permissions:

```bash
# Test access
aws ssm describe-parameters
aws ssm get-parameter --name "/myapp/prod/database-url" --with-decryption
```

### "ParameterNotFound"

Parameter doesn't exist. Check:

```bash
# List parameters with path
aws ssm get-parameters-by-path --path "/myapp/prod/" --recursive

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

- [AWS Secrets Manager](/providers/aws-sm) - For automatic rotation and complex secrets
- [AWS KMS](/providers/aws-kms) - For encrypting secrets in git
- [Real-World Example](/guide/real-world-example) - Complete AWS setup
- [Profiles](/guide/profiles) - Multi-environment configuration
