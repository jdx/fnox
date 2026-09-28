---
description: "Read and write AWS Systems Manager Parameter Store secrets with fnox, including path prefixes and environment-specific profiles."
---

# AWS Parameter Store

AWS Systems Manager Parameter Store stores values under hierarchical paths. Use the `aws-ps` provider to read and write parameters, including encrypted `SecureString` values.

## Quick start

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
ps = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/prod/" }
```

```sh
# Create parameter in AWS
aws ssm put-parameter \
  --name "/myapp/prod/database-url" \
  --value "postgresql://prod.example.com/db" \
  --type "SecureString"
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[secrets]
DATABASE_URL = { provider = "ps", value = "database-url" }  # With prefix, fetches "/myapp/prod/database-url"
```

```sh
# Fetch secret
fnox get DATABASE_URL
```

## Prerequisites

- AWS account
- AWS credentials configured (CLI, environment variables, or IAM role)
- IAM permissions (see below)

## IAM permissions

### Read-only access (minimum)

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

### Full access (for testing)

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

### Configure AWS credentials

Choose one:

#### Option 1: environment variables

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-east-1"
```

#### Option 2: AWS CLI profile

```bash
aws configure

# Or use named profile
export AWS_PROFILE=myapp
```

#### Option 3: IAM role (automatic on AWS)

If running on EC2, ECS, Lambda, or other AWS services:

```bash
# No configuration needed!
# Credentials are automatic via instance metadata
```

### Configure fnox provider

```toml
[providers]
# Include only the optional fields you need.
ps = { type = "aws-ps", region = "us-east-1", profile = "my-aws-profile", prefix = "/myapp/prod/" }
```

| Field      | Required | Description                                                                                       |
| ---------- | -------- | ------------------------------------------------------------------------------------------------- |
| `region`   | Yes      | AWS region (e.g. `us-east-1`)                                                                     |
| `profile`  | No       | AWS CLI profile name from `~/.aws/config`. Falls back to the default credential chain if omitted. |
| `role_arn` | No       | IAM role to assume before reading parameters                                                      |
| `prefix`   | No       | Prepended to all parameter names                                                                  |

The `profile` field is useful when you have multiple AWS accounts or roles configured and want to pin a provider to a specific one without relying on `AWS_PROFILE` in the environment.

Set `role_arn` to have fnox call `sts:AssumeRole` and use the resulting credentials for every request. The credentials from `profile` (or the default chain) are the source credentials for that call:

```toml
[providers]
ps = { type = "aws-ps", region = "eu-west-1", profile = "sso-dev", role_arn = "arn:aws:iam::123456789012:role/param-reader" }
```

## Creating parameters

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

### Via AWS console

1. Go to [AWS Systems Manager Console](https://console.aws.amazon.com/systems-manager/parameters)
2. Click "Create parameter"
3. Name it with your path (e.g., `/myapp/prod/database-url`)
4. Choose "SecureString" for sensitive values
5. Enter the value
6. Create

## Referencing parameters

Add references to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "ps", value = "database-url" }  # → Fetches "/myapp/prod/database-url"
API_KEY = { provider = "ps", value = "api-key" }  # → Fetches "/myapp/prod/api-key"
# Without prefix in provider, use full path like: value = "/myapp/prod/api-key"
```

## Usage

### Get a secret

```bash
fnox get DATABASE_URL
```

### Run commands

```bash
# Fetches all secrets from Parameter Store
fnox exec -- ./start-server.sh
```

### Use different profiles

```bash
# Different profile for different environments
fnox exec --profile production -- ./deploy.sh
```

## Prefix behavior

The `prefix` is prepended to the `value`:

```toml
[providers]
ps = { type = "aws-ps", region = "us-east-1", prefix = "/myapp/prod/" }

[secrets]
DATABASE_URL = { provider = "ps", value = "database-url" }  # → Fetches "/myapp/prod/database-url"
API_KEY = { provider = "ps", value = "api-key" }  # → Fetches "/myapp/prod/api-key"
```

Without prefix:

```toml
[providers]
ps = { type = "aws-ps", region = "us-east-1" }  # No prefix

[secrets]
DATABASE_URL = { provider = "ps", value = "/myapp/prod/database-url" }  # → Full path
```

## Hierarchical organization

Parameter Store supports path-based organization:

```text
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

## Multi-environment example

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

# Production: AWS Parameter Store using a dedicated AWS profile
[profiles.production.providers]
ps = { type = "aws-ps", region = "us-east-1", profile = "prod-account", prefix = "/myapp/prod/" }

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

Charges depend on region, storage, key type or tier, and API usage. Consult the [service pricing](https://aws.amazon.com/systems-manager/pricing/) for current rates. fnox does not change the provider's billing model.

## Comparison: Parameter Store vs Secrets Manager

| Feature       | Parameter Store               | Secrets Manager           |
| ------------- | ----------------------------- | ------------------------- |
| Max Size      | 4KB (8KB advanced)            | 64KB                      |
| Rotation      | Manual                        | Automatic                 |
| Versioning    | Limited                       | Full versioning           |
| Organization  | Hierarchical paths (`/a/b/c`) | Flat with tags            |
| Cross-account | Via resource policies         | Via resource policies     |
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

## CI/CD example

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

## Usage notes

Use `SecureString` for sensitive parameter values. The provider applies its prefix to the configured parameter name; include the leading and trailing separators you need. Refresh any fnox cache after updating a parameter.

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
grep prefix fnox.toml
```

### "Invalid Region"

Verify region matches:

```bash
# Check fnox.toml region
grep region fnox.toml

# Check AWS credentials region
echo $AWS_REGION
```

## Next steps

- [AWS Secrets Manager](/providers/aws-sm) - For automatic rotation and complex secrets
- [AWS KMS](/providers/aws-kms) - For encrypting secrets in git
- [Real-World Example](/guide/real-world-example) - Complete AWS setup
- [Profiles](/guide/profiles) - Multi-environment configuration
