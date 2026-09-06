---
description: "Read AWS Secrets Manager values with fnox. Configure authentication, IAM permissions, prefixes, and profiles."
---

# AWS Secrets Manager

AWS Secrets Manager provides centralized secret management with IAM access control, audit logs, and automatic rotation.

## Quick start

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }
```

```sh
# Create secret in AWS
aws secretsmanager create-secret \
  --name "myapp/database-url" \
  --secret-string "postgresql://prod.example.com/db"
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # With prefix, fetches "myapp/database-url"
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
      "Sid": "ListSecrets",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:ListSecrets",
        "secretsmanager:BatchGetSecretValue"
      ],
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

::: warning ListSecrets and BatchGetSecretValue Permissions
The `secretsmanager:ListSecrets` and `secretsmanager:BatchGetSecretValue` actions **must** use `"Resource": "*"` and cannot be scoped to specific ARNs.
:::

### Full access (for testing)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListSecretsPermission",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:ListSecrets",
        "secretsmanager:BatchGetSecretValue"
      ],
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
aws = { type = "aws-sm", region = "us-east-1", profile = "my-aws-profile", prefix = "myapp/" }
```

| Field      | Required | Description                                                                                       |
| ---------- | -------- | ------------------------------------------------------------------------------------------------- |
| `region`   | Yes      | AWS region (e.g. `us-east-1`)                                                                     |
| `profile`  | No       | AWS CLI profile name from `~/.aws/config`. Falls back to the default credential chain if omitted. |
| `role_arn` | No       | IAM role to assume before reading secrets                                                         |
| `prefix`   | No       | Prepended to all secret names                                                                     |

The `profile` field is useful when you have multiple AWS accounts or roles configured and want to pin a provider to a specific one without relying on `AWS_PROFILE` in the environment.

### Assuming a role

Set `role_arn` to have fnox call `sts:AssumeRole` and use the resulting credentials for every request. The credentials from `profile` (or the default chain) are the source credentials for that call, so an SSO profile plus a cross-account role works in one step:

```toml
[providers]
aws = { type = "aws-sm", region = "eu-west-1", profile = "sso-dev", role_arn = "arn:aws:iam::123456789012:role/secrets-reader" }
```

This mirrors the `role` option in SOPS. If your `~/.aws/config` profile already declares `role_arn` and `source_profile`, the AWS SDK assumes that role on its own and you do not need this field.

The session name is always `fnox`, and the role must trust the source identity for `sts:AssumeRole`.

## Creating secrets

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

### Via AWS console

1. Go to [AWS Secrets Manager Console](https://console.aws.amazon.com/secretsmanager/)
2. Click "Store a new secret"
3. Choose "Other type of secret"
4. Enter key/value pairs or plaintext
5. Name it with your prefix (e.g., `myapp/database-url`)
6. Configure rotation (optional)
7. Store

## Referencing secrets

Add references to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # → Fetches "myapp/database-url"
API_KEY = { provider = "aws", value = "api-key" }  # → Fetches "myapp/api-key"
# Without prefix in provider, use full name like: value = "myapp/api-key"
```

## Usage

### Get a secret

```bash
fnox get DATABASE_URL
```

### Run commands

```bash
# Fetches all secrets from AWS
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
aws = { type = "aws-sm", region = "us-east-1", prefix = "myapp/" }

[secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }  # → Fetches "myapp/database-url"
API_KEY = { provider = "aws", value = "api-key" }  # → Fetches "myapp/api-key"
```

Without prefix:

```toml
[providers]
aws = { type = "aws-sm", region = "us-east-1" }  # No prefix

[secrets]
DATABASE_URL = { provider = "aws", value = "myapp/database-url" }  # → Fetches "myapp/database-url"
```

## Multi-environment example

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

# Production: AWS Secrets Manager (us-west-2) using a dedicated AWS profile
[profiles.production.providers]
aws = { type = "aws-sm", region = "us-west-2", profile = "prod-account", prefix = "myapp-prod/" }

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

## JSON secrets

AWS Secrets Manager supports JSON secrets:

```bash
# Create JSON secret
aws secretsmanager create-secret \
  --name "myapp/db-credentials" \
  --secret-string '{"host":"db.example.com","port":"5432","username":"admin","password":"secret"}'
```

By default, fnox returns the entire JSON string. Use `json_path` to extract specific fields:

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

Literal dots in a key name need to be escaped (`\.`).
In TOML, either use a literal string (`'\.'`) or escape the backslash itself (`"\\."`):

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

## Secret rotation

AWS Secrets Manager supports automatic rotation:

```bash
# Enable rotation via AWS CLI
aws secretsmanager rotate-secret \
  --secret-id "myapp/database-url" \
  --rotation-lambda-arn "arn:aws:lambda:..."
```

Direct reads fetch the current version. Refresh an encrypted sync cache or clear the daemon cache to pick up a rotated value.

## Costs

Charges depend on region, storage, key type or tier, and API usage. Consult the [service pricing](https://aws.amazon.com/secrets-manager/pricing/) for current rates. fnox does not change the provider's billing model.

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

fnox reads the current secret value from AWS when it resolves directly. If you use sync or daemon caching, refresh that cache after rotation. `json_path` can select a field from a JSON secret without creating separate AWS secrets.

## Comparison: AWS Secrets Manager vs AWS KMS

| Feature        | AWS Secrets Manager  | AWS KMS                           |
| -------------- | -------------------- | --------------------------------- |
| Storage        | Remote (AWS)         | Local (encrypted in fnox.toml)    |
| Secrets in git | No (references only) | Yes (encrypted ciphertext)        |
| Rotation       | Automatic            | Manual                            |
| Offline        | No                   | No (needs AWS to encrypt/decrypt) |
| Access Control | IAM policies         | IAM policies                      |

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

- [AWS KMS](/providers/aws-kms) - Alternative with secrets in git
- [Real-World Example](/guide/real-world-example) - Complete AWS setup
- [Profiles](/guide/profiles) - Multi-environment configuration
