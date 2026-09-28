---
description: "Create temporary AWS role credentials with fnox, including session duration, external IDs, and SSO-backed authentication."
---

# AWS STS

The `aws-sts` lease backend calls [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) to create short-lived AWS credentials from a long-lived IAM user or role.

## Configuration

```toml
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

| Field      | Required | Description                                              |
| ---------- | -------- | -------------------------------------------------------- |
| `region`   | Yes      | AWS region for STS endpoint                              |
| `role_arn` | Yes      | ARN of the IAM role to assume                            |
| `profile`  | No       | AWS profile name (from `~/.aws/config`)                  |
| `endpoint` | No       | Custom STS endpoint URL (for LocalStack, etc.)           |
| `duration` | No       | Lease duration (e.g., `"1h"`, `"30m"`; default: `"15m"`) |

## Prerequisites

The backend needs AWS credentials to call `sts:AssumeRole`. Before creating a lease, fnox checks that at least one of these is available:

1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables (plus `AWS_SESSION_TOKEN` for temporary credentials)
2. `AWS_PROFILE` or `AWS_SSO_SESSION` environment variables, or the `profile` config field
3. `~/.aws/credentials` or `~/.aws/config` files

The AWS SDK's default credential chain then decides which of them is used. If none are found, fnox prints:

```text
AWS credentials not found. Run 'aws sso login' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.
```

## Credentials produced

| Environment Variable    | Description          |
| ----------------------- | -------------------- |
| `AWS_ACCESS_KEY_ID`     | Temporary access key |
| `AWS_SECRET_ACCESS_KEY` | Temporary secret key |
| `AWS_SESSION_TOKEN`     | Session token        |

These replace any long-lived credentials in the subprocess environment.

## Limits

- **Max duration:** 12 hours (the role's own maximum session duration is configured in IAM and may be lower)
- **Revocation:** No-op — credentials expire automatically via AWS TTL

## Examples

### With stored credentials

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "op", value = "AWS IAM/access key", env = false }
AWS_SECRET_ACCESS_KEY = { provider = "op", value = "AWS IAM/secret key", env = false }

[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

```bash
fnox exec -- aws s3 ls
```

### With interactive prompting

```toml
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

```bash
fnox lease create aws -i
```

### With SSO

If you use AWS SSO, no stored credentials are needed — just log in first:

```bash
aws sso login --profile my-sso-profile

# Select the same profile used for login
AWS_PROFILE=my-sso-profile fnox exec -- aws s3 ls
```

## See also

- [Credential Leases](/guide/leases) — overview and approaches
- [AWS Secrets Manager provider](/providers/aws-sm) — for storing secrets in AWS
