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

| Field      | Required | Description                                    |
| ---------- | -------- | ---------------------------------------------- |
| `region`   | Yes      | AWS region for STS endpoint                    |
| `role_arn` | Yes      | ARN of the IAM role to assume                  |
| `profile`  | No       | AWS profile name (from `~/.aws/config`)        |
| `endpoint` | No       | Custom STS endpoint URL (for LocalStack, etc.) |
| `duration` | No       | Lease duration (e.g., `"1h"`, `"30m"`)         |

## Prerequisites

The backend needs AWS credentials to call `sts:AssumeRole`. fnox looks for them in this order:

1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables
2. `AWS_SESSION_TOKEN` (for temporary credentials)
3. `AWS_PROFILE` or `AWS_SSO_SESSION` environment variables
4. `~/.aws/credentials` or `~/.aws/config` files

If none are found, fnox prints:

```
AWS credentials not found. Run 'aws sso login' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.
```

## Credentials Produced

| Environment Variable    | Description          |
| ----------------------- | -------------------- |
| `AWS_ACCESS_KEY_ID`     | Temporary access key |
| `AWS_SECRET_ACCESS_KEY` | Temporary secret key |
| `AWS_SESSION_TOKEN`     | Session token        |

These replace any long-lived credentials in the subprocess environment.

## Limits

- **Max duration:** 12 hours (configurable per-role in IAM, up to 12h)
- **Revocation:** No-op — credentials expire automatically via AWS TTL

## Examples

### With stored credentials

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "op", value = "AWS IAM/access key" }
AWS_SECRET_ACCESS_KEY = { provider = "op", value = "AWS IAM/secret key" }

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

# fnox picks up the SSO session automatically
fnox exec -- aws s3 ls
```

## See Also

- [Credential Leases](/guide/leases) — overview and approaches
- [AWS Secrets Manager provider](/providers/aws-sm) — for storing secrets in AWS
