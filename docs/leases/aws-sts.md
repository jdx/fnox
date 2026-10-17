---
description: "Assume an AWS IAM role with fnox and inject temporary AWS credentials into commands, bootstrapped from stored keys, a profile or SSO."
---

# AWS STS

The `aws-sts` lease backend calls [STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) and injects the resulting temporary credentials into `fnox exec`. Use it to keep long-lived AWS keys out of the commands you run.

|              |                                                                   |
| ------------ | ----------------------------------------------------------------- |
| Config type  | `aws-sts`                                                         |
| Produces     | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| Max duration | 12 hours (the role's own maximum session duration may be lower)   |
| Revocation   | None; credentials expire on their own                             |
| Needs        | AWS credentials allowed to call `sts:AssumeRole` on the role      |

## Quick start

```toml
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

```sh
aws sso login --profile my-sso-profile
AWS_PROFILE=my-sso-profile fnox exec -- aws s3 ls
```

The command sees only the temporary credentials, which replace any long-lived AWS keys in its environment.

## Bootstrap credentials

fnox loads the AWS SDK's default credential chain to call AssumeRole. Before creating a lease, it checks that at least one of these is present:

- `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (plus `AWS_SESSION_TOKEN` for temporary keys)
- `AWS_PROFILE`, `AWS_SSO_SESSION`, or the lease's `profile` field
- `~/.aws/credentials` or `~/.aws/config`

The SDK then picks the source, so web identity, container and instance credentials work when one of the checks above also passes.

To keep the long-lived keys in a provider, define secrets with the same names. fnox resolves them for lease creation, and `env = false` keeps them out of the command:

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "op", value = "AWS IAM/access key", env = false }
AWS_SECRET_ACCESS_KEY = { provider = "op", value = "AWS IAM/secret key", env = false }
```

With no stored keys, `fnox lease create -i aws` prompts for them once and caches the resulting lease.

## Configuration

| Field      | Required | Default      | Description                                                           |
| ---------- | -------- | ------------ | --------------------------------------------------------------------- |
| `region`   | Yes      | none         | Region for the STS client.                                            |
| `role_arn` | Yes      | none         | ARN of the role to assume.                                            |
| `profile`  | No       | SDK default  | Profile in `~/.aws/config` used to call STS.                          |
| `endpoint` | No       | AWS endpoint | Custom STS endpoint URL, for example LocalStack.                      |
| `duration` | No       | `"15m"`      | Requested session length, such as `"30m"` or `"1h"`. At most `"12h"`. |

The role session name is the lease label, such as `fnox-exec-aws`, so it appears in CloudTrail.

## Permissions

The calling identity needs `sts:AssumeRole` on `role_arn`, and the role's trust policy must allow that identity. The role's maximum session duration must be at least `duration`.

## Troubleshooting

### AWS credentials not found

None of the bootstrap sources was found. Run `aws sso login`, set `AWS_PROFILE`, or store the access keys as secrets. Under `fnox exec`, the lease is skipped with this warning and the command runs without leased credentials unless a cached lease is still valid.

### AccessDenied or not authorized

The caller cannot assume the role. Check the identity with `aws sts get-caller-identity`, then the role's trust policy and the caller's `sts:AssumeRole` permission.

### Duration longer than the role allows

STS rejects a `duration` above the role's maximum session duration. Lower `duration` or raise the limit on the role.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [AWS Secrets Manager](/providers/aws-sm): store secrets in AWS and read them with the same credentials.
- [Lease commands](/cli/lease): create, list and revoke leases.
