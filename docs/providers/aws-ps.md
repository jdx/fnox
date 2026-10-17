---
description: "Read and write AWS Systems Manager Parameter Store values with fnox: credentials, minimal IAM policy, path prefixes, and role assumption."
---

# AWS Parameter Store

Store values in AWS Systems Manager Parameter Store and keep only their names in `fnox.toml`. The provider reads and writes: `fnox set` stores the value as a `SecureString` parameter.

|                     |                                                   |
| ------------------- | ------------------------------------------------- |
| Config type         | `aws-ps`                                          |
| Storage             | Remote service                                    |
| Writes (`fnox set`) | Yes                                               |
| Requires            | AWS credentials and network access to the AWS API |

## Quick start

With AWS credentials available in your shell, add a provider and store a value through the hidden prompt:

```toml
[providers.ps]
type = "aws-ps"
region = "us-east-1"
prefix = "/myapp/prod/"
```

```sh
fnox set DATABASE_URL --provider ps
```

This writes the parameter `/myapp/prod/DATABASE_URL` and adds the reference to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "ps", value = "DATABASE_URL" }
```

To use a parameter that already exists, write the reference yourself with its name minus the prefix. Then check it:

```sh
fnox provider test ps
fnox exec -- ./start-server.sh
```

## Authentication

The provider authenticates exactly like [AWS Secrets Manager](/providers/aws-sm#configure-aws-credentials): the AWS SDK default credential chain, optionally pinned to a `profile`. The provider's `region` field sets the region for every request; `AWS_REGION` does not override it.

When a request fails because credentials are missing or expired in an interactive terminal, fnox offers to run `aws sso login`. Change that command with [`auth_command`](/reference/configuration#auth-command). For CI, see [CI/CD](/guide/ci).

## Configuration

```toml
[providers.ps]
type = "aws-ps"
region = "us-east-1"
profile = "my-aws-profile" # optional
prefix = "/myapp/prod/"    # optional
```

| Field      | Required | Default       | Description                                                                                      |
| ---------- | -------- | ------------- | ------------------------------------------------------------------------------------------------ |
| `region`   | Yes      |               | AWS region for all requests.                                                                     |
| `profile`  | No       | Default chain | Profile from `~/.aws/config`. Pins the provider to one account without relying on `AWS_PROFILE`. |
| `role_arn` | No       |               | IAM role to assume before every request. See [Assume a role](#assume-a-role).                    |
| `prefix`   | No       |               | Prepended to every parameter name, for reads and for `fnox set`.                                 |
| `endpoint` | No       | AWS endpoint  | Custom endpoint URL, such as `http://localhost:4566` for LocalStack.                             |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

## Reference formats

A secret's `value` is the parameter name. fnox prepends the provider's `prefix` as-is, so include the leading and trailing `/` you need.

| Provider `prefix` | `value`                    | Parameter fnox reads       |
| ----------------- | -------------------------- | -------------------------- |
| (none)            | `/myapp/prod/database/url` | `/myapp/prod/database/url` |
| `/myapp/prod/`    | `database/url`             | `/myapp/prod/database/url` |
| `/myapp/prod`     | `database/url`             | `/myapp/proddatabase/url`  |

fnox requests every parameter with decryption, so `SecureString` values come back as plaintext and `String` values are returned unchanged. A parameter that holds JSON can be narrowed with [`json_path`](/reference/configuration#json-path).

### One provider per path

Path prefixes map well onto environments. Give each environment its own provider instance and select it with a [profile](/guide/profiles):

```toml
[providers.ps]
type = "aws-ps"
region = "us-east-1"
prefix = "/myapp/staging/"

[profiles.production.providers.ps]
type = "aws-ps"
region = "us-east-1"
profile = "prod-account"
prefix = "/myapp/prod/"

[secrets]
DATABASE_URL = { provider = "ps", value = "database/url" }
```

## IAM permissions

fnox calls these Systems Manager actions:

| Operation                                       | Actions                  |
| ----------------------------------------------- | ------------------------ |
| Resolve one secret                              | `ssm:GetParameter`       |
| Resolve several secrets, such as in `fnox exec` | `ssm:GetParameters`      |
| `fnox provider test`                            | `ssm:DescribeParameters` |
| `fnox set`                                      | `ssm:PutParameter`       |

A read-only policy for parameters under `/myapp/`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ssm:DescribeParameters",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["ssm:GetParameter", "ssm:GetParameters"],
      "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/myapp/*"
    }
  ]
}
```

`ssm:DescribeParameters` cannot be scoped to parameter ARNs, so it needs `"Resource": "*"`. To let `fnox set` write, add `ssm:PutParameter` to the second statement.

`fnox set` writes a `SecureString` with the account's default `aws/ssm` key and overwrites an existing parameter of the same name. Reading a `SecureString` encrypted with a customer managed KMS key also needs `kms:Decrypt` on that key.

## Batch reads

When fnox resolves several secrets from one provider, it sends `GetParameters` requests of up to 10 names each, with up to 10 requests in flight. fnox keys that point at the same parameter share one fetch.

## Assume a role

Set `role_arn` to have fnox call `sts:AssumeRole` and use the resulting credentials for every request. The credentials from `profile`, or from the default chain, are the source credentials for that call:

```toml
[providers.ps]
type = "aws-ps"
region = "eu-west-1"
profile = "sso-dev"
role_arn = "arn:aws:iam::123456789012:role/param-reader"
```

The session name is always `fnox`, and the role must trust the source identity for `sts:AssumeRole`. When `endpoint` is set, the AssumeRole call goes to that endpoint too.

## Troubleshooting

### `fnox get` works but `fnox exec` is denied

Resolving several secrets uses `ssm:GetParameters`, a separate action from `ssm:GetParameter`. Grant both.

### Parameter not found

Check the region and the composed name: the provider's `prefix` followed by the secret's `value`, including the `/` between them.

```sh
aws ssm get-parameters-by-path --region us-east-1 --path /myapp/prod/ --recursive --query 'Parameters[].Name'
```

### Credentials expired

Run `aws sso login`, or your profile's equivalent, and retry. `fnox provider test ps` confirms the credentials and region.

## See also

- [AWS Secrets Manager](/providers/aws-sm): larger values, rotation, and batch reads of up to 20 secrets.
- [AWS KMS](/providers/aws-kms): keep ciphertext in `fnox.toml` instead of a remote store.
- [AWS STS](/leases/aws-sts): lease short-lived AWS credentials to commands.
