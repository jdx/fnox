---
description: "Read and write AWS Secrets Manager secrets with fnox: credentials, minimal IAM policy, name prefixes, role assumption, and JSON fields."
---

# AWS Secrets Manager

Store secrets in AWS Secrets Manager and keep only their names in `fnox.toml`. The provider reads and writes: `fnox set` creates or updates the secret in AWS.

|                     |                                                   |
| ------------------- | ------------------------------------------------- |
| Config type         | `aws-sm`                                          |
| Storage             | Remote service                                    |
| Writes (`fnox set`) | Yes                                               |
| Requires            | AWS credentials and network access to the AWS API |

## Quick start

With AWS credentials available in your shell, add a provider and store a value through the hidden prompt:

```toml
[providers.sm]
type = "aws-sm"
region = "us-east-1"
prefix = "myapp/"
```

```sh
fnox set DATABASE_URL --provider sm
```

This creates the secret `myapp/DATABASE_URL` in AWS and adds the reference to `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "sm", value = "DATABASE_URL" }
```

To use a secret that already exists, write the reference yourself with the secret's name minus the prefix. Then check it:

```sh
fnox provider test sm
fnox exec -- ./start-server.sh
```

## Authentication {#configure-aws-credentials}

fnox uses the AWS SDK default credential chain, so credentials that work for the `aws` CLI work here:

- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`.
- A profile from `~/.aws/config`, including SSO profiles, selected by `AWS_PROFILE` or the provider's `profile` field.
- Web identity tokens (`AWS_WEB_IDENTITY_TOKEN_FILE` with `AWS_ROLE_ARN`), as used by EKS and GitHub Actions OIDC.
- Container and EC2 instance credentials.

The provider's `region` field sets the region for every request; `AWS_REGION` does not override it.

When a request fails because credentials are missing or expired in an interactive terminal, fnox offers to run `aws sso login`. Change that command with [`auth_command`](/reference/configuration#auth-command).

### CI

Give the job an AWS identity before fnox runs. In GitHub Actions, OIDC avoids long-lived keys:

```yaml
permissions:
  id-token: write # lets GitHub issue the OIDC token
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/ci-secrets-reader
      aws-region: us-east-1
  - run: fnox exec -- ./deploy.sh
```

See [CI/CD](/guide/ci) for non-interactive settings.

## Configuration

```toml
[providers.sm]
type = "aws-sm"
region = "us-east-1"
profile = "my-aws-profile" # optional
prefix = "myapp/"          # optional
```

| Field      | Required | Default       | Description                                                                                      |
| ---------- | -------- | ------------- | ------------------------------------------------------------------------------------------------ |
| `region`   | Yes      |               | AWS region for all requests.                                                                     |
| `profile`  | No       | Default chain | Profile from `~/.aws/config`. Pins the provider to one account without relying on `AWS_PROFILE`. |
| `role_arn` | No       |               | IAM role to assume before every request. See [Assume a role](#assume-a-role).                    |
| `prefix`   | No       |               | Prepended to every secret name, for reads and for `fnox set`.                                    |
| `endpoint` | No       | AWS endpoint  | Custom endpoint URL, such as `http://localhost:4566` for LocalStack.                             |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

## Reference formats

A secret's `value` is the Secrets Manager secret name. fnox prepends the provider's `prefix`.

| Provider `prefix` | `value`              | Secret fnox reads          |
| ----------------- | -------------------- | -------------------------- |
| (none)            | `myapp/database-url` | `myapp/database-url`       |
| `myapp/`          | `database-url`       | `myapp/database-url`       |
| `myapp/`          | `myapp/database-url` | `myapp/myapp/database-url` |

Use secret names, not ARNs: the prefix is applied to every value, and batch reads match results by name.

fnox reads the `SecretString` of the current version. Binary secrets are not supported.

### JSON fields

When a secret holds a JSON object, select one field with [`json_path`](/reference/configuration#json-path):

```toml
[secrets]
DB_CREDENTIALS = { provider = "sm", value = "db-credentials" } # whole JSON string
DB_PASSWORD = { provider = "sm", value = "db-credentials", json_path = "password" }
DB_HOST = { provider = "sm", value = "config", json_path = "database.host" } # nested key
DB_CACHE_KEY = { provider = "sm", value = "config", json_path = 'database.cache\.key' } # key containing a dot
```

Escape a literal dot in a key name as `\.`. In TOML, use a literal string (`'\.'`) or escape the backslash (`"\\."`).

## IAM permissions

fnox calls these Secrets Manager actions:

| Operation                                       | Actions                                                                                    |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Resolve one secret                              | `secretsmanager:GetSecretValue`                                                            |
| Resolve several secrets, such as in `fnox exec` | `secretsmanager:BatchGetSecretValue`, plus `GetSecretValue` on each secret                 |
| `fnox provider test`                            | `secretsmanager:ListSecrets`                                                               |
| `fnox set`                                      | `secretsmanager:PutSecretValue`, plus `secretsmanager:CreateSecret` when the secret is new |

A read-only policy for secrets under `myapp/`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:BatchGetSecretValue", "secretsmanager:ListSecrets"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:myapp/*"
    }
  ]
}
```

`BatchGetSecretValue` and `ListSecrets` cannot be scoped to secret ARNs, so they need `"Resource": "*"`. To let `fnox set` write, add `secretsmanager:PutSecretValue` and `secretsmanager:CreateSecret` to the second statement. A secret encrypted with a customer managed KMS key also needs `kms:Decrypt` on that key.

## Batch reads

When fnox resolves several secrets from one provider, it sends `BatchGetSecretValue` requests of up to 20 secrets each. fnox keys that point at the same secret, for example with different `json_path` values, share one fetch.

## Assume a role

Set `role_arn` to have fnox call `sts:AssumeRole` and use the resulting credentials for every request. The credentials from `profile`, or from the default chain, are the source credentials for that call, so an SSO profile plus a cross-account role works in one step:

```toml
[providers.sm]
type = "aws-sm"
region = "eu-west-1"
profile = "sso-dev"
role_arn = "arn:aws:iam::123456789012:role/secrets-reader"
```

The session name is always `fnox`, and the role must trust the source identity for `sts:AssumeRole`. If your `~/.aws/config` profile already declares `role_arn` and `source_profile`, the AWS SDK assumes that role itself and you do not need this field. When `endpoint` is set, the AssumeRole call goes to that endpoint too.

## Troubleshooting

### `fnox get` works but `fnox exec` is denied

Resolving several secrets uses `BatchGetSecretValue`, which a policy that grants only `GetSecretValue` does not cover. Add it with `"Resource": "*"`.

### Secret not found

Check the region and the composed name: the provider's `prefix` followed by the secret's `value`. A value that repeats the prefix reads a different secret.

```sh
aws secretsmanager describe-secret --region us-east-1 --secret-id myapp/database-url
```

### Secret has no string value

The secret holds binary data. fnox reads only string secrets.

### Credentials expired

Run `aws sso login`, or your profile's equivalent, and retry. `fnox provider test sm` confirms the credentials and region.

## See also

- [AWS Parameter Store](/providers/aws-ps): hierarchical parameters with the same credential handling.
- [AWS KMS](/providers/aws-kms): keep ciphertext in `fnox.toml` instead of a remote store.
- [AWS STS](/leases/aws-sts): lease short-lived AWS credentials to commands.
- [Connect a vault](/guide/existing-vault): add a local cache for offline reads.
