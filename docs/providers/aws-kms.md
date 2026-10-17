---
description: "Encrypt values in fnox.toml with an AWS KMS key. Configure credentials, an assumed role, the minimal IAM policy, and key migration."
---

# AWS KMS

The `aws-kms` provider encrypts values into `fnox.toml` with an AWS Key Management Service key. The ciphertext lives in your config, but both `fnox set` and every decryption call the KMS API.

|                     |                                           |
| ------------------- | ----------------------------------------- |
| Config type         | `aws-kms`                                 |
| Storage             | Encrypted in config                       |
| Writes (`fnox set`) | Yes                                       |
| Requires            | AWS credentials and network access to KMS |

Use `aws-kms` to keep encrypted secrets in git under an AWS-managed key. To keep values out of git entirely, use [AWS Secrets Manager](/providers/aws-sm) or [AWS Parameter Store](/providers/aws-ps).

## Quick start

Create a symmetric encryption key and give it an alias, or use an existing key:

```sh
KEY_ID=$(aws kms create-key --description "fnox secrets encryption" --query KeyMetadata.KeyId --output text)
aws kms create-alias --alias-name alias/fnox --target-key-id "$KEY_ID"
```

Add the provider with the key's ID, ARN, or alias:

```toml
[providers.kms]
type = "aws-kms"
key_id = "alias/fnox"
region = "us-east-1"
```

Store a value through the hidden prompt, then use it:

```sh
fnox set DATABASE_URL --provider kms
fnox provider test kms
fnox exec -- npm start
```

## Authentication

fnox uses the AWS SDK's [default credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html): environment variables such as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, SSO and shared config files, and container or instance roles. Set `profile` to pick a named profile for this provider only.

### Local development

Sign in with your usual AWS CLI method. When credentials have expired in an interactive terminal, fnox offers to run `aws sso login`; override it with [`auth_command`](/reference/configuration#auth-command).

### CI

Prefer short-lived credentials from your CI platform's OIDC integration, such as `aws-actions/configure-aws-credentials` on GitHub Actions. The SDK picks them up from the environment. See [CI/CD](/guide/ci).

### Assume a role

With `role_arn` set, fnox calls `sts:AssumeRole` with the credentials from `profile` (or the default chain) and uses the role's credentials for KMS. This covers an SSO profile in one account and a key-holding role in another:

```toml
[providers.kms]
type = "aws-kms"
key_id = "alias/fnox"
region = "eu-west-1"
profile = "sso-dev"
role_arn = "arn:aws:iam::123456789012:role/kms-user"
```

## Configuration

| Field      | Required | Default       | Description                                                                                              |
| ---------- | -------- | ------------- | -------------------------------------------------------------------------------------------------------- |
| `key_id`   | Yes      | None          | Key ID (`1234abcd-...`), key ARN, or alias (`alias/my-key`).                                             |
| `region`   | Yes      | None          | AWS region of the key.                                                                                   |
| `profile`  | No       | Default chain | AWS CLI profile name from `~/.aws/config`.                                                               |
| `role_arn` | No       | None          | IAM role to assume before calling KMS. Must have the form `arn:aws:iam::<12-digit-account>:role/<name>`. |
| `endpoint` | No       | AWS endpoint  | Custom endpoint URL, such as `http://localhost:4566` for LocalStack. Also used for the AssumeRole call.  |

All fields accept `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

## How values are stored

`fnox set` calls KMS `Encrypt` with `key_id` and stores the base64-encoded ciphertext blob as the secret's `value`. Decryption calls KMS `Decrypt` with the same `key_id`:

```toml
[secrets]
DATABASE_URL = { provider = "kms", value = "AQICAHhw..." } # ciphertext, abbreviated
```

KMS `Encrypt` accepts up to 4 KB of plaintext per value. fnox decrypts up to 100 values concurrently.

## Permissions

The identity needs these actions on the key. `kms:DescribeKey` is used only by `fnox provider test`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"
    }
  ]
}
```

Readers who never run `fnox set` need only `kms:Decrypt`. The key policy must also allow the identity.

## Move to another key

Rotating key material within the same KMS key needs no change in fnox. Switching to a different key ID does: fnox passes `key_id` when decrypting, so changing it before migrating values prevents the old ciphertext from decrypting.

Keep the old provider configured and add a second provider for the new key. Resolve each value through the old definition and store it with the new provider:

```sh
fnox get DATABASE_URL | fnox set DATABASE_URL --provider new-kms
```

Repeat for the affected secrets and profiles, verify access, then remove the old provider. Rotate the underlying application secret separately if its plaintext may have been exposed.

## Troubleshooting

### `AccessDenied` on Encrypt or Decrypt

Check the IAM policy and the key policy for the action in the error, and confirm which identity fnox uses:

```sh
aws sts get-caller-identity --profile sso-dev
```

### `NotFoundException`

The key ID, ARN, or alias does not exist in the configured `region`, or the identity cannot see it. Check with `aws kms describe-key --key-id alias/fnox --region us-east-1`.

### No credentials

Run `aws sso login` (or your usual sign-in), or set `AWS_PROFILE` or the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` pair for the fnox process.

## See also

- [AWS Secrets Manager](/providers/aws-sm): store values in AWS instead of in config.
- [AWS STS lease](/leases/aws-sts): mint short-lived AWS credentials for your commands.
- [age](/providers/age): encryption in config without a cloud dependency.
