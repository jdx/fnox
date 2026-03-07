# Credential Leases

Credential leases let you vend short-lived credentials from cloud providers like AWS, GCP, Azure, and HashiCorp Vault. Instead of storing long-lived access keys, fnox creates temporary credentials that expire automatically.

::: warning Experimental
Leases are an experimental feature. Enable them with `FNOX_EXPERIMENTAL=true`.
:::

## Why Leases?

Long-lived credentials are a security risk. If they leak, an attacker has access until someone rotates them. Leases flip this model: credentials are created on demand, last minutes to hours, and expire on their own.

fnox supports two approaches depending on your security requirements:

1. **Stored master credentials** — keep the long-lived credentials in a provider (keychain, 1Password, etc.) and let fnox handle lease creation automatically
2. **Prompt-based** — never store master credentials on the machine; paste them in when needed

## Approach 1: Stored Master Credentials

This is the simplest setup. You store the long-lived credentials (e.g., an AWS IAM user's access key) in a fnox provider, and fnox uses them to create short-lived leases automatically via `fnox exec`.

Any provider works here. Choose based on your security requirements:

- **1Password / Bitwarden** — requires authentication (password, biometric, or service account token) to access secrets. Best when you want a gate on every session.
- **OS Keychain** — unlocked at login on most systems. Convenient but offers no additional prompt after login on Linux. macOS may prompt for Touch ID/password on first access.
- **Age / KMS** — encrypted in git. Good for CI and shared team setups.

### Example: AWS STS with 1Password

```toml
# fnox.toml

[providers.op]
type = "1password"
vault = "Development"

# Long-lived IAM credentials stored in 1Password
[secrets]
AWS_ACCESS_KEY_ID = { provider = "op", value = "AWS IAM/access key" }
AWS_SECRET_ACCESS_KEY = { provider = "op", value = "AWS IAM/secret key" }

# Lease: use those credentials to assume a role and get temp creds
[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

```bash
# fnox exec automatically:
# 1. Retrieves AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY from 1Password
#    (prompts to authenticate if needed)
# 2. Calls sts:AssumeRole to get temporary credentials
# 3. Injects AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
#    (the short-lived ones) into your subprocess
fnox exec -- aws s3 ls
```

You can also use `keychain` if you prefer convenience over per-session authentication:

```toml
[providers.keychain]
type = "keychain"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "keychain" }
AWS_SECRET_ACCESS_KEY = { provider = "keychain" }
```

```bash
fnox set AWS_ACCESS_KEY_ID "AKIA..."
fnox set AWS_SECRET_ACCESS_KEY "wJalr..."
```

The temporary credentials are cached in the lease ledger and reused until they're close to expiring (within 5 minutes of expiry). When they expire, fnox automatically creates a new lease.

### Example: GCP IAM

```toml
# fnox.toml

[providers.op]
type = "1password"
vault = "Development"

[secrets]
GOOGLE_APPLICATION_CREDENTIALS = { provider = "op", value = "GCP Service Account/key file", as_file = true }

[leases.gcp]
type = "gcp-iam"
service_account_email = "my-sa@my-project.iam.gserviceaccount.com"
duration = "1h"
```

```bash
# fnox exec writes the key file to a temp path, creates a short-lived OAuth2 token
fnox exec -- gcloud storage ls
```

### Example: Vault

```toml
# fnox.toml

[providers.op]
type = "1password"
vault = "Infrastructure"

[secrets]
VAULT_TOKEN = { provider = "op", value = "Vault/token" }

[leases.vault-aws]
type = "vault"
address = "https://vault.example.com:8200"
secret_path = "aws/creds/my-role"
duration = "1h"

[leases.vault-aws.env_map]
access_key = "AWS_ACCESS_KEY_ID"
secret_key = "AWS_SECRET_ACCESS_KEY"
security_token = "AWS_SESSION_TOKEN"
```

### Example: Azure

```toml
# fnox.toml

[providers.op]
type = "1password"
vault = "Development"

[secrets]
AZURE_CLIENT_ID = { provider = "op", value = "Azure SP/client id" }
AZURE_CLIENT_SECRET = { provider = "op", value = "Azure SP/client secret" }
AZURE_TENANT_ID = { provider = "op", value = "Azure SP/tenant id" }

[leases.azure]
type = "azure-token"
scope = "https://management.azure.com/.default"
```

## Approach 2: Prompt-Based (No Stored Credentials)

This approach is ideal for remote machines, shared servers, or environments where you don't want master credentials persisted to disk at all. Instead of storing credentials in a provider, you paste them in when `fnox lease create` prompts you.

This is useful when:

- You're working on a remote server over SSH
- You keep master credentials in a password manager (1Password, Bitwarden, etc.) on your local machine
- Security policy prohibits storing long-lived credentials on the server
- You want to explicitly control when credentials are provisioned

### Setup

Configure only the lease backend — no secrets or providers needed:

```toml
# fnox.toml

[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

### Daily workflow

When you start your session, create a lease interactively:

```bash
$ fnox lease create aws
AWS credentials not found. Run 'aws sso login' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.

AWS_ACCESS_KEY_ID (AWS access key): AKIA...
AWS_SECRET_ACCESS_KEY (AWS secret key): wJalr...
AWS_SESSION_TOKEN (AWS session token (optional)):

Lease created (expires in 1h0m)

AWS_ACCESS_KEY_ID         ASIA...F3YQ
AWS_SECRET_ACCESS_KEY     wJal...EKEY
AWS_SESSION_TOKEN         FwoG...==
Expires                   2024-01-15T10:00:00+00:00
```

The credentials you paste are used once to call `sts:AssumeRole`, then discarded. Only the short-lived assumed-role credentials are cached in the lease ledger.

Now `fnox exec` uses the cached lease without prompting:

```bash
# Uses the cached lease (no prompting, no stored master creds)
fnox exec -- aws s3 ls
fnox exec -- terraform plan
```

When the lease expires, run `fnox lease create aws` again and paste fresh credentials from your password manager.

### What `fnox exec` does when credentials are missing

If you run `fnox exec` without having created a lease and without stored master credentials, it skips the lease gracefully:

```
Skipping lease 'aws': AWS credentials not found. Run 'aws sso login' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.
Run 'fnox lease create aws' to set up credentials interactively.
```

The subprocess still runs — just without the lease credentials. This means other secrets and leases that _are_ available will still be injected.

## Supported Backends

| Backend                              | Type          | Max Duration | Revocation              |
| ------------------------------------ | ------------- | ------------ | ----------------------- |
| [AWS STS](/cli/lease/create)         | `aws-sts`     | 12 hours     | No-op (native TTL)      |
| [GCP IAM](/cli/lease/create)         | `gcp-iam`     | 1 hour       | No-op (native TTL)      |
| [Azure Token](/cli/lease/create)     | `azure-token` | ~1 hour      | No-op (native TTL)      |
| [HashiCorp Vault](/cli/lease/create) | `vault`       | 24 hours     | Vault lease revocation  |
| [Custom Command](/cli/lease/create)  | `command`     | 24 hours     | Optional revoke command |

## Managing Leases

```bash
# List active leases
fnox lease list --active

# List expired leases
fnox lease list --expired

# Revoke a specific lease
fnox lease revoke <lease-id>

# Clean up all expired leases
fnox lease cleanup
```

## Custom Command Backend

For systems not natively supported, use the `command` backend to run any script that outputs JSON credentials:

```toml
[leases.custom]
type = "command"
create_command = "./scripts/get-creds.sh"
revoke_command = "./scripts/revoke-creds.sh"  # optional
duration = "1h"
```

Your script receives `FNOX_LEASE_DURATION` (in seconds) and `FNOX_LEASE_LABEL` as environment variables, and must output JSON on stdout:

```json
{
  "credentials": {
    "MY_TOKEN": "tok-abc123",
    "MY_SECRET": "sec-xyz789"
  },
  "expires_at": "2024-01-15T10:00:00Z",
  "lease_id": "my-custom-lease-1"
}
```

The revoke script receives `FNOX_LEASE_ID` as an environment variable.

## How Caching Works

fnox caches lease credentials in a per-project ledger file (`~/.config/fnox/leases/<hash>.toml`). Cached leases are reused until:

- They're within 5 minutes of expiring
- The backend configuration changes (e.g., you change the role ARN)
- They're explicitly revoked

The ledger automatically prunes entries that have been expired or revoked for more than 24 hours.
