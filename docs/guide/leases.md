# Credential Leases

Credential leases let you vend short-lived credentials from cloud providers like AWS, GCP, Azure, and HashiCorp Vault. Instead of storing long-lived access keys, fnox creates temporary credentials that expire automatically.

## Why Leases?

Long-lived credentials are a security risk. If they leak, an attacker has access until someone rotates them. Leases flip this model: credentials are created on demand, last minutes to hours, and expire on their own.

fnox supports three approaches depending on your security requirements:

1. **Stored master credentials** — keep the long-lived credentials in a provider (keychain, 1Password, etc.) and let fnox handle lease creation automatically
2. **Hardware-protected** — store master credentials encrypted on disk, requiring a physical security key (YubiKey or FIDO2) to decrypt
3. **Prompt-based** — never store master credentials on the machine; paste them in when needed

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

## Approach 2: Hardware-Protected Master Credentials

This approach stores master credentials encrypted on disk with a hardware security key required for decryption. It combines the convenience of Approach 1 (no manual paste step each session) with stronger security — decryption is physically impossible without the key.

fnox supports two hardware provider types:

- **[`yubikey`](/providers/yubikey)** — uses YubiKey HMAC-SHA1 challenge-response. Simple setup, works with any YubiKey that has HMAC-SHA1 configured on a slot.
- **[`fido2`](/providers/fido2)** — uses the FIDO2 hmac-secret extension. Works with any FIDO2-compatible key (YubiKey 5, SoloKeys, Nitrokey, etc.).

Both derive an AES-256-GCM encryption key from the hardware device via HKDF-SHA256. The config is fully portable — move `fnox.local.toml` to any machine with the same key and it works.

::: tip Use fnox.local.toml
Put the provider and secret definitions in `fnox.local.toml` (which is gitignored) and keep only the lease backend config in `fnox.toml`.
:::

### Setup (YubiKey example)

```toml
# fnox.local.toml (gitignored — personal provider + secrets)

[providers.secure]
type = "yubikey"
challenge = "a1b2c3..."  # auto-populated by `fnox provider add`
slot = "2"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "secure", env = false }
AWS_SECRET_ACCESS_KEY = { provider = "secure", env = false }
```

```toml
# fnox.toml (committed — shared lease backend config)

[leases.aws]
type = "aws-sts"
region = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
duration = "1h"
```

For FIDO2, replace the provider section with:

```toml
[providers.secure]
type = "fido2"
credential_id = "a1b2c3..."  # auto-populated by `fnox provider add`
salt = "d4e5f6..."
rp_id = "fnox.secure"
```

Key points:

- `env = false` prevents the master credentials from leaking into subprocess environment variables
- The master credentials are only used internally by the lease backend to create short-lived credentials
- Only the short-lived assumed-role credentials are injected into the subprocess

### Initial setup

```bash
# 1. Create the hardware-backed provider (choose one)
fnox provider add secure yubikey    # YubiKey HMAC-SHA1
fnox provider add secure fido2      # Any FIDO2 key

# 2. Store your master credentials (requires key tap)
fnox set AWS_ACCESS_KEY_ID "AKIA..." --provider secure
fnox set AWS_SECRET_ACCESS_KEY "wJalr..." --provider secure
```

### Daily workflow

```bash
$ fnox exec -- aws s3 ls
Tap your YubiKey...
# → Derives encryption key from hardware device (one tap per session)
# → Decrypts master creds
# → Calls sts:AssumeRole
# → Injects short-lived creds into subprocess
# → Caches lease for reuse
```

The hardware key tap only happens once per `fnox exec` invocation, even when multiple secrets use the same provider. After the lease is cached, subsequent `fnox exec` calls reuse it without prompting until it's close to expiring.

## Approach 3: Prompt-Based (No Stored Credentials)

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

When you start your session, create a lease interactively with `--interactive`:

```bash
$ fnox lease create aws -i
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

When the lease expires, run `fnox lease create aws -i` again and paste fresh credentials from your password manager.

### What `fnox exec` does when credentials are missing

If you run `fnox exec` without having created a lease and without stored master credentials, it skips the lease gracefully:

```
Skipping lease 'aws': AWS credentials not found. Run 'aws sso login' or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.
Run 'fnox lease create aws -i' to set up credentials interactively.
```

The subprocess still runs — just without the lease credentials. This means other secrets and leases that _are_ available will still be injected.

## Supported Backends

| Backend                              | Type           | Max Duration | Revocation              |
| ------------------------------------ | -------------- | ------------ | ----------------------- |
| [AWS STS](/leases/aws-sts)           | `aws-sts`      | 12 hours     | No-op (native TTL)      |
| [GCP IAM](/leases/gcp-iam)           | `gcp-iam`      | 1 hour       | No-op (native TTL)      |
| [Azure Token](/leases/azure-token)   | `azure-token`  | ~1 hour      | No-op (native TTL)      |
| [HashiCorp Vault](/leases/vault)     | `vault`        | 24 hours     | Vault lease revocation  |
| [Cloudflare](/leases/cloudflare)     | `cloudflare`   | 24 hours     | Token deletion          |
| [GitHub App](/leases/github-app)     | `github-app`   | 1 hour       | No-op (native TTL)      |
| [GitHub OAuth](/leases/github-oauth) | `github-oauth` | ~8 hours     | No-op (native TTL)      |
| [Custom Command](/leases/command)    | `command`      | 24 hours     | Optional revoke command |

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

## How Caching Works

fnox caches lease credentials in a per-project ledger file (`~/.local/state/fnox/leases/<hash>.toml`). Cached leases are reused until:

- They're within 5 minutes of expiring
- The backend configuration changes (e.g., you change the role ARN)
- They're explicitly revoked

The ledger automatically prunes entries that have been expired or revoked for more than 24 hours.
