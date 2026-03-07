# Age + 2FA

The `age-2fa` provider combines [age encryption](/providers/age) with a second factor (TOTP or YubiKey). The age private key is encrypted with a passphrase derived from the 2FA device, making decryption impossible without the second factor.

::: warning Experimental
This provider is experimental. Enable it with `FNOX_EXPERIMENTAL=true`.
:::

## Why?

Regular age encryption protects secrets at rest, but anyone with access to the age key file can decrypt them. The `age-2fa` provider adds a cryptographically enforced gate: the age private key itself is encrypted with a passphrase derived from your TOTP shared secret or YubiKey HMAC response. No 2FA = no decryption.

This is especially useful for protecting long-lived master credentials (like AWS IAM keys) that are used by [lease backends](/guide/leases) to create short-lived credentials.

## Setup

```bash
# TOTP (Google Authenticator, Authy, etc.)
fnox provider add --type age-2fa --name secure

# YubiKey HMAC-SHA1 challenge-response
fnox provider add --type age-2fa --name secure
```

During setup, fnox will:

1. Generate a new age keypair
2. **TOTP:** Generate a shared secret and display it for your authenticator app, then verify a code
3. **YubiKey:** Prompt you to tap your YubiKey to perform an HMAC-SHA1 challenge-response
4. Encrypt the age private key with a passphrase derived from the 2FA
5. Store the encrypted key at `~/.config/fnox/2fa/<name>.age`
6. Add the provider config (with public key) to `fnox.toml`

## Configuration

```toml
[providers.secure]
type = "age-2fa"
recipients = ["age1..."]  # auto-populated during setup
auth = "totp"             # or "yubikey"
```

## Usage

Encrypting secrets uses the public key only — no 2FA prompt:

```bash
fnox set AWS_ACCESS_KEY_ID "AKIA..." --provider secure
```

Decrypting prompts for 2FA:

```bash
$ fnox get AWS_ACCESS_KEY_ID
TOTP code: 123456
AKIA...
```

Within a single `fnox exec` invocation, the 2FA is only prompted once. The decrypted identity is cached in memory for the duration of the process.

## With Credential Leases

The `age-2fa` provider works well with [credential leases](/guide/leases) and the `env = false` secret option. Store master credentials encrypted with 2FA, and have lease backends use them to create short-lived credentials:

```toml
[providers.secure]
type = "age-2fa"
recipients = ["age1..."]
auth = "totp"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "secure", env = false }
AWS_SECRET_ACCESS_KEY = { provider = "secure", env = false }

[leases.aws]
type = "aws-sts"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
region = "us-east-1"
```

With `env = false`, the master credentials are never injected into subprocess environment variables. They are only used internally by the lease backend to call `sts:AssumeRole`, and the resulting short-lived credentials are what gets injected.

## Auth Methods

### TOTP

Uses a standard TOTP shared secret (RFC 6238). Compatible with any authenticator app (Google Authenticator, Authy, 1Password, etc.).

The shared secret is stored at `~/.config/fnox/2fa/<name>.toml`. The age private key passphrase is derived from the shared secret using HKDF-SHA256 — not from the 6-digit code. The code is only used to verify the user has the authenticator.

### YubiKey

Uses HMAC-SHA1 challenge-response (slot 1 or 2). Requires a YubiKey with HMAC-SHA1 configured on the chosen slot.

A random challenge is stored at `~/.config/fnox/2fa/<name>.toml`. On each decryption, the challenge is sent to the YubiKey and the HMAC response is used as the passphrase.

## Key Files

| File                             | Purpose                                       |
| -------------------------------- | --------------------------------------------- |
| `~/.config/fnox/2fa/<name>.age`  | Encrypted age private key                     |
| `~/.config/fnox/2fa/<name>.toml` | 2FA config (TOTP secret or YubiKey challenge) |

Both files are created with `0600` permissions. The `.age` file cannot be decrypted without the 2FA device. The `.toml` file contains the TOTP shared secret or YubiKey challenge — protect it accordingly.
