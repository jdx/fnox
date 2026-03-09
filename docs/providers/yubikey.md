# YubiKey

The `yubikey` provider uses YubiKey HMAC-SHA1 challenge-response to derive an AES-256-GCM encryption key. Secrets are encrypted symmetrically — decryption requires the same physical YubiKey.

## Why?

Regular age encryption protects secrets at rest, but anyone with access to the key file can decrypt them. The `yubikey` provider ties encryption to a physical hardware device. No YubiKey = no decryption.

The config is fully portable: move your `fnox.local.toml` to any machine, plug in the same YubiKey, and it works.

This is especially useful for protecting long-lived master credentials (like AWS IAM keys) that are used by [lease backends](/guide/leases) to create short-lived credentials.

## Setup

```bash
fnox provider add secure yubikey
```

During setup, fnox will:

1. Prompt for the YubiKey slot (1 or 2, default: 2)
2. Generate a random challenge
3. Verify the YubiKey works with an HMAC-SHA1 challenge-response
4. Store the challenge and slot in `fnox.toml`

## Configuration

```toml
[providers.secure]
type = "yubikey"
challenge = "a1b2c3..."  # auto-generated hex challenge
slot = "2"               # YubiKey slot (1 or 2)
```

## Usage

Both encrypting and decrypting require the YubiKey:

```bash
# Encrypt (requires YubiKey tap)
fnox set MY_SECRET "supersecret" --provider secure

# Decrypt (requires YubiKey tap)
fnox get MY_SECRET
```

Within a single `fnox exec` invocation, the YubiKey is only tapped once. The HMAC response is cached in memory for the duration of the process.

## With Credential Leases

The `yubikey` provider works well with [credential leases](/guide/leases) and the `env = false` secret option. Store master credentials encrypted with the YubiKey, and have lease backends use them to create short-lived credentials:

```toml
[providers.secure]
type = "yubikey"
challenge = "a1b2c3..."
slot = "2"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "secure", env = false }
AWS_SECRET_ACCESS_KEY = { provider = "secure", env = false }

[leases.aws]
type = "aws-sts"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
region = "us-east-1"
```

With `env = false`, the master credentials are never injected into subprocess environment variables. They are only used internally by the lease backend to call `sts:AssumeRole`, and the resulting short-lived credentials are what gets injected.

## How It Works

1. **Setup:** A random 32-byte challenge is generated and stored in config
2. **HMAC-SHA1:** The challenge is sent to the YubiKey, which returns a 20-byte HMAC response
3. **Key derivation:** HKDF-SHA256 derives a 256-bit AES key from the HMAC response
4. **Encryption:** AES-256-GCM encrypts the secret; output is `base64(nonce || ciphertext || tag)`

The HMAC response is never stored on disk. It exists only in process memory after a YubiKey tap.

## Important Notes

::: warning Renaming providers invalidates cached credentials
The provider name is used in key derivation (HKDF context). Renaming a provider (e.g., from `secure` to `my_yubikey`) will change the derived encryption key, making all previously encrypted secrets and cached lease credentials undecryptable. If you need to rename, re-encrypt all secrets after renaming.
:::

## Requirements

- A YubiKey with HMAC-SHA1 challenge-response configured on slot 1 or 2
- Configure HMAC-SHA1 using the [YubiKey Manager](https://www.yubico.com/support/download/yubikey-manager/) or `ykman otp chalresp` command
