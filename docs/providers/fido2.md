# FIDO2

The `fido2` provider uses the FIDO2 hmac-secret extension to derive an AES-256-GCM encryption key from a hardware security key. Secrets are encrypted symmetrically — decryption requires the same physical FIDO2 key.

## Why?

The `fido2` provider ties encryption to a physical hardware device using the CTAP2 hmac-secret extension. Any FIDO2-compatible security key that supports hmac-secret can be used (YubiKey 5, SoloKeys, Nitrokey, etc.).

The config is fully portable: move your `fnox.local.toml` to any machine, plug in the same FIDO2 key, and it works.

## Setup

```bash
fnox provider add secure fido2
```

During setup, fnox will:

1. Create a FIDO2 credential with the hmac-secret extension enabled
2. Prompt for PIN if required by the authenticator
3. Generate a random salt for key derivation
4. Verify the key works with a test assertion
5. Store the credential ID, salt, and relying party ID in `fnox.toml`

## Configuration

```toml
[providers.secure]
type = "fido2"
credential_id = "a1b2c3..."  # auto-generated hex credential ID
salt = "d4e5f6..."           # auto-generated hex salt
rp_id = "fnox.secure"        # relying party ID
```

## Usage

Both encrypting and decrypting require the FIDO2 key:

```bash
# Encrypt (requires key touch)
fnox set MY_SECRET "supersecret" --provider secure

# Decrypt (requires key touch)
fnox get MY_SECRET
```

Within a single `fnox exec` invocation, the key is only touched once. The hmac-secret response is cached in memory for the duration of the process.

## With Credential Leases

The `fido2` provider works well with [credential leases](/guide/leases) and the `env = false` secret option:

```toml
[providers.secure]
type = "fido2"
credential_id = "a1b2c3..."
salt = "d4e5f6..."
rp_id = "fnox.secure"

[secrets]
AWS_ACCESS_KEY_ID = { provider = "secure", env = false }
AWS_SECRET_ACCESS_KEY = { provider = "secure", env = false }

[leases.aws]
type = "aws-sts"
role_arn = "arn:aws:iam::123456789012:role/dev-role"
region = "us-east-1"
```

## How It Works

1. **Setup:** A FIDO2 credential is created with hmac-secret extension; credential ID and a random 32-byte salt are stored in config
2. **hmac-secret:** The salt is sent to the authenticator during assertion, which returns a 32-byte HMAC derived from an internal device secret
3. **Key derivation:** HKDF-SHA256 derives a 256-bit AES key from the HMAC response
4. **Encryption:** AES-256-GCM encrypts the secret; output is `base64(nonce || ciphertext || tag)`

The HMAC response is never stored on disk. It exists only in process memory after a key touch.

## Important Notes

::: warning Renaming providers invalidates cached credentials
The provider name is used in key derivation (HKDF context). Renaming a provider (e.g., from `secure` to `my_fido2`) will change the derived encryption key, making all previously encrypted secrets and cached lease credentials undecryptable. If you need to rename, re-encrypt all secrets after renaming.
:::

## Requirements

- A FIDO2-compatible security key with hmac-secret extension support
- Most modern security keys support this: YubiKey 5 series, SoloKeys, Nitrokey FIDO2, Google Titan (v2+)
- PIN may be required depending on your key's configuration

## FIDO2 vs YubiKey Provider

| Feature     | FIDO2             | YubiKey                      |
| ----------- | ----------------- | ---------------------------- |
| Key types   | Any FIDO2 key     | YubiKey only                 |
| Protocol    | CTAP2 hmac-secret | HMAC-SHA1 challenge-response |
| PIN support | Yes               | No                           |
| Key output  | 32 bytes          | 20 bytes                     |
| Slot config | N/A               | Slot 1 or 2                  |

Choose `fido2` if you have any FIDO2-compatible key. Choose `yubikey` if you specifically use YubiKey's HMAC-SHA1 challenge-response (configured via `ykman otp chalresp`).
