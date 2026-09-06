---
description: "Encrypt secrets in fnox.toml with age recipients, SSH keys, or plugins. Configure identities and share access with teammates."
---

# Age encryption

The `age` provider encrypts values into `fnox.toml`. Decryption uses an age identity, a supported SSH private key, or an age plugin. Standard age keys work offline and do not require a cloud account.

## Quick start

Follow the [age quick start](/guide/quick-start) for a complete setup. If you already have a key and a configured provider:

```sh
fnox set DATABASE_URL --provider age
fnox check --all
fnox exec -- npm start
```

Omitting the value from `fnox set` prompts with hidden input. Never paste a private key into `recipients`: that field takes public recipients only.

## Installation

Install the age CLI:

```bash
# macOS
brew install age

# Linux (Ubuntu/Debian)
sudo apt install age

# Or download from https://github.com/FiloSottile/age/releases
```

## Setup

### Option 1: generate age key

```bash
# Create config directory
mkdir -p ~/.config/fnox

# Generate age key
age-keygen -o ~/.config/fnox/age.txt

# Print only the public recipient
age-keygen -y ~/.config/fnox/age.txt
```

Output:

```text
age1...
```

### Option 2: use SSH key

Age has first-class SSH key support — no key generation needed. Your existing SSH public key becomes the recipient and your private key decrypts; see [SSH Key Support](#ssh-key-support) below.

## Configuration

Add age provider to `fnox.toml`:

```toml
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }
```

Or with SSH key:

```toml
[providers]
age = { type = "age", recipients = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQs8..."] }
```

Or with an explicit identity file:

```toml
[providers]
age = { type = "age", recipients = ["age1..."], key_file = "./age.txt" }
```

Relative `key_file` paths are resolved from the config file that declares the provider. Paths beginning with `~` expand to your home directory, and absolute paths are used unchanged.

Or store the age identity in another provider, such as the OS keychain:

```toml
[providers]
keychain = { type = "keychain", service = "fnox" }
age = { type = "age", recipients = ["age1..."], identity = { provider = "keychain", value = "age-key" } }
```

### Set decryption key {#set-decryption-key}

fnox selects an identity in this order:

1. `FNOX_AGE_KEY` (inline identity contents).
2. The provider's `identity` reference.
3. The provider's `key_file`.
4. The key-file setting (`FNOX_AGE_KEY_FILE` or the deprecated CLI flag).
5. `age.txt` in the fnox configuration directory.

For local use, prefer `key_file` or the default file. `FNOX_AGE_KEY` is useful when CI supplies the identity directly. An exported inline key overrides the provider-specific settings.

#### Using age key

```bash
# Optional when the key is already in the default location
export FNOX_AGE_KEY_FILE=~/.config/fnox/age.txt
```

#### Using SSH key

```bash
# Point to SSH private key
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519

# Add to shell profile
echo 'export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519' >> ~/.bashrc
```

## Usage

### Encrypt and store a secret

```bash
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider age
```

The resulting `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }  # ← Encrypted, safe to commit!
```

### Decrypt and get a secret

```bash
fnox get DATABASE_URL
```

### Run commands with secrets

```bash
fnox exec -- npm run dev
```

## SSH key support

Use a supported SSH public key as a recipient and the matching private key for decryption.

### Supported SSH key types

- **`ssh-ed25519`** - Ed25519 keys
- **`ssh-rsa`** - RSA keys (2048-bit minimum, 4096-bit recommended)

### Using SSH keys

```toml
[providers.age]
type = "age"
recipients = [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQs8YqSC... alice@example.com",
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC5... bob@example.com"
]
```

Set decryption key:

```bash
# Point to your SSH private key
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519
```

::: warning Password-Protected SSH Keys
Password-protected SSH keys are not supported by this integration. Generate a dedicated age identity or use a supported age plugin instead of removing the passphrase from your SSH key.
:::

### Get your SSH public key

```bash
# Ed25519 key
cat ~/.ssh/id_ed25519.pub

# RSA key
cat ~/.ssh/id_rsa.pub
```

## Plugin support

Age plugins extend age with hardware-backed and alternative keys. fnox supports any [age plugin](https://github.com/FiloSottile/awesome-age#plugins), for example [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) (YubiKey / PIV) or [age-plugin-se](https://github.com/remko/age-plugin-se) (Apple's Secure Enclave).

Plugin recipients usually carry the plugin name in their prefix
(`age1yubikey1...`), though not always — current age-plugin-tpm releases
produce `age1tag1...` recipients, for example.

```toml
[providers.age]
type = "age"
recipients = ["age1yubikey1qwla8v7cu3mx6mp79asgrh5ad2h52flwln7c66ydcyy50lg5uh0gxh4kmaz"]
```

Refer to each plugin's docs for setup instructions. The sync guide also has
full [hardware-backed decryption](/guide/sync#hardware-backed-decryption)
walkthroughs for Secure Enclave, YubiKey, TPM, and FIDO2.

## Team workflow

### 1. Collect public keys

Each team member shares their public key:

```bash
# Using age key
grep "public key:" ~/.config/fnox/age.txt

# Using SSH key
cat ~/.ssh/id_ed25519.pub
```

### 2. Add all recipients

```toml
[providers.age]
type = "age"
recipients = [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQs...",  # alice
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBws...",  # bob
  "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2el..."   # ci-bot
]
```

### 3. Encrypt secrets

```bash
fnox set DATABASE_URL "postgresql://dev.example.com/db" --provider age
fnox set API_KEY --provider age
```

### 4. Commit to git

```bash
git add fnox.toml
git commit -m "Add encrypted development secrets"
git push
```

### 5. Decrypt with a matching identity

Each team member sets their private key:

```bash
# Alice (SSH key)
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519

# Bob (SSH key)
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519

# CI bot (age key)
export FNOX_AGE_KEY="AGE-SECRET-KEY-1..."
```

A teammate whose public recipient was included when the secret was encrypted can now decrypt:

```bash
fnox get DATABASE_URL  # Works for all recipients!
```

## Adding a new team member

1. **New member generates/shares public key**:

   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```

2. **Admin adds to recipients**:

   ```toml
   [providers.age]
   type = "age"
   recipients = [
     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQs...",  # alice
     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBws...",  # bob
     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIXyz..."   # charlie (NEW)
   ]
   ```

3. **Re-encrypt all secrets** (necessary for new recipient):

   ```bash
   fnox reencrypt -p age
   ```

   Use `--dry-run` to preview what would be re-encrypted:

   ```bash
   fnox reencrypt -p age --dry-run
   ```

   For multiple profiles:

   ```bash
   fnox reencrypt -p age -P default -f
   fnox reencrypt -p age -P staging -f
   fnox reencrypt -p age -P prod -f
   ```

4. **Commit and push**:

   ```bash
   git add fnox.toml
   git commit -m "Add charlie to age recipients"
   git push
   ```

5. **New member pulls and decrypts**:

   ```bash
   git pull
   export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519
   fnox get DATABASE_URL  # Works!
   ```

## CI/CD setup

### GitHub Actions

```yaml
name: CI
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup fnox age key
        env:
          FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
        run: |
          # Key is already set via environment variable
          echo "Age key configured"

      - name: Run tests
        run: |
          fnox exec -- npm test
```

**Setting up the GitHub Secret:**

1. Generate a dedicated CI age key:

   ```bash
   age-keygen -o ci-age.txt
   ```

2. Add CI public key to `fnox.toml` recipients

3. Copy the secret key:

   ```bash
   grep "AGE-SECRET-KEY" ci-age.txt
   ```

4. Add to GitHub Secrets as `FNOX_AGE_KEY`

## Usage notes

Age decrypts locally with a matching identity. Changing recipients does not update existing ciphertext: run `fnox reencrypt` for each affected profile. Removing a recipient cannot revoke that person's access to old ciphertext in git history; rotate the underlying secret if access must end.

## Troubleshooting

### "no identity matched any of the recipients"

Your private key doesn't match any of the recipients. Check:

```bash
# Verify your public key matches a recipient
cat ~/.config/fnox/age.txt  # Check public key
cat ~/.ssh/id_ed25519.pub   # Check SSH public key

# Compare with fnox.toml recipients
grep recipients fnox.toml
```

### "failed to decrypt"

- Check that `FNOX_AGE_KEY` or `FNOX_AGE_KEY_FILE` is set, or that the default key file `~/.config/fnox/age.txt` exists
- Verify the key file exists and is readable
- Ensure you're using the correct private key

### SSH key not working

- Verify SSH key type is supported (ed25519 or rsa)
- Check that the private key file path is correct
- Ensure the private key is NOT password-protected

## Next steps

- [Real-World Example](/guide/real-world-example) - Complete project setup with age
- [Profiles](/guide/profiles) - Multi-environment configuration
- [AWS KMS](/providers/aws-kms) - Alternative with AWS-managed keys
