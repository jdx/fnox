# Age Encryption

Age is a modern encryption tool that's simple, secure, and works beautifully with SSH keys.

## Quick Start

```bash
# 1. Generate age key
age-keygen -o ~/.config/fnox/age.txt

# 2. Get public key
grep "public key:" ~/.config/fnox/age.txt
# Output: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# 3. Configure fnox
cat >> fnox.toml << 'EOF'
[providers]
age = { type = "age", recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"] }
EOF

# 4. Set private key
export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")

# 5. Encrypt a secret
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider age
```

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

### Option 1: Generate Age Key

```bash
# Create config directory
mkdir -p ~/.config/fnox

# Generate age key
age-keygen -o ~/.config/fnox/age.txt

# View the generated key
cat ~/.config/fnox/age.txt
```

Output:

```
# created: 2024-01-15T10:30:45-08:00
# public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRS
```

### Option 2: Use SSH Key

Age has first-class SSH key support! Use your existing SSH keys:

```bash
# No key generation needed!
# Just use your SSH public key as the recipient
```

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

### Set Decryption Key

#### Using Age Key

```bash
# Export the secret key
export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")

# Add to shell profile
echo 'export FNOX_AGE_KEY=$(cat ~/.config/fnox/age.txt | grep "AGE-SECRET-KEY")' >> ~/.bashrc
```

#### Using SSH Key

```bash
# Point to SSH private key
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519

# Add to shell profile
echo 'export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519' >> ~/.bashrc
```

## Usage

### Encrypt and Store a Secret

```bash
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider age
```

The resulting `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdC..." }  # ← Encrypted, safe to commit!
```

### Decrypt and Get a Secret

```bash
fnox get DATABASE_URL
```

### Run Commands with Secrets

```bash
fnox exec -- npm run dev
```

## SSH Key Support

Age natively supports SSH keys—no conversion needed!

### Supported SSH Key Types

- **`ssh-ed25519`** - Ed25519 keys (recommended, most secure)
- **`ssh-rsa`** - RSA keys (2048-bit minimum, 4096-bit recommended)

### Using SSH Keys

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
Password-protected SSH keys are NOT supported. If your SSH key has a passphrase, you must create a copy without a passphrase for use with fnox/age.
:::

### Get Your SSH Public Key

```bash
# Ed25519 key
cat ~/.ssh/id_ed25519.pub

# RSA key
cat ~/.ssh/id_rsa.pub
```

## Team Workflow

### 1. Collect Public Keys

Each team member shares their public key:

```bash
# Using age key
grep "public key:" ~/.config/fnox/age.txt

# Using SSH key
cat ~/.ssh/id_ed25519.pub
```

### 2. Add All Recipients

```toml
[providers.age]
type = "age"
recipients = [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGQs...",  # alice
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBws...",  # bob
  "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2el..."   # ci-bot
]
```

### 3. Encrypt Secrets

```bash
fnox set DATABASE_URL "postgresql://dev.example.com/db" --provider age
fnox set API_KEY "secret-key" --provider age
```

### 4. Commit to Git

```bash
git add fnox.toml
git commit -m "Add encrypted development secrets"
git push
```

### 5. Everyone Can Decrypt

Each team member sets their private key:

```bash
# Alice (SSH key)
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519

# Bob (SSH key)
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519

# CI bot (age key)
export FNOX_AGE_KEY="AGE-SECRET-KEY-1..."
```

Now everyone can decrypt:

```bash
fnox get DATABASE_URL  # Works for all recipients!
```

## Adding a New Team Member

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
   # Re-encrypt each secret with new recipient list
   fnox set DATABASE_URL "$(fnox get DATABASE_URL)" --provider age
   fnox set API_KEY "$(fnox get API_KEY)" --provider age
   # ... repeat for all secrets
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

## CI/CD Setup

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
   cat ci-age.txt | grep "AGE-SECRET-KEY"
   ```

4. Add to GitHub Secrets as `FNOX_AGE_KEY`

## Pros

- ✅ Secrets live in git (version control, code review)
- ✅ Works offline
- ✅ Zero runtime dependencies (after initial setup)
- ✅ Free forever
- ✅ Works with SSH keys you already have
- ✅ Simple and secure
- ✅ Team-friendly (multiple recipients)

## Cons

- ❌ Key rotation requires re-encrypting all secrets
- ❌ No audit logs
- ❌ No centralized access control
- ❌ Manual key management
- ❌ Adding new team members requires re-encryption

## Troubleshooting

### "no identity matched any of the recipients"

Your private key doesn't match any of the recipients. Check:

```bash
# Verify your public key matches a recipient
cat ~/.config/fnox/age.txt  # Check public key
cat ~/.ssh/id_ed25519.pub   # Check SSH public key

# Compare with fnox.toml recipients
cat fnox.toml | grep recipients
```

### "failed to decrypt"

- Check that `FNOX_AGE_KEY` or `FNOX_AGE_KEY_FILE` is set
- Verify the key file exists and is readable
- Ensure you're using the correct private key

### SSH key not working

- Verify SSH key type is supported (ed25519 or rsa)
- Check that the private key file path is correct
- Ensure the private key is NOT password-protected

## Next Steps

- [Real-World Example](/guide/real-world-example) - Complete project setup with age
- [Team Workflow Guide](/guide/profiles) - Manage team secrets effectively
- [AWS KMS](/providers/aws-kms) - Alternative with AWS-managed keys
