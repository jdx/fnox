# password-store

Integrate with the standard Unix password manager (`pass`) to store and retrieve secrets from GPG-encrypted files.

## Quick Start

```bash
# 1. Install pass (password-store)
brew install pass  # macOS
# OR: sudo apt install pass  # Linux

# 2. Initialize password-store (one-time setup)
pass init <your-gpg-key-id>

# 3. Configure fnox provider
cat >> fnox.toml << 'EOF'
[providers]
pass = { type = "password-store", prefix = "fnox/" }
EOF

# 4. Store a secret in password-store
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider pass

# 5. Retrieve from password-store
fnox get DATABASE_URL

# 6. Use in shell commands
fnox exec -- npm start
```

## Prerequisites

- GPG (GNU Privacy Guard) installed and configured
- GPG key pair generated
- [pass](https://www.passwordstore.org/) (password-store) installed

## Installation

### Install GPG

::: code-group

```bash [macOS]
brew install gnupg
```

```bash [Ubuntu/Debian]
sudo apt install gnupg
```

```bash [Fedora/RHEL]
sudo dnf install gnupg2
```

```bash [Arch]
sudo pacman -S gnupg
```

:::

### Install password-store

::: code-group

```bash [macOS]
brew install pass
```

```bash [Ubuntu/Debian]
sudo apt install pass
```

```bash [Fedora/RHEL]
sudo dnf install pass
```

```bash [Arch]
sudo pacman -S pass
```

:::

## Setup

### 1. Generate GPG Key (if needed)

If you don't have a GPG key:

```bash
# Generate a new GPG key
gpg --full-generate-key

# List your GPG keys
gpg --list-secret-keys --keyid-format LONG
```

Note your key ID from the output (the long hex string after `sec`).

### 2. Initialize password-store

```bash
# Initialize with your GPG key ID
pass init <your-gpg-key-id>

# Example:
pass init 3AA5C34371567BD2

# Or with email:
pass init user@example.com
```

This creates `~/.password-store/` directory.

### 3. (Optional) Configure Custom Store Directory

```bash
# Set custom store location
export PASSWORD_STORE_DIR=/path/to/custom/store

# Or configure in fnox
cat >> fnox.toml << 'EOF'
[providers]
pass = { type = "password-store", store_dir = "/path/to/custom/store" }
EOF
```

## Configuration

Add password-store provider to `fnox.toml`:

```toml
[providers]
pass = { type = "password-store", prefix = "fnox/" }
```

### Configuration Options

```toml
[providers.pass]
type = "password-store"
prefix = "fnox/"  # Optional: prepend to all secret paths (default: none)
store_dir = "/custom/path"  # Optional: custom store location (default: ~/.password-store)
```

## How It Works

1. **Storage:** Secrets are stored as GPG-encrypted files in `~/.password-store/` (or custom location)
2. **Config:** `fnox.toml` contains only the secret path/reference (not the actual value)
3. **Encryption:** When you run `fnox set`, it calls `pass insert` to GPG-encrypt and store the secret
4. **Retrieval:** When you run `fnox get`, it calls `pass show` to decrypt and retrieve the secret
5. **Prefix:** If configured, the prefix is prepended to the secret path (e.g., `value = "api-key"` becomes `fnox/api-key`)
6. **Hierarchy:** Supports nested paths for organizing secrets (e.g., `work/github/token`)

## Usage

### Store a Secret

```bash
# Simple secret
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider pass

# With nested path (using --key-name)
fnox set DB_PASSWORD "secret123" --provider pass --key-name "database/production"

# With prefix configured, "database/production" becomes "fnox/database/production"
```

Your `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "pass", value = "database-url" }  # Stored at fnox/database-url
DB_PASSWORD = { provider = "pass", value = "database/production" }  # Stored at fnox/database/production
```

### Retrieve a Secret

```bash
fnox get DATABASE_URL
```

### Run Commands with Secrets

```bash
fnox exec -- npm run dev
```

### List Secrets in password-store

```bash
# View password-store structure
pass

# Or with specific prefix
pass ls fnox/
```

## Reference Formats

```toml
[secrets]
# Simple name (with prefix)
MY_SECRET = { provider = "pass", value = "api-key" }
# → Stored at: fnox/api-key.gpg

# Nested path
DB_PASSWORD = { provider = "pass", value = "database/production" }
# → Stored at: fnox/database/production.gpg

# Without prefix in config
API_TOKEN = { provider = "pass", value = "tokens/github" }
# → Stored at: tokens/github.gpg (no prefix)
```

## Git Integration

password-store has built-in git support:

```bash
# Initialize git repo in password-store
pass git init

# Add remote
pass git remote add origin https://github.com/username/password-store.git

# Configure git
pass git config user.name "Your Name"
pass git config user.email "you@example.com"

# Changes are automatically committed
fnox set API_KEY "new-key" --provider pass  # Auto-commits!

# Push changes
pass git push
```

## Team Workflow

### Option 1: Shared GPG Key

Share a single GPG key with the team (less secure, simpler):

```bash
# Export GPG key
gpg --export-secret-keys <key-id> > team-key.gpg

# Team members import
gpg --import team-key.gpg
pass init <key-id>
```

### Option 2: Multiple Recipients (Recommended)

Encrypt for multiple team members (more secure):

```bash
# Re-init with multiple GPG keys
pass init <key-id-1> <key-id-2> <key-id-3>

# Or add recipients later
cd ~/.password-store
echo "<key-id-1> <key-id-2> <key-id-3>" > .gpg-id
pass init -p / $(cat .gpg-id)
```

Then push to shared git repository:

```bash
pass git push
```

Team members pull:

```bash
git clone https://github.com/team/password-store.git ~/.password-store
pass  # Verify they can decrypt
```

## Multi-Environment Example

```toml
# Development (password-store)
[providers]
pass = { type = "password-store", prefix = "fnox/dev/" }

[secrets]
DATABASE_URL = { provider = "pass", value = "database-url" }  # fnox/dev/database-url

# Production (AWS Secrets Manager)
[profiles.production.providers]
aws = { type = "aws-sm", region = "us-east-1" }

[profiles.production.secrets]
DATABASE_URL = { provider = "aws", value = "database-url" }
```

## Bootstrap Pattern

Store provider tokens in password-store:

```toml
[providers]
pass = { type = "password-store", prefix = "tokens/" }
aws = { type = "aws-sm", region = "us-east-1" }

[secrets]
AWS_ACCESS_KEY_ID = { provider = "pass", value = "aws-access-key" }
AWS_SECRET_ACCESS_KEY = { provider = "pass", value = "aws-secret-key" }
DATABASE_URL = { provider = "aws", value = "db-url" }  # Retrieved from AWS
```

Bootstrap:

```bash
export AWS_ACCESS_KEY_ID=$(fnox get AWS_ACCESS_KEY_ID)
export AWS_SECRET_ACCESS_KEY=$(fnox get AWS_SECRET_ACCESS_KEY)
fnox exec -- ./deploy.sh  # Now can access AWS secrets
```

## Multiline Secrets

password-store fully supports multiline secrets:

```bash
# Store multiline secret
fnox set SSH_PRIVATE_KEY "$(cat ~/.ssh/id_rsa)" --provider pass

# Or using heredoc with pass directly
pass insert -m work/ssh-key <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
EOF
```

## Environment Variables

password-store respects standard environment variables:

```bash
# Custom store location
export PASSWORD_STORE_DIR=/path/to/store
export FNOX_PASSWORD_STORE_DIR=/path/to/store  # fnox-specific

# GPG options
export PASSWORD_STORE_GPG_OPTS="--no-throw-keyids"
export FNOX_PASSWORD_STORE_GPG_OPTS="--armor"  # fnox-specific
```

## Sync Across Machines

### Using Git

```bash
# Machine 1: Push
pass git push

# Machine 2: Pull
cd ~/.password-store
git pull
```

### Using Sync Service

password-store is just a directory of GPG files. Sync with:

- **Dropbox:** Symlink `~/.password-store` to Dropbox
- **Syncthing:** Sync the directory
- **rsync:** Manual sync between machines

## Pros

- ✅ Local-first: No cloud service required
- ✅ Open standard: Uses GPG encryption (widely trusted)
- ✅ Git-friendly: Encrypted files can be safely committed to version control
- ✅ Portable: Easy to sync across machines using git
- ✅ Transparent: Files are just GPG-encrypted text files
- ✅ Ecosystem: Many third-party tools and integrations exist
- ✅ Free and open source
- ✅ Team support: Multiple GPG recipients
- ✅ Hierarchical organization: Nested directory structure

## Cons

- ❌ Manual key management (GPG keys)
- ❌ No audit logs (unless using git)
- ❌ Re-encryption needed when adding team members
- ❌ GPG setup can be complex for beginners
- ❌ No GUI (CLI only, though third-party GUIs exist)

## Troubleshooting

### "password store is empty"

Initialize password-store:

```bash
pass init <your-gpg-key-id>
```

### "gpg: decryption failed: No secret key"

Your GPG private key is not available:

```bash
# Check available keys
gpg --list-secret-keys

# Import key if needed
gpg --import private-key.gpg
```

### "gpg: public key decryption failed: Inappropriate ioctl for device"

Set GPG TTY:

```bash
export GPG_TTY=$(tty)

# Add to shell profile
echo 'export GPG_TTY=$(tty)' >> ~/.bashrc
```

### "pass: passphrase entry cancelled"

GPG agent needs unlocking. Enter your GPG key passphrase when prompted.

### Custom store directory not working

Ensure `PASSWORD_STORE_DIR` or `store_dir` in config is set:

```bash
export PASSWORD_STORE_DIR=/path/to/store
# OR in fnox.toml:
# pass = { type = "password-store", store_dir = "/path/to/store" }
```

### Changes not being committed to git

Ensure git is initialized:

```bash
cd ~/.password-store
git status  # Should show a git repo
# If not:
pass git init
```

## Best Practices

1. **Use git integration** - Track changes and sync across machines
2. **Organize with prefixes** - Use nested paths like `work/`, `personal/`
3. **Back up GPG keys** - Export and store securely offline
4. **Team: Use multiple recipients** - More secure than sharing keys
5. **Sync via git** - Private repository for encrypted password store
6. **Set GPG TTY** - Add `export GPG_TTY=$(tty)` to shell profile
7. **Use fnox prefix** - Isolate fnox secrets from other pass entries

## Security Considerations

- **Encryption:** GPG encrypts files with your public key
- **Access control:** Filesystem permissions + GPG key passphrase
- **Git history:** Old secrets remain in git history (use `pass git` carefully)
- **Key security:** Protect your GPG private key
- **Passphrase:** Use a strong GPG key passphrase

## Third-Party Tools

password-store has a rich ecosystem:

- **[QtPass](https://qtpass.org/)** - Cross-platform GUI
- **[Android Password Store](https://github.com/android-password-store/Android-Password-Store)** - Android app
- **[passff](https://github.com/passff/passff)** - Firefox extension
- **[browserpass](https://github.com/browserpass/browserpass-extension)** - Browser extension
- **[gopass](https://github.com/gopasspw/gopass)** - Go implementation with extra features

## Next Steps

- [Age Encryption](/providers/age) - Modern alternative to GPG
- [OS Keychain](/providers/keychain) - OS-native storage
- [1Password](/providers/1password) - Commercial password manager
- [Real-World Example](/guide/real-world-example) - Complete setup guide
