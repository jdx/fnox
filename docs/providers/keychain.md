# OS Keychain

Store secrets in your operating system's native secure storage.

## Supported Platforms

- **macOS:** Keychain Access (built-in)
- **Windows:** Credential Manager (built-in)
- **Linux:** Secret Service (via libsecret - GNOME Keyring, KWallet)

## Quick Start

```bash
# 1. Linux only: Install libsecret
sudo apt-get install libsecret-1-0 libsecret-1-dev  # Ubuntu/Debian

# 2. Configure provider
cat >> fnox.toml << 'EOF'
[providers]
keychain = { type = "keychain", service = "fnox" }
EOF

# 3. Store a secret in OS keychain
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keychain

# 4. Retrieve from keychain
fnox get DATABASE_URL
```

## Linux Setup

On Linux, you need libsecret installed:

::: code-group

```bash [Ubuntu/Debian]
sudo apt-get install libsecret-1-0 libsecret-1-dev
```

```bash [Fedora/RHEL]
sudo dnf install libsecret libsecret-devel
```

```bash [Arch]
sudo pacman -S libsecret
```

:::

macOS and Windows have built-in support—no installation needed.

## Configuration

```toml
[providers]
keychain = { type = "keychain", service = "fnox", prefix = "myapp/" }  # Prefix is optional
```

### Service Name

The `service` acts as a namespace to isolate fnox secrets from other applications:

```toml
[providers]
keychain = { service = "fnox" }  # All fnox secrets under "fnox" service

# Or use project-specific service
keychain = { service = "myapp" }  # All secrets under "myapp" service
```

### Prefix

Optional prefix prepended to secret names:

```toml
[providers]
keychain = { service = "fnox", prefix = "myapp/" }  # "database-url" becomes "myapp/database-url"
```

## How It Works

1. **Storage:** Secrets are stored in the OS credential manager (encrypted by OS)
2. **Config:** `fnox.toml` contains only the secret name, not the value
3. **Retrieval:** fnox queries the OS keychain API
4. **Service:** Acts as a namespace (isolates fnox secrets from other apps)
5. **Prefix:** Additional namespacing within the service

## Usage

### Store a Secret

```bash
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keychain
```

Your `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "keychain", value = "database-url" }  # ← Keychain entry name, not the actual secret
```

The actual secret is stored in the OS keychain, encrypted.

### Retrieve a Secret

```bash
fnox get DATABASE_URL
```

### Run Commands

```bash
fnox exec -- npm run dev
```

## Bootstrap Pattern

A common pattern is to store provider tokens in the keychain:

```toml
[providers]
keychain = { type = "keychain", service = "fnox" }
age = { type = "age", recipients = ["age1..."] }

[secrets]
OP_SERVICE_ACCOUNT_TOKEN = { provider = "keychain", value = "op-token" }  # Store 1Password token in keychain
DATABASE_URL = { provider = "age", value = "encrypted..." }  # Other secrets encrypted with age
```

Then bootstrap:

```bash
export OP_SERVICE_ACCOUNT_TOKEN=$(fnox get OP_SERVICE_ACCOUNT_TOKEN)
# Now can access 1Password secrets
fnox exec -- ./start.sh
```

## Example Configurations

### Personal Project

```toml
[providers]
keychain = { type = "keychain", service = "myapp" }

[secrets]
DATABASE_URL = { provider = "keychain", value = "database-url" }
API_KEY = { provider = "keychain", value = "api-key" }
```

### Bootstrap Tokens

```toml
[providers]
keychain = { type = "keychain", service = "fnox-tokens" }

[secrets]
GITHUB_TOKEN = { provider = "keychain", value = "github" }
NPM_TOKEN = { provider = "keychain", value = "npm" }
```

### Machine-Specific Secrets

```toml
# fnox.local.toml (gitignored)
[providers]
keychain = { type = "keychain", service = "fnox-local" }

[secrets]
LAPTOP_DB_URL = { provider = "keychain", value = "laptop-db" }
```

## Platform Details

### macOS Keychain

Secrets stored in:

- **Login Keychain** (default)
- **System Keychain** (requires admin)

View in Keychain Access app:

1. Open Keychain Access
2. Search for service name (e.g., "fnox")
3. Double-click to view/edit

### Windows Credential Manager

Secrets stored in Windows Credential Manager.

View in Control Panel:

1. Control Panel → User Accounts → Credential Manager
2. Windows Credentials
3. Look for fnox entries

### Linux Secret Service

Secrets stored in:

- **GNOME Keyring** (GNOME desktop)
- **KWallet** (KDE desktop)
- **Other Secret Service implementations**

View with Seahorse (GNOME):

```bash
sudo apt install seahorse
seahorse
```

## Pros

- ✅ OS-managed encryption
- ✅ Cross-platform (macOS, Windows, Linux)
- ✅ No external dependencies
- ✅ Free
- ✅ Built into operating system
- ✅ Secure by default

## Cons

- ❌ Requires GUI/interactive session (doesn't work in headless CI)
- ❌ Not suitable for teams (secrets are per-machine)
- ❌ Keyring must be unlocked
- ❌ No audit logs
- ❌ No centralized management

## Limitations

### Headless Environments

Keychain provider requires a GUI session and doesn't work in:

- CI/CD (GitHub Actions, GitLab CI, etc.)
- Docker containers (without X11/Wayland)
- SSH sessions (without forwarding)
- Headless servers

For CI/CD, use age encryption or cloud providers instead.

### Tests Auto-Skip in CI

fnox's keychain tests automatically skip in CI environments:

```bash
# Runs locally
mise run test:bats

# Skips keychain tests in CI
# GitHub Actions, GitLab CI, etc.
```

## Security

- **Encryption:** OS handles encryption (typically AES-256)
- **Access control:** OS enforces access (user/session isolation)
- **Keyring unlock:** May require password entry on first access
- **Memory protection:** OS manages secure memory handling

## Troubleshooting

### "Keyring is locked"

Unlock your keyring:

**macOS:**

- Keyring unlocks automatically on login

**Linux (GNOME):**

```bash
# Unlock manually
gnome-keyring-daemon --unlock
```

**Windows:**

- Credential Manager unlocks on login

### "Access denied"

Check that the process has access:

- **macOS:** May prompt for Keychain Access permission
- **Linux:** Ensure Secret Service is running
- **Windows:** Check User Account Control settings

### "Service not available" (Linux)

Install and start Secret Service:

```bash
# Ubuntu/Debian
sudo apt-get install gnome-keyring
gnome-keyring-daemon --start

# Or use KWallet
sudo apt-get install kwalletmanager
```

## Best Practices

1. **Use for local development only** - Not for teams or CI
2. **Bootstrap provider tokens** - Store 1Password/AWS tokens
3. **Machine-specific overrides** - Use in `fnox.local.toml`
4. **Descriptive service names** - Use project-specific services
5. **Keep keyring unlocked** - Unlock on login for convenience

## Next Steps

- [Age Encryption](/providers/age) - Team-friendly alternative
- [Hierarchical Config](/guide/hierarchical-config) - Per-machine configuration with fnox.local.toml
- [1Password](/providers/1password) - Team password manager
