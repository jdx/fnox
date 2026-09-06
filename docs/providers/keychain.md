---
description: "Store local secrets in the macOS Keychain, Windows Credential Manager, or Linux Secret Service, and use them to bootstrap other providers."
---

# OS keychain

Store secrets in your operating system's native secure storage.

## Supported platforms

- **macOS:** Keychain Access (built-in)
- **Windows:** Credential Manager (built-in)
- **Linux:** Secret Service over D-Bus (GNOME Keyring, KWallet)

## Quick start

```sh
# Linux only: make sure a Secret Service daemon is running
sudo apt-get install gnome-keyring  # Ubuntu/Debian
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
keychain = { type = "keychain", service = "fnox" }
```

```sh
# Store a secret in OS keychain
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keychain

# Retrieve from keychain
fnox get DATABASE_URL
```

## Linux setup

On Linux, fnox talks to the Secret Service API directly over D-Bus, so you need a Secret Service implementation such as GNOME Keyring or KWallet running (no libsecret packages are required):

::: code-group

```bash [Ubuntu/Debian]
sudo apt-get install gnome-keyring
```

```bash [Fedora/RHEL]
sudo dnf install gnome-keyring
```

```bash [Arch]
sudo pacman -S gnome-keyring
```

:::

macOS and Windows have built-in support—no installation needed.

## Configuration

```toml
[providers]
keychain = { type = "keychain", service = "fnox", prefix = "myapp/" }  # Prefix is optional
```

### Service name

The `service` acts as a namespace to isolate fnox secrets from other applications:

```toml
[providers]
keychain = { type = "keychain", service = "myapp" }
```

### Prefix

Optional prefix prepended to secret names:

```toml
[providers]
keychain = { type = "keychain", service = "fnox", prefix = "myapp/" }  # "database-url" becomes "myapp/database-url"
```

## How it works

1. **Storage:** Secrets are stored in the OS credential manager (encrypted by OS)
2. **Config:** `fnox.toml` contains only the secret name, not the value
3. **Retrieval:** fnox queries the OS keychain API
4. **Service:** Acts as a namespace (isolates fnox secrets from other apps)
5. **Prefix:** Additional namespacing within the service

## Usage

### Store a secret

```bash
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keychain
```

Your `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "keychain", value = "DATABASE_URL" }  # ← Keychain entry name, not the actual secret
```

The actual secret is stored in the OS keychain, encrypted.

### Retrieve a secret

```bash
fnox get DATABASE_URL
```

### Run commands

```bash
fnox exec -- npm run dev
```

## Recommended: use with age, not as bulk storage

On macOS, access controls can prompt separately for each keychain item. If those prompts interrupt a project with many secrets, store one age identity in the keychain and use it to decrypt the rest.

The pattern that scales much better is to store a single **age private key** in the keychain and encrypt all your secrets with age:

```toml
[providers]
keychain = { type = "keychain", service = "fnox" }
age = { type = "age", recipients = ["age1..."], identity = { provider = "keychain", value = "age-key" } }

[secrets]
# Many secrets, all encrypted with age — only one keychain access (the age key)
DATABASE_URL = { provider = "age", value = "encrypted..." }
API_KEY      = { provider = "age", value = "encrypted..." }
STRIPE_KEY   = { provider = "age", value = "encrypted..." }
# ...
```

This way:

- **One keychain item for the identity.** Access prompts depend on the keychain's application permissions.
- Adding more secrets is free — they go into the encrypted config, not into the keychain.
- Loss of the keychain item is recoverable from any other machine that holds the same age identity.

Reach for direct `provider = "keychain"` only for the handful of bootstrap secrets that don't have anything else to decrypt them (e.g., the age key itself, a 1Password service account token).

## Bootstrap pattern

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

## Example configurations

### Personal project

```toml
[providers]
app-keychain = { type = "keychain", service = "myapp" }

[secrets]
DATABASE_URL = { provider = "keychain", value = "database-url" }
API_KEY = { provider = "keychain", value = "api-key" }
```

### Bootstrap tokens

```toml
[providers]
keychain = { type = "keychain", service = "fnox-tokens" }

[secrets]
GITHUB_TOKEN = { provider = "keychain", value = "github" }
NPM_TOKEN = { provider = "keychain", value = "npm" }
```

### Machine-specific secrets

```toml
# fnox.local.toml (gitignored)
[providers]
keychain = { type = "keychain", service = "fnox-local" }

[secrets]
LAPTOP_DB_URL = { provider = "keychain", value = "laptop-db" }
```

## Platform details

### macOS keychain

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

## Usage notes

Access depends on the current user and an available, unlocked credential store. macOS may prompt for access to individual items. Linux needs a Secret Service implementation on D-Bus; headless setups must provide one explicitly.

## Limitations

### Headless environments

The keychain provider needs an unlocked OS keychain or Secret Service session, which is usually unavailable in:

- CI/CD (GitHub Actions, GitLab CI, etc.)
- Docker containers (without X11/Wayland)
- SSH sessions (without forwarding)
- Headless servers

No desktop session is required, though — only an unlocked Secret Service on the bus. If you provision one yourself, the provider works headlessly; fnox's own Linux CI does this with `gnome-keyring-daemon --unlock --components=secrets --daemonize`. That means keeping the unlock password in CI, which is the secret you were trying to protect, so for CI/CD prefer age encryption or a cloud provider.

### Tests auto-skip in CI

fnox's keychain tests skip automatically on macOS CI runners (where they hang) and on platforms other than macOS and Linux. On Linux CI they run against a headless `gnome-keyring-daemon`. Set `SKIP_KEYCHAIN_TESTS=1` to skip them everywhere:

```bash
# Runs locally
mise run test:bats -- test/keychain.bats

# Skip the keychain tests
SKIP_KEYCHAIN_TESTS=1 mise run test:bats
```

## Security

- **Encryption:** Managed by the platform credential store
- **Access control:** OS enforces access (user/session isolation)
- **Keyring unlock:** May require password entry on first access
- **Resolved values:** fnox and the receiving process still handle plaintext in memory

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

## Next steps

- [Age Encryption](/providers/age) - Team-friendly alternative
- [Hierarchical Config](/guide/hierarchical-config) - Per-machine configuration with fnox.local.toml
- [1Password](/providers/1password) - Team password manager
