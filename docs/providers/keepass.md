# KeePass

Store secrets in a local KeePass database file (`.kdbx`), supporting KDBX4 format with read/write operations.

## Quick Start

```bash
# 1. Set database password
export FNOX_KEEPASS_PASSWORD="your-master-password"

# 2. Configure provider
cat >> fnox.toml << 'EOF'
[providers]
keepass = { type = "keepass", database = "~/secrets.kdbx" }
EOF

# 3. Store a secret
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keepass

# 4. Retrieve from database
fnox get DATABASE_URL
```

## Configuration

```toml
[providers]
keepass = { type = "keepass", database = "~/secrets.kdbx" }

# OR with keyfile for additional security
keepass = { type = "keepass", database = "~/secrets.kdbx", keyfile = "~/keyfile.key" }
```

### Database Path

The `database` field specifies the path to your `.kdbx` file. Shell expansion is supported:

```toml
[providers]
keepass = { database = "~/secrets.kdbx" }           # Home directory
keepass = { database = "./secrets/vault.kdbx" }     # Relative path
keepass = { database = "/opt/secrets/shared.kdbx" } # Absolute path
```

### Keyfile (Optional)

For additional security, use a keyfile alongside the password:

```toml
[providers]
keepass = { database = "~/secrets.kdbx", keyfile = "~/keyfile.key" }
```

## Authentication

Set the database password via environment variable:

- `FNOX_KEEPASS_PASSWORD` (preferred)
- `KEEPASS_PASSWORD` (fallback)

```bash
# Recommended: FNOX_KEEPASS_PASSWORD
export FNOX_KEEPASS_PASSWORD="your-master-password"

# Alternative: KEEPASS_PASSWORD
export KEEPASS_PASSWORD="your-master-password"
```

::: warning
Avoid storing the password directly in the provider config. Use environment variables instead for security.
:::

## Reference Formats

KeePass supports flexible path formats:

| Format      | Example                      | Description                               |
| ----------- | ---------------------------- | ----------------------------------------- |
| Entry name  | `my-entry`                   | Gets password field (searches all groups) |
| Entry/field | `my-entry/username`          | Gets specific field from entry            |
| Group/entry | `work/my-entry`              | Gets password from entry in group         |
| Full path   | `work/project/api-key/notes` | Group path + entry + field                |

### Simple Entry Name

```toml
[secrets]
DATABASE_URL = { provider = "keepass", value = "database-url" }
```

Searches all groups for an entry with this title and returns the password field.

### Entry with Field

```toml
[secrets]
DB_USER = { provider = "keepass", value = "database/username" }
DB_PASS = { provider = "keepass", value = "database/password" }
DB_HOST = { provider = "keepass", value = "database/url" }
```

### Group Path

```toml
[secrets]
PROD_API_KEY = { provider = "keepass", value = "production/api/my-service" }
DEV_API_KEY = { provider = "keepass", value = "development/api/my-service" }
```

### Full Path with Field

```toml
[secrets]
API_USER = { provider = "keepass", value = "production/api/my-service/username" }
API_NOTES = { provider = "keepass", value = "production/api/my-service/notes" }
```

## Supported Fields

| Field      | Description              |
| ---------- | ------------------------ |
| `password` | Entry password (default) |
| `username` | Entry username           |
| `url`      | Entry URL                |
| `notes`    | Entry notes              |
| `title`    | Entry title (read-only)  |

Field names are case-insensitive (`Username`, `USERNAME`, `username` all work).

## How It Works

1. **Storage:** Secrets are stored in a local `.kdbx` database file
2. **Config:** `fnox.toml` contains the entry name/path (not the actual secret value)
3. **Auto-creation:** Database and group structure are created automatically if they don't exist
4. **Atomic writes:** Uses temporary files with sync-to-disk before rename to prevent data loss
5. **Protected fields:** Password fields are stored encrypted within KDBX format

## Usage

### Store a Secret

```bash
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keepass
```

Your `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "keepass", value = "database-url" }
```

### Store with Specific Path

```bash
# Store in a specific group with specific field
fnox set API_USER "admin" --provider keepass --key-name "production/api-service/username"
```

### Retrieve a Secret

```bash
fnox get DATABASE_URL
```

### Run Commands

```bash
fnox exec -- npm run dev
```

## Example Configurations

### Personal Password Database

```toml
[providers]
keepass = { type = "keepass", database = "~/Documents/passwords.kdbx" }

[secrets]
GITHUB_TOKEN = { provider = "keepass", value = "github/token" }
NPM_TOKEN = { provider = "keepass", value = "npm/token" }
```

### Project-Specific Database

```toml
[providers]
keepass = { type = "keepass", database = "./secrets.kdbx" }

[secrets]
DATABASE_URL = { provider = "keepass", value = "database" }
API_KEY = { provider = "keepass", value = "api-key" }
```

### Organized by Environment

```toml
[providers]
keepass = { type = "keepass", database = "~/work/secrets.kdbx" }

[secrets]
DEV_DB = { provider = "keepass", value = "development/database/password" }

[profiles.production.secrets]
PROD_DB = { provider = "keepass", value = "production/database/password" }
```

### With Keyfile

```toml
[providers]
keepass = { type = "keepass", database = "~/secure.kdbx", keyfile = "~/secure.key" }

[secrets]
MASTER_KEY = { provider = "keepass", value = "master-key" }
```

## Pros

- ✅ Local-first - no cloud dependency
- ✅ Industry-standard KDBX4 format
- ✅ Works offline
- ✅ Free and open source
- ✅ Compatible with KeePass, KeePassXC, and other KDBX tools
- ✅ Supports keyfile for two-factor security
- ✅ Organized with groups/folders
- ✅ Atomic writes prevent corruption

## Cons

- ❌ Database file must be accessible (not suitable for teams without sync)
- ❌ Requires master password in environment
- ❌ No built-in sync (use Syncthing, Dropbox, etc.)
- ❌ No audit logs
- ❌ No centralized management

## Limitations

### Database Sync

KeePass databases are single files. For team use, sync via:

- Git (with care - merge conflicts possible)
- Syncthing
- Dropbox/OneDrive
- Network share

For teams, consider [1Password](/providers/1password), [Bitwarden](/providers/bitwarden), or cloud providers instead.

### Title Field is Read-Only

The `title` field cannot be modified via fnox - it's reserved for entry identification.

## Security

- **Encryption:** KDBX4 format uses AES-256 or ChaCha20
- **Key derivation:** Argon2d for password-based key derivation
- **Protected fields:** Password fields stored in protected memory
- **Atomic saves:** Prevents corruption on write failure

## Troubleshooting

### "Database password not set"

Set the password environment variable:

```bash
export FNOX_KEEPASS_PASSWORD="your-master-password"
# or
export KEEPASS_PASSWORD="your-master-password"
```

### "Entry not found"

Check that:

1. Entry exists in the database
2. Entry title matches the reference exactly
3. Group path is correct (if using group paths)

View entries with KeePassXC:

```bash
# macOS
brew install --cask keepassxc
keepassxc ~/secrets.kdbx
```

### "Cannot open database"

Verify:

1. Database file exists at the specified path
2. Password is correct
3. Keyfile is accessible (if configured)
4. File permissions allow read/write

### "Database created but empty"

fnox auto-creates databases. If you need to pre-populate:

1. Create database with KeePassXC
2. Add entries manually
3. Reference them in fnox.toml

## Best Practices

1. **Use FNOX_KEEPASS_PASSWORD** - Set via environment, not config
2. **Consider keyfile** - Adds two-factor security
3. **Organize with groups** - Use group paths for organization
4. **Back up regularly** - Database is a single file
5. **Use KeePassXC** - Modern GUI for database management
6. **Gitignore the database** - Unless intentionally sharing encrypted

## Running Tests

```bash
# Set the test password
export KEEPASS_PASSWORD="test-password"

# Run the KeePass tests
mise run test:bats -- test/keepass.bats
```

Tests will automatically skip if `KEEPASS_PASSWORD` is not available.

## Next Steps

- [OS Keychain](/providers/keychain) - Alternative local storage
- [password-store](/providers/password-store) - GPG-based alternative
- [Age Encryption](/providers/age) - Team-friendly, git-based secrets
