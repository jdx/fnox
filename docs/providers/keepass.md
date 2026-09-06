---
description: "Read and write KeePass database entries with fnox. Configure the database, password, key file, and entry paths."
---

# KeePass

Store secrets in a local KeePass database file (`.kdbx`), supporting KDBX4 format with read/write operations.

## Quick start

```sh
# Set database password
export FNOX_KEEPASS_PASSWORD="your-master-password"
```

Add these definitions to `fnox.toml`. Merge them into any existing tables with the same names:

```toml
[providers]
keepass = { type = "keepass", database = "~/secrets.kdbx" }
```

```sh
# Store a secret
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keepass

# Retrieve from database
fnox get DATABASE_URL
```

## Configuration

```toml
[providers]
keepass = { type = "keepass", database = "~/secrets.kdbx" }

# A second instance using a keyfile
keepass-with-keyfile = { type = "keepass", database = "~/secrets.kdbx", keyfile = "~/keyfile.key" }
```

### Database path

The `database` field specifies the path to your `.kdbx` file. Relative paths are resolved from the config file that declares the provider, and `~` expands to your home directory:

```toml
[providers]
home-db = { type = "keepass", database = "~/secrets.kdbx" }           # Home directory
project-db = { type = "keepass", database = "./secrets/vault.kdbx" }     # Relative to this config file
shared-db = { type = "keepass", database = "/opt/secrets/shared.kdbx" } # Absolute path
```

### Keyfile (optional)

For additional security, use a keyfile alongside the password:

```toml
[providers]
keepass = { type = "keepass", database = "~/secrets.kdbx", keyfile = "~/keyfile.key" }
```

Relative `keyfile` paths follow the same config-relative rule as `database`.

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
The provider also accepts a `password` field, but avoid storing the password directly in the provider config. Use environment variables instead; they take priority over the config value.
:::

## Reference formats

KeePass supports flexible path formats:

| Format      | Example                      | Description                               |
| ----------- | ---------------------------- | ----------------------------------------- |
| Entry name  | `my-entry`                   | Gets password field (searches all groups) |
| Entry/field | `my-entry/username`          | Gets specific field from entry            |
| Group/entry | `work/my-entry`              | Gets password from entry in group         |
| Full path   | `work/project/api-key/notes` | Group path + entry + field                |

### Simple entry name

```toml
[secrets]
DATABASE_URL = { provider = "keepass", value = "database-url" }
```

Searches all groups for an entry with this title and returns the password field.

### Entry with field

```toml
[secrets]
DB_USER = { provider = "keepass", value = "database/username" }
DB_PASS = { provider = "keepass", value = "database/password" }
DB_HOST = { provider = "keepass", value = "database/url" }
```

### Group path

```toml
[secrets]
PROD_API_KEY = { provider = "keepass", value = "production/api/my-service" }
DEV_API_KEY = { provider = "keepass", value = "development/api/my-service" }
```

### Full path with field

```toml
[secrets]
API_USER = { provider = "keepass", value = "production/api/my-service/username" }
API_NOTES = { provider = "keepass", value = "production/api/my-service/notes" }
```

## Supported fields

| Field      | Description              |
| ---------- | ------------------------ |
| `password` | Entry password (default) |
| `username` | Entry username           |
| `url`      | Entry URL                |
| `notes`    | Entry notes              |
| `title`    | Entry title (read-only)  |

Field names are case-insensitive (`Username`, `USERNAME`, `username` all work).

## How it works

1. **Storage:** Secrets are stored in a local `.kdbx` database file
2. **Config:** `fnox.toml` contains the entry name/path (not the actual secret value)
3. **Auto-creation:** Database and group structure are created automatically if they don't exist
4. **Atomic writes:** Uses temporary files with sync-to-disk before rename to prevent data loss
5. **Protected fields:** Password fields are stored encrypted within KDBX format

## Usage

### Store a secret

```bash
fnox set DATABASE_URL "postgresql://localhost/mydb" --provider keepass
```

Your `fnox.toml`:

```toml
[secrets]
DATABASE_URL = { provider = "keepass", value = "DATABASE_URL" }  # Entry title, not the actual secret
```

### Store with specific path

```bash
# Store in a specific group with specific field
fnox set API_USER "admin" --provider keepass --key-name "production/api-service/username"
```

### Retrieve a secret

```bash
fnox get DATABASE_URL
```

### Run commands

```bash
fnox exec -- npm run dev
```

## Example configurations

### Personal password database

```toml
[providers]
keepass = { type = "keepass", database = "~/Documents/passwords.kdbx" }

[secrets]
GITHUB_TOKEN = { provider = "keepass", value = "github/token" }
NPM_TOKEN = { provider = "keepass", value = "npm/token" }
```

### Project-specific database

```toml
[providers]
keepass = { type = "keepass", database = "./secrets.kdbx" }

[secrets]
DATABASE_URL = { provider = "keepass", value = "database" }
API_KEY = { provider = "keepass", value = "api-key" }
```

### Organized by environment

```toml
[providers]
keepass = { type = "keepass", database = "~/work/secrets.kdbx" }

[secrets]
DEV_DB = { provider = "keepass", value = "development/database/password" }

[profiles.production.secrets]
PROD_DB = { provider = "keepass", value = "production/database/password" }
```

### With keyfile

```toml
[providers]
keepass = { type = "keepass", database = "~/secure.kdbx", keyfile = "~/secure.key" }

[secrets]
MASTER_KEY = { provider = "keepass", value = "master-key" }
```

## Usage notes

The provider reads and writes a local KDBX4 database. Back up the database and any required keyfile. Coordinate writes if several machines share the same file; atomic local saves do not merge concurrent changes.

## Limitations

### Database sync

KeePass databases are single files. For team use, sync via:

- Git (with care - merge conflicts possible)
- Syncthing
- Dropbox/OneDrive
- Network share

For teams, consider [1Password](/providers/1password), [Bitwarden](/providers/bitwarden), or cloud providers instead.

### Title field is read-only

The `title` field cannot be modified via fnox - it's reserved for entry identification.

## Database protection

- **Encryption:** KDBX4 format uses AES-256 or ChaCha20
- **Key derivation:** Argon2d for password-based key derivation
- **Atomic saves:** Writes through a temporary file before replacing the database

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

## Running tests

```bash
# Run the KeePass tests
mise run test:bats -- test/keepass.bats
```

The tests create a temporary database with their own password, so no external setup is needed.

## Next steps

- [OS Keychain](/providers/keychain) - Alternative local storage
- [password-store](/providers/password-store) - GPG-based alternative
- [Age Encryption](/providers/age) - Team-friendly, git-based secrets
