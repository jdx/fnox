# Syncing Secrets Locally

`fnox sync` fetches secrets from remote providers (1Password, AWS Secrets Manager, etc.) and re-encrypts them with a local encryption provider (age, YubiKey via age plugin, AWS KMS, etc.). The encrypted values are stored in `fnox.local.toml` (gitignored) so that subsequent access is instant and offline — no remote calls needed.

## Why Sync?

A typical team setup stores secrets in a shared provider like 1Password:

```toml
# fnox.toml (committed)
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
STRIPE_KEY = { provider = "op", value = "Stripe/secret-key" }
SENDGRID_KEY = { provider = "op", value = "SendGrid/api-key" }
```

This works, but every time you `cd` into the project (with [shell integration](/guide/shell-integration)), fnox calls 1Password to fetch each secret. This is slow and requires network access.

With `fnox sync`, you pull those values once and cache them locally with a fast, offline encryption provider:

```bash
fnox sync --provider sync-age --local-file
```

Now entering the directory is instant — secrets are decrypted locally from age without any remote calls.

## How It Works

1. fnox reads all secrets from your merged config
2. It resolves each secret's plaintext value from the original remote provider
3. It encrypts each value with the target provider (e.g., age)
4. It writes the encrypted cache into `fnox.local.toml` as a `sync` field on each secret

When fnox resolves secrets, it checks for a `sync` field first and uses that instead of calling the original provider.

## Basic Usage

```bash
# Set up a personal age provider if you haven't already. Replace the generated
# age1... placeholder in ~/.config/fnox/config.toml with your recipient.
fnox provider add sync-age age --global

# Sync everything to fnox.local.toml
fnox sync --provider sync-age --local-file
```

Using a distinct name such as `sync-age` avoids colliding with an `age` provider
that the project may already use for secrets encrypted in git. The global
provider is machine-scoped and can be reused across checkouts. You can instead
put the personal provider in `fnox.local.toml` if each project needs different
settings.

### Preview what would be synced

```bash
fnox sync --provider sync-age --local-file --dry-run
```

### Sync specific secrets

```bash
fnox sync --provider sync-age --local-file DATABASE_URL STRIPE_KEY
```

### Sync only secrets from a specific source

```bash
fnox sync --provider sync-age --local-file --source op
```

### Filter by regex pattern

```bash
fnox sync --provider sync-age --local-file --filter "^DB_"
```

## What It Looks Like

If you keep the personal provider in the project-local override, your files
look like this after syncing. With the global setup above, the
`[providers.sync-age]` block lives in `~/.config/fnox/config.toml` instead.

**fnox.toml** (committed — the source of truth):

```toml
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
STRIPE_KEY = { provider = "op", value = "Stripe/secret-key" }
SENDGRID_KEY = { provider = "op", value = "SendGrid/api-key" }
```

**fnox.local.toml** (gitignored — your local cache):

```toml
[providers.sync-age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]

[secrets]
DATABASE_URL = {
  provider = "op",
  value = "Database/url",
  sync = {
    provider = "sync-age",
    value = "YWdlLWVuY3J5cHRpb24...",
  },
}
STRIPE_KEY = {
  provider = "op",
  value = "Stripe/secret-key",
  sync = {
    provider = "sync-age",
    value = "YWdlLWVuY3J5cHRpb24...",
  },
}
SENDGRID_KEY = {
  provider = "op",
  value = "SendGrid/api-key",
  sync = {
    provider = "sync-age",
    value = "YWdlLWVuY3J5cHRpb24...",
  },
}
```

When you `cd` into the project, fnox sees the `sync` field and decrypts with age locally — no 1Password calls.

::: tip Sync cache vs. encrypted secrets in git
A sync cache is personal: its recipient belongs in the global config or
`fnox.local.toml`.

For age-encrypted secrets committed to git, commit a separate provider whose
recipients include the whole team and CI. After changing that list, run
`fnox reencrypt --provider <team-provider-name>` to update the committed
ciphertext.

Provider definitions are replaced as a unit when configs are merged. A local
`[providers.age]` does not deep-merge with a committed provider of the same
name, so use a distinct name such as `sync-age` for the cache.
:::

## Using a YubiKey

If you use a YubiKey with the [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey), syncing works the same way. Your age provider just uses the YubiKey identity:

```toml
[providers.sync-age]
type = "age"
recipients = ["age1yubikey1q..."]  # YubiKey recipient
```

```bash
fnox sync --provider sync-age --local-file
```

Secrets are encrypted to your YubiKey's age identity. Decryption requires the YubiKey to be plugged in, adding hardware-based security to your local cache. See [Age Plugin Support](/providers/age#plugin-support) for details and other plugins (TPM, FIDO2, …).

## Refreshing the Cache

When secrets change in the remote provider, re-run sync to update the local cache:

```bash
fnox sync --provider sync-age --local-file --force
```

The `--force` flag skips the confirmation prompt. fnox re-fetches from the original provider and re-encrypts.

## Full Workflow Example

Configure the personal provider once per machine:

```bash
# 1. Set up your age key if it does not already exist
mkdir -p ~/.config/fnox
if [ ! -f ~/.config/fnox/age.txt ]; then
	age-keygen -o ~/.config/fnox/age.txt
fi
export FNOX_AGE_KEY=$(grep "AGE-SECRET-KEY" ~/.config/fnox/age.txt)

# 2. Read the recipient, failing before changing any config if the key is invalid
recipient=$(age-keygen -y ~/.config/fnox/age.txt 2>/dev/null)
if [ -z "$recipient" ]; then
	echo "Could not find an age public key in ~/.config/fnox/age.txt" >&2
	exit 1
fi

# 3. Add the machine-wide provider, then replace its age1... placeholder
# with $recipient in the file opened by the second command
fnox provider add sync-age age --global
"${EDITOR:-vi}" "${FNOX_CONFIG_DIR:-$HOME/.config/fnox}/config.toml"
```

Then reuse that provider in every checkout:

```bash
# 1. Clone a project with 1Password secrets in fnox.toml
git clone https://github.com/myorg/my-api && cd my-api

# 2. Sync all 1Password secrets to local age encryption
fnox sync --provider sync-age --local-file --force

# 3. Done — entering the directory is now instant
cd .. && cd my-api
# Secrets load from local age cache, no 1Password calls
```

## Next Steps

- [Per-User Daemon](/guide/daemon) - Cache resolved secrets in memory for a session
- [Import/Export](/guide/import-export) - Migrate secrets between formats
- [Shell Integration](/guide/shell-integration) - Auto-load secrets on `cd`
- [Hierarchical Config](/guide/hierarchical-config) - Organize configs across directories
- [Providers](/providers/overview) - All available providers
