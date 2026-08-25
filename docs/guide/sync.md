# Syncing Secrets Locally

`fnox sync` fetches secrets from remote providers (1Password, AWS Secrets Manager, etc.) and re-encrypts them with a local encryption provider (age, YubiKey via age plugin, AWS KMS, etc.). The encrypted values are stored in `fnox.local.toml` (gitignored) so that subsequent access is instant and offline — no remote calls needed.

::: tip The golden path
This is the recommended way to use fnox: keep secrets in a remote vault like
1Password as the single source of truth, commit only references to them in
`fnox.toml`, and cache them locally with `fnox sync` behind a personal age key.
You get centralized management and instant, offline secret loading. For the
strongest setup, bind the local key to hardware —
[Apple's Secure Enclave (Touch ID)](#apple-secure-enclave-touch-id), a
[YubiKey](#yubikey), or [TPM and FIDO2 hardware](#tpm-and-fido2). Secure Enclave
and TPM keys are bound to one machine, while YubiKey and FIDO2 tokens are
portable; each option's security properties are described below.
:::

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

## Hardware-Backed Decryption

The sync cache is only as secure as the age key that decrypts it. Instead of a
plaintext key file on disk, you can bind decryption to hardware via an
[age plugin](/providers/age#plugin-support) — the workflow stays exactly the
same, only the provider's recipient (and identity) changes. The guarantees vary:
Secure Enclave and TPM identities are machine-bound, YubiKey identities require
the portable token, and FIDO2-HMAC unwraps an age identity into host memory.

### Apple Secure Enclave (Touch ID)

On macOS, [age-plugin-se](https://github.com/remko/age-plugin-se) generates the
age key inside Apple's Secure Enclave. The private key is non-exportable and
never leaves the hardware. Decryption requires that Mac and enforces the access
control policy chosen when the identity was created, which can require Touch ID.

```bash
# 1. Install the plugin (must be on PATH)
brew install age-plugin-se

# 2. Generate a hardware-bound identity
mkdir -p ~/.config/fnox
age-plugin-se keygen --access-control=any-biometry -o ~/.config/fnox/age-se.txt
# Public key: age1se1...
```

Configure the personal provider with the printed `age1se1...` recipient — in
the global config so every project on this machine can reuse it:

```toml
# ~/.config/fnox/config.toml
[providers.sync-age]
type = "age"
recipients = ["age1se1..."]
key_file = "~/.config/fnox/age-se.txt"
```

Then sync as usual:

```bash
fnox sync --provider sync-age --local-file
```

From now on, `fnox get`, `fnox exec`, and shell integration decrypt the cache
through the Secure Enclave, prompting for Touch ID according to the
`--access-control` policy you chose (`any-biometry`, `any-biometry-or-passcode`,
`none`, …).

::: warning
`age-se.txt` is only a reference to the hardware key, not the key itself — but
treat it like an identity file anyway. Unset `FNOX_AGE_KEY` if you have it
exported, since it takes precedence over the provider's `key_file`. Secure
Enclave identity generation and decryption require macOS 14 or later and a Mac
with a Secure Enclave processor.
:::

### YubiKey

If you use a YubiKey with the [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey), syncing works the same way. Your age provider just uses the YubiKey identity:

```toml
[providers.sync-age]
type = "age"
recipients = ["age1yubikey1q..."]  # YubiKey recipient
```

```bash
fnox sync --provider sync-age --local-file
```

Secrets are encrypted to your YubiKey's age identity. Decryption requires the
YubiKey to be plugged in, adding hardware-based security to your local cache.
The token is portable, so you can decrypt on another compatible machine that
has the plugin and identity reference. See [Age Plugin
Support](/providers/age#plugin-support) for details and other plugins.

### TPM and FIDO2

Machines without a Secure Enclave or YubiKey usually still have hardware key
storage:

- [age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm) binds the age
  key to the TPM 2.0 chip built into most modern laptops. The identity cannot be
  used with another machine's TPM; current recipients start with `age1tag1...`.
- [age-plugin-fido2-hmac](https://github.com/olastor/age-plugin-fido2-hmac)
  works with FIDO2 security keys that support the `hmac-secret` extension;
  documented recipients start with `age1zdy...`. The plugin is experimental and
  unwraps the age identity into host memory during decryption. If that in-memory
  identity is stolen, it can decrypt without the token.

Follow each plugin's installation instructions for your platform, then generate
the identity and recipient with its documented command:

```bash
# TPM
age-plugin-tpm --generate -o ~/.config/fnox/age-tpm.txt
age-plugin-tpm -y ~/.config/fnox/age-tpm.txt

# FIDO2-HMAC; writes the identity and prints its public key in a comment
age-plugin-fido2-hmac -g > ~/.config/fnox/age-fido2.txt
```

Put the resulting recipient in the provider's `recipients`, point `key_file` at
the identity file, and run `fnox sync` as usual. A YubiKey is preferable to
FIDO2-HMAC when the decrypted identity must never enter host memory.

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
