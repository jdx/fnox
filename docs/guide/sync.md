---
description: "Cache vault secrets with a personal encryption provider. Learn where the cache lives, how to refresh it, and when it works offline."
---

# Syncing secrets locally

`fnox sync` fetches secrets from their source providers and re-encrypts them with a target encryption provider. Use `--local-file` to write the cache to `fnox.local.toml`, and add that file to `.gitignore`. A local target such as age supports offline reads; a cloud KMS target still needs its cloud API.

::: tip The golden path
This is the recommended way to use fnox: secrets live in a remote vault like
1Password, `fnox.toml` only holds references to them, and `fnox sync` caches
them locally under a personal age key. The vault stays the single source of
truth, but day-to-day reads use local decryption and work offline. To go further, keep
the age key in hardware:
[Apple's Secure Enclave (Touch ID)](#apple-secure-enclave-touch-id), a
[YubiKey](#yubikey), or a [TPM or FIDO2 token](#tpm-and-fido2).

For a zero-to-working walkthrough of the whole setup, see
[Golden Path Setup](/guide/golden-path).
:::

## Why sync?

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

Without a fnox cache, reads query the provider. Its own CLI may cache data or require a network connection and an authentication prompt. Sync gives fnox a local encrypted copy that it can read independently of the source provider.

With `fnox sync`, you pull those values once and cache them locally with a fast, offline encryption provider:

```bash
fnox sync --provider sync-age --local-file
```

Subsequent reads decrypt with age locally. The cache stays unchanged until you run sync again.

## How it works

1. fnox reads all secrets from your merged config
2. It resolves each secret's plaintext value from the original remote provider
3. It encrypts each value with the target provider (e.g., age)
4. It writes the encrypted cache into `fnox.local.toml` as a `sync` field on each secret

When fnox resolves secrets, it checks for a `sync` field first and uses that instead of calling the original provider.

## Basic usage

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

`--local-file` requires normal config discovery: run from the project directory with the default config name. It rejects explicit paths such as `-c ./fnox.toml`, because those paths would not load the adjacent local cache on later reads.

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

## What it looks like

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

[secrets.DATABASE_URL]
provider = "op"
value = "Database/url"

[secrets.DATABASE_URL.sync]
provider = "sync-age"
value = "YWdlLWVuY3J5cHRpb24..."

[secrets.STRIPE_KEY]
provider = "op"
value = "Stripe/secret-key"

[secrets.STRIPE_KEY.sync]
provider = "sync-age"
value = "YWdlLWVuY3J5cHRpb24..."

[secrets.SENDGRID_KEY]
provider = "op"
value = "SendGrid/api-key"

[secrets.SENDGRID_KEY.sync]
provider = "sync-age"
value = "YWdlLWVuY3J5cHRpb24..."
```

The ciphertext above is abbreviated; let `fnox sync` generate the actual values. The original provider references remain in `fnox.toml`. When you `cd` into the project, fnox sees the `sync` field and decrypts with age locally — no 1Password calls.

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

## Hardware-backed decryption

The sync cache is only as secure as the age key that decrypts it. Rather than
keeping that key in a plaintext file on disk, you can hold it in hardware
through an [age plugin](/providers/age#plugin-support). Syncing works the same
either way; all that changes is the provider's recipient and identity. Secure
Enclave and TPM keys never leave the machine they were created on, a YubiKey
travels with you, and FIDO2-HMAC sits somewhere in between (the identity gets
copied into host memory during decryption).

### Apple Secure Enclave (Touch ID)

On macOS, [age-plugin-se](https://github.com/remko/age-plugin-se) generates the
age key inside Apple's Secure Enclave. The private key can't be exported, so
decryption only works on that Mac — and, depending on the access control policy
you pick at keygen time, only after a Touch ID prompt.

```bash
# 1. Install the plugin (must be on PATH)
brew install age-plugin-se

# 2. Generate a hardware-bound identity
mkdir -p ~/.config/fnox
age-plugin-se keygen --access-control=any-biometry -o ~/.config/fnox/age-se.txt
# Public key: age1se1...
```

Put the printed `age1se1...` recipient in the provider config. The global
config is a good home for it, since every project on the machine can then reuse
the same key:

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

That's it — `fnox get`, `fnox exec`, and shell integration now decrypt the
cache through the Secure Enclave. Whether you're prompted for Touch ID depends
on the `--access-control` policy you chose (`any-biometry`,
`any-biometry-or-passcode`, `none`, …).

::: warning
`age-se.txt` doesn't contain the private key — it's a reference to the key in
the Secure Enclave — but treat it like an identity file anyway. If you have
`FNOX_AGE_KEY` exported, unset it: it takes precedence over the provider's
`key_file`. Requires macOS 14+ and a Mac with a Secure Enclave.
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

Secrets are encrypted to your YubiKey's age identity, so decrypting the cache
requires the key to be plugged in. Unlike a Secure Enclave or TPM key, the
YubiKey isn't tied to one machine: plug it into any machine that has the plugin
and the identity reference and you can decrypt there too. See [Age Plugin
Support](/providers/age#plugin-support) for details and other plugins.

### TPM and FIDO2

No Secure Enclave or YubiKey? Most machines still have some form of hardware
key storage:

- [age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm) stores the age
  key in the TPM 2.0 chip found in most modern laptops. Like the Secure
  Enclave, the key is stuck to that machine. Current releases produce
  recipients starting with `age1tag1...`; identities generated with
  `--tpm-recipient` use the older `age1tpm1...` form. Both work with fnox.
- [age-plugin-fido2-hmac](https://github.com/olastor/age-plugin-fido2-hmac)
  works with FIDO2 security keys that support the `hmac-secret` extension
  (recipients start with `age1zdy...`). It's still experimental, and during
  decryption the age identity gets unwrapped into host memory — anyone who
  steals it from there can decrypt without the token.

Install the plugin for your platform, then generate an identity:

```bash
# TPM, protected by a PIN
age-plugin-tpm --generate --pin -o ~/.config/fnox/age-tpm.txt
age-plugin-tpm -y ~/.config/fnox/age-tpm.txt

# FIDO2-HMAC; writes the identity and prints its public key in a comment
age-plugin-fido2-hmac -g > ~/.config/fnox/age-fido2.txt
```

Add the resulting recipient to the provider's `recipients`, point `key_file`
at the identity file, and sync as usual. If the identity must never touch host
memory, use a YubiKey rather than FIDO2-HMAC.

Without `--pin`, any process running as your user on that machine can use the
TPM key, so the key stays on the machine but nothing stops local malware or a
stray script from decrypting the cache. With `--pin`, every decrypt needs the
PIN. Within one command, fnox asks once for each distinct age ciphertext it
decrypts, and reuses the result when the same ciphertext comes up again. Values
written by one `fnox sync` run share a single wrapped key, so reading the whole
cache costs one prompt; a secret encrypted on its own, such as a token stored
with `fnox set`, is a separate ciphertext and adds a prompt when a command
needs it. With the [daemon](/guide/daemon) enabled, the
first command prompts in your terminal and the daemon caches the results in
memory, so later commands don't prompt again until the daemon idles out or you
run `fnox daemon clear`. Values with `daemon_cache = false` still prompt on
every command.

::: warning
age-plugin-tpm also reads the PIN from `AGE_TPM_PIN`. Exporting it in your
shell gives every process the PIN and undoes the protection; keep it for
non-interactive testing only.
:::

### Age plugins vs. native hardware providers

fnox also ships native [`yubikey`](/providers/yubikey) and
[`fido2`](/providers/fido2) providers that skip age entirely: they derive a
symmetric AES-256-GCM key from the hardware token and can be used as sync
targets the same way (`fnox sync --provider secure --local-file`). The
trade-offs:

- **Native providers** need no plugin binary — fnox talks to the token
  directly — and the config is fully portable: move `fnox.local.toml` to
  another machine, plug in the same token, and it decrypts. But the encryption
  is symmetric, so the token must be present (and touched) for `fnox sync`
  itself, not just for decryption, and only that one token can ever decrypt
  the cache.
- **Age plugins** encrypt to a public recipient, so syncing never touches the
  hardware — only decryption does — and a provider can list several recipients
  (e.g. a YubiKey plus a backup key). In exchange, the plugin binary must be
  installed wherever you decrypt.

For a personal sync cache either works well; pick the native providers if you
don't want to install age plugins, and the age route if you want backup
recipients or hardware-free syncing.

## Protect the vault credential

Some remote providers authenticate with a long-lived token rather than an
interactive login: a Doppler or Infisical service token, a Vault token, a
Bitwarden Secrets Manager access token. Exporting that token in your shell
profile puts it in plain text in every process you start, including scripts
and coding agents that never needed it. Store it in the same hardware-backed
cache instead and let fnox hand it to the provider directly.

This example uses Doppler and the PIN-protected TPM key from above. The same
shape works with any provider whose `token` (or similar field) accepts
[`{ secret = "NAME" }`](/guide/profiles#secret-references-in-provider-config).

```toml
# ~/.config/fnox/config.toml
[providers.sync-age]
type = "age"
recipients = ["age1tag1..."]
key_file = "~/.config/fnox/age-tpm.txt"
```

```toml
# fnox.toml (committed)
[providers.doppler]
type = "doppler"
project = "my-app"
config = "dev"
token = { secret = "DOPPLER_TOKEN" }

[secrets]
DATABASE_URL = { provider = "doppler", value = "DATABASE_URL" }
STRIPE_KEY = { provider = "doppler", value = "STRIPE_KEY" }
```

Store the token in the gitignored local file. fnox prompts for the value with
hidden input, so it never lands in shell history:

```bash
fnox -c fnox.local.toml set DOPPLER_TOKEN --provider sync-age
```

Then mark it `env = false` so fnox uses it to reach Doppler but never injects
it into your shell or `fnox exec` commands:

```toml
# fnox.local.toml (gitignored)
[secrets]
DOPPLER_TOKEN = { provider = "sync-age", value = "<age ciphertext>", env = false }
```

Finally sync the project's secrets into the same cache:

```bash
fnox sync --provider sync-age --local-file
```

What you get:

- **Only ciphertext on disk.** The synced values and the service token are all
  encrypted to the TPM key, which can't leave the machine.
- **The token stays out of the environment.** No `export DOPPLER_TOKEN=...`;
  only fnox reads it, and only when a secret has to be fetched from Doppler.
  Values served from the sync cache don't decrypt the token at all.
- **Few PIN prompts.** Reading the synced values costs one prompt per command,
  and the token adds a second only when a command has to fetch from Doppler.
  With the [daemon](/guide/daemon), the prompts happen once per daemon session.

If the machine is lost or its TPM is reset, the cache and the token can't be
decrypted anywhere else. Revoke the service token in Doppler, issue a new one,
store it again, and re-sync; the vault is still the source of truth.

### Keep production out of the daemon

To keep the daemon's convenience for development while forcing a PIN prompt
on every production command, use a [profile](/guide/profiles) for production
and set `daemon_cache = false` on both its age provider and its remote
provider. The first stops the decrypted token from being cached, the second
stops the fetched production secrets from being cached.

::: warning Move the development cache into its own profile first
Top-level secrets in `fnox.local.toml` are inherited by every profile and take
precedence over `fnox.production.toml`. If the development cache from the
previous section stays under the top-level `[secrets]`, `fnox --profile
production` reads the cached development values instead of fetching from
Doppler's `prd` config. Put development under a `development` profile (or run
production commands with [`--no-defaults`](/guide/profiles)).
:::

Development then looks like the previous section, scoped to a profile:

```toml
# fnox.toml (committed)
[profiles.development.providers.doppler]
type = "doppler"
project = "my-app"
config = "dev"
token = { secret = "DOPPLER_TOKEN" }

[profiles.development.secrets]
DATABASE_URL = { provider = "doppler", value = "DATABASE_URL" }
```

```bash
fnox --profile development -c fnox.local.toml set DOPPLER_TOKEN --provider sync-age
fnox --profile development sync --provider sync-age --local-file
```

The token and the synced values land under `[profiles.development.secrets]`
in `fnox.local.toml`; add `env = false` to the token as before. Set
`FNOX_PROFILE=development` in your shell or project environment to make it the
everyday profile.

Production gets its own age provider, remote provider and token:

```toml
# ~/.config/fnox/config.toml
[providers.prod-age]
type = "age"
recipients = ["age1tag1..."]
key_file = "~/.config/fnox/age-tpm.txt"
daemon_cache = false
```

```toml
# fnox.production.toml (committed)
[profiles.production.providers.doppler]
type = "doppler"
project = "my-app"
config = "prd"
token = { secret = "DOPPLER_TOKEN" }
daemon_cache = false

[profiles.production.secrets]
DATABASE_URL = { provider = "doppler", value = "DATABASE_URL" }
```

```toml
# fnox.local.toml (gitignored)
[profiles.production.secrets]
DOPPLER_TOKEN = { provider = "prod-age", value = "<age ciphertext>", env = false }
```

Production secrets aren't synced, so each `fnox --profile production exec`
asks for the PIN, decrypts the production token, and fetches fresh values
from Doppler.

## Refreshing the cache

When secrets change in the remote provider, re-run sync to update the local cache:

```bash
fnox sync --provider sync-age --local-file --force
```

The `--force` flag skips the confirmation prompt. fnox re-fetches from the original provider and re-encrypts.

## What about CI?

CI can read the committed references directly using a service account token or cloud identity. Install fnox and any required provider CLI, then supply authentication through your CI secret store.

A personal sync cache is usually unnecessary on an ephemeral runner. If you intentionally cache in CI, manage its encryption key, expiry, and refresh policy separately from developers' caches.

## Next steps

- [Golden Path Setup](/guide/golden-path) - Zero-to-working walkthrough of this workflow
- [Per-User Daemon](/guide/daemon) - Cache resolved secrets in memory for a session
- [Import/Export](/guide/import-export) - Migrate secrets between formats
- [Shell Integration](/guide/shell-integration) - Auto-load secrets on `cd`
- [Hierarchical Config](/guide/hierarchical-config) - Organize configs across directories
- [Providers](/providers/overview) - All available providers
