---
description: "Cache vault secrets on your machine, encrypted to a personal key, for fast offline reads. Learn what fnox sync writes, how to refresh it, and how to use hardware keys."
---

# Local sync cache

`fnox sync` reads every secret from its provider once and stores a copy in your gitignored `fnox.local.toml`, encrypted to a key only you hold. Later commands decrypt that copy locally instead of calling the vault.

Use it when your secrets live in a remote vault and you want reads that are fast, work offline, and don't trigger an authentication prompt each time. The vault stays the source of truth; the cache is a snapshot you refresh when values change.

## Set up

You need a project whose `fnox.toml` references a vault (see [use an existing vault](/guide/existing-vault)) and a personal encryption provider. Create the provider once per machine in your global config:

```sh
mkdir -p ~/.config/fnox
age-keygen -o ~/.config/fnox/age.txt     # prints your public key
fnox provider add sync-age age --global  # then set recipients in ~/.config/fnox/config.toml
```

```toml
# ~/.config/fnox/config.toml
[providers.sync-age]
type = "age"
recipients = ["age1..."] # your public key
```

Use a distinct name such as `sync-age`. A project may already have a provider called `age` for secrets shared through git, and a local provider with the same name would [replace it](/guide/config-files#merging-rules).

Then, in the project:

```sh
echo "fnox.local.toml" >> .gitignore
fnox sync --provider sync-age --local-file
```

## What it writes

`fnox.toml` is unchanged:

```toml
[providers.op]
type = "1password"
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }
```

`fnox.local.toml` gets each secret's definition plus a `sync` entry holding the ciphertext:

```toml
[secrets.DATABASE_URL]
provider = "op"
value = "Database/url"

[secrets.DATABASE_URL.sync]
provider = "sync-age"
value = "YWdl..." # ciphertext, abbreviated
```

When fnox resolves a secret that has a `sync` entry, it decrypts that and never calls the original provider.

## Refresh

The cache never updates itself. After a value changes in the vault:

```sh
fnox sync --provider sync-age --local-file --force
```

`--force` skips the confirmation prompt. To refresh only some secrets, name them, or filter:

```sh
fnox sync --provider sync-age --local-file DATABASE_URL STRIPE_KEY
fnox sync --provider sync-age --local-file --source op       # only secrets from provider "op"
fnox sync --provider sync-age --local-file --filter '^DB_'   # regex on names
fnox sync --provider sync-age --local-file --dry-run         # preview
```

Run sync from the project directory without `-c`: `--local-file` writes next to the discovered config, and an explicit config path wouldn't load that file on later reads.

## Offline use

A local target such as age decrypts with no network access. A cloud KMS provider also works as a sync target, but then every read needs that cloud's API.

## Hardware-backed keys {#hardware-backed-decryption}

The cache is only as safe as the key that decrypts it. Instead of `age.txt` on disk, you can keep the key in hardware through an [age plugin](/providers/age#plugin-support). Only the provider's recipient and identity file change; syncing works the same.

| Hardware                        | Plugin                                                                                   | Key leaves the device?                 | Works on another machine? |
| ------------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------- | ------------------------- |
| Apple Secure Enclave (Touch ID) | [age-plugin-se](https://github.com/remko/age-plugin-se)                                  | No                                     | No                        |
| YubiKey                         | [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey)                        | No                                     | Yes, plug it in           |
| TPM 2.0                         | [age-plugin-tpm](https://github.com/Foxboron/age-plugin-tpm)                             | No                                     | No                        |
| FIDO2 key with hmac-secret      | [age-plugin-fido2-hmac](https://github.com/olastor/age-plugin-fido2-hmac) (experimental) | Unwrapped into memory while decrypting | Yes                       |

The plugin binary must be on your `PATH` wherever you decrypt.

### Apple Secure Enclave (Touch ID) {#apple-secure-enclave-touch-id}

Requires macOS 14 or later on a Mac with a Secure Enclave.

```sh
brew install age-plugin-se
age-plugin-se keygen --access-control=any-biometry -o ~/.config/fnox/age-se.txt
# prints: Public key: age1se1...
```

```toml
# ~/.config/fnox/config.toml
[providers.sync-age]
type = "age"
recipients = ["age1se1..."]
key_file = "~/.config/fnox/age-se.txt"
```

Sync again, and reads now go through the Secure Enclave. Whether you are asked for Touch ID depends on the `--access-control` policy you chose. `age-se.txt` is a reference to the key, not the key itself.

If `FNOX_AGE_KEY` is set in your environment, unset it: it takes precedence over `key_file`.

### YubiKey {#yubikey}

With [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) set up, use its recipient and identity:

```toml
[providers.sync-age]
type = "age"
recipients = ["age1yubikey1..."]
key_file = "~/.config/fnox/age-yubikey.txt" # from age-plugin-yubikey --identity
```

Decrypting requires the YubiKey to be plugged in.

### TPM and FIDO2 {#tpm-and-fido2}

```sh
age-plugin-tpm --generate --pin -o ~/.config/fnox/age-tpm.txt
age-plugin-tpm -y ~/.config/fnox/age-tpm.txt           # public key (age1tag1...)

age-plugin-fido2-hmac -g > ~/.config/fnox/age-fido2.txt # public key is in a comment
```

Put the public key in `recipients` and the identity file in `key_file`. Identities generated with `--tpm-recipient` use the older `age1tpm1...` form; fnox accepts both.

**Use `--pin` for TPM keys.** Without it, any process running as your user can decrypt with the TPM key: the key can't leave the machine, but nothing stops a stray script or local malware from reading the cache. With a PIN, fnox asks for it:

- once per distinct ciphertext per command. Everything one `fnox sync` run writes shares a single wrapped key, so reading the whole cache costs one prompt. A value stored separately with `fnox set`, such as a [vault token](#protect-the-vault-credential), adds a prompt only when a command needs it.
- once per daemon session, if the [daemon](/guide/daemon) is on. Values with `daemon_cache = false` still prompt on every command.

::: warning
age-plugin-tpm also reads the PIN from `AGE_TPM_PIN`. Exporting it in your shell hands the PIN to every process and undoes the protection. Use it only for non-interactive testing.
:::

### Native YubiKey and FIDO2 providers

fnox also has built-in [`yubikey`](/providers/yubikey) and [`fido2`](/providers/fido2) providers that need no plugin. They derive a symmetric key from the token, so:

- the token must be present for `fnox sync` itself, not only for reads;
- only that one token can decrypt (no backup recipient);
- the config is portable: any machine with the token can decrypt.

Age plugins encrypt to a public key, so syncing doesn't touch the hardware and you can list a backup recipient. Pick native providers to avoid installing plugins, or age plugins for backup keys and hardware-free syncing.

## Protect the vault credential {#protect-the-vault-credential}

Some providers authenticate with a long-lived token instead of an interactive login: a Doppler or Infisical service token, a Vault token, a Bitwarden Secrets Manager access token. Exporting it in your shell profile puts it in plain text in every process you start, including scripts and coding agents that never need it. Keep it in the same hardware-backed cache instead, and let fnox hand it to the provider.

This example uses Doppler and the PIN-protected TPM key from above. It works with any provider field that accepts [`{ secret = "NAME" }`](/guide/config-files#secret-references-in-provider-config).

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

Store the token in the gitignored local file. fnox prompts for it with hidden input:

```sh
fnox -c fnox.local.toml set DOPPLER_TOKEN --provider sync-age
```

Then add `env = false` by hand, so fnox uses the token to reach Doppler but never injects it into your shell or commands:

```toml
# fnox.local.toml (gitignored)
[secrets]
DOPPLER_TOKEN = { provider = "sync-age", value = "YWdl...", env = false } # ciphertext, abbreviated
```

Finally, sync the project into the same cache:

```sh
fnox sync --provider sync-age --local-file
```

Now everything on disk is ciphertext for a key that can't leave the machine, and the token never enters any environment. Values served from the cache don't decrypt the token at all; it is only used when a secret has to be fetched from Doppler.

If the machine is lost or its TPM is reset, nothing can decrypt the cache or the token. Revoke the token in Doppler, issue a new one, store it again, and sync. The vault is still the source of truth.

### Keep production out of the daemon {#keep-production-out-of-the-daemon}

To keep the [daemon](/guide/daemon)'s single prompt per session for development while requiring the PIN on every production command, give production its own profile and set `daemon_cache = false` on **both** its age provider and its remote provider. The first keeps the decrypted token out of the cache; the second keeps the fetched production values out.

::: warning Move the development cache into its own profile first
A top-level secret in `fnox.local.toml` overrides that secret in every profile (see [local overrides](/guide/config-files#local-overrides)). If the development cache stays under top-level `[secrets]`, `fnox --profile production` reads cached development values instead of fetching from Doppler's production config. Put development under a `development` profile, or run production commands with `--no-defaults`.
:::

Development, scoped to a profile:

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

```sh
fnox --profile development -c fnox.local.toml set DOPPLER_TOKEN --provider sync-age
fnox --profile development sync --provider sync-age --local-file
```

Both land under `[profiles.development.secrets]` in `fnox.local.toml`; add `env = false` to the token as before. Set `FNOX_PROFILE=development` to make it your everyday profile.

Production gets its own age provider, remote provider, and token:

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
DOPPLER_TOKEN = { provider = "prod-age", value = "YWdl...", env = false } # ciphertext, abbreviated
```

Production isn't synced, so each `fnox --profile production exec` asks for the PIN, decrypts the production token, and fetches fresh values from Doppler.

## Sync versus the daemon

Both make remote secrets fast. Sync stores encrypted copies on disk that survive restarts and work offline. The [daemon](/guide/daemon) keeps resolved values in memory for a session, needs no setup beyond turning it on, and forgets everything when it stops. You can use both.

## In CI

Skip it. CI runners are ephemeral and can read the vault directly with a service credential. See [CI/CD](/guide/ci).

## See also

- [Use an existing vault](/guide/existing-vault): the full vault-plus-cache setup.
- [`fnox sync` reference](/cli/sync): every flag.
- [age provider](/providers/age): identities, SSH keys, and plugins.
