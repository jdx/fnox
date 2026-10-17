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
age-plugin-tpm --generate -o ~/.config/fnox/age-tpm.txt
age-plugin-tpm -y ~/.config/fnox/age-tpm.txt           # public key (age1tag1...)

age-plugin-fido2-hmac -g > ~/.config/fnox/age-fido2.txt # public key is in a comment
```

Put the public key in `recipients` and the identity file in `key_file`.

### Native YubiKey and FIDO2 providers

fnox also has built-in [`yubikey`](/providers/yubikey) and [`fido2`](/providers/fido2) providers that need no plugin. They derive a symmetric key from the token, so:

- the token must be present for `fnox sync` itself, not only for reads;
- only that one token can decrypt (no backup recipient);
- the config is portable: any machine with the token can decrypt.

Age plugins encrypt to a public key, so syncing doesn't touch the hardware and you can list a backup recipient. Pick native providers to avoid installing plugins, or age plugins for backup keys and hardware-free syncing.

## Sync versus the daemon

Both make remote secrets fast. Sync stores encrypted copies on disk that survive restarts and work offline. The [daemon](/guide/daemon) keeps resolved values in memory for a session, needs no setup beyond turning it on, and forgets everything when it stops. You can use both.

## In CI

Skip it. CI runners are ephemeral and can read the vault directly with a service credential. See [CI/CD](/guide/ci).

## See also

- [Use an existing vault](/guide/existing-vault): the full vault-plus-cache setup.
- [`fnox sync` reference](/cli/sync): every flag.
- [age provider](/providers/age): identities, SSH keys, and plugins.
