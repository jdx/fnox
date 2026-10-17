---
description: "Store secrets in the macOS Keychain, Windows Credential Manager, or Linux Secret Service, and use one to hold an age identity."
---

# OS keychain

The `keychain` provider stores values in your operating system's credential store. `fnox.toml` holds only the entry name; `fnox set` writes the value to the keychain.

|                     |                                                                                |
| ------------------- | ------------------------------------------------------------------------------ |
| Config type         | `keychain`                                                                     |
| Storage             | Local store                                                                    |
| Writes (`fnox set`) | Yes                                                                            |
| Requires            | macOS Keychain, Windows Credential Manager, or a Linux Secret Service on D-Bus |

On Linux, fnox talks to the Secret Service API directly over D-Bus, so you need a Secret Service implementation such as GNOME Keyring or KWallet running. No libsecret packages are required. macOS and Windows need no setup.

## Quick start

```toml
[providers.keychain]
type = "keychain"
service = "fnox"
```

```sh
fnox set GITHUB_TOKEN --provider keychain
fnox provider test keychain
fnox exec -- ./release.sh
```

`fnox set` stores the entry under the secret's name and records that name in `fnox.toml`:

```toml
[secrets]
GITHUB_TOKEN = { provider = "keychain", value = "GITHUB_TOKEN" }
```

Use `--key-name` to choose a different entry name.

## Authentication

Access belongs to the current OS user and requires an unlocked credential store. macOS may show an access prompt for each keychain item. fnox reads entries one at a time so those prompts never overlap.

The provider needs a desktop session or an unlocked Secret Service, which CI runners and containers usually lack. Prefer [age](/providers/age) or a cloud provider there. You can provision one yourself; fnox's own Linux CI runs `gnome-keyring-daemon --unlock --components=secrets --daemonize`, but that means keeping the unlock password in CI.

## Configuration

| Field     | Required | Default | Description                                                                                            |
| --------- | -------- | ------- | ------------------------------------------------------------------------------------------------------ |
| `service` | Yes      | None    | Service name for every entry; isolates fnox's entries from other applications.                         |
| `prefix`  | No       | None    | String prepended to each entry name. With `prefix = "myapp/"`, `api-key` is stored as `myapp/api-key`. |

Both fields accept `{ secret = "NAME" }`. Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

## Reference formats

| `value`                            | Keychain entry read                        |
| ---------------------------------- | ------------------------------------------ |
| `api-key`                          | Service `service`, account `api-key`       |
| `api-key` with `prefix = "myapp/"` | Service `service`, account `myapp/api-key` |

The entry holds the value as a single string. On macOS it appears in Keychain Access under the service name; on Windows, in Credential Manager under Windows Credentials.

## Hold an age identity

The keychain works best for a few bootstrap secrets rather than every value. Store one age private key in the keychain and encrypt the rest with [age](/providers/age), so a project with many secrets touches the keychain once:

```toml
[providers.keychain]
type = "keychain"
service = "fnox"

[providers.age]
type = "age"
recipients = ["age1..."]
identity = { provider = "keychain", value = "age-key" }

[secrets]
DATABASE_URL = { provider = "age", value = "YWdl..." } # ciphertext, abbreviated
API_KEY = { provider = "age", value = "YWdl..." }      # ciphertext, abbreviated
```

To store the identity, run the command below and paste the `AGE-SECRET-KEY-1...` line from your key file at the hidden prompt:

```sh
fnox set AGE_IDENTITY --provider keychain --key-name age-key
```

Then delete the `AGE_IDENTITY` entry from `[secrets]`, or add `env = false` to it, so `fnox exec` does not export the private key to your commands. Losing the keychain item is recoverable from any machine that holds the same age identity.

Other good candidates are tokens that unlock remote providers, such as a 1Password service account token.

## Troubleshooting

### No OS keyring backend is available

On Linux, no Secret Service is reachable. Start one (for example `gnome-keyring-daemon --start --components=secrets`), and check that `DBUS_SESSION_BUS_ADDRESS` is set in the fnox process.

### Keychain is locked or access is denied

Unlock the login keychain or Secret Service collection, then accept the access prompt. `fnox provider test keychain` writes, reads, and deletes a `__fnox_test__` entry to check access.

### Entry not found

The entry does not exist under this `service` (and `prefix`). Check the service and account name in Keychain Access, Credential Manager, or Seahorse, or store it again with `fnox set`.

## See also

- [age](/providers/age): encrypt the bulk of your secrets with a keychain-held identity.
- [Configuration files](/guide/config-files): keep machine-specific providers in `fnox.local.toml`.
- [1Password](/providers/1password): a shared password manager for teams.
