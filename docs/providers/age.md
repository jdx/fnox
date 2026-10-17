---
description: "Encrypt secrets into fnox.toml with age recipients, SSH keys, or age plugins. Choose a decryption identity and share access with a team."
---

# age

The `age` provider encrypts values into `fnox.toml` with [age](https://age-encryption.org). Anyone with a matching identity (an age key, a supported SSH private key, or an age plugin identity) can decrypt them, offline and without a cloud account. `fnox set` writes new ciphertext.

|                     |                                                                 |
| ------------------- | --------------------------------------------------------------- |
| Config type         | `age`                                                           |
| Storage             | Encrypted in config                                             |
| Writes (`fnox set`) | Yes                                                             |
| Requires            | An age identity; `age-plugin-*` on `PATH` for plugin recipients |

## Quick start

The [quick start](/guide/quick-start) walks through a complete first setup. In short, generate a key with the age CLI and print its public recipient:

```sh
mkdir -p ~/.config/fnox
age-keygen -o ~/.config/fnox/age.txt
age-keygen -y ~/.config/fnox/age.txt
```

Add the recipient (it starts with `age1`) to `fnox.toml`:

```toml
[providers.age]
type = "age"
recipients = ["age1..."]
```

Store a value through the hidden prompt, then use it:

```sh
fnox set DATABASE_URL --provider age
fnox provider test age
fnox exec -- npm start
```

`recipients` takes public keys only. Never paste a private key (`AGE-SECRET-KEY-...`) into it.

## Decryption identity {#set-decryption-key}

Encryption needs only the public recipients. To decrypt, fnox uses the first identity it finds, in this order:

1. `FNOX_AGE_KEY` (inline identity contents).
2. The provider's `identity` reference.
3. The provider's `key_file`.
4. The key-file setting (`FNOX_AGE_KEY_FILE` or the deprecated `--age-key-file` flag).
5. `age.txt` in the fnox configuration directory (`~/.config/fnox/age.txt` by default; see [`FNOX_CONFIG_DIR`](/reference/environment#fnox-config-dir)).

An exported `FNOX_AGE_KEY` overrides every provider-specific setting.

### Local development

Keep your key at the default path, or point the provider at it with `key_file`. To decrypt with an SSH key instead, set the key-file path:

```sh
export FNOX_AGE_KEY_FILE=~/.ssh/id_ed25519
```

### CI

Generate a dedicated key for CI, add its public recipient to `recipients`, run `fnox reencrypt -p age`, and store the private key in your CI secret store as `FNOX_AGE_KEY`:

```yaml
- name: Run tests with secrets
  env:
    FNOX_AGE_KEY: ${{ secrets.FNOX_AGE_KEY }}
  run: fnox exec -- npm test
```

See [CI/CD](/guide/ci) for non-interactive runs and pull requests from forks.

## Configuration

| Field        | Required | Default | Description                                                                                                        |
| ------------ | -------- | ------- | ------------------------------------------------------------------------------------------------------------------ |
| `recipients` | Yes      | None    | Public recipients to encrypt to: `age1...` keys, `ssh-ed25519` or `ssh-rsa` public keys, or age plugin recipients. |
| `key_file`   | No       | None    | Path to an identity file: an age key, SSH private key, or plugin identity. Accepts `{ secret = "NAME" }`.          |
| `identity`   | No       | None    | A `{ provider = "...", value = "..." }` reference that resolves to the identity contents through another provider. |

Relative `key_file` paths are resolved from the config file that declares the provider. Paths beginning with `~` expand to your home directory, and absolute paths are used unchanged.

Every provider also accepts [`auth_command` and `daemon_cache`](/reference/configuration#provider-configuration).

Store the identity in another provider, such as the [OS keychain](/providers/keychain), so it never sits in a file:

```toml
[providers.keychain]
type = "keychain"
service = "fnox"

[providers.age]
type = "age"
recipients = ["age1..."]
identity = { provider = "keychain", value = "age-key" }
```

The `identity` reference cannot point at the age provider that uses it.

## How values are stored

`fnox set` encrypts the value to every recipient and stores the base64-encoded age file as the secret's `value`:

```toml
[secrets]
DATABASE_URL = { provider = "age", value = "YWdlLWVuY3J5cHRpb24ub3Jn..." } # ciphertext, abbreviated
```

The ciphertext is safe to commit. Typing a plaintext string into `value` by hand does not encrypt it; let `fnox set` generate the ciphertext.

`fnox reencrypt` and `fnox sync` encrypt each group of secrets with one shared key, which is itself encrypted to the recipients. Values in this form start with `fnox-age-batch-v1:`. Resolving them through `fnox exec` unlocks the shared key once, so a hardware-backed identity asks for one approval instead of one per secret. To consolidate separately encrypted values, including secrets added with `fnox set`, run:

```sh
fnox reencrypt --provider age
```

The command uses the provider's current recipients and preserves each secret's source file and profile. Decrypting the existing values during re-encryption can still require multiple hardware approvals. Key or `--filter` arguments consolidate only the selected secrets.

## SSH keys

Use an existing SSH public key as a recipient and the matching private key to decrypt. Supported key types are `ssh-ed25519` and `ssh-rsa`.

```toml
[providers.age]
type = "age"
recipients = [
  "ssh-ed25519 AAAAC3Nza... alice@example.com",
  "ssh-rsa AAAAB3Nza... bob@example.com",
]
```

Point fnox at the private key with `key_file` or `FNOX_AGE_KEY_FILE`.

::: warning Password-protected SSH keys
Password-protected SSH keys are not supported by this integration. Generate a dedicated age identity or use a supported age plugin instead of removing the passphrase from your SSH key.
:::

## Plugin support

Age plugins add hardware-backed and alternative identities, such as [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) (YubiKey PIV) or [age-plugin-se](https://github.com/remko/age-plugin-se) (Apple Secure Enclave). fnox works with any [age plugin](https://github.com/FiloSottile/awesome-age#plugins): it runs the matching `age-plugin-<name>` binary from your `PATH` to encrypt and decrypt.

Plugin recipients usually carry the plugin name in their prefix (`age1yubikey1...`), though not always; current age-plugin-tpm releases produce `age1tag1...` recipients, for example.

```toml
[providers.age]
type = "age"
recipients = ["age1yubikey1..."]
key_file = "~/.config/fnox/yubikey-identity.txt"
```

Within one command, fnox decrypts each ciphertext once, so a PIN or touch prompt is not repeated when several secrets or providers share a value. Refer to each plugin's documentation for setup. [Syncing secrets locally](/guide/sync) has walkthroughs for Secure Enclave, YubiKey, TPM, and FIDO2 plugins.

## Team workflow

Encrypt each secret to every teammate's public key. Anyone whose recipient was included can decrypt with their own private key.

1. Each person shares their public recipient:

   ```sh
   age-keygen -y ~/.config/fnox/age.txt   # age key
   cat ~/.ssh/id_ed25519.pub              # SSH key
   ```

2. List every recipient on the provider:

   ```toml
   [providers.age]
   type = "age"
   recipients = [
     "ssh-ed25519 AAAAC3Nza...", # alice
     "ssh-ed25519 AAAAC3Nza...", # bob
     "age1...",                  # ci
   ]
   ```

3. Encrypt secrets with `fnox set KEY --provider age` and commit `fnox.toml`.

Each teammate decrypts with an identity from the [selection order](#set-decryption-key) above. See [Teams](/guide/teams) for onboarding and offboarding across providers.

### Adding a new team member

Adding a recipient does not update existing ciphertext. After adding the new public key to `recipients`, re-encrypt:

```sh
fnox reencrypt -p age --dry-run   # preview
fnox reencrypt -p age
```

`reencrypt` works on the selected profile. Repeat it for each profile that has age secrets, with `-f` to skip the confirmation:

```sh
fnox reencrypt -p age -P staging -f
fnox reencrypt -p age -P production -f
```

Commit the updated `fnox.toml`. The new member can decrypt after pulling.

### Removing a team member

Remove their recipient and run `fnox reencrypt` for each affected profile. Re-encryption cannot revoke access to old ciphertext in git history; rotate the underlying secret if that person's access must end.

## Troubleshooting

### `no identity matched any of the recipients`

Your identity does not match any recipient the value was encrypted to. Compare your public key with the provider's `recipients`, then ask a teammate who can decrypt to add you and run `fnox reencrypt`:

```sh
age-keygen -y ~/.config/fnox/age.txt
grep -A5 recipients fnox.toml
```

### Identity file not found

No identity was found in the [selection order](#set-decryption-key). Set `FNOX_AGE_KEY`, `key_file`, or `FNOX_AGE_KEY_FILE`, or create `age.txt` in the fnox configuration directory, and check that the file is readable.

### SSH key not working

Check that the key type is `ssh-ed25519` or `ssh-rsa`, that the path points at the private key (not the `.pub` file), and that the key is not password-protected.

### Age plugin not found

Plugin recipients and identities need the `age-plugin-<name>` binary on `PATH`. Run `which age-plugin-yubikey` (or the plugin you use) in the same shell as fnox.

## See also

- [Quick start](/guide/quick-start): create a key and store your first secret.
- [Teams](/guide/teams): onboard and offboard people across providers.
- [Syncing secrets locally](/guide/sync): cache remote secrets under a personal age key.
- [`fnox reencrypt`](/cli/reencrypt): re-encrypt after recipient changes.
