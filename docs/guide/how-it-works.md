---
description: "The fnox model: secrets, providers, profiles, and config layers; how a value is resolved; and the three kinds of cache."
---

# How fnox works

This page explains the pieces fnox is built from and what happens when you run a command. You don't need it to get started, but it makes the rest of the docs easier to follow.

## The pieces

```toml
[providers.op]                 # a provider named "op"…
type = "1password"             # …of type 1password
vault = "Engineering"

[secrets]
DATABASE_URL = { provider = "op", value = "Database/url" }  # a secret
LOG_LEVEL = { default = "info" }                            # a plaintext default

[profiles.production.secrets]  # a profile that overrides DATABASE_URL
DATABASE_URL = { provider = "op", value = "Prod Database/url" }
```

**Secret.** A named value, defined under `[secrets]`. The name is the environment variable your program sees.

**Provider.** Where a secret's value comes from. You configure a provider once under `[providers.<name>]` and refer to it by that name. Its `type` selects the backend: `age`, `1password`, `aws-sm`, and [many more](/providers/overview).

**Value.** What the `value` field means depends on the provider:

- For an **encryption provider** (age, YubiKey, FIDO2, a cloud KMS), it is ciphertext that `fnox set` wrote. You never write it by hand.
- For a **storage provider** (a password manager, cloud secret store, or local keychain), it is a reference: the name or path of an item.

**Default.** A plaintext fallback, for non-sensitive settings or a local development value.

**Profile.** A named set of overrides under `[profiles.<name>]`, selected with `--profile` or `FNOX_PROFILE`. Profiles inherit the top-level secrets and providers. See [profiles](/guide/profiles).

**Config layers.** fnox merges several files: a global config, `fnox.toml` files in parent directories, the project's `fnox.toml`, profile files such as `fnox.staging.toml`, and gitignored `fnox.local.toml` overrides. See [config files](/guide/config-files).

## What happens when you run `fnox exec`

```sh
fnox exec -- npm start
```

1. **Load config.** fnox finds and merges the config layers for the current directory.
2. **Pick the profile.** It applies the selected profile on top of the top-level definitions.
3. **Resolve each secret.** It decrypts ciphertext or fetches references, batching requests to the same provider. Cached values are used when available (see below).
4. **Prepare the environment.** It applies `json_path` or `line` selectors, writes `as_file` secrets to temporary files, and creates any configured [credential leases](/guide/leases).
5. **Run the command** with those variables added to the inherited environment, then clean up temporary files when it exits.

Your shell is never modified. Each secret's [`env` setting](/reference/configuration#env-1) decides whether it is injected into commands, the interactive shell, both, or neither.

## Resolution order

For each secret, fnox uses the first of these that produces a value:

1. **Sync cache.** If `fnox sync` stored an encrypted copy, fnox decrypts that instead of calling the original provider.
2. **Provider.** The configured provider and `value`.
3. **Default.** The `default` field. It is also used if the provider lookup fails. Defaults can [reference other secrets](/reference/configuration#default).
4. **Environment.** An environment variable of the same name that is already set.

A provider _error_ (access denied, network failure, item not found) is different from having no value. If the provider fails and the secret has no `default`, fnox reports the error and does not fall back to the environment.

If none of these produces a value, the secret's [`if_missing`](/guide/missing-secrets) policy decides whether the command fails, warns, or continues.

## Three kinds of cache

All three are optional, and they solve different problems.

|           | [Sync](/guide/sync)                 | [Daemon](/guide/daemon)                                     | [Lease ledger](/guide/leases)               |
| --------- | ----------------------------------- | ----------------------------------------------------------- | ------------------------------------------- |
| Stores    | Encrypted copies of vault values    | Resolved values                                             | Short-lived credentials                     |
| Where     | `fnox.local.toml`                   | Memory of a per-user process                                | `~/.local/state/fnox/leases/`               |
| Lasts     | Until you sync again                | Until idle timeout, `fnox daemon clear`, or a config change | Until the credential nears expiry           |
| Use it to | Read vault secrets offline and fast | Avoid repeated remote reads during a session                | Reuse temporary credentials across commands |

## Inspect what fnox sees

```sh
fnox config-files     # which files were loaded, in order
fnox profiles         # which profiles exist
fnox list --sources   # each secret, its provider, and the file that defined it
fnox check --all      # can every secret be resolved?
```

None of these print secret values. See [troubleshooting](/guide/troubleshooting) when the results surprise you.

## See also

- [Configuration reference](/reference/configuration): every field in `fnox.toml`.
- [Running commands](/guide/running-commands): `exec`, `get`, `export`, and file secrets.
- [Provider catalog](/providers/overview): choose where secrets live.
