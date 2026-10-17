---
description: "How fnox finds and merges config files: parent directories, profile files, gitignored local overrides, the global config, and imports."
---

# Config files

fnox merges several files into one configuration. This lets a monorepo share providers at the root, each service add its own secrets, and each developer keep personal overrides out of git.

## Which files are loaded

From the current directory, fnox walks up toward the filesystem root and loads every config it finds, plus your global config. Later files override earlier ones:

| Order | File                                                 | Committed?     |
| ----- | ---------------------------------------------------- | -------------- |
| 1     | `~/.config/fnox/config.toml` (global)                | No, personal   |
| 2     | `fnox.toml` in the outermost parent directory        | Yes            |
| 3     | `fnox.<profile>.toml` there, for each active profile | Yes            |
| 4     | `fnox.local.toml` there                              | No, gitignored |
| …     | the same three files in each directory closer to you |                |
| last  | `fnox.local.toml` in the current directory           | No, gitignored |

So a closer directory always beats its parent, and within one directory `fnox.local.toml` beats profile files, which beat `fnox.toml`.

Each file can also be hidden (`.fnox.toml`, `.fnox.local.toml`) or live in a `.config/` directory (`.config/fnox.toml`, `.config/fnox.staging.toml`, `.config/fnox.local.toml`). They work the same. If a directory has more than one form, `fnox.toml` loads first, then `.fnox.toml`, then `.config/fnox.toml`.

See what is loaded, in order:

```sh
fnox config-files
fnox list --sources   # which file defined each secret
```

## A monorepo example

```text
project/
├── fnox.toml            # providers and shared secrets
└── services/
    ├── api/
    │   └── fnox.toml    # API secrets
    └── worker/
        └── fnox.toml    # worker secrets
```

```toml
# project/fnox.toml
[providers.age]
type = "age"
recipients = ["age1..."]

[secrets]
LOG_LEVEL = { default = "info" }
JWT_SECRET = { provider = "age", value = "YWdl..." }
```

```toml
# project/services/api/fnox.toml
[secrets]
DATABASE_URL = { provider = "age", value = "YWdl..." }
LOG_LEVEL = { default = "debug" }
```

From `services/api/`, fnox sees `JWT_SECRET` from the root, `DATABASE_URL` from the API, and `LOG_LEVEL = "debug"`. From `services/worker/`, `LOG_LEVEL` stays `info`.

To stop the upward search at a directory, set `root = true` in its `fnox.toml`. The global config still loads.

## Merging rules

- **Secrets** merge by name. A closer file's definition of `DATABASE_URL` replaces the whole definition from a parent.
- **Providers** merge by name, and each provider is replaced as a unit. A `[providers.age]` in `fnox.local.toml` does not add fields to the committed `[providers.age]`; it replaces it. Give personal providers a distinct name such as `sync-age`.
- **Top-level settings** such as `default_provider` and `if_missing` take the closest value.

## Local overrides {#local-overrides}

`fnox.local.toml` is for things that should never be committed: personal values, a local database URL, or the encrypted cache that [`fnox sync`](/guide/sync) writes. Add it to `.gitignore`:

```sh
printf 'fnox.local.toml\n.fnox.local.toml\n' >> .gitignore
```

```toml
# fnox.local.toml
[secrets]
DATABASE_URL = { default = "postgresql://localhost/alice_dev" }
```

`default` values are plaintext. For a sensitive personal value, use an encryption provider or a vault reference here too.

## Profile files {#profile-files}

`fnox.staging.toml` is loaded only when the `staging` profile is active. Write its settings at the top level, as you would in `fnox.toml`, not under `[profiles.staging]`. It is a way to keep each environment in its own committed file instead of `[profiles.*]` sections. With several active profiles, their files load in the order the profiles were given. `fnox.default.toml` is never loaded.

## Global config {#global-config}

`~/.config/fnox/config.toml` (or `$FNOX_CONFIG_DIR/config.toml`) is the base layer for every project. Use it for personal providers, such as the age key behind your sync cache, and for tokens you want everywhere:

```sh
fnox init --global
fnox provider add sync-age age --global
fnox set GITHUB_TOKEN --global --provider sync-age
```

## Imports

`import` pulls other files into a config explicitly, regardless of directory. Paths are relative to the importing file, and the importing file's own settings win:

```toml
import = ["../shared/providers.toml", "./envs/common.toml"]
```

Use directory layering for "everything under this folder", and imports for a shared bundle that several unrelated projects use.

## Use one file only

Pass an explicit path to skip the directory search and local overrides:

```sh
fnox -c ./fnox.toml check --all
```

fnox then loads that file, its imports, and the global config. This is useful for checking exactly what is committed.

## Secret references in provider config {#secret-references-in-provider-config}

Many provider fields accept `{ secret = "NAME" }` instead of a literal, so a provider's own credential can be stored as a secret:

```toml
[providers.vault]
type = "vault"
address = "https://vault.example.com:8200"
token = { secret = "VAULT_TOKEN" }

[secrets]
VAULT_TOKEN = { provider = "age", value = "YWdl...", env = false }
DATABASE_URL = { provider = "vault", value = "database/password" }
```

fnox resolves `VAULT_TOKEN` first (from config, then the environment), then uses it to configure the provider. Cycles are reported as errors.

## See also

- [Profiles](/guide/profiles): environment overrides within a file.
- [Configuration reference](/reference/configuration): every field.
- [Troubleshooting](/guide/troubleshooting#the-wrong-value-is-being-loaded): when the wrong value wins.
