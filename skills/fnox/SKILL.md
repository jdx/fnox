---
name: fnox
description: Configure fnox secret providers and profiles, inject secrets into commands, and diagnose missing secrets or authentication failures. Use for fnox.toml and fnox CLI workflows.
---

# fnox

Use the project's existing providers and profiles. Check `fnox --version` and
`fnox <command> --help` when installed behavior differs from these examples.

## Find the effective configuration

Run from the directory where the application runs:

```sh
fnox config-files
fnox list --sources
fnox profiles
```

`list` describes configured secrets, not every item in a remote vault. Values
are hidden unless `--values` is requested. Avoid `get`, `export`, and
`list --values` for routine inspection: they expose resolved secrets.

Global config is the base. At each directory, project config, profile-specific
config, and local overrides merge in that order; closer directories win over
parents. `-c ./fnox.toml` skips directory discovery and adjacent local overrides,
but still loads global config and the file's imports.

`-P staging` selects a profile. Repeated `-P` flags compose profiles with later
ones winning; write commands then need `--write-profile` to select their target.
Top-level secrets remain included unless `--no-defaults` is set.

## Configure and store secrets

`fnox init --skip-wizard` creates a minimal config; it does not enable encryption.
Before `fnox set`, select a configured provider: with no provider, `set` writes a
plaintext default. `default` values are always plaintext, including when other
secrets use encryption.

For a new local encrypted setup, use an age provider with the user's public
recipient, keeping its private key outside the repository:

```toml
#:schema https://fnox.jdx.dev/schema.json
default_provider = "age"

[providers.age]
type = "age"
recipients = ["age1..."] # Replace with an actual public recipient
```

fnox reads `age.txt` from its config directory by default. Reuse an existing key;
use the [age guide](https://fnox.jdx.dev/providers/age) for key creation, alternate
locations, or team recipients.

```sh
fnox set DATABASE_URL --provider age
fnox set SSH_PRIVATE_KEY --provider age --from-file ~/.ssh/id_ed25519
```

Omitting the value prompts with hidden input in a terminal or reads piped stdin.
Use those paths or `--from-file` instead of putting secret values in command
arguments, generated scripts, or transcripts. Encryption providers store
ciphertext in config; storage providers store references. Preserve that
distinction when editing `value` fields. Provider fields and reference formats
vary; consult the [provider guide](https://fnox.jdx.dev/providers/overview)
instead of guessing. Keep `fnox.local.toml`, `.fnox.local.toml`, and private keys
out of version control.

## Inject and verify

```sh
fnox check --all
fnox exec -- npm start
fnox exec --profile staging --if-missing error -- ./app
fnox exec -- sh -c 'test -n "$DATABASE_URL"'
```

Put fnox options before `--`; arguments after it belong to the child command.
Single quotes defer shell expansion until the child receives the secret.
`exec` changes the child environment, not the parent shell. Use `--replace`
only when process replacement is needed; it cannot clean up file secrets or
credential leases.

`check` normally checks required secrets; `--all` also checks secrets configured
to warn or ignore when missing. It resolves secrets without printing their
values. For unattended commands, add `--non-interactive` to prevent prompts and
browser authentication flows; provider credentials must already be available.

For profile-specific diagnosis, set `FNOX_PROFILE` for both commands:

```sh
FNOX_PROFILE=staging fnox config-files
FNOX_PROFILE=staging fnox list --sources
```

`config-files` currently selects profiles from the environment and does not honor
`-P`; using only that flag can show a different file set from `list --sources`.
Use the same profile environment for `fnox doctor`, `fnox provider test <name>`,
and `fnox check --all` to distinguish configuration, authentication, and
resolution problems. Preserve redaction when reporting results; verify presence
or command success without echoing a credential.
