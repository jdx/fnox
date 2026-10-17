---
description: "Fix common fnox problems: the wrong value loads, a vault change doesn't show up, authentication fails, age can't decrypt, or a command doesn't see a secret."
---

# Troubleshooting

Start with these. None of them print secret values:

```sh
fnox doctor             # overall health check
fnox config-files       # which files are loaded, in order
fnox list --sources     # each secret, its provider, and which file defined it
fnox check --all        # does every secret resolve?
```

Add `--profile <name>` to each if you're debugging a profile.

## The wrong value is being loaded

Some config file is overriding the one you expect. Closer directories beat parent directories, and in each directory `fnox.local.toml` beats profile files, which beat `fnox.toml`. Your global config is loaded too. `fnox list --sources` shows which file won.

To see only what's committed in one file (plus its imports and the global config):

```sh
fnox -c ./fnox.toml list --sources
```

See [config files](/guide/config-files).

## I changed a secret in the vault, but fnox returns the old value

A cache is serving it.

- **Sync cache:** run `fnox sync --provider <your-sync-provider> --local-file --force`.
- **Daemon:** run `fnox daemon clear KEY`, or `fnox get --refresh KEY`.

`--no-daemon` bypasses the daemon but not the sync cache. To read straight from the provider, bypass both: `fnox -c ./fnox.toml --no-daemon get KEY`.

## Authentication fails

Test one provider by its name in your config:

```sh
fnox provider test op
```

Then check that provider's **Authentication** section in the [provider docs](/providers/overview). Providers that wrap a CLI (`op`, `bw`, `pass`, …) need it on your `PATH` and signed in; cloud providers need credentials from their usual SDK chain.

In a terminal, fnox offers to run the provider's login command for you. That's disabled by `prompt_auth = false`, `FNOX_PROMPT_AUTH=false`, `--non-interactive`, or when there's no terminal, as in CI. In CI, supply credentials up front; see [CI/CD](/guide/ci).

## age can't decrypt a secret

Usually your key isn't one of the recipients the value was encrypted to.

1. Print your public key and compare it with `recipients`:

   ```sh
   age-keygen -y ~/.config/fnox/age.txt
   ```

2. Check which key fnox is using. `FNOX_AGE_KEY` wins over the provider's `key_file`, which wins over `~/.config/fnox/age.txt`. A stray `FNOX_AGE_KEY` in your environment is a common cause. See [age decryption keys](/providers/age#set-decryption-key).
3. If your key was added to `recipients` recently, someone who could already decrypt must run `fnox reencrypt`. Adding a recipient doesn't change existing ciphertext. See [team setup](/guide/teams#add-someone).

## A command doesn't see a secret

- **Shell expansion.** `fnox exec -- echo $KEY` expands `$KEY` in your shell before fnox runs. Use `fnox exec -- sh -c 'echo "$KEY"'`.
- **The `env` setting.** `env = false` secrets are never injected; `env = "exec"` secrets aren't loaded into the interactive shell. See [choose which secrets reach a command](/guide/running-commands#choose-which-secrets-reach-a-command).
- **A file secret.** With `as_file = true`, the variable holds a path, not the contents.
- **A missing value.** With the default `if_missing = "warn"`, fnox prints a warning and starts the command without it. Run `fnox check --all`.

## Shell integration is not loading

- Make sure you used the activation line for your actual shell; Fish, Nushell, and PowerShell don't use `eval`. See [shell integration](/guide/shell-integration).
- Open a new terminal after editing the startup file.
- If `fnox exec -- env` shows the secret but the shell doesn't, check `env` settings, then run with `FNOX_SHELL_OUTPUT=debug` to see what the hook does.

## A write command asks which profile to use

With more than one active profile, `set`, `remove`, `import`, `sync`, and `provider add/remove` need a target:

```sh
fnox -P aws,staging --write-profile staging set DATABASE_URL
```

See [stacking profiles](/guide/profiles#stack-profiles-on-the-command-line).

## `fnox set` stored a plaintext value

Without a provider, `fnox set` writes a plaintext `default`. Pass `--provider <name>` or set `default_provider` in `fnox.toml`, then set the value again.

## Reporting a bug

Open an issue in the [tracker](https://github.com/jdx/fnox/issues) with your fnox version, OS, the failing command, the first error, and a minimal config using dummy values. Say which provider type you use and whether sync or the daemon is on.

Check what you paste: `fnox get`, `fnox export`, `fnox list --values`, and verbose provider output can contain secrets.
