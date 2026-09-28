---
description: "Diagnose configuration overrides, stale caches, authentication failures, age keys, and missing environment variables."
---

# Troubleshooting

Start by checking which configuration fnox loaded, then test the provider involved. These commands help narrow the problem without printing resolved secret values:

```sh
fnox --version
fnox config-files
fnox profiles
fnox list --sources
fnox doctor
```

## The wrong value is being loaded

Inspect the active profile and the files in the configuration stack:

```sh
fnox --profile staging config-files
fnox --profile staging list --sources
```

Closer directories override parent directories. At each level, profile-specific and local files can override the main file. A global config is also loaded. See [configuration layering](/guide/hierarchical-config).

To read only a particular project file and its imports, pass an explicit path:

```sh
fnox -c ./fnox.toml list --sources
```

This skips directory discovery and adjacent local overrides, but still loads the global config. See [explicit config paths](/reference/configuration#explicit-config-paths).

## A secret changed in the vault but fnox still returns the old value

Check both kinds of optional cache:

- **Encrypted local cache:** refresh it with `fnox sync --provider sync-age --local-file`. Use the name of your own sync provider.
- **Daemon memory cache:** clear it with `fnox daemon clear`, or bypass the daemon for one invocation with `fnox --no-daemon check --all`.

Bypassing the daemon does not remove a `sync` value from your config. Refresh the sync cache to fetch the current remote value. For a direct project-file check without local overrides, use `fnox -c ./fnox.toml --no-daemon check --all`.

## Authentication fails

Test a single configured provider by its instance name:

```sh
fnox provider test op
```

Then follow that [provider's authentication instructions](/providers/overview). CLI-backed providers need their CLI on `PATH`; API-backed providers need the appropriate credentials and permissions.

In a terminal, fnox can offer to run the provider's authentication command. `prompt_auth = false`, `FNOX_PROMPT_AUTH=false`, and `--non-interactive` affect prompting. For CI, supply non-interactive credentials before running fnox.

A provider connection test checks access to the service. `fnox check --all` also checks the configured secret references.

## Age cannot decrypt a secret

Check the [identity selection order](/providers/age#set-decryption-key). An exported `FNOX_AGE_KEY` takes precedence over the provider's `identity` and `key_file` settings.

Compare the public recipient derived from your private key with the provider's recipients:

```sh
age-keygen -y ~/.config/fnox/age.txt
```

Adding a recipient to the config does not update existing ciphertext. Someone who can already decrypt it must run `fnox reencrypt --provider age` for the affected profiles. See [adding a team member](/providers/age#adding-a-new-team-member).

## A command does not see a secret

Check the secret's [`env` setting](/reference/configuration#env-1):

- `true`: shell integration and `fnox exec`.
- `"exec"`: subprocess injection, excluded from the interactive shell.
- `false`: no normal environment injection; explicit reads and internal dependencies can still use it.

Shell expansion happens before fnox starts. To expand a secret inside the child, use a child shell and single quotes:

```sh
fnox exec -- sh -c 'test -n "$DATABASE_URL"'
```

An `as_file = true` secret supplies a file path, not the raw contents. Configure your application to read the file.

## Shell integration is not loading

Confirm you used the activation command for your actual shell and placed it in the right startup file. Fish, Nushell, and PowerShell do not use Bash's `eval` syntax. See [shell integration](/guide/shell-integration).

Try the same command through `fnox exec`. If that works, the problem is in shell activation or injection settings. Enable hook diagnostics with `FNOX_SHELL_OUTPUT=debug` while investigating.

## A write command asks for a profile

When multiple profiles are active, select a write target explicitly:

```sh
fnox -P aws,staging --write-profile staging set DATABASE_URL
```

Read commands compose the profiles in order. Write commands need one destination. See [profile composition](/guide/profiles#composing-multiple-profiles).

## Report an issue

Include the fnox version, OS, failing command, first substantive error, and a minimal configuration using dummy values. Describe the provider type and whether sync or daemon caching is enabled.

Review logs and config before attaching them: `fnox get`, `fnox export`, `fnox list --values`, and verbose provider tools may print secrets. Open an issue in the [GitHub tracker](https://github.com/jdx/fnox/issues).
