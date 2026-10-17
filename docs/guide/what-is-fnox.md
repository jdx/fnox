---
description: "fnox loads secrets from encrypted files, password managers, and cloud secret stores into your commands, using one fnox.toml per project."
---

# What is fnox?

fnox is a command-line tool that gives your programs the secrets they need as environment variables. A `fnox.toml` file in your project lists each secret and where it lives: encrypted in the file itself, in a password manager, or in a cloud secret store. One command runs your program with those values:

```sh
fnox exec -- npm start
```

Your program reads `DATABASE_URL` or `STRIPE_KEY` the way it always has. It does not know or care where the value came from.

## The problem it solves

Most projects end up with secrets in several places: a `.env` file nobody is supposed to commit, a team vault, a CI secret store, and a cloud secret manager for production. Each one has its own CLI, its own login, and its own way of getting values into a process.

fnox puts the _description_ of those secrets in one committed file and handles the rest:

- **One file, many backends.** Each secret names its provider. Mix age-encrypted values, 1Password items, and AWS Secrets Manager references in the same project.
- **The same command everywhere.** `fnox exec -- <command>` works on your laptop, in CI, and in a deploy script. Only the credentials differ.
- **Nothing sensitive in git.** The file holds ciphertext or references, never plaintext secrets.

## Two ways to store secrets

|                          | Encrypted in `fnox.toml`                           | Referenced from a vault                                    |
| ------------------------ | -------------------------------------------------- | ---------------------------------------------------------- |
| What's committed         | Ciphertext                                         | The name or path of the item                               |
| To read a value you need | A private key (age, a YubiKey, or a cloud KMS key) | Access to the vault                                        |
| Good for                 | Small teams, no shared vault, offline use          | Teams that already use 1Password, Bitwarden, AWS, Vault, … |
| Start with               | [Quick start](/guide/quick-start)                  | [Use an existing vault](/guide/existing-vault)             |

You can combine them. A common setup reads development secrets from age-encrypted values and production secrets from a cloud secret manager, using [profiles](/guide/profiles) to switch between them. Non-sensitive settings such as `LOG_LEVEL` can sit in the same file as plaintext defaults.

See the [provider catalog](/providers/overview) for every supported backend.

## How your program gets the secrets

| You want to…                                                                    | Use                                                              |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Run one command with secrets                                                    | [`fnox exec`](/guide/running-commands)                           |
| Load secrets into your shell when you `cd` into a project                       | [Shell integration](/guide/shell-integration)                    |
| Give a tool a file path instead of a value (for example, a service-account key) | [`as_file = true`](/guide/running-commands#secrets-as-files)     |
| Let an AI agent call an API without seeing the key                              | [Credential proxy](/guide/proxy) or the [MCP server](/guide/mcp) |
| Hand short-lived cloud credentials to a command                                 | [Credential leases](/guide/leases)                               |

## When remote vaults are slow

Reading from a remote vault on every command can be slow, and it fails when you are offline. fnox has two optional caches:

- [**Sync**](/guide/sync) copies vault values into a gitignored file, encrypted to your personal age key. Reads are local and work offline.
- The [**daemon**](/guide/daemon) keeps resolved values in memory for your login session.

The vault stays the source of truth either way.

## See also

- [Quick start](/guide/quick-start): encrypt your first secret in five minutes.
- [How fnox works](/guide/how-it-works): config loading, resolution order, and the caches.
- [mise integration](/guide/mise-integration): install fnox and run tasks with secrets.
