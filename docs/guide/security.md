---
description: "Understand what fnox protects, which code and systems you need to trust, and how to report a vulnerability privately."
---

# Security and threat model

fnox helps keep plaintext secrets out of source control. With an encryption provider, the config stores ciphertext. With a vault provider, it stores references and the provider controls who can read the values. Plain values and defaults are not encrypted; use them only for non-sensitive settings.

A [local sync cache](/guide/sync) stores an encrypted copy that fnox can read without contacting the vault. Revoking vault access does not invalidate a copy that someone can still decrypt. To stop a synced credential from working, revoke or rotate it in the service that accepts it.

## What you need to trust

- **Project config and code.** Review the [config files and imports](/guide/config-files) before running fnox or loading secrets through [shell integration](/guide/shell-integration) in an unfamiliar checkout. Project config can select providers and plugins, and project code can read the secrets you give it.
- **Plugins and provider tools.** [Lua plugins](/providers/lua) and provider CLIs run with the permissions of the account running fnox. Use sources you trust, pin shared plugins to a reviewed commit, and give provider credentials only the access they need.
- **Your provider and machine.** fnox does not override provider permissions or protect secrets from a compromised workstation or CI runner. Protect your encryption keys and provider credentials. The optional [daemon](/guide/daemon) can keep resolved values in memory; set a cache lifetime or disable caching where that does not fit your needs.

## When a secret leaves fnox

[`fnox exec`](/guide/running-commands) gives the command selected secrets in its environment or as readable temporary files. The command can read, copy, or pass them on to child processes. `fnox get` and `fnox export` can write plaintext to stdout. Prefer passing only the secrets a trusted command needs, and avoid putting real values in command arguments, logs, config defaults, or exported files.

In [CI](/guide/ci), keep credentials out of jobs that run untrusted code, including code from forks. Use a separate, narrowly scoped CI identity and short-lived credentials when your provider supports them. Log masking and fnox output redaction can reduce accidental exposure, but they do not restrict what a command can do with a secret.

## Reporting a vulnerability

Use [Report a vulnerability on GitHub](https://github.com/jdx/fnox/security/advisories/new) rather than a public issue or discussion. Include your fnox version and platform, the command and provider involved, what you expected to be protected, and what happened. Share only the relevant, redacted config and output. Do not include real secrets, credentials, or private keys.
