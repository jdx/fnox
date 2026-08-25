# What is fnox?

fnox is a secrets management tool that works with both encrypted secrets in git and remote cloud providers.

## The Problem

Secrets are typically done in 2 ways:

1. **In git, encrypted** (hopefully)
2. **Remote**, typically a cloud provider like AWS Secrets Manager

## The Solution

fnox works with either—or both! They've got their pros and cons. Either way, fnox gives you a nice front-end to manage secrets and make them easy to work with in dev/ci/prod.

fnox's config file, `fnox.toml`, will either contain the encrypted secrets, or a reference to a secret in a cloud provider. You can either use `fnox exec -- <command>` to run a command with the secrets, or you can use the [shell integration](/guide/shell-integration) to automatically load the secrets into your shell environment when you `cd` into a directory with a `fnox.toml` file.

## The Golden Path

fnox supports a lot of provider combinations, but there's one workflow we recommend — the golden path:

1. **Keep secrets in a remote vault** like [1Password](/providers/1password) and commit only references to them in `fnox.toml`. The vault stays the single source of truth and nothing sensitive goes into git.
2. **Cache them locally with [`fnox sync`](/guide/sync)**, which re-encrypts each secret to your personal [age](/providers/age) key in the gitignored `fnox.local.toml`.
3. **Load them from the cache** via [shell integration](/guide/shell-integration) or `fnox exec`. Decryption is local, so it's instant and works offline.

You can also keep the age key in hardware: [Apple's Secure Enclave (Touch ID)](/guide/sync#apple-secure-enclave-touch-id), a [YubiKey](/guide/sync#yubikey), or a [TPM or FIDO2 token](/guide/sync#tpm-and-fido2). A Secure Enclave or TPM key only decrypts on the machine that created it, while a YubiKey travels with you. See [Syncing Secrets Locally](/guide/sync) for the walkthroughs and what each option actually protects against.

## Why Choose fnox?

### Works with Your Existing Infrastructure

Already using AWS Secrets Manager? 1Password? age encryption? fnox integrates with all of them. Mix and match providers based on your needs.

### Secrets in Version Control (Done Right)

Store encrypted secrets in git using age, AWS KMS, Azure KMS, or GCP KMS. Your team can clone the repo and immediately have access to development secrets.

### Multi-Environment Made Easy

Use profiles to manage different secrets for dev, staging, and production—all in the same config file.

### Developer Experience First

- Simple TOML configuration
- Shell integration for automatic secret loading
- Works offline (with encrypted secrets)
- No vendor lock-in

## Why is this a standalone CLI and not part of mise?

[mise](https://mise.jdx.dev) has support for [encrypted secrets](https://mise.jdx.dev/environments/secrets/) but mise's design makes it a poor fit for remote secrets. mise reloads its environment too frequently—whenever a directory is changed, `mise x` is run, a shim is called, etc. Any other use-case like this mise leverages caching but secrets are an area where caching is a bad idea for obvious reasons. It might be possible to change mise's design to retain its environment in part to better support something like this but that's a huge challenge.

Basically it's just too hard to get remote secrets to work effectively with mise so I made this a standalone tool.
