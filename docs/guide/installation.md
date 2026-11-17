---
description: "Install fnox with mise, Cargo, Nix, or a prebuilt binary for macOS, Linux, or Windows."
---

# Installation

fnox is a single binary for macOS, Linux, and Windows. Install it with any of the methods below, then continue with the [quick start](/guide/quick-start).

## mise (recommended)

```sh
mise use -g fnox
```

To pin a version for a project instead, run `mise use fnox` in the project and commit `mise.toml`. Teammates and CI then get the same version. Upgrade with `mise upgrade fnox`.

## Cargo

```sh
cargo install fnox --locked
```

This builds from source. The minimum Rust version is the `rust-version` in [Cargo.toml](https://github.com/jdx/fnox/blob/main/Cargo.toml). Run the same command again to upgrade.

### Smaller builds

Some providers bring in large SDKs or system libraries. Each group is a Cargo feature, and all of them are on by default:

| Feature      | Adds                                                                 |
| ------------ | -------------------------------------------------------------------- |
| `aws`        | AWS KMS, Secrets Manager and Parameter Store; the `aws-sts` lease    |
| `azure`      | Azure Key Vault, App Configuration and Container Apps; `azure-token` |
| `gcp`        | Google Cloud KMS and Secret Manager; the `gcp-iam` lease             |
| `kubernetes` | Kubernetes Secrets; the `kubernetes` lease                           |
| `keeper`     | Keeper Secrets Manager                                               |
| `enpass`     | Enpass (builds SQLCipher and OpenSSL from source)                    |
| `fido2`      | FIDO2 keys (needs libudev on Linux)                                  |

To leave groups out, turn off the defaults and list the ones you want:

```sh
cargo install fnox --locked --no-default-features --features aws
```

With `--no-default-features` alone, fnox still includes every other provider, such as age, 1Password, Bitwarden, HashiCorp Vault and the OS keychain. A config that uses a left-out provider still loads; fnox reports an error only when it needs a secret from that provider.

## Nix

The repository is a Nix flake:

```sh
nix profile install github:jdx/fnox
```

## Prebuilt binaries

Download the archive for your platform from [GitHub Releases](https://github.com/jdx/fnox/releases) and put `fnox` somewhere on your `PATH`. Builds are published for macOS (Apple silicon and Intel), Linux (x86_64 and arm64, glibc and musl), and Windows (x86_64 and arm64).

### Lite builds for Linux

Each Linux release also has a lite build, `fnox-lite-<target>.tar.gz`. It is the same as a Cargo install with `--no-default-features` (see [Smaller builds](#smaller-builds)). It leaves out the AWS, Azure, Google Cloud, Kubernetes, Keeper, Enpass and FIDO2 providers, so it is smaller, and the glibc build does not need libudev. A config that uses a left-out provider still loads, but reading a secret from that provider fails.

To install the lite build with mise, ask for the `lite` variant:

```toml
[tools]
"packslip:github.com/jdx/fnox" = { version = "latest", variant = "lite", workflow = "release.yml" }
```

Plain `mise use fnox` and the other install methods keep installing the full build.

## Code signing

Windows release binaries (`fnox.exe`) are Authenticode-signed. Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

- **Signing policy:** only binaries built by the [release workflow](https://github.com/jdx/fnox/blob/main/.github/workflows/release.yml) from this repository's tagged releases are submitted for signing, and each signing request is approved by the project maintainer ([@jdx](https://github.com/jdx)).
- **Privacy:** fnox does not collect telemetry. Network calls include configured secret providers and other user-requested actions, such as plugin downloads and proxied requests. Nothing is sent to the signing service beyond the release binaries submitted for signing.

To check a download, run `Get-AuthenticodeSignature .\fnox.exe` in PowerShell, or open the file's Properties and its Digital Signatures tab. Trust the file only if the status is `Valid` and the signer is **SignPath Foundation**; a valid signature from any other publisher is not a fnox release.

## Verify

```sh
fnox --version
```

If your shell can't find `fnox`, check that the install directory (`~/.cargo/bin` for Cargo) is on your `PATH`, or that [mise is activated](https://mise.jdx.dev/getting-started.html), then open a new terminal.

## Provider tools

fnox itself has no runtime dependencies, but some providers call a vendor CLI: 1Password needs `op`, Bitwarden needs `bw`, and so on. Each [provider page](/providers/overview) lists what it needs. The quick start uses `age-keygen` from [age](https://github.com/FiloSottile/age) to create a key:

```sh
mise use -g age
```

## Shell completions

```sh
fnox completion zsh > "${fpath[1]}/_fnox"
fnox completion bash > ~/.local/share/bash-completion/completions/fnox
fnox completion fish > ~/.config/fish/completions/fnox.fish
```

## See also

- [Quick start](/guide/quick-start): encrypt your first secret.
- [Use an existing vault](/guide/existing-vault): connect 1Password or another vault.
- [Contributing](/contributing): build fnox from a checkout.
