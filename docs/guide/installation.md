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

## Nix

The repository is a Nix flake:

```sh
nix profile install github:jdx/fnox
```

## Prebuilt binaries

Download the archive for your platform from [GitHub Releases](https://github.com/jdx/fnox/releases) and put `fnox` somewhere on your `PATH`. Builds are published for macOS (Apple silicon and Intel), Linux (x86_64 and arm64, glibc and musl), and Windows (x86_64 and arm64).

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
