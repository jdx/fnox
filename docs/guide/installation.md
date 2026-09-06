---
description: "Install fnox with mise, Cargo, or a prebuilt binary, then verify and update your installation."
---

# Installation

Install the fnox CLI, verify it is on your `PATH`, then [configure your first provider](/guide/quick-start).

## With mise

If you use [mise](https://mise.jdx.dev), install fnox globally:

```sh
mise use -g fnox
```

To manage the version in a project, run `mise use fnox` from that project instead. Commit the resulting mise configuration so teammates use the same version.

To update a mise-managed installation:

```sh
mise upgrade fnox
```

Installing fnox does not automatically upgrade it on every run. See [mise upgrade](https://mise.jdx.dev/cli/upgrade.html) for version constraints and update options.

## With cargo

With a supported Rust toolchain installed:

```sh
cargo install fnox --locked
```

This builds from source using the published lockfile. Ensure Cargo's binary directory (`~/.cargo/bin` on Unix) is on your `PATH`. Check the package's `rust-version` in [Cargo.toml](https://github.com/jdx/fnox/blob/main/Cargo.toml) for the minimum Rust version.

Run the same command again to install a newer published release.

## Prebuilt binaries

Download the archive for your operating system and architecture from [GitHub Releases](https://github.com/jdx/fnox/releases). Extract `fnox` into a directory on your `PATH`.

Provider requirements are separate from fnox installation. For example, 1Password needs `op`, Bitwarden needs `bw`, and generating an age key needs `age-keygen`. Each [provider guide](/providers/overview) lists its prerequisites.

## From a checkout

```sh
git clone https://github.com/jdx/fnox
cd fnox
cargo install --path . --locked
```

For development, use the debug build and project tasks in the [contributing guide](/contributing).

## Verify the installation

```sh
fnox --version
fnox --help
```

If the shell cannot find fnox, check that your install directory is on `PATH`, or that mise is [activated](https://mise.jdx.dev/getting-started.html). Open a new terminal after changing shell configuration.

Continue with the [quick start](/guide/quick-start) for local encryption or [connect a vault](/guide/golden-path).
