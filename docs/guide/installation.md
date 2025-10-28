# Installation

## Using mise (recommended)

The easiest way to install fnox is with [mise](https://mise.jdx.dev):

```bash
mise use -g fnox
```

This installs fnox globally and keeps it up to date.

## Using Cargo

If you have Rust installed:

```bash
cargo install fnox
```

## From Source

```bash
git clone https://github.com/jdx/fnox
cd fnox
cargo install --path .
```

## Verify Installation

```bash
fnox --version
```

## Next Steps

- [Quick Start](/guide/quick-start) - Get started with fnox in 5 minutes
- [Shell Integration](/guide/shell-integration) - Set up automatic secret loading
