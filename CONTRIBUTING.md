# Contributing

See the [contributing guide](https://fnox.jdx.dev/contributing).

## mbx build cache

`mise install` installs [mbx](https://mr-boxington.jdx.dev) 1.8. The normal
`mise run build`, `mise run test:cargo`, and `mise run lint` workflows activate
its transparent Cargo wrapper and therefore use the cache while invoking Cargo
normally. Standalone Cargo commands require an activated mise shell. To bypass
mbx without skipping or weakening a check, prefix the
equivalent Cargo command with `MBX_DISABLE=1`:

```sh
MBX_DISABLE=1 cargo build
MBX_DISABLE=1 cargo test
MBX_DISABLE=1 cargo check --workspace
MBX_DISABLE=1 cargo clippy -q -- -D warnings
# CI also runs this broader clippy check:
MBX_DISABLE=1 cargo clippy --workspace --all-targets -- -D warnings
MBX_DISABLE=1 cargo msrv verify
```

If bypassed Cargo succeeds where the wrapper fails, or mbx introduces a papercut, please start a
[mr-boxington Discussion](https://github.com/jdx/mr-boxington/discussions).
Include the repository and commit, operating system, `mbx --version`,
`mbx doctor`, and both commands and their output. Before posting, redact
secrets, absolute cache paths, remote URLs, namespaces, and other sensitive or
identifying details.
