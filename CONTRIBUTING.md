# Contributing to fnox

Read the [contribution expectations](https://fnox.jdx.dev/contributing) before starting a substantial change. For repository conventions, see [AGENTS.md](AGENTS.md).

## Set up a checkout

```sh
mise install
mise run build
```

Development uses the debug build in `target/debug`. An activated mise shell puts the project tools on `PATH`.

## Run the relevant checks

```sh
mise run test:cargo                 # Rust tests
mise run build                     # Build before Bats tests
mise run test:bats -- test/init.bats # One end-to-end test file
mise run test:bats                  # All Bats tests
mise run lint                      # Formatting and lint checks
mise run ci                        # Build, tests, and lint
```

Provider tests may require credentials or local services. See the [test guide](test/README.md) for setup and skip behavior.

## Work on documentation

```sh
aube install
aube run docs:dev
aube run docs:build
```

The build checks internal links and social previews as well as rendering the site. See [docs/README.md](docs/README.md) for layout, generated CLI pages, and visual checks. Markdown-only changes do not require the full Rust test suite.

## mbx build cache

`mise install` installs the mbx version pinned in [mise.toml](mise.toml). `mise run` activates the transparent Cargo wrapper for compilation tasks and lint checks. Standalone Cargo commands require an activated mise shell.

If the wrapper fails, bypass it for the equivalent check without weakening that check:

```sh
MBX_DISABLE=1 cargo build
MBX_DISABLE=1 cargo test
MBX_DISABLE=1 cargo check --workspace
MBX_DISABLE=1 cargo clippy -q -- -D warnings
# CI's broader clippy check:
MBX_DISABLE=1 cargo clippy --workspace --all-targets -- -D warnings
MBX_DISABLE=1 cargo msrv verify
```

If bypassed Cargo succeeds where the wrapper fails, report the mismatch in a [mr-boxington Discussion](https://github.com/jdx/mr-boxington/discussions). Include the repository and commit, OS, `mbx --version`, `mbx doctor`, and both commands and their output. Redact secrets, absolute cache paths, remote URLs, namespaces, and other sensitive or identifying details before posting. Keep the wrapper enabled in project configuration.
