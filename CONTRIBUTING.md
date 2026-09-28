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

mise wraps `cargo` with [mbx](https://mr-boxington.jdx.dev), so compiled work is shared across checkouts. `mise run` tasks and `mise exec -- cargo …` use the wrapper; plain `cargo` does too once mise is [activated in your shell](https://mise.jdx.dev/getting-started.html#activate-mise). Builds that set `MBX_DISABLE=1`, including CI, skip the cache.
