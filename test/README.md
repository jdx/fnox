# End-to-end tests

fnox uses [Bats](https://github.com/bats-core/bats-core) for end-to-end CLI tests. Run commands from the repository root with the project tools available through mise.

## Build and run

```sh
mise install
mise run build
mise run test:bats
```

`test:bats` uses an existing binary. Rebuild after Rust changes so the tests exercise your changes.

For a focused run:

```sh
mise run test:bats -- test/version.bats
```

In an activated mise shell, invoke Bats directly for a name filter or timing:

```sh
bats test/version.bats --filter "fnox --version prints version"
bats test/version.bats --timing
```

The mise task resolves configured test credentials through `fnox exec` and runs Bats in parallel. Direct Bats invocations use the environment you supply.

## Provider prerequisites

Provider tests skip when required credentials or services are unavailable. A skipped provider test does not validate that integration.

- [Bitwarden with Vaultwarden](BITWARDEN_TESTING.md): local Docker service and an unlocked `BW_SESSION`.
- [HashiCorp Vault](VAULT_TESTING.md): local dev server and a test token.
- 1Password: `OP_SERVICE_ACCOUNT_TOKEN` with access to the test vault.
- Infisical: `INFISICAL_TOKEN` or the credentials required by the test setup.
- KeePass: tests create temporary databases and use test passwords.
- Passwordstate: `PASSWORDSTATE_BASE_URL`, `PASSWORDSTATE_API_KEY`, and `PASSWORDSTATE_LIST_ID`.

See the individual `.bats` file for the exact setup and skip conditions before running a provider test.

## Write a test

Use the shared setup and teardown so config and temporary files are isolated:

```bash
setup() {
  load 'test_helper/common_setup'
  _common_setup
}

teardown() {
  _common_teardown
}

@test "fnox --version prints a version" {
  run fnox --version
  assert_success
  assert_output --regexp '^fnox [0-9]+\.[0-9]+\.[0-9]+'
}
```

Pass `--git` to `_common_setup` only when the test needs a repository. Follow adjacent tests for the behavior being exercised.

The shared setup selects `target/debug/fnox` when available, sets `$FNOX_BIN`, creates an isolated config environment, and puts test artifacts under [`tmp/`](../tmp/README.md). Teardown removes those artifacts unless Bats preservation options are enabled.

## Helpers and fixtures

- [Assertions](test_helper/assertions.bash): config, secret, and command assertions.
- [Common setup](test_helper/common_setup.bash): environment isolation and binary selection.
- [Fixtures](fixtures/README.md): disposable provider data and certificates.

Keep fixtures free of real credentials. Test failures should show enough context to identify the first substantive error without dumping resolved secrets.
