# Test Bitwarden with Vaultwarden

Run the Bitwarden provider tests against a local [Vaultwarden](https://github.com/dani-garcia/vaultwarden) instance. The test server uses disposable data and a self-signed TLS certificate.

## Prerequisites

- Docker running locally.
- Project tools installed with `mise install`, including the `bw` CLI.
- A current debug build from `mise run build`.

Use a dedicated test shell and a separate Bitwarden CLI data directory so the helper does not switch your everyday vault session:

```sh
export BITWARDENCLI_APPDATA_DIR="$(mktemp -d)"
source ./test/setup-bitwarden-test.sh
bats test/bitwarden.bats
```

Run from the repository root in an activated mise shell. The helper configures `bw` for `https://localhost:8080`, sets public test credentials, and unlocks the vault into `BW_SESSION`. Follow its account-creation instructions if prompted.

The helper sets `NODE_TLS_REJECT_UNAUTHORIZED=0` for the disposable local certificate. Keep that setting confined to the test shell and unset it afterwards; it disables TLS verification for other Node processes in that shell too.

## Files

| File                                                         | Purpose                                 |
| ------------------------------------------------------------ | --------------------------------------- |
| [docker-compose.bitwarden.yml](docker-compose.bitwarden.yml) | Local test server                       |
| [setup-bitwarden-test.sh](setup-bitwarden-test.sh)           | Local setup and login                   |
| [setup-bitwarden-ci.sh](setup-bitwarden-ci.sh)               | CI setup using seeded data              |
| [bitwarden.bats](bitwarden.bats)                             | Provider tests                          |
| [fixtures/README.md](fixtures/README.md)                     | Seeded database and public test account |
| [Certificate README](fixtures/bitwarden-certs/README.md)     | Local TLS fixtures                      |

## Verify the session

```sh
bw status
bats test/bitwarden.bats
```

If the vault needs unlocking again:

```sh
export BW_SESSION="$(bw unlock --raw)"
```

Keep the returned session token out of logs and issues even when it belongs to the test account.

## CI setup

The CI setup uses a pre-seeded SQLite database containing the public account documented in [fixtures/README.md](fixtures/README.md). The setup script prepares the disposable service and exports `BW_SESSION` for the tests.

See [ci-impl.yml](../.github/workflows/ci-impl.yml) for runner-specific service setup. Tests skip when no usable session is supplied; a skipped run does not exercise Bitwarden authentication.

## Cleanup

```sh
docker compose -f test/docker-compose.bitwarden.yml down
unset BW_SESSION BW_PASSWORD BW_EMAIL NODE_TLS_REJECT_UNAUTHORIZED
```

Exit the dedicated test shell when finished. The temporary CLI directory contains only test state; remove it once it is no longer needed. Do not remove a directory used by your normal Bitwarden installation.

## Troubleshooting

- **No `BW_SESSION`:** run the helper in the same shell as Bats, and confirm the vault is unlocked.
- **Cannot connect:** verify Docker is running, the service is listening on port 8080, and the configured URL uses HTTPS.
- **Login fails:** follow the local helper's account setup. The local account differs from the pre-seeded CI account.
- **`bw` missing:** install and activate the mise-managed tools.
- **Fixtures need updating:** follow the [database regeneration instructions](fixtures/README.md#regenerating).
