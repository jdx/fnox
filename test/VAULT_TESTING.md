# Test Vault locally

Use the repository's disposable Vault dev server to run the Vault provider tests. It stores data in memory, starts unsealed, and uses the public test token `fnox-test-token`. It is not a production configuration.

## Prerequisites

Install the project tools with `mise install`, start Docker, and build fnox:

```sh
mise run build
```

## Start and test

From the repository root, in an activated mise shell:

```sh
source ./test/setup-vault-test.sh
bats test/vault.bats
```

The setup script starts [the Compose service](docker-compose.vault.yml), sets `VAULT_ADDR=http://localhost:8200` and `VAULT_TOKEN=fnox-test-token`, and checks that Vault is available.

Use a dedicated test shell: the helper changes Vault environment variables and shell options.

## Manual setup

```sh
docker compose -f test/docker-compose.vault.yml up -d
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=fnox-test-token
vault status
bats test/vault.bats
```

The dev server provides a KV v2 engine at `secret/`. Each test creates the records it needs.

## Inspect a test record

```sh
vault kv put secret/fnox-test/database value=example-password username=test-user
vault kv get secret/fnox-test/database
```

A matching fnox configuration is:

```toml
[providers.vault]
type = "vault"
address = "http://localhost:8200"
path = "secret/fnox-test"

[secrets]
DB_PASSWORD = { provider = "vault", value = "database" }
DB_USER = { provider = "vault", value = "database/username" }
```

A reference without a field selects `value`. These are test values only. Normal server setup and provider-scoped authentication are covered in the [Vault provider guide](../docs/providers/vault.md).

## Cleanup

```sh
docker compose -f test/docker-compose.vault.yml down
unset VAULT_ADDR VAULT_TOKEN
```

Stopping the dev server discards its in-memory data. Do not point this helper at a production Vault instance.

## Troubleshooting

- **Tests skip:** confirm `VAULT_TOKEN` is present in the shell running Bats.
- **Connection refused:** check `docker compose -f test/docker-compose.vault.yml ps` and verify port 8200 is available.
- **Authentication failure:** run `vault status` and confirm the helper's test address and token are active.
- **CLI missing:** install project tools and activate mise before running the helper.

For CI provisioning, read [ci-impl.yml](../.github/workflows/ci-impl.yml). The workflow is the source of truth for runner-specific setup; local Docker instructions are not a description of every CI runner.
