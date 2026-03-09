#!/usr/bin/env bats
#
# Vault Lease Backend Tests
#
# These tests verify the HashiCorp Vault dynamic secrets lease backend.
#
# Prerequisites:
#   1. Start Vault dev server: source ./test/setup-vault-test.sh
#   2. Enable a dynamic secrets engine (e.g., database or AWS):
#      vault secrets enable -path=secret database  (or use KV for basic testing)
#   3. Run tests: mise run test:bats -- test/lease_vault.bats
#
# For basic testing without a real dynamic engine, these tests use the KV
# secrets engine to verify the HTTP plumbing (read path, env_map, revocation).
#
# Note: Tests will automatically skip if VAULT_TOKEN is not available.

setup() {
	load 'test_helper/common_setup'
	_common_setup

	if ! command -v vault >/dev/null 2>&1; then
		skip "Vault CLI not installed. Install with: mise install vault"
	fi

	if [ -z "$VAULT_TOKEN" ]; then
		skip "VAULT_TOKEN not available. Run: source ./test/setup-vault-test.sh"
	fi

	if [ -z "$VAULT_ADDR" ]; then
		export VAULT_ADDR="http://localhost:8200"
	fi

	if ! vault status >/dev/null 2>&1; then
		skip "Cannot connect to Vault. Server may not be running or token invalid."
	fi

	# Create a test KV secret that the lease backend can read
	vault kv put secret/fnox-lease-test access_key="AKIATEST123" secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >/dev/null 2>&1 || true
}

teardown() {
	_common_teardown
}

# Helper: create fnox config with Vault lease backend
create_vault_lease_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_vault]
type = "vault"
address = "$VAULT_ADDR"
secret_path = "secret/data/fnox-lease-test"

[leases.test_vault.env_map]
access_key = "AWS_ACCESS_KEY_ID"
secret_key = "AWS_SECRET_ACCESS_KEY"
EOF
}

# Helper: create config with namespace
create_vault_ns_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_vault_ns]
type = "vault"
address = "$VAULT_ADDR"
secret_path = "secret/data/fnox-lease-test"
namespace = "test-ns"

[leases.test_vault_ns.env_map]
access_key = "AWS_ACCESS_KEY_ID"
EOF
}

@test "vault lease: create outputs credentials in json format" {
	create_vault_lease_config

	run "$FNOX_BIN" lease create test_vault --duration 15m --format json
	assert_success
	assert_output --partial "AWS_ACCESS_KEY_ID"
	assert_output --partial "AWS_SECRET_ACCESS_KEY"
	assert_output --partial "lease_id"
}

@test "vault lease: create outputs credentials in env format" {
	create_vault_lease_config

	run "$FNOX_BIN" lease create test_vault --duration 15m --format env
	assert_success
	assert_output --partial "export AWS_ACCESS_KEY_ID="
	assert_output --partial "export AWS_SECRET_ACCESS_KEY="
}

@test "vault lease: exec injects credentials into subprocess" {
	create_vault_lease_config

	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "AWS_ACCESS_KEY_ID=AKIATEST123"
	assert_output --partial "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

@test "vault lease: list shows created lease" {
	create_vault_lease_config

	run "$FNOX_BIN" lease create test_vault --duration 15m --format json
	assert_success

	run "$FNOX_BIN" lease list --active
	assert_success
	assert_output --partial "test_vault"
	assert_output --partial "active"
}

@test "vault lease: revoke marks lease as revoked" {
	create_vault_lease_config

	run "$FNOX_BIN" lease create test_vault --duration 15m --format json
	assert_success

	local lease_id
	lease_id=$(echo "$output" | grep -o '"lease_id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"lease_id"[[:space:]]*:[[:space:]]*"//;s/"$//')

	run "$FNOX_BIN" lease revoke "$lease_id"
	assert_success
	assert_output --partial "revoked"
}

@test "vault lease: env_map maps vault fields to env vars" {
	# Config that maps only access_key
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_partial]
type = "vault"
address = "$VAULT_ADDR"
secret_path = "secret/data/fnox-lease-test"

[leases.test_partial.env_map]
access_key = "CUSTOM_KEY_VAR"
EOF

	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "CUSTOM_KEY_VAR=AKIATEST123"
}

@test "vault lease: auth failure with bad token" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_bad_token]
type = "vault"
address = "$VAULT_ADDR"
token = "s.badtoken12345"
secret_path = "secret/data/fnox-lease-test"

[leases.test_bad_token.env_map]
access_key = "AWS_ACCESS_KEY_ID"
EOF

	run "$FNOX_BIN" lease create test_bad_token --duration 15m --format json
	assert_failure
}

@test "vault lease: missing address without VAULT_ADDR fails" {
	local saved_addr="$VAULT_ADDR"
	unset VAULT_ADDR
	unset FNOX_VAULT_ADDR

	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_no_addr]
type = "vault"
secret_path = "secret/data/fnox-lease-test"

[leases.test_no_addr.env_map]
access_key = "AWS_ACCESS_KEY_ID"
EOF

	run "$FNOX_BIN" lease create test_no_addr --duration 15m --format json
	assert_failure
	assert_output --partial "address"

	export VAULT_ADDR="$saved_addr"
}
