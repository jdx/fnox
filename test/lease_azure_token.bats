#!/usr/bin/env bats
#
# Azure Token Lease Backend Tests
#
# These tests verify the Azure token acquisition lease backend.
#
# Prerequisites:
#   1. Azure credentials configured (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
#      or az CLI logged in
#   2. Run tests: mise run test:bats -- test/lease_azure_token.bats
#
# In CI, Azure credentials are decrypted by fnox exec from the project's fnox.toml.
# The backend uses ClientSecretCredential when env vars are set (no az CLI needed).
#
# Note: Tests will automatically skip if Azure credentials are not available.

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export FNOX_EXPERIMENTAL=true

	# Determine if we're in CI with secrets access (not a forked PR)
	local in_ci_with_secrets=false
	if [ "${CI:-}" = "true" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
		if [ -f ~/.config/fnox/age.txt ] || [ -n "${FNOX_AGE_KEY:-}" ]; then
			in_ci_with_secrets=true
		fi
	fi

	# Check if Azure credentials are available (env vars or az CLI)
	if [ -n "${AZURE_CLIENT_ID:-}" ] && [ -n "${AZURE_CLIENT_SECRET:-}" ] && [ -n "${AZURE_TENANT_ID:-}" ]; then
		# Service principal env vars are set — backend will use ClientSecretCredential
		true
	elif command -v az >/dev/null 2>&1 && az account show >/dev/null 2>&1; then
		# az CLI is logged in — backend will use DeveloperToolsCredential
		true
	else
		if [ "$in_ci_with_secrets" = "true" ]; then
			echo "# ERROR: In CI with secrets access, but Azure credentials are not available!" >&3
			return 1
		fi
		skip "Azure credentials not available. Run 'az login' or set AZURE_CLIENT_ID/SECRET/TENANT_ID."
	fi
}

teardown() {
	_common_teardown
}

# Helper: create fnox config with Azure token lease backend
create_azure_token_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_azure]
type = "azure-token"
scope = "https://management.azure.com/.default"
EOF
}

create_azure_token_config_custom_var() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_azure]
type = "azure-token"
scope = "https://management.azure.com/.default"
env_var = "MY_AZURE_TOKEN"
EOF
}

@test "azure-token lease: create outputs credentials in json format" {
	create_azure_token_config

	run "$FNOX_BIN" lease create test_azure --duration 30m --format json
	assert_success
	assert_output --partial "AZURE_ACCESS_TOKEN"
	assert_output --partial "lease_id"
}

@test "azure-token lease: create outputs credentials in env format" {
	create_azure_token_config

	run "$FNOX_BIN" lease create test_azure --duration 30m --format env
	assert_success
	assert_output --partial "export AZURE_ACCESS_TOKEN="
}

@test "azure-token lease: exec injects credentials into subprocess" {
	create_azure_token_config

	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "AZURE_ACCESS_TOKEN="
}

@test "azure-token lease: custom env_var name" {
	create_azure_token_config_custom_var

	run "$FNOX_BIN" lease create test_azure --duration 30m --format json
	assert_success
	assert_output --partial "MY_AZURE_TOKEN"
}

@test "azure-token lease: list shows created lease" {
	create_azure_token_config

	run "$FNOX_BIN" lease create test_azure --duration 30m --format json
	assert_success

	run "$FNOX_BIN" lease list --active
	assert_success
	assert_output --partial "test_azure"
	assert_output --partial "active"
}

@test "azure-token lease: revoke is a no-op (succeeds silently)" {
	create_azure_token_config

	run "$FNOX_BIN" lease create test_azure --duration 30m --format json
	assert_success

	local lease_id
	lease_id=$(echo "$output" | python3 -c "import sys, json; print(json.load(sys.stdin)['lease_id'])")

	run "$FNOX_BIN" lease revoke "$lease_id"
	assert_success
	assert_output --partial "revoked"
}

@test "azure-token lease: bad scope fails gracefully" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_bad_scope]
type = "azure-token"
scope = "https://nonexistent.example.com/.default"
EOF

	run "$FNOX_BIN" lease create test_bad_scope --duration 15m --format json
	assert_failure
}
