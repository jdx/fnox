#!/usr/bin/env bats
#
# Azure Token Lease Backend Tests
#
# These tests verify the Azure token acquisition lease backend.
#
# Prerequisites:
#   1. Azure credentials configured (az login, or AZURE_CLIENT_ID/SECRET/TENANT_ID)
#   2. Run tests: mise run test:bats -- test/lease_azure_token.bats
#
# Note: Tests will automatically skip if Azure credentials are not available.

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export FNOX_EXPERIMENTAL=true

	# Check if Azure credentials are available via env vars
	if [ -z "$AZURE_CLIENT_ID" ] || [ -z "$AZURE_CLIENT_SECRET" ] || [ -z "$AZURE_TENANT_ID" ]; then
		# Check if az CLI is logged in as fallback
		if ! command -v az >/dev/null 2>&1; then
			skip "Azure CLI not installed and AZURE_CLIENT_ID/SECRET/TENANT_ID not set."
		fi
		if ! az account show >/dev/null 2>&1; then
			skip "Azure credentials not available. Run 'az login' or set AZURE_CLIENT_ID/SECRET/TENANT_ID."
		fi
	fi

	# Authenticate Azure CLI with service principal if env vars are set
	if [ -n "$AZURE_CLIENT_ID" ] && [ -n "$AZURE_CLIENT_SECRET" ] && [ -n "$AZURE_TENANT_ID" ]; then
		az login --service-principal \
			-u "$AZURE_CLIENT_ID" \
			-p "$AZURE_CLIENT_SECRET" \
			--tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 ||
			skip "Failed to authenticate Azure CLI with service principal"
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
