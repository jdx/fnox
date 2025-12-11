#!/usr/bin/env bats
#
# Passwordstate Provider Tests
#
# These tests verify the Click Studios Passwordstate provider integration with fnox.
#
# Prerequisites:
#   1. Access to a Passwordstate server
#   2. API key for a specific password list
#   3. Export PASSWORDSTATE_BASE_URL: export PASSWORDSTATE_BASE_URL="https://passwordstate.example.com"
#   4. Export PASSWORDSTATE_API_KEY: export PASSWORDSTATE_API_KEY="your-api-key"
#   5. Export PASSWORDSTATE_LIST_ID: export PASSWORDSTATE_LIST_ID="123"
#   6. Run tests: mise run test:bats -- test/passwordstate.bats
#
# Note: Passwordstate is an on-premise enterprise password manager.
# Each password list has its own API key - create one provider per list.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Some tests don't need credentials (like 'fnox list')
	if [[ $BATS_TEST_DESCRIPTION != *"list"* ]]; then
		# Check for Passwordstate credentials
		if [ -z "$PASSWORDSTATE_BASE_URL" ]; then
			skip "PASSWORDSTATE_BASE_URL not set"
		fi

		if [ -z "$PASSWORDSTATE_API_KEY" ]; then
			skip "PASSWORDSTATE_API_KEY not set"
		fi

		if [ -z "$PASSWORDSTATE_LIST_ID" ]; then
			skip "PASSWORDSTATE_LIST_ID not set"
		fi
	fi
}

teardown() {
	_common_teardown
}

# Helper function to create a Passwordstate test config
create_passwordstate_config() {
	local base_url="${1:-${PASSWORDSTATE_BASE_URL:-https://passwordstate.example.com}}"
	local api_key="${2:-${PASSWORDSTATE_API_KEY:-}}"
	local password_list_id="${3:-${PASSWORDSTATE_LIST_ID:-123}}"

	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.ps]
type = "passwordstate"
base_url = "$base_url"
password_list_id = "$password_list_id"
EOF

	if [ -n "$api_key" ]; then
		echo "api_key = \"$api_key\"" >>"${FNOX_CONFIG_FILE:-fnox.toml}"
	fi

	cat >>"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF

[secrets]
EOF
}

@test "fnox list shows Passwordstate secrets" {
	# This test doesn't need real credentials since list just reads the config file
	create_passwordstate_config "https://passwordstate.example.com" "fake-api-key" "123"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.DB_PASSWORD]
description = "Database password"
provider = "ps"
value = "Database Server"

[secrets.DB_USER]
description = "Database username"
provider = "ps"
value = "Database Server/username"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "DB_PASSWORD"
	assert_output --partial "DB_USER"
	assert_output --partial "Database password"
}

@test "fnox get retrieves secret by title" {
	# Skip if required env vars not set or test title not configured
	if [ -z "$PASSWORDSTATE_TEST_TITLE" ]; then
		skip "PASSWORDSTATE_TEST_TITLE not set - set to a valid password title for testing"
	fi

	create_passwordstate_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SECRET]
provider = "ps"
value = "$PASSWORDSTATE_TEST_TITLE"
EOF

	run "$FNOX_BIN" get TEST_SECRET
	assert_success
	# Should return some value (not empty)
	[ -n "$output" ]
}

@test "fnox get retrieves specific field from password" {
	# Skip if required env vars not set
	if [ -z "$PASSWORDSTATE_TEST_TITLE" ]; then
		skip "PASSWORDSTATE_TEST_TITLE not set"
	fi

	create_passwordstate_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_USERNAME]
provider = "ps"
value = "$PASSWORDSTATE_TEST_TITLE/username"
EOF

	run "$FNOX_BIN" get TEST_USERNAME
	# May fail if username field is empty, but should at least not error on format
	# Success or specific field error is acceptable
	if [ "$status" -ne 0 ]; then
		assert_output --partial "not found or empty"
	fi
}

@test "fnox get fails with invalid title" {
	create_passwordstate_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_SECRET]
provider = "ps"
value = "THIS_TITLE_SHOULD_NOT_EXIST_$(date +%s)"
if_missing = "error"
EOF

	run "$FNOX_BIN" get INVALID_SECRET
	assert_failure
	# Should contain error message about not found or API error
	assert_output --partial "not found"
}

@test "Passwordstate provider uses API key from environment" {
	# Skip if required env vars not set
	if [ -z "$PASSWORDSTATE_TEST_TITLE" ]; then
		skip "PASSWORDSTATE_TEST_TITLE not set"
	fi

	# Create config without explicit api_key - should use env var
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.ps]
type = "passwordstate"
base_url = "$PASSWORDSTATE_BASE_URL"
password_list_id = "$PASSWORDSTATE_LIST_ID"

[secrets.TEST_FROM_ENV]
provider = "ps"
value = "$PASSWORDSTATE_TEST_TITLE"
EOF

	run "$FNOX_BIN" get TEST_FROM_ENV
	assert_success
	[ -n "$output" ]
}

@test "fnox exec loads Passwordstate secrets into environment" {
	# Skip if required env vars not set
	if [ -z "$PASSWORDSTATE_TEST_TITLE" ]; then
		skip "PASSWORDSTATE_TEST_TITLE not set"
	fi

	create_passwordstate_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_EXEC_SECRET]
provider = "ps"
value = "$PASSWORDSTATE_TEST_TITLE"
EOF

	# Run a command that prints the environment variable
	# shellcheck disable=SC2016 # Single quotes intentional - variable should expand in subshell
	run "$FNOX_BIN" exec -- sh -c 'echo "$TEST_EXEC_SECRET"'
	assert_success
	[ -n "$output" ]
}

@test "Passwordstate provider fails gracefully without credentials" {
	# Create config without credentials
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.ps]
type = "passwordstate"
base_url = "https://passwordstate.example.com"
password_list_id = "123"

[secrets.TEST_SECRET]
provider = "ps"
value = "Some Title"
EOF

	# Temporarily unset credentials
	local original_api_key="$PASSWORDSTATE_API_KEY"
	unset PASSWORDSTATE_API_KEY
	unset FNOX_PASSWORDSTATE_API_KEY

	run "$FNOX_BIN" get TEST_SECRET
	# Should fail with connection error or auth error
	assert_failure

	# Restore credentials
	export PASSWORDSTATE_API_KEY="$original_api_key"
}

@test "Passwordstate provider handles SSL verification option" {
	# This test verifies the verify_ssl configuration is accepted
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.ps]
type = "passwordstate"
base_url = "https://passwordstate.example.com"
api_key = "test-key"
password_list_id = "123"
verify_ssl = "false"

[secrets.TEST_SSL]
provider = "ps"
value = "Some Title"
EOF

	# Just verify config is parsed correctly
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "TEST_SSL"
}
