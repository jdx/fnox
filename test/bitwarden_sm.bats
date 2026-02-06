#!/usr/bin/env bats
#
# Bitwarden Secrets Manager Provider Tests
#
# These tests verify the Bitwarden Secrets Manager provider integration with fnox.
#
# Prerequisites:
#   1. Install bws CLI: brew install bws
#   2. Set access token: export BWS_ACCESS_TOKEN=<token>
#   3. Set project ID: export BWS_PROJECT_ID=<project-id>
#   4. Run tests: mise run test:bats -- test/bitwarden_sm.bats
#
# Note: Tests will automatically skip if bws is not installed or BWS_ACCESS_TOKEN is not set.
#       These tests create and delete temporary secrets in your BSM project.
#

# Serialize tests within this file to prevent concurrent bws CLI state corruption
export BATS_NO_PARALLELIZE_WITHIN_FILE=true

setup() {
	load 'test_helper/common_setup'
	_common_setup
	_bsm_secrets_to_cleanup=()

	# Check if bws CLI is installed
	if ! command -v bws >/dev/null 2>&1; then
		skip "bws CLI not installed"
	fi

	# Some tests don't need BWS_ACCESS_TOKEN (like 'fnox list')
	if [[ $BATS_TEST_DESCRIPTION != *"list"* ]]; then
		if [ -z "$BWS_ACCESS_TOKEN" ]; then
			skip "BWS_ACCESS_TOKEN not available. Set it to a valid Bitwarden Secrets Manager access token."
		fi

		if [ -z "$BWS_PROJECT_ID" ]; then
			skip "BWS_PROJECT_ID not available. Set it to a BSM project ID for testing."
		fi
	fi
}

teardown() {
	# Clean up any test secrets created during this test
	if [ ${#_bsm_secrets_to_cleanup[@]} -gt 0 ]; then
		for secret_name in "${_bsm_secrets_to_cleanup[@]}"; do
			delete_test_bsm_secret "$secret_name"
		done
	fi
	_common_teardown
}

# Helper function to create a BSM test config
create_bsm_config() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.bws]
type = "bitwarden-sm"
project_id = "${BWS_PROJECT_ID:-test-project-id}"

[secrets]
EOF
}

# Helper function to create a test secret in BSM
# Returns the secret name (key)
create_test_bsm_secret() {
	local secret_name
	secret_name="fnox-test-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_value
	secret_value="test-secret-value-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"

	bws secret create "$secret_name" "$secret_value" "$BWS_PROJECT_ID" >/dev/null 2>&1

	echo "$secret_name"
}

# Helper function to create a test secret with a note
# Returns the secret name (key)
create_test_bsm_secret_with_note() {
	local secret_name
	secret_name="fnox-test-note-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_value="test-value"
	local secret_note="test-note-content"

	bws secret create "$secret_name" "$secret_value" "$BWS_PROJECT_ID" --note "$secret_note" >/dev/null 2>&1

	echo "$secret_name"
}

# Helper function to delete a test secret from BSM by name
delete_test_bsm_secret() {
	local secret_name="${1}"
	local json_output
	json_output=$(bws secret list "$BWS_PROJECT_ID" --output json 2>/dev/null) || return 0
	local secret_id
	secret_id=$(echo "$json_output" | jq -r --arg name "$secret_name" '.[] | select(.key == $name) | .id' 2>/dev/null)
	if [ -n "$secret_id" ]; then
		bws secret delete "$secret_id" >/dev/null 2>&1 || true
	fi
}

@test "fnox get retrieves secret from Bitwarden Secrets Manager" {
	create_bsm_config

	# Create a test secret
	local secret_name
	secret_name=$(create_test_bsm_secret)
	_bsm_secrets_to_cleanup+=("$secret_name")

	# Add secret reference to config (by name)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_BSM_SECRET]
provider = "bws"
value = "$secret_name"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_BSM_SECRET
	assert_success
	assert_output --partial "test-secret-value-"
}

@test "fnox get retrieves note field from BSM secret" {
	create_bsm_config

	# Create a test secret with a note
	local secret_name
	secret_name=$(create_test_bsm_secret_with_note)
	_bsm_secrets_to_cleanup+=("$secret_name")

	# Add secret reference to config (fetch note field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_BSM_NOTE]
provider = "bws"
value = "$secret_name/note"
EOF

	# Get the secret note
	run "$FNOX_BIN" get TEST_BSM_NOTE
	assert_success
	assert_output "test-note-content"
}

@test "fnox get fails with nonexistent secret name" {
	create_bsm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.NONEXISTENT_SECRET]
provider = "bws"
value = "this-secret-does-not-exist"
EOF

	# Try to get non-existent secret
	run "$FNOX_BIN" get NONEXISTENT_SECRET
	assert_failure
}

@test "fnox get handles unknown field name" {
	create_bsm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_FIELD]
provider = "bws"
value = "some-secret/badfield"
EOF

	run "$FNOX_BIN" get INVALID_FIELD
	assert_failure
	assert_output --partial "Unknown field"
}

@test "fnox list shows BSM secrets" {
	# This test doesn't need BWS_ACCESS_TOKEN since list just reads the config file
	create_bsm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.BSM_SECRET_1]
description = "First BSM secret"
provider = "bws"
value = "my-database-password"

[secrets.BSM_SECRET_2]
description = "Second BSM secret"
provider = "bws"
value = "my-api-key/note"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "BSM_SECRET_1"
	assert_output --partial "BSM_SECRET_2"
	assert_output --partial "First BSM secret"
}

@test "BSM provider works with token from environment" {
	create_bsm_config

	local secret_name
	secret_name=$(create_test_bsm_secret)
	_bsm_secrets_to_cleanup+=("$secret_name")

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_WITH_ENV_TOKEN]
provider = "bws"
value = "$secret_name"
EOF

	# BWS_ACCESS_TOKEN should be set by setup()
	run "$FNOX_BIN" get TEST_WITH_ENV_TOKEN
	assert_success
	assert_output --partial "test-secret-value-"
}

@test "fnox set creates a new secret in BSM" {
	create_bsm_config

	local test_secret_name
	test_secret_name="fnox-set-test-$(date +%s)-$$"
	_bsm_secrets_to_cleanup+=("$test_secret_name")

	# Use fnox set to create a new secret
	run "$FNOX_BIN" set TEST_NEW_SECRET "my-new-secret-value" --provider bws --key-name "$test_secret_name"
	assert_success

	# Verify we can retrieve it
	run "$FNOX_BIN" get TEST_NEW_SECRET
	assert_success
	assert_output "my-new-secret-value"
}

@test "fnox set updates an existing secret in BSM" {
	create_bsm_config

	local test_secret_name
	test_secret_name="fnox-update-test-$(date +%s)-$$"
	_bsm_secrets_to_cleanup+=("$test_secret_name")

	# Create an initial secret directly
	bws secret create "$test_secret_name" "initial-value" "$BWS_PROJECT_ID" >/dev/null 2>&1

	# Add to config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_UPDATE_SECRET]
provider = "bws"
value = "$test_secret_name"
EOF

	# Verify initial value
	run "$FNOX_BIN" get TEST_UPDATE_SECRET
	assert_success
	assert_output "initial-value"

	# Use fnox set to update the secret
	run "$FNOX_BIN" set TEST_UPDATE_SECRET "updated-value"
	assert_success

	# Verify it was updated
	run "$FNOX_BIN" get TEST_UPDATE_SECRET
	assert_success
	assert_output "updated-value"
}

@test "fnox exec loads BSM secrets into environment" {
	create_bsm_config

	local secret_name
	secret_name=$(create_test_bsm_secret)
	_bsm_secrets_to_cleanup+=("$secret_name")

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_BSM_EXEC]
provider = "bws"
value = "$secret_name"
EOF

	# Use fnox exec to load secrets into environment
	run "$FNOX_BIN" exec -- sh -c 'echo "$TEST_BSM_EXEC"'
	assert_success
	assert_output --partial "test-secret-value-"
}
