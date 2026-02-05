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
	_common_teardown
}

# Helper function to create a BSM test config
create_bsm_config() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.bsm]
type = "bitwarden-sm"
project_id = "${BWS_PROJECT_ID:-test-project-id}"

[secrets]
EOF
}

# Helper function to create a test secret in BSM
# Returns the secret ID (UUID)
create_test_bsm_secret() {
	local secret_name
	secret_name="fnox-test-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_value
	secret_value="test-secret-value-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"

	# Create secret with bws CLI, parse JSON output for the ID
	local json_output
	json_output=$(bws secret create "$secret_name" "$secret_value" "$BWS_PROJECT_ID" --output json 2>/dev/null)
	local secret_id
	secret_id=$(echo "$json_output" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

	echo "$secret_id"
}

# Helper function to create a test secret with a note
create_test_bsm_secret_with_note() {
	local secret_name
	secret_name="fnox-test-note-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_value="test-value"
	local secret_note="test-note-content"

	local json_output
	json_output=$(bws secret create "$secret_name" "$secret_value" "$BWS_PROJECT_ID" --note "$secret_note" --output json 2>/dev/null)
	local secret_id
	secret_id=$(echo "$json_output" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

	echo "$secret_id"
}

# Helper function to delete a test secret from BSM
delete_test_bsm_secret() {
	local secret_id="${1}"
	bws secret delete "$secret_id" >/dev/null 2>&1 || true
}

@test "fnox get retrieves secret from Bitwarden Secrets Manager" {
	create_bsm_config

	# Create a test secret
	secret_id=$(create_test_bsm_secret)

	# Add secret reference to config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_BSM_SECRET]
provider = "bsm"
value = "$secret_id"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_BSM_SECRET
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_bsm_secret "$secret_id"
}

@test "fnox get retrieves note field from BSM secret" {
	create_bsm_config

	# Create a test secret with a note
	secret_id=$(create_test_bsm_secret_with_note)

	# Add secret reference to config (fetch note field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_BSM_NOTE]
provider = "bsm"
value = "$secret_id/note"
EOF

	# Get the secret note
	run "$FNOX_BIN" get TEST_BSM_NOTE
	assert_success
	assert_output "test-note-content"

	# Cleanup
	delete_test_bsm_secret "$secret_id"
}

@test "fnox get fails with invalid secret ID" {
	create_bsm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_SECRET]
provider = "bsm"
value = "00000000-0000-0000-0000-000000000000"
EOF

	# Try to get non-existent secret
	run "$FNOX_BIN" get INVALID_SECRET
	assert_failure
}

@test "fnox get handles invalid reference format" {
	create_bsm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_FORMAT]
provider = "bsm"
value = "invalid/format/with/too/many/slashes"
EOF

	run "$FNOX_BIN" get INVALID_FORMAT
	assert_failure
	assert_output --partial "Invalid secret reference format"
}

@test "fnox list shows BSM secrets" {
	# This test doesn't need BWS_ACCESS_TOKEN since list just reads the config file
	create_bsm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.BSM_SECRET_1]
description = "First BSM secret"
provider = "bsm"
value = "00000000-0000-0000-0000-000000000001"

[secrets.BSM_SECRET_2]
description = "Second BSM secret"
provider = "bsm"
value = "00000000-0000-0000-0000-000000000002/note"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "BSM_SECRET_1"
	assert_output --partial "BSM_SECRET_2"
	assert_output --partial "First BSM secret"
}

@test "BSM provider works with token from environment" {
	create_bsm_config

	secret_id=$(create_test_bsm_secret)

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_WITH_ENV_TOKEN]
provider = "bsm"
value = "$secret_id"
EOF

	# BWS_ACCESS_TOKEN should be set by setup()
	run "$FNOX_BIN" get TEST_WITH_ENV_TOKEN
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_bsm_secret "$secret_id"
}

@test "fnox set creates a new secret in BSM" {
	create_bsm_config

	# Use fnox set to create a new secret
	run "$FNOX_BIN" set TEST_NEW_SECRET "my-new-secret-value" --provider bsm
	assert_success

	# The set command should have stored a UUID in the config
	# Verify we can retrieve it
	run "$FNOX_BIN" get TEST_NEW_SECRET
	assert_success
	assert_output "my-new-secret-value"

	# Read the config to get the secret ID for cleanup
	local secret_id
	secret_id=$(grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "${FNOX_CONFIG_FILE}" | tail -1)
	if [ -n "$secret_id" ]; then
		delete_test_bsm_secret "$secret_id"
	fi
}

@test "fnox exec loads BSM secrets into environment" {
	create_bsm_config

	secret_id=$(create_test_bsm_secret)

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_BSM_EXEC]
provider = "bsm"
value = "$secret_id"
EOF

	# Use fnox exec to load secrets into environment
	run "$FNOX_BIN" exec -- sh -c 'echo "$TEST_BSM_EXEC"'
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_bsm_secret "$secret_id"
}
