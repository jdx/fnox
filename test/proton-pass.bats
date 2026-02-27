#!/usr/bin/env bats
#
# Proton Pass Provider Tests
#
# These tests verify the Proton Pass provider integration with fnox.
#
# Prerequisites:
#   1. Install Proton Pass CLI: Download from https://proton.me/pass/download
#   2. Login to Proton Pass: pass-cli login --interactive
#   3. Create test items in a vault
#   4. Run tests: mise run test:bats -- test/proton-pass.bats
#
# Note: Tests will automatically skip if:
#       - pass-cli is not installed
#       - Not authenticated with Proton Pass
#       - Test vault/items don't exist
#
# Environment Variables:
#   FNOX_PROTON_PASS_PASSWORD or PROTON_PASS_PASSWORD - Account password for non-interactive auth
#   FNOX_PROTON_PASS_TOTP or PROTON_PASS_TOTP - 2FA TOTP code if enabled
#   PROTON_PASS_TEST_VAULT - Vault name to use for tests (default: "Personal")
#   PROTON_PASS_TEST_ITEM - An existing item in your vault that tests will read from
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Check if pass-cli is installed
	if ! command -v pass-cli >/dev/null 2>&1; then
		skip "Proton Pass CLI (pass-cli) not installed. Download from https://proton.me/pass/download"
	fi

	# Some tests don't need authentication (like 'fnox list')
	# Some tests intentionally run without auth (like 'fails gracefully')
	# Only check auth if this test actually needs it
	if [[ $BATS_TEST_DESCRIPTION != *"list"* ]] && [[ $BATS_TEST_DESCRIPTION != *"fails gracefully"* ]]; then
		# Check if we can authenticate by running pass-cli test
		if ! pass-cli test >/dev/null 2>&1; then
			skip "Cannot authenticate with Proton Pass. Run 'pass-cli login --interactive' first."
		fi
	fi

	# Set test vault (use environment variable or default to "Personal")
	TEST_VAULT="${PROTON_PASS_TEST_VAULT:-Personal}"
}

teardown() {
	_common_teardown
}

# Helper function to create a Proton Pass test config
create_proton_pass_config() {
	local vault="${1:-$TEST_VAULT}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.protonpass]
type = "proton-pass"
vault = "$vault"

[secrets]
EOF
}

# Helper function to create a Proton Pass config without vault
create_proton_pass_config_no_vault() {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.protonpass]
type = "proton-pass"

[secrets]
EOF
}

@test "fnox get retrieves secret from Proton Pass with full pass:// reference" {
	# This test requires a pre-existing item in Proton Pass
	# Skip if test item is not configured
	if [ -z "$PROTON_PASS_TEST_ITEM" ]; then
		skip "PROTON_PASS_TEST_ITEM not set. Set this to an existing item name in your vault."
	fi

	create_proton_pass_config_no_vault

	# Add secret reference to config using full pass:// format
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SECRET]
provider = "protonpass"
value = "pass://$TEST_VAULT/$PROTON_PASS_TEST_ITEM/password"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_SECRET
	assert_success
	# Output should not be empty
	[ -n "$output" ]
}

@test "fnox get retrieves secret with vault/item/field format" {
	# This test requires a pre-existing item in Proton Pass
	if [ -z "$PROTON_PASS_TEST_ITEM" ]; then
		skip "PROTON_PASS_TEST_ITEM not set. Set this to an existing item name in your vault."
	fi

	create_proton_pass_config_no_vault

	# Add secret reference to config using vault/item/field format
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SECRET]
provider = "protonpass"
value = "$TEST_VAULT/$PROTON_PASS_TEST_ITEM/password"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_SECRET
	assert_success
	[ -n "$output" ]
}

@test "fnox get retrieves secret with item/field format when vault is configured" {
	# This test requires a pre-existing item in Proton Pass
	if [ -z "$PROTON_PASS_TEST_ITEM" ]; then
		skip "PROTON_PASS_TEST_ITEM not set. Set this to an existing item name in your vault."
	fi

	create_proton_pass_config "$TEST_VAULT"

	# Add secret reference to config using item/field format
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SECRET]
provider = "protonpass"
value = "$PROTON_PASS_TEST_ITEM/password"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_SECRET
	assert_success
	[ -n "$output" ]
}

@test "fnox get retrieves secret with item name only when vault is configured" {
	# This test requires a pre-existing item in Proton Pass
	if [ -z "$PROTON_PASS_TEST_ITEM" ]; then
		skip "PROTON_PASS_TEST_ITEM not set. Set this to an existing item name in your vault."
	fi

	create_proton_pass_config "$TEST_VAULT"

	# Add secret reference to config using item name only (defaults to password field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SECRET]
provider = "protonpass"
value = "$PROTON_PASS_TEST_ITEM"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_SECRET
	assert_success
	[ -n "$output" ]
}

@test "fnox get fails without vault when using item-only reference" {
	create_proton_pass_config_no_vault

	# Add secret reference without vault
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SECRET]
provider = "protonpass"
value = "some-item"
EOF

	# Should fail because vault is not configured
	run "$FNOX_BIN" get TEST_SECRET
	assert_failure
	assert_output --partial "Unknown vault"
}

@test "fnox get fails with invalid reference format (too many slashes)" {
	create_proton_pass_config "$TEST_VAULT"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_FORMAT]
provider = "protonpass"
value = "a/b/c/d/e"
EOF

	run "$FNOX_BIN" get INVALID_FORMAT
	assert_failure
	assert_output --partial "Invalid secret reference format"
}

@test "fnox get fails with nonexistent item" {
	create_proton_pass_config "$TEST_VAULT"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.NONEXISTENT]
provider = "protonpass"
value = "nonexistent-item-$(date +%s)"
EOF

	# Should fail because item doesn't exist
	run "$FNOX_BIN" get NONEXISTENT
	assert_failure
}

@test "fnox list shows Proton Pass secrets" {
	create_proton_pass_config "$TEST_VAULT"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.PP_SECRET_1]
description = "First Proton Pass secret"
provider = "protonpass"
value = "item1"

[secrets.PP_SECRET_2]
description = "Second Proton Pass secret"
provider = "protonpass"
value = "item2/username"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "PP_SECRET_1"
	assert_output --partial "PP_SECRET_2"
	assert_output --partial "First Proton Pass secret"
}

@test "fnox provider add creates Proton Pass provider config" {
	# Initialize fnox first
	run "$FNOX_BIN" init
	assert_success

	# Add a Proton Pass provider
	run "$FNOX_BIN" provider add mypass proton-pass
	assert_success

	# Check the config file
	run cat "$FNOX_CONFIG_FILE"
	assert_output --partial "[providers.mypass]"
	assert_output --partial 'type = "proton-pass"'
}

@test "fnox provider add with vault creates proper config" {
	# Initialize fnox first
	run "$FNOX_BIN" init
	assert_success

	# Add a Proton Pass provider with vault
	run "$FNOX_BIN" provider add mypass proton-pass --vault "MyVault"
	assert_success

	# Check the config file
	run cat "$FNOX_CONFIG_FILE"
	assert_output --partial "[providers.mypass]"
	assert_output --partial 'type = "proton-pass"'
	assert_output --partial 'vault = "MyVault"'
}

@test "Proton Pass provider fails gracefully with missing authentication" {
	# This test verifies that fnox returns an auth_failed error when not authenticated
	# The setup() function skips auth check for tests with "fails gracefully" in the name

	create_proton_pass_config "$TEST_VAULT"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SECRET]
provider = "protonpass"
value = "some-item"
EOF

	# If authenticated, skip this test (we need to be unauthenticated to test auth failure)
	if pass-cli test >/dev/null 2>&1; then
		skip "Already authenticated with Proton Pass. Run 'pass-cli logout' to test auth failure handling."
	fi

	# Run the get command - should fail with auth_failed error
	run "$FNOX_BIN" get TEST_SECRET
	assert_failure
	assert_output --partial "auth_failed"
}
