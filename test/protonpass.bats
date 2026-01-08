#!/usr/bin/env bats
#
# Proton Pass Provider Tests
#
# These tests verify Proton Pass provider integration with fnox.
#
# Prerequisites:
#   1. Install Proton Pass CLI: brew install protonpass/tap/pass-cli
#      OR: mise use -g github:tnfssc/protonpass-cli-bin
#   2. Login to Proton Pass: pass-cli login
#   3. Create a vault named "fnox" (if needed)
#   4. Run tests: mise run test:bats -- test/protonpass.bats
#
# Note: Tests will automatically skip if:
#       - pass-cli not installed
#       - Not logged in to Proton Pass
#       - The 'fnox' vault doesn't exist
#
#       These tests create and delete temporary items in the "fnox" vault.
#       Tests should run serially (within this file) to avoid race conditions when
#       creating/deleting items. Use `--no-parallelize-within-files` bats flag.
#
# CI Setup:
#   Unlike Bitwarden (which can use a local vaultwarden server), Proton Pass requires
#   a real Proton Pass account and authenticated session. In CI environments without
#   proper Proton Pass setup, these tests will gracefully skip with informative messages.
#
#   To run these tests in CI:
#   1. Create a Proton Pass account with access to a "fnox" vault
#   2. Store credentials securely in CI secrets
#   3. Configure pass-cli in CI to use those credentials
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Check if pass-cli is installed
	if ! command -v pass-cli >/dev/null 2>&1; then
		skip "Proton Pass CLI (pass-cli) not installed. Install with: brew install protonpass/tap/pass-cli"
	fi

	# Check if we're logged in to Proton Pass
	if ! pass-cli test >/dev/null 2>&1; then
		skip "Not logged in to Proton Pass. Login with: pass-cli login"
	fi

	# Check if 'fnox' vault exists
	if ! pass-cli vault list | grep -q "fnox" >/dev/null 2>&1; then
		skip "The 'fnox' vault does not exist. Create it with: pass-cli vault create fnox"
	fi
}

teardown() {
	_common_teardown
}

# Helper function to create a Proton Pass test config
create_protonpass_config() {
	local vault="${1:-fnox}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.protonpass]
type = "protonpass"
vault_name = "$vault"

[secrets]
EOF
}

# Helper function to create a test item in Proton Pass
# Returns item name on success, empty string on failure
create_test_pass_item() {
	local vault="${1:-fnox}"
	local item_name
	item_name="fnox-test-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local password
	password="test-secret-value-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"

	# Create item with pass-cli
	if pass-cli item create \
		--category=password \
		--title="$item_name" \
		--vault-name="$vault" \
		"password=$password" >/dev/null 2>&1; then
		echo "$item_name"
		return 0
	else
		# Return empty string on failure
		return 1
	fi
}

# Helper function to delete a test item from Proton Pass
delete_test_pass_item() {
	local vault="${1:-fnox}"
	local item_name="${2}"
	pass-cli item delete "$item_name" --vault-name="$vault" >/dev/null 2>&1 || true
}

@test "fnox get retrieves secret from Proton Pass" {
	create_protonpass_config "fnox"

	# Create a test item
	if ! item_name=$(create_test_pass_item "fnox"); then
		skip "Failed to create test item in Proton Pass"
	fi

	# Add secret reference to config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_PP_SECRET]
provider = "protonpass"
value = "$item_name"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_PP_SECRET
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "fnox get retrieves specific field from Proton Pass item" {
	create_protonpass_config "fnox"

	# Create a test item with custom field
	item_name="fnox-test-field-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	if ! pass-cli item create \
		--category=password \
		--title="$item_name" \
		--vault-name="fnox" \
		"username=testuser" \
		"password=testpass" >/dev/null 2>&1; then
		skip "Failed to create test item in Proton Pass"
	fi

	# Add secret reference to config (fetch username field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_USERNAME]
provider = "protonpass"
value = "$item_name/username"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_USERNAME
	assert_success
	assert_output "testuser"

	# Cleanup
	pass-cli item delete "$item_name" --vault-name="fnox" >/dev/null 2>&1 || true
}

@test "fnox get handles invalid item name" {
	create_protonpass_config "fnox"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_ITEM]
provider = "protonpass"
value = "nonexistent-item-$(date +%s)"
EOF

	# Try to get non-existent secret
	run "$FNOX_BIN" get INVALID_ITEM
	assert_failure
	assert_output --partial "not found"
}

@test "fnox get fails with invalid vault" {
	create_protonpass_config "nonexistent-vault-$(date +%s)"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_SECRET]
provider = "protonpass"
value = "some-item"
EOF

	# Try to get secret from non-existent vault
	run "$FNOX_BIN" get TEST_SECRET
	assert_failure
}

@test "fnox list shows Proton Pass secrets" {
	create_protonpass_config "fnox"

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

@test "fnox get handles invalid secret reference format" {
	create_protonpass_config "fnox"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_FORMAT]
provider = "protonpass"
value = "invalid/format/with/too/many/slashes"
EOF

	run "$FNOX_BIN" get INVALID_FORMAT
	assert_failure
	assert_output --partial "Invalid secret reference format"
}

@test "fnox get with Proton Pass vault_name parameter" {
	create_protonpass_config "fnox"

	if ! item_name=$(create_test_pass_item "fnox"); then
		skip "Failed to create test item in Proton Pass"
	fi

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_WITH_VAULT]
provider = "protonpass"
value = "$item_name"
EOF

	# This should use the vault_name from provider config
	run "$FNOX_BIN" get TEST_WITH_VAULT
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "Proton Pass provider handles multiline secrets" {
	create_protonpass_config "fnox"

	# Create a test item with multiline notes
	item_name="fnox-test-multiline-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	if ! pass-cli item create \
		--category=password \
		--title="$item_name" \
		--vault-name="fnox" \
		"password=testpass" \
		"notes=line1
line2
line3" >/dev/null 2>&1; then
		skip "Failed to create test item in Proton Pass"
	fi

	# Add secret reference to config (fetch notes field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_MULTILINE]
provider = "protonpass"
value = "$item_name/notes"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_MULTILINE
	assert_success
	assert_output --partial "line1"

	# Cleanup
	pass-cli item delete "$item_name" --vault-name="fnox" >/dev/null 2>&1 || true
}

@test "fnox get supports custom fields" {
	create_protonpass_config "fnox"

	# Create a test item with custom field
	item_name="fnox-test-custom-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	if ! pass-cli item create \
		--category=login \
		--title="$item_name" \
		--vault-name="fnox" \
		"username=testuser" \
		"password=testpass" \
		"customField=customValue" >/dev/null 2>&1; then
		skip "Failed to create test item in Proton Pass"
	fi

	# Add secret reference to config (fetch custom field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_CUSTOM_FIELD]
provider = "protonpass"
value = "$item_name/customField"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_CUSTOM_FIELD
	assert_success
	assert_output "customValue"

	# Cleanup
	pass-cli item delete "$item_name" --vault-name="fnox" >/dev/null 2>&1 || true
}

@test "Proton Pass provider with share_id parameter" {
	skip "Requires specific share ID configuration"

	# This test verifies that share_id can be configured
	# It requires a known share_id which is user-specific

	# Create config with share_id
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.protonpass]
type = "protonpass"
share_id = "test-share-id"

[secrets.TEST_SECRET]
provider = "protonpass"
value = "test-item"
EOF

	# This would test that share_id is passed to pass-cli
	# but requires a real share_id to work
	run "$FNOX_BIN" get TEST_SECRET
	# Will fail without real share_id, but that's expected
}
