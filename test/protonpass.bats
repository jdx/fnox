#!/usr/bin/env bats
#
# Proton Pass Provider Tests
#
# These tests verify Proton Pass provider integration with fnox.
# The provider stores all secrets for a project in a single custom item with hidden fields.
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
#       Tests should run serially (within this file) to avoid race conditions.
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
	local item_name="${1:-fnox-test-project}"
	local vault="${2:-fnox}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.protonpass]
type = "protonpass"
item_name = "$item_name"
vault_name = "$vault"

[secrets]
EOF
}

# Helper function to delete a test item from Proton Pass
delete_test_pass_item() {
	local vault="${1:-fnox}"
	local item_name="${2}"
	pass-cli item delete "$item_name" --vault-name="$vault" >/dev/null 2>&1 || true
}

@test "fnox set creates custom item with Secrets section" {
	local item_name
	item_name="fnox-test-item-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set a secret to trigger item creation
	run "$FNOX_BIN" set TEST_SECRET "test-value-123"
	assert_success

	# Verify the item was created in Proton Pass
	run pass-cli item list --vault-name="fnox" --output=json
	assert_success

	# Check if item exists in the output
	assert_output --partial "$item_name"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "fnox set adds hidden field to custom item" {
	local item_name
	item_name="fnox-test-field-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set a secret
	run "$FNOX_BIN" set API_KEY "secret-api-key-123"
	assert_success

	# View the item to verify field structure
	run pass-cli item view --item-title="$item_name" --vault-name="fnox" --output=json
	assert_success

	# Verify it's a custom item with Secrets section
	assert_output --partial '"sections"'
	assert_output --partial '"Secrets"'

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "fnox get retrieves field from custom item" {
	local item_name
	item_name="fnox-test-get-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set a secret
	run "$FNOX_BIN" set MY_SECRET "my-secret-value-456"
	assert_success

	# Get the secret back
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output "my-secret-value-456"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "fnox set updates existing field in custom item" {
	local item_name
	item_name="fnox-test-update-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set a secret
	run "$FNOX_BIN" set MY_KEY "initial-value"
	assert_success

	# Get the secret
	run "$FNOX_BIN" get MY_KEY
	assert_success
	assert_output "initial-value"

	# Update the secret
	run "$FNOX_BIN" set MY_KEY "updated-value"
	assert_success

	# Get the updated secret
	run "$FNOX_BIN" get MY_KEY
	assert_success
	assert_output "updated-value"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "multiple secrets in same item" {
	local item_name
	item_name="fnox-test-multi-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set multiple secrets
	run "$FNOX_BIN" set SECRET_1 "value-1"
	assert_success

	run "$FNOX_BIN" set SECRET_2 "value-2"
	assert_success

	run "$FNOX_BIN" set SECRET_3 "value-3"
	assert_success

	# Get all secrets back
	run "$FNOX_BIN" get SECRET_1
	assert_success
	assert_output "value-1"

	run "$FNOX_BIN" get SECRET_2
	assert_success
	assert_output "value-2"

	run "$FNOX_BIN" get SECRET_3
	assert_success
	assert_output "value-3"

	# Verify only one item exists (all secrets in same item)
	run pass-cli item list --vault-name="fnox" --output=json | grep -o "\"name\":\"$item_name\"" | wc -l
	assert_output "1"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "missing field returns error" {
	local item_name
	item_name="fnox-test-missing-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set one secret
	run "$FNOX_BIN" set EXISTING_SECRET "exists"
	assert_success

	# Try to get non-existent field
	run "$FNOX_BIN" get NONEXISTENT_FIELD
	assert_failure
	assert_output --partial "not found"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "fnox get fails for nonexistent item" {
	local item_name
	item_name="fnox-nonexistent-item-$(date +%s)"
	create_protonpass_config "$item_name" "fnox"

	# Try to get secret from non-existent item
	run "$FNOX_BIN" get SOME_FIELD
	assert_failure
	assert_output --partial "not found"
}

@test "fnox get fails with invalid vault" {
	local item_name
	item_name="fnox-test-vault-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "nonexistent-vault-$(date +%s)"

	# Try to get secret from non-existent vault
	run "$FNOX_BIN" get SOME_FIELD
	assert_failure
}

@test "fnox list shows Proton Pass secrets" {
	local item_name
	item_name="fnox-test-list-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set multiple secrets
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.API_KEY]
provider = "protonpass"
value = "API_KEY"
description = "API Key for service"

[secrets.DB_PASSWORD]
provider = "protonpass"
value = "DB_PASSWORD"
description = "Database password"
EOF

	# List secrets
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "API_KEY"
	assert_output --partial "DB_PASSWORD"
	assert_output --partial "API Key for service"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "fnox get with vault_name parameter" {
	local item_name
	item_name="fnox-test-vault-param-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set and get secret with vault_name configured
	run "$FNOX_BIN" set TEST_SECRET "vault-test-value"
	assert_success

	run "$FNOX_BIN" get TEST_SECRET
	assert_success
	assert_output "vault-test-value"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "Proton Pass provider handles field names with special characters" {
	local item_name
	item_name="fnox-test-special-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set secret with underscore in name
	run "$FNOX_BIN" set API_KEY_V2 "v2-secret"
	assert_success

	run "$FNOX_BIN" get API_KEY_V2
	assert_success
	assert_output "v2-secret"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "fnox exec injects secrets from Proton Pass" {
	local item_name
	item_name="fnox-test-exec-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set a secret
	run "$FNOX_BIN" set TEST_VAR "exec-test-value"
	assert_success

	# Execute command with secret injected
	run "$FNOX_BIN" exec -- env | grep "^TEST_VAR="
	assert_success
	assert_output "TEST_VAR=exec-test-value"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}

@test "Proton Pass provider with share_id parameter" {
	skip "Requires specific share ID configuration"

	# This test verifies that share_id can be configured
	# It requires a known share_id which is user-specific

	# Create config with share_id
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.protonpass]
type = "protonpass"
item_name = "test-item"
share_id = "test-share-id"

[secrets.TEST_SECRET]
provider = "protonpass"
value = "TEST_SECRET"
EOF

	# This would test that share_id is passed to pass-cli
	# but requires a real share_id to work
	run "$FNOX_BIN" get TEST_SECRET
	# Will fail without real share_id, but that's expected
}

@test "fnox get_secrets_batch retrieves multiple secrets" {
	local item_name
	item_name="fnox-test-batch-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	create_protonpass_config "$item_name" "fnox"

	# Set multiple secrets
	run "$FNOX_BIN" set BATCH_1 "value-1"
	assert_success

	run "$FNOX_BIN" set BATCH_2 "value-2"
	assert_success

	run "$FNOX_BIN" set BATCH_3 "value-3"
	assert_success

	# Execute command to verify all secrets are injected
	run "$FNOX_BIN" exec -- sh -c 'echo "BATCH_1=$BATCH_1;BATCH_2=$BATCH_2;BATCH_3=$BATCH_3"'
	assert_success
	assert_output "BATCH_1=value-1;BATCH_2=value-2;BATCH_3=value-3"

	# Cleanup
	delete_test_pass_item "fnox" "$item_name"
}
