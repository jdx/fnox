#!/usr/bin/env bats
#
# HashiCorp Vault Provider Tests
#
# These tests verify the HashiCorp Vault provider integration with fnox.
#
# Prerequisites:
#   1. Install Vault CLI: mise install vault
#   2. Start Vault dev server: source ./test/setup-vault-test.sh
#   3. Run tests: mise run test:bats -- test/vault.bats
#
# Note: Tests will automatically skip if VAULT_TOKEN is not available.
#       These tests create and delete temporary secrets in your Vault instance.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Check if vault CLI is installed
	if ! command -v vault >/dev/null 2>&1; then
		skip "Vault CLI not installed. Install with: mise install vault"
	fi

	# Some tests don't need VAULT_TOKEN (like 'fnox list')
	# Only skip if this test actually needs authentication
	if [[ $BATS_TEST_DESCRIPTION != *"list"* ]]; then
		# Check if VAULT_TOKEN is available
		if [ -z "$VAULT_TOKEN" ]; then
			skip "VAULT_TOKEN not available. Run: source ./test/setup-vault-test.sh"
		fi

		# Set default VAULT_ADDR if not set
		if [ -z "$VAULT_ADDR" ]; then
			export VAULT_ADDR="http://localhost:8200"
		fi

		# Verify we can authenticate with Vault by checking status
		if ! vault status >/dev/null 2>&1; then
			skip "Cannot authenticate with Vault. Server may not be running or token invalid."
		fi
	fi
}

teardown() {
	_common_teardown
}

# Helper function to create a Vault test config
create_vault_config() {
	local vault_addr="${1:-http://localhost:8200}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.vault]
type = "vault"
address = "$vault_addr"

[secrets]
EOF
}

# Helper function to create a test secret in Vault
# Returns the secret name
create_test_vault_secret() {
	local secret_name
	secret_name="fnox-test-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_value
	secret_value="test-secret-value-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local username="testuser"

	# Create secret with vault CLI
	# vault kv put secret/data/<name> key=value
	vault kv put "secret/$secret_name" \
		value="$secret_value" \
		username="$username" \
		description="Created by fnox test" \
		>/dev/null 2>&1

	echo "$secret_name"
}

# Helper function to delete a test secret from Vault
delete_test_vault_secret() {
	local secret_name="${1}"
	vault kv delete "secret/$secret_name" >/dev/null 2>&1 || true
}

@test "fnox get retrieves secret from Vault" {
	create_vault_config

	# Create a test secret
	secret_name=$(create_test_vault_secret)

	# Add secret reference to config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_VAULT_SECRET]
provider = "vault"
value = "$secret_name"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_VAULT_SECRET
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_vault_secret "$secret_name"
}

@test "fnox get retrieves specific field from Vault secret" {
	create_vault_config

	# Create a test secret
	secret_name=$(create_test_vault_secret)

	# Add secret reference to config (fetch username field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_USERNAME]
provider = "vault"
value = "$secret_name/username"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_USERNAME
	assert_success
	assert_output "testuser"

	# Cleanup
	delete_test_vault_secret "$secret_name"
}

@test "fnox get retrieves value field from Vault secret" {
	create_vault_config

	# Create a test secret
	secret_name=$(create_test_vault_secret)

	# Add secret reference to config (explicit value field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_VALUE]
provider = "vault"
value = "$secret_name/value"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_VALUE
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_vault_secret "$secret_name"
}

@test "fnox get fails with invalid secret name" {
	create_vault_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_SECRET]
provider = "vault"
value = "nonexistent-secret-$(date +%s)"
EOF

	# Try to get non-existent secret
	run "$FNOX_BIN" get INVALID_SECRET
	assert_failure
	assert_output --partial "HashiCorp Vault: command failed"
}

@test "fnox get handles invalid secret reference format" {
	create_vault_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_FORMAT]
provider = "vault"
value = "invalid/format/with/too/many/slashes"
EOF

	run "$FNOX_BIN" get INVALID_FORMAT
	assert_failure
	assert_output --partial "Invalid secret reference format"
}

@test "fnox list shows Vault secrets" {
	# This test doesn't need VAULT_TOKEN since list just reads the config file
	create_vault_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.VAULT_SECRET_1]
description = "First Vault secret"
provider = "vault"
value = "secret1"

[secrets.VAULT_SECRET_2]
description = "Second Vault secret"
provider = "vault"
value = "secret2/username"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "VAULT_SECRET_1"
	assert_output --partial "VAULT_SECRET_2"
	assert_output --partial "First Vault secret"
}

@test "Vault provider works with token from environment" {
	# This test verifies that vault CLI uses VAULT_TOKEN from environment
	# The token should be set by setup() from fnox config or environment

	create_vault_config

	secret_name=$(create_test_vault_secret)

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_WITH_ENV_TOKEN]
provider = "vault"
value = "$secret_name"
EOF

	# The VAULT_TOKEN should be set by setup()
	run "$FNOX_BIN" get TEST_WITH_ENV_TOKEN
	assert_success
	assert_output --partial "test-secret-value-"

	# Cleanup
	delete_test_vault_secret "$secret_name"
}

@test "Vault provider with custom path prefix" {
	# Create config with custom path (no /data/ - vault kv adds it automatically)
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.vault]
type = "vault"
address = "http://localhost:8200"
path = "secret/custom"

[secrets.TEST_SECRET]
provider = "vault"
value = "test-item"
EOF

	# Create a secret at the custom path
	vault kv put "secret/custom/test-item" value="custom-path-value" >/dev/null 2>&1

	# Get the secret
	run "$FNOX_BIN" get TEST_SECRET
	assert_success
	assert_output "custom-path-value"

	# Cleanup
	vault kv delete "secret/custom/test-item" >/dev/null 2>&1 || true
}

@test "Vault provider with token in config" {
	# Create config with token in provider config (not recommended for real use)
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.vault]
type = "vault"
address = "http://localhost:8200"
token = "$VAULT_TOKEN"

[secrets.TEST_TOKEN_IN_CONFIG]
provider = "vault"
value = "test-secret"
EOF

	# Create a test secret
	vault kv put "secret/test-secret" value="token-in-config-test" >/dev/null 2>&1

	# Temporarily unset VAULT_TOKEN to force using config token
	VAULT_TOKEN_BACKUP="$VAULT_TOKEN"
	unset VAULT_TOKEN

	# Get the secret
	run "$FNOX_BIN" get TEST_TOKEN_IN_CONFIG
	assert_success
	assert_output "token-in-config-test"

	# Restore token
	export VAULT_TOKEN="$VAULT_TOKEN_BACKUP"

	# Cleanup
	vault kv delete "secret/test-secret" >/dev/null 2>&1 || true
}

@test "Vault provider test connection works" {
	create_vault_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.DUMMY_SECRET]
provider = "vault"
value = "dummy"
EOF

	# The test_connection is called during provider initialization
	# If vault is accessible, get should work (even if secret doesn't exist)
	# We're just testing that the connection test doesn't fail
	run "$FNOX_BIN" list
	assert_success
}

@test "Vault provider with description field" {
	create_vault_config

	# Create a test secret
	secret_name=$(create_test_vault_secret)

	# Add secret reference to config (fetch description field)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.TEST_DESCRIPTION]
provider = "vault"
value = "$secret_name/description"
EOF

	# Get the secret
	run "$FNOX_BIN" get TEST_DESCRIPTION
	assert_success
	assert_output "Created by fnox test"

	# Cleanup
	delete_test_vault_secret "$secret_name"
}
