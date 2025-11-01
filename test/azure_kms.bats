#!/usr/bin/env bats
#
# Azure KMS Provider Tests
#
# These tests verify the Azure KMS (Azure Key Vault Keys) provider integration with fnox.
#
# Prerequisites:
#   1. Azure credentials configured (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
#   2. Azure Key Vault with a key available
#   3. IAM permissions: Key Vault Crypto User role
#   4. Run tests: mise run test:bats -- test/azure_kms.bats
#
# Note: Tests will automatically skip if Azure credentials are not available.
#       The mise task runs `fnox exec` which automatically decrypts provider-based secrets.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Check if Azure credentials are available
	if [ -z "$AZURE_CLIENT_ID" ] || [ -z "$AZURE_CLIENT_SECRET" ] || [ -z "$AZURE_TENANT_ID" ]; then
		skip "Azure credentials not available. Ensure AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID are configured."
	fi

	# Check if az CLI is installed
	if ! command -v az >/dev/null 2>&1; then
		skip "Azure CLI not installed. Install with: brew install azure-cli"
	fi

	# Set the Key Vault URL and key name
	export VAULT_URL="https://fnox-testing-kv.vault.azure.net/"
	export KEY_NAME="fnox-test-key"

	# Authenticate Azure CLI with service principal if not already logged in
	if ! az account show >/dev/null 2>&1; then
		az login --service-principal \
			-u "$AZURE_CLIENT_ID" \
			-p "$AZURE_CLIENT_SECRET" \
			--tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 ||
			skip "Failed to authenticate Azure CLI with service principal"
	fi

	# Verify we can access the Key Vault key
	if ! az keyvault key show --vault-name fnox-testing-kv --name "$KEY_NAME" >/dev/null 2>&1; then
		skip "Cannot access Azure Key Vault key '$KEY_NAME'. Key may not exist or permissions may be insufficient."
	fi
}

teardown() {
	_common_teardown
}

# Helper function to create an Azure KMS test config
create_azure_kms_config() {
	local vault_url="${1:-https://fnox-testing-kv.vault.azure.net/}"
	local key_name="${2:-fnox-test-key}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.azure-kms]
type = "azure-kms"
vault_url = "$vault_url"
key_name = "$key_name"

[secrets]
EOF
}

@test "fnox set encrypts secret with Azure KMS" {
	create_azure_kms_config

	# Set a secret with Azure KMS encryption
	run "$FNOX_BIN" set AZURE_KMS_TEST_SECRET "my-secret-value" --provider azure-kms
	assert_success
	assert_output --partial "✓ Set secret AZURE_KMS_TEST_SECRET"

	# Verify the config contains encrypted value (base64)
	run grep "value =" "${FNOX_CONFIG_FILE}"
	assert_success
	assert_output --regexp 'value = "[A-Za-z0-9+/=]{50,}"'
}

@test "fnox get decrypts secret from Azure KMS" {
	create_azure_kms_config

	# Set a secret
	run "$FNOX_BIN" set AZURE_KMS_DECRYPT_TEST "test-plaintext-value" --provider azure-kms
	assert_success

	# Get the secret back
	run "$FNOX_BIN" get AZURE_KMS_DECRYPT_TEST
	assert_success
	assert_output "test-plaintext-value"
}

@test "fnox set and get with special characters" {
	create_azure_kms_config

	# Set a secret with special characters
	local special_value='{"password":"p@ssw0rd!","key":"abc=123&xyz"}'
	run "$FNOX_BIN" set AZURE_KMS_SPECIAL_CHARS "$special_value" --provider azure-kms
	assert_success

	# Get the secret back
	run "$FNOX_BIN" get AZURE_KMS_SPECIAL_CHARS
	assert_success
	assert_output "$special_value"
}

@test "fnox set with multiline secret" {
	create_azure_kms_config

	# Set a multiline secret
	local multiline_value="line1
line2
line3"
	run "$FNOX_BIN" set AZURE_KMS_MULTILINE "$multiline_value" --provider azure-kms
	assert_success

	# Get the secret back
	run "$FNOX_BIN" get AZURE_KMS_MULTILINE
	assert_success
	assert_output "$multiline_value"
}

@test "fnox get fails with invalid ciphertext" {
	create_azure_kms_config

	# Manually create config with invalid base64 ciphertext
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_CIPHERTEXT]
provider = "azure-kms"
value = "invalid-base64-!@#$%"
EOF

	run "$FNOX_BIN" get INVALID_CIPHERTEXT
	assert_failure
	assert_output --partial "Failed to decode base64 ciphertext"
}

@test "fnox set warns and stores plaintext with wrong key" {
	# Create config with non-existent key
	create_azure_kms_config "https://fnox-testing-kv.vault.azure.net/" "non-existent-key"

	# When encryption fails, fnox currently warns and stores plaintext
	run "$FNOX_BIN" set AZURE_KMS_WRONG_KEY "test" --provider azure-kms
	assert_success
	assert_output --partial "Encryption not supported for provider 'azure-kms'"
	assert_output --partial "Storing plaintext"
}

@test "fnox list shows Azure KMS secrets" {
	create_azure_kms_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.AZURE_KMS_SECRET_1]
description = "First Azure KMS secret"
provider = "azure-kms"
value = "AQICAHiy8nEpehKbN0gxZ6AQfrlCEWWoKMLw5eogFUZ3c5gd1QEA1/K/EPEgXnmoj0rHIELGAAAAjDCBiQYJKoZIhvcNAQcGoHwwegIBADB1BgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDNaM0QctJeav8gwCMgIBEIBIbZFODxF3kivTBXDBZ+NenrryPEJz10X6XxeZtT32HjgMtUwravXPF0O4xpoaRlcHVYssmhq2RmOYGJxtlayDC0YsNwfb7kgX"

[secrets.AZURE_KMS_SECRET_2]
description = "Second Azure KMS secret"
provider = "azure-kms"
value = "AQICAHiy8nEpehKbN0gxZ6AQfrlCEWWoKMLw5eogFUZ3c5gd1QEA1/K/EPEgXnmoj0rHIELGAAAAjDCBiQYJKoZIhvcNAQcGoHwwegIBADB1BgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDNaM0QctJeav8gwCMgIBEIBIbZFODxF3kivTBXDBZ+NenrryPEJz10X6XxeZtT32HjgMtUwravXPF0O4xpoaRlcHVYssmhq2RmOYGJxtlayDC0YsNwfb7kgX"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "AZURE_KMS_SECRET_1"
	assert_output --partial "AZURE_KMS_SECRET_2"
	assert_output --partial "First Azure KMS secret"
}

@test "fnox set with description" {
	create_azure_kms_config

	run "$FNOX_BIN" set AZURE_KMS_WITH_DESC "test-value" --provider azure-kms --description "My Azure KMS secret"
	assert_success

	# Verify description is in config
	run grep "description" "${FNOX_CONFIG_FILE}"
	assert_success
	assert_output --partial "My Azure KMS secret"
}

@test "Azure KMS encryption produces different ciphertext each time" {
	create_azure_kms_config

	# Set a secret twice with the same value
	run "$FNOX_BIN" set AZURE_KMS_UNIQUE_1 "same-value" --provider azure-kms
	assert_success

	# Set again with same value
	run "$FNOX_BIN" set AZURE_KMS_UNIQUE_2 "same-value" --provider azure-kms
	assert_success

	# Get the encrypted values from config (inline table format)
	# Secrets are now stored as: AZURE_KMS_UNIQUE_1 = { provider = "azure-kms", value = "..." }
	cipher1=$(grep "^AZURE_KMS_UNIQUE_1\s*=" "${FNOX_CONFIG_FILE}" | sed 's/.*value = "\([^"]*\)".*/\1/')
	cipher2=$(grep "^AZURE_KMS_UNIQUE_2\s*=" "${FNOX_CONFIG_FILE}" | sed 's/.*value = "\([^"]*\)".*/\1/')

	# Verify ciphertexts were extracted
	[ -n "$cipher1" ]
	[ -n "$cipher2" ]

	# Ciphertexts should be different (Azure KMS adds randomness)
	[ "$cipher1" != "$cipher2" ]

	# But both should decrypt to the same value
	run "$FNOX_BIN" get AZURE_KMS_UNIQUE_1
	assert_success
	assert_output "same-value"

	run "$FNOX_BIN" get AZURE_KMS_UNIQUE_2
	assert_success
	assert_output "same-value"
}

@test "fnox set updates existing Azure KMS secret" {
	create_azure_kms_config

	# Set initial value
	run "$FNOX_BIN" set AZURE_KMS_UPDATE_TEST "initial-value" --provider azure-kms
	assert_success

	# Update with new value
	run "$FNOX_BIN" set AZURE_KMS_UPDATE_TEST "updated-value" --provider azure-kms
	assert_success

	# Verify new value is retrieved
	run "$FNOX_BIN" get AZURE_KMS_UPDATE_TEST
	assert_success
	assert_output "updated-value"
}

@test "fnox exec sets Azure KMS environment variables" {
	create_azure_kms_config

	# Set a secret
	run "$FNOX_BIN" set MY_AZURE_KMS_VAR "azure-kms-env-value" --provider azure-kms
	assert_success

	# Use exec to run a command with the secret as env var
	# Explicitly set FNOX_CONFIG_FILE to avoid inheriting parent config
	run env FNOX_CONFIG_FILE="$FNOX_CONFIG_FILE" "$FNOX_BIN" exec -- sh -c 'echo $MY_AZURE_KMS_VAR'
	assert_success
	assert_output "azure-kms-env-value"
}
