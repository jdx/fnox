#!/usr/bin/env bats
#
# AWS KMS Provider Tests
#
# These tests verify the AWS KMS provider integration with fnox.
# Note: Tests use setup_file() to pre-encrypt shared values once,
#       significantly reducing KMS API calls.
#
# Prerequisites:
#   1. AWS credentials configured (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#   2. KMS key available (created during setup)
#   3. IAM permissions: kms:Encrypt, kms:Decrypt, kms:DescribeKey
#   4. Run tests: mise run test:bats -- test/aws_kms.bats
#
# Note: Tests will automatically skip if AWS credentials are not available.
#       The mise task runs `fnox exec` which automatically decrypts provider-based secrets.
#

# File-level setup - runs once before all tests (reduces KMS API calls)
setup_file() {
	# Need to load common setup for FNOX_BIN
	load 'test_helper/common_setup'

	export KMS_KEY_ID="alias/fnox-testing"
	export KMS_REGION="us-east-1"

	# Check if AWS credentials are available
	if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
		export SKIP_AWS_KMS_TESTS="AWS credentials not available. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are configured."
		return
	fi

	# Check if aws CLI is installed
	if ! command -v aws >/dev/null 2>&1; then
		export SKIP_AWS_KMS_TESTS="AWS CLI not installed. Install with: brew install awscli"
		return
	fi

	# Verify we can access the KMS key (single API call for all tests)
	if ! aws kms describe-key --key-id "$KMS_KEY_ID" --region "$KMS_REGION" >/dev/null 2>&1; then
		export SKIP_AWS_KMS_TESTS="Cannot access KMS key '$KMS_KEY_ID'. Key may not exist or permissions may be insufficient."
		return
	fi

	# Get the full ARN for later tests (single API call)
	export KMS_KEY_ARN
	KMS_KEY_ARN=$(aws kms describe-key --key-id "$KMS_KEY_ID" --region "$KMS_REGION" --query 'KeyMetadata.Arn' --output text)

	# Pre-encrypt shared test values using AWS CLI directly (reduces fnox encrypt calls)
	# These ciphertexts can be reused across multiple tests
	# Note: Using fileb:///dev/stdin to pass raw plaintext bytes to aws kms encrypt
	export SHARED_SIMPLE_VALUE="test-plaintext-value"
	export SHARED_SIMPLE_CIPHERTEXT
	SHARED_SIMPLE_CIPHERTEXT=$(echo -n "$SHARED_SIMPLE_VALUE" | aws kms encrypt \
		--key-id "$KMS_KEY_ID" \
		--plaintext fileb:///dev/stdin \
		--region "$KMS_REGION" \
		--query 'CiphertextBlob' \
		--output text)

	export SHARED_SPECIAL_VALUE='{"password":"p@ssw0rd!","key":"abc=123&xyz"}'
	export SHARED_SPECIAL_CIPHERTEXT
	SHARED_SPECIAL_CIPHERTEXT=$(echo -n "$SHARED_SPECIAL_VALUE" | aws kms encrypt \
		--key-id "$KMS_KEY_ID" \
		--plaintext fileb:///dev/stdin \
		--region "$KMS_REGION" \
		--query 'CiphertextBlob' \
		--output text)

	export SHARED_MULTILINE_VALUE="line1
line2
line3"
	export SHARED_MULTILINE_CIPHERTEXT
	SHARED_MULTILINE_CIPHERTEXT=$(printf '%s' "$SHARED_MULTILINE_VALUE" | aws kms encrypt \
		--key-id "$KMS_KEY_ID" \
		--plaintext fileb:///dev/stdin \
		--region "$KMS_REGION" \
		--query 'CiphertextBlob' \
		--output text)

	export SHARED_ENV_VALUE="kms-env-value"
	export SHARED_ENV_CIPHERTEXT
	SHARED_ENV_CIPHERTEXT=$(echo -n "$SHARED_ENV_VALUE" | aws kms encrypt \
		--key-id "$KMS_KEY_ID" \
		--plaintext fileb:///dev/stdin \
		--region "$KMS_REGION" \
		--query 'CiphertextBlob' \
		--output text)
}

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Skip if file-level setup determined we can't run
	if [ -n "$SKIP_AWS_KMS_TESTS" ]; then
		skip "$SKIP_AWS_KMS_TESTS"
	fi
}

teardown() {
	_common_teardown
}

# Helper function to create an AWS KMS test config
create_kms_config() {
	local key_id="${1:-alias/fnox-testing}"
	local region="${2:-us-east-1}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.kms]
type = "aws-kms"
key_id = "$key_id"
region = "$region"

[secrets]
EOF
}

# Helper to create config with pre-encrypted secret
create_kms_config_with_secret() {
	local secret_name="$1"
	local ciphertext="$2"
	local key_id="${3:-alias/fnox-testing}"
	local region="${4:-us-east-1}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.kms]
type = "aws-kms"
key_id = "$key_id"
region = "$region"

[secrets]
$secret_name = { provider = "kms", value = "$ciphertext" }
EOF
}

@test "fnox set encrypts secret with AWS KMS" {
	create_kms_config

	# Set a secret with KMS encryption
	run "$FNOX_BIN" set KMS_TEST_SECRET "my-secret-value" --provider kms
	assert_success
	assert_output --partial "✓ Set secret KMS_TEST_SECRET"

	# Verify the config contains encrypted value (base64)
	run grep "value =" "${FNOX_CONFIG_FILE}"
	assert_success
	assert_output --regexp 'value = "[A-Za-z0-9+/=]{50,}"'
}

@test "fnox get decrypts secret from AWS KMS" {
	# Use pre-encrypted value from setup_file (no KMS encrypt call needed)
	create_kms_config_with_secret "KMS_DECRYPT_TEST" "$SHARED_SIMPLE_CIPHERTEXT"

	# Get the secret back (only 1 KMS decrypt call)
	run "$FNOX_BIN" get KMS_DECRYPT_TEST
	assert_success
	assert_output "$SHARED_SIMPLE_VALUE"
}

@test "fnox get decrypts secret with special characters" {
	# Use pre-encrypted value from setup_file
	create_kms_config_with_secret "KMS_SPECIAL_CHARS" "$SHARED_SPECIAL_CIPHERTEXT"

	# Get the secret back
	run "$FNOX_BIN" get KMS_SPECIAL_CHARS
	assert_success
	assert_output "$SHARED_SPECIAL_VALUE"
}

@test "fnox get decrypts multiline secret" {
	# Use pre-encrypted value from setup_file
	create_kms_config_with_secret "KMS_MULTILINE" "$SHARED_MULTILINE_CIPHERTEXT"

	# Get the secret back
	run "$FNOX_BIN" get KMS_MULTILINE
	assert_success
	assert_output "$SHARED_MULTILINE_VALUE"
}

@test "fnox get fails with invalid ciphertext" {
	create_kms_config

	# Manually create config with invalid base64 ciphertext (no KMS calls)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.INVALID_CIPHERTEXT]
provider = "kms"
value = "invalid-base64-!@#\$%"
EOF

	run "$FNOX_BIN" get INVALID_CIPHERTEXT
	assert_failure
	assert_output --partial "Failed to decode base64 ciphertext"
}

@test "fnox set warns and stores plaintext with wrong KMS key" {
	# Create config with non-existent key (fails fast, no actual KMS encryption)
	create_kms_config "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"

	# When encryption fails, fnox currently warns and stores plaintext
	run "$FNOX_BIN" set KMS_WRONG_KEY "test" --provider kms
	assert_success
	assert_output --partial "Encryption not supported for provider 'kms'"
	assert_output --partial "Storing plaintext"
}

@test "fnox list shows KMS secrets" {
	create_kms_config

	# Use hardcoded ciphertexts (no KMS calls needed for list)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.KMS_SECRET_1]
description = "First KMS secret"
provider = "kms"
value = "AQICAHiy8nEpehKbN0gxZ6AQfrlCEWWoKMLw5eogFUZ3c5gd1QEA1/K/EPEgXnmoj0rHIELGAAAAjDCBiQYJKoZIhvcNAQcGoHwwegIBADB1BgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDNaM0QctJeav8gwCMgIBEIBIbZFODxF3kivTBXDBZ+NenrryPEJz10X6XxeZtT32HjgMtUwravXPF0O4xpoaRlcHVYssmhq2RmOYGJxtlayDC0YsNwfb7kgX"

[secrets.KMS_SECRET_2]
description = "Second KMS secret"
provider = "kms"
value = "AQICAHiy8nEpehKbN0gxZ6AQfrlCEWWoKMLw5eogFUZ3c5gd1QEA1/K/EPEgXnmoj0rHIELGAAAAjDCBiQYJKoZIhvcNAQcGoHwwegIBADB1BgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDNaM0QctJeav8gwCMgIBEIBIbZFODxF3kivTBXDBZ+NenrryPEJz10X6XxeZtT32HjgMtUwravXPF0O4xpoaRlcHVYssmhq2RmOYGJxtlayDC0YsNwfb7kgX"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "KMS_SECRET_1"
	assert_output --partial "KMS_SECRET_2"
	assert_output --partial "First KMS secret"
}

@test "fnox set with description" {
	create_kms_config

	run "$FNOX_BIN" set KMS_WITH_DESC "test-value" --provider kms --description "My KMS secret"
	assert_success

	# Verify description is in config
	run grep "description" "${FNOX_CONFIG_FILE}"
	assert_success
	assert_output --partial "My KMS secret"
}

@test "AWS KMS provider works with full key ARN" {
	# Use the ARN obtained in setup_file
	create_kms_config_with_secret "KMS_ARN_TEST" "$SHARED_SIMPLE_CIPHERTEXT" "$KMS_KEY_ARN" "us-east-1"

	run "$FNOX_BIN" get KMS_ARN_TEST
	assert_success
	assert_output "$SHARED_SIMPLE_VALUE"
}

@test "fnox exec sets KMS environment variables" {
	# Use pre-encrypted value from setup_file
	create_kms_config_with_secret "MY_KMS_VAR" "$SHARED_ENV_CIPHERTEXT"

	# Use exec to run a command with the secret as env var
	# Explicitly set FNOX_CONFIG_FILE to avoid inheriting parent config
	# shellcheck disable=SC2016 # Single quotes intentional - variable should expand in subshell
	run env FNOX_CONFIG_FILE="$FNOX_CONFIG_FILE" "$FNOX_BIN" exec -- sh -c 'echo $MY_KMS_VAR'
	assert_success
	assert_output "$SHARED_ENV_VALUE"
}

@test "fnox set updates existing KMS secret" {
	# Start with pre-encrypted value
	create_kms_config_with_secret "KMS_UPDATE_TEST" "$SHARED_SIMPLE_CIPHERTEXT"

	# Update with new value (1 encrypt call)
	run "$FNOX_BIN" set KMS_UPDATE_TEST "updated-value" --provider kms
	assert_success

	# Verify new value is retrieved (1 decrypt call)
	run "$FNOX_BIN" get KMS_UPDATE_TEST
	assert_success
	assert_output "updated-value"
}

@test "KMS provider respects region configuration" {
	# Use pre-encrypted value with explicit region
	create_kms_config_with_secret "KMS_REGION_TEST" "$SHARED_SIMPLE_CIPHERTEXT" "alias/fnox-testing" "us-east-1"

	run "$FNOX_BIN" get KMS_REGION_TEST
	assert_success
	assert_output "$SHARED_SIMPLE_VALUE"
}
