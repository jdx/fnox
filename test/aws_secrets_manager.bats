#!/usr/bin/env bats
#
# AWS Secrets Manager Provider Tests
#
# These tests verify the AWS Secrets Manager provider integration with fnox.
# Note: Tests should run serially (within this file) due to AWS Secrets Manager
#       eventual consistency. Use `--no-parallelize-within-files` bats flag.
#
# Prerequisites:
#   1. AWS credentials configured (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#   2. IAM permissions: secretsmanager:GetSecretValue, secretsmanager:CreateSecret, secretsmanager:PutSecretValue
#   3. Run tests: mise run test:bats -- test/aws_secrets_manager.bats
#
# Note: Tests will automatically skip if AWS credentials are not available.
#       The mise task runs `fnox exec` which automatically decrypts provider-based secrets.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Check if AWS credentials are available
	if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
		skip "AWS credentials not available. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are configured."
	fi

	# Check if aws CLI is installed
	if ! command -v aws >/dev/null 2>&1; then
		skip "AWS CLI not installed. Install with: brew install awscli"
	fi

	# Set the region
	export SM_REGION="us-east-1"

	# Verify we can access Secrets Manager
	if ! aws secretsmanager list-secrets --region "$SM_REGION" --max-results 1 >/dev/null 2>&1; then
		skip "Cannot access AWS Secrets Manager. Permissions may be insufficient."
	fi
}

teardown() {
	# Clean up any test secrets created during tests
	if [ -n "$TEST_SECRET_NAME" ]; then
		aws secretsmanager delete-secret \
			--secret-id "$TEST_SECRET_NAME" \
			--force-delete-without-recovery \
			--region "$SM_REGION" >/dev/null 2>&1 || true
	fi

	_common_teardown
}

# Helper function to create an AWS Secrets Manager test config
create_sm_config() {
	local region="${1:-us-east-1}"
	local prefix="${2}"
	if [ -z "$prefix" ] && [ "$#" -lt 2 ]; then
		prefix="fnox-test/"
	fi

	if [ -z "$prefix" ]; then
		# Omit prefix line entirely when empty
		cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.sm]
type = "aws-sm"
region = "$region"

[secrets]
EOF
	else
		cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.sm]
type = "aws-sm"
region = "$region"
prefix = "$prefix"

[secrets]
EOF
	fi
}

# Helper function to create a test secret in AWS Secrets Manager
create_test_secret() {
	local secret_name="$1"
	local secret_value="$2"

	aws secretsmanager create-secret \
		--name "$secret_name" \
		--secret-string "$secret_value" \
		--region "$SM_REGION" >/dev/null 2>&1

	# Give AWS Secrets Manager time to propagate the secret (eventual consistency)
	sleep 2

	export TEST_SECRET_NAME="$secret_name"
}

@test "fnox get retrieves secret from AWS Secrets Manager" {
	create_sm_config

	# Create a test secret
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_name="fnox-test/test-secret-${timestamp}"
	local secret_value="my-test-secret-value"
	create_test_secret "$secret_name" "$secret_value"

	# Add secret reference to config (using just the name without prefix)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.SM_TEST]
provider = "sm"
value = "test-secret-${timestamp}"
EOF

	# Get the secret
	run "$FNOX_BIN" get SM_TEST
	assert_success
	assert_output "$secret_value"
}

@test "fnox get with prefix prepends prefix to secret name" {
	create_sm_config "us-east-1" "fnox-test/"

	# Create a test secret with full path
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_name="fnox-test/prefixed-${timestamp}"
	local secret_value="value-with-prefix"
	create_test_secret "$secret_name" "$secret_value"

	# Add secret reference using just the suffix
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.PREFIXED_SECRET]
provider = "sm"
value = "prefixed-${timestamp}"
EOF

	# Get the secret
	run "$FNOX_BIN" get PREFIXED_SECRET
	assert_success
	assert_output "$secret_value"
}

@test "fnox get without prefix uses full secret name" {
	create_sm_config "us-east-1" ""

	# Create a test secret without prefix
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_name="fnox-full-name-${timestamp}"
	local secret_value="value-no-prefix"
	create_test_secret "$secret_name" "$secret_value"

	# Add secret reference
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.FULL_NAME_SECRET]
provider = "sm"
value = "$secret_name"
EOF

	# Get the secret
	run "$FNOX_BIN" get FULL_NAME_SECRET
	assert_success
	assert_output "$secret_value"
}

@test "fnox get fails with non-existent secret" {
	create_sm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.NONEXISTENT]
provider = "sm"
value = "does-not-exist-$(date +%s)"
EOF

	# Try to get non-existent secret
	run "$FNOX_BIN" get NONEXISTENT
	assert_failure
	assert_output --partial "Failed to get secret"
}

@test "fnox get with JSON secret value" {
	create_sm_config

	# Create a JSON secret
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_name="fnox-test/json-secret-${timestamp}"
	local secret_value='{"api_key":"test123","endpoint":"https://api.example.com"}'
	create_test_secret "$secret_name" "$secret_value"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.JSON_SECRET]
provider = "sm"
value = "json-secret-${timestamp}"
EOF

	# Get the secret
	run "$FNOX_BIN" get JSON_SECRET
	assert_success
	assert_output "$secret_value"
}

@test "fnox get with multiline secret" {
	create_sm_config

	# Create a multiline secret
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_name="fnox-test/multiline-${timestamp}"
	local secret_value="line1
line2
line3"
	create_test_secret "$secret_name" "$secret_value"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.MULTILINE_SECRET]
provider = "sm"
value = "multiline-${timestamp}"
EOF

	# Get the secret
	run "$FNOX_BIN" get MULTILINE_SECRET
	assert_success
	assert_output "$secret_value"
}

@test "fnox list shows Secrets Manager secrets" {
	create_sm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.SM_SECRET_1]
description = "First Secrets Manager secret"
provider = "sm"
value = "secret1"

[secrets.SM_SECRET_2]
description = "Second Secrets Manager secret"
provider = "sm"
value = "secret2"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "SM_SECRET_1"
	assert_output --partial "SM_SECRET_2"
	assert_output --partial "First Secrets Manager secret"
}

@test "fnox get respects region configuration" {
	create_sm_config "us-east-1"

	# Create a secret in the specified region
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_name="fnox-test/regional-${timestamp}"
	local secret_value="region-specific-value"
	create_test_secret "$secret_name" "$secret_value"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.REGIONAL_SECRET]
provider = "sm"
value = "regional-${timestamp}"
EOF

	# Get the secret
	run "$FNOX_BIN" get REGIONAL_SECRET
	assert_success
	assert_output "$secret_value"
}

@test "fnox get with special characters in secret value" {
	create_sm_config

	# Create a secret with special characters
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local secret_name="fnox-test/special-${timestamp}"
	local secret_value='p@ssw0rd!#$%^&*()_+-={}[]|\:";'\''<>?,./~`'
	create_test_secret "$secret_name" "$secret_value"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.SPECIAL_CHARS]
provider = "sm"
value = "special-${timestamp}"
EOF

	# Get the secret
	run "$FNOX_BIN" get SPECIAL_CHARS
	assert_success
	assert_output "$secret_value"
}

@test "AWS Secrets Manager works with existing fnox/test-secret" {
	# Test with the pre-created secret from setup
	create_sm_config "us-east-1" "fnox/"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.EXISTING_SECRET]
provider = "sm"
value = "test-secret"
EOF

	# Get the secret
	run "$FNOX_BIN" get EXISTING_SECRET
	assert_success
	assert_output "This is a test secret in AWS Secrets Manager!"
}

@test "fnox get with description" {
	create_sm_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.DESCRIBED_SECRET]
description = "A secret with a description"
provider = "sm"
value = "some-secret"
EOF

	# List to verify description
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "DESCRIBED_SECRET"
	assert_output --partial "A secret with a description"
}
