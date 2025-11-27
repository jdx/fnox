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

# File-level setup - runs once before all tests (reduces API calls)
setup_file() {
	export SM_REGION="us-east-1"

	# Check if AWS credentials are available
	if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
		export SKIP_AWS_SM_TESTS="AWS credentials not available. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are configured."
		return
	fi

	# Check if aws CLI is installed
	if ! command -v aws >/dev/null 2>&1; then
		export SKIP_AWS_SM_TESTS="AWS CLI not installed. Install with: brew install awscli"
		return
	fi

	# Verify we can access Secrets Manager (expensive call - do once)
	if ! aws secretsmanager list-secrets --region "$SM_REGION" --max-results 1 >/dev/null 2>&1; then
		export SKIP_AWS_SM_TESTS="Cannot access AWS Secrets Manager. Permissions may be insufficient."
		return
	fi

	# Create a shared test secret for reuse across multiple tests
	# This reduces API calls vs creating/deleting per test
	export SHARED_SECRET_NAME="fnox-test/shared-test-$$"
	export SHARED_SECRET_VALUE="shared-test-value-for-fnox"
	aws secretsmanager create-secret \
		--name "$SHARED_SECRET_NAME" \
		--secret-string "$SHARED_SECRET_VALUE" \
		--region "$SM_REGION" >/dev/null 2>&1

	# Wait for propagation (eventual consistency)
	sleep 2
}

# File-level teardown - runs once after all tests
teardown_file() {
	# Clean up shared test secret
	if [ -n "$SHARED_SECRET_NAME" ]; then
		aws secretsmanager delete-secret \
			--secret-id "$SHARED_SECRET_NAME" \
			--force-delete-without-recovery \
			--region "$SM_REGION" >/dev/null 2>&1 || true
	fi
}

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Skip if file-level setup determined we can't run
	if [ -n "$SKIP_AWS_SM_TESTS" ]; then
		skip "$SKIP_AWS_SM_TESTS"
	fi
}

teardown() {
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

@test "fnox get retrieves secret from AWS Secrets Manager" {
	create_sm_config

	# Use the shared test secret (created in setup_file)
	# Extract the suffix after "fnox-test/" prefix
	local secret_suffix="${SHARED_SECRET_NAME#fnox-test/}"

	# Add secret reference to config (using just the name without prefix)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.SM_TEST]
provider = "sm"
value = "${secret_suffix}"
EOF

	# Get the secret
	run "$FNOX_BIN" get SM_TEST
	assert_success
	assert_output "$SHARED_SECRET_VALUE"
}

@test "fnox get with prefix prepends prefix to secret name" {
	create_sm_config "us-east-1" "fnox-test/"

	# Use the shared test secret (created in setup_file)
	# Extract the suffix after "fnox-test/" prefix
	local secret_suffix="${SHARED_SECRET_NAME#fnox-test/}"

	# Add secret reference using just the suffix (prefix will be prepended)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.PREFIXED_SECRET]
provider = "sm"
value = "${secret_suffix}"
EOF

	# Get the secret
	run "$FNOX_BIN" get PREFIXED_SECRET
	assert_success
	assert_output "$SHARED_SECRET_VALUE"
}

@test "fnox get without prefix uses full secret name" {
	create_sm_config "us-east-1" ""

	# Use existing fnox/test-secret (no prefix, so full path required)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.FULL_NAME_SECRET]
provider = "sm"
value = "fnox/test-secret"
EOF

	# Get the secret
	run "$FNOX_BIN" get FULL_NAME_SECRET
	assert_success
	assert_output "This is a test secret in AWS Secrets Manager!"
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

	# Use the shared test secret to verify region config works
	local secret_suffix="${SHARED_SECRET_NAME#fnox-test/}"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.REGIONAL_SECRET]
provider = "sm"
value = "${secret_suffix}"
EOF

	# Get the secret
	run "$FNOX_BIN" get REGIONAL_SECRET
	assert_success
	assert_output "$SHARED_SECRET_VALUE"
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
