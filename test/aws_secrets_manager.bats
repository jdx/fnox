#!/usr/bin/env bats
#
# AWS Secrets Manager Provider Tests
#
# These tests verify the AWS Secrets Manager provider integration with fnox
# using LocalStack for mock AWS services.
#
# Prerequisites:
#   1. Start LocalStack: docker run -d -p 4566:4566 -e SERVICES=secretsmanager localstack/localstack
#   2. Set LOCALSTACK_ENDPOINT=http://localhost:4566
#   3. Run tests: mise run test:bats -- test/aws_secrets_manager.bats
#
# Note: Tests will automatically skip if LOCALSTACK_ENDPOINT is not set.
#

# File-level setup - runs once before all tests (reduces API calls)
setup_file() {
	export SM_REGION="us-east-1"

	if [ -z "$LOCALSTACK_ENDPOINT" ]; then
		export SKIP_AWS_SM_TESTS="LOCALSTACK_ENDPOINT not set. Start LocalStack and set LOCALSTACK_ENDPOINT=http://localhost:4566"
		return
	fi

	# Set dummy AWS credentials for LocalStack
	export AWS_ACCESS_KEY_ID="test"
	export AWS_SECRET_ACCESS_KEY="test"
	export AWS_DEFAULT_REGION="us-east-1"

	# Check if aws CLI is installed
	if ! command -v aws >/dev/null 2>&1; then
		export SKIP_AWS_SM_TESTS="AWS CLI not installed. Install with: brew install awscli"
		return
	fi

	# Wait for LocalStack to be ready
	local retries=10
	while ! curl -sf "$LOCALSTACK_ENDPOINT/_localstack/health" >/dev/null 2>&1; do
		retries=$((retries - 1))
		if [ "$retries" -le 0 ]; then
			export SKIP_AWS_SM_TESTS="LocalStack not ready"
			return
		fi
		sleep 1
	done

	# Create shared test secrets in LocalStack
	export SHARED_SECRET_NAME="fnox-test/shared-test-$$"
	export SHARED_SECRET_VALUE="shared-test-value-for-fnox"
	aws --endpoint-url "$LOCALSTACK_ENDPOINT" secretsmanager create-secret \
		--name "$SHARED_SECRET_NAME" \
		--secret-string "$SHARED_SECRET_VALUE" \
		--region "$SM_REGION" >/dev/null 2>&1

	# Create the pre-existing test secret
	aws --endpoint-url "$LOCALSTACK_ENDPOINT" secretsmanager create-secret \
		--name "fnox/test-secret" \
		--secret-string "This is a test secret in AWS Secrets Manager!" \
		--region "$SM_REGION" >/dev/null 2>&1 ||
		aws --endpoint-url "$LOCALSTACK_ENDPOINT" secretsmanager put-secret-value \
			--secret-id "fnox/test-secret" \
			--secret-string "This is a test secret in AWS Secrets Manager!" \
			--region "$SM_REGION" >/dev/null 2>&1
}

# File-level teardown - runs once after all tests
teardown_file() {
	if [ -n "$SHARED_SECRET_NAME" ] && [ -n "$LOCALSTACK_ENDPOINT" ]; then
		aws --endpoint-url "$LOCALSTACK_ENDPOINT" secretsmanager delete-secret \
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
endpoint = "$LOCALSTACK_ENDPOINT"

[secrets]
EOF
	else
		cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.sm]
type = "aws-sm"
region = "$region"
prefix = "$prefix"
endpoint = "$LOCALSTACK_ENDPOINT"

[secrets]
EOF
	fi
}

@test "fnox get retrieves secret from AWS Secrets Manager" {
	create_sm_config

	# Use the shared test secret (created in setup_file)
	local secret_suffix="${SHARED_SECRET_NAME#fnox-test/}"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.SM_TEST]
provider = "sm"
value = "${secret_suffix}"
EOF

	run "$FNOX_BIN" get SM_TEST
	assert_success
	assert_output "$SHARED_SECRET_VALUE"
}

@test "fnox get with prefix prepends prefix to secret name" {
	create_sm_config "us-east-1" "fnox-test/"

	local secret_suffix="${SHARED_SECRET_NAME#fnox-test/}"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.PREFIXED_SECRET]
provider = "sm"
value = "${secret_suffix}"
EOF

	run "$FNOX_BIN" get PREFIXED_SECRET
	assert_success
	assert_output "$SHARED_SECRET_VALUE"
}

@test "fnox get without prefix uses full secret name" {
	create_sm_config "us-east-1" ""

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.FULL_NAME_SECRET]
provider = "sm"
value = "fnox/test-secret"
EOF

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
	assert_output --partial "secret_not_found"
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

	local secret_suffix="${SHARED_SECRET_NAME#fnox-test/}"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.REGIONAL_SECRET]
provider = "sm"
value = "${secret_suffix}"
EOF

	run "$FNOX_BIN" get REGIONAL_SECRET
	assert_success
	assert_output "$SHARED_SECRET_VALUE"
}

@test "AWS Secrets Manager works with existing fnox/test-secret" {
	create_sm_config "us-east-1" "fnox/"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.EXISTING_SECRET]
provider = "sm"
value = "test-secret"
EOF

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
