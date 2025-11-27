#!/usr/bin/env bats
#
# AWS Parameter Store Provider Tests
#
# These tests verify the AWS Systems Manager Parameter Store provider integration with fnox.
# Note: Tests should run serially (within this file) due to AWS eventual consistency.
#       Use `--no-parallelize-within-files` bats flag.
#
# Prerequisites:
#   1. AWS credentials from fnox.toml (decrypted via fnox exec)
#   2. IAM permissions: ssm:GetParameter, ssm:GetParameters, ssm:PutParameter, ssm:DeleteParameter, ssm:DescribeParameters
#   3. Run tests: mise run test:bats -- test/aws_parameter_store.bats
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Set the region
	export PS_REGION="us-east-1"
}

teardown() {
	# Clean up any test parameters created during tests
	if [ -n "$TEST_PARAM_NAME" ]; then
		aws ssm delete-parameter \
			--name "$TEST_PARAM_NAME" \
			--region "$PS_REGION" >/dev/null 2>&1 || true
	fi

	_common_teardown
}

# Helper function to create an AWS Parameter Store test config
create_ps_config() {
	local region="${1:-us-east-1}"
	local prefix="${2}"
	if [ -z "$prefix" ] && [ "$#" -lt 2 ]; then
		prefix="/fnox-test/"
	fi

	if [ -z "$prefix" ]; then
		# Omit prefix line entirely when empty
		cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.ps]
type = "aws-ps"
region = "$region"

[secrets]
EOF
	else
		cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.ps]
type = "aws-ps"
region = "$region"
prefix = "$prefix"

[secrets]
EOF
	fi
}

# Helper function to create a test parameter in AWS Parameter Store
create_test_parameter() {
	local param_name="$1"
	local param_value="$2"

	aws ssm put-parameter \
		--name "$param_name" \
		--value "$param_value" \
		--type "SecureString" \
		--overwrite \
		--region "$PS_REGION"

	# Give AWS Parameter Store time to propagate the parameter
	sleep 1

	export TEST_PARAM_NAME="$param_name"
}

@test "fnox get retrieves parameter from AWS Parameter Store" {
	create_ps_config

	# Create a test parameter
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local param_name="/fnox-test/test-param-${timestamp}"
	local param_value="my-test-param-value"
	create_test_parameter "$param_name" "$param_value"

	# Add parameter reference to config (using just the name without prefix)
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.PS_TEST]
provider = "ps"
value = "test-param-${timestamp}"
EOF

	# Get the parameter
	run "$FNOX_BIN" get PS_TEST
	assert_success
	assert_output "$param_value"
}

@test "fnox get with prefix prepends prefix to parameter name" {
	create_ps_config "us-east-1" "/fnox-test/"

	# Create a test parameter with full path
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local param_name="/fnox-test/prefixed-${timestamp}"
	local param_value="value-with-prefix"
	create_test_parameter "$param_name" "$param_value"

	# Add parameter reference using just the suffix
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.PREFIXED_PARAM]
provider = "ps"
value = "prefixed-${timestamp}"
EOF

	# Get the parameter
	run "$FNOX_BIN" get PREFIXED_PARAM
	assert_success
	assert_output "$param_value"
}

@test "fnox get without prefix uses full parameter name" {
	create_ps_config "us-east-1" ""

	# Create a test parameter without prefix
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local param_name="/fnox-full-name-${timestamp}"
	local param_value="value-no-prefix"
	create_test_parameter "$param_name" "$param_value"

	# Add parameter reference
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.FULL_NAME_PARAM]
provider = "ps"
value = "$param_name"
EOF

	# Get the parameter
	run "$FNOX_BIN" get FULL_NAME_PARAM
	assert_success
	assert_output "$param_value"
}

@test "fnox get fails with non-existent parameter" {
	create_ps_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.NONEXISTENT]
provider = "ps"
value = "does-not-exist-$(date +%s)"
EOF

	# Try to get non-existent parameter
	run "$FNOX_BIN" get NONEXISTENT
	assert_failure
	assert_output --partial "Failed to get parameter"
}

@test "fnox get with multiline parameter" {
	create_ps_config

	# Create a multiline parameter
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local param_name="/fnox-test/multiline-${timestamp}"
	local param_value="line1
line2
line3"
	create_test_parameter "$param_name" "$param_value"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.MULTILINE_PARAM]
provider = "ps"
value = "multiline-${timestamp}"
EOF

	# Get the parameter
	run "$FNOX_BIN" get MULTILINE_PARAM
	assert_success
	assert_output "$param_value"
}

@test "fnox list shows Parameter Store parameters" {
	create_ps_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.PS_PARAM_1]
description = "First Parameter Store parameter"
provider = "ps"
value = "param1"

[secrets.PS_PARAM_2]
description = "Second Parameter Store parameter"
provider = "ps"
value = "param2"
EOF

	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "PS_PARAM_1"
	assert_output --partial "PS_PARAM_2"
	assert_output --partial "First Parameter Store parameter"
}

@test "fnox get respects region configuration" {
	create_ps_config "us-east-1"

	# Create a parameter in the specified region
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local param_name="/fnox-test/regional-${timestamp}"
	local param_value="region-specific-value"
	create_test_parameter "$param_name" "$param_value"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.REGIONAL_PARAM]
provider = "ps"
value = "regional-${timestamp}"
EOF

	# Get the parameter
	run "$FNOX_BIN" get REGIONAL_PARAM
	assert_success
	assert_output "$param_value"
}

@test "fnox get with special characters in parameter value" {
	create_ps_config

	# Create a parameter with special characters
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local param_name="/fnox-test/special-${timestamp}"
	local param_value='p@ssw0rd!#$%^&*()_+-={}[]|\:";'\''<>?,./~`'
	create_test_parameter "$param_name" "$param_value"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.SPECIAL_CHARS]
provider = "ps"
value = "special-${timestamp}"
EOF

	# Get the parameter
	run "$FNOX_BIN" get SPECIAL_CHARS
	assert_success
	assert_output "$param_value"
}

@test "fnox get with hierarchical path" {
	create_ps_config "us-east-1" "/myapp/prod/"

	# Create a parameter with hierarchical path
	local timestamp
	timestamp="$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
	local param_name="/myapp/prod/database/url-${timestamp}"
	local param_value="postgres://localhost/mydb"
	create_test_parameter "$param_name" "$param_value"

	# Update TEST_PARAM_NAME for cleanup
	export TEST_PARAM_NAME="$param_name"

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.DATABASE_URL]
provider = "ps"
value = "database/url-${timestamp}"
EOF

	# Get the parameter
	run "$FNOX_BIN" get DATABASE_URL
	assert_success
	assert_output "$param_value"
}

@test "fnox get with description" {
	create_ps_config

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.DESCRIBED_PARAM]
description = "A parameter with a description"
provider = "ps"
value = "some-param"
EOF

	# List to verify description
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "DESCRIBED_PARAM"
	assert_output --partial "A parameter with a description"
}
