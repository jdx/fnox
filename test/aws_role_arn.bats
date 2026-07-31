#!/usr/bin/env bats
#
# AWS role_arn validation tests
#
# A malformed role_arn is rejected before any AWS call, so these tests need no
# credentials and no LocalStack.

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

write_role_arn_config() {
	local provider_type="$1"
	local role_arn="$2"
	local key_id=""

	if [ "$provider_type" = "aws-kms" ]; then
		key_id='key_id = "alias/my-key"'
	fi

	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[providers.aws]
type = "$provider_type"
region = "us-east-1"
$key_id
role_arn = "$role_arn"

[secrets.SOME_SECRET]
provider = "aws"
value = "some-secret"
EOF
}

@test "aws-sm rejects a malformed role ARN" {
	write_role_arn_config "aws-sm" "fnox-test-role"

	run "$FNOX_BIN" get SOME_SECRET
	assert_failure
	assert_output --partial "IAM role ARN"
}

@test "aws-ps rejects a role ARN with a region segment" {
	write_role_arn_config "aws-ps" "arn:aws:iam:us-east-1:123456789012:role/my-role"

	run "$FNOX_BIN" get SOME_SECRET
	assert_failure
	assert_output --partial "IAM role ARN"
}

@test "aws-kms rejects a role ARN with a non-numeric account" {
	write_role_arn_config "aws-kms" "arn:aws:iam::not-an-account:role/my-role"

	run "$FNOX_BIN" get SOME_SECRET
	assert_failure
	assert_output --partial "IAM role ARN"
}
