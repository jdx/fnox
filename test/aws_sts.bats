#!/usr/bin/env bats
#
# AWS STS Lease Backend Tests
#
# These tests verify the AWS STS lease backend integration with fnox
# using LocalStack for mock AWS services.
#
# Prerequisites:
#   1. Start LocalStack: docker run -d -p 4566:4566 -e SERVICES=sts,iam localstack/localstack
#   2. Set LOCALSTACK_ENDPOINT=http://localhost:4566
#   3. Run tests: mise run test:bats -- test/aws_sts.bats
#
# Note: Tests will automatically skip if LOCALSTACK_ENDPOINT is not set.

setup_file() {
	if [ -z "$LOCALSTACK_ENDPOINT" ]; then
		skip "LOCALSTACK_ENDPOINT not set. Start LocalStack and set LOCALSTACK_ENDPOINT=http://localhost:4566"
	fi

	if ! command -v aws >/dev/null 2>&1; then
		skip "AWS CLI not installed"
	fi

	# Wait for LocalStack to be ready
	local retries=10
	while ! aws --endpoint-url "$LOCALSTACK_ENDPOINT" sts get-caller-identity --region us-east-1 --no-sign-request 2>/dev/null; do
		retries=$((retries - 1))
		if [ "$retries" -le 0 ]; then
			skip "LocalStack not ready"
		fi
		sleep 1
	done

	# Create an IAM role in LocalStack for testing
	export TEST_ROLE_ARN="arn:aws:iam::000000000000:role/fnox-test-role"

	aws --endpoint-url "$LOCALSTACK_ENDPOINT" --region us-east-1 \
		iam create-role \
		--role-name fnox-test-role \
		--assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}' \
		2>/dev/null || true
}

setup() {
	load 'test_helper/common_setup'
	_common_setup

	if [ -z "$LOCALSTACK_ENDPOINT" ]; then
		skip "LOCALSTACK_ENDPOINT not set"
	fi

	# Set dummy AWS credentials for LocalStack
	export AWS_ACCESS_KEY_ID="test"
	export AWS_SECRET_ACCESS_KEY="test"
	export AWS_DEFAULT_REGION="us-east-1"
}

teardown() {
	_common_teardown
}

# Helper: create fnox config with STS lease backend
create_sts_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_sts]
type = "aws-sts"
region = "us-east-1"
endpoint = "$LOCALSTACK_ENDPOINT"
role_arn = "$TEST_ROLE_ARN"

[secrets]
AWS_CREDS = { lease = "test_sts", value = "$TEST_ROLE_ARN" }
EOF
}

@test "fnox lease requires experimental flag" {
	create_sts_config

	run "$FNOX_BIN" lease list
	assert_failure
	assert_output --partial "experimental"
}

@test "fnox lease create outputs credentials in json format" {
	create_sts_config
	export FNOX_EXPERIMENTAL=true

	run "$FNOX_BIN" lease create AWS_CREDS --duration 15m --format json
	assert_success
	assert_output --partial "AWS_ACCESS_KEY_ID"
	assert_output --partial "AWS_SECRET_ACCESS_KEY"
	assert_output --partial "AWS_SESSION_TOKEN"
	assert_output --partial "lease_id"
}

@test "fnox lease create outputs credentials in env format" {
	create_sts_config
	export FNOX_EXPERIMENTAL=true

	run "$FNOX_BIN" lease create AWS_CREDS --duration 15m --format env
	assert_success
	assert_output --partial "export AWS_ACCESS_KEY_ID="
	assert_output --partial "export AWS_SECRET_ACCESS_KEY="
	assert_output --partial "export AWS_SESSION_TOKEN="
}

@test "fnox lease create outputs credentials in shell format" {
	create_sts_config
	export FNOX_EXPERIMENTAL=true

	run "$FNOX_BIN" lease create AWS_CREDS --duration 15m --format shell
	assert_success
	assert_output --partial "Lease created"
	assert_output --partial "AWS_ACCESS_KEY_ID"
}

@test "fnox lease list shows created lease" {
	create_sts_config
	export FNOX_EXPERIMENTAL=true

	# Create a lease first
	run "$FNOX_BIN" lease create AWS_CREDS --duration 15m --format json --label test-list
	assert_success

	# List should show the lease
	run "$FNOX_BIN" lease list --active
	assert_success
	assert_output --partial "BACKEND"
	assert_output --partial "test_sts"
	assert_output --partial "AWS_CREDS"
	assert_output --partial "active"
}

@test "fnox lease revoke marks lease as revoked" {
	create_sts_config
	export FNOX_EXPERIMENTAL=true

	# Create a lease and extract the lease_id
	run "$FNOX_BIN" lease create AWS_CREDS --duration 15m --format json --label test-revoke
	assert_success
	local lease_id
	lease_id=$(echo "$output" | python3 -c "import sys, json; print(json.load(sys.stdin)['lease_id'])")

	# Revoke it
	run "$FNOX_BIN" lease revoke "$lease_id"
	assert_success
	assert_output --partial "revoked"

	# List should show it as revoked
	run "$FNOX_BIN" lease list
	assert_success
	assert_output --partial "revoked"
}

@test "fnox lease cleanup handles expired leases" {
	create_sts_config
	export FNOX_EXPERIMENTAL=true

	# With no expired leases, cleanup should report nothing
	run "$FNOX_BIN" lease cleanup
	assert_success
	assert_output --partial "No expired leases"
}

@test "fnox lease create fails with missing lease backend" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[secrets]
MY_SECRET = { lease = "nonexistent", value = "some-value" }
EOF
	export FNOX_EXPERIMENTAL=true

	run "$FNOX_BIN" lease create MY_SECRET --duration 15m
	assert_failure
	assert_output --partial "not found"
}

@test "fnox lease create fails with missing secret" {
	create_sts_config
	export FNOX_EXPERIMENTAL=true

	run "$FNOX_BIN" lease create NONEXISTENT_SECRET --duration 15m
	assert_failure
}
