#!/usr/bin/env bats
#
# GCP IAM Lease Backend Tests
#
# These tests verify the GCP IAM service account impersonation lease backend.
#
# Prerequisites:
#   1. GCP credentials configured (GOOGLE_APPLICATION_CREDENTIALS or GCP_SERVICE_ACCOUNT_KEY)
#   2. The service account must have iam.serviceAccounts.getAccessToken on itself
#   3. Run tests: mise run test:bats -- test/lease_gcp_iam.bats
#
# In CI, GCP_SERVICE_ACCOUNT_KEY is decrypted by fnox exec and the service
# account email is extracted from the JSON key file automatically.
#
# Note: Tests will automatically skip if GCP credentials are not available.

setup() {
	load 'test_helper/common_setup'
	_common_setup
	export FNOX_EXPERIMENTAL=true

	# Determine if we're in CI with secrets access (not a forked PR)
	local in_ci_with_secrets=false
	if [ "${CI:-}" = "true" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
		if [ -f ~/.config/fnox/age.txt ] || [ -n "${FNOX_AGE_KEY:-}" ]; then
			in_ci_with_secrets=true
		fi
	fi

	# Check if GCP credentials are available
	if [ -z "$GCP_SERVICE_ACCOUNT_KEY" ] && [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
		if [ "$in_ci_with_secrets" = "true" ]; then
			echo "# ERROR: In CI with secrets access, but GCP credentials are not available!" >&3
			return 1
		fi
		skip "GCP credentials not available. Set GCP_SERVICE_ACCOUNT_KEY or GOOGLE_APPLICATION_CREDENTIALS."
	fi

	# If GCP_SERVICE_ACCOUNT_KEY is set, create a temp credentials file
	# and extract the service account email for impersonation
	if [ -n "$GCP_SERVICE_ACCOUNT_KEY" ]; then
		export GOOGLE_APPLICATION_CREDENTIALS="${TEST_TEMP_DIR}/gcp-creds.json"
		echo "$GCP_SERVICE_ACCOUNT_KEY" >"$GOOGLE_APPLICATION_CREDENTIALS"

		# Extract service account email from the key file
		GCP_LEASE_TEST_SA=$(python3 -c "import sys, json; print(json.load(open('$GOOGLE_APPLICATION_CREDENTIALS'))['client_email'])" 2>/dev/null) || true
	fi

	if [ -z "$GCP_LEASE_TEST_SA" ]; then
		if [ "$in_ci_with_secrets" = "true" ]; then
			echo "# ERROR: Could not determine service account email for lease impersonation!" >&3
			return 1
		fi
		skip "GCP_LEASE_TEST_SA not set and could not be extracted from credentials."
	fi

	export GCP_LEASE_TEST_SA
}

teardown() {
	_common_teardown
}

# Helper: create fnox config with GCP IAM lease backend
create_gcp_iam_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_gcp]
type = "gcp-iam"
service_account_email = "$GCP_LEASE_TEST_SA"
EOF
}

create_gcp_iam_config_with_scopes() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_gcp]
type = "gcp-iam"
service_account_email = "$GCP_LEASE_TEST_SA"
scopes = ["https://www.googleapis.com/auth/cloud-platform"]
duration = "30m"
EOF
}

@test "gcp-iam lease: create outputs credentials in json format" {
	create_gcp_iam_config

	run "$FNOX_BIN" lease create test_gcp --duration 30m --format json
	assert_success
	assert_output --partial "CLOUDSDK_AUTH_ACCESS_TOKEN"
	assert_output --partial "lease_id"
}

@test "gcp-iam lease: create outputs credentials in env format" {
	create_gcp_iam_config

	run "$FNOX_BIN" lease create test_gcp --duration 30m --format env
	assert_success
	assert_output --partial "export CLOUDSDK_AUTH_ACCESS_TOKEN="
}

@test "gcp-iam lease: exec injects credentials into subprocess" {
	create_gcp_iam_config

	run "$FNOX_BIN" exec -- env
	assert_success
	assert_output --partial "CLOUDSDK_AUTH_ACCESS_TOKEN="
}

@test "gcp-iam lease: custom scopes and duration" {
	create_gcp_iam_config_with_scopes

	run "$FNOX_BIN" lease create test_gcp --format json
	assert_success
	assert_output --partial "CLOUDSDK_AUTH_ACCESS_TOKEN"
}

@test "gcp-iam lease: list shows created lease" {
	create_gcp_iam_config

	run "$FNOX_BIN" lease create test_gcp --duration 30m --format json
	assert_success

	run "$FNOX_BIN" lease list --active
	assert_success
	assert_output --partial "test_gcp"
	assert_output --partial "active"
}

@test "gcp-iam lease: revoke is a no-op (succeeds silently)" {
	create_gcp_iam_config

	run "$FNOX_BIN" lease create test_gcp --duration 30m --format json
	assert_success

	local lease_id
	lease_id=$(echo "$output" | grep -o '"lease_id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed 's/.*"lease_id"[[:space:]]*:[[:space:]]*"//;s/"$//')

	run "$FNOX_BIN" lease revoke "$lease_id"
	assert_success
	assert_output --partial "revoked"
}

@test "gcp-iam lease: duration exceeding 1h max fails" {
	create_gcp_iam_config

	run "$FNOX_BIN" lease create test_gcp --duration 2h --format json
	assert_failure
	assert_output --partial "exceeds maximum"
}

@test "gcp-iam lease: bad service account email fails" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.test_bad_sa]
type = "gcp-iam"
service_account_email = "nonexistent@fake-project.iam.gserviceaccount.com"
EOF

	run "$FNOX_BIN" lease create test_bad_sa --duration 15m --format json
	assert_failure
}
