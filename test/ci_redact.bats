#!/usr/bin/env bats
#
# CI Redact Command Tests
#
# Tests for the fnox ci-redact command which masks secrets in CI/CD output.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Create a test config with secrets
	# Use root = true to prevent loading parent configs
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
SECRET_ONE = { provider = "plain", value = "secret-value-1" }
SECRET_TWO = { provider = "plain", value = "secret-value-2" }
PASSWORD = { provider = "plain", value = "super-secret-password" }
EOF
}

teardown() {
	_common_teardown
}

@test "ci-redact fails when not in CI environment" {
	# Ensure CI env vars are not set
	unset CI
	unset GITHUB_ACTIONS
	unset GITLAB_CI
	unset CIRCLECI

	run "$FNOX_BIN" ci-redact
	assert_failure
	assert_output --partial "Not running in a CI environment"
}

@test "ci-redact works in GitHub Actions" {
	# Simulate GitHub Actions environment
	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success
	assert_output --partial "::add-mask::secret-value-1"
	assert_output --partial "::add-mask::secret-value-2"
	assert_output --partial "::add-mask::super-secret-password"
}

@test "ci-redact outputs correct number of mask commands" {
	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success

	# Count the number of mask commands (should be 3 for our 3 secrets)
	mask_count=$(echo "$output" | grep -c "::add-mask::" || true)
	[ "$mask_count" -eq 3 ]
}

@test "ci-redact fails on GitLab CI" {
	export CI=true
	export GITLAB_CI=true
	unset GITHUB_ACTIONS

	run "$FNOX_BIN" ci-redact
	assert_failure
	assert_output --partial "GitLab CI does not support runtime secret masking"
}

@test "ci-redact fails on CircleCI" {
	export CI=true
	export CIRCLECI=true
	unset GITHUB_ACTIONS

	run "$FNOX_BIN" ci-redact
	assert_failure
	assert_output --partial "CircleCI does not support runtime secret masking"
}

@test "ci-redact handles empty secrets gracefully" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
EOF

	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success
	# Should have no output for empty secrets
	[ -z "$output" ]
}

@test "ci-redact with profile" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
DEFAULT_SECRET = { provider = "plain", value = "default-value" }

[profiles.staging.secrets]
STAGING_SECRET = { provider = "plain", value = "staging-value" }
EOF

	export CI=true
	export GITHUB_ACTIONS=true

	# Test default profile
	run "$FNOX_BIN" ci-redact
	assert_success
	assert_output --partial "::add-mask::default-value"
	refute_output --partial "staging-value"

	# Test staging profile - inherits top-level secrets
	run "$FNOX_BIN" -P staging ci-redact
	assert_success
	assert_output --partial "::add-mask::staging-value"
	assert_output --partial "::add-mask::default-value" # Inherited from top level
}

@test "ci-redact handles missing secrets with if_missing=ignore" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
REQUIRED = { provider = "plain", value = "required-value" }
OPTIONAL = { if_missing = "ignore" }
EOF

	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success
	assert_output --partial "::add-mask::required-value"
	# Should only output one mask command
	mask_count=$(echo "$output" | grep -c "::add-mask::" || true)
	[ "$mask_count" -eq 1 ]
}

@test "ci-redact handles missing secrets with if_missing=warn" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
REQUIRED = { provider = "plain", value = "required-value" }
OPTIONAL = { if_missing = "warn" }
EOF

	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success
	assert_output --partial "::add-mask::required-value"
	assert_output --partial "Warning: Secret 'OPTIONAL' not found"
}

@test "ci-redact fails with missing required secrets" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
REQUIRED = { if_missing = "error" }
EOF

	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_failure
	assert_output --partial "Secret 'REQUIRED' not found"
}

@test "ci-redact with environment variable values" {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[providers.plain]
type = "plain"

[secrets]
FROM_ENV = {}
FROM_DEFAULT = { provider = "plain", value = "default-value" }
EOF

	export FROM_ENV="env-value"
	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success
	assert_output --partial "::add-mask::env-value"
	assert_output --partial "::add-mask::default-value"
}

@test "ci-redact is hidden from main help" {
	run "$FNOX_BIN" --help
	assert_success
	refute_output --partial "ci-redact"
}

@test "ci-redact has its own help" {
	run "$FNOX_BIN" ci-redact --help
	assert_success
	assert_output --partial "Redact secrets in CI/CD output"
}

@test "ci-redact warns about multiline secrets" {
	# Create a multiline secret (like a JSON file or private key)
	cat >"$FNOX_CONFIG_FILE" <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
MULTILINE_SECRET = { provider = "plain", value = """line1
line2
line3""" }
SINGLE_LINE = { provider = "plain", value = "single" }
EOF

	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success

	# Should warn about the multiline secret
	assert_output --partial "Secret 'MULTILINE_SECRET' contains newlines and cannot be fully redacted"

	# Should still mask the single-line secret
	assert_output --partial "::add-mask::single"

	# Only 1 mask command for single-line secret
	mask_count=$(echo "$output" | grep -c "::add-mask::" || true)
	[ "$mask_count" -eq 1 ]
}

@test "ci-redact warns about JSON secrets" {
	# Simulate a GCP service account key or similar JSON secret
	cat >"$FNOX_CONFIG_FILE" <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
GCP_KEY = { provider = "plain", value = """{
  "type": "service_account",
  "project_id": "my-project",
  "private_key": "-----BEGIN PRIVATE KEY-----\nABCD1234\n-----END PRIVATE KEY-----"
}""" }
SAFE_SECRET = { provider = "plain", value = "safe-value" }
EOF

	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success

	# Should warn about the multiline JSON secret
	assert_output --partial "Secret 'GCP_KEY' contains newlines and cannot be fully redacted"
	assert_output --partial "Consider using a secret manager"

	# Should still mask single-line secrets
	assert_output --partial "::add-mask::safe-value"
}

@test "ci-redact does not mask plaintext defaults" {
	cat >"$FNOX_CONFIG_FILE" <<'TOML'
root = true

[providers.plain]
type = "plain"

[secrets]
LOG_LEVEL = { default = "INFO" }
GREETING = { default = "hello-world" }
INTERPOLATED = { default = "${GREETING}-suffix" }
API_KEY = { provider = "plain", value = "real-secret-value" }
TOML

	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success
	assert_output --partial "::add-mask::real-secret-value"
	# An interpolated default can embed another secret, so it stays masked.
	assert_output --partial "::add-mask::hello-world-suffix"
	refute_output --partial "::add-mask::INFO"
	# The plain literal default is not masked on its own.
	mask_count=$(echo "$output" | grep -c "::add-mask::" || true)
	[ "$mask_count" -eq 2 ]
}

@test "ci-redact masks a plaintext default marked sensitive" {
	cat >"$FNOX_CONFIG_FILE" <<'TOML'
root = true

[secrets]
LOG_LEVEL = { default = "INFO" }
LOCAL_TOKEN = { default = "dev-token-123", sensitive = true }
TOML

	export CI=true
	export GITHUB_ACTIONS=true

	run "$FNOX_BIN" ci-redact
	assert_success
	assert_output --partial "::add-mask::dev-token-123"
	refute_output --partial "::add-mask::INFO"
}
