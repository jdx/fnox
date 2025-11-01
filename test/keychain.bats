#!/usr/bin/env bats
#
# OS Keychain Provider Tests
#
# These tests verify the OS keychain provider integration with fnox.
#
# Prerequisites:
#   - macOS: Keychain Access (built-in)
#   - Linux: Secret Service (gnome-keyring or KWallet)
#   - Run tests: mise run test:bats -- test/keychain.bats
#
# Note: Tests use a dedicated "fnox-test" service name to avoid conflicts.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Check if keychain tests are disabled via env var
	if [ -n "$SKIP_KEYCHAIN_TESTS" ]; then
		skip "Keychain tests disabled via SKIP_KEYCHAIN_TESTS env var"
	fi

	# Detect platform
	local platform
	platform="$(uname)"
	export PLATFORM="$platform"

	# Platform-specific setup
	if [[ $platform == "Darwin" ]]; then
		setup_macos_keychain
	elif [[ $platform == "Linux" ]]; then
		setup_linux_keychain
	else
		skip "OS keychain tests only support macOS and Linux (detected: $platform)"
	fi

	# Set a unique service name for tests
	export KEYCHAIN_SERVICE="fnox-test-$$"
}

setup_macos_keychain() {
	# In CI environments, skip keychain tests on macOS (they hang)
	if [ "${CI:-}" = "true" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${GITLAB_CI:-}" ] || [ -n "${CIRCLECI:-}" ]; then
		skip "Keychain tests disabled on macOS CI (tests hang)"
	fi

	# Verify keychain is accessible by attempting to list keychains
	security list-keychains >/dev/null 2>&1

	# Verify keychain access by creating a test entry
	security add-generic-password -s "fnox-test-access-check-$$" -a "test" -w "test" -U 2>&1

	# Clean up the test entry
	security delete-generic-password -s "fnox-test-access-check-$$" -a "test" 2>&1 || true
}

setup_linux_keychain() {
	# Check if secret-tool is available (for manual testing verification)
	if ! command -v secret-tool >/dev/null 2>&1; then
		echo "# Warning: secret-tool not found (install libsecret-tools for manual testing)" >&3
	fi

	# In CI environments, assume gnome-keyring-daemon is already running
	# (started by CI workflow before tests begin)
	if [ "${CI:-}" = "true" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${GITLAB_CI:-}" ] || [ -n "${CIRCLECI:-}" ]; then
		export USING_TEST_KEYRING=1
		return 0
	fi

	# For non-CI Linux, verify that a secret service is available via D-Bus
	if [ -z "${USING_TEST_KEYRING:-}" ]; then
		# Connect to the secret service (fail if not available)
		dbus-send --print-reply --dest=org.freedesktop.secrets /org/freedesktop/secrets org.freedesktop.DBus.Peer.Ping >/dev/null 2>&1
	fi
}

teardown() {
	# Clean up any test secrets from keychain (platform-specific)
	if [ -n "$TEST_SECRET_KEYS" ]; then
		for key in $TEST_SECRET_KEYS; do
			if [[ $PLATFORM == "Darwin" ]]; then
				# macOS: Use security command to delete test secrets
				security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$key" >/dev/null 2>&1 || true
			elif [[ $PLATFORM == "Linux" ]] && command -v secret-tool >/dev/null 2>&1; then
				# Linux: Use secret-tool to delete test secrets
				secret-tool clear service "$KEYCHAIN_SERVICE" account "$key" >/dev/null 2>&1 || true
			fi
		done
	fi

	# Note: Don't kill gnome-keyring-daemon or dbus in CI
	# They are started by the CI workflow and shared across all tests

	_common_teardown
}

# Helper function to create a keychain provider config
create_keychain_config() {
	local service="${1:-fnox-test}"
	local prefix="${2:-}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.keychain]
type = "keychain"
service = "$service"
EOF

	if [ -n "$prefix" ]; then
		cat >>"${FNOX_CONFIG_FILE}" <<EOF
prefix = "$prefix"
EOF
	fi

	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets]
EOF
}

# Helper to track secret keys for cleanup
track_secret() {
	local key="$1"
	TEST_SECRET_KEYS="${TEST_SECRET_KEYS:-} $key"
}

@test "fnox set stores secret in OS keychain" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Set a secret using the keychain provider
	run "$FNOX_BIN" set MY_SECRET "my-secret-value" --provider keychain
	assert_success
	assert_output --partial "Set secret MY_SECRET"

	track_secret "MY_SECRET"

	# Verify the config contains only a reference (not the value)
	run cat "${FNOX_CONFIG_FILE}"
	assert_success
	# Check for inline table or TOML table format (both are valid)
	assert_output --partial 'MY_SECRET'
	assert_output --partial 'provider = "keychain"'
	assert_output --partial 'value = "MY_SECRET"'
	refute_output --partial "my-secret-value"
}

@test "fnox get retrieves secret from OS keychain" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Set a secret
	run "$FNOX_BIN" set TEST_GET "test-value-123" --provider keychain
	assert_success
	track_secret "TEST_GET"

	# Get the secret back
	run "$FNOX_BIN" get TEST_GET
	assert_success
	assert_output "test-value-123"
}

@test "fnox set and get with prefix" {
	create_keychain_config "$KEYCHAIN_SERVICE" "myapp/"

	# Set a secret with prefix
	run "$FNOX_BIN" set PREFIXED_SECRET "prefixed-value" --provider keychain
	assert_success
	track_secret "myapp/PREFIXED_SECRET"

	# Get the secret (prefix is applied automatically)
	run "$FNOX_BIN" get PREFIXED_SECRET
	assert_success
	assert_output "prefixed-value"
}

@test "fnox get fails with non-existent secret" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Manually add a reference to a non-existent secret
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.NONEXISTENT]
provider = "keychain"
value = "does-not-exist-$$"
EOF

	# Try to get non-existent secret
	run "$FNOX_BIN" get NONEXISTENT
	assert_failure
	assert_output --partial "Failed to retrieve secret"
}

@test "fnox set with special characters" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	local secret_value='p@ssw0rd!#$%^&*()_+-={}[]|\:";'\''<>?,./~`'

	# Set a secret with special characters
	run "$FNOX_BIN" set SPECIAL_CHARS "$secret_value" --provider keychain
	assert_success
	track_secret "SPECIAL_CHARS"

	# Get it back
	run "$FNOX_BIN" get SPECIAL_CHARS
	assert_success
	assert_output "$secret_value"
}

@test "fnox set with multiline value" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	local multiline_value="line1
line2
line3"

	# Set a multiline secret (using bash -c for stdin pipe)
	run bash -c "echo '$multiline_value' | '$FNOX_BIN' set MULTILINE --provider keychain"
	assert_success
	track_secret "MULTILINE"

	# Get it back
	run "$FNOX_BIN" get MULTILINE
	assert_success
	assert_output "$multiline_value"
}

@test "fnox set with interactive prompt" {
	skip "Interactive test - requires manual testing"
	# This test would require interactive input
	# Manual test: fnox set INTERACTIVE_SECRET --provider keychain
	# (will prompt for value when no value provided and stdin is a tty)
}

@test "fnox set updates existing secret" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Set initial value
	run "$FNOX_BIN" set UPDATE_TEST "initial-value" --provider keychain
	assert_success
	track_secret "UPDATE_TEST"

	# Update the value
	run "$FNOX_BIN" set UPDATE_TEST "updated-value" --provider keychain
	assert_success

	# Get the updated value
	run "$FNOX_BIN" get UPDATE_TEST
	assert_success
	assert_output "updated-value"
}

@test "fnox list shows keychain secrets" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Set multiple secrets
	run "$FNOX_BIN" set SECRET1 "value1" --provider keychain --description "First secret"
	assert_success
	track_secret "SECRET1"

	run "$FNOX_BIN" set SECRET2 "value2" --provider keychain --description "Second secret"
	assert_success
	track_secret "SECRET2"

	# List secrets
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "SECRET1"
	assert_output --partial "SECRET2"
	assert_output --partial "First secret"
	assert_output --partial "Second secret"
}

@test "fnox exec with keychain secrets" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Set a secret
	run "$FNOX_BIN" set EXEC_TEST "exec-value" --provider keychain
	assert_success
	track_secret "EXEC_TEST"

	# Use it in exec (redirect stderr to filter age warnings from global config)
	run bash -c "'$FNOX_BIN' exec -- bash -c 'echo \$EXEC_TEST' 2>/dev/null"
	assert_success
	assert_output "exec-value"
}

@test "fnox set with description metadata" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Set secret with description
	run "$FNOX_BIN" set DESCRIBED "value" --provider keychain --description "Test description"
	assert_success
	track_secret "DESCRIBED"

	# Verify description in list
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "DESCRIBED"
	assert_output --partial "Test description"
}

@test "fnox get with JSON-like value" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	local json_value='{"api_key":"test123","endpoint":"https://api.example.com"}'

	# Set JSON value
	run "$FNOX_BIN" set JSON_SECRET "$json_value" --provider keychain
	assert_success
	track_secret "JSON_SECRET"

	# Get it back
	run "$FNOX_BIN" get JSON_SECRET
	assert_success
	assert_output "$json_value"
}

@test "keychain provider isolation with different service names" {
	# Create config with first service
	create_keychain_config "${KEYCHAIN_SERVICE}-1"
	run "$FNOX_BIN" set ISOLATED1 "value1" --provider keychain
	assert_success
	track_secret "ISOLATED1"

	# Create config with second service
	create_keychain_config "${KEYCHAIN_SERVICE}-2"
	run "$FNOX_BIN" set ISOLATED2 "value2" --provider keychain
	assert_success
	track_secret "ISOLATED2"

	# First secret should not be accessible with second config
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.ISOLATED1]
provider = "keychain"
value = "ISOLATED1"
EOF

	run "$FNOX_BIN" get ISOLATED1
	assert_failure
}

@test "fnox set reads from stdin" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Set secret from stdin (using bash -c for stdin pipe)
	run bash -c "echo 'stdin-value' | '$FNOX_BIN' set STDIN_SECRET --provider keychain"
	assert_success
	track_secret "STDIN_SECRET"

	# Get it back
	run "$FNOX_BIN" get STDIN_SECRET
	assert_success
	assert_output "stdin-value"
}

@test "fnox with empty service name fails gracefully" {
	cat >"${FNOX_CONFIG_FILE}" <<EOF
[providers.keychain]
type = "keychain"
service = ""

[secrets.TEST]
provider = "keychain"
value = "test"
EOF

	# Should fail with helpful error
	run "$FNOX_BIN" get TEST
	assert_failure
}

@test "keychain provider with long values" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Create a long value (4KB)
	local long_value
	long_value=$(python3 -c "print('a' * 4096)")

	# Set long value
	run "$FNOX_BIN" set LONG_SECRET "$long_value" --provider keychain
	assert_success
	track_secret "LONG_SECRET"

	# Get it back
	run "$FNOX_BIN" get LONG_SECRET
	assert_success
	assert_output "$long_value"
}

@test "fnox check detects missing keychain secrets" {
	create_keychain_config "$KEYCHAIN_SERVICE"

	# Add reference without actually storing in keychain
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.MISSING_SECRET]
provider = "keychain"
value = "not-in-keychain"
if_missing = "error"
EOF

	# Check should detect the missing secret
	run "$FNOX_BIN" check
	assert_failure
	assert_output --partial "MISSING_SECRET"
}
