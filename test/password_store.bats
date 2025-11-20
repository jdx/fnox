#!/usr/bin/env bats
#
# Password-Store Provider Tests
#
# These tests verify the password-store (pass) provider integration with fnox.
#
# Prerequisites:
#   - pass CLI installed (password-store)
#   - gpg or gpg2 installed
#   - Run tests: mise run test:bats -- test/password_store.bats
#
# Note: Tests use a temporary PASSWORD_STORE_DIR to avoid conflicts.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Check if pass is installed
	if ! command -v pass >/dev/null 2>&1; then
		skip "password-store (pass) not installed"
	fi

	# Check if gpg is installed
	if ! command -v gpg >/dev/null 2>&1 && ! command -v gpg2 >/dev/null 2>&1; then
		skip "gpg not installed"
	fi

	# Set up test password store
	export PASSWORD_STORE_DIR="$BATS_TEST_TMPDIR/password-store"
	export GNUPGHOME="$BATS_TEST_TMPDIR/gnupg"
	mkdir -p "$PASSWORD_STORE_DIR" "$GNUPGHOME"
	chmod 700 "$GNUPGHOME"

	# Generate a test GPG key (non-interactive)
	local gpg_cmd="gpg"
	if command -v gpg2 >/dev/null 2>&1; then
		gpg_cmd="gpg2"
	fi

	# Create GPG batch config for key generation
	cat >"$GNUPGHOME/keygen.batch" <<EOF
%no-protection
Key-Type: DSA
Key-Length: 1024
Subkey-Type: ELG-E
Subkey-Length: 1024
Name-Real: Fnox Test
Name-Email: fnox-test@example.com
Expire-Date: 0
EOF

	# Generate the key
	$gpg_cmd --batch --gen-key "$GNUPGHOME/keygen.batch" >/dev/null 2>&1 || {
		skip "Failed to generate test GPG key"
	}

	# Get the key ID
	GPG_KEY_ID=$($gpg_cmd --list-keys --with-colons | grep '^fpr' | head -1 | cut -d: -f10)
	if [ -z "$GPG_KEY_ID" ]; then
		skip "Failed to get GPG key ID"
	fi
	export GPG_KEY_ID

	# Initialize password store
	pass init "$GPG_KEY_ID" >/dev/null 2>&1 || {
		skip "Failed to initialize password-store"
	}

	# Track secrets for cleanup
	export TEST_SECRET_PATHS=""
}

teardown() {
	# Clean up test secrets from password store
	if [ -n "$TEST_SECRET_PATHS" ]; then
		for path in $TEST_SECRET_PATHS; do
			pass rm -f "$path" >/dev/null 2>&1 || true
		done
	fi

	_common_teardown
}

# Helper function to create a password-store provider config
create_pass_config() {
	local prefix="${1:-}"
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
[providers.pass]
type = "password-store"
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

# Helper to track secret paths for cleanup
track_secret_path() {
	local path="$1"
	TEST_SECRET_PATHS="${TEST_SECRET_PATHS} $path"
}

@test "fnox set stores secret in password-store" {
	create_pass_config

	# Set a secret using the password-store provider
	run "$FNOX_BIN" set MY_SECRET "my-secret-value" --provider pass
	assert_success
	assert_output --partial "Set secret MY_SECRET"

	track_secret_path "MY_SECRET"

	# Verify the config contains only a reference (not the value)
	run cat "${FNOX_CONFIG_FILE}"
	assert_success
	assert_output --partial 'MY_SECRET'
	assert_output --partial 'provider = "pass"'
	assert_output --partial 'value = "MY_SECRET"'
	refute_output --partial "my-secret-value"

	# Verify the secret is actually stored in password-store
	run pass show MY_SECRET
	assert_success
	assert_output "my-secret-value"
}

@test "fnox get retrieves secret from password-store" {
	create_pass_config

	# Set a secret
	run "$FNOX_BIN" set TEST_GET "test-value-123" --provider pass
	assert_success
	track_secret_path "TEST_GET"

	# Get the secret back
	run "$FNOX_BIN" get TEST_GET
	assert_success
	assert_output "test-value-123"
}

@test "fnox set and get with prefix" {
	create_pass_config "work/"

	# Set a secret with prefix
	run "$FNOX_BIN" set PREFIXED_SECRET "prefixed-value" --provider pass
	assert_success
	track_secret_path "work/PREFIXED_SECRET"

	# Get the secret (prefix is applied automatically)
	run "$FNOX_BIN" get PREFIXED_SECRET
	assert_success
	assert_output "prefixed-value"

	# Verify it's stored in the right location
	run pass show work/PREFIXED_SECRET
	assert_success
	assert_output "prefixed-value"
}

@test "fnox get fails with non-existent secret" {
	create_pass_config

	# Manually add a reference to a non-existent secret
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.NONEXISTENT]
provider = "pass"
value = "does-not-exist-$$"
EOF

	# Try to get non-existent secret
	run "$FNOX_BIN" get NONEXISTENT
	assert_failure
	assert_output --partial "password-store CLI command failed"
}

@test "fnox set with special characters" {
	create_pass_config

	local secret_value='p@ssw0rd!#$%^&*()_+-={}[]|\:";'\''<>?,./~`'

	# Set a secret with special characters
	run "$FNOX_BIN" set SPECIAL_CHARS "$secret_value" --provider pass
	assert_success
	track_secret_path "SPECIAL_CHARS"

	# Get it back
	run "$FNOX_BIN" get SPECIAL_CHARS
	assert_success
	assert_output "$secret_value"
}

@test "fnox set with multiline value" {
	create_pass_config

	local multiline_value="line1
line2
line3"

	# Set a multiline secret (using bash -c for stdin pipe)
	run bash -c "echo '$multiline_value' | '$FNOX_BIN' set MULTILINE --provider pass"
	assert_success
	track_secret_path "MULTILINE"

	# Get it back
	run "$FNOX_BIN" get MULTILINE
	assert_success
	assert_output "$multiline_value"

	# Verify in password-store (pass show returns all lines)
	run pass show MULTILINE
	assert_success
	assert_output "$multiline_value"
}

@test "fnox set updates existing secret" {
	create_pass_config

	# Set initial value
	run "$FNOX_BIN" set UPDATE_TEST "initial-value" --provider pass
	assert_success
	track_secret_path "UPDATE_TEST"

	# Update the value
	run "$FNOX_BIN" set UPDATE_TEST "updated-value" --provider pass
	assert_success

	# Get the updated value
	run "$FNOX_BIN" get UPDATE_TEST
	assert_success
	assert_output "updated-value"
}

@test "fnox list shows password-store secrets" {
	create_pass_config

	# Set multiple secrets
	run "$FNOX_BIN" set SECRET1 "value1" --provider pass --description "First secret"
	assert_success
	track_secret_path "SECRET1"

	run "$FNOX_BIN" set SECRET2 "value2" --provider pass --description "Second secret"
	assert_success
	track_secret_path "SECRET2"

	# List secrets
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "SECRET1"
	assert_output --partial "SECRET2"
	assert_output --partial "First secret"
	assert_output --partial "Second secret"
}

@test "fnox exec with password-store secrets" {
	create_pass_config

	# Set a secret
	run "$FNOX_BIN" set EXEC_TEST "exec-value" --provider pass
	assert_success
	track_secret_path "EXEC_TEST"

	# Use it in exec (redirect stderr to filter warnings)
	run bash -c "'$FNOX_BIN' exec -- bash -c 'echo \$EXEC_TEST' 2>/dev/null"
	assert_success
	assert_output "exec-value"
}

@test "fnox set with description metadata" {
	create_pass_config

	# Set secret with description
	run "$FNOX_BIN" set DESCRIBED "value" --provider pass --description "Test description"
	assert_success
	track_secret_path "DESCRIBED"

	# Verify description in list
	run "$FNOX_BIN" list
	assert_success
	assert_output --partial "DESCRIBED"
	assert_output --partial "Test description"
}

@test "fnox get with JSON-like value" {
	create_pass_config

	local json_value='{"api_key":"test123","endpoint":"https://api.example.com"}'

	# Set JSON value
	run "$FNOX_BIN" set JSON_SECRET "$json_value" --provider pass
	assert_success
	track_secret_path "JSON_SECRET"

	# Get it back
	run "$FNOX_BIN" get JSON_SECRET
	assert_success
	assert_output "$json_value"
}

@test "fnox set reads from stdin" {
	create_pass_config

	# Set secret from stdin (using bash -c for stdin pipe)
	run bash -c "echo 'stdin-value' | '$FNOX_BIN' set STDIN_SECRET --provider pass"
	assert_success
	track_secret_path "STDIN_SECRET"

	# Get it back
	run "$FNOX_BIN" get STDIN_SECRET
	assert_success
	assert_output "stdin-value"
}

@test "password-store provider with long values" {
	create_pass_config

	# Create a long value (4KB)
	local long_value
	long_value=$(python3 -c "print('a' * 4096)")

	# Set long value
	run "$FNOX_BIN" set LONG_SECRET "$long_value" --provider pass
	assert_success
	track_secret_path "LONG_SECRET"

	# Get it back
	run "$FNOX_BIN" get LONG_SECRET
	assert_success
	assert_output "$long_value"
}

@test "fnox check detects missing password-store secrets" {
	create_pass_config

	# Add reference without actually storing in password-store
	cat >>"${FNOX_CONFIG_FILE}" <<EOF

[secrets.MISSING_SECRET]
provider = "pass"
value = "not-in-pass-store"
if_missing = "error"
EOF

	# Check should detect the missing secret
	run "$FNOX_BIN" check
	assert_failure
	assert_output --partial "MISSING_SECRET"
}

@test "fnox set with nested path" {
	create_pass_config

	# Set a secret with nested path
	run "$FNOX_BIN" set NESTED_SECRET "nested-value" --provider pass --key-name "company/project/api-key"
	assert_success
	track_secret_path "company/project/api-key"

	# Get it back
	run "$FNOX_BIN" get NESTED_SECRET
	assert_success
	assert_output "nested-value"

	# Verify it's stored in the nested path
	run pass show company/project/api-key
	assert_success
	assert_output "nested-value"
}

@test "password-store provider respects PASSWORD_STORE_DIR" {
	# Create a custom password store directory
	local custom_store="$BATS_TEST_TMPDIR/custom-password-store"
	mkdir -p "$custom_store"

	# Initialize custom password store
	PASSWORD_STORE_DIR="$custom_store" pass init "$GPG_KEY_ID" >/dev/null 2>&1

	# Set PASSWORD_STORE_DIR and create config
	export PASSWORD_STORE_DIR="$custom_store"
	create_pass_config

	# Set a secret
	run "$FNOX_BIN" set CUSTOM_STORE_SECRET "custom-value" --provider pass
	assert_success
	track_secret_path "CUSTOM_STORE_SECRET"

	# Verify it's in the custom store
	run pass show CUSTOM_STORE_SECRET
	assert_success
	assert_output "custom-value"

	# Verify the .gpg file exists in custom location
	[ -f "$custom_store/CUSTOM_STORE_SECRET.gpg" ]
}

@test "password-store provider with hierarchical secrets" {
	create_pass_config "myapp/"

	# Set secrets in hierarchy
	run "$FNOX_BIN" set DB_PASSWORD "db-pass" --provider pass --key-name "database/password"
	assert_success
	track_secret_path "myapp/database/password"

	run "$FNOX_BIN" set API_KEY "api-key" --provider pass --key-name "api/github"
	assert_success
	track_secret_path "myapp/api/github"

	# Get them back
	run "$FNOX_BIN" get DB_PASSWORD
	assert_success
	assert_output "db-pass"

	run "$FNOX_BIN" get API_KEY
	assert_success
	assert_output "api-key"

	# Verify hierarchy with pass ls
	run pass ls myapp
	assert_success
	assert_output --partial "database"
	assert_output --partial "api"
}
