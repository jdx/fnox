#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox export includes parent config secrets without masking" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config with a secret
	cat >parent/fnox.toml <<EOF
root = true

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-value-123" }
EOF

	# Create child config with another secret
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-value-456" }
EOF

	# Change to child directory
	cd parent/child

	# Export secrets and check they're not masked
	run "$FNOX_BIN" export --format env
	assert_success

	# Check that parent secret is exported with actual value, not masked
	assert_output --partial "PARENT_SECRET='parent-value-123'"
	assert_output --partial "CHILD_SECRET='child-value-456'"

	# Make sure secrets are not masked with dots
	refute_output --partial "··"
}

@test "fnox export with -o file includes parent config secrets" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config
	cat >parent/fnox.toml <<EOF
root = true

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "sb_secret_asdas12345" }
EOF

	# Create child config
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-token-xyz" }
EOF

	# Change to child directory
	cd parent/child

	# Export to file
	run "$FNOX_BIN" export -o .env
	assert_success

	# Check the file contents
	run cat .env
	assert_success
	assert_output --partial "PARENT_SECRET='sb_secret_asdas12345'"
	assert_output --partial "CHILD_SECRET='child-token-xyz'"

	# Make sure secrets are not masked
	refute_output --partial "··"
}

@test "fnox export with stdout redirect includes parent config secrets" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config
	cat >parent/fnox.toml <<EOF
root = true

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-api-key" }
EOF

	# Create child config
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-api-key" }
EOF

	# Change to child directory
	cd parent/child

	# Export with stdout redirect
	"$FNOX_BIN" export > .env

	# Check the file contents
	run cat .env
	assert_success
	assert_output --partial "PARENT_SECRET='parent-api-key'"
	assert_output --partial "CHILD_SECRET='child-api-key'"

	# Make sure secrets are not masked
	refute_output --partial "··"
}

@test "fnox export json format includes parent config secrets" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config
	cat >parent/fnox.toml <<EOF
root = true

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-json-value" }
EOF

	# Create child config
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-json-value" }
EOF

	# Change to child directory
	cd parent/child

	# Export as JSON
	run "$FNOX_BIN" export --format json
	assert_success

	# Check JSON contains actual values
	assert_output --partial '"PARENT_SECRET": "parent-json-value"'
	assert_output --partial '"CHILD_SECRET": "child-json-value"'

	# Make sure secrets are not masked
	refute_output --partial "··"
}

@test "fnox export with age provider and profile includes parent secrets" {
	# Skip if age not installed
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	# Generate age key
	local keygen_output
	keygen_output=$(age-keygen -o key.txt 2>&1)
	local public_key
	public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
	local private_key
	private_key=$(grep "^AGE-SECRET-KEY" key.txt)

	# Create directory structure
	mkdir -p parent/child

	# Create parent config with age provider and profile
	cat >parent/fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[profiles.prod.secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-prod-secret-123" }
EOF

	# Encrypt parent secret
	cd parent
	export FNOX_AGE_KEY="$private_key"
	run "$FNOX_BIN" set PARENT_SECRET "sb_secret_parent_encrypted_value_xyz" --provider age --profile prod
	assert_success
	cd ..

	# Create child config with age secret
	cat >parent/child/fnox.toml <<EOF
[profiles.prod.secrets]
CHILD_SECRET = { description = "Child secret", default = "child-prod-secret-456" }
EOF

	# Encrypt child secret
	cd parent/child
	run "$FNOX_BIN" set CHILD_SECRET "child_encrypted_token_abc" --provider age --profile prod
	assert_success

	# Export with profile
	run "$FNOX_BIN" export --profile prod --age-key-file ../../key.txt
	assert_success

	# Check that both secrets are exported with actual values
	assert_output --partial "PARENT_SECRET='sb_secret_parent_encrypted_value_xyz'"
	assert_output --partial "CHILD_SECRET='child_encrypted_token_abc'"

	# Make sure secrets are not masked
	refute_output --partial "··"
}
