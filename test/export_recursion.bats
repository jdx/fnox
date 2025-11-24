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
