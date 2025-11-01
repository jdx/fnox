#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "config recursion finds parent configs" {
	# Create directory structure
	mkdir -p parent/child/grandchild

	# Create parent config (allows recursion to child)
	cat >parent/fnox.toml <<EOF
[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-value" }

[profiles.production.secrets]
PARENT_PROD_SECRET = { description = "Parent prod secret", default = "parent-prod-value" }
EOF

	# Create child config
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-value" }
PARENT_SECRET = { description = "Override parent secret", default = "child-override-value" }
EOF

	# Change to grandchild directory
	cd parent/child/grandchild

	# Test that we can access merged secrets
	run "$FNOX_BIN" get PARENT_SECRET
	assert_success
	assert_output --partial "child-override-value" # Child overrides parent

	run "$FNOX_BIN" get CHILD_SECRET
	assert_success
	assert_output --partial "child-value"

	run "$FNOX_BIN" get PARENT_PROD_SECRET --profile production
	assert_success
	assert_output --partial "parent-prod-value"
}

@test "config root stops recursion" {
	# Create directory structure
	mkdir -p root/child/grandchild

	# Create root config with root = true
	cat >root/fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
ROOT_SECRET = { description = "Root secret", default = "root-value" }
EOF

	# Create grandparent config above root (should be ignored)
	cat >fnox.toml <<EOF
root = true

[secrets]
GRANDPARENT_SECRET = { description = "Should be ignored", default = "grandparent-value" }
EOF

	# Change to child directory
	cd root/child

	# Test that we can access root secrets
	run "$FNOX_BIN" get ROOT_SECRET
	assert_success
	assert_output --partial "root-value"

	# Test that grandparent secrets are not accessible
	run "$FNOX_BIN" get GRANDPARENT_SECRET
	assert_failure
	assert_output --partial "not found"
}

@test "config imports work correctly" {
	# Create imported config
	cat >imported.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
IMPORTED_SECRET = { description = "Imported secret", default = "imported-value" }

[profiles.imported.secrets]
IMPORTED_PROFILE_SECRET = { description = "Imported profile secret", default = "imported-profile-value" }
EOF

	# Create main config that imports
	cat >fnox.toml <<EOF
root = true
import = ["./imported.toml"]

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { description = "Main secret", default = "main-value" }
IMPORTED_SECRET = { description = "Override imported secret", default = "main-override-value" }
EOF

	# Test that we can access imported secrets
	run "$FNOX_BIN" get IMPORTED_SECRET
	assert_success
	assert_output --partial "main-override-value" # Main overrides imported

	run "$FNOX_BIN" get MAIN_SECRET
	assert_success
	assert_output --partial "main-value"

	run "$FNOX_BIN" get IMPORTED_PROFILE_SECRET --profile imported
	assert_success
	assert_output --partial "imported-profile-value"
}

@test "config imports with absolute paths work" {
	# Create imported config
	cat >imported.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
ABS_IMPORT_SECRET = { description = "Absolute import secret", default = "abs-import-value" }
EOF

	# Get absolute path
	abs_path="$(pwd)/imported.toml"

	# Create main config with absolute import
	cat >fnox.toml <<EOF
root = true
import = ["${abs_path}"]

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { description = "Main secret", default = "main-value" }
EOF

	# Test that absolute import works
	run "$FNOX_BIN" get ABS_IMPORT_SECRET
	assert_success
	assert_output --partial "abs-import-value"
}

@test "config import errors are handled gracefully" {
	# Create main config with non-existent import
	cat >fnox.toml <<EOF
root = true
import = ["./nonexistent.toml"]

[secrets]
MAIN_SECRET = { description = "Main secret", default = "main-value" }
EOF

	# Test that import error is reported
	run "$FNOX_BIN" get MAIN_SECRET
	assert_failure
	assert_output --partial "Import file not found"
}

@test "config recursion with imports works together" {
	# Create directory structure
	mkdir -p parent/child

	# Create imported config
	cat >imported.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
IMPORTED_SECRET = { description = "Imported secret", default = "imported-value" }
EOF

	# Create parent config with import
	cat >parent/fnox.toml <<EOF
import = ["../imported.toml"]

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-value" }
EOF

	# Create child config
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-value" }
EOF

	# Change to child directory
	cd parent/child

	# Test that we can access all secrets
	run "$FNOX_BIN" get IMPORTED_SECRET
	assert_success
	assert_output --partial "imported-value"

	run "$FNOX_BIN" get PARENT_SECRET
	assert_success
	assert_output --partial "parent-value"

	run "$FNOX_BIN" get CHILD_SECRET
	assert_success
	assert_output --partial "child-value"
}

@test "explicit config path bypasses recursion" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config
	cat >parent/fnox.toml <<EOF
[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-value" }
EOF

	# Create child config
	cat >parent/child/fnox.toml <<EOF
root = true

[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-value" }
EOF

	# Change to child directory and test explicit path
	cd parent/child

	# Use explicit path - should only load that file
	run "$FNOX_BIN" -c ../fnox.toml get PARENT_SECRET
	assert_success
	assert_output --partial "parent-value"

	# Should not find child secret when using parent config
	run "$FNOX_BIN" -c ../fnox.toml get CHILD_SECRET
	assert_failure
	assert_output --partial "not found"
}
