#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "config-files lists the discovery chain" {
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[secrets]
GLOBAL_SECRET = { default = "global-value" }
EOF

	mkdir -p parent/child
	cat >parent/fnox.toml <<EOF
[secrets]
PARENT_SECRET = { default = "parent-value" }
EOF
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { default = "child-value" }
EOF

	cd parent/child

	run "$FNOX_BIN" config-files
	assert_success
	assert_output --partial "parent/child/fnox.toml"
	assert_output --partial "parent/fnox.toml"
	assert_output --partial ".config/fnox/config.toml"
}

@test "config-files with explicit --config lists only that file and global" {
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[secrets]
GLOBAL_SECRET = { default = "global-value" }
EOF

	mkdir -p parent/child
	cat >parent/fnox.toml <<EOF
[secrets]
PARENT_SECRET = { default = "parent-value" }
EOF
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { default = "child-value" }
EOF
	cat >parent/child/custom.toml <<EOF
[secrets]
CUSTOM_SECRET = { default = "custom-value" }
EOF

	cd parent/child

	run "$FNOX_BIN" -c custom.toml config-files
	assert_success
	assert_output --partial "custom.toml"
	assert_output --partial ".config/fnox/config.toml"

	# Files that are not actually loaded must not be listed
	refute_output --partial "child/fnox.toml"
	refute_output --partial "parent/fnox.toml"
}

@test "config-files with explicit --config lists imports" {
	cat >imported.toml <<EOF
[secrets]
IMPORTED_SECRET = { default = "imported-value" }
EOF
	cat >custom.toml <<EOF
import = ["./imported.toml"]

[secrets]
CUSTOM_SECRET = { default = "custom-value" }
EOF

	run "$FNOX_BIN" -c custom.toml config-files
	assert_success
	assert_output --partial "custom.toml"
	assert_output --partial "imported.toml"
}

@test "config-files fails on a missing explicit --config file" {
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[secrets]
GLOBAL_SECRET = { default = "global-value" }
EOF

	# Loading would fail before reaching the global layer, so listing the
	# global config here would describe a load that cannot happen
	run "$FNOX_BIN" -c missing.toml config-files
	assert_failure
	assert_output --partial "Failed to read configuration file"
	refute_output --partial ".config/fnox/config.toml"
}
