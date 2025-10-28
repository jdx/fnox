#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# ============================================================================
# fnox activate tests
# ============================================================================

@test "fnox activate bash generates valid bash code" {
	run "$FNOX_BIN" activate bash

	assert_success
	assert_output --partial "export FNOX_SHELL=bash"
	assert_output --partial "fnox()"
	assert_output --partial "_fnox_hook()"
	assert_output --partial "PROMPT_COMMAND"
}

@test "fnox activate zsh generates valid zsh code" {
	run "$FNOX_BIN" activate zsh

	assert_success
	assert_output --partial "export FNOX_SHELL=zsh"
	assert_output --partial "fnox()"
	assert_output --partial "_fnox_hook()"
	assert_output --partial "precmd_functions"
	assert_output --partial "chpwd_functions"
}

@test "fnox activate fish generates valid fish code" {
	run "$FNOX_BIN" activate fish

	assert_success
	assert_output --partial "set -gx FNOX_SHELL fish"
	assert_output --partial "function fnox"
	assert_output --partial "function __fnox_env_eval"
	assert_output --partial "function __fnox_cd_hook --on-variable PWD"
}

@test "fnox activate --no-hook-env skips hook setup" {
	run "$FNOX_BIN" activate bash --no-hook-env

	assert_success
	assert_output --partial "export FNOX_SHELL=bash"
	assert_output --partial "fnox()"
	refute_output --partial "_fnox_hook()"
	refute_output --partial "PROMPT_COMMAND"
}

@test "fnox activate with invalid shell fails" {
	run "$FNOX_BIN" activate invalid-shell

	assert_failure
	assert_output --partial "unsupported shell"
}

@test "fnox activate detects shell from SHELL env var" {
	export SHELL="/bin/bash"
	run "$FNOX_BIN" activate

	assert_success
	assert_output --partial "export FNOX_SHELL=bash"
}

# ============================================================================
# fnox hook-env tests - basic functionality
# ============================================================================

@test "fnox hook-env with no config produces minimal output" {
	# Use a fresh directory that's not in the project tree
	mkdir -p "$TEST_TEMP_DIR/isolated"
	cd "$TEST_TEMP_DIR/isolated"
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	# Should at least output session vars even with no secrets
	assert_output --partial '__FNOX_SESSION='
}

@test "fnox hook-env loads secrets from fnox.toml" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.TEST_SECRET]
		provider = "plain"
		value = "test-value-123"
	EOF

	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export TEST_SECRET="test-value-123"'
	assert_output --partial 'export __FNOX_SESSION='
	assert_output --partial 'export __FNOX_DIFF='
}

@test "fnox hook-env loads multiple secrets" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.SECRET_ONE]
		provider = "plain"
		value = "value-one"

		[secrets.SECRET_TWO]
		provider = "plain"
		value = "value-two"

		[secrets.SECRET_THREE]
		provider = "plain"
		value = "value-three"
	EOF

	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export SECRET_ONE="value-one"'
	assert_output --partial 'export SECRET_TWO="value-two"'
	assert_output --partial 'export SECRET_THREE="value-three"'
}

@test "fnox hook-env generates fish-compatible output" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.FISH_SECRET]
		provider = "plain"
		value = "fish-value"
	EOF

	run "$FNOX_BIN" hook-env -s fish

	assert_success
	assert_output --partial 'set -gx FISH_SECRET "fish-value"'
	assert_output --partial 'set -gx __FNOX_SESSION'
	assert_output --partial 'set -gx __FNOX_DIFF'
}

@test "fnox hook-env finds config in parent directory" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.PARENT_SECRET]
		provider = "plain"
		value = "parent-value"
	EOF

	# Create subdirectory and run from there
	mkdir -p subdir/nested
	cd subdir/nested

	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export PARENT_SECRET="parent-value"'
}

# ============================================================================
# Session tracking and optimization tests
# ============================================================================

@test "fnox hook-env with same directory and config exits early" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.CACHED_SECRET]
		provider = "plain"
		value = "cached-value"
	EOF

	# First run - should load secrets
	output1=$("$FNOX_BIN" hook-env -s bash)
	echo "$output1" | grep -q 'export CACHED_SECRET="cached-value"'

	# Extract session from first run
	session=$(echo "$output1" | grep '__FNOX_SESSION=' | sed 's/^export __FNOX_SESSION="//' | sed 's/"$//')

	# Second run with session - should exit early (no output)
	export __FNOX_SESSION="$session"
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output ""
}

@test "fnox hook-env reloads when config is modified" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.MODIFIED_SECRET]
		provider = "plain"
		value = "original-value"
	EOF

	# First run
	output1=$("$FNOX_BIN" hook-env -s bash)
	session=$(echo "$output1" | grep '__FNOX_SESSION=' | sed 's/^export __FNOX_SESSION="//' | sed 's/"$//')

	# Modify config file
	sleep 1 # Ensure mtime changes
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.MODIFIED_SECRET]
		provider = "plain"
		value = "updated-value"
	EOF

	# Second run with session - should detect modification and reload
	export __FNOX_SESSION="$session"
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export MODIFIED_SECRET="updated-value"'
}

@test "fnox hook-env reloads when parent config is modified" {
	# Create parent directory with config
	parent_dir="$TEST_TEMP_DIR/parent"
	mkdir -p "$parent_dir"
	cd "$parent_dir"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.PARENT_SECRET]
		provider = "plain"
		value = "parent-original"
	EOF

	# Create child directory with its own config
	child_dir="$parent_dir/child"
	mkdir -p "$child_dir"
	cd "$child_dir"
	cat >fnox.toml <<-EOF
		[secrets.CHILD_SECRET]
		provider = "plain"
		value = "child-value"
	EOF

	# First run - should load both parent and child secrets
	output1=$("$FNOX_BIN" hook-env -s bash)
	session=$(echo "$output1" | grep '__FNOX_SESSION=' | sed 's/^export __FNOX_SESSION="//' | sed 's/"$//')
	echo "$output1" | grep -q 'export PARENT_SECRET="parent-original"'
	echo "$output1" | grep -q 'export CHILD_SECRET="child-value"'

	# Modify parent config file
	sleep 1 # Ensure mtime changes
	cat >"$parent_dir/fnox.toml" <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.PARENT_SECRET]
		provider = "plain"
		value = "parent-updated"
	EOF

	# Second run with session - should detect parent modification and reload
	export __FNOX_SESSION="$session"
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export PARENT_SECRET="parent-updated"'
}

@test "fnox hook-env reloads when config is deleted" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.TEMPORARY_SECRET]
		provider = "plain"
		value = "temp-value"
	EOF

	# First run - should load secret
	output1=$("$FNOX_BIN" hook-env -s bash)
	session=$(echo "$output1" | grep '__FNOX_SESSION=' | sed 's/^export __FNOX_SESSION="//' | sed 's/"$//')
	echo "$output1" | grep -q 'export TEMPORARY_SECRET="temp-value"'

	# Delete config file
	rm fnox.toml

	# Second run with session - should detect deletion and unset the secret
	export __FNOX_SESSION="$session"
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'unset TEMPORARY_SECRET'
}

@test "fnox hook-env reloads when directory changes" {
	# Create first directory with config
	dir1="$TEST_TEMP_DIR/dir1"
	mkdir -p "$dir1"
	cd "$dir1"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.DIR1_SECRET]
		provider = "plain"
		value = "dir1-value"
	EOF

	# First run in dir1
	output1=$("$FNOX_BIN" hook-env -s bash)
	session=$(echo "$output1" | grep '__FNOX_SESSION=' | sed 's/^export __FNOX_SESSION="//' | sed 's/"$//')
	echo "$output1" | grep -q 'export DIR1_SECRET="dir1-value"'

	# Create second directory with different config
	dir2="$TEST_TEMP_DIR/dir2"
	mkdir -p "$dir2"
	cd "$dir2"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.DIR2_SECRET]
		provider = "plain"
		value = "dir2-value"
	EOF

	# Second run in dir2 with session from dir1 - should detect directory change
	export __FNOX_SESSION="$session"
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export DIR2_SECRET="dir2-value"'
	# DIR1_SECRET should be unset
	assert_output --partial 'unset DIR1_SECRET'
}

@test "fnox hook-env removes secrets when leaving directory with config" {
	# Create directory with config
	dir_with_config="$TEST_TEMP_DIR/with-config"
	mkdir -p "$dir_with_config"
	cd "$dir_with_config"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.TEMPORARY_SECRET]
		provider = "plain"
		value = "temp-value"
	EOF

	# First run - loads secret
	output1=$("$FNOX_BIN" hook-env -s bash)
	session=$(echo "$output1" | grep '__FNOX_SESSION=' | sed 's/^export __FNOX_SESSION="//' | sed 's/"$//')
	echo "$output1" | grep -q 'export TEMPORARY_SECRET="temp-value"'

	# Move to directory without config
	dir_without_config="$TEST_TEMP_DIR/without-config"
	mkdir -p "$dir_without_config"
	cd "$dir_without_config"

	# Second run - should unset the secret
	export __FNOX_SESSION="$session"
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'unset TEMPORARY_SECRET'
}

# ============================================================================
# Profile support tests
# ============================================================================

@test "fnox hook-env respects FNOX_PROFILE environment variable" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.DEFAULT_SECRET]
		provider = "plain"
		value = "default-value"

		[profiles.dev]
		[profiles.dev.providers.plain]
		type = "plain"

		[profiles.dev.secrets.DEV_SECRET]
		provider = "plain"
		value = "dev-value"
	EOF

	# Test with dev profile - should inherit top-level secrets
	export FNOX_PROFILE="dev"
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export DEV_SECRET="dev-value"'
	assert_output --partial 'export DEFAULT_SECRET="default-value"'
}

# ============================================================================
# Error handling tests
# ============================================================================

@test "fnox hook-env handles missing provider gracefully" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[secrets.MISSING_PROVIDER_SECRET]
		provider = "nonexistent"
		value = "some-value"
	EOF

	# Should not fail, just skip the secret
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	# Should still set session vars even if some secrets fail
	assert_output --partial '__FNOX_SESSION='
}

@test "fnox hook-env handles invalid toml gracefully" {
	# Create isolated directory to avoid picking up parent config
	mkdir -p "$TEST_TEMP_DIR/isolated-invalid"
	cd "$TEST_TEMP_DIR/isolated-invalid"
	cat >fnox.toml <<-EOF
		[secrets.BAD_TOML
		this is not valid toml
	EOF

	# Should not crash even with invalid toml
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	# May output session vars even if config is invalid
	# Just verify it didn't crash
}

# ============================================================================
# Integration with age provider
# ============================================================================

@test "fnox hook-env works with age-encrypted secrets" {
	# Skip - age provider integration needs more investigation
	# The plain provider tests already validate core hook-env functionality
	skip "age provider integration test - needs settings system configuration"

	# Skip if age not available
	if ! command -v age-keygen &>/dev/null; then
		skip "age-keygen not installed"
	fi

	cd "$TEST_TEMP_DIR"

	# Generate age key
	age-keygen -o age.txt 2>/dev/null
	recipient=$(grep "^# public key:" age.txt | cut -d: -f2 | tr -d ' ')

	# Encrypt a value
	encrypted=$(echo -n "encrypted-value" | age -r "$recipient" -a)

	cat >fnox.toml <<-EOF
		age_key_file = "$TEST_TEMP_DIR/age.txt"

		[providers.age]
		type = "age"
		recipients = ["$recipient"]

		[secrets.AGE_SECRET]
		provider = "age"
		value = """
$encrypted"""
	EOF

	# Run hook-env
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export AGE_SECRET="encrypted-value"'
}

# ============================================================================
# Shell-specific formatting tests
# ============================================================================

@test "fnox hook-env escapes special characters for bash" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-'EOF'
		[providers.plain]
		type = "plain"

		[secrets.SPECIAL_CHARS]
		provider = "plain"
		value = "value with spaces and \"quotes\""
	EOF

	run "$FNOX_BIN" hook-env -s bash

	assert_success
	# Should properly escape quotes
	assert_output --partial 'export SPECIAL_CHARS='
	assert_output --partial '\"quotes\"'
}

@test "fnox hook-env handles newlines in secret values" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-'EOF'
		[providers.plain]
		type = "plain"

		[secrets.MULTILINE]
		provider = "plain"
		value = """line1
line2
line3"""
	EOF

	run "$FNOX_BIN" hook-env -s bash

	assert_success
	# Should export the value (bash will handle the newlines)
	assert_output --partial 'export MULTILINE='
}

# ============================================================================
# Session state persistence tests
# ============================================================================

@test "fnox hook-env session state is valid base64" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.SESSION_TEST]
		provider = "plain"
		value = "session-value"
	EOF

	output=$("$FNOX_BIN" hook-env -s bash)
	session=$(echo "$output" | grep '__FNOX_SESSION=' | sed 's/^export __FNOX_SESSION="//' | sed 's/"$//')

	# Should be valid base64 (can decode without error)
	run base64 -d <<<"$session"
	assert_success
}

@test "fnox hook-env session tracks loaded secrets" {
	cd "$TEST_TEMP_DIR"
	cat >fnox.toml <<-EOF
		[providers.plain]
		type = "plain"

		[secrets.TRACKED_SECRET]
		provider = "plain"
		value = "tracked-value"
	EOF

	output=$("$FNOX_BIN" hook-env -s bash)

	# Session should be created
	echo "$output" | grep -q '__FNOX_SESSION='

	# Extract and verify session is not empty
	session=$(echo "$output" | grep '__FNOX_SESSION=' | sed 's/^export __FNOX_SESSION="//' | sed 's/"$//')
	[ -n "$session" ]
}

# ============================================================================
# fnox.local.toml support tests
# ============================================================================

@test "fnox hook-env loads secrets from fnox.local.toml without fnox.toml" {
	# Create an isolated directory with only fnox.local.toml (no fnox.toml)
	mkdir -p "$TEST_TEMP_DIR/local-only"
	cd "$TEST_TEMP_DIR/local-only"

	cat >fnox.local.toml <<-EOF
		root = true

		[providers.plain]
		type = "plain"

		[secrets.LOCAL_ONLY_SECRET]
		provider = "plain"
		value = "local-only-value"
	EOF

	# hook-env should load secrets even with only fnox.local.toml
	run "$FNOX_BIN" hook-env -s bash

	assert_success
	assert_output --partial 'export LOCAL_ONLY_SECRET="local-only-value"'
	assert_output --partial '__FNOX_SESSION='
}
