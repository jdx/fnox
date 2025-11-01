#!/usr/bin/env bash

# Common setup function for fnox bats tests
# Usage: _common_setup [--git]
#
# Options:
#   --git    Initialize a git repository in the test directory
#            (only needed for tests that specifically require git functionality)
_common_setup() {
	local setup_git=false

	# Parse optional --git flag
	while [[ $# -gt 0 ]]; do
		case $1 in
		--git)
			setup_git=true
			shift
			;;
		*)
			shift
			;;
		esac
	done

	load 'test_helper/bats-support/load'
	load 'test_helper/bats-assert/load'
	load 'test_helper/bats-file/load'
	load 'test_helper/assertions'
	load 'test_helper/setup_helpers'

	export PROJECT_ROOT="$BATS_TEST_DIRNAME/.."

	# Set BATS_TMPDIR to use our custom tmp directory
	# This ensures temp_make creates directories in ~/src/fnox/tmp
	export BATS_TMPDIR="$PROJECT_ROOT/tmp"

	# Create a temporary directory for each test
	TEST_TEMP_DIR="$(temp_make --prefix 'fnox-test-')"
	mkdir -p "$TEST_TEMP_DIR"
	cd "$TEST_TEMP_DIR" || exit 1

	# Set up git repository only for tests that need it
	if [[ $setup_git == true ]]; then
		export GIT_CONFIG_NOSYSTEM=1
		export GIT_CONFIG_GLOBAL="$TEST_TEMP_DIR/.gitconfig"

		git config --global init.defaultBranch main
		git config --global user.email "test@example.com"
		git config --global user.name "Test User"

		git init . 2>/dev/null || true # Don't fail if already in a git repo
	fi

	# Add fnox to PATH - prefer debug build for testing, fall back to release
	if [[ -f "$PROJECT_ROOT/target/debug/fnox" ]]; then
		export FNOX_BIN="$PROJECT_ROOT/target/debug/fnox"
	elif [[ -f "$PROJECT_ROOT/target/release/fnox" ]]; then
		export FNOX_BIN="$PROJECT_ROOT/target/release/fnox"
	else
		echo "Error: fnox binary not found. Please run 'cargo build' first." >&2
		exit 1
	fi

	# Make sure fnox is executable
	chmod +x "$FNOX_BIN"

	# Add to PATH for convenience
	local fnox_dir
	fnox_dir="$(dirname "$FNOX_BIN")"
	export PATH="$fnox_dir:$PATH"

	# Set up test environment variables
	export HOME="$TEST_TEMP_DIR"
	export FNOX_CONFIG_FILE="$TEST_TEMP_DIR/fnox.toml"

	# Clear hook-env session state to ensure clean test environment
	unset __FNOX_SESSION

	# Ensure no existing config
	rm -f "$FNOX_CONFIG_FILE"
}

_common_teardown() {
	chmod -R u+w "$TEST_TEMP_DIR"
	temp_del "$TEST_TEMP_DIR"
}
