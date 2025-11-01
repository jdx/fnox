#!/usr/bin/env bats
#
# Test hook-env with provider inheritance from parent configs using plain provider
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# Suppress shell integration output for cleaner test output
	export FNOX_SHELL_INTEGRATION_OUTPUT="none"
}

teardown() {
	_common_teardown
}

@test "hook-env inherits plain provider from parent config" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config with plain provider
	cat >parent/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.PARENT_SECRET]
provider = "plain"
value = "parent-plain-value"
description = "Parent secret"
EOF

	# Create child config that uses plain provider but doesn't define it
	cat >parent/child/fnox.toml <<EOF
[secrets.CHILD_SECRET]
provider = "plain"
value = "child-plain-value"
description = "Child secret"
EOF

	# Change to child directory
	cd parent/child

	# Test 1: fnox ls should show both secrets merged
	run "$FNOX_BIN" ls
	assert_success
	assert_output --partial "PARENT_SECRET"
	assert_output --partial "CHILD_SECRET"

	# Test 2: fnox get should work for child secret (inheriting parent provider)
	run "$FNOX_BIN" get CHILD_SECRET
	assert_success
	assert_output "child-plain-value"

	# Test 3: fnox hook-env should load both secrets without error
	run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$CHILD_SECRET"
	assert_success
	assert_output "child-plain-value"

	# Test 4: Verify no warning about provider not found
	run "$FNOX_BIN" hook-env -s bash 2>&1
	assert_success
	refute_output --partial "Provider 'plain' not found"
}

@test "hook-env with nested provider inheritance (3 levels)" {
	# Create directory structure
	mkdir -p root/parent/child

	# Create root config with plain provider
	cat >root/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.ROOT_SECRET]
provider = "plain"
value = "root-value"
description = "Root secret"
EOF

	# Create parent config (no provider, just secrets)
	cat >root/parent/fnox.toml <<EOF
[secrets.PARENT_SECRET]
provider = "plain"
value = "parent-value"
description = "Parent secret"
EOF

	# Create child config (no provider, just secrets)
	cat >root/parent/child/fnox.toml <<EOF
[secrets.CHILD_SECRET]
provider = "plain"
value = "child-value"
description = "Child secret"
EOF

	# Change to child directory (deepest level)
	cd root/parent/child

	# Test 1: fnox ls should show all three secrets
	run "$FNOX_BIN" ls
	assert_success
	assert_output --partial "ROOT_SECRET"
	assert_output --partial "PARENT_SECRET"
	assert_output --partial "CHILD_SECRET"

	# Test 2: fnox get should work for all secrets
	run "$FNOX_BIN" get ROOT_SECRET
	assert_success
	assert_output "root-value"

	run "$FNOX_BIN" get PARENT_SECRET
	assert_success
	assert_output "parent-value"

	run "$FNOX_BIN" get CHILD_SECRET
	assert_success
	assert_output "child-value"

	# Test 3: hook-env should load all secrets without error
	run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$CHILD_SECRET"
	assert_success
	assert_output "child-value"

	# Test 4: Verify no warnings
	run "$FNOX_BIN" hook-env -s bash 2>&1
	assert_success
	refute_output --partial "Provider 'plain' not found"
}

@test "hook-env merges secrets from multiple config levels" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config
	cat >parent/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.SECRET1]
provider = "plain"
value = "value1"

[secrets.SECRET2]
provider = "plain"
value = "value2"
EOF

	# Create child config with additional secrets
	cat >parent/child/fnox.toml <<EOF
[secrets.SECRET3]
provider = "plain"
value = "value3"

[secrets.SECRET4]
provider = "plain"
value = "value4"
EOF

	# Change to child directory
	cd parent/child

	# hook-env should load all 4 secrets
	run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$SECRET1 \$SECRET2 \$SECRET3 \$SECRET4"
	assert_success
	assert_output "value1 value2 value3 value4"
}

@test "hook-env respects child override of parent secret" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config
	cat >parent/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.SHARED_SECRET]
provider = "plain"
value = "parent-value"
EOF

	# Create child config that overrides parent secret
	cat >parent/child/fnox.toml <<EOF
[secrets.SHARED_SECRET]
provider = "plain"
value = "child-override-value"
EOF

	# Change to child directory
	cd parent/child

	# Should get the child's value, not the parent's
	run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$SHARED_SECRET"
	assert_success
	assert_output "child-override-value"
}

@test "hook-env loads fnox.local.toml and merges with fnox.toml" {
	# Create directory with both fnox.toml and fnox.local.toml
	mkdir -p test_dir

	# Create main config
	cat >test_dir/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.MAIN_SECRET]
provider = "plain"
value = "main-value"
EOF

	# Create local config that overrides and adds secrets
	cat >test_dir/fnox.local.toml <<EOF
[secrets.MAIN_SECRET]
provider = "plain"
value = "local-override"

[secrets.LOCAL_SECRET]
provider = "plain"
value = "local-only"
EOF

	cd test_dir

	# Both secrets should be loaded, with local override taking precedence
	run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$MAIN_SECRET \$LOCAL_SECRET"
	assert_success
	assert_output "local-override local-only"
}

@test "hook-env inherits provider from parent with local config override" {
	# Create directory structure
	mkdir -p parent/child

	# Create parent config with provider
	cat >parent/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.PARENT_SECRET]
provider = "plain"
value = "parent-value"
EOF

	# Create child main config
	cat >parent/child/fnox.toml <<EOF
[secrets.CHILD_SECRET]
provider = "plain"
value = "child-value"
EOF

	# Create child local config (inherits provider from parent)
	cat >parent/child/fnox.local.toml <<EOF
[secrets.LOCAL_SECRET]
provider = "plain"
value = "local-value"
EOF

	cd parent/child

	# All three secrets should be loaded
	run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$PARENT_SECRET \$CHILD_SECRET \$LOCAL_SECRET"
	assert_success
	assert_output "parent-value child-value local-value"
}
