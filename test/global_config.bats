#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "global config is loaded as base" {
	# Create global config directory and file
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[providers.global]
type = "age"
recipients = ["age1global"]

[secrets]
GLOBAL_SECRET = { description = "Global secret", default = "global-value" }
AWS_ACCESS_KEY_ID = { description = "AWS access key", default = "global-aws-key" }
EOF

	# Create project config (no root flag, so will use global config)
	cat >fnox.toml <<EOF
root = true

[secrets]
PROJECT_SECRET = { description = "Project secret", default = "project-value" }
EOF

	# Test that global secret is accessible
	run "$FNOX_BIN" get GLOBAL_SECRET
	assert_success
	assert_output --partial "global-value"

	# Test that project secret is accessible
	run "$FNOX_BIN" get PROJECT_SECRET
	assert_success
	assert_output --partial "project-value"
}

@test "project config overrides global config" {
	# Create global config
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[providers.shared]
type = "age"
recipients = ["age1global"]

[secrets]
SHARED_SECRET = { description = "Global version", default = "global-value" }
GLOBAL_ONLY = { description = "Global only secret", default = "global-only-value" }
EOF

	# Create project config that overrides the shared secret
	cat >fnox.toml <<EOF
root = true

[secrets]
SHARED_SECRET = { description = "Project version", default = "project-override" }
PROJECT_ONLY = { description = "Project only secret", default = "project-only-value" }
EOF

	# Test that project config overrides global
	run "$FNOX_BIN" get SHARED_SECRET
	assert_success
	assert_output --partial "project-override"

	# Test that global-only secret is still accessible
	run "$FNOX_BIN" get GLOBAL_ONLY
	assert_success
	assert_output --partial "global-only-value"

	# Test that project-only secret is accessible
	run "$FNOX_BIN" get PROJECT_ONLY
	assert_success
	assert_output --partial "project-only-value"
}

@test "global config with profiles" {
	# Create global config with profiles
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[providers.global]
type = "age"
recipients = ["age1global"]

[secrets]
API_KEY = { description = "Default API key", default = "global-default-key" }

[profiles.production.secrets]
API_KEY = { description = "Production API key", default = "global-prod-key" }
EOF

	# Create project config (minimal, uses global config)
	cat >fnox.toml <<EOF
root = true

[secrets]
PROJECT_SECRET = { description = "Project secret", default = "project-value" }
EOF

	# Test default profile uses global default
	run "$FNOX_BIN" get API_KEY
	assert_success
	assert_output --partial "global-default-key"

	# Test production profile uses global production secret
	run "$FNOX_BIN" get API_KEY --profile production
	assert_success
	assert_output --partial "global-prod-key"
}

@test "global config providers are available to project secrets" {
	# Create global config with a provider
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[providers.global-age]
type = "age"
recipients = ["age1test"]
EOF

	# Create project config that uses global provider
	cat >fnox.toml <<EOF
root = true

[secrets]
MY_SECRET = { provider = "global-age", default = "fallback-value" }
EOF

	# Test that global provider is recognized (will use default since no age key)
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output --partial "fallback-value"
}

@test "project provider overrides global provider" {
	# Create global config with a provider
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[providers.shared]
type = "age"
recipients = ["age1global"]

[secrets]
TEST_SECRET = { description = "Test secret", default = "global-value" }
EOF

	# Create project config that overrides the provider
	cat >fnox.toml <<EOF
root = true

[providers.shared]
type = "age"
recipients = ["age1project"]

[secrets]
TEST_SECRET = { description = "Test secret", default = "project-value" }
EOF

	# Test that project secret value is used
	run "$FNOX_BIN" get TEST_SECRET
	assert_success
	assert_output --partial "project-value"
}

@test "config recursion includes global config" {
	# Create directory structure
	mkdir -p parent/child

	# Create global config
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[providers.global]
type = "age"
recipients = ["age1global"]

[secrets]
GLOBAL_SECRET = { description = "Global secret", default = "global-value" }
EOF

	# Create parent config (no root, so recursion continues)
	cat >parent/fnox.toml <<EOF
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

	# Test that all secrets are accessible
	run "$FNOX_BIN" get GLOBAL_SECRET
	assert_success
	assert_output --partial "global-value"

	run "$FNOX_BIN" get PARENT_SECRET
	assert_success
	assert_output --partial "parent-value"

	run "$FNOX_BIN" get CHILD_SECRET
	assert_success
	assert_output --partial "child-value"
}

@test "root=true stops recursion but still loads global config" {
	# Create directory structure
	mkdir -p parent/child

	# Create global config
	mkdir -p "$HOME/.config/fnox"
	cat >"$HOME/.config/fnox/config.toml" <<EOF
[providers.global]
type = "age"
recipients = ["age1global"]

[secrets]
GLOBAL_SECRET = { description = "Global secret", default = "global-value" }
EOF

	# Create parent config above child's root
	cat >parent/fnox.toml <<EOF
[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-value" }
EOF

	# Create child config with root=true
	cat >parent/child/fnox.toml <<EOF
root = true

[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-value" }
EOF

	# Change to child directory
	cd parent/child

	# Test that global secret is still accessible (root doesn't block global)
	run "$FNOX_BIN" get GLOBAL_SECRET
	assert_success
	assert_output --partial "global-value"

	# Test that child secret is accessible
	run "$FNOX_BIN" get CHILD_SECRET
	assert_success
	assert_output --partial "child-value"

	# Test that parent secret is NOT accessible (root blocks parent recursion)
	run "$FNOX_BIN" get PARENT_SECRET
	assert_failure
	assert_output --partial "not found"
}

@test "no global config works fine" {
	# Don't create any global config
	# Create project config
	cat >fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
PROJECT_SECRET = { description = "Project secret", default = "project-value" }
EOF

	# Test that project secret is accessible
	run "$FNOX_BIN" get PROJECT_SECRET
	assert_success
	assert_output --partial "project-value"
}

@test "FNOX_CONFIG_DIR can override global config location" {
	# Create custom config directory
	mkdir -p "$TEST_TEMP_DIR/custom-config"
	cat >"$TEST_TEMP_DIR/custom-config/config.toml" <<EOF
[providers.custom]
type = "age"
recipients = ["age1custom"]

[secrets]
CUSTOM_SECRET = { description = "Custom secret", default = "custom-value" }
EOF

	# Create project config
	cat >fnox.toml <<EOF
root = true

[secrets]
PROJECT_SECRET = { description = "Project secret", default = "project-value" }
EOF

	# Set custom config dir
	export FNOX_CONFIG_DIR="$TEST_TEMP_DIR/custom-config"

	# Test that custom global config is loaded
	run "$FNOX_BIN" get CUSTOM_SECRET
	assert_success
	assert_output --partial "custom-value"

	# Test that project secret is accessible
	run "$FNOX_BIN" get PROJECT_SECRET
	assert_success
	assert_output --partial "project-value"
}
