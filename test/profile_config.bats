#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test 'fnox.$FNOX_PROFILE.toml overrides fnox.toml secrets' {
	# Create main config
	cat >fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
SHARED_SECRET = { description = "Main config secret", default = "main-value" }
MAIN_ONLY_SECRET = { description = "Main only secret", default = "main-only-value" }
EOF

	# Create production profile config that overrides SHARED_SECRET
	# Note: This works with the default profile but loads when FNOX_PROFILE=production
	cat >fnox.production.toml <<EOF
[secrets]
SHARED_SECRET = { description = "Production override", default = "prod-value" }
PROD_ONLY_SECRET = { description = "Production only secret", default = "prod-only-value" }
EOF

	# Test with default profile (no FNOX_PROFILE) - should use main config values
	run "$FNOX_BIN" get SHARED_SECRET
	assert_success
	assert_output --partial "main-value"

	# Test with production profile env var - should use production config values
	# This still uses the "default" profile's secrets, but loads fnox.production.toml
	run env FNOX_PROFILE=production "$FNOX_BIN" get SHARED_SECRET
	assert_success
	assert_output --partial "prod-value"

	# Test that main-only secret is still accessible with production env
	run env FNOX_PROFILE=production "$FNOX_BIN" get MAIN_ONLY_SECRET
	assert_success
	assert_output --partial "main-only-value"

	# Test that production-only secret is accessible
	run env FNOX_PROFILE=production "$FNOX_BIN" get PROD_ONLY_SECRET
	assert_success
	assert_output --partial "prod-only-value"
}

@test 'fnox.$FNOX_PROFILE.toml loading order: fnox.toml < fnox.$FNOX_PROFILE.toml < fnox.local.toml' {
	# Create main config
	cat >fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
SECRET_A = { description = "Secret A", default = "main-a" }
SECRET_B = { description = "Secret B", default = "main-b" }
SECRET_C = { description = "Secret C", default = "main-c" }
EOF

	# Create staging profile config
	cat >fnox.staging.toml <<EOF
[secrets]
SECRET_B = { description = "Secret B staging", default = "staging-b" }
SECRET_C = { description = "Secret C staging", default = "staging-c" }
EOF

	# Create local config (highest priority)
	cat >fnox.local.toml <<EOF
[secrets]
SECRET_C = { description = "Secret C local", default = "local-c" }
EOF

	# Test with staging profile
	# SECRET_A should come from fnox.toml (main-a)
	run env FNOX_PROFILE=staging "$FNOX_BIN" get SECRET_A
	assert_success
	assert_output --partial "main-a"

	# SECRET_B should come from fnox.staging.toml (staging-b)
	run env FNOX_PROFILE=staging "$FNOX_BIN" get SECRET_B
	assert_success
	assert_output --partial "staging-b"

	# SECRET_C should come from fnox.local.toml (local-c) - highest priority
	run env FNOX_PROFILE=staging "$FNOX_BIN" get SECRET_C
	assert_success
	assert_output --partial "local-c"
}

@test 'fnox.$FNOX_PROFILE.toml works with FNOX_PROFILE env var' {
	# Create main config
	cat >fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MY_SECRET = { description = "My secret", default = "main-value" }
EOF

	# Create dev profile config
	cat >fnox.dev.toml <<EOF
[secrets]
MY_SECRET = { description = "Dev secret", default = "dev-value" }
EOF

	# Test with FNOX_PROFILE env var (should load fnox.dev.toml)
	run env FNOX_PROFILE=dev "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output --partial "dev-value"

	# Test without FNOX_PROFILE (should use main config only)
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output --partial "main-value"
}

@test 'fnox.$FNOX_PROFILE.toml works with config recursion' {
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

	# Create parent production profile config
	cat >parent/fnox.production.toml <<EOF
[secrets]
PARENT_SECRET = { description = "Parent production override", default = "parent-prod-value" }
PARENT_PROD_SECRET = { description = "Parent prod secret", default = "parent-prod-only" }
EOF

	# Create child config
	cat >parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-value" }
EOF

	# Create child production profile config
	cat >parent/child/fnox.production.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child production override", default = "child-prod-value" }
CHILD_PROD_SECRET = { description = "Child prod secret", default = "child-prod-only" }
EOF

	# Change to child directory
	cd parent/child

	# Test default profile - child overrides parent
	run "$FNOX_BIN" get CHILD_SECRET
	assert_success
	assert_output --partial "child-value"

	run "$FNOX_BIN" get PARENT_SECRET
	assert_success
	assert_output --partial "parent-value"

	# Test production profile - child production overrides parent production
	run env FNOX_PROFILE=production "$FNOX_BIN" get CHILD_SECRET
	assert_success
	assert_output --partial "child-prod-value"

	# Parent secret should use parent production value
	run env FNOX_PROFILE=production "$FNOX_BIN" get PARENT_SECRET
	assert_success
	assert_output --partial "parent-prod-value"

	# Production-only secrets should be accessible
	run env FNOX_PROFILE=production "$FNOX_BIN" get CHILD_PROD_SECRET
	assert_success
	assert_output --partial "child-prod-only"

	run env FNOX_PROFILE=production "$FNOX_BIN" get PARENT_PROD_SECRET
	assert_success
	assert_output --partial "parent-prod-only"
}

@test 'fnox.$FNOX_PROFILE.toml can add new providers' {
	# Create main config with one provider
	cat >fnox.toml <<EOF
root = true

[providers.main_provider]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { provider = "main_provider", default = "main-value" }
EOF

	# Create ci profile config with additional provider
	cat >fnox.ci.toml <<EOF
[providers.ci_provider]
type = "age"
recipients = ["age1citest"]

[secrets]
CI_SECRET = { provider = "ci_provider", default = "ci-value" }
EOF

	# Test default profile - only main provider accessible
	run "$FNOX_BIN" get MAIN_SECRET
	assert_success
	assert_output --partial "main-value"

	# Test ci profile - both providers accessible
	run env FNOX_PROFILE=ci "$FNOX_BIN" get MAIN_SECRET
	assert_success
	assert_output --partial "main-value"

	run env FNOX_PROFILE=ci "$FNOX_BIN" get CI_SECRET
	assert_success
	assert_output --partial "ci-value"

	# CI secret should not be accessible in default profile
	run "$FNOX_BIN" get CI_SECRET
	assert_failure
}

@test 'fnox.$FNOX_PROFILE.toml is not loaded for default profile' {
	# Create main config
	cat >fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MY_SECRET = { description = "My secret", default = "main-value" }
EOF

	# Create default profile config (should be ignored)
	cat >fnox.default.toml <<EOF
[secrets]
MY_SECRET = { description = "Default override", default = "default-value" }
EOF

	# Test with default profile - should NOT use fnox.default.toml
	run "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output --partial "main-value"

	run env FNOX_PROFILE=default "$FNOX_BIN" get MY_SECRET
	assert_success
	assert_output --partial "main-value"
}

@test 'fnox list shows secrets from fnox.$FNOX_PROFILE.toml' {
	# Create main config
	cat >fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { description = "Main config secret", default = "main-value" }
SHARED_SECRET = { description = "Shared secret", default = "main-value" }
EOF

	# Create testing profile config (renamed from 'test' to 'testing' to avoid confusion)
	cat >fnox.testing.toml <<EOF
[secrets]
TESTING_SECRET = { description = "Testing config secret", default = "testing-value" }
SHARED_SECRET = { description = "Testing override", default = "testing-value" }
EOF

	# Test list without FNOX_PROFILE
	run "$FNOX_BIN" list --complete
	assert_success
	assert_output --partial "MAIN_SECRET"
	assert_output --partial "SHARED_SECRET"
	# Should NOT show TESTING_SECRET without FNOX_PROFILE
	refute_output --partial "TESTING_SECRET"

	# Test list with FNOX_PROFILE=testing
	run env FNOX_PROFILE=testing "$FNOX_BIN" list --complete
	assert_success
	assert_output --partial "MAIN_SECRET"
	assert_output --partial "TESTING_SECRET"
	assert_output --partial "SHARED_SECRET"
}

@test 'explicit config path ignores fnox.$FNOX_PROFILE.toml' {
	# Create main config
	cat >fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { description = "Main secret", default = "main-value" }
EOF

	# Create production profile config
	cat >fnox.production.toml <<EOF
[secrets]
PROD_SECRET = { description = "Production secret", default = "prod-value" }
MAIN_SECRET = { description = "Production override", default = "prod-override" }
EOF

	# Using explicit path should only load that specific file
	# (bypasses profile-specific config loading)
	run env FNOX_PROFILE=production "$FNOX_BIN" -c ./fnox.toml get MAIN_SECRET
	assert_success
	assert_output --partial "main-value"

	# Production secret should not be accessible with explicit path
	run env FNOX_PROFILE=production "$FNOX_BIN" -c ./fnox.toml get PROD_SECRET
	assert_failure
	assert_output --partial "not found"
}

@test 'fnox.$FNOX_PROFILE.toml can override default_provider' {
	# Create main config with default provider
	cat >fnox.toml <<EOF
root = true
default_provider = "main_provider"

[providers.main_provider]
type = "age"
recipients = ["age1maintest"]

[providers.alt_provider]
type = "age"
recipients = ["age1alttest"]
EOF

	# Create profile config that changes default provider
	cat >fnox.prod.toml <<EOF
default_provider = "alt_provider"
EOF

	# Set a secret with default profile (should use main_provider)
	run "$FNOX_BIN" set TEST_SECRET_DEFAULT "test-value"
	assert_success

	# Set a secret with prod profile (should use alt_provider)
	run env FNOX_PROFILE=prod "$FNOX_BIN" set TEST_SECRET_PROD "test-value"
	assert_success

	# Check the configs
	run cat fnox.toml
	assert_success
	assert_output --partial 'TEST_SECRET_DEFAULT'
}
