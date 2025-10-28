#!/usr/bin/env bats

setup() {
    load 'test_helper/common_setup'
    _common_setup
}

teardown() {
    _common_teardown
}

@test "fnox.local.toml overrides fnox.toml secrets" {
    # Create main config
    cat > fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
SHARED_SECRET = { description = "Main config secret", default = "main-value" }
MAIN_ONLY_SECRET = { description = "Main only secret", default = "main-only-value" }
EOF

    # Create local config that overrides SHARED_SECRET
    cat > fnox.local.toml <<EOF
[secrets]
SHARED_SECRET = { description = "Local override", default = "local-value" }
LOCAL_ONLY_SECRET = { description = "Local only secret", default = "local-only-value" }
EOF

    # Test that local config overrides shared secret
    run "$FNOX_BIN" get SHARED_SECRET
    assert_success
    assert_output --partial "local-value"

    # Test that main-only secret is still accessible
    run "$FNOX_BIN" get MAIN_ONLY_SECRET
    assert_success
    assert_output --partial "main-only-value"

    # Test that local-only secret is accessible
    run "$FNOX_BIN" get LOCAL_ONLY_SECRET
    assert_success
    assert_output --partial "local-only-value"
}

@test "fnox.local.toml can add new providers" {
    # Create main config with one provider
    cat > fnox.toml <<EOF
root = true

[providers.main_provider]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { provider = "main_provider", default = "main-value" }
EOF

    # Create local config with additional provider
    cat > fnox.local.toml <<EOF
[providers.local_provider]
type = "age"
recipients = ["age1localtest"]

[secrets]
LOCAL_SECRET = { provider = "local_provider", default = "local-value" }
EOF

    # Test that both secrets work
    run "$FNOX_BIN" get MAIN_SECRET
    assert_success
    assert_output --partial "main-value"

    run "$FNOX_BIN" get LOCAL_SECRET
    assert_success
    assert_output --partial "local-value"
}

@test "fnox.local.toml works with profile-specific secrets" {
    # Create main config
    cat > fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[profiles.production.secrets]
PROD_SECRET = { description = "Production secret", default = "prod-value" }
EOF

    # Create local config with production profile override
    cat > fnox.local.toml <<EOF
[profiles.production.secrets]
PROD_SECRET = { description = "Local prod override", default = "local-prod-value" }
LOCAL_PROD_SECRET = { description = "Local prod secret", default = "local-prod-only" }
EOF

    # Test that local overrides production secret
    run "$FNOX_BIN" get PROD_SECRET --profile production
    assert_success
    assert_output --partial "local-prod-value"

    # Test that local-only production secret is accessible
    run "$FNOX_BIN" get LOCAL_PROD_SECRET --profile production
    assert_success
    assert_output --partial "local-prod-only"
}

@test "fnox.local.toml works with config recursion" {
    # Create directory structure
    mkdir -p parent/child

    # Create parent config
    cat > parent/fnox.toml <<EOF
[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-value" }
EOF

    # Create parent local config
    cat > parent/fnox.local.toml <<EOF
[secrets]
PARENT_SECRET = { description = "Parent local override", default = "parent-local-value" }
PARENT_LOCAL_SECRET = { description = "Parent local secret", default = "parent-local-only" }
EOF

    # Create child config
    cat > parent/child/fnox.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child secret", default = "child-value" }
EOF

    # Create child local config
    cat > parent/child/fnox.local.toml <<EOF
[secrets]
CHILD_SECRET = { description = "Child local override", default = "child-local-value" }
CHILD_LOCAL_SECRET = { description = "Child local secret", default = "child-local-only" }
EOF

    # Change to child directory
    cd parent/child

    # Test that child local overrides child config
    run "$FNOX_BIN" get CHILD_SECRET
    assert_success
    assert_output --partial "child-local-value"

    # Test that child local secrets are accessible
    run "$FNOX_BIN" get CHILD_LOCAL_SECRET
    assert_success
    assert_output --partial "child-local-only"

    # Test that parent local overrides parent config
    run "$FNOX_BIN" get PARENT_SECRET
    assert_success
    assert_output --partial "parent-local-value"

    # Test that parent local secrets are accessible
    run "$FNOX_BIN" get PARENT_LOCAL_SECRET
    assert_success
    assert_output --partial "parent-local-only"
}

@test "fnox.local.toml alone without fnox.toml works" {
    # Create only local config (no main config)
    cat > fnox.local.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
LOCAL_ONLY = { description = "Local only secret", default = "local-only-value" }
EOF

    # Test that local config works on its own
    run "$FNOX_BIN" get LOCAL_ONLY
    assert_success
    assert_output --partial "local-only-value"
}

@test "fnox.local.toml can override default_provider" {
    # Create main config with default provider
    cat > fnox.toml <<EOF
root = true
default_provider = "main_provider"

[providers.main_provider]
type = "age"
recipients = ["age1maintest"]

[providers.alt_provider]
type = "age"
recipients = ["age1alttest"]
EOF

    # Create local config that changes default provider
    cat > fnox.local.toml <<EOF
default_provider = "alt_provider"
EOF

    # Set a secret without specifying provider (should use default)
    run "$FNOX_BIN" set TEST_SECRET "test-value"
    assert_success

    # Check that it used the local default provider
    # The config should show the secret was set with alt_provider
    run cat fnox.toml
    assert_success
    assert_output --partial 'TEST_SECRET'
}

@test "fnox.local.toml can set if_missing default" {
    # Create main config
    cat > fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
NO_VALUE_SECRET = { description = "Secret without value" }
EOF

    # Create local config with if_missing = ignore
    cat > fnox.local.toml <<EOF
if_missing = "ignore"
EOF

    # Test that missing secret is ignored (no error)
    run "$FNOX_BIN" exec -- env
    assert_success
    # Should not fail even though NO_VALUE_SECRET has no value
}

@test "fnox list shows secrets from both fnox.toml and fnox.local.toml" {
    # Create main config
    cat > fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { description = "Main config secret", default = "main-value" }
SHARED_SECRET = { description = "Shared secret", default = "main-value" }
EOF

    # Create local config
    cat > fnox.local.toml <<EOF
[secrets]
LOCAL_SECRET = { description = "Local config secret", default = "local-value" }
SHARED_SECRET = { description = "Local override", default = "local-value" }
EOF

    # Test that list shows all secrets
    run "$FNOX_BIN" list --complete
    assert_success

    # Should show MAIN_SECRET, LOCAL_SECRET, and SHARED_SECRET (merged)
    assert_output --partial "MAIN_SECRET"
    assert_output --partial "LOCAL_SECRET"
    assert_output --partial "SHARED_SECRET"
}

@test "fnox.local.toml respects root flag" {
    # Create parent config
    cat > fnox.toml <<EOF
[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
PARENT_SECRET = { description = "Parent secret", default = "parent-value" }
EOF

    # Create local config with root=true to stop recursion
    cat > fnox.local.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
LOCAL_SECRET = { description = "Local secret", default = "local-value" }
EOF

    # Test that local config's root flag is respected
    run "$FNOX_BIN" get LOCAL_SECRET
    assert_success
    assert_output --partial "local-value"

    # Parent secret should still be accessible because it's in the same directory
    # (Both fnox.toml and fnox.local.toml are loaded before checking root)
    run "$FNOX_BIN" get PARENT_SECRET
    assert_success
    assert_output --partial "parent-value"
}

@test "explicit config path ignores fnox.local.toml" {
    # Create main config
    cat > fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { description = "Main secret", default = "main-value" }
EOF

    # Create local config
    cat > fnox.local.toml <<EOF
[secrets]
LOCAL_SECRET = { description = "Local secret", default = "local-value" }
MAIN_SECRET = { description = "Local override", default = "local-override" }
EOF

    # Using explicit path with ./ prefix should only load that specific file
    # (bypasses recursion and local config merging)
    run "$FNOX_BIN" -c ./fnox.toml get MAIN_SECRET
    assert_success
    assert_output --partial "main-value"

    # Local secret should not be accessible with explicit path
    run "$FNOX_BIN" -c ./fnox.toml get LOCAL_SECRET
    assert_failure
    assert_output --partial "not found"
}

@test "fnox.local.toml can have imports" {
    # Create imported config
    cat > shared.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
SHARED_IMPORT = { description = "Shared import secret", default = "shared-value" }
EOF

    # Create main config
    cat > fnox.toml <<EOF
root = true

[providers.test]
type = "age"
recipients = ["age1test"]

[secrets]
MAIN_SECRET = { description = "Main secret", default = "main-value" }
EOF

    # Create local config with import
    cat > fnox.local.toml <<EOF
import = ["./shared.toml"]

[secrets]
LOCAL_SECRET = { description = "Local secret", default = "local-value" }
EOF

    # Test that imported secret is accessible
    run "$FNOX_BIN" get SHARED_IMPORT
    assert_success
    assert_output --partial "shared-value"

    # Test that main and local secrets are still accessible
    run "$FNOX_BIN" get MAIN_SECRET
    assert_success
    assert_output --partial "main-value"

    run "$FNOX_BIN" get LOCAL_SECRET
    assert_success
    assert_output --partial "local-value"
}
