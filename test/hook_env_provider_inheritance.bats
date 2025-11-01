#!/usr/bin/env bats
#
# Test hook-env with provider inheritance from parent configs
#

setup() {
    load 'test_helper/common_setup'
    _common_setup

    # Check if keychain tests are disabled via env var
    if [ -n "$SKIP_KEYCHAIN_TESTS" ]; then
        skip "Keychain tests disabled via SKIP_KEYCHAIN_TESTS env var"
    fi

    # Check if we're on macOS for keychain tests
    if [[ "$(uname)" != "Darwin" ]]; then
        skip "Keychain provider tests require macOS"
    fi

    # Check if keychain is accessible
    if ! security list-keychains >/dev/null 2>&1; then
        skip "macOS keychain not accessible (may be locked or unavailable in this environment)"
    fi

    # Try to verify keychain access by creating a test entry with timeout
    # Use timeout to prevent hanging in CI environments
    if ! timeout 5 security add-generic-password -s "fnox-test-access-check-$$" -a "test" -w "test" -U >/dev/null 2>&1; then
        skip "macOS keychain not accessible for write operations (may require GUI/interactive session)"
    fi

    # Clean up the test entry
    timeout 5 security delete-generic-password -s "fnox-test-access-check-$$" -a "test" >/dev/null 2>&1 || true

    # Set a unique service name for tests
    export KEYCHAIN_SERVICE="fnox-test-$$"
}

teardown() {
    # Clean up any test secrets from keychain
    if [ -n "$TEST_SECRET_KEYS" ]; then
        for key in $TEST_SECRET_KEYS; do
            security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$key" >/dev/null 2>&1 || true
        done
    fi

    _common_teardown
}

# Helper to track secret keys for cleanup
track_secret() {
    local key="$1"
    TEST_SECRET_KEYS="${TEST_SECRET_KEYS:-} $key"
}

@test "hook-env inherits keychain provider from parent config" {
    # Create directory structure
    mkdir -p parent/child

    # Create parent config with keychain provider
    cat > parent/fnox.toml <<EOF
[providers.keychain]
type = "keychain"
service = "$KEYCHAIN_SERVICE"

[secrets.PARENT_SECRET]
description = "Parent secret"
default = "parent-value"
EOF

    # Store a secret in the keychain for the child
    cd parent
    run "$FNOX_BIN" set CHILD_SECRET "child-keychain-value" --provider keychain
    assert_success
    track_secret "CHILD_SECRET"

    # Create child config that references keychain provider but doesn't define it
    cat > child/fnox.toml <<EOF
[secrets.CHILD_SECRET]
provider = "keychain"
value = "CHILD_SECRET"
description = "Child secret stored in keychain"
EOF

    # Change to child directory
    cd child

    # Test 1: fnox ls should work and show both secrets merged
    run "$FNOX_BIN" ls
    assert_success
    assert_output --partial "PARENT_SECRET"
    assert_output --partial "CHILD_SECRET"

    # Test 2: fnox get should work for child secret (inheriting parent provider)
    run "$FNOX_BIN" get CHILD_SECRET
    assert_success
    assert_output "child-keychain-value"

    # Test 3: fnox hook-env should load both secrets without error
    run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash)\" && echo \$CHILD_SECRET"
    assert_success
    assert_output "child-keychain-value"

    # Test 4: Verify no warning about provider not found
    run "$FNOX_BIN" hook-env -s bash
    assert_success
    refute_output --partial "Provider 'keychain' not found"
}

@test "hook-env with nested keychain provider inheritance (3 levels)" {
    # Create directory structure
    mkdir -p root/parent/child

    # Create root config with keychain provider
    cat > root/fnox.toml <<EOF
[providers.keychain]
type = "keychain"
service = "$KEYCHAIN_SERVICE"

[secrets.ROOT_SECRET]
description = "Root secret"
default = "root-value"
EOF

    # Store secrets in the keychain
    cd root
    run "$FNOX_BIN" set PARENT_SECRET "parent-keychain-value" --provider keychain
    assert_success
    track_secret "PARENT_SECRET"

    run "$FNOX_BIN" set CHILD_SECRET "child-keychain-value" --provider keychain
    assert_success
    track_secret "CHILD_SECRET"

    # Create parent config (no provider, just secrets)
    cat > parent/fnox.toml <<EOF
[secrets.PARENT_SECRET]
provider = "keychain"
value = "PARENT_SECRET"
description = "Parent secret"
EOF

    # Create child config (no provider, just secrets)
    cat > parent/child/fnox.toml <<EOF
[secrets.CHILD_SECRET]
provider = "keychain"
value = "CHILD_SECRET"
description = "Child secret"
EOF

    # Change to child directory (deepest level)
    cd parent/child

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
    assert_output "parent-keychain-value"

    run "$FNOX_BIN" get CHILD_SECRET
    assert_success
    assert_output "child-keychain-value"

    # Test 3: hook-env should load all secrets without error
    run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash)\" && echo \$CHILD_SECRET"
    assert_success
    assert_output "child-keychain-value"

    # Test 4: Verify no warnings
    run "$FNOX_BIN" hook-env -s bash
    assert_success
    refute_output --partial "Provider 'keychain' not found"
}
