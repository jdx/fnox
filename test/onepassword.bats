#!/usr/bin/env bats
#
# 1Password Provider Tests
#
# These tests verify the 1Password provider integration with fnox.
#
# Prerequisites:
#   1. Install 1Password CLI: brew install 1password-cli
#   2. Configure OP_SERVICE_ACCOUNT_TOKEN in fnox.toml (encrypted with age provider)
#   3. Create a vault named "fnox": op vault create fnox
#   4. Ensure the token has write permissions to the vault
#   5. Run tests: mise run test:bats -- test/onepassword.bats
#
# Note: Tests will automatically skip if:
#       - OP_SERVICE_ACCOUNT_TOKEN is not available
#       - The 'fnox' vault doesn't exist
#       - The token doesn't have write permissions
#
#       The mise task runs `fnox exec` which automatically decrypts provider-based secrets.
#       These tests create and delete temporary items in the "fnox" vault.
#       Tests should run serially (within this file) to avoid race conditions when
#       creating/deleting items. Use `--no-parallelize-within-files` bats flag.
#
# CI Setup:
#   Unlike Bitwarden (which can use a local vaultwarden server), 1Password requires
#   a real 1Password account and service account token. In CI environments without
#   proper 1Password setup, these tests will gracefully skip with informative messages.
#
#   To run these tests in CI:
#   1. Create a 1Password service account with access to a "fnox" vault
#   2. Store the token in GitHub Secrets as OP_SERVICE_ACCOUNT_TOKEN
#   3. Add to CI workflow: echo "${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}" | fnox set OP_SERVICE_ACCOUNT_TOKEN --provider age
#

setup() {
    load 'test_helper/common_setup'
    _common_setup

    # Check if op CLI is installed
    if ! command -v op >/dev/null 2>&1; then
        skip "1Password CLI (op) not installed. Install with: brew install 1password-cli"
    fi

    # Check if OP_SERVICE_ACCOUNT_TOKEN is available
    # (mise run test:bats automatically loads secrets via fnox exec)
    if [ -z "$OP_SERVICE_ACCOUNT_TOKEN" ]; then
        skip "OP_SERVICE_ACCOUNT_TOKEN not available. Ensure it's configured in fnox.toml or set in environment."
    fi

    # Verify we can authenticate with 1Password by trying to list vaults
    if ! op vault list >/dev/null 2>&1; then
        skip "Cannot authenticate with 1Password. Token may be invalid or expired."
    fi

    # Check if the 'fnox' vault exists
    if ! op vault get fnox >/dev/null 2>&1; then
        skip "The 'fnox' vault does not exist. Create it with: op vault create fnox"
    fi

    # Test if we have write permissions by creating and deleting a test item
    local test_item="fnox-permission-test-$$"
    if ! op item create --category=password --title="$test_item" --vault=fnox "password=test" >/dev/null 2>&1; then
        skip "Cannot create items in 'fnox' vault. Token may not have write permissions."
    fi
    op item delete "$test_item" --vault=fnox >/dev/null 2>&1 || true
}

teardown() {
    _common_teardown
}

# Helper function to create a 1Password test config
create_onepassword_config() {
    local vault="${1:-fnox}"
    cat > "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF
[providers.onepass]
type = "1password"
vault = "$vault"

[secrets]
EOF
}

# Helper function to create a test item in 1Password
# Returns the item name on success, empty string on failure
create_test_op_item() {
    local vault="${1:-fnox}"
    local item_name="fnox-test-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
    local password="test-secret-value-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"

    # Create item with op CLI and capture output
    if op item create \
        --category=password \
        --title="$item_name" \
        --vault="$vault" \
        "password=$password" >/dev/null 2>&1; then
        echo "$item_name"
        return 0
    else
        # Return empty string on failure
        return 1
    fi
}

# Helper function to delete a test item from 1Password
delete_test_op_item() {
    local vault="${1}"
    local item_name="${2}"
    op item delete "$item_name" --vault="$vault" >/dev/null 2>&1 || true
}

@test "fnox get retrieves secret from 1Password" {
    create_onepassword_config "fnox"

    # Create a test item
    if ! item_name=$(create_test_op_item "fnox"); then
        skip "Failed to create test item in 1Password"
    fi

    # Add secret reference to config
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_OP_SECRET]
provider = "onepass"
value = "$item_name"
EOF

    # Get the secret
    run "$FNOX_BIN" get TEST_OP_SECRET
    assert_success
    assert_output --partial "test-secret-value-"

    # Cleanup
    delete_test_op_item "fnox" "$item_name"
}

@test "fnox get retrieves specific field from 1Password item" {
    create_onepassword_config "fnox"

    # Create a test item with custom field
    item_name="fnox-test-field-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
    if ! op item create \
        --category=password \
        --title="$item_name" \
        --vault="fnox" \
        "username=testuser" \
        "password=testpass" >/dev/null 2>&1; then
        skip "Failed to create test item in 1Password"
    fi

    # Add secret reference to config (fetch username field)
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_USERNAME]
provider = "onepass"
value = "$item_name/username"
EOF

    # Get the secret
    run "$FNOX_BIN" get TEST_USERNAME
    assert_success
    assert_output "testuser"

    # Cleanup
    delete_test_op_item "fnox" "$item_name"
}

@test "fnox get handles full op:// reference" {
    create_onepassword_config "fnox"

    # Create a test item
    if ! item_name=$(create_test_op_item "fnox"); then
        skip "Failed to create test item in 1Password"
    fi

    # Add secret reference to config using full op:// format
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_OP_FULL_REF]
provider = "onepass"
value = "op://fnox/$item_name/password"
EOF

    # Get the secret
    run "$FNOX_BIN" get TEST_OP_FULL_REF
    assert_success
    assert_output --partial "test-secret-value-"

    # Cleanup
    delete_test_op_item "fnox" "$item_name"
}

@test "fnox get fails with invalid item name" {
    create_onepassword_config "fnox"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.INVALID_ITEM]
provider = "onepass"
value = "nonexistent-item-$(date +%s)"
EOF

    # Try to get non-existent secret
    run "$FNOX_BIN" get INVALID_ITEM
    assert_failure
    assert_output --partial "1Password CLI command failed"
}

@test "fnox get fails with invalid vault" {
    create_onepassword_config "nonexistent-vault-$(date +%s)"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_SECRET]
provider = "onepass"
value = "some-item"
EOF

    # Try to get secret from non-existent vault
    run "$FNOX_BIN" get TEST_SECRET
    assert_failure
}

@test "fnox get with 1Password account parameter" {
    skip "Requires 1Password account configuration"

    # Create config with account parameter
    cat > "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF
[providers.onepass]
type = "1password"
vault = "fnox"
account = "my.1password.com"

[secrets.TEST_SECRET]
provider = "onepass"
value = "test-item"
EOF

    # This should pass account flag to op CLI
    run "$FNOX_BIN" get TEST_SECRET
    # Will fail if account doesn't exist, but that's expected
    assert_failure
}

@test "fnox list shows 1Password secrets" {
    create_onepassword_config "fnox"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.OP_SECRET_1]
description = "First 1Password secret"
provider = "onepass"
value = "item1"

[secrets.OP_SECRET_2]
description = "Second 1Password secret"
provider = "onepass"
value = "item2/username"
EOF

    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "OP_SECRET_1"
    assert_output --partial "OP_SECRET_2"
    assert_output --partial "First 1Password secret"
}

@test "fnox get handles invalid secret reference format" {
    create_onepassword_config "fnox"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.INVALID_FORMAT]
provider = "onepass"
value = "invalid/format/with/too/many/slashes"
EOF

    run "$FNOX_BIN" get INVALID_FORMAT
    assert_failure
    assert_output --partial "Invalid secret reference format"
}

@test "1Password provider works with service account token from environment" {
    # This test verifies that op CLI uses OP_SERVICE_ACCOUNT_TOKEN from environment
    # The token should be set by setup() from fnox config

    create_onepassword_config "fnox"
    if ! item_name=$(create_test_op_item "fnox"); then
        skip "Failed to create test item in 1Password"
    fi

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_WITH_ENV_TOKEN]
provider = "onepass"
value = "$item_name"
EOF

    # The OP_SERVICE_ACCOUNT_TOKEN should be set by setup()

    run "$FNOX_BIN" get TEST_WITH_ENV_TOKEN
    assert_success
    assert_output --partial "test-secret-value-"

    # Cleanup
    delete_test_op_item "fnox" "$item_name"
}
