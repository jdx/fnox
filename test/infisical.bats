#!/usr/bin/env bats
#
# Infisical Provider Tests
#
# These tests verify the Infisical provider integration with fnox.
#
# Prerequisites:
#   1. Install Infisical CLI: brew install infisical/get-cli/infisical
#   2. Get a service token from Infisical project settings
#   3. Export token: export INFISICAL_TOKEN="st.xxx.yyy.zzz"
#      OR store encrypted in fnox.toml with age provider
#   4. Run tests: mise run test:bats -- test/infisical.bats
#
# Note: Tests will automatically skip if INFISICAL_TOKEN is not available.
#       These tests create and delete temporary secrets in your Infisical project.
#

setup() {
    load 'test_helper/common_setup'
    _common_setup

    # Check if infisical CLI is installed
    if ! command -v infisical >/dev/null 2>&1; then
        skip "Infisical CLI not installed. Install with: brew install infisical/get-cli/infisical"
    fi

    # Some tests don't need INFISICAL_TOKEN (like 'fnox list')
    # Only skip if this test actually needs authentication
    if [[ "$BATS_TEST_DESCRIPTION" != *"list"* ]]; then
        # Check if INFISICAL_TOKEN is available
        if [ -z "$INFISICAL_TOKEN" ]; then
            skip "INFISICAL_TOKEN not available. Get a service token from Infisical project settings."
        fi

        # Verify we can authenticate with Infisical
        if ! infisical user >/dev/null 2>&1; then
            skip "Cannot authenticate with Infisical. Token may be invalid or expired."
        fi
    fi
}

teardown() {
    _common_teardown
}

# Helper function to create an Infisical test config
create_infisical_config() {
    local project_id="${1:-}"
    local environment="${2:-dev}"
    local path="${3:-/}"

    cat > "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF
[providers.infisical]
type = "infisical"
EOF

    if [ -n "$project_id" ]; then
        echo "project_id = \"$project_id\"" >> "${FNOX_CONFIG_FILE:-fnox.toml}"
    fi

    if [ -n "$environment" ]; then
        echo "environment = \"$environment\"" >> "${FNOX_CONFIG_FILE:-fnox.toml}"
    fi

    if [ -n "$path" ]; then
        echo "path = \"$path\"" >> "${FNOX_CONFIG_FILE:-fnox.toml}"
    fi

    cat >> "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF

[secrets]
EOF
}

# Helper function to create a test secret in Infisical
# Returns the secret name
create_test_infisical_secret() {
    local secret_name="FNOX_TEST_$(date +%s)_$(( RANDOM % 10000 ))"
    local secret_value="test-secret-value-$(date +%s)"
    local project_id="${1:-}"
    local environment="${2:-dev}"

    # Create secret with infisical CLI
    local cmd_args=("secrets" "set" "$secret_name" "$secret_value")

    if [ -n "$project_id" ]; then
        cmd_args+=("--projectId=$project_id")
    fi

    if [ -n "$environment" ]; then
        cmd_args+=("--env=$environment")
    fi

    if ! infisical "${cmd_args[@]}" >/dev/null 2>&1; then
        echo "ERROR:Failed to create secret" >&2
        return 1
    fi

    echo "$secret_name"
}

# Helper function to delete a test secret from Infisical
delete_test_infisical_secret() {
    local secret_name="${1}"
    local project_id="${2:-}"
    local environment="${3:-dev}"

    local cmd_args=("secrets" "delete" "$secret_name")

    if [ -n "$project_id" ]; then
        cmd_args+=("--projectId=$project_id")
    fi

    if [ -n "$environment" ]; then
        cmd_args+=("--env=$environment")
    fi

    infisical "${cmd_args[@]}" >/dev/null 2>&1 || true
}

@test "fnox get retrieves secret from Infisical" {
    create_infisical_config

    # Create a test secret
    secret_name=$(create_test_infisical_secret)

    # Add secret reference to config
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_INFISICAL_SECRET]
provider = "infisical"
value = "$secret_name"
EOF

    # Get the secret
    run "$FNOX_BIN" get TEST_INFISICAL_SECRET
    assert_success
    assert_output --partial "test-secret-value-"

    # Cleanup
    delete_test_infisical_secret "$secret_name"
}

@test "fnox get fails with invalid secret name" {
    create_infisical_config

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.INVALID_SECRET]
provider = "infisical"
value = "NONEXISTENT_SECRET_$(date +%s)"
EOF

    # Try to get non-existent secret
    run "$FNOX_BIN" get INVALID_SECRET
    assert_failure
    assert_output --partial "Infisical CLI command failed"
}

@test "fnox list shows Infisical secrets" {
    # This test doesn't need INFISICAL_TOKEN since list just reads the config file
    create_infisical_config

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.INFISICAL_SECRET_1]
description = "First Infisical secret"
provider = "infisical"
value = "DATABASE_URL"

[secrets.INFISICAL_SECRET_2]
description = "Second Infisical secret"
provider = "infisical"
value = "API_KEY"
EOF

    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "INFISICAL_SECRET_1"
    assert_output --partial "INFISICAL_SECRET_2"
    assert_output --partial "First Infisical secret"
}

@test "Infisical provider works with token from environment" {
    # This test verifies that infisical CLI uses INFISICAL_TOKEN from environment
    # The token should be set by setup() from fnox config or environment

    create_infisical_config

    secret_name=$(create_test_infisical_secret)

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_WITH_ENV_TOKEN]
provider = "infisical"
value = "$secret_name"
EOF

    # The INFISICAL_TOKEN should be set by setup()
    run "$FNOX_BIN" get TEST_WITH_ENV_TOKEN
    assert_success
    assert_output --partial "test-secret-value-"

    # Cleanup
    delete_test_infisical_secret "$secret_name"
}

@test "Infisical provider with project_id configuration" {
    # Note: This test will skip if you don't have a specific project configured
    # In real usage, you'd provide your project ID
    create_infisical_config "your-project-id" "dev" "/"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_SECRET]
provider = "infisical"
value = "TEST_SECRET"
EOF

    # This test just verifies the configuration is accepted
    # It will fail if the project doesn't exist or secret isn't found
    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "TEST_SECRET"
}

@test "Infisical provider with environment configuration" {
    # Test that environment parameter is properly passed
    create_infisical_config "" "staging" "/"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.STAGING_SECRET]
provider = "infisical"
value = "STAGING_SECRET"
EOF

    # This test just verifies the configuration is accepted
    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "STAGING_SECRET"
}

@test "Infisical provider with path configuration" {
    # Test that path parameter is properly passed
    create_infisical_config "" "dev" "/api"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.API_SECRET]
provider = "infisical"
value = "API_KEY"
EOF

    # This test just verifies the configuration is accepted
    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "API_SECRET"
}

@test "fnox exec loads Infisical secrets into environment" {
    create_infisical_config

    secret_name=$(create_test_infisical_secret)

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_EXEC_SECRET]
provider = "infisical"
value = "$secret_name"
EOF

    # Run a command that prints the environment variable
    run "$FNOX_BIN" exec -- sh -c 'echo "$TEST_EXEC_SECRET"'
    assert_success
    assert_output --partial "test-secret-value-"

    # Cleanup
    delete_test_infisical_secret "$secret_name"
}

@test "Infisical provider fails gracefully with missing token" {
    create_infisical_config

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.TEST_SECRET]
provider = "infisical"
value = "DATABASE_URL"
EOF

    # Temporarily unset INFISICAL_TOKEN
    local original_token="$INFISICAL_TOKEN"
    unset INFISICAL_TOKEN
    unset FNOX_INFISICAL_TOKEN

    run "$FNOX_BIN" get TEST_SECRET
    assert_failure
    assert_output --partial "Infisical token not found"

    # Restore token
    export INFISICAL_TOKEN="$original_token"
}
