#!/usr/bin/env bats
#
# GCP Secret Manager Provider Tests
#
# These tests verify the GCP Secret Manager provider integration with fnox.
#
# Prerequisites:
#   1. GCP service account credentials configured (GOOGLE_APPLICATION_CREDENTIALS or via fnox)
#   2. IAM permissions: secretsmanager.secrets.get, secretsmanager.versions.access, secretsmanager.secrets.list
#   3. Test secrets created in Secret Manager
#   4. Run tests: mise run test:bats -- test/gcp_secret_manager.bats
#
# Note: Tests will automatically skip if GCP credentials are not available.
#       The mise task runs `fnox exec` which automatically decrypts provider-based secrets.
#

setup() {
    load 'test_helper/common_setup'
    _common_setup

    # Determine if we're in CI with secrets access (not a forked PR)
    local in_ci_with_secrets=false
    if [ "${CI:-}" = "true" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
        # Check if age key is available (indicates secrets are decrypted)
        if [ -f ~/.config/fnox/age.txt ] || [ -n "${FNOX_AGE_KEY:-}" ]; then
            in_ci_with_secrets=true
        fi
    fi

    # Check if GCP credentials are available
    if [ -z "$GCP_SERVICE_ACCOUNT_KEY" ] && [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
        if [ "$in_ci_with_secrets" = "true" ]; then
            echo "# ERROR: In CI with secrets access, but GCP_SERVICE_ACCOUNT_KEY is not available!" >&3
            return 1
        fi
        skip "GCP credentials not available. Ensure GCP_SERVICE_ACCOUNT_KEY or GOOGLE_APPLICATION_CREDENTIALS are configured."
    fi

    # If GCP_SERVICE_ACCOUNT_KEY is set, create a temp credentials file
    if [ -n "$GCP_SERVICE_ACCOUNT_KEY" ]; then
        export GOOGLE_APPLICATION_CREDENTIALS="${TEST_TEMP_DIR}/gcp-creds.json"
        echo "$GCP_SERVICE_ACCOUNT_KEY" > "$GOOGLE_APPLICATION_CREDENTIALS"
    fi

    # Set the project
    export GCP_PROJECT="chim-361015"

    # Check if gcloud CLI is installed
    if ! command -v gcloud >/dev/null 2>&1; then
        if [ "$in_ci_with_secrets" = "true" ]; then
            echo "# ERROR: In CI with secrets access, but gcloud CLI is not installed!" >&3
            return 1
        fi
        skip "gcloud CLI not installed. Install with: brew install google-cloud-sdk"
    fi

    # Verify we can access Secret Manager
    if ! gcloud secrets list --project="$GCP_PROJECT" --limit=1 >/dev/null 2>&1; then
        if [ "$in_ci_with_secrets" = "true" ]; then
            echo "# ERROR: In CI with secrets access, but cannot access GCP Secret Manager!" >&3
            echo "# This indicates a real problem with GCP access that should be fixed." >&3
            return 1
        fi
        skip "Cannot access GCP Secret Manager. Permissions may be insufficient."
    fi
}

teardown() {
    _common_teardown
}

# Helper function to create a GCP Secret Manager test config
create_gcp_sm_config() {
    local project="${1:-chim-361015}"
    local prefix="${2:-}"
    cat > "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF
[providers.gcp_sm]
type = "gcp-sm"
project = "$project"
EOF

    if [ -n "$prefix" ]; then
        echo "prefix = \"$prefix\"" >> "${FNOX_CONFIG_FILE}"
    fi

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets]
EOF
}

@test "fnox get retrieves secret from GCP Secret Manager" {
    create_gcp_sm_config

    # Add secret reference to config (using existing test secret)
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_TEST]
provider = "gcp_sm"
value = "fnox-test-secret-1"
EOF

    # Get the secret
    run "$FNOX_BIN" get GCP_SM_TEST
    assert_success
    assert_output "test-secret-value-1"
}

@test "fnox get retrieves second test secret" {
    create_gcp_sm_config

    # Add secret reference to config
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_TEST_2]
provider = "gcp_sm"
value = "fnox-test-secret-2"
EOF

    # Get the secret
    run "$FNOX_BIN" get GCP_SM_TEST_2
    assert_success
    assert_output "test-secret-value-2"
}

@test "fnox get retrieves JSON secret from GCP Secret Manager" {
    create_gcp_sm_config

    # Add secret reference to config
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_JSON]
provider = "gcp_sm"
value = "fnox-test-secret-json"
EOF

    # Get the secret
    run "$FNOX_BIN" get GCP_SM_JSON
    assert_success
    assert_output '{"key":"value"}'
}

@test "fnox get fails with non-existent secret" {
    create_gcp_sm_config

    # Add reference to non-existent secret
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_NONEXISTENT]
provider = "gcp_sm"
value = "this-secret-does-not-exist"
EOF

    # Try to get the secret
    run "$FNOX_BIN" get GCP_SM_NONEXISTENT
    assert_failure
    assert_output --partial "Failed to access secret"
}

@test "fnox list shows GCP Secret Manager secrets" {
    create_gcp_sm_config

    # Add multiple secret references
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_LIST_1]
description = "First GCP SM secret"
provider = "gcp_sm"
value = "fnox-test-secret-1"

[secrets.GCP_SM_LIST_2]
description = "Second GCP SM secret"
provider = "gcp_sm"
value = "fnox-test-secret-2"
EOF

    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "GCP_SM_LIST_1"
    assert_output --partial "GCP_SM_LIST_2"
    assert_output --partial "First GCP SM secret"
    assert_output --partial "Second GCP SM secret"
}

@test "GCP Secret Manager uses latest version" {
    create_gcp_sm_config

    # Add secret reference (should use latest version)
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_LATEST]
provider = "gcp_sm"
value = "fnox-test-secret-1"
EOF

    # Get the secret (should retrieve latest version)
    run "$FNOX_BIN" get GCP_SM_LATEST
    assert_success
    assert_output "test-secret-value-1"
}

@test "fnox exec sets GCP Secret Manager environment variables" {
    # Skip: Test isolation issue - fnox exec inherits parent config with age secrets
    # Exec functionality is tested in other test files
    skip "Test isolation issue with fnox exec under bats"

    create_gcp_sm_config

    # Add secret reference
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.MY_GCP_SM_VAR]
provider = "gcp_sm"
value = "fnox-test-secret-1"
EOF

    # Use exec to run a command with the secret as env var
    run "$FNOX_BIN" exec -- sh -c 'echo $MY_GCP_SM_VAR'
    assert_success
    assert_output "test-secret-value-1"
}

@test "GCP Secret Manager provider works with description" {
    create_gcp_sm_config

    # Add secret reference with description
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_WITH_DESC]
description = "My GCP Secret Manager secret"
provider = "gcp_sm"
value = "fnox-test-secret-1"
EOF

    # Verify description is in config
    run grep "description" "${FNOX_CONFIG_FILE}"
    assert_success
    assert_output --partial "My GCP Secret Manager secret"

    # Verify secret can be retrieved
    run "$FNOX_BIN" get GCP_SM_WITH_DESC
    assert_success
    assert_output "test-secret-value-1"
}

@test "GCP Secret Manager provider works without prefix" {
    create_gcp_sm_config "chim-361015" ""

    # Add secret reference without prefix
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_NO_PREFIX]
provider = "gcp_sm"
value = "fnox-test-secret-1"
EOF

    # Get the secret
    run "$FNOX_BIN" get GCP_SM_NO_PREFIX
    assert_success
    assert_output "test-secret-value-1"
}

@test "fnox set creates secret in GCP Secret Manager" {
    create_gcp_sm_config

    # Create a temporary secret with unique name using fnox set
    local secret_name="fnox-test-create-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
    local secret_value="my-test-secret-value-$(date +%s)-$$-${BATS_TEST_NUMBER:-0}"
    
    # Set the secret name for teardown cleanup
    export TEST_SECRET_NAME="fnox-test-create-GCP_SM_CREATE_TEST"

    # Add secret to config so fnox set will use GCP SM provider
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.GCP_SM_CREATE_TEST]
provider = "gcp_sm"
value = "$secret_name"
EOF

    # Create the secret using fnox set (should use GCP SM provider)
    run "$FNOX_BIN" set GCP_SM_CREATE_TEST "$secret_value" --provider gcp_sm
    assert_success

    # Get the secret back to verify it was created correctly
    run "$FNOX_BIN" get GCP_SM_CREATE_TEST
    assert_success
    assert_output "$secret_value"

    # Cleanup - delete actual secret created by fnox set
    # fnox set creates a secret with the provider prefix + secret key
    gcloud secrets delete "$TEST_SECRET_NAME" --project="$GCP_PROJECT" --quiet >/dev/null 2>&1 || true
}
