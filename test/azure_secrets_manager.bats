#!/usr/bin/env bats
#
# Azure Secrets Manager Provider Tests
#
# These tests verify the Azure Secrets Manager (Azure Key Vault Secrets) provider integration with fnox.
#
# Prerequisites:
#   1. Azure credentials configured (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
#   2. Azure Key Vault with appropriate permissions (Key Vault Secrets User role)
#   3. Run tests: mise run test:bats -- test/azure_secrets_manager.bats
#
# Note: Tests will automatically skip if Azure credentials are not available.
#       The mise task runs `fnox exec` which automatically decrypts provider-based secrets.
#

setup() {
    load 'test_helper/common_setup'
    _common_setup

    # Check if Azure credentials are available
    if [ -z "$AZURE_CLIENT_ID" ] || [ -z "$AZURE_CLIENT_SECRET" ] || [ -z "$AZURE_TENANT_ID" ]; then
        skip "Azure credentials not available. Ensure AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID are configured."
    fi

    # Check if az CLI is installed
    if ! command -v az >/dev/null 2>&1; then
        skip "Azure CLI not installed. Install with: brew install azure-cli"
    fi

    # Set the Key Vault URL (from fnox.toml secrets)
    export VAULT_URL="https://fnox-testing-kv.vault.azure.net/"

    # Authenticate Azure CLI with service principal if not already logged in
    if ! az account show >/dev/null 2>&1; then
        az login --service-principal \
            -u "$AZURE_CLIENT_ID" \
            -p "$AZURE_CLIENT_SECRET" \
            --tenant "$AZURE_TENANT_ID" >/dev/null 2>&1 || \
            skip "Failed to authenticate Azure CLI with service principal"
    fi

    # Verify we can access Key Vault secrets
    if ! az keyvault secret list --vault-name fnox-testing-kv >/dev/null 2>&1; then
        skip "Cannot access Azure Key Vault. Permissions may be insufficient."
    fi
}

teardown() {
    # Clean up any test secrets created during tests
    if [ -n "$TEST_SECRET_NAME" ]; then
        az keyvault secret delete \
            --vault-name fnox-testing-kv \
            --name "$TEST_SECRET_NAME" >/dev/null 2>&1 || true
        # Purge the deleted secret (Key Vault has soft-delete by default)
        az keyvault secret purge \
            --vault-name fnox-testing-kv \
            --name "$TEST_SECRET_NAME" >/dev/null 2>&1 || true
    fi

    # Clean up Azure CLI cache/config directory created during tests
    if [ -d "$TEST_TEMP_DIR/.azure" ]; then
        rm -rf "$TEST_TEMP_DIR/.azure" || true
    fi

    _common_teardown
}

# Helper function to create an Azure Secrets Manager test config
create_azure_sm_config() {
    local vault_url="${1:-https://fnox-testing-kv.vault.azure.net/}"
    local prefix="${2}"
    if [ -z "$prefix" ] && [ "$#" -lt 2 ]; then
        prefix="fnox-test-"
    fi

    if [ -z "$prefix" ]; then
        # Omit prefix line entirely when empty
        cat > "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF
root = true

[providers.azure-sm]
type = "azure-sm"
vault_url = "$vault_url"

[secrets]
EOF
    else
        cat > "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF
root = true

[providers.azure-sm]
type = "azure-sm"
vault_url = "$vault_url"
prefix = "$prefix"

[secrets]
EOF
    fi
}

# Helper function to create a test secret in Azure Key Vault
create_test_secret() {
    local secret_name="$1"
    local secret_value="$2"

    az keyvault secret set \
        --vault-name fnox-testing-kv \
        --name "$secret_name" \
        --value "$secret_value" >/dev/null 2>&1

    export TEST_SECRET_NAME="$secret_name"
}

@test "fnox get retrieves secret from Azure Key Vault" {
    create_azure_sm_config

    # Create a test secret
    local timestamp="$(date +%s)"
    local secret_name="fnox-test-secret-${timestamp}"
    local secret_value="my-test-secret-value"
    create_test_secret "$secret_name" "$secret_value"

    # Add secret reference to config (using just the name without prefix)
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.AZURE_TEST]
provider = "azure-sm"
value = "secret-${timestamp}"
EOF

    # Get the secret
    run "$FNOX_BIN" get AZURE_TEST
    assert_success
    assert_output "$secret_value"
}

@test "fnox get with prefix prepends prefix to secret name" {
    create_azure_sm_config "https://fnox-testing-kv.vault.azure.net/" "fnox-test-"

    # Create a test secret with full path
    local timestamp="$(date +%s)"
    local secret_name="fnox-test-prefixed-${timestamp}"
    local secret_value="value-with-prefix"
    create_test_secret "$secret_name" "$secret_value"

    # Add secret reference using just the suffix
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.PREFIXED_SECRET]
provider = "azure-sm"
value = "prefixed-${timestamp}"
EOF

    # Get the secret
    run "$FNOX_BIN" get PREFIXED_SECRET
    assert_success
    assert_output "$secret_value"
}

@test "fnox get without prefix uses full secret name" {
    create_azure_sm_config "https://fnox-testing-kv.vault.azure.net/" ""

    # Create a test secret without prefix
    local timestamp="$(date +%s)"
    local secret_name="fnox-full-name-${timestamp}"
    local secret_value="value-no-prefix"
    create_test_secret "$secret_name" "$secret_value"

    # Add secret reference
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.FULL_NAME_SECRET]
provider = "azure-sm"
value = "$secret_name"
EOF

    # Get the secret
    run "$FNOX_BIN" get FULL_NAME_SECRET
    assert_success
    assert_output "$secret_value"
}

@test "fnox get fails with non-existent secret" {
    create_azure_sm_config

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.NONEXISTENT]
provider = "azure-sm"
value = "does-not-exist-$(date +%s)"
EOF

    # Try to get non-existent secret
    run "$FNOX_BIN" get NONEXISTENT
    assert_failure
    assert_output --partial "Failed to get secret"
}

@test "fnox get with JSON secret value" {
    create_azure_sm_config

    # Create a JSON secret
    local timestamp="$(date +%s)"
    local secret_name="fnox-test-json-secret-${timestamp}"
    local secret_value='{"api_key":"test123","endpoint":"https://api.example.com"}'
    create_test_secret "$secret_name" "$secret_value"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.JSON_SECRET]
provider = "azure-sm"
value = "json-secret-${timestamp}"
EOF

    # Get the secret
    run "$FNOX_BIN" get JSON_SECRET
    assert_success
    assert_output "$secret_value"
}

@test "fnox get with multiline secret" {
    create_azure_sm_config

    # Create a multiline secret
    local timestamp="$(date +%s)"
    local secret_name="fnox-test-multiline-${timestamp}"
    local secret_value="line1
line2
line3"
    create_test_secret "$secret_name" "$secret_value"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.MULTILINE_SECRET]
provider = "azure-sm"
value = "multiline-${timestamp}"
EOF

    # Get the secret
    run "$FNOX_BIN" get MULTILINE_SECRET
    assert_success
    assert_output "$secret_value"
}

@test "fnox list shows Azure Secrets Manager secrets" {
    create_azure_sm_config

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.AZURE_SECRET_1]
description = "First Azure secret"
provider = "azure-sm"
value = "secret1"

[secrets.AZURE_SECRET_2]
description = "Second Azure secret"
provider = "azure-sm"
value = "secret2"
EOF

    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "AZURE_SECRET_1"
    assert_output --partial "AZURE_SECRET_2"
    assert_output --partial "First Azure secret"
}

@test "fnox get with special characters in secret value" {
    create_azure_sm_config

    # Create a secret with special characters
    local timestamp="$(date +%s)"
    local secret_name="fnox-test-special-${timestamp}"
    local secret_value='p@ssw0rd!#$%^&*()_+-={}[]|\:";'\''<>?,./~`'
    create_test_secret "$secret_name" "$secret_value"

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.SPECIAL_CHARS]
provider = "azure-sm"
value = "special-${timestamp}"
EOF

    # Get the secret
    run "$FNOX_BIN" get SPECIAL_CHARS
    assert_success
    assert_output "$secret_value"
}

@test "Azure Secrets Manager works with existing fnox-test-secret" {
    # Test with the pre-created secret from setup
    create_azure_sm_config "https://fnox-testing-kv.vault.azure.net/" ""

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.EXISTING_SECRET]
provider = "azure-sm"
value = "fnox-test-secret"
EOF

    # Get the secret
    run "$FNOX_BIN" get EXISTING_SECRET
    assert_success
    assert_output "test-secret-value-123"
}

@test "fnox get with description" {
    create_azure_sm_config

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.DESCRIBED_SECRET]
description = "A secret with a description"
provider = "azure-sm"
value = "some-secret"
EOF

    # List to verify description
    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "DESCRIBED_SECRET"
    assert_output --partial "A secret with a description"
}
