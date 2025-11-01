#!/usr/bin/env bats
#
# GCP Cloud KMS Provider Tests
#
# These tests verify the GCP Cloud KMS provider integration with fnox.
#
# Prerequisites:
#   1. GCP service account credentials configured (GOOGLE_APPLICATION_CREDENTIALS or via fnox)
#   2. Cloud KMS keyring and key available
#   3. IAM permissions: cloudkms.cryptoKeyVersions.useToEncrypt, cloudkms.cryptoKeyVersions.useToDecrypt, cloudkms.cryptoKeys.get
#   4. Run tests: mise run test:bats -- test/gcp_kms.bats
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

    # Set the KMS key details
    export GCP_PROJECT="chim-361015"
    export GCP_LOCATION="global"
    export GCP_KEYRING="fnox-test"
    export GCP_KEY="fnox-test-key"

    # Check if gcloud CLI is installed
    if ! command -v gcloud >/dev/null 2>&1; then
        if [ "$in_ci_with_secrets" = "true" ]; then
            echo "# ERROR: In CI with secrets access, but gcloud CLI is not installed!" >&3
            return 1
        fi
        skip "gcloud CLI not installed. Install with: brew install google-cloud-sdk"
    fi

    # Verify we can access the KMS key
    if ! gcloud kms keys list --location="$GCP_LOCATION" --keyring="$GCP_KEYRING" --project="$GCP_PROJECT" >/dev/null 2>&1; then
        if [ "$in_ci_with_secrets" = "true" ]; then
            echo "# ERROR: In CI with secrets access, but cannot access GCP KMS key!" >&3
            echo "# This indicates a real problem with GCP access that should be fixed." >&3
            return 1
        fi
        skip "Cannot access GCP KMS key. Key may not exist or permissions may be insufficient."
    fi
}

teardown() {
    _common_teardown
}

# Helper function to create a GCP KMS test config
create_gcp_kms_config() {
    local project="${1:-chim-361015}"
    local location="${2:-global}"
    local keyring="${3:-fnox-test}"
    local key="${4:-fnox-test-key}"
    cat > "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF
[providers.gcp_kms]
type = "gcp-kms"
project = "$project"
location = "$location"
keyring = "$keyring"
key = "$key"

[secrets]
EOF
}

@test "fnox set encrypts secret with GCP KMS" {
    create_gcp_kms_config

    # Set a secret with KMS encryption
    run "$FNOX_BIN" set GCP_KMS_TEST_SECRET "my-secret-value" --provider gcp_kms
    assert_success
    assert_output --partial "✓ Set secret GCP_KMS_TEST_SECRET"

    # Verify the config contains encrypted value (base64)
    run grep "value =" "${FNOX_CONFIG_FILE}"
    assert_success
    assert_output --regexp 'value = "[A-Za-z0-9+/=]{50,}"'
}

@test "fnox get decrypts secret from GCP KMS" {
    create_gcp_kms_config

    # Set a secret
    run "$FNOX_BIN" set GCP_KMS_DECRYPT_TEST "test-plaintext-value" --provider gcp_kms
    assert_success

    # Get the secret back
    run "$FNOX_BIN" get GCP_KMS_DECRYPT_TEST
    assert_success
    assert_output "test-plaintext-value"
}

@test "fnox set and get with special characters" {
    create_gcp_kms_config

    # Set a secret with special characters
    local special_value='{"password":"p@ssw0rd!","key":"abc=123&xyz"}'
    run "$FNOX_BIN" set GCP_KMS_SPECIAL_CHARS "$special_value" --provider gcp_kms
    assert_success

    # Get the secret back
    run "$FNOX_BIN" get GCP_KMS_SPECIAL_CHARS
    assert_success
    assert_output "$special_value"
}

@test "fnox set with multiline secret" {
    create_gcp_kms_config

    # Set a multiline secret
    local multiline_value="line1
line2
line3"
    run "$FNOX_BIN" set GCP_KMS_MULTILINE "$multiline_value" --provider gcp_kms
    assert_success

    # Get the secret back
    run "$FNOX_BIN" get GCP_KMS_MULTILINE
    assert_success
    assert_output "$multiline_value"
}

@test "fnox get fails with invalid ciphertext" {
    create_gcp_kms_config

    # Manually create config with invalid base64 ciphertext
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.INVALID_CIPHERTEXT]
provider = "gcp_kms"
value = "invalid-base64-!@#$%"
EOF

    run "$FNOX_BIN" get INVALID_CIPHERTEXT
    assert_failure
    assert_output --partial "Failed to decode base64 ciphertext"
}

@test "fnox list shows GCP KMS secrets" {
    create_gcp_kms_config

    # Set a couple of secrets
    run "$FNOX_BIN" set GCP_KMS_SECRET_1 "value1" --provider gcp_kms --description "First GCP KMS secret"
    assert_success

    run "$FNOX_BIN" set GCP_KMS_SECRET_2 "value2" --provider gcp_kms --description "Second GCP KMS secret"
    assert_success

    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "GCP_KMS_SECRET_1"
    assert_output --partial "GCP_KMS_SECRET_2"
    assert_output --partial "First GCP KMS secret"
}

@test "fnox set with description" {
    create_gcp_kms_config

    run "$FNOX_BIN" set GCP_KMS_WITH_DESC "test-value" --provider gcp_kms --description "My GCP KMS secret"
    assert_success

    # Verify description is in config
    run grep "description" "${FNOX_CONFIG_FILE}"
    assert_success
    assert_output --partial "My GCP KMS secret"
}

@test "GCP KMS encryption produces different ciphertext each time" {
    create_gcp_kms_config

    # Set a secret twice with the same value
    run "$FNOX_BIN" set GCP_KMS_UNIQUE_1 "same-value" --provider gcp_kms
    assert_success

    # Set again with same value
    run "$FNOX_BIN" set GCP_KMS_UNIQUE_2 "same-value" --provider gcp_kms
    assert_success

    # Get the encrypted values from config (inline table format)
    # Secrets are now stored as: GCP_KMS_UNIQUE_1 = { provider = "gcp_kms", value = "..." }
    cipher1=$(grep "^GCP_KMS_UNIQUE_1\s*=" "${FNOX_CONFIG_FILE}" | sed 's/.*value = "\([^"]*\)".*/\1/')
    cipher2=$(grep "^GCP_KMS_UNIQUE_2\s*=" "${FNOX_CONFIG_FILE}" | sed 's/.*value = "\([^"]*\)".*/\1/')

    # Verify ciphertexts were extracted
    [ -n "$cipher1" ]
    [ -n "$cipher2" ]

    # Ciphertexts should be different (KMS adds randomness)
    [ "$cipher1" != "$cipher2" ]

    # But both should decrypt to the same value
    run "$FNOX_BIN" get GCP_KMS_UNIQUE_1
    assert_success
    assert_output "same-value"

    run "$FNOX_BIN" get GCP_KMS_UNIQUE_2
    assert_success
    assert_output "same-value"
}

@test "fnox set updates existing GCP KMS secret" {
    create_gcp_kms_config

    # Set initial value
    run "$FNOX_BIN" set GCP_KMS_UPDATE_TEST "initial-value" --provider gcp_kms
    assert_success

    # Update with new value
    run "$FNOX_BIN" set GCP_KMS_UPDATE_TEST "updated-value" --provider gcp_kms
    assert_success

    # Verify new value is retrieved
    run "$FNOX_BIN" get GCP_KMS_UPDATE_TEST
    assert_success
    assert_output "updated-value"
}
