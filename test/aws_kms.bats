#!/usr/bin/env bats
#
# AWS KMS Provider Tests
#
# These tests verify the AWS KMS provider integration with fnox.
#
# Prerequisites:
#   1. AWS credentials configured (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#   2. KMS key available (created during setup)
#   3. IAM permissions: kms:Encrypt, kms:Decrypt, kms:DescribeKey
#   4. Run tests: mise run test:bats -- test/aws_kms.bats
#
# Note: Tests will automatically skip if AWS credentials are not available.
#       The mise task runs `fnox exec` which automatically decrypts provider-based secrets.
#

setup() {
    load 'test_helper/common_setup'
    _common_setup

    # Check if AWS credentials are available
    # (mise run test:bats automatically loads secrets via fnox exec)
    if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
        skip "AWS credentials not available. Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are configured."
    fi

    # Check if aws CLI is installed
    if ! command -v aws >/dev/null 2>&1; then
        skip "AWS CLI not installed. Install with: brew install awscli"
    fi

    # Set the KMS key ID and region
    export KMS_KEY_ID="alias/fnox-testing"
    export KMS_REGION="us-east-1"

    # Verify we can access the KMS key
    if ! aws kms describe-key --key-id "$KMS_KEY_ID" --region "$KMS_REGION" >/dev/null 2>&1; then
        skip "Cannot access KMS key '$KMS_KEY_ID'. Key may not exist or permissions may be insufficient."
    fi
}

teardown() {
    _common_teardown
}

# Helper function to create an AWS KMS test config
create_kms_config() {
    local key_id="${1:-alias/fnox-testing}"
    local region="${2:-us-east-1}"
    cat > "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF
root = true

[providers.kms]
type = "aws-kms"
key_id = "$key_id"
region = "$region"

[secrets]
EOF
}

@test "fnox set encrypts secret with AWS KMS" {
    create_kms_config

    # Set a secret with KMS encryption
    run "$FNOX_BIN" set KMS_TEST_SECRET "my-secret-value" --provider kms
    assert_success
    assert_output --partial "✓ Set secret KMS_TEST_SECRET"

    # Verify the config contains encrypted value (base64)
    run grep "value =" "${FNOX_CONFIG_FILE}"
    assert_success
    assert_output --regexp 'value = "[A-Za-z0-9+/=]{50,}"'
}

@test "fnox get decrypts secret from AWS KMS" {
    create_kms_config

    # Set a secret
    run "$FNOX_BIN" set KMS_DECRYPT_TEST "test-plaintext-value" --provider kms
    assert_success

    # Get the secret back
    run "$FNOX_BIN" get KMS_DECRYPT_TEST
    assert_success
    assert_output "test-plaintext-value"
}

@test "fnox set and get with special characters" {
    create_kms_config

    # Set a secret with special characters
    local special_value='{"password":"p@ssw0rd!","key":"abc=123&xyz"}'
    run "$FNOX_BIN" set KMS_SPECIAL_CHARS "$special_value" --provider kms
    assert_success

    # Get the secret back
    run "$FNOX_BIN" get KMS_SPECIAL_CHARS
    assert_success
    assert_output "$special_value"
}

@test "fnox set with multiline secret" {
    create_kms_config

    # Set a multiline secret
    local multiline_value="line1
line2
line3"
    run "$FNOX_BIN" set KMS_MULTILINE "$multiline_value" --provider kms
    assert_success

    # Get the secret back
    run "$FNOX_BIN" get KMS_MULTILINE
    assert_success
    assert_output "$multiline_value"
}

@test "fnox get fails with invalid ciphertext" {
    create_kms_config

    # Manually create config with invalid base64 ciphertext
    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.INVALID_CIPHERTEXT]
provider = "kms"
value = "invalid-base64-!@#$%"
EOF

    run "$FNOX_BIN" get INVALID_CIPHERTEXT
    assert_failure
    assert_output --partial "Failed to decode base64 ciphertext"
}

@test "fnox set warns and stores plaintext with wrong KMS key" {
    # Create config with non-existent key
    create_kms_config "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"

    # When encryption fails, fnox currently warns and stores plaintext
    run "$FNOX_BIN" set KMS_WRONG_KEY "test" --provider kms
    assert_success
    assert_output --partial "Encryption not supported for provider 'kms'"
    assert_output --partial "Storing plaintext"
}

@test "fnox list shows KMS secrets" {
    create_kms_config

    cat >> "${FNOX_CONFIG_FILE}" << EOF

[secrets.KMS_SECRET_1]
description = "First KMS secret"
provider = "kms"
value = "AQICAHiy8nEpehKbN0gxZ6AQfrlCEWWoKMLw5eogFUZ3c5gd1QEA1/K/EPEgXnmoj0rHIELGAAAAjDCBiQYJKoZIhvcNAQcGoHwwegIBADB1BgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDNaM0QctJeav8gwCMgIBEIBIbZFODxF3kivTBXDBZ+NenrryPEJz10X6XxeZtT32HjgMtUwravXPF0O4xpoaRlcHVYssmhq2RmOYGJxtlayDC0YsNwfb7kgX"

[secrets.KMS_SECRET_2]
description = "Second KMS secret"
provider = "kms"
value = "AQICAHiy8nEpehKbN0gxZ6AQfrlCEWWoKMLw5eogFUZ3c5gd1QEA1/K/EPEgXnmoj0rHIELGAAAAjDCBiQYJKoZIhvcNAQcGoHwwegIBADB1BgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDNaM0QctJeav8gwCMgIBEIBIbZFODxF3kivTBXDBZ+NenrryPEJz10X6XxeZtT32HjgMtUwravXPF0O4xpoaRlcHVYssmhq2RmOYGJxtlayDC0YsNwfb7kgX"
EOF

    run "$FNOX_BIN" list
    assert_success
    assert_output --partial "KMS_SECRET_1"
    assert_output --partial "KMS_SECRET_2"
    assert_output --partial "First KMS secret"
}

@test "fnox set with description" {
    create_kms_config

    run "$FNOX_BIN" set KMS_WITH_DESC "test-value" --provider kms --description "My KMS secret"
    assert_success

    # Verify description is in config
    run grep "description" "${FNOX_CONFIG_FILE}"
    assert_success
    assert_output --partial "My KMS secret"
}

@test "AWS KMS provider works with full key ARN" {
    # Get the full ARN of the test key
    local key_arn=$(aws kms describe-key --key-id "alias/fnox-testing" --region us-east-1 --query 'KeyMetadata.Arn' --output text)

    create_kms_config "$key_arn" "us-east-1"

    run "$FNOX_BIN" set KMS_ARN_TEST "test-with-arn" --provider kms
    assert_success

    run "$FNOX_BIN" get KMS_ARN_TEST
    assert_success
    assert_output "test-with-arn"
}

@test "fnox exec sets KMS environment variables" {
    create_kms_config

    # Set a secret
    run "$FNOX_BIN" set MY_KMS_VAR "kms-env-value" --provider kms
    assert_success

    # Use exec to run a command with the secret as env var
    # Explicitly set FNOX_CONFIG_FILE to avoid inheriting parent config
    run env FNOX_CONFIG_FILE="$FNOX_CONFIG_FILE" "$FNOX_BIN" exec -- sh -c 'echo $MY_KMS_VAR'
    assert_success
    assert_output "kms-env-value"
}

@test "KMS encryption produces different ciphertext each time" {
    create_kms_config

    # Set a secret twice with the same value
    run "$FNOX_BIN" set KMS_UNIQUE_1 "same-value" --provider kms
    assert_success

    # Set again with same value
    run "$FNOX_BIN" set KMS_UNIQUE_2 "same-value" --provider kms
    assert_success

    # Get the encrypted values from config (inline table format)
    # Secrets are now stored as: KMS_UNIQUE_1 = { provider = "kms", value = "..." }
    cipher1=$(grep "^KMS_UNIQUE_1\s*=" "${FNOX_CONFIG_FILE}" | sed 's/.*value = "\([^"]*\)".*/\1/')
    cipher2=$(grep "^KMS_UNIQUE_2\s*=" "${FNOX_CONFIG_FILE}" | sed 's/.*value = "\([^"]*\)".*/\1/')

    # Verify ciphertexts were extracted
    [ -n "$cipher1" ]
    [ -n "$cipher2" ]

    # Ciphertexts should be different (KMS adds randomness)
    [ "$cipher1" != "$cipher2" ]

    # But both should decrypt to the same value
    run "$FNOX_BIN" get KMS_UNIQUE_1
    assert_success
    assert_output "same-value"

    run "$FNOX_BIN" get KMS_UNIQUE_2
    assert_success
    assert_output "same-value"
}

@test "fnox set updates existing KMS secret" {
    create_kms_config

    # Set initial value
    run "$FNOX_BIN" set KMS_UPDATE_TEST "initial-value" --provider kms
    assert_success

    # Update with new value
    run "$FNOX_BIN" set KMS_UPDATE_TEST "updated-value" --provider kms
    assert_success

    # Verify new value is retrieved
    run "$FNOX_BIN" get KMS_UPDATE_TEST
    assert_success
    assert_output "updated-value"
}

@test "KMS provider respects region configuration" {
    # Test that we're using the correct region
    create_kms_config "alias/fnox-testing" "us-east-1"

    run "$FNOX_BIN" set KMS_REGION_TEST "region-specific" --provider kms
    assert_success

    run "$FNOX_BIN" get KMS_REGION_TEST
    assert_success
    assert_output "region-specific"
}
