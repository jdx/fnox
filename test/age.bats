#!/usr/bin/env bats

setup() {
    load 'test_helper/common_setup'
    _common_setup
}

teardown() {
    _common_teardown
}

@test "decrypts using FNOX_AGE_KEY environment variable" {
    # Skip if age not installed
    if ! command -v age-keygen >/dev/null 2>&1; then
        skip "age-keygen not installed"
    fi

    # Generate age key
    local keygen_output
    keygen_output=$(age-keygen -o key.txt 2>&1)
    local public_key
    public_key=$(echo "$keygen_output" | grep "^Public key:" | cut -d' ' -f3)
    local private_key=$(grep "^AGE-SECRET-KEY" key.txt)

    # Create config with single provider
    cat > fnox.toml << EOF
root = true

[providers.age]
type = "age"
recipients = ["$public_key"]

[secrets]
EOF

    # Set a secret without specifying provider - should use the only one available
    run "$FNOX_BIN" set MY_SECRET "secret-value"
    assert_success

    # Verify the secret was encrypted with the age provider
    assert_config_contains "MY_SECRET"
    assert_config_not_contains "secret-value"

    # Should be able to get it back
    export FNOX_AGE_KEY=$private_key
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "secret-value"
}
