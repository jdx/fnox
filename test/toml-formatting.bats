#!/usr/bin/env bats

load 'test_helper/common_setup'

# Test TOML formatting behavior for secrets - visitor pattern approach

setup() {
    _common_setup
}

teardown() {
    _common_teardown
}

@test "fnox set uses inline table format by default for new secrets" {
    # Generate age key
    if ! command -v age-keygen >/dev/null 2>&1; then
        skip "age-keygen not installed"
    fi
    mkdir -p "$HOME/.config/fnox"
    age-keygen -o "$HOME/.config/fnox/age.txt" 2>/dev/null

    # Create minimal config with age provider
    cat > fnox.toml << EOF
root = true

[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
EOF

    # Set a secret with provider and description
    run fnox set MY_SECRET "test-value" --provider age --description "Test secret"
    assert_success

    # Check that the secret is formatted as an inline table
    run cat fnox.toml
    assert_output --partial 'MY_SECRET'
    assert_output --partial '{'
    assert_output --partial 'provider = "age"'
    assert_output --partial 'description = "Test secret"'

    # Verify it's on a single line (inline table format)
    local secret_line=$(grep "^MY_SECRET" fnox.toml)
    assert [ -n "$secret_line" ]
    echo "$secret_line" | grep -q '{'
}

@test "fnox set with multiple fields uses inline table format" {
    # Generate age key
    if ! command -v age-keygen >/dev/null 2>&1; then
        skip "age-keygen not installed"
    fi
    mkdir -p "$HOME/.config/fnox"
    age-keygen -o "$HOME/.config/fnox/age.txt" 2>/dev/null

    # Create minimal config
    cat > fnox.toml << EOF
root = true

[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
EOF

    # Set a secret with provider, description, and default value
    run fnox set COMPLEX_SECRET "test-value" --provider age --description "Complex secret" --default "fallback"
    assert_success

    # Check that all fields are in the inline table
    run cat fnox.toml
    assert_output --partial 'COMPLEX_SECRET'
    assert_output --partial '{'
    assert_output --partial 'provider = "age"'
    assert_output --partial 'description = "Complex secret"'
    assert_output --partial 'default = "fallback"'
}

@test "multiple secrets all use inline table format by default" {
    # Generate age key
    if ! command -v age-keygen >/dev/null 2>&1; then
        skip "age-keygen not installed"
    fi
    mkdir -p "$HOME/.config/fnox"
    age-keygen -o "$HOME/.config/fnox/age.txt" 2>/dev/null

    # Create minimal config
    cat > fnox.toml << EOF
root = true

[providers.age]
type = "age"
recipients = ["age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"]
EOF

    # Set multiple secrets
    run fnox set SECRET1 "value1" --provider age
    assert_success
    run fnox set SECRET2 "value2" --provider age --description "Second"
    assert_success
    run fnox set SECRET3 "value3" --provider age
    assert_success

    # Check that all are inline tables
    run cat fnox.toml
    assert_output --partial 'SECRET1'
    assert_output --partial 'SECRET2'
    assert_output --partial 'SECRET3'
    # Verify all contain inline table brackets
    grep -q "SECRET1.*{" fnox.toml
    grep -q "SECRET2.*{" fnox.toml
    grep -q "SECRET3.*{" fnox.toml
}
