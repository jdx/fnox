#!/usr/bin/env bats

setup() {
    load 'test_helper/common_setup'
    _common_setup
}

teardown() {
    _common_teardown
}

@test "fnox check passes with valid config" {
    create_test_config
    assert_fnox_success check
}

@test "fnox check fails with missing required secret" {
    create_test_config
    
    # Add a required secret without value
    cat >> "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF

[secrets.required_secret]
if_missing = "error"
EOF
    
    assert_fnox_failure check
    assert_output --partial "required_secret"
}

@test "fnox check warns about missing optional secret" {
    create_test_config
    
    # Add an optional secret without value
    cat >> "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF

[secrets.optional_secret]
if_missing = "warn"
EOF
    
    assert_fnox_success check
    assert_output --partial "optional_secret"
}

@test "fnox check with profile" {
    create_test_config
    assert_fnox_success check --profile test
}

@test "fnox check works with unknown profile (profile-specific config file support)" {
    create_test_config
    # With fnox.$FNOX_PROFILE.toml support, unknown profiles are allowed
    # They just use top-level secrets (same as default profile)
    assert_fnox_success check --profile unknown
    # Should show it's checking the profile
    assert_output --partial "unknown"
}

@test "fnox check warns about unknown provider" {
    create_test_config
    
    # Add a secret with unknown provider
    cat >> "${FNOX_CONFIG_FILE:-fnox.toml}" << EOF

[secrets.bad_secret]
provider = "unknown"
value = "test"
EOF
    
    assert_fnox_success check
    assert_output --partial "unknown"
}

@test "fnox check with empty config" {
    # Create empty config with root=true to prevent recursion
    echo "root = true" > "${FNOX_CONFIG_FILE:-fnox.toml}"

    assert_fnox_success check
    assert_output --partial "No secrets"
}