#!/usr/bin/env bats
#
# CI Redact Command Tests
#
# Tests for the fnox ci-redact command which masks secrets in CI/CD output.
#

setup() {
    load 'test_helper/common_setup'
    _common_setup

    # Create a test config with secrets
    # Use root = true to prevent loading parent configs
    cat > "$FNOX_CONFIG_FILE" << EOF
root = true

[secrets]
SECRET_ONE = { default = "secret-value-1" }
SECRET_TWO = { default = "secret-value-2" }
PASSWORD = { default = "super-secret-password" }
EOF
}

teardown() {
    _common_teardown
}

@test "ci-redact fails when not in CI environment" {
    # Ensure CI env vars are not set
    unset CI
    unset GITHUB_ACTIONS
    unset GITLAB_CI
    unset CIRCLECI

    run "$FNOX_BIN" ci-redact
    assert_failure
    assert_output --partial "Not running in a CI environment"
}

@test "ci-redact works in GitHub Actions" {
    # Simulate GitHub Actions environment
    export CI=true
    export GITHUB_ACTIONS=true

    run "$FNOX_BIN" ci-redact
    assert_success
    assert_output --partial "::add-mask::secret-value-1"
    assert_output --partial "::add-mask::secret-value-2"
    assert_output --partial "::add-mask::super-secret-password"
}

@test "ci-redact outputs correct number of mask commands" {
    export CI=true
    export GITHUB_ACTIONS=true

    run "$FNOX_BIN" ci-redact
    assert_success

    # Count the number of mask commands (should be 3 for our 3 secrets)
    mask_count=$(echo "$output" | grep -c "::add-mask::" || true)
    [ "$mask_count" -eq 3 ]
}

@test "ci-redact fails on GitLab CI" {
    export CI=true
    export GITLAB_CI=true
    unset GITHUB_ACTIONS

    run "$FNOX_BIN" ci-redact
    assert_failure
    assert_output --partial "GitLab CI does not support runtime secret masking"
}

@test "ci-redact fails on CircleCI" {
    export CI=true
    export CIRCLECI=true
    unset GITHUB_ACTIONS

    run "$FNOX_BIN" ci-redact
    assert_failure
    assert_output --partial "CircleCI does not support runtime secret masking"
}

@test "ci-redact handles empty secrets gracefully" {
    cat > "$FNOX_CONFIG_FILE" << EOF
root = true

[secrets]
EOF

    export CI=true
    export GITHUB_ACTIONS=true

    run "$FNOX_BIN" ci-redact
    assert_success
    # Should have no output for empty secrets
    [ -z "$output" ]
}

@test "ci-redact with profile" {
    cat > "$FNOX_CONFIG_FILE" << EOF
root = true

[secrets]
DEFAULT_SECRET = { default = "default-value" }

[profiles.staging.secrets]
STAGING_SECRET = { default = "staging-value" }
EOF

    export CI=true
    export GITHUB_ACTIONS=true

    # Test default profile
    run "$FNOX_BIN" ci-redact
    assert_success
    assert_output --partial "::add-mask::default-value"
    refute_output --partial "staging-value"

    # Test staging profile - inherits top-level secrets
    run "$FNOX_BIN" -p staging ci-redact
    assert_success
    assert_output --partial "::add-mask::staging-value"
    assert_output --partial "::add-mask::default-value"  # Inherited from top level
}

@test "ci-redact handles missing secrets with if_missing=ignore" {
    cat > "$FNOX_CONFIG_FILE" << EOF
root = true

[secrets]
REQUIRED = { default = "required-value" }
OPTIONAL = { if_missing = "ignore" }
EOF

    export CI=true
    export GITHUB_ACTIONS=true

    run "$FNOX_BIN" ci-redact
    assert_success
    assert_output --partial "::add-mask::required-value"
    # Should only output one mask command
    mask_count=$(echo "$output" | grep -c "::add-mask::" || true)
    [ "$mask_count" -eq 1 ]
}

@test "ci-redact handles missing secrets with if_missing=warn" {
    cat > "$FNOX_CONFIG_FILE" << EOF
root = true

[secrets]
REQUIRED = { default = "required-value" }
OPTIONAL = { if_missing = "warn" }
EOF

    export CI=true
    export GITHUB_ACTIONS=true

    run "$FNOX_BIN" ci-redact
    assert_success
    assert_output --partial "::add-mask::required-value"
    assert_output --partial "Warning: Secret 'OPTIONAL' not found"
}

@test "ci-redact fails with missing required secrets" {
    cat > "$FNOX_CONFIG_FILE" << EOF
root = true

[secrets]
REQUIRED = { if_missing = "error" }
EOF

    export CI=true
    export GITHUB_ACTIONS=true

    run "$FNOX_BIN" ci-redact
    assert_failure
    assert_output --partial "Secret 'REQUIRED' not found"
}

@test "ci-redact with environment variable values" {
    cat > "$FNOX_CONFIG_FILE" << EOF
root = true

[secrets]
FROM_ENV = {}
FROM_DEFAULT = { default = "default-value" }
EOF

    export FROM_ENV="env-value"
    export CI=true
    export GITHUB_ACTIONS=true

    run "$FNOX_BIN" ci-redact
    assert_success
    assert_output --partial "::add-mask::env-value"
    assert_output --partial "::add-mask::default-value"
}

@test "ci-redact is hidden from main help" {
    run "$FNOX_BIN" --help
    assert_success
    refute_output --partial "ci-redact"
}

@test "ci-redact has its own help" {
    run "$FNOX_BIN" ci-redact --help
    assert_success
    assert_output --partial "Redact secrets in CI/CD output"
}
