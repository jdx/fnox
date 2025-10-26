#!/usr/bin/env bats

# Tests for secret resolution priority order:
# 1. Provider (if specified)
# 2. Default value
# 3. Environment variable

setup() {
    load 'test_helper/common_setup'
    _common_setup
}

teardown() {
    _common_teardown
}

@test "provider takes priority over default value" {
    # Create config with plain provider, secret has both provider value and default
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
provider = "plain"
value = "from-provider"
default = "from-default"
EOF

    # Should return provider value, not default
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "from-provider"
}

@test "provider takes priority over environment variable" {
    # Create config with plain provider
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
provider = "plain"
value = "from-provider"
EOF

    # Set env var
    export MY_SECRET="from-env-var"

    # Should return provider value, not env var
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "from-provider"
}

@test "provider takes priority over both default and env var" {
    # Create config with plain provider, secret has provider, default, and env var
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
provider = "plain"
value = "from-provider"
default = "from-default"
EOF

    # Set env var
    export MY_SECRET="from-env-var"

    # Should return provider value (highest priority)
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "from-provider"
}

@test "default takes priority over environment variable" {
    # Create config with default but no provider value
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
default = "from-default"
EOF

    # Set env var
    export MY_SECRET="from-env-var"

    # Should return default value, not env var
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "from-default"
}

@test "environment variable used when no provider and no default" {
    # Create config with no provider value and no default
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
EOF

    # Set env var
    export MY_SECRET="from-env-var"

    # Should return env var (lowest priority, but only option)
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "from-env-var"
}

@test "error when secret not found and no fallback" {
    # Create config with no provider, no default, no env var
    # Set if_missing = "error" to require the secret
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
if_missing = "error"
EOF

    # Don't set env var - should error
    run "$FNOX_BIN" get MY_SECRET
    assert_failure
    assert_output --partial "Secret 'MY_SECRET' not found"
}

@test "priority order works with fnox exec" {
    # Create config with provider value and default
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.PROVIDER_SECRET]
provider = "plain"
value = "from-provider"
default = "from-default"

[secrets.DEFAULT_SECRET]
default = "from-default"

[secrets.ENV_SECRET]
EOF

    # Set env vars
    export PROVIDER_SECRET="from-env-var"
    export DEFAULT_SECRET="from-env-var"
    export ENV_SECRET="from-env-var"

    # Run a command that prints the env vars
    run "$FNOX_BIN" exec -- sh -c 'echo "$PROVIDER_SECRET|$DEFAULT_SECRET|$ENV_SECRET"'
    assert_success
    # Provider > default > env
    assert_output "from-provider|from-default|from-env-var"
}

@test "priority order works in CI redact mode" {
    # Skip if not in a CI environment (we'll simulate GitHub Actions)
    export CI=true
    export GITHUB_ACTIONS=true

    # Create config
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.PROVIDER_SECRET]
provider = "plain"
value = "provider-value-to-mask"
default = "default-value"

[secrets.DEFAULT_SECRET]
default = "default-value-to-mask"
EOF

    # Set env vars (should be ignored)
    export PROVIDER_SECRET="env-value"
    export DEFAULT_SECRET="env-value"

    # Run ci-redact
    run "$FNOX_BIN" ci-redact
    assert_success

    # Should mask provider value, not default or env
    assert_output --partial "::add-mask::provider-value-to-mask"
    assert_output --partial "::add-mask::default-value-to-mask"

    # Should NOT contain env value
    refute_output --partial "env-value"
}

@test "value field requires provider to be used" {
    # Create config with value but no provider specified and no default provider
    cat > fnox.toml << 'EOF'
root = true

[providers.plain1]
type = "plain"

[providers.plain2]
type = "plain"

[secrets.MY_SECRET]
value = "value-needs-provider"
default = "from-default"
EOF

    # With multiple providers and no default, can't auto-select provider
    # So value field can't be used - should fall back to default
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "from-default"
}

@test "provider value used as provider input, not direct output" {
    # This tests that the 'value' field is used as input to the provider
    # not returned directly
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
provider = "plain"
value = "plain-provider-input-value"
EOF

    # The plain provider should return the value as-is
    # (demonstrating value is passed to provider)
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "plain-provider-input-value"
}

@test "multiple secrets respect individual priorities" {
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.SECRET_A]
provider = "plain"
value = "a-provider"
default = "a-default"

[secrets.SECRET_B]
default = "b-default"

[secrets.SECRET_C]
# No provider, no default - will use env
EOF

    # Set env vars for all
    export SECRET_A="a-env"
    export SECRET_B="b-env"
    export SECRET_C="c-env"

    # A: provider wins
    run "$FNOX_BIN" get SECRET_A
    assert_success
    assert_output "a-provider"

    # B: default wins over env
    run "$FNOX_BIN" get SECRET_B
    assert_success
    assert_output "b-default"

    # C: env var is used (only option)
    run "$FNOX_BIN" get SECRET_C
    assert_success
    assert_output "c-env"
}

@test "default provider with explicit value follows priority" {
    cat > fnox.toml << 'EOF'
root = true
default_provider = "plain"

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
# Uses default provider
value = "provider-value"
default = "default-value"
EOF

    export MY_SECRET="env-value"

    # Should use provider (default provider) with value
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "provider-value"
}

@test "secret with provider but no value falls back to default" {
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.MY_SECRET]
provider = "plain"
# No value - provider can't be used
default = "default-value"
EOF

    export MY_SECRET="env-value"

    # Can't use provider without value, should fall back to default
    run "$FNOX_BIN" get MY_SECRET
    assert_success
    assert_output "default-value"
}

@test "if_missing=warn allows missing secrets without error" {
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.OPTIONAL_SECRET]
if_missing = "warn"
EOF

    # Don't set env var - should warn but not error
    run "$FNOX_BIN" get OPTIONAL_SECRET
    assert_success
    # Should produce warning on stderr
}

@test "if_missing=ignore silently skips missing secrets" {
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.OPTIONAL_SECRET]
if_missing = "ignore"
EOF

    # Don't set env var - should silently skip
    run "$FNOX_BIN" get OPTIONAL_SECRET
    assert_success
    assert_output ""
}

@test "priority works with profile-specific secrets" {
    cat > fnox.toml << 'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.GLOBAL_SECRET]
provider = "plain"
value = "global-provider"
default = "global-default"

[profiles.dev]

[profiles.dev.providers.plain]
type = "plain"

[profiles.dev.secrets.DEV_SECRET]
default = "dev-default"

[profiles.dev.secrets.PROFILE_PROVIDER]
provider = "plain"
value = "profile-provider"
EOF

    export GLOBAL_SECRET="env-value"
    export DEV_SECRET="env-value"
    export PROFILE_PROVIDER="env-value"

    # Global secret from default profile should still use provider
    run "$FNOX_BIN" get GLOBAL_SECRET
    assert_success
    assert_output "global-provider"

    # Dev profile secret should use default over env
    run "$FNOX_BIN" get --profile dev DEV_SECRET
    assert_success
    assert_output "dev-default"

    # Profile secret with provider should use provider over env
    run "$FNOX_BIN" get --profile dev PROFILE_PROVIDER
    assert_success
    assert_output "profile-provider"
}
