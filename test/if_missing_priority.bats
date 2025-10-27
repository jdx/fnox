#!/usr/bin/env bats

load 'test_helper/common_setup'

setup() {
    _common_setup
}

@test "fnox exec with top-level if_missing=error fails on missing secret" {
    cat > fnox.toml << 'TOML'
root = true
if_missing = "error"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

    run "$FNOX_BIN" exec -- echo "should not run"
    assert_failure
}

@test "fnox exec with top-level if_missing=warn continues on missing secret" {
    cat > fnox.toml << 'TOML'
root = true
if_missing = "warn"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

    run "$FNOX_BIN" exec -- echo "command succeeded"
    assert_success
    assert_output --partial "command succeeded"
}

@test "fnox exec with top-level if_missing=ignore silently continues on missing secret" {
    cat > fnox.toml << 'TOML'
root = true
if_missing = "ignore"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

    run "$FNOX_BIN" exec -- echo "command succeeded"
    assert_success
    assert_output --partial "command succeeded"
    # Should not have warning message
    refute_output --partial "Warning:"
}

@test "fnox exec with FNOX_IF_MISSING=error fails on missing secret" {
    cat > fnox.toml << 'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
    export FNOX_IF_MISSING="error"

    run "$FNOX_BIN" exec -- echo "should not run"
    assert_failure
}

@test "fnox exec with FNOX_IF_MISSING=ignore silently continues on missing secret" {
    cat > fnox.toml << 'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
    export FNOX_IF_MISSING="ignore"

    run "$FNOX_BIN" exec -- echo "command succeeded"
    assert_success
    assert_output --partial "command succeeded"
    # Should not have warning message
    refute_output --partial "Warning:"
}

@test "fnox exec CLI flag --if-missing overrides secret-level config" {
    cat > fnox.toml << 'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
if_missing = "ignore"
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

    # Should fail because --if-missing error overrides secret-level if_missing=ignore
    run "$FNOX_BIN" exec --if-missing error -- echo "should not run"
    assert_failure
}

@test "fnox exec secret-level if_missing overrides top-level config" {
    cat > fnox.toml << 'TOML'
root = true
if_missing = "error"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
if_missing = "ignore"
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

    # Should succeed because secret-level if_missing=ignore overrides top-level if_missing=error
    run "$FNOX_BIN" exec -- echo "command succeeded"
    assert_success
    assert_output --partial "command succeeded"
}

@test "fnox exec FNOX_IF_MISSING env var overrides secret-level config" {
    cat > fnox.toml << 'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
if_missing = "ignore"
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
    export FNOX_IF_MISSING="error"

    # Should fail because FNOX_IF_MISSING=error overrides secret-level if_missing=ignore
    run "$FNOX_BIN" exec -- echo "should not run"
    assert_failure
}

@test "fnox exec FNOX_IF_MISSING env var overrides top-level config" {
    cat > fnox.toml << 'TOML'
root = true
if_missing = "ignore"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
    export FNOX_IF_MISSING="error"

    # Should fail because FNOX_IF_MISSING=error overrides top-level if_missing=ignore
    run "$FNOX_BIN" exec -- echo "should not run"
    assert_failure
}

@test "fnox exec explicit --if-missing warn overrides config ignore" {
    cat > fnox.toml << 'TOML'
root = true
if_missing = "ignore"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"

    # Should show warning because explicit --if-missing warn overrides config if_missing=ignore
    run "$FNOX_BIN" exec --if-missing warn -- echo "command succeeded"
    assert_success
    assert_output --partial "command succeeded"
    assert_output --partial "WARN"
}

@test "fnox exec explicit FNOX_IF_MISSING=warn overrides config ignore" {
    cat > fnox.toml << 'TOML'
root = true
if_missing = "ignore"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
    export FNOX_IF_MISSING="warn"

    # Should show warning because explicit FNOX_IF_MISSING=warn overrides config if_missing=ignore
    run "$FNOX_BIN" exec -- echo "command succeeded"
    assert_success
    assert_output --partial "command succeeded"
    assert_output --partial "WARN"
}

@test "fnox exec with FNOX_IF_MISSING_DEFAULT=error fails on missing secret" {
    cat > fnox.toml << 'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
    export FNOX_IF_MISSING_DEFAULT="error"

    run "$FNOX_BIN" exec -- echo "should not run"
    assert_failure
}

@test "fnox exec top-level config overrides FNOX_IF_MISSING_DEFAULT" {
    cat > fnox.toml << 'TOML'
root = true
if_missing = "ignore"

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
    export FNOX_IF_MISSING_DEFAULT="error"

    # Should succeed because config if_missing=ignore overrides FNOX_IF_MISSING_DEFAULT=error
    run "$FNOX_BIN" exec -- echo "command succeeded"
    assert_success
    assert_output --partial "command succeeded"
}

@test "fnox exec FNOX_IF_MISSING overrides FNOX_IF_MISSING_DEFAULT" {
    cat > fnox.toml << 'TOML'
root = true

[providers.age]
type = "age"
recipients = ["age1cdk0klj88zzhg0ncfhe4ul9ja5k58w2st3fpkhmy0f46vlsuh5wq0s0gr9"]

[secrets.MY_SECRET]
provider = "age"
value = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBaaTFhczNBYnN3S1c0NjZwZnlDN2NUMTVaSTFXd2k1OWhnWUJvckVxYmh3CjNRSmhxSWJiYXU3eHoyNlcyOVVLRWNnUlFJeFBjL2N0YlA5K2hUaU04VDQKLS0tIGN6UVYzMHZJUUhKNmlkQjFOaXRXYUpjbzBOaHRMZkFFVVRPa3FaQUs2dHcKf3AcueEBLdl8lzRwKXik+OvDVg48g44QoPZu0j0NLV4lPLDqoq0="
TOML

    # Set invalid age key to trigger error
    export FNOX_AGE_KEY="/tmp/nonexistent-age-key.txt"
    export FNOX_IF_MISSING_DEFAULT="error"
    export FNOX_IF_MISSING="ignore"

    # Should succeed because FNOX_IF_MISSING=ignore overrides FNOX_IF_MISSING_DEFAULT=error
    run "$FNOX_BIN" exec -- echo "command succeeded"
    assert_success
    assert_output --partial "command succeeded"
}
