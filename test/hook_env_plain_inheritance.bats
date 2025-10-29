#!/usr/bin/env bats
#
# Test hook-env with provider inheritance from parent configs using plain provider
#

setup() {
    load 'test_helper/common_setup'
    _common_setup

    # Suppress shell integration output for cleaner test output
    export FNOX_SHELL_INTEGRATION_OUTPUT="none"
}

teardown() {
    _common_teardown
}

@test "hook-env merges secrets from multiple config levels" {
    # Create directory structure
    mkdir -p parent/child

    # Create parent config
    cat > parent/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.SECRET1]
provider = "plain"
value = "value1"

[secrets.SECRET2]
provider = "plain"
value = "value2"
EOF

    # Create child config with additional secrets
    cat > parent/child/fnox.toml <<EOF
[secrets.SECRET3]
provider = "plain"
value = "value3"

[secrets.SECRET4]
provider = "plain"
value = "value4"
EOF

    # Change to child directory
    cd parent/child

    # hook-env should load all 4 secrets
    run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$SECRET1 \$SECRET2 \$SECRET3 \$SECRET4"
    assert_success
    assert_line --index -1 "value1 value2 value3 value4"
}

@test "hook-env respects child override of parent secret" {
    # Create directory structure
    mkdir -p parent/child

    # Create parent config
    cat > parent/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.SHARED_SECRET]
provider = "plain"
value = "parent-value"
EOF

    # Create child config that overrides parent secret
    cat > parent/child/fnox.toml <<EOF
[secrets.SHARED_SECRET]
provider = "plain"
value = "child-override-value"
EOF

    # Change to child directory
    cd parent/child

    # Should get the child's value, not the parent's
    run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$SHARED_SECRET"
    assert_success
    assert_line --index -1 "child-override-value"
}

@test "hook-env loads fnox.local.toml and merges with fnox.toml" {
    # Create directory with both fnox.toml and fnox.local.toml
    mkdir -p test_dir

    # Create main config
    cat > test_dir/fnox.toml <<EOF
[providers.plain]
type = "plain"

[secrets.MAIN_SECRET]
provider = "plain"
value = "main-value"
EOF

    # Create local config that overrides and adds secrets
    cat > test_dir/fnox.local.toml <<EOF
[secrets.MAIN_SECRET]
provider = "plain"
value = "local-override"

[secrets.LOCAL_SECRET]
provider = "plain"
value = "local-only"
EOF

    cd test_dir

    # Both secrets should be loaded, with local override taking precedence
    run bash -c "eval \"\$('$FNOX_BIN' hook-env -s bash 2>/dev/null)\" && echo \$MAIN_SECRET \$LOCAL_SECRET"
    assert_success
    assert_line --index -1 "local-override local-only"
}
