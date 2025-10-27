#!/usr/bin/env bats

setup() {
    load 'test_helper/common_setup'
    _common_setup
}

teardown() {
    _common_teardown
}

@test "fnox import reads from .env file with -i flag" {
    # Initialize config
    assert_fnox_success init

    # Create a .env file with test secrets
    cat > .env << EOF
DATABASE_URL=postgresql://localhost:5432/mydb
API_KEY=secret-key-123
DEBUG_MODE=true
EOF

    # Import from .env file
    assert_fnox_success import -i .env --force

    # Verify secrets were imported
    assert_fnox_success get DATABASE_URL
    assert_output "postgresql://localhost:5432/mydb"

    assert_fnox_success get API_KEY
    assert_output "secret-key-123"

    assert_fnox_success get DEBUG_MODE
    assert_output "true"
}

@test "fnox import handles quoted values in .env file" {
    assert_fnox_success init

    # Create a .env file with quoted values
    cat > .env << EOF
SINGLE_QUOTED='value with spaces'
DOUBLE_QUOTED="another value with spaces"
UNQUOTED=no_spaces
EOF

    assert_fnox_success import -i .env --force

    assert_fnox_success get SINGLE_QUOTED
    assert_output "value with spaces"

    assert_fnox_success get DOUBLE_QUOTED
    assert_output "another value with spaces"

    assert_fnox_success get UNQUOTED
    assert_output "no_spaces"
}

@test "fnox import handles export statements in .env file" {
    assert_fnox_success init

    # Create a .env file with export statements
    cat > .env << EOF
export DATABASE_URL=postgresql://localhost:5432/mydb
export API_KEY=secret-key-456
REGULAR_VAR=regular-value
EOF

    assert_fnox_success import -i .env --force

    assert_fnox_success get DATABASE_URL
    assert_output "postgresql://localhost:5432/mydb"

    assert_fnox_success get API_KEY
    assert_output "secret-key-456"

    assert_fnox_success get REGULAR_VAR
    assert_output "regular-value"
}

@test "fnox import skips comments and empty lines" {
    assert_fnox_success init

    # Create a .env file with comments and empty lines
    cat > .env << EOF
# This is a comment
DATABASE_URL=postgresql://localhost:5432/mydb

# Another comment
API_KEY=secret-key-789

EOF

    assert_fnox_success import -i .env --force

    # Should only import the two actual variables
    assert_fnox_success list
    assert_output --partial "DATABASE_URL"
    assert_output --partial "API_KEY"
    refute_output --partial "#"
}

@test "fnox import with --filter flag filters secrets by regex" {
    assert_fnox_success init

    # Create a .env file
    cat > .env << EOF
DATABASE_URL=postgresql://localhost:5432/mydb
DATABASE_PASSWORD=secret123
API_KEY=secret-key-abc
API_SECRET=secret-abc-456
DEBUG_MODE=true
EOF

    # Import only DATABASE_* secrets
    assert_fnox_success import -i .env --filter "^DATABASE_" --force

    # Should have DATABASE_* secrets
    assert_fnox_success get DATABASE_URL
    assert_output "postgresql://localhost:5432/mydb"

    assert_fnox_success get DATABASE_PASSWORD
    assert_output "secret123"

    # Should not have API_* or DEBUG_MODE
    assert_fnox_failure get API_KEY
    assert_fnox_failure get DEBUG_MODE
}

@test "fnox import with --prefix flag adds prefix to secret names" {
    assert_fnox_success init

    # Create a .env file
    cat > .env << EOF
DATABASE_URL=postgresql://localhost:5432/mydb
API_KEY=secret-key-xyz
EOF

    # Import with prefix
    assert_fnox_success import -i .env --prefix "MYAPP_" --force

    # Should be accessible with prefix
    assert_fnox_success get MYAPP_DATABASE_URL
    assert_output "postgresql://localhost:5432/mydb"

    assert_fnox_success get MYAPP_API_KEY
    assert_output "secret-key-xyz"

    # Should not be accessible without prefix
    assert_fnox_failure get DATABASE_URL
    assert_fnox_failure get API_KEY
}

@test "fnox import requires confirmation by default" {
    assert_fnox_success init

    # Create a .env file
    cat > .env << EOF
DATABASE_URL=postgresql://localhost:5432/mydb
EOF

    # Import without --force should prompt for confirmation
    run bash -c "echo 'n' | $FNOX_BIN import -i .env"
    assert_output --partial "Continue? [y/N]"
    assert_output --partial "Import cancelled"

    # Secret should not have been imported
    assert_fnox_failure get DATABASE_URL
}

@test "fnox import reads from stdin when -i is not specified" {
    assert_fnox_success init

    # Import from stdin
    run bash -c "echo -e 'DATABASE_URL=postgresql://localhost:5432/mydb\nAPI_KEY=secret-key' | $FNOX_BIN import --force"
    assert_success

    # Verify secrets were imported
    assert_fnox_success get DATABASE_URL
    assert_output "postgresql://localhost:5432/mydb"

    assert_fnox_success get API_KEY
    assert_output "secret-key"
}

@test "fnox import from stdin requires --force flag" {
    assert_fnox_success init

    # FIXED: stdin imports now require --force to avoid double-stdin consumption bug
    # Without --force, importing from stdin would consume stdin twice:
    #   1. First to read import data (read_input)
    #   2. Then to read confirmation (stdin.read_line)
    # This would cause the import to fail because stdin is at EOF after reading data

    # Try to import from stdin without --force - should fail with helpful error
    run bash -c "echo -e 'TEST_VAR=test123' | $FNOX_BIN import"
    assert_failure
    assert_output --partial "the --force flag"
    assert_output --partial "stdin is consumed"

    # Verify secret was NOT imported
    assert_fnox_failure get TEST_VAR

    # Now try with --force - should succeed
    run bash -c "echo -e 'TEST_VAR=test123' | $FNOX_BIN import --force"
    assert_success

    # Verify secret WAS imported
    assert_fnox_success get TEST_VAR
    assert_output "test123"
}

@test "fnox import supports json format" {
    assert_fnox_success init

    # Create a JSON file
    cat > secrets.json << EOF
{
  "DATABASE_URL": "postgresql://localhost:5432/mydb",
  "API_KEY": "secret-key-json"
}
EOF

    assert_fnox_success import -i secrets.json json --force

    assert_fnox_success get DATABASE_URL
    assert_output "postgresql://localhost:5432/mydb"

    assert_fnox_success get API_KEY
    assert_output "secret-key-json"
}

@test "fnox import shows helpful error when file does not exist" {
    assert_fnox_success init

    # Try to import from non-existent file
    assert_fnox_failure import -i nonexistent.env --force
    assert_output --partial "Failed to read input file"
}
