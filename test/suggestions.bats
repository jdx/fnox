#!/usr/bin/env bats
# Test helpful error messages with suggestions

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

# ============================================================================
# Secret not found with suggestions
# ============================================================================

@test "get: suggests similar secret names for typos" {
	# Set up a secret
	fnox init --force
	fnox set DATABASE_URL "postgresql://localhost/db"

	# Try to get with a typo
	run fnox get DATABSE_URL # Missing 'A'
	[ "$status" -ne 0 ]
	[[ $output =~ "Did you mean 'DATABASE_URL'?" ]]
}

@test "get: suggests multiple similar secret names" {
	fnox init --force
	fnox set DATABASE_URL "postgresql://localhost/db"
	fnox set DATABASE_URI "postgresql://localhost/db2"
	fnox set DATABASE_HOST "localhost"

	# Try to get with something that matches multiple
	run fnox get DATABSE # Partial match
	[ "$status" -ne 0 ]
	# Should suggest at least one of the similar names
	[[ $output =~ "Did you mean" ]]
}

@test "get: no suggestion for completely different name" {
	fnox init --force
	fnox set DATABASE_URL "postgresql://localhost/db"

	# Try to get something completely different
	run fnox get COMPLETELY_UNRELATED_NAME
	[ "$status" -ne 0 ]
	# Should not have "Did you mean" since nothing is similar
	[[ ! $output =~ "Did you mean" ]]
}

# ============================================================================
# Provider not configured with suggestions
# ============================================================================

@test "get: suggests similar provider names for typos" {
	fnox init --force

	# Set up a provider
	cat >fnox.toml <<'EOF'
[providers]
onepassword = { type = "1password", vault = "test" }

[secrets]
MY_SECRET = { provider = "onepasswrd", value = "item" }
EOF

	# Try to get the secret (provider name has typo)
	run fnox get MY_SECRET
	[ "$status" -ne 0 ]
	[[ $output =~ "Did you mean 'onepassword'?" ]]
}

@test "get: suggests provider when using bitwarden typo" {
	fnox init --force

	cat >fnox.toml <<'EOF'
[providers]
bitwarden = { type = "bitwarden" }

[secrets]
MY_SECRET = { provider = "bitwrden", value = "test" }
EOF

	run fnox get MY_SECRET
	[ "$status" -ne 0 ]
	[[ $output =~ "Did you mean 'bitwarden'?" ]]
}

# ============================================================================
# Case insensitive matching
# ============================================================================

@test "get: suggestions are case-insensitive" {
	fnox init --force
	fnox set API_KEY "secret123"

	# Try to get with wrong case
	run fnox get api_key
	[ "$status" -ne 0 ]
	[[ $output =~ "Did you mean 'API_KEY'?" ]]
}
