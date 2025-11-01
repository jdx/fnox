#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "top-level secrets are inherited by all profiles" {
	# Create config with top-level secrets and multiple profiles
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

# Top-level secrets - should be available in all profiles
[secrets.SHARED_API_KEY]
provider = "plain"
value = "top-level-api-key"

[secrets.SHARED_DATABASE_URL]
provider = "plain"
value = "postgres://localhost/default"

# Dev profile doesn't define these secrets, should inherit from top-level
[profiles.dev]

[profiles.dev.providers.plain]
type = "plain"

# Prod profile also inherits top-level secrets
[profiles.prod]

[profiles.prod.providers.plain]
type = "plain"
EOF

	# Get top-level secret from default profile
	run "$FNOX_BIN" get SHARED_API_KEY
	assert_success
	assert_output "top-level-api-key"

	# Get top-level secret from dev profile
	run "$FNOX_BIN" get --profile dev SHARED_API_KEY
	assert_success
	assert_output "top-level-api-key"

	# Get top-level secret from prod profile
	run "$FNOX_BIN" get --profile prod SHARED_DATABASE_URL
	assert_success
	assert_output "postgres://localhost/default"
}

@test "profile-specific secrets override top-level secrets" {
	# Create config where profile overrides top-level secret
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

# Top-level secret
[secrets.DATABASE_URL]
provider = "plain"
value = "postgres://localhost/default"

# Dev profile overrides with its own value
[profiles.dev]

[profiles.dev.providers.plain]
type = "plain"

[profiles.dev.secrets.DATABASE_URL]
provider = "plain"
value = "postgres://dev-server/devdb"

# Prod profile uses top-level value (no override)
[profiles.prod]

[profiles.prod.providers.plain]
type = "plain"
EOF

	# Default profile uses top-level value
	run "$FNOX_BIN" get DATABASE_URL
	assert_success
	assert_output "postgres://localhost/default"

	# Dev profile uses overridden value
	run "$FNOX_BIN" get --profile dev DATABASE_URL
	assert_success
	assert_output "postgres://dev-server/devdb"

	# Prod profile inherits top-level value
	run "$FNOX_BIN" get --profile prod DATABASE_URL
	assert_success
	assert_output "postgres://localhost/default"
}

@test "top-level secrets with different providers per profile" {
	# Set up age keys for different profiles
	AGE_KEY_DEV=$(age-keygen 2>&1 | grep "^AGE-SECRET-KEY" || true)
	AGE_PUB_DEV=$(echo "$AGE_KEY_DEV" | age-keygen -y 2>/dev/null || true)

	AGE_KEY_PROD=$(age-keygen 2>&1 | grep "^AGE-SECRET-KEY" || true)
	AGE_PUB_PROD=$(echo "$AGE_KEY_PROD" | age-keygen -y 2>/dev/null || true)

	# Create config with top-level secrets but different encryption keys per profile
	cat >fnox.toml <<EOF
root = true

[providers.age]
type = "age"
recipients = ["$AGE_PUB_DEV"]

# Top-level secrets defined once with age provider reference
[secrets.ENCRYPTED_SECRET]
provider = "age"
value = "-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBmTExaeVp0VzdYT2RGbUtm\nCkZPdzZWZ2JJSENOZDdRU1NlTXJUUmY5RUVBCi0tLSBRTWhZZ1BqMFJkcjgyMHpi\nOVJRb0JPeU0wQ0c4VXBEOG1OY2JDQUNBWUE4ClNvbWVFbmNyeXB0ZWRWYWx1ZQ==\n-----END AGE ENCRYPTED FILE-----"

# Dev profile with its own age provider config
[profiles.dev]

[profiles.dev.providers.age]
type = "age"
recipients = ["$AGE_PUB_DEV"]

# Prod profile with different age key
[profiles.prod]

[profiles.prod.providers.age]
type = "age"
recipients = ["$AGE_PUB_PROD"]
EOF

	# The secret should be accessible from both profiles
	# (This will use the encrypted value from top-level, but with profile-specific decryption)

	# List should show the inherited secret in both profiles
	run "$FNOX_BIN" list --profile dev
	assert_success
	assert_output --partial "ENCRYPTED_SECRET"

	run "$FNOX_BIN" list --profile prod
	assert_success
	assert_output --partial "ENCRYPTED_SECRET"
}

@test "list shows both top-level and profile-specific secrets" {
	# Create config with mix of top-level and profile secrets
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

# Top-level secrets
[secrets.SHARED_SECRET]
provider = "plain"
value = "shared-value"

[secrets.ANOTHER_SHARED]
provider = "plain"
value = "another-shared-value"

# Dev profile with additional secrets
[profiles.dev]

[profiles.dev.providers.plain]
type = "plain"

[profiles.dev.secrets.DEV_ONLY_SECRET]
provider = "plain"
value = "dev-only-value"
EOF

	# Default profile shows only top-level secrets
	run "$FNOX_BIN" list --complete
	assert_success
	assert_line "SHARED_SECRET"
	assert_line "ANOTHER_SHARED"
	refute_output --partial "DEV_ONLY_SECRET"

	# Dev profile shows both inherited and profile-specific secrets
	run "$FNOX_BIN" list --profile dev --complete
	assert_success
	assert_line "SHARED_SECRET"
	assert_line "ANOTHER_SHARED"
	assert_line "DEV_ONLY_SECRET"
}

@test "export includes top-level secrets in profiles" {
	# Create config with top-level secrets
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

# Top-level secrets
[secrets.SHARED_VAR]
provider = "plain"
value = "shared-value"

# Dev profile
[profiles.dev]

[profiles.dev.providers.plain]
type = "plain"

[profiles.dev.secrets.DEV_VAR]
provider = "plain"
value = "dev-value"
EOF

	# Export from dev profile should include both
	run "$FNOX_BIN" export --profile dev --format env
	assert_success
	assert_output --partial "export SHARED_VAR='shared-value'"
	assert_output --partial "export DEV_VAR='dev-value'"
}

@test "top-level secrets work with exec command" {
	# Create config with top-level secret
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets.EXEC_TEST_VAR]
provider = "plain"
value = "exec-test-value"

[profiles.dev]

[profiles.dev.providers.plain]
type = "plain"
EOF

	# Test exec in default profile
	# shellcheck disable=SC2016 # Single quotes intentional - variable should expand in subshell
	run "$FNOX_BIN" exec -- sh -c 'echo $EXEC_TEST_VAR'
	assert_success
	assert_output "exec-test-value"

	# Test exec in dev profile (should inherit)
	# shellcheck disable=SC2016 # Single quotes intentional - variable should expand in subshell
	run "$FNOX_BIN" exec --profile dev -- sh -c 'echo $EXEC_TEST_VAR'
	assert_success
	assert_output "exec-test-value"
}
