#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test 'profile inherits ordered secrets and providers' {
	cat >fnox.toml <<'EOF'
root = true

[profiles.openai]
default_provider = "plain"

[profiles.openai.providers.plain]
type = "plain"

[profiles.openai.secrets]
OPENAI_API_KEY = { provider = "plain", value = "shared-key" }
SHARED = { default = "openai" }

[profiles.database-local.secrets]
DATABASE_PASSWORD = { default = "local-password" }
INHERITED_DEFAULT_PROVIDER = { value = "plain-value" }
SHARED = { default = "database" }

[profiles.api-local]
inherits = ["openai", "database-local"]

[profiles.api-local.secrets]
APP_ONLY = { default = "app" }
SHARED = { default = "app" }
EOF

	run "$FNOX_BIN" -P api-local --no-defaults get OPENAI_API_KEY
	assert_success
	assert_output 'shared-key'

	run "$FNOX_BIN" -P api-local --no-defaults get DATABASE_PASSWORD
	assert_success
	assert_output 'local-password'

	run "$FNOX_BIN" -P api-local --no-defaults get INHERITED_DEFAULT_PROVIDER
	assert_success
	assert_output 'plain-value'

	run "$FNOX_BIN" -P api-local --no-defaults get SHARED
	assert_success
	assert_output 'app'
}

@test 'profile inheritance is nested and later profiles override earlier profiles' {
	cat >fnox.toml <<'EOF'
root = true

[profiles.openai.secrets]
OPENAI_API_KEY = { default = "shared" }

[profiles.database-local.secrets]
DATABASE_PASSWORD = { default = "local" }

[profiles.api-local]
inherits = ["openai", "database-local"]

[profiles.openai-john.secrets]
OPENAI_API_KEY = { default = "john" }

[profiles.api-local-john]
inherits = ["api-local", "openai-john"]
EOF

	run "$FNOX_BIN" -P api-local-john --no-defaults export --format json
	assert_success
	assert_output --partial '"OPENAI_API_KEY": "john"'
	assert_output --partial '"DATABASE_PASSWORD": "local"'
}

@test 'profile inheritance loads inherited profile-specific files' {
	cat >fnox.toml <<'EOF'
root = true

[profiles.source]

[profiles.app]
inherits = ["source"]
EOF

	cat >fnox.source.toml <<'EOF'
[secrets]
SOURCE_ONLY = { default = "from-profile-file" }
EOF

	run "$FNOX_BIN" -P app get SOURCE_ONLY
	assert_success
	assert_output 'from-profile-file'
}

@test 'profile inheritance reports unknown profiles' {
	cat >fnox.toml <<'EOF'
root = true

[profiles.app]
inherits = ["missing"]
EOF

	run "$FNOX_BIN" -P app list
	assert_failure
	assert_output --partial "Profile 'missing' not found"
}

@test 'profile inheritance reports cycles' {
	cat >fnox.toml <<'EOF'
root = true

[profiles.a]
inherits = ["b"]

[profiles.b]
inherits = ["a"]
EOF

	run "$FNOX_BIN" -P a list
	assert_failure
	assert_output --partial 'Profile inheritance cycle detected: a -> b -> a'
}
