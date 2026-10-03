#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "discovers project .config configs through parent directories" {
	mkdir -p project/.config project/service/child
	cat >project/.config/fnox.toml <<'EOF'
[secrets]
PROJECT_SECRET = { default = "project-value" }
EOF

	cd project/service/child

	run "$FNOX_BIN" get PROJECT_SECRET
	assert_success
	assert_output "project-value"

	run "$FNOX_BIN" config-files
	assert_success
	assert_output --partial "project/.config/fnox.toml"
}

@test "project .config files override root and hidden configs at the same level" {
	mkdir -p .config
	cat >fnox.toml <<'EOF'
[secrets]
VALUE = { default = "root" }
EOF
	cat >.fnox.toml <<'EOF'
[secrets]
VALUE = { default = "hidden" }
EOF
	cat >.config/fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
VALUE = { default = "config-dir" }
EOF

	assert_fnox_success get VALUE
	assert_output "config-dir"
}

@test "project .config imports resolve relative to the config directory" {
	mkdir -p .config
	cat >.config/shared.toml <<'EOF'
[secrets]
IMPORTED_SECRET = { default = "imported-value" }
EOF
	cat >.config/fnox.toml <<'EOF'
root = true
import = ["./shared.toml"]

[providers.plain]
type = "plain"
EOF

	assert_fnox_success get IMPORTED_SECRET
	assert_output "imported-value"
}

@test "project .config supports profile and local overlays" {
	mkdir -p .config
	cat >.config/fnox.toml <<'EOF'
[secrets]
VALUE = { default = "base" }
EOF
	cat >.config/fnox.staging.toml <<'EOF'
[secrets]
VALUE = { default = "profile" }
EOF
	cat >.config/fnox.local.toml <<'EOF'
[profiles.staging.secrets]
VALUE = { default = "local" }
EOF

	assert_fnox_success --profile staging get VALUE
	assert_output "local"
}

@test "project .config root stops parent traversal" {
	mkdir -p parent/.config parent/child
	cat >fnox.toml <<'EOF'
[secrets]
PARENT_SECRET = { default = "parent-value" }
EOF
	cat >parent/.config/fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
PROJECT_SECRET = { default = "project-value" }
EOF

	cd parent/child
	assert_fnox_success get PROJECT_SECRET
	run "$FNOX_BIN" get PARENT_SECRET
	assert_failure
	assert_output --partial "not found"
}

@test "set writes to an existing project .config config" {
	mkdir -p .config
	printf '[secrets]\n' >.config/fnox.toml

	assert_fnox_success set PROJECT_SECRET project-value
	assert_file_contains .config/fnox.toml 'PROJECT_SECRET'
	[[ ! -e fnox.toml ]]
}

@test "sync local-file writes alongside a discovered project .config config" {
	if ! command -v age-keygen >/dev/null 2>&1; then
		skip "age-keygen not installed"
	fi

	age-keygen -o key.txt >/dev/null
	local public_key
	public_key=$(age-keygen -y key.txt)
	export FNOX_AGE_KEY
	FNOX_AGE_KEY=$(grep '^AGE-SECRET-KEY' key.txt)

	mkdir -p .config
	cat >.config/fnox.toml <<EOF
[providers.age]
type = "age"
recipients = ["$public_key"]

[providers.source-age]
type = "age"
recipients = ["$public_key"]
EOF

	assert_fnox_success set PROJECT_SECRET project-value --provider source-age
	assert_fnox_success sync --local-file --provider age --force
	assert_file_exists .config/fnox.local.toml
}

@test "init creates a requested project .config config" {
	assert_fnox_success --config .config/fnox.toml init
	assert_file_exists .config/fnox.toml
}
