#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup --git
}

teardown() {
	_common_teardown
}

@test "fnox scan passes when no secrets are found" {
	echo 'name = "fnox"' >safe.toml

	assert_fnox_success scan
	assert_output --partial "No potential secrets found"
}

@test "fnox scan fails when known token is found" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env

	assert_fnox_failure scan
	assert_output --partial "github-token"
	assert_output --partial "secrets.env"
}

@test "fnox scan redacts secret values" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env

	assert_fnox_failure scan
	assert_output --partial "ghp_"
	refute_output --partial "abcdefghijklmnopqrstuvwxyz123456"
}

@test "fnox scan quiet prints only affected files" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env
	echo 'name = "fnox"' >safe.toml

	run bash -c '"$1" scan --quiet 2>/dev/null' _ "$FNOX_BIN"
	assert_failure
	assert_output "secrets.env"
}

@test "fnox scan quiet json prints affected files as json" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env
	echo 'name = "fnox"' >safe.toml

	run bash -c '"$1" scan --quiet --format json 2>/dev/null' _ "$FNOX_BIN"
	assert_failure
	echo "$output" | /usr/bin/python3 -m json.tool >/dev/null
	assert_output --partial '"secrets.env"'
	refute_output --partial '"findings"'
}

@test "fnox scan json emits parseable findings and summary" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env

	run bash -c '"$1" scan --format json 2>/dev/null' _ "$FNOX_BIN"
	assert_failure
	echo "$output" | /usr/bin/python3 -m json.tool >/dev/null
	assert_output --partial '"findings"'
	assert_output --partial '"summary"'
	assert_output --partial '"detector": "github-token"'
}

@test "fnox scan human output uses lowercase severity" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >secrets.env

	assert_fnox_failure scan
	assert_output --partial "[github-token high]"
	refute_output --partial "[github-token High]"
}

@test "fnox scan accepts positional directory" {
	mkdir -p src
	echo 'password = "abc12345!"' >src/config.env

	assert_fnox_failure scan src
	assert_output --partial "src/config.env"
}

@test "fnox scan ignore suppresses matching files" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >ignored.env

	assert_fnox_success scan --ignore ignored.env
	assert_output --partial "No potential secrets found"
}

@test "fnox scan skips vcs build and vendor directories" {
	mkdir -p .git target node_modules vendor dist build
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >.git/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >target/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >node_modules/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >vendor/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >dist/secrets.env
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >build/secrets.env
	echo 'name = "fnox"' >safe.toml

	assert_fnox_success scan
	assert_output --partial "No potential secrets found"
}

@test "fnox scan includes hidden files" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >.env

	assert_fnox_failure scan
	assert_output --partial ".env"
}

@test "fnox scan does not skip files named like excluded directories" {
	echo 'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"' >build

	assert_fnox_failure scan
	assert_output --partial "build"
}

_write_values_config() {
	cat >fnox.toml <<'TOML'
[providers.plain]
type = "plain"

[secrets.DB_PASSWORD]
provider = "plain"
value = "hunter2-correct-horse-battery"

[secrets.SHORT]
provider = "plain"
value = "abc"
TOML
}

@test "fnox scan --values reports resolved values by name without printing them" {
	_write_values_config
	echo 'db = "hunter2-correct-horse-battery"' >app.env
	echo 'x = "abc"' >short.env

	run "$FNOX_BIN" scan --values --ignore fnox.toml
	assert_failure
	assert_output --partial "app.env:1"
	assert_output --partial "DB_PASSWORD"
	refute_output --partial "hunter2"
	refute_output --partial "short.env"
}

@test "fnox scan --values passes when no value is present" {
	_write_values_config
	echo 'nothing here' >app.env

	run "$FNOX_BIN" scan --values --ignore fnox.toml
	assert_success
}

@test "fnox scan --values --staged reads the index, not the working tree" {
	_write_values_config
	echo 'db = "hunter2-correct-horse-battery"' >app.env
	git add app.env
	echo 'clean' >app.env

	run "$FNOX_BIN" scan --values --staged
	assert_failure
	assert_output --partial "app.env:1"
	refute_output --partial "hunter2"
}

@test "fnox scan --values skips gitignored files unless --include-ignored" {
	_write_values_config
	echo 'ignored.env' >.gitignore
	echo 'db = "hunter2-correct-horse-battery"' >ignored.env

	run "$FNOX_BIN" scan --values --ignore fnox.toml
	assert_success
	run "$FNOX_BIN" scan --values --include-ignored --ignore fnox.toml
	assert_failure
	assert_output --partial "ignored.env"
}

@test "fnox scan --install-hook installs a hook that blocks commits with secrets" {
	_write_values_config
	run "$FNOX_BIN" scan --install-hook
	assert_success
	assert_file_executable .git/hooks/pre-commit

	PATH="$(dirname "$FNOX_BIN"):$PATH"
	export PATH
	echo 'db = "hunter2-correct-horse-battery"' >app.env
	git add app.env
	run git commit -m "leak"
	assert_failure
	assert_output --partial "DB_PASSWORD"

	git rm -q --cached app.env
	echo 'fine' >ok.txt
	git add ok.txt
	run git commit -m "ok"
	assert_success
}

@test "fnox scan --install-hook respects core.hooksPath and does not clobber hooks" {
	mkdir -p .githooks
	git config core.hooksPath .githooks
	printf '#!/bin/sh\necho mine\n' >.githooks/pre-commit

	run "$FNOX_BIN" scan --install-hook
	assert_failure
	assert_output --partial "--append"
	run cat .githooks/pre-commit
	refute_output --partial "fnox scan"

	run "$FNOX_BIN" scan --install-hook --append
	assert_success
	run cat .githooks/pre-commit
	assert_output --partial "echo mine"
	assert_output --partial "fnox scan --values --staged"
	assert_not_exists .git/hooks/pre-commit
}

@test "fnox scan --install-hook --append keeps a failing earlier hook failing" {
	printf '#!/bin/sh\nfalse\n' >.git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit

	run "$FNOX_BIN" scan --install-hook --append
	assert_success

	run .git/hooks/pre-commit
	assert_failure
}
