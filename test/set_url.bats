#!/usr/bin/env bats

setup() {
	load 'test_helper/common_setup'
	_common_setup
}

teardown() {
	_common_teardown
}

@test "fnox set --url records the url without asking for a value" {
	echo "root = true" >"${FNOX_CONFIG_FILE:-fnox.toml}"

	assert_fnox_success set GITHUB_TOKEN --url "https://github.com/settings/tokens" </dev/null
	run grep 'url = "https://github.com/settings/tokens"' "${FNOX_CONFIG_FILE:-fnox.toml}"
	assert_success
}

@test "fnox set --url rejects non-http schemes" {
	echo "root = true" >"${FNOX_CONFIG_FILE:-fnox.toml}"

	assert_fnox_failure set GITHUB_TOKEN --url "file:///etc/passwd" </dev/null
	assert_output --partial "http"
}

@test "config with a non-http url is rejected" {
	cat >"${FNOX_CONFIG_FILE:-fnox.toml}" <<EOF
root = true

[secrets.TOKEN]
default = "x"
url = "javascript:alert(1)"
EOF

	assert_fnox_failure list
}

@test "fnox set --open conflicts with an explicit value" {
	echo "root = true" >"${FNOX_CONFIG_FILE:-fnox.toml}"

	assert_fnox_failure set TOKEN value --open
}

@test "fnox set --open with --url still requires a terminal for the value" {
	echo "root = true" >"${FNOX_CONFIG_FILE:-fnox.toml}"

	assert_fnox_failure set TOKEN --url "https://example.com/tokens" --open </dev/null
	assert_output --partial "interactive terminal"
}
