#!/usr/bin/env bats
#
# Tera templates in config values. Strings containing `{{` or `{%` are rendered
# with the active profile selection; the profile is never exported to children.
#

setup() {
	load 'test_helper/common_setup'
	_common_setup

	# root = true stops config recursion into parent directories (the test
	# temp dir lives inside the fnox repo, which has its own fnox.toml)
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
AWS_PROFILE = { default = "{{ fnox.profile }}" }
SST_STAGE = { default = "stage-{{ fnox.profile }}" }
LITERAL = { default = "{% raw %}{{ keep }}{% endraw %}" }
PLAIN_DOLLAR = { default = "${AWS_PROFILE}-x" }

[profiles.staging.secrets]
EXTRA = { provider = "plain", value = "extra" }

[profiles.prod.secrets]
EXTRA = { provider = "plain", value = "extra" }
EOF
}

teardown() {
	_common_teardown
}

@test "template renders the profile selected with --profile" {
	run "$FNOX_BIN" get AWS_PROFILE --profile staging
	assert_success
	assert_output "staging"
}

@test "template renders the profile selected with FNOX_PROFILE" {
	FNOX_PROFILE=prod run "$FNOX_BIN" get AWS_PROFILE
	assert_success
	assert_output "prod"
}

@test "template uses the default profile when none is selected" {
	run "$FNOX_BIN" get SST_STAGE
	assert_success
	assert_output "stage-default"
}

@test "template output feeds secret interpolation" {
	run "$FNOX_BIN" get PLAIN_DOLLAR --profile staging
	assert_success
	assert_output "staging-x"
}

@test "raw block keeps literal template markers" {
	run "$FNOX_BIN" get LITERAL
	assert_success
	assert_output "{{ keep }}"
}

@test "--profile does not export FNOX_PROFILE to exec children" {
	run env -u FNOX_PROFILE "$FNOX_BIN" exec --profile staging -- sh -c 'echo "profile=${FNOX_PROFILE:-unset} aws=$AWS_PROFILE"'
	assert_success
	assert_output "profile=unset aws=staging"
}

@test "undefined template variable names the secret" {
	cat >fnox.toml <<'EOF'
root = true

[providers.plain]
type = "plain"

[secrets]
BAD = { default = "{{ nope }}" }
EOF
	run "$FNOX_BIN" get BAD
	assert_failure
	assert_output --partial "default of secret 'BAD'"
}
