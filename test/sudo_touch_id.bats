#!/usr/bin/env bats

@test "sudo Touch ID setup preserves rejected configurations" {
	if [ "$EUID" -eq 0 ]; then
		skip "fixture operations are intentionally refused when run as root"
	fi
	run bash "$BATS_TEST_DIRNAME/scripts/sudo-touch-id.sh"
	[ "$status" -eq 0 ]
}
