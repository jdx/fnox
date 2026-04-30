#!/usr/bin/env bash
# Bring up gnome-keyring on Linux agents so the keychain provider tests
# can read/write/delete entries. macOS uses the built-in Keychain.
set -euo pipefail

case "$(uname -s)" in
Linux)
	sudo apt-get update
	sudo apt-get install -y gnome-keyring libsecret-tools dbus-x11

	mkdir -p ~/.dbus-session
	dbus-daemon --session --fork --print-address=1 >~/.dbus-session/bus-address
	DBUS_SESSION_BUS_ADDRESS=$(cat ~/.dbus-session/bus-address)
	export DBUS_SESSION_BUS_ADDRESS
	buildkite-agent meta-data set "DBUS_SESSION_BUS_ADDRESS" "$DBUS_SESSION_BUS_ADDRESS" || true
	echo "export DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS" >>"$BUILDKITE_ENV_FILE"

	echo "foobar" | gnome-keyring-daemon --unlock --components=secrets --daemonize
	;;
Darwin)
	: # macOS keychain is already available
	;;
*)
	echo "Unsupported OS: $(uname -s)"
	exit 1
	;;
esac
