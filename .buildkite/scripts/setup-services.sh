#!/usr/bin/env bash
# Bring up every external service the bats suite needs:
#   - gnome-keyring (Linux only) for keychain tests
#   - vaultwarden  (Linux only, via Docker) for Bitwarden tests
#   - HashiCorp Vault (Linux: Docker, macOS: dev mode) for Vault tests
#   - Self-hosted Infisical (Linux only, via docker compose) for Infisical tests
#   - Bitwarden CLI session
#   - Infisical CLI + service token
#
# Anything that fails to provision is allowed to short-circuit — the bats
# suite skips tests whose dependent env vars are unset.
set -euo pipefail

# shellcheck source=/dev/null
append_env() {
	echo "export $1=${2}" >>"$BUILDKITE_ENV_FILE"
	export "$1=$2"
}

case "$(uname -s)" in
Linux)
	sudo apt-get update
	sudo apt-get install -y parallel gnome-keyring libsecret-tools dbus-x11

	mkdir -p ~/.dbus-session
	dbus-daemon --session --fork --print-address=1 >~/.dbus-session/bus-address
	append_env DBUS_SESSION_BUS_ADDRESS "$(cat ~/.dbus-session/bus-address)"

	echo "foobar" | gnome-keyring-daemon --unlock --components=secrets --daemonize

	# Vaultwarden with HTTPS (self-signed)
	mkdir -p /tmp/vaultwarden-certs
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout /tmp/vaultwarden-certs/key.pem \
		-out /tmp/vaultwarden-certs/cert.pem \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null || true

	docker run -d --name vaultwarden \
		-p 8080:80 \
		-e DOMAIN=https://localhost:8080 \
		-e SIGNUPS_ALLOWED=true \
		-e DISABLE_ADMIN_TOKEN=true \
		-e I_REALLY_WANT_VOLATILE_STORAGE=true \
		-e ROCKET_TLS='{certs="/data/certs/cert.pem",key="/data/certs/key.pem"}' \
		-v /tmp/vaultwarden-certs:/data/certs:ro \
		vaultwarden/server:latest

	docker run -d --name vault --cap-add=IPC_LOCK \
		-p 8200:8200 \
		-e VAULT_DEV_ROOT_TOKEN_ID=fnox-test-token \
		-e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
		-e VAULT_ADDR=http://127.0.0.1:8200 \
		hashicorp/vault:latest

	docker compose -f test/docker-compose.infisical-ci.yml up -d

	sleep 5

	append_env VAULT_ADDR "http://localhost:8200"
	append_env VAULT_TOKEN "fnox-test-token"

	# Bitwarden session
	# shellcheck source=/dev/null
	source ./test/setup-bitwarden-ci.sh
	append_env BW_SESSION "$BW_SESSION"

	# Infisical CLI
	curl -1sLf 'https://artifacts-cli.infisical.com/setup.deb.sh' | sudo -E bash
	sudo apt-get update
	sudo apt-get install -y infisical

	# shellcheck source=/dev/null
	source ./test/setup-infisical-ci.sh
	append_env INFISICAL_TOKEN "$INFISICAL_TOKEN"
	append_env INFISICAL_CLIENT_ID "$INFISICAL_CLIENT_ID"
	append_env INFISICAL_CLIENT_SECRET "$INFISICAL_CLIENT_SECRET"
	append_env INFISICAL_PROJECT_ID "$INFISICAL_PROJECT_ID"
	append_env INFISICAL_API_URL "http://localhost:8081/api"
	;;

Darwin)
	if ! command -v parallel >/dev/null 2>&1; then
		brew install parallel
	fi
	if ! command -v vault >/dev/null 2>&1; then
		brew install vault
	fi

	vault server -dev \
		-dev-root-token-id=fnox-test-token \
		-dev-listen-address=127.0.0.1:8200 &

	append_env VAULT_ADDR "http://127.0.0.1:8200"
	append_env VAULT_TOKEN "fnox-test-token"

	sleep 2
	;;

*)
	echo "Unsupported OS: $(uname -s)"
	exit 1
	;;
esac
