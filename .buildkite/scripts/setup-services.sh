#!/usr/bin/env bash
# Bring up every external service the bats suite needs:
#   - gnome-keyring (Linux only) for keychain tests
#   - vaultwarden  (Linux only, via Docker) for Bitwarden tests
#   - HashiCorp Vault (Linux: Docker, macOS: dev mode) for Vault tests
#   - Self-hosted Infisical (Linux only, via docker compose) for Infisical tests
#   - LocalStack (Linux only) for AWS provider + STS-lease tests
#   - Bitwarden CLI session
#   - Infisical CLI + service token
#
# Anything that fails to provision is allowed to short-circuit — the bats
# suite skips tests whose dependent env vars are unset.
set -euo pipefail

# Append "export NAME=VALUE" to BUILDKITE_ENV_FILE, escaping VALUE so values
# containing whitespace or shell metacharacters survive the agent re-reading
# the env file in a fresh shell.
append_env() {
	printf 'export %s=%q\n' "$1" "$2" >>"$BUILDKITE_ENV_FILE"
	export "$1=$2"
}

case "$(uname -s)" in
Linux)
	# gnome-keyring + D-Bus setup is shared with ci-other; sourcing keeps
	# DBUS_SESSION_BUS_ADDRESS in this shell's env for any later use.
	# shellcheck source=/dev/null
	source "$(dirname "$0")/setup-keychain.sh"

	sudo apt-get install -y parallel openssl awscli

	# Vaultwarden with HTTPS (self-signed). Don't swallow openssl errors —
	# without certs the vaultwarden container fails to start later with a
	# much less obvious error.
	mkdir -p /tmp/vaultwarden-certs
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout /tmp/vaultwarden-certs/key.pem \
		-out /tmp/vaultwarden-certs/cert.pem \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

	# Clear stale containers from prior runs on persistent agents — fixed
	# names and ports collide otherwise.
	docker rm -f vaultwarden vault localstack 2>/dev/null || true

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

	# LocalStack for AWS provider tests (STS leases, KMS, Secrets Manager,
	# Parameter Store). Without this the aws-* bats tests skip silently.
	docker run -d --name localstack \
		-p 4566:4566 \
		-e SERVICES=sts,iam,kms,secretsmanager,ssm \
		localstack/localstack:4

	# Wait for LocalStack to be healthy (cold pulls take 10–30s).
	for _i in $(seq 1 30); do
		curl -sf http://localhost:4566/_localstack/health >/dev/null && break
		sleep 2
	done

	# Wait for Vault to be ready.
	for _i in $(seq 1 15); do
		curl -sf http://localhost:8200/v1/sys/health >/dev/null && break
		sleep 1
	done

	# Wait for Vaultwarden to be ready (TLS, self-signed → -k).
	for _i in $(seq 1 15); do
		curl -skf https://localhost:8080/alive >/dev/null && break
		sleep 1
	done

	# Provision LocalStack resources expected by the AWS bats tests.
	export AWS_ACCESS_KEY_ID=test
	export AWS_SECRET_ACCESS_KEY=test
	export AWS_DEFAULT_REGION=us-east-1
	LOCALSTACK_KMS_KEY_ID=$(aws --endpoint-url http://localhost:4566 kms create-key \
		--region us-east-1 --query 'KeyMetadata.KeyId' --output text)
	aws --endpoint-url http://localhost:4566 kms create-alias \
		--alias-name alias/fnox-testing \
		--target-key-id "$LOCALSTACK_KMS_KEY_ID" \
		--region us-east-1
	aws --endpoint-url http://localhost:4566 secretsmanager create-secret \
		--name "fnox/test-secret" \
		--secret-string "This is a test secret in AWS Secrets Manager!" \
		--region us-east-1

	append_env VAULT_ADDR "http://localhost:8200"
	append_env VAULT_TOKEN "fnox-test-token"
	append_env LOCALSTACK_ENDPOINT "http://localhost:4566"
	append_env AWS_ACCESS_KEY_ID "test"
	append_env AWS_SECRET_ACCESS_KEY "test"
	append_env AWS_DEFAULT_REGION "us-east-1"

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
