#!/usr/bin/env bats
#
# Kubernetes Lease Backend Tests
#
# These tests point a kubeconfig at a mock API server to avoid requiring a cluster.

export BATS_NO_PARALLELIZE_WITHIN_FILE=true

setup() {
	load 'test_helper/common_setup'
	_common_setup
	load 'test_helper/mock_server'
	unset KUBECONFIG
}

teardown() {
	stop_mock_server
	_common_teardown
}

start_kube_server() {
	start_mock_server '
def respond(method, path, body):
    parts = path.split("/")
    # /api/v1/namespaces/<ns>/serviceaccounts/<name>/token
    if method == "POST" and path.endswith("/token") and "serviceaccounts" in parts:
        name = parts[parts.index("serviceaccounts") + 1]
        if name == "missing":
            return 404, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "serviceaccounts \"missing\" not found", "reason": "NotFound", "code": 404}
        if name == "forbidden":
            return 403, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "serviceaccounts \"forbidden\" is forbidden: cannot create resource \"serviceaccounts/token\"", "reason": "Forbidden", "code": 403}
        return 201, {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "metadata": {"name": name},
            "spec": {"audiences": ["https://kubernetes.default.svc"], "expirationSeconds": 3600},
            "status": {"token": "k8s-mock-token", "expirationTimestamp": "2099-01-01T00:00:00Z"},
        }
    return 404, {"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": "not found", "code": 404}
'
}

# Write a kubeconfig for the mock server; $1 is the context's default namespace.
write_kubeconfig() {
	cat >"$TEST_TEMP_DIR/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: mock
  cluster:
    server: http://127.0.0.1:$MOCK_PORT
users:
- name: tester
  user:
    token: tester-token
contexts:
- name: mock
  context:
    cluster: mock
    user: tester
    namespace: ${1:-ci}
current-context: mock
EOF
}

write_config() {
	cat >"$FNOX_CONFIG_FILE" <<EOF
root = true

[leases.k8s]
type = "kubernetes"
kubeconfig = "$TEST_TEMP_DIR/kubeconfig"
$1
EOF
}

@test "kubernetes: token is available via fnox exec" {
	start_kube_server
	write_kubeconfig
	write_config 'service_account = "deployer"'

	run fnox exec -- printenv KUBE_TOKEN
	assert_success
	assert_line "k8s-mock-token"
}

@test "kubernetes: custom env_var" {
	start_kube_server
	write_kubeconfig
	write_config 'service_account = "deployer"
env_var = "K8S_TOKEN"'

	run fnox exec -- printenv K8S_TOKEN
	assert_success
	assert_line "k8s-mock-token"
}

@test "kubernetes: defaults to the kubeconfig context's namespace" {
	start_kube_server
	write_kubeconfig team-a
	write_config 'service_account = "deployer"'

	run fnox lease create k8s
	assert_success

	run mock_requests
	assert_output --partial "/api/v1/namespaces/team-a/serviceaccounts/deployer/token"
}

@test "kubernetes: namespace overrides the kubeconfig default" {
	start_kube_server
	write_kubeconfig team-a
	write_config 'service_account = "deployer"
namespace = "prod"'

	run fnox lease create k8s
	assert_success

	run mock_requests
	assert_output --partial "/api/v1/namespaces/prod/serviceaccounts/deployer/token"
}

@test "kubernetes: requests the configured duration and audiences" {
	start_kube_server
	write_kubeconfig
	write_config 'service_account = "deployer"
audiences = ["https://vault.example.com"]
duration = "1h"'

	run fnox lease create k8s
	assert_success

	local body
	body=$(mock_requests | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["body"])')
	run python3 -c '
import json, sys
spec = json.loads(sys.argv[1])["spec"]
assert spec["audiences"] == ["https://vault.example.com"], spec
assert spec["expirationSeconds"] == 3600, spec
' "$body"
	assert_success
}

@test "kubernetes: lease is recorded in ledger" {
	start_kube_server
	write_kubeconfig
	write_config 'service_account = "deployer"'

	run fnox lease create k8s
	assert_success

	run fnox lease list --active
	assert_success
	assert_output --partial "k8s"
}

@test "kubernetes: rejects durations under 10 minutes" {
	start_kube_server
	write_kubeconfig
	write_config 'service_account = "deployer"
duration = "5m"'

	run fnox lease create k8s
	assert_failure
	assert_output --partial "at least 10m"
}

@test "kubernetes: reports a missing ServiceAccount" {
	start_kube_server
	write_kubeconfig
	write_config 'service_account = "missing"'

	run fnox lease create k8s
	assert_failure
	assert_output --partial "not found"
}

@test "kubernetes: reports denied access" {
	start_kube_server
	write_kubeconfig
	write_config 'service_account = "forbidden"'

	run fnox lease create k8s
	assert_failure
	assert_output --partial "serviceaccounts/token"
}
