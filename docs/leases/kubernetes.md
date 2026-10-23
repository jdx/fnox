---
description: "Request short-lived, audience-bound Kubernetes ServiceAccount tokens with fnox through the TokenRequest API, using your kubeconfig and no kubectl."
---

# Kubernetes

The `kubernetes` lease backend asks the API server for a short-lived [ServiceAccount token](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/) with the TokenRequest API and injects it into `fnox exec`. It talks to the cluster directly, so `kubectl` is not required.

|              |                                                                                     |
| ------------ | ----------------------------------------------------------------------------------- |
| Config type  | `kubernetes`                                                                        |
| Produces     | `KUBE_TOKEN` (configurable with `env_var`)                                          |
| Max duration | 24 hours requested; at least 10 minutes. The API server may grant less.             |
| Revocation   | None; the token expires on its own                                                  |
| Needs        | A kubeconfig (or in-cluster identity) that may create tokens for the ServiceAccount |

## Quick start

```toml
[leases.deploy]
type = "kubernetes"
service_account = "deployer"
namespace = "ci"
duration = "1h"
```

```sh
fnox exec -- sh -c 'kubectl --token "$KUBE_TOKEN" -n ci get pods'
```

The command acts as the `deployer` ServiceAccount, not as you, and only until the token expires. fnox records the expiry the API server reports and reuses the token until it is about to expire.

## Bootstrap credentials

fnox connects the way the [Kubernetes Secrets provider](/providers/kubernetes) does: the `kubeconfig` and `context` fields if set, otherwise `KUBECONFIG` and the current context, otherwise the in-cluster service account. An explicit `KUBECONFIG` that cannot be loaded is an error rather than a fallback to another cluster.

The identity needs the `create` verb on `serviceaccounts/token` for the named ServiceAccount, and nothing else:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployer-token
  namespace: ci
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    resourceNames: ["deployer"]
    verbs: ["create"]
```

## Configuration

| Field             | Required | Default                             | Description                                                                 |
| ----------------- | -------- | ----------------------------------- | --------------------------------------------------------------------------- |
| `service_account` | Yes      | none                                | Name of the ServiceAccount to issue a token for.                            |
| `namespace`       | No       | the kubeconfig context's namespace  | Namespace of the ServiceAccount.                                            |
| `audiences`       | No       | the API server's default audience   | Audiences the token is valid for, such as `["https://vault.example.com"]`.  |
| `context`         | No       | the current context                 | kubeconfig context to use.                                                  |
| `kubeconfig`      | No       | `KUBECONFIG`, then `~/.kube/config` | Path to a kubeconfig file.                                                  |
| `env_var`         | No       | `"KUBE_TOKEN"`                      | Variable that receives the token.                                           |
| `duration`        | No       | `"15m"`                             | Requested lifetime, between `"10m"` and `"24h"`. The API server may cap it. |

With `audiences`, the token is only accepted by services that expect one of those audiences, which makes it suitable for authenticating to Vault, AWS or other systems that trust the cluster's OIDC issuer.

## Troubleshooting

### Kubernetes tokens must last at least 10m

The API server rejects TokenRequests shorter than 10 minutes. Raise `duration`, which defaults to `"15m"`.

### Unable to load Kubernetes client configuration

fnox found no usable kubeconfig, context or in-cluster identity. Check `kubeconfig`, `context` and `KUBECONFIG`.

### HTTP 401 or 403

The identity may not create tokens for that ServiceAccount. Grant `create` on `serviceaccounts/token`, as shown above.

### HTTP 404

The ServiceAccount does not exist in `namespace`. When `namespace` is unset, fnox uses the kubeconfig context's namespace, which may not be the one you expect.

### A shorter token than requested

The API server enforces its own maximum, so the lifetime is whatever it reports. fnox uses that expiry.

## See also

- [Credential leases](/guide/leases): how leases are cached and reused.
- [Kubernetes Secrets](/providers/kubernetes): read Secret values with the same connection settings.
- [Custom command](/leases/command): wrap `kubectl create token` or another API with your own script.
