---
description: "Read named Kubernetes Secret data through the Kubernetes API without listing, watching, or changing Secrets."
---

# Kubernetes Secrets

The Kubernetes provider reads existing core/v1 `Secret` objects through the Kubernetes API. It is read-only: `fnox set` cannot create or update Secrets, and the provider never lists, watches, or deletes them. A resolution performs a named `GET` for each distinct namespace and Secret name requested by your fnox configuration.

## Configuration

```toml
[providers.kubernetes]
type = "kubernetes"
context = "production"             # optional
namespace = "payments"              # optional
kubeconfig = "./ops/kubeconfig"     # optional; relative to this fnox.toml
prefix = "myapp-"                   # optional; applies only to Secret names

[secrets]
DATABASE_URL = { provider = "kubernetes", value = "database/url" }
API_TOKEN = { provider = "kubernetes", value = "payments/api/token" }
```

`kubeconfig` selects one explicit file. A relative path is resolved against the fnox config file that declares the provider. Treat that file as trusted: Kubernetes kubeconfigs can reference credential plugins and other executable material.

Context selection is deterministic:

1. The provider's `context` field wins.
2. If it is absent, `FNOX_K8S_CONTEXT` is used when set.
3. Otherwise, the kubeconfig current context is used.

When `kubeconfig` is set, fnox reads only that file. When a context is set without `kubeconfig`, fnox reads the standard Kubernetes kubeconfig source (`KUBECONFIG`, then `~/.kube/config`). A selected context must be present there; fnox does not silently fall back to in-cluster credentials in that case.

With neither `context` nor `kubeconfig`, a non-empty `KUBECONFIG` is treated as explicit: fnox loads it through the standard kubeconfig loader and returns an error if it cannot be read. It does not then fall back to an in-cluster identity. When `KUBECONFIG` is unset or empty, fnox follows Kubernetes client inference: it tries the standard local kubeconfig first, then in-cluster service-account authentication. The in-cluster namespace comes from the mounted service-account namespace file. `namespace` in the fnox provider overrides the context or in-cluster default, and a namespace in an individual secret reference overrides both.

## References

Use one of these forms in a secret's `value`:

| Value                  | Meaning                                                 |
| ---------------------- | ------------------------------------------------------- |
| `secret`               | The sole data key in `secret` in the selected namespace |
| `secret/key`           | Data key `key` in `secret` in the selected namespace    |
| `namespace/secret/key` | Data key `key` in `secret` in the named namespace       |

For a Secret with more than one data key, select the key explicitly. `prefix` applies only to the Secret name, never to the namespace or data key: with `prefix = "myapp-"`, `payments/api/token` reads Secret `myapp-api`, key `token`, in namespace `payments`.

Kubernetes stores `data` as base64-encoded bytes in the API. fnox decodes those bytes and accepts only valid UTF-8 text values. Binary Secret values return an error without printing the value.

## Authentication and RBAC

Authentication comes from the selected kubeconfig or Kubernetes in-cluster service account. fnox does not shell out to `kubectl` and does not add an `auth_command` default. Use a trusted kubeconfig and the authentication mechanism approved for that cluster.

Grant the smallest possible permission: `get` on the named Secret objects that fnox references. Avoid `list` and `watch`; both can expose all Secret data in a namespace.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: payments
  name: fnox-read-secrets
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["myapp-database", "myapp-api"]
    verbs: ["get"]
```

A `401` or `403` is reported as an authentication/authorization failure with an RBAC hint. A missing Secret returns a not-found error. API error messages, kubeconfig contents, credentials, and Secret values are not included in fnox errors.

`fnox provider test kubernetes` only verifies that client configuration can be loaded. It intentionally does not query, list, or watch Secrets. Use `fnox check` to verify the configured Secret references with your intended identity.

## Caching and sync

The fnox daemon’s in-memory cache is forcibly disabled for Kubernetes Secrets in this initial release. Setting `daemon_cache = true` cannot re-enable it, preventing accidental reuse across changing kubeconfig targets or contexts.

[`fnox sync`](/guide/sync) can still create an encrypted local snapshot using your configured local encryption provider. That snapshot is persistent and can become stale after a Secret rotation, namespace/context change, or RBAC change; run `fnox sync` again whenever the source changes. Kubernetes remains the source of truth.
