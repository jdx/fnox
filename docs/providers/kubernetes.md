---
description: "Read named Kubernetes Secret data with fnox through the Kubernetes API, using a kubeconfig or in-cluster service account and get-only RBAC."
---

# Kubernetes Secrets

Read existing core/v1 `Secret` objects through the Kubernetes API. `fnox.toml` holds Secret names and data keys; values stay in the cluster. The provider is read-only: `fnox set` cannot create or update Secrets, and fnox never lists, watches or deletes them.

|                     |                                                                      |
| ------------------- | -------------------------------------------------------------------- |
| Config type         | `kubernetes`                                                         |
| Storage             | Remote service (Kubernetes API)                                      |
| Writes (`fnox set`) | No (read-only)                                                       |
| Requires            | A kubeconfig or in-cluster service account with `get` on the Secrets |

## Quick start

With a working kubeconfig context, reference a data key in an existing Secret:

```toml
[providers.k8s]
type = "kubernetes"
namespace = "payments"

[secrets]
DATABASE_URL = { provider = "k8s", value = "database/url" }
```

```sh
fnox check
fnox exec -- ./start-server.sh
```

`database/url` reads data key `url` from Secret `database` in namespace `payments`.

## Authentication

Authentication comes from the selected kubeconfig or the in-cluster service account. fnox talks to the API directly; it does not run `kubectl` and has no default `auth_command`. Kubeconfig credential plugins, such as cloud provider exec plugins, run as configured.

### Context and kubeconfig selection

The context is chosen in this order:

1. The provider's `context` field.
2. `FNOX_K8S_CONTEXT`, when set.
3. The kubeconfig's current context.

The kubeconfig is chosen as follows:

- With `kubeconfig` set, fnox reads only that file.
- With a context set but no `kubeconfig`, fnox reads the standard sources (`KUBECONFIG`, then `~/.kube/config`). The context must exist there; fnox does not fall back to in-cluster credentials.
- With neither, a non-empty `KUBECONFIG` is treated as explicit: fnox loads it and fails if it cannot be read, with no in-cluster fallback.
- Otherwise fnox follows Kubernetes client inference: the standard local kubeconfig first, then in-cluster service-account authentication.

## Configuration

```toml
[providers.k8s]
type = "kubernetes"
context = "production"         # optional
namespace = "payments"         # optional
kubeconfig = "./ops/kubeconfig" # optional; relative to this fnox.toml
prefix = "myapp-"              # optional; applies only to Secret names
```

| Field        | Required | Default                                  | Description                                                                                                              |
| ------------ | -------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `context`    | No       | `FNOX_K8S_CONTEXT`, then current context | Kubeconfig context to use.                                                                                               |
| `namespace`  | No       | Context or in-cluster namespace          | Namespace for references that do not name one.                                                                           |
| `kubeconfig` | No       | Standard kubeconfig sources              | Path to one kubeconfig file. Relative paths resolve against the config file that declares the provider; `~` is expanded. |
| `prefix`     | No       |                                          | Prepended to every Secret name. Never applied to namespaces or data keys.                                                |

Every field accepts `{ secret = "NAME" }` to take its value from another fnox secret. The options shared by all providers, `auth_command` and `daemon_cache`, are in the [configuration reference](/reference/configuration#provider-configuration).

Treat a configured kubeconfig as trusted: kubeconfigs can reference credential plugins and other executable material.

## Reference formats

| `value`                | What fnox reads                                          |
| ---------------------- | -------------------------------------------------------- |
| `secret`               | The only data key in `secret`, in the selected namespace |
| `secret/key`           | Data key `key` in `secret`, in the selected namespace    |
| `namespace/secret/key` | Data key `key` in `secret`, in `namespace`               |

The namespace in a reference overrides the provider's `namespace`, which overrides the context or in-cluster default. A Secret with more than one data key needs an explicit key. With `prefix = "myapp-"`, `payments/api/token` reads key `token` of Secret `myapp-api` in namespace `payments`.

fnox decodes the base64 `data` and accepts only UTF-8 text. Binary values return an error without printing the value. Text values that hold JSON can be narrowed with [`json_path`](/reference/configuration#json-path).

When several fnox keys reference the same Secret, fnox fetches it once. Distinct Secrets are fetched in parallel, up to 10 at a time.

## RBAC

Grant only `get` on the named Secrets fnox references. Avoid `list` and `watch`: both can expose every Secret in a namespace.

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

`fnox provider test` only verifies that the client configuration loads. It does not query Secrets. Use `fnox check` to verify the configured references with the intended identity.

## Caching and sync

The [daemon](/guide/daemon) never caches Kubernetes values, and `daemon_cache = true` cannot re-enable it. This prevents reuse across changing kubeconfig targets or contexts.

[`fnox sync`](/guide/sync) can still store an encrypted local snapshot with your local encryption provider. The snapshot goes stale after a Secret rotation, a namespace or context change, or an RBAC change; run `fnox sync` again when the source changes.

## Troubleshooting

### Unable to load Kubernetes client configuration

The kubeconfig, context or in-cluster environment could not be loaded. Check the selection rules above, particularly a stale `KUBECONFIG` or `FNOX_K8S_CONTEXT`.

```sh
kubectl config get-contexts
```

### Access denied

A `401` or `403` means the identity lacks `get` on that Secret or the wrong context was selected. fnox errors do not include API messages, kubeconfig contents, credentials or Secret values.

```sh
kubectl auth can-i get secret/myapp-database -n payments
```

### Secret has several data keys

Add the key to the reference: `secret/key` or `namespace/secret/key`.

## See also

- [Sync](/guide/sync): keep an encrypted local snapshot for offline reads.
- [Profiles](/guide/profiles): select a context or namespace per environment.
