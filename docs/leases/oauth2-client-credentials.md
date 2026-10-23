---
description: "Get short-lived access tokens from any OAuth2 token endpoint with fnox using the client credentials grant, for Auth0, Okta, Keycloak, Entra ID and similar."
---

# OAuth2 client credentials

The `oauth2-client-credentials` lease backend requests an access token from an OAuth2 token endpoint with the [client credentials grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) and injects it into `fnox exec`. Use it for any identity provider or internal service that issues machine tokens: Auth0, Okta, Keycloak, Entra ID, and others.

|              |                                                                                              |
| ------------ | -------------------------------------------------------------------------------------------- |
| Config type  | `oauth2-client-credentials`                                                                  |
| Produces     | `OAUTH2_ACCESS_TOKEN` (configurable with `env_var`)                                          |
| Max duration | Set by the token endpoint's `expires_in`; `duration` (up to 24 hours) is used only if absent |
| Revocation   | Only when `revocation_url` is set; otherwise the token expires on its own                    |
| Needs        | A token endpoint, a client ID, and the client secret in `OAUTH2_CLIENT_SECRET`               |

## Quick start

```toml
[providers.op]
type = "1password"
vault = "Development"

[secrets]
OAUTH2_CLIENT_SECRET = { provider = "op", value = "Auth0/m2m client secret", env = false }

[leases.api]
type = "oauth2-client-credentials"
token_url = "https://example.us.auth0.com/oauth/token"
client_id = "Zk3...your-client-id"
audience = "https://api.example.com"
env_var = "API_TOKEN"
```

```sh
fnox exec -- sh -c 'curl -fsS -H "Authorization: Bearer $API_TOKEN" https://api.example.com/v1/things'
```

The command sees the access token in `API_TOKEN`; the client secret stays out of its environment.

## Bootstrap credentials

fnox reads the client secret from `OAUTH2_CLIENT_SECRET`. Store it as a secret with that name, as in the quick start, or export it. `fnox lease create -i api` prompts for it when it is not set.

The name is fixed, so two leases that use different client secrets need separate [profiles](/guide/profiles).

## Configuration

| Field            | Required | Default                 | Description                                                                                                                                                |
| ---------------- | -------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `token_url`      | Yes      | none                    | The token endpoint. Must use https; http is accepted only for localhost. Redirects are not followed.                                                       |
| `client_id`      | Yes      | none                    | The OAuth2 client ID.                                                                                                                                      |
| `scope`          | No       | none                    | Space-separated scopes to request.                                                                                                                         |
| `audience`       | No       | none                    | Sent as `audience`, which Auth0 and some others use to pick the API.                                                                                       |
| `env_var`        | No       | `"OAUTH2_ACCESS_TOKEN"` | Variable that receives the access token.                                                                                                                   |
| `auth_method`    | No       | `"basic"`               | `"basic"` sends the client ID and secret in an `Authorization` header; `"post"` sends them in the request body.                                            |
| `params`         | No       | none                    | Extra form parameters for the token request, such as `resource`.                                                                                           |
| `revocation_url` | No       | none                    | An [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) revocation endpoint. Without it, nothing is sent. Must use https; redirects are not followed. |
| `duration`       | No       | `"15m"`                 | Lifetime to assume if the endpoint omits `expires_in`. At most `"24h"`.                                                                                    |

fnox records the token's expiry from `expires_in` and reuses the token until it is about to expire, so the endpoint's lifetime wins over `duration`. Set the lifetime on the identity provider, such as the API's token lifetime in Auth0.

### Examples

Entra ID, with the `.default` scope of the target API:

```toml
[leases.graph]
type = "oauth2-client-credentials"
token_url = "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token"
client_id = "<application-id>"
scope = "https://graph.microsoft.com/.default"
env_var = "GRAPH_TOKEN"
```

Keycloak, with the client secret in the body and a revocation endpoint:

```toml
[leases.kc]
type = "oauth2-client-credentials"
token_url = "https://sso.example.com/realms/ops/protocol/openid-connect/token"
revocation_url = "https://sso.example.com/realms/ops/protocol/openid-connect/revoke"
client_id = "deployer"
auth_method = "post"
```

## Troubleshooting

### OAuth2 client secret not found

`OAUTH2_CLIENT_SECRET` is not set when the lease is created. Under `fnox exec`, the lease is skipped with this warning unless a cached lease is still valid.

### invalid_client

The endpoint rejected the client ID or secret. Some servers only accept credentials in the body: set `auth_method = "post"`.

### invalid_scope or invalid_request

The client is not allowed the `scope` or `audience` you asked for, or the server needs a parameter fnox does not send by default. Add it with `params`.

### Revocation failed on `fnox lease revoke`

With `revocation_url` set, fnox needs the token to send it, and warns that backend revocation failed when it has none. The token is missing when it was never cached, or when the encryption provider that holds it is unavailable. The lease is still marked revoked locally and the token expires on its own. `fnox lease cleanup` warns the same way for expired leases, which need no revocation.

## See also

- [Credential leases](/guide/leases): how leases are cached, reused and revoked.
- [Lease commands](/cli/lease): revoke early with `fnox lease revoke`.
- [Azure Token](/leases/azure-token): Entra ID tokens through a service principal, the Azure CLI or managed identity, without a client secret in the config.
- [Custom command](/leases/command): wrap a token API this backend cannot call.
