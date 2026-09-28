---
description: "Use plaintext defaults for non-sensitive settings and understand what fnox writes when no provider is selected."
---

# Plaintext defaults

Use plaintext for non-sensitive settings such as log levels, ports, and public URLs. Plaintext values are readable by anyone with access to the config file.

## Default values

A secret can provide a default without a provider:

```toml
[secrets]
LOG_LEVEL = { default = "info" }
PORT = { default = "3000" }
API_URL = { default = "http://localhost:3000" }
```

`fnox set` also writes a plaintext default when neither the secret nor the configuration selects a provider. To encrypt a value, configure an [encryption provider](/providers/overview#encryption-in-your-config) first.

## Explicit plain provider

The `plain` provider returns `value` unchanged:

```toml
[providers.plain]
type = "plain"

[secrets]
LOG_LEVEL = { provider = "plain", value = "debug" }
```

Use this when a test or configuration needs a provider-backed value without encryption. A `default` is usually simpler for public settings.

## Fallbacks

A remote or encrypted secret can have a non-sensitive fallback:

```toml
[providers.aws]
type = "aws-sm"
region = "us-east-1"

[secrets]
REDIS_URL = { provider = "aws", value = "redis-url", default = "redis://localhost:6379" }
```

If the provider lookup fails, fnox can use the default. The default is plaintext even when the main value uses encryption. Avoid production fallbacks that would silently connect to the wrong service; use a separate [profile](/guide/profiles) when appropriate.

## Review before committing

Check both `value` and `default` fields. Setting `provider = "age"` does not encrypt a string you manually type into `value`; let `fnox set` generate the ciphertext.

[`fnox scan`](/cli/scan) can flag potential secrets in files. It is a heuristic scan, not a guarantee that a repository or its history is free of secrets. If a real credential was exposed, rotate it at its source.

## Next steps

- [Age quick start](/guide/quick-start): store sensitive values with encryption.
- [Missing secrets and defaults](/guide/missing-secrets): choose when to fall back, warn, or fail.
- [Configuration reference](/reference/configuration#default): interpolate defaults and set provider references.
