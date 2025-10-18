# fnox

## Scope

- Server vault stores only age‑encrypted ciphertext; server cannot decrypt.
- Authentication/authorization via OIDC (GitHub Actions first).
- Project declaration via `fnox.toml` (profiles + `require_approval`).
- One‑time per‑use approvals with ntfy notifications.
- CI‑friendly `fnox run -- <command>` waits for approval, decrypts locally, injects env only for the child process.

References: [SecretSpec](https://github.com/cachix/secretspec), [ntfy](https://ntfy.sh)

## Threat Model

- Server is honest‑but‑curious (zero‑knowledge of plaintexts).
- Clients prove identity via OIDC; decryption gated by client‑held age keys.
- Approvals and single‑use short‑TTL grants mitigate misuse.

## Architecture

- Crates
    - `fnox-core`: models, API client, `age` helpers, `fnox.toml` loader, OIDC/JWT types.
    - `fnox-cli`: Clap CLI; OIDC login (GH Actions auto), age key mgmt, run flow.
    - `fnox-server`: Axum server; SQLite store (ciphertext + metadata), approvals/grants, OIDC verifier, ntfy.
- Storage
    - SQLite: `secrets(key, ciphertext_b64, recipients[], version, created_at)`, `approvals`, `grants`, `audit`.

## `fnox.toml`

- Defines keys per profile with `description`, `require_approval`.
```toml
[project]
name = "my-app"
revision = "1.0"

[profiles.default]
NPM_TOKEN = { description = "NPM publish token", require_approval = true }
SENTRY_DSN = { description = "Sentry DSN", require_approval = false }
```


## Client Config

```toml
server_url = "https://fnox.example.com"
[age]
identities_file = "/home/user/.config/fnox/age/identities.txt"
recipients = ["age1...runnerpub..."]
```

## AuthN/AuthZ (OIDC + policy)

- Clients obtain OIDC ID token (GitHub Actions: `permissions: id-token: write`).
- CLI presents `Authorization: Bearer <oidc_token>` to server.
- Server verifies issuer (`https://token.actions.githubusercontent.com`), audience, signature (JWKS), and claims.
- Policy checks (configurable): allowed repositories, refs/branches, environments, workflow names.
- Server issues a short‑lived session (opaque or JWT) bound to OIDC subject + claims for API calls.

## Encryption (age)

- Secrets uploaded as age ciphertext for configured recipients; server stores only ciphertext.
- On fetch, server returns ciphertext after approval+grant; CLI decrypts locally with age identities and sets envs.
- Recipient enforcement: optionally require that requester’s registered age public key is present in recipients.

## Server API (selected)

- OIDC login: accept bearer ID token → issue session.
- Secrets (admin): PUT `/v1/secrets/{key}` `{ciphertext, recipients, description?}`, list, delete.
- Approvals: POST `/v1/approvals` → `{id, code, exp}`; approve/deny; get status.
- Grants: POST `/v1/grants` `{approval_id}` → `{grant_token, exp}`; Fetch: POST `/v1/fetch` with grant → ciphertexts (single‑use).

## One‑time Per‑use Flow

1. CLI authenticates via OIDC; gets session.
2. Reads `fnox.toml`; determines keys; requests approval for those with `require_approval`.
3. Server sends ntfy push with signed Approve/Deny links; user approves.
4. CLI exchanges approval for a one‑time grant; fetches ciphertext; decrypts with age; spawns child process with envs.
5. Audit log recorded (no plaintexts).

## Notifications (ntfy)

- Server posts to ntfy topic with metadata (repo, ref, job, keys) and HMAC‑signed action URLs with short TTL.

## CLI UX

- `fnox serve [--listen ...] [--db ...] [--oidc.issuer ...] [--oidc.audience ...] [--policy ...] [--ntfy-*] [--signing-key ...]`
- `fnox age keygen` / `fnox age add-recipient <AGE_PUB>`
- `fnox secret set <KEY> [--from-stdin] [--recipients <AGE_PUB>...]` (encrypt client‑side, upload)
- `fnox init` / `fnox check [--profile prod]` / `fnox run [--profile prod] -- <command>`

## GitHub Actions Example

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: actions/checkout@v4
  - run: curl -fsSL https://get.fnox.sh | sh
  - name: Login to fnox via OIDC (implicit)
    run: |
      export FNOX_SERVER_URL=https://fnox.example.com
      # CLI auto-detects GHA and uses OIDC ID token for auth
      fnox check
      fnox run -- npm publish
```

## Security Notes

- Zero‑knowledge storage preserved (server never sees plaintext).
- OIDC yields short‑lived, scoped sessions tied to CI identity; policy limits misuse.
- Grants are single‑use with low TTL; approval links are HMAC‑signed and short‑lived.

## Minimal Files

- `fnox-core/src/{lib.rs,api.rs,models.rs,age.rs,config.rs,oidc.rs}`
- `fnox-cli/src/main.rs`
- `fnox-server/src/main.rs`, `routes/{auth,secrets,approvals,grants}.rs`, `store/sqlite.rs`
- Example `fnox.toml` and `README.md`

## Future

- Web UI + SSO for approvals, SMS/email channels.
- Ephemeral age keys derived per‑run via OIDC (bound keys); per‑secret policies; mTLS.
