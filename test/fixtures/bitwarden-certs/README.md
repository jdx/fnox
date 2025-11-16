# SSL Certificates for Vaultwarden HTTPS

This directory contains the self-signed SSL certificates used by vaultwarden for HTTPS during testing.

## Files

- `certs/cert.pem` - Self-signed SSL certificate
- `certs/key.pem` - Private key for the certificate

Vaultwarden serves HTTPS directly using the `ROCKET_TLS` environment variable.

## Regenerating Certificates

If you need to regenerate the self-signed certificates:

```bash
cd test/fixtures/bitwarden-certs/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

## Why HTTPS?

The Bitwarden CLI now requires HTTPS for all server connections. This is a security enhancement that prevents insecure HTTP connections. For local testing, we use:

1. A self-signed certificate (generated above)
2. Vaultwarden's built-in HTTPS support via `ROCKET_TLS` environment variable
3. `NODE_TLS_REJECT_UNAUTHORIZED=0` environment variable to allow self-signed certificates

**Note:** The `NODE_TLS_REJECT_UNAUTHORIZED=0` setting is only for local testing. Never use this in production!
