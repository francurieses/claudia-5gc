<!-- tier: public -->
# Security Policy

## Reporting Vulnerabilities

Open a GitHub issue tagged `security`. Do not include private keys or production credentials
in the issue. For sensitive disclosures, contact the maintainer directly.

## Development Credentials

This repository ships example **development-only** values that are not secrets:

| Location | Value | Purpose |
|---|---|---|
| `docker-compose.yml` `POSTGRES_PASSWORD` | `5gc-dev` | Local Docker dev stack only |
| `docker-compose.yml` `GF_SECURITY_ADMIN_PASSWORD` | `admin` | Local Grafana dev only |
| `nf/udm/config/dev.yaml` `hn_private_key_x25519` | TS 33.501 §C.3 published test vector | Out-of-the-box SUCI Profile A dev use |
| `nf/udm/config/dev.yaml` `hn_private_key_p256` | TS 33.501 Annex C.4.4.1 published test vector | Out-of-the-box SUCI Profile B dev use (key id 2) |

**None of these values should appear in any production or internet-facing deployment.**

## PKI

The `pki/` directory contains development TLS certificates for local use.

- Private keys (`*.key`) are excluded by `.gitignore` and are never committed.
- The CA certificate (`pki/ca.crt`) is committed — it is a public certificate needed to
  verify inter-NF connections in the dev stack.
- **Regenerate all PKI before any production deployment:** run `make pki`.

## SUCI Home Network Keys (Profile A and Profile B)

`nf/udm/config/dev.yaml` carries two **TS 33.501 published test vectors** so the dev stack
works out of the box: the X25519 key (Annex C.3, Profile A, `hn_key_id_x25519: 0` = any) and
the P-256 key (Annex C.4.4.1, Profile B, `hn_key_id_p256: 2`). Both are well known and
**not secrets**; UDM logs a startup Warn whenever a loaded key equals a published vector.

Real home-network private keys **are secrets**: never commit them, never bake them into an
image, and supply them as files (Docker/Kubernetes secrets) with mode `0400`. The UDM image
is distroless nonroot (UID 65532), so that user must be able to read the file (set the owner
or `fsGroup`). UDM resolves each key in this precedence (first match wins):

1. env `HN_PRIVATE_KEY_X25519_FILE` / `HN_PRIVATE_KEY_P256_FILE`
2. yaml `hn_private_key_x25519_file` / `hn_private_key_p256_file`
3. env `HN_PRIVATE_KEY_X25519` / `HN_PRIVATE_KEY_P256`
4. yaml `hn_private_key_x25519` / `hn_private_key_p256`

Files hold the key as hex (whitespace trimmed, at most 4 KiB). A missing, unreadable or
invalid key (bad hex, length other than 32 bytes, all-zero X25519, invalid P-256 scalar)
makes UDM exit 1 with an error naming the key and its source. A group/world-accessible key
file logs a Warn. Key material is never logged, only the source (`file:<path>`, `env`,
`yaml`) and the key id.

Rotation is by key id: generate a new key pair, assign a new `hn_key_id_*`, provision UEs
with the new public key, and keep the old key until UEs have migrated. UDM holds one key per
profile today, so overlapping keys are not yet supported.

For any real deployment, generate fresh key pairs:
```bash
openssl genpkey -algorithm X25519 | openssl pkey -text -noout
openssl ecparam -name prime256v1 -genkey -noout | openssl ec -text -noout
```

## Production Hardening Checklist

Before deploying in any real environment:

1. `make pki` — regenerate all TLS certificates with your own CA
2. Replace both SUCI home-network keys (X25519 and P-256) with freshly generated ones, mounted
   as `0400` files via `HN_PRIVATE_KEY_*_FILE`, set real `hn_key_id_*` values, and confirm
   UDM logs no published-test-vector Warn at startup
3. Change all default passwords in `docker-compose.yml` (use environment variables or secrets management)
4. Enable Redis authentication (`requirepass` in Redis config)
5. Scope the PostgreSQL user to minimum required privileges
6. This codebase is a **research/development implementation** — conduct your own security
   review before any production use
