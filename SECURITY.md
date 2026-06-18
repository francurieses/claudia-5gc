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

**None of these values should appear in any production or internet-facing deployment.**

## PKI

The `pki/` directory contains development TLS certificates for local use.

- Private keys (`*.key`) are excluded by `.gitignore` and are never committed.
- The CA certificate (`pki/ca.crt`) is committed — it is a public certificate needed to
  verify inter-NF connections in the dev stack.
- **Regenerate all PKI before any production deployment:** run `make pki`.

## SUCI Profile A Key

The X25519 private key in `nf/udm/config/dev.yaml` is the **TS 33.501 Annex C.3 published
test vector** — a well-known value from the 3GPP standard used for interoperability testing.
It is intentionally included so the dev stack works out of the box.

For any real deployment, generate a fresh key pair:
```bash
openssl genpkey -algorithm X25519 | openssl pkey -text -noout
```

## Production Hardening Checklist

Before deploying in any real environment:

1. `make pki` — regenerate all TLS certificates with your own CA
2. Replace `hn_private_key_x25519` in `nf/udm/config/dev.yaml` with a freshly generated key
3. Change all default passwords in `docker-compose.yml` (use environment variables or secrets management)
4. Enable Redis authentication (`requirepass` in Redis config)
5. Scope the PostgreSQL user to minimum required privileges
6. This codebase is a **research/development implementation** — conduct your own security
   review before any production use
