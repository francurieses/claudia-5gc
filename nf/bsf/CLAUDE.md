# CLAUDE.md — BSF (Binding Support Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

The **BSF** is the 5GC registry of PCF-for-a-PDU-session bindings. For every UE PDU
session, exactly one PCF is the serving policy authority. When a consumer (typically
the **NEF** on behalf of an **AF**) wants to influence a session, it queries the BSF
with the UE IP address to discover the serving PCF. The PCF registers a binding
`(UE IP, DNN, S-NSSAI) → serving PCF` when it creates the SM policy association,
and deregisters it when the association is deleted.

**Primary specifications:**
- TS 23.501 §6.2.16 — BSF functional description
- TS 29.521 §5 — Nbsf_Management service (Stage 3)
- TS 29.521 §6.2.6 — PcfBinding data type
- TS 29.510 §6.1.6.2.2 — NRF registration (NFType BSF)
- TS 29.500 §5.2.7 — ProblemDetails / error handling

## 2. Reference Points

| Interface | Peer        | Protocol             | Spec               |
|-----------|-------------|----------------------|--------------------|
| Nbsf      | PCF         | Nbsf_Management / mTLS + HTTP/2 | TS 29.521 |
| Nbsf      | NEF/AF (future) | Nbsf_Management / mTLS + HTTP/2 | TS 29.521 |
| Nnrf      | NRF         | Nnrf_NFManagement (register + heartbeat) | TS 29.510 |

## 3. Provided SBI Services (Nbsf_Management)

| Method | Path                                          | Operation        | Spec              |
|--------|-----------------------------------------------|------------------|-------------------|
| POST   | `/nbsf-management/v1/pcfBindings`             | Register         | TS 29.521 §5.2.2.2 |
| DELETE | `/nbsf-management/v1/pcfBindings/{bindingId}` | Deregister       | TS 29.521 §5.2.2.3 |
| GET    | `/nbsf-management/v1/pcfBindings`             | Discovery        | TS 29.521 §5.2.2.4 |
| GET    | `/healthz`                                    | Liveness probe   | — |
| GET    | `/metrics`                                    | Prometheus       | — |

## 4. Consumed SBI Services

| Target NF | Service           | Operation              | Spec        |
|-----------|-------------------|------------------------|-------------|
| NRF       | Nnrf_NFManagement | Register + Heartbeat   | TS 29.510 §5.2.2 |

## 5. Implemented Procedures

- [x] Nbsf_Management_Register — POST /nbsf-management/v1/pcfBindings → 201 + Location
- [x] Nbsf_Management_DeRegister — DELETE /nbsf-management/v1/pcfBindings/{bindingId} → 204
- [x] Nbsf_Management_Discovery — GET /nbsf-management/v1/pcfBindings?ipv4Addr=… → 200/404
- [x] BSF NRF Registration (TS 29.510 §5.2.2) — nfType BSF, nbsf-management service
- [ ] PCF client integration — separate pass BSF-002 (see docs/procedures/binding-support.md)
- [ ] PostgreSQL persistence — in-memory is authoritative for this increment (BSF-003)
- [ ] Redis discovery cache — O(1) cache on top of Postgres (BSF-003)

## 6. Internal Architecture

```
cmd/bsf/
  main.go                  Bootstrap + NRF registration + graceful shutdown
internal/
  config/                  Config loader (YAML)
    config.go
  store/                   In-memory PCF binding store
    store.go               Store struct + Create/Delete/FindByQuery
  server/                  Nbsf_Management SBI server (mTLS + HTTP/2)
    server.go              HTTP/2 server + route handlers + PcfBinding types
    server_test.go         Unit tests (httptest, no TLS)
config/dev.yaml            Dev configuration
tests/features/            BDD feature files (step defs: test-engineer task)
```

## 7. Ports

| Port | Role |
|------|------|
| **8010** | SBI Nbsf_Management (mTLS + HTTP/2) |
| **9111** | Prometheus metrics |

## 8. Logging — Additional Mandatory Fields

Beyond global mandatory fields (`nf`, `procedure`, `correlation_id`, `interface`, `direction`, `spec_ref`):

| Field        | Value                                                  |
|--------------|--------------------------------------------------------|
| `binding_id` | ULID / UUID of the PCF binding (when available)        |
| `supi`       | SUPI of the UE (when present in the binding)           |
| `ipv4_addr`  | UE IPv4 address (when querying / registering by IP)    |
| `dnn`        | Data Network Name of the PDU session                   |
| `result`     | `OK` / `REJECT` / `FAILURE`                            |
| `cause`      | ProblemDetails cause string (on REJECT)                |

Interface: `Nbsf` for all PCF/NEF-facing calls.

## 9. ALPN Invariant

`TLSConfig.NextProtos = ["h2"]` **must be set BEFORE** `http2.ConfigureServer` is called.
Mirrors the SMSF / NSSF server pattern. See `docs/memory/http2_alpn_conformance.md`.

## 10. Commands

```bash
make -C nf/bsf build
make -C nf/bsf test
make -C nf/bsf lint
make -C nf/bsf docker
```

## 11. TODO

- [ ] BSF-002: PCF client integration — register/deregister from nf/pcf SM policy lifecycle
- [ ] BSF-003: PostgreSQL persistence (table `pcf_binding`, migration `001_pcf_binding.sql`)
- [ ] BSF-003: Redis O(1) discovery cache (`bsf:binding:ipv4:{ipv4Addr}` → bindingId)
- [ ] BSF-004: docker-compose.yml service wiring + PCAP sidecar + PKI cert generation
         (orchestrator task — not touched here per scope constraint)
- [ ] NEF-001: Consumer-side discovery (GET /nbsf-management/v1/pcfBindings?ipv4Addr=…)
         is already built; NEF-001 consumes it unchanged.
