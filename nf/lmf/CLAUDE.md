# CLAUDE.md — LMF (Location Management Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

The **LMF** is the 5GC NF responsible for UE positioning (TS 23.501 §6.2.18). It
provides the `Nlmf_Location` SBI service (`nlmf-loc`) and, for Cell-ID positioning,
consumes the `Namf_Location` SBI service from the AMF. The AMF relays to/from the
gNB over the NGAP N2 interface.

**Primary specifications:**
- TS 23.501 §6.2.18 — LMF functional description
- TS 23.273 §6–7 — Location services architecture and UE positioning procedures
- **TS 29.572** — Nlmf_Location Stage 3
- TS 29.518 §5.2.2.6 — Namf_Location ProvideLocationInfo (consumed)
- TS 29.510 §6.1.6.3.3 — NRF registration (NFType=LMF)
- TS 33.501 — mTLS SBI security

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| Nlmf | LCS Client / internal NF | SBI mTLS+HTTP/2 (producer) | TS 29.572 |
| Namf | AMF | SBI mTLS+HTTP/2 (consumer) | TS 29.518 §5.2.2.6 |
| Nnrf | NRF | Nnrf_NFManagement register+heartbeat | TS 29.510 |

The LMF has **no direct N2 (NGAP/SCTP)** association — the AMF is the sole NGAP relay.

## 3. Provided SBI Services (Nlmf_Location)

| Method | Path | Operation | Spec |
|--------|------|-----------|------|
| POST | `/nlmf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info` | DetermineLocation | TS 29.572 §5.2.2.2 |
| GET  | `/healthz` | Liveness probe | — |
| GET  | `/metrics` | Prometheus | — |

## 4. Consumed SBI Services

| Target NF | Service | Operation | Spec |
|-----------|---------|-----------|------|
| NRF | Nnrf_NFManagement | Register + Heartbeat | TS 29.510 §5.2.2 |
| AMF | Namf_Location | ProvideLocationInfo | TS 29.518 §5.2.2.6 |

## 5. Implemented Procedures

- [x] LMF-001: DetermineLocation (Cell-ID MVP) — TS 29.572 §5.2.2.2 / TS 23.273 §7.2
- [ ] LMF-002: EventSubscription / periodic / area-of-interest (TS 29.572 §5.2.3)
- [ ] LMF-003: CancelLocation (TS 29.572 §5.2.2.5)
- [ ] LMF-004: LPP/NRPPa relay for E-CID/OTDOA/GNSS (TS 38.413 §8.17.2, TS 37.355)
- [ ] LMF-005: GMLC integration / N56 interface (TS 29.515)

## 6. Internal Architecture

```
cmd/lmf/
  main.go                  Bootstrap + NRF registration + graceful shutdown
internal/
  config/config.go         Config loader (YAML) + cell→coord map
  server/
    server.go              HTTP/2 SBI server + DetermineLocation handler
    amf_client.go          AMF Namf_Location client (Namf_Location consumer)
    server_test.go         Unit tests (httptest, no TLS, mock AMF client)
config/dev.yaml            Dev configuration
tests/features/            BDD feature files (step defs: test-engineer task)
```

## 7. Ports

| Port | Role |
|------|------|
| **8012** | SBI Nlmf_Location (mTLS + HTTP/2) |
| **9113** | Prometheus metrics |

## 8. Logging — Additional Mandatory Fields

Beyond global mandatory fields:

| Field | Value |
|---|---|
| `ue_context_id` | UE identifier from path segment |
| `supi` | SUPI when resolved |
| `result` | `OK` / `REJECT` / `FAILURE` |
| `cause` | 3GPP cause string on error |
| `duration_ms` | Handler latency |

## 9. ALPN Invariant

`TLSConfig.NextProtos = ["h2"]` MUST be set BEFORE `http2.ConfigureServer`.
See `docs/memory/http2_alpn_conformance.md`.

## 10. TODO

- [ ] LMF-002+: see §5 deferred procedures above
- [ ] Wire docker-compose + CI matrix + root Makefile (orchestrator task)
