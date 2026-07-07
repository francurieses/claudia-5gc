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
| UDM | Nudm_SDM | Get lcsPrivacyData | TS 29.503 §5.2.2 / TS 23.273 §9.1 |

## 5. Implemented Procedures

- [x] LMF-001: DetermineLocation (Cell-ID MVP) — TS 29.572 §5.2.2.2 / TS 23.273 §7.2
- [x] LMF-002: Deferred MT Location (paging-then-locate for CM-IDLE UEs) + UDM Location Privacy —
      TS 23.273 §7.2 steps E2–E7 / §9.1 / TS 29.503 §5.2.2
- [x] LMF-006: Live Cell-ID E2E — UERANSIM gNB LocationReport patch (`0040`) + LMF synthetic
      mobility model (`internal/server/mobility.go`) + portal "UE Location" live map (TS 38.413 §8.17)
- [x] LMF-003: EventSubscription / periodic / area-of-interest + CancelLocation (TS 29.572 §5.2.3, §5.2.2.5)
- [x] LMF-004: NRPPa relay — E-CID positioning (TS 38.455 / TS 23.273 §6.2.9); core-side codec +
      AMF NGAP NRPPa transport (ProcCode 8/50) + LMF method selection + weighted centroid
- [x] LMF-008: Live E-CID E2E — UERANSIM gNB NRPPa-Transport patch `0041` + `validate-ueransim-mod.sh nrppa`
- [x] LMF-005: LPP relay for GNSS positioning via N1 (TS 37.355, TS 24.501 §8.7.4, payload container
      type **0x03**) — `shared/lpp` APER codec + WLS GNSS solver; AMF additive 0x03 NAS branch +
      `dl-lpp-info` synchronous relay; LMF `methodLPP` band (hAccuracy<50 m) + `performLPPOrFallback`
      (GNSS→E-CID→Cell-ID). Live UE patch `0042` + GNSS E2E deferred (follow-up, mirrors LMF-008)
- [ ] LMF-007: GMLC integration / N56 interface (TS 29.515)

## 6. Internal Architecture

```
cmd/lmf/
  main.go                  Bootstrap + NRF registration + graceful shutdown
internal/
  config/config.go         Config loader (YAML) + cell→coord map + privacy_check flag
  server/
    server.go              HTTP/2 SBI server + DetermineLocation handler (privacy gate)
    amf_client.go          AMF Namf_Location client (Namf_Location consumer)
    udm_client.go          UDM SDM client: lcs-privacy-data (5-min per-SUPI cache, fail-open)
    mobility.go            Synthetic per-SUPI mobility model for cell-ID positioning
    server_test.go         Unit tests (httptest, no TLS, mock AMF + mock UDM clients)
config/dev.yaml            Dev configuration (privacy_check: true, peers.udm)
tests/features/            BDD feature files + step defs (8 scenarios, incl. paging + privacy)
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
