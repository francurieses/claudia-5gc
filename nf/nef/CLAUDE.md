# CLAUDE.md — NEF (Network Exposure Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

The **NEF** is the 5GC's secure gateway between the trusted core and external
**Application Functions (AFs)**. It exposes selected core capabilities northbound over
the **Nnef** API surface (TS 29.522) while shielding internal NFs and hiding network
topology. AFs know only UE IP addresses; the NEF discovers the serving PCF via the BSF
(`Nbsf_Management_Discovery`) and maps AF requests onto PCF policy operations
(`Npcf_PolicyAuthorization`).

**Primary specifications:**
- TS 23.501 §6.2.5 — NEF functional description
- TS 23.502 §4.15 — Network exposure procedures
- **TS 29.522** — Nnef northbound APIs (Stage 3)
- TS 29.514 — Npcf_PolicyAuthorization (Stage 3)
- TS 29.521 — Nbsf_Management (BSF discovery consumption)
- TS 33.501 — OAuth2 token security for northbound API

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| Nnef | AF (Application Function) | Nnef_AFsessionWithQoS / mTLS + HTTP/2 + OAuth2 | TS 29.522 |
| Nbsf | BSF | Nbsf_Management_Discovery / mTLS + HTTP/2 | TS 29.521 |
| Npcf | PCF | Npcf_PolicyAuthorization / mTLS + HTTP/2 | TS 29.514 |
| Nnrf | NRF | Nnrf_NFManagement (register + heartbeat) | TS 29.510 |

## 3. Provided SBI Services (Nnef_AFsessionWithQoS)

| Method | Path | Operation | Spec |
|--------|------|-----------|------|
| POST | `/3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions` | Create | TS 29.522 §4.4.13.2.5 |
| GET | `/3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId}` | Get | TS 29.522 §4.4.13.2.5 |
| DELETE | `/3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId}` | Delete | TS 29.522 §4.4.13.2.5 |
| GET | `/healthz` | Liveness probe | — |
| GET | `/metrics` | Prometheus | — |

All northbound routes require an OAuth2 bearer token with scope `nnef-afsessionwithqos`.

## 4. Consumed SBI Services

| Target NF | Service | Operation | Spec |
|-----------|---------|-----------|------|
| NRF | Nnrf_NFManagement | Register + Heartbeat | TS 29.510 §5.2.2 |
| BSF | Nbsf_Management | Discovery (GET pcfBindings?ipv4Addr=…) | TS 29.521 §5.2.2.4 |
| PCF | Npcf_PolicyAuthorization | Create + Delete app-sessions | TS 29.514 §5.2.2 |

## 5. Implemented Procedures

- [x] NEF-001: AsSessionWithQoS Create / Get / Delete (TS 29.522 §4.4.13)
- [x] BSF Discovery consumption (Nbsf_Management_Discovery)
- [x] PCF Policy Authorization mapping (Npcf_PolicyAuthorization_Create / _Delete)
- [x] OAuth2 bearer token verification (scope=nnef-afsessionwithqos)
- [x] NRF registration (nfType=NEF, service nnef-afsessionwithqos)

## 6. Internal Architecture

```
cmd/nef/
  main.go                  Bootstrap + NRF registration + graceful shutdown
internal/
  config/config.go         Config loader (YAML)
  server/
    server.go              HTTP/2 SBI server + route handlers + OAuth2 middleware
    bsf_client.go          BSF discovery client (Nbsf_Management)
    pcf_client.go          PCF policy-authorization client (Npcf_PolicyAuthorization)
    server_test.go         Unit tests (httptest, no TLS, mock BSF + PCF)
config/dev.yaml            Dev configuration
tests/features/            BDD feature files (step defs: test-engineer task)
```

## 7. Ports

| Port | Role |
|------|------|
| **8011** | SBI Nnef_AFsessionWithQoS (mTLS + HTTP/2) |
| **9112** | Prometheus metrics |

## 8. Logging — Additional Mandatory Fields

Beyond global mandatory fields:

| Field | Value |
|---|---|
| `scs_as_id` | SCS/AS identifier from path segment |
| `subscription_id` | NEF-minted subscriptionId |
| `app_session_id` | PCF-assigned appSessionId |
| `ue_ipv4` | UE IPv4 address |
| `af_id` | AF identifier |
| `pcf_id` | PCF NF instance ID from BSF binding |

## 9. OAuth2 Model

Northbound requests require `Authorization: Bearer <token>` with:
- Valid HS256 JWT signature (shared secret with NRF, same model as other NFs)
- `scope` includes `nnef-afsessionwithqos`
- Token not expired (`exp` check)

Missing token → 401 UNAUTHORIZED; valid token but wrong scope → 403 UNAUTHORIZED_AF.

## 10. ALPN Invariant

`TLSConfig.NextProtos = ["h2"]` MUST be set BEFORE `http2.ConfigureServer`.
See `docs/memory/http2_alpn_conformance.md`.

## 11. TODO

- [ ] NEF-002: QoS Notification Control callbacks from PCF → AF (TS 29.514 §5.2.2.2 events)
- [ ] NEF-003: AF subscription update (PUT /subscriptions/{id}) (TS 29.522 §4.4.13.2.5)
- [ ] NEF-004: Full TS 29.514 app-session lifecycle (Subscribe/Notify/Patch)
- [ ] NEF-005: docker-compose service wiring + PCAP sidecar + PKI cert
- [ ] NEF-006: PostgreSQL persistence for subscriptions (restart-survival)
