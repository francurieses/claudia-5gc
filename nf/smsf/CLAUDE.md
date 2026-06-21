# CLAUDE.md — SMSF (Short Message Service Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

SMSF anchors **SMS over NAS** in 5GS. It manages per-UE SMS contexts, terminates
the SMS relay/transfer layer (SM-CP / SM-RP), and forwards toward the SMS
infrastructure (SMS-GMSC / SMS-IWMSC / SMS-Router). In this lab there is no real
SMS infrastructure; instead a built-in **loopback / echo DTE** reflects every MO
SMS back to the originating UE as an MT SMS, proving the full MO + MT round-trip.

The AMF is a transparent NAS relay: it never parses SM-CP/SM-RP content; it only
routes the NAS **Payload Container** (type = SMS, `0x02`) between the UE (N1) and
the SMSF (Nsmsf_SMService, N20/N21).

**Primary specifications:**
- TS 23.501 §5.20 — SMS over NAS architecture, SMSF role
- TS 23.502 §4.13 — SMS over NAS procedures
- **TS 29.540** — Nsmsf_SMService (Stage 3)
- TS 29.518 §5.2.2.3 — Namf_Communication_N1N2MessageTransfer (MT delivery)
- TS 24.501 §8.2.10 / §8.2.11 — UL/DL NAS Transport (Payload Container Type = SMS 0x02)
- TS 29.510 — Nnrf_NFManagement / NFDiscovery (NF type SMSF)
- TS 33.501 — Security aspects

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N20 | AMF | Nsmsf_SMService / mTLS + HTTP/2 | TS 29.540 |
| N21 | UDM | Nudm_UECM (SMSF registration) | TS 29.503 |
| Nsmsf | AMF callback | Namf_Communication_N1N2MessageTransfer | TS 29.518 |

## 3. Provided SBI Services (Nsmsf_SMService)

| Method | Path | Operation | Spec |
|---|---|---|---|
| POST | `/nsmsf-sms/v2/ue-contexts/{supiOrGpsi}` | Activate (SMS Management Activation) | TS 29.540 §5.2.2 |
| DELETE | `/nsmsf-sms/v2/ue-contexts/{supiOrGpsi}` | Deactivate | TS 29.540 §5.2.3 |
| POST | `/nsmsf-sms/v2/ue-contexts/{supiOrGpsi}/sendsms` | UplinkSMS (MO) | TS 29.540 §5.2.4 |
| POST | `/nsmsf-sms-internal/v1/ue-contexts/{supi}/mt-sms` | MT SMS trigger (internal) | — |
| GET | `/healthz` | Liveness probe | — |
| GET | `/metrics` | Prometheus | — |

## 4. Consumed SBI Services

| Target NF | Service | Operation | Spec |
|---|---|---|---|
| NRF | Nnrf_NFManagement | Register + Heartbeat | TS 29.510 §5.2.2 |
| UDM | Nudm_UECM | Registration (smsf-3gpp-access) | TS 29.503 §5.3.2 |
| AMF | Namf_Communication | N1N2MessageTransfer (MT SMS / acks) | TS 29.518 §5.2.2.3 |

## 5. Implemented Procedures

- [x] SMS Management Activation (TS 23.502 §4.13.2) — Activate + UDM UECM registration
- [x] SMS Management Deactivation (TS 29.540 §5.2.3)
- [x] MO SMS (TS 23.502 §4.13.3) — UplinkSMS → loopback DTE → MT echo
- [x] MT SMS (TS 23.502 §4.13.4) — N1N2MessageTransfer to AMF callback URI
- [x] SMSF NRF Registration (TS 29.510 §5.2)
- [ ] Real SMS-GMSC / SMS-IWMSC forwarding (future — requires external SMSC)
- [ ] SMS Status Report relay (future)

## 6. State Machine (per UE)

```
INACTIVE   → no SMS context (no Activate received or after Deactivate)
ACTIVE     → Activate done, UDM UECM registered, ready for MO/MT
```

Transition INACTIVE → ACTIVE: Activate (POST /nsmsf-sms/v2/ue-contexts/{supi})
Transition ACTIVE → INACTIVE: Deactivate (DELETE /nsmsf-sms/v2/ue-contexts/{supi})

## 7. Internal Architecture

```
cmd/smsf/
  main.go                    Bootstrap + NRF registration + graceful shutdown
internal/
  config/                    Config loader (YAML)
  context/                   Per-UE SMS context (supi, gpsi, amfId, amfN1N2Uri, accessType, state)
  server/                    Nsmsf_SMService SBI server (mTLS + HTTP/2)
    server.go                HTTP/2 server + route handlers
    server_test.go           Unit tests (activation, uplinkSMS, MT, error cases)
config/dev.yaml              Dev configuration
tests/features/              BDD feature files (godog step definitions go here)
```

## 8. Logging — Additional Mandatory Fields

Beyond global mandatory fields (`nf`, `procedure`, `correlation_id`, `interface`, `direction`, `spec_ref`):

| Field | Value |
|---|---|
| `supi` | SUPI of the UE (when available) |
| `gpsi` | GPSI (when present in context) |
| `message_type` | `Activate` / `Deactivate` / `UplinkSMS` / `MTsms` |
| `result` | `OK` / `REJECT` / `FAILURE` |

Interface values: `Nsmsf` (for AMF-facing Nsmsf SBI), `N21` (UDM UECM calls), `Namf` (AMF callback).

## 9. ALPN Invariant

`TLSConfig.NextProtos = ["h2"]` **must be set BEFORE** `http2.ConfigureServer` is called.
This is enforced by setting `s.httpSrv.TLSConfig = tlsCfg` before calling
`http2.ConfigureServer(s.httpSrv, ...)`. Mirror the NSSF server.

## 10. Commands

```bash
make -C nf/smsf build
make -C nf/smsf test
make -C nf/smsf lint
make -C nf/smsf docker

# Unit tests (in-process, no stack):
go test ./nf/smsf/...

# Manual curl (if stack is running):
curl -sk --cert pki/smsf.crt --key pki/smsf.key --cacert pki/ca.crt \
  -X POST https://localhost:8009/nsmsf-sms/v2/ue-contexts/imsi-001010000000001 \
  -H 'Content-Type: application/json' \
  -d '{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS","amfId":"amf-001","amfCallbackUri":"https://amf:8001/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"}'
docker logs smsf | grep SmsOverNas
```

## 11. TODO

- [ ] Redis persistence for SMS contexts (`smsf:uectx:{supi}` key)
- [ ] SMS retry / retransmit correlation via `smsf:smsrec:{supi}:{smsRecordId}`
- [ ] SMSF UECM conflict handling (403 / 409 from UDM)
- [ ] Support for GPSI as alternate context key
- [ ] Paging integration for CM-IDLE MT SMS delivery (SMSF-002)
