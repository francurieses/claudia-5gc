# CLAUDE.md — AMF (Access and Mobility Management Function)

> Read the root `CLAUDE.md` for global conventions.

## 1. Function

Control plane entry point for the UE. Manages mobility, access, and NAS signaling.

**Primary specifications:** TS 23.501 §6.2.1 · TS 23.502 §4.2 · TS 29.518 · TS 38.413 · TS 24.501 · TS 33.501 §6.7

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N1 | UE | NAS-5GS | TS 24.501 |
| N2 | gNB | NGAP/SCTP | TS 38.413 |
| N8 | UDM | Nudm SBI | TS 29.503 |
| N11 | SMF | Nsmf SBI | TS 29.502 |
| N12 | AUSF | Nausf SBI | TS 29.509 |
| N15 | PCF | Npcf SBI | TS 29.507 |
| N22 | NSSF | Nnssf SBI | TS 29.531 |

## 3. Implemented Procedures

| Procedure | Spec | Status |
|---|---|---|
| Initial Registration | TS 23.502 §4.2.2.2.2 | ✅ |
| Deregistration (UE-initiated) | TS 23.502 §4.2.2.3.2 | ✅ |
| AN Release / CM-IDLE | TS 23.502 §4.2.6 | ✅ |
| Service Request | TS 23.502 §4.2.3 | ✅ |
| PDU Session Establishment | TS 23.502 §4.3.2 | ✅ |
| PDU Session Release (UE-initiated) | TS 23.502 §4.3.4.2 | ✅ |
| PDU Session Modification (UE-requested) | TS 23.502 §4.3.3.1 | ✅ |
| Registration (GUTI-based) | TS 23.502 §4.2.2.2.3 | ⏳ |
| Deregistration (NW-initiated) | TS 23.502 §4.2.2.3.3 | ✅ |
| NW-initiated PDU Session Release | TS 23.502 §4.3.4.3 | ✅ |
| Xn Handover | TS 23.502 §4.9.1.2 | ✅ |
| N2 Handover | TS 23.502 §4.9.1.3 | ✅ |

## 4. Internal Architecture

```
cmd/amf/
  main.go         Bootstrap + config + wiring
  clients.go      HTTP SBI clients (AUSF/UDM/SMF/NSSF)
internal/
  context/        UEContext, Manager, GMM5State, GUTI5G, SecurityContext
  procedures/     Registration handler (3 phases)
  ngap/           NGAP SCTP server + message handlers
  nas/            NAS dispatcher → procedures
```

Initial Registration flow:
```
gNB → ngap.handleInitialUEMessage
        → nas.handleRegistrationRequest
            → procedures.Registration.Phase1 → AUSF
            → procedures.Registration.Phase2 → AUSF confirm
            → procedures.Registration.Phase3 → UDM
            → ngap.SendDownlinkNASTransport → gNB → UE
```

## 5. Additional Log Fields

Beyond globals: `amf_ue_ngap_id`, `ran_ue_ngap_id`, `gnb_id`.

## 6. NGAP — Implementation Notes

- Current NGAP uses TCP + length-prefix (not real SCTP). For production: `github.com/ishidawataru/sctp`.
- **NGAP messages processed serially per SCTP association** (no goroutine per message). Required to preserve `UplinkCount` order. Do not re-introduce `go s.dispatch`.

## 7. NAS Security

| Message | SHT | Note |
|---|---|---|
| Authentication Request | 0x00 (plain) | Before activating security |
| Security Mode Command | 0x03 (integrity + new SC) | TS 24.501 §4.4.4.3.1 |
| Registration Accept, DL post-SMC | 0x02 (integrity+ciphered) | NIA2 + NEA2 |
| SMC Complete (UL) | 0x04 | Received from UE |

**MAC** (TS 33.501 §D.3.3): ciphered messages → cipher first → MAC over `SQN||ciphertext`. Integrity-only → MAC over `SQN||plaintext`.

**NEA2 IV**: `COUNT(32b)|BEARER(5b)|DIR(1b)|0(90b)` — the lower 90 bits are **zero** (do not replicate the first half). Ref: TS 33.401 §B.1.2.

**KAMF**: SUPI without "imsi-" prefix (digits only: `001010000000001`). UERANSIM does `Supi::Parse` = `substr(5)`. Ref: TS 33.501 §A.7.1.

**DL N1SM**: a 5GSM message never travels alone on N1. It must go inside a DL NAS Transport (5GMM) ciphered (SHT=0x02) before the NGAP NAS-PDU. See `sendNASSecured` + `DLNASTransport`.

**TODO**: T3560, T3570, MAC hard-failure in production.

## 8. Persistence

**PostgreSQL** — `amf_ue_contexts (supi PK, tmsi BIGINT nullable, gmm_state INT, context_json JSONB, registered_at TIMESTAMPTZ, last_activity TIMESTAMPTZ)`. Persisted in: `handleRegistrationComplete`, `handleULNASTransport`, `handlePDUSessionRelease`.

**Redis** — key `amf:seq:tmsi` (atomic INCR). `SeedTMSIIfLower` (Lua) on startup — prevents TMSI reuse after Redis restart.

**Env vars**: `DATABASE_URL=postgres://5gc:5gc-dev@postgres:5432/5gc?sslmode=disable`, `REDIS_URL=redis:6379`. Both nil-safe.

## 9. Invariants: Deregistration / Context Release

- `CMState = CMConnected` is set when sending `InitialContextSetupRequest` (also in TMSI-found path of `handleInitialUEMessage`).
- **`ue.PendingRemoval = true` is set BEFORE calling `SendUEContextReleaseCommandForUE`.** If set after, the watchdog timer doesn't arm. `handleUEContextReleaseComplete` calls `mgr.Remove` only if `PendingRemoval == true`.
- TMSI not found in `InitialUEMessage` → `ServiceReject` cause 0x09 (TS 24.501 §5.6.1.5.2), do not create empty context.
- **`ProcPDUSessionResourceRelease = 28`** (not 30; that code is `PDUSessionResourceNotify`). Ref: TS 38.413 Table 9.1-1.
- 5GSM Cause in Release Command: send **only the value byte** (no IEI 0x59 prefix). UERANSIM v3.2.8 uses `mandatoryIE` which reads 1 byte without prefix. Format = `EPD|PSI|PTI|0xD3|cause_value` (5 bytes). Ref: TS 24.501 §8.3.9.

## 10. Service Request — KgNB Invariant

KgNB = `kdf.KgNB(KAMF, UplinkCount-1, 0x01)` — use `UplinkCount - 1` because `unwrapNASSecurity` already incremented the counter before the handler runs. Ref: TS 33.501 §A.9.

## 11. PDU Session Modification (UE-requested)

UE sends 0xC9 in UL NAS Transport → AMF calls `ModifySMContext` (POST `.../modify`) → SMF responds with 0xCB + N2SM Modify Transfer → AMF wraps 0xCB in ciphered DL NAS Transport (SHT=0x02) + NGAP PDU Session Resource Modify Request (ProcCode=26).

UERANSIM v3.2.8 does not expose `ps-modify`. Test with `./scripts/test-pdu-session-modification.sh`.

```bash
go test ./nf/amf/internal/ngap/... -v -run "TestBuildPDUSessionResourceModifyRequest|TestExtractPDUSessionResourceModifyResponse"
go test ./nf/amf/internal/ngap/... -v -run "TestBuildPDUSessionResourceReleaseCommand|TestPDUSessionResourceReleaseResponse_Decode"
go test ./nf/amf/... -v
```

## 12. UE Lifecycle Timers

Configure in `nf/amf/config/dev.yaml` section `timers:`:

```yaml
timers:
  t3512_secs: 60                    # Sent to UE in Reg Accept (IEI 0x5E)
  mobile_reachable_guard_secs: 120  # MobileReachable = t3512 + guard
  implicit_detach_secs: 60          # On expiry: release PDU sessions + dereg UDM + remove
  pending_removal_watchdog_secs: 30 # Force-remove if UEContextReleaseComplete doesn't arrive
```

Restart: `docker compose restart amf`. Flow: RegistrationComplete → MobileReachable → [Periodic Reg/SR resets] → ImplicitDetach → cleanup. Ref: TS 23.501 §5.3.2, TS 24.501 §10.2.

```bash
go test ./shared/nas/... -v -run "TestEncodeGPRSTimer3|TestRegistrationAccept_T3512"
```

## 13. N2 Handover — Implementation Notes

Flow (TS 23.502 §4.9.1.3 / TS 38.413 §8.4):

1. **HandoverRequired** (source gNB → AMF, ProcCode=12): AMF resolves target gNB by `GlobalRANNodeID` bytes stored on NG Setup. Derives NH = KDF(KAMF, KgNB_source) with NCC=1. Sends **HandoverRequest** (ProcCode=13) to target gNB.
2. **HandoverRequestAcknowledge** (target gNB → AMF, ProcCode=13): AMF builds **HandoverCommand** (SuccessfulOutcome of ProcCode=12) from the `TargetToSourceTransparentContainer` and sends it to source gNB.
3. **HandoverNotify** (target gNB → AMF, ProcCode=11): UE is now at target. AMF migrates UE context (`RANUENGAPId`, `GNBAddr`, `TAI`), calls `onN2HandoverComplete` per admitted PDU session so SMF can update PFCP, then sends **UEContextReleaseCommand** to source gNB.

Key invariants:
- `KgNB` is stored in `UEContext` after every `SendInitialContextSetupRequest` (Initial Registration, Service Request, Periodic Reg Update). Required to derive NH.
- Pending state (`n2HandoverState`) is kept in `Server.pendingN2HO` map keyed by AMF UE NGAP ID. Cleaned up on HandoverNotify.
- Target gNB must have completed NG Setup before N2 handover — `GlobalGNBID` must match.

To test with two PacketRusher gNBs connected to the same AMF, trigger N2 handover via the scripted scenario.

## 14. Commands

```bash
make -C nf/amf build
make -C nf/amf test
make -C nf/amf docker
docker logs -f amf | jq '.procedure, .result, .cause'
```
