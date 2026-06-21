# SMS over NAS — SMSF (TS 23.502 §4.13, TS 29.540)

**Spec:** TS 23.501 §5.20 (SMS over NAS architecture) · TS 23.502 §4.13.3 (MO SMS) / §4.13.4
(MT SMS) · TS 29.540 (Nsmsf_SMService) · TS 24.501 §8.2.10 / §8.2.11 (UL/DL NAS Transport)
· TS 24.501 §9.11.3.40 (Payload Container Type) · TS 29.510 (Nnrf_NFManagement, NF type SMSF)

## Purpose

The **SMSF** (Short Message Service Function) anchors **SMS over NAS** in 5GS. The UE exchanges
SM-RP/SM-CP-framed short messages with the SMSF inside **5GMM NAS Transport** messages relayed
by the AMF over N1. The SMSF terminates the SMS relay/transfer layers and forwards toward the
SMS infrastructure (SMS-GMSC / SMS-IWMSC / SMS-Router). The AMF is a **transparent NAS
relay** for the SMS payload — it never parses the SM-CP/SM-RP content; it only routes the NAS
**Payload Container** (type = SMS) between the UE (N1) and the SMSF (Nsmsf_SMService, N20/N21).

This is a **brand-new NF**, created from `nf/_template/`. It mirrors the NAS-Transport
container model already used in this codebase for N1 SM (container type `0x01`) and UE policy
(container type `0x05`); SMS uses container type **`0x02`** (see note below).

Because there is no real SMS-GMSC/IWMSC in this lab, the SMSF terminates against a built-in
**loopback / echo DTE**: an MO SMS submitted by the UE is reflected back as an MT SMS to the
same UE (or a configured peer), proving the full MO + MT round-trip end-to-end.

> **Spec note (Payload Container Type).** The backlog descriptor cited SMS = `0x01`. Per
> TS 24.501 §9.11.3.40 Table 9.11.3.40.1, **`0x01` = N1 SM information** and **`0x02` = SMS**.
> The existing `shared/nas/transport.go` already defines `PayloadContainerTypeSMS = 0x02`.
> This document uses the spec-correct value **`0x02`**. `[VERIFY: confirm against the
> SMSF-facing Nsmsf payload base64 wrapping when implementing]`.

## Specifications

| Topic | Reference |
|---|---|
| SMS over NAS architecture, SMSF role | TS 23.501 §5.20 |
| MO SMS procedure | TS 23.502 §4.13.3 |
| MT SMS procedure | TS 23.502 §4.13.4 |
| SMS management activation / registration in UDM | TS 23.502 §4.13.2 |
| Nsmsf_SMService service (Activate / Deactivate / UplinkSMS) | TS 29.540 §5.2 |
| Namf_Communication_N1N2MessageTransfer (MT delivery) | TS 29.518 §5.2.2.3 |
| UL NAS Transport (SMS payload) | TS 24.501 §8.2.10 |
| DL NAS Transport (SMS payload) | TS 24.501 §8.2.11 |
| Payload Container Type IE (SMS = 0x02) | TS 24.501 §9.11.3.40 |
| SMSF NF registration / discovery | TS 29.510 §5.2 (NF type `SMSF`) |
| SM-CP / SM-RP / SM-TP framing | TS 24.011, TS 23.040 (payload, opaque to AMF) |

## Nsmsf_SMService operations (TS 29.540 §5.2)

| Operation | HTTP | Resource | Purpose |
|---|---|---|---|
| **Activate** | `POST` | `/nsmsf-sms/v2/ue-contexts/{supiOrGpsi}` | Create the UE's SMS context in the SMSF (SMS management activation) |
| **Deactivate** | `DELETE` | `/nsmsf-sms/v2/ue-contexts/{supiOrGpsi}` | Remove the UE's SMS context |
| **UplinkSMS** | `POST` | `/nsmsf-sms/v2/ue-contexts/{supiOrGpsi}/sendsms` | Carry an MO SMS (SM-CP/RP payload) from AMF → SMSF |

- **Activate** body (`UeSmsContextData`, TS 29.540 §6.1.6.2.2): `supi`, `gpsi`, `pei`,
  `amfId`, `accessType`, `traceData?`, `udmGroupId?`, `routingInfo?`, plus the AMF callback
  URI the SMSF uses to push MT SMS back via the AMF.
- **UplinkSMS** body (`SmsRecordData`, TS 29.540 §6.1.6.2.x): `smsPayload` (base64 of the
  SM-CP/SM-RP message lifted from the NAS Payload Container), `smsRecordId`.
- **MT SMS** is *not* a pull from the AMF; the SMSF **originates** it toward the AMF via
  `Namf_Communication_N1N2MessageTransfer` (TS 29.518) targeting the AMF callback registered
  at Activate. This reuses the AMF inbound `namf-comm` SBI server already present in this repo
  (port 8001).

## NAS messages (TS 24.501 §8.2.10 / §8.2.11)

SMS rides the same UL/DL NAS Transport message family already implemented for SM and URSP:

| Message | NAS msg type | Direction | Key IEs |
|---|---|---|---|
| UL NAS TRANSPORT | `0x67` | UE → AMF | Payload Container Type = **SMS (0x02)** · Payload Container (SM-CP/RP) |
| DL NAS TRANSPORT | `0x68` | AMF → UE | Payload Container Type = **SMS (0x02)** · Payload Container (SM-CP/RP) |

- **Payload Container Type (§9.11.3.40):** 1 octet, value `0x02` = SMS.
- **Payload Container (§9.11.3.39, LV-E):** 2-octet length + the opaque SM-CP message
  (RP-DATA / RP-ACK / RP-ERROR carrying the TPDU). The AMF treats it as an opaque blob.
- For SMS, the UL/DL NAS Transport **omit** the PDU-session-related optional IEs
  (PDU Session ID, S-NSSAI, DNN, Request Type) that the N1 SM variant carries.
- These travel **ciphered + integrity-protected** (SHT `0x02`) — SMS over NAS is only allowed
  after the NAS security context is active.

## Sequence diagram

```mermaid
sequenceDiagram
    participant UE
    participant gNB
    participant AMF
    participant SMSF
    participant UDM
    participant NRF
    participant DTE as Loopback DTE (SMS infra sim)

    Note over SMSF,NRF: SMSF startup — NF registration (TS 29.510 §5.2)
    SMSF->>NRF: PUT /nnrf-nfm/v1/nf-instances/{id} (nfType=SMSF, nsmsf-sms)  %% mandatory

    Note over UE,UDM: SMS Management Activation (TS 23.502 §4.13.2) — at Registration or first SMS
    AMF->>UDM: GET /nudm-sdm/v2/{supi}/sms-mng-data  %% conditional (smsSupported?)
    UDM-->>AMF: SmsManagementSubscriptionData {smsSupported, smsf?}
    AMF->>NRF: GET /nnrf-disc nf-instances?target-nf-type=SMSF  %% conditional (no smsf hint)
    NRF-->>AMF: SMSF instance(s)
    AMF->>SMSF: POST /nsmsf-sms/v2/ue-contexts/{supi} (Activate)  %% mandatory for SMS-capable UE
    SMSF->>UDM: PUT /nudm-uecm/v1/{supi}/registrations/smsf-3gpp-access  %% conditional (SMSF registration in UDM)
    SMSF-->>AMF: 201 Created (UeSmsContextData)

    Note over UE,DTE: MO SMS (TS 23.502 §4.13.3)
    UE->>gNB: UL NAS TRANSPORT [0x67] (PCT=SMS 0x02, CP-DATA RP-DATA)  %% mandatory
    gNB->>AMF: N2 UplinkNASTransport (NAS PDU)  %% mandatory
    AMF->>SMSF: POST /nsmsf-sms/v2/ue-contexts/{supi}/sendsms (smsPayload)  %% mandatory
    SMSF->>SMSF: SM-RP/RP-ACK; relay to DTE  %% mandatory
    SMSF-->>AMF: 200 (RP-ACK eventually via DL, see below)
    SMSF->>AMF: N1N2MessageTransfer (DL CP-ACK / RP-ACK)  %% mandatory
    AMF->>UE: DL NAS TRANSPORT [0x68] (PCT=SMS 0x02, CP-ACK/RP-ACK)  %% mandatory
    SMSF->>DTE: submit MO message  %% conditional (loopback test only)

    Note over DTE,UE: MT SMS (TS 23.502 §4.13.4) — loopback reflects MO back as MT
    DTE->>SMSF: deliver MT message  %% conditional (loopback test only)
    SMSF->>AMF: Namf_Communication_N1N2MessageTransfer (n1MessageContainer=SMS)  %% mandatory
    AMF->>UE: DL NAS TRANSPORT [0x68] (PCT=SMS 0x02, CP-DATA RP-DATA)  %% mandatory
    UE->>AMF: UL NAS TRANSPORT [0x67] (PCT=SMS 0x02, CP-ACK / RP-ACK)  %% mandatory
    AMF->>SMSF: POST .../sendsms (delivery report)  %% mandatory
    SMSF->>DTE: delivery report  %% conditional (loopback)
```

## Spec reference table

| Step | TS reference | Message / operation | Direction | Mandatory? |
|---|---|---|---|---|
| 1 | TS 29.510 §5.2 | Nnrf_NFManagement Register (nfType=SMSF) | SMSF→NRF | Yes |
| 2 | TS 23.502 §4.13.2 | Nudm_SDM_Get sms-mng-data | AMF→UDM | Conditional (SMS-capable check) |
| 3 | TS 29.510 §6.2 | Nnrf_NFDiscovery (target SMSF) | AMF→NRF | Conditional (no SMSF hint) |
| 4 | TS 29.540 §5.2.2 | Nsmsf_SMService Activate | AMF→SMSF | Yes (SMS-capable UE) |
| 5 | TS 23.502 §4.13.2 | Nudm_UECM Registration (smsf) | SMSF→UDM | Conditional |
| 6 | TS 24.501 §8.2.10 | UL NAS TRANSPORT (PCT=SMS) | UE→AMF | Yes (MO) |
| 7 | TS 29.540 §5.2.4 | Nsmsf_SMService UplinkSMS (sendsms) | AMF→SMSF | Yes (MO) |
| 8 | TS 29.518 §5.2.2.3 | Namf_Communication_N1N2MessageTransfer | SMSF→AMF | Yes (MO ack / MT) |
| 9 | TS 24.501 §8.2.11 | DL NAS TRANSPORT (PCT=SMS) | AMF→UE | Yes (MT / ack) |
| 10 | TS 29.540 §5.2.3 | Nsmsf_SMService Deactivate | AMF→SMSF | Conditional (dereg) |

## Mandatory IEs

| Message | IE name | Type | Presence | TS reference |
|---|---|---|---|---|
| UL NAS TRANSPORT | Payload Container Type (=SMS 0x02) | 5GMM | Mandatory | TS 24.501 §9.11.3.40 |
| UL NAS TRANSPORT | Payload Container (SM-CP/RP) | 5GMM (LV-E) | Mandatory | TS 24.501 §9.11.3.39 |
| DL NAS TRANSPORT | Payload Container Type (=SMS 0x02) | 5GMM | Mandatory | TS 24.501 §9.11.3.40 |
| DL NAS TRANSPORT | Payload Container (SM-CP/RP) | 5GMM (LV-E) | Mandatory | TS 24.501 §9.11.3.39 |
| Nsmsf Activate (UeSmsContextData) | supi | string | Mandatory | TS 29.540 §6.1.6.2.2 |
| Nsmsf Activate (UeSmsContextData) | amfId | NfInstanceId | Mandatory | TS 29.540 §6.1.6.2.2 |
| Nsmsf Activate (UeSmsContextData) | accessType | enum | Mandatory | TS 29.540 §6.1.6.2.2 |
| Nsmsf Activate (UeSmsContextData) | gpsi / pei | string | Conditional | TS 29.540 §6.1.6.2.2 |
| Nsmsf UplinkSMS (SmsRecordData) | smsPayload | RefToBinaryData | Mandatory | TS 29.540 §6.1.6.2 |
| Nsmsf UplinkSMS (SmsRecordData) | smsRecordId | string | Mandatory | TS 29.540 §6.1.6.2 |
| N1N2MessageTransfer (MT) | n1MessageContainer (n1MessageClass=SMS) | object | Mandatory | TS 29.518 §6.1.6.2 |
| NF profile (register) | nfType = `SMSF` | enum | Mandatory | TS 29.510 §6.1.6.2.2 |
| NF profile (register) | smsfInfo (allowed PLMN, tai list)? | object | Conditional | TS 29.510 §6.1.6.2.x |

## Error / cause cases

| Trigger | 5GMM / SBI cause | NF | Response |
|---|---|---|---|
| UE not subscribed to SMS over NAS | 5GMM cause #27 "N1 mode not allowed" / reject in Reg | AMF | SMS service not activated; UL SMS dropped |
| SMSF context not found on UplinkSMS | 404 `CONTEXT_NOT_FOUND` | SMSF | AMF re-activates (Activate) then retries |
| No SMSF discoverable in NRF | (internal) | AMF | SMS Management Activation deferred; logged FAILURE |
| MT delivery to CM-IDLE UE | (paging) | AMF | Page UE first (TS 23.502 §4.13.4) then DL NAS Transport `[VERIFY: paging-for-SMS clause]` |
| Malformed Payload Container | 5GMM cause #96 "Invalid mandatory information" | AMF/UE | NAS message discarded |
| SMSF UDM UECM registration conflict | 403 / 409 | UDM | SMSF rejects Activate; AMF logs FAILURE |
| smsPayload not decodable by SMS layer | RP-ERROR (TS 24.011) | SMSF | DL NAS Transport carries RP-ERROR |

## NF interaction map (SBI calls)

- `SMSF → NRF: Nnrf_NFManagement_NFRegister (PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId})` — nfType `SMSF`
- `SMSF → NRF: Nnrf_NFManagement_NFUpdate (PATCH …, heartbeat)`
- `AMF → UDM: Nudm_SDM_Get (GET /nudm-sdm/v2/{supi}/sms-mng-data)` — SMS subscription check
- `AMF → NRF: Nnrf_NFDiscovery (GET /nnrf-disc/v1/nf-instances?target-nf-type=SMSF&requester-nf-type=AMF)`
- `AMF → SMSF: Nsmsf_SMService_Activate (POST /nsmsf-sms/v2/ue-contexts/{supiOrGpsi})`
- `AMF → SMSF: Nsmsf_SMService_Deactivate (DELETE /nsmsf-sms/v2/ue-contexts/{supiOrGpsi})`
- `AMF → SMSF: Nsmsf_SMService_UplinkSMS (POST /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}/sendsms)`
- `SMSF → UDM: Nudm_UECM_Registration (PUT /nudm-uecm/v1/{supi}/registrations/smsf-3gpp-access)` — `[VERIFY: exact UECM sub-resource name in Rel-17]`
- `SMSF → AMF: Namf_Communication_N1N2MessageTransfer (POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages)` — MT SMS + MO acks, on AMF inbound namf-comm server (port 8001)

## Implementation notes (for the nf-developer)

**New NF (`nf/smsf/`), copied from `nf/_template/`:**
- `cmd/smsf/main.go` — config → logger → NRF register → SBI server → signals → shutdown.
- `internal/server/` — `nsmsf-sms` SBI producer (HTTP/2 + mTLS): Activate / Deactivate / sendsms.
- `internal/context/` — per-UE SMS context: `{supi, gpsi, amfId, amfN1N2Uri, accessType, state}`.
- `internal/dte/` — loopback echo DTE: on UplinkSMS, build the MT message and originate it back
  via the AMF callback (`Namf_Communication_N1N2MessageTransfer`).
- `internal/sbi/amfclient/` — Namf_Communication client for MT push.
- Logger: `logging.NewProcedureLogger(ctx, "SmsOverNas")`; `nf="SMSF"`, `interface="Nsmsf"|"N1"`,
  `spec_ref` per step; conditional fields `supi`, `gpsi`, `message_type`, `result`.

**SMSF SMS-context state machine (per UE):**
```
INACTIVE   → no SMS context
ACTIVE     → Activate done, UDM UECM registered, ready for MO/MT
RELOCATING → AMF change (Activate from a new AMF) [VERIFY: relocation handling Rel-17]
```

**Redis keys (SMSF):**
- `smsf:uectx:{supi}` → JSON UE SMS context (amfN1N2Uri, accessType, state).
- `smsf:smsrec:{supi}:{smsRecordId}` → in-flight SMS record (TTL) for retransmit/ack correlation.

**AMF side (additive, control-plane + N1 NAS only — no PFCP, no crypto changes):**
- Extend the existing UL NAS Transport handler: when `PayloadContainerType == 0x02` (SMS),
  route the container to the SMSF via `Nsmsf_SMService_UplinkSMS` instead of the SMF SM path.
- Reuse `shared/nas.PayloadContainerTypeSMS` (already `0x02`) and the existing
  `DLNASTransport` encoder to deliver MT SMS / acks (PDU-session IEs omitted for SMS).
- MT path: AMF inbound `namf-comm` N1N2MessageTransfer handler already exists; add an
  `n1MessageClass=SMS` branch that builds a DL NAS Transport with PCT=SMS and the SMSF-provided
  container, then sends it on N2 (or pages a CM-IDLE UE first).
- Store the selected SMSF + UE SMS-activation flag on the AMF UE context so MO routing and
  dereg-time Deactivate are deterministic.

## Scope boundary (this increment)

**In scope (control-plane SBI + N1 NAS path):**
- New `nf/smsf/` NF from `nf/_template/`: NRF registration, `nsmsf-sms` Activate / Deactivate /
  UplinkSMS, per-UE SMS context, loopback echo DTE for MO→MT round-trip.
- AMF: SMS Management Activation toward SMSF; UL NAS Transport (PCT=SMS) → Nsmsf UplinkSMS;
  MT via Namf_Communication_N1N2MessageTransfer → DL NAS Transport (PCT=SMS).
- `shared/nas`: SMS already has `PayloadContainerTypeSMS=0x02`; add SMS-variant encode/decode
  if the SMS UL/DL Transport needs SMS-specific IE handling (omit PDU-session IEs).
- Unit + functional (godog, in-process) tests for MO + MT round-trip via the loopback DTE.

**Hard-stop areas — NOT touched in this increment:**
- No changes to `shared/` crypto primitives.
- No changes to the **PFCP session-management** path (SMS does not use a PDU session).
- No `docker-compose` service definitions edited here — the SMSF container/compose wiring,
  PCAP sidecar, and `/metrics` scrape are a **documented follow-up** (orchestrator will note it).

**Not validated live (documented, same posture as NSSAA / URSP / EAP-AKA'):**
- **UERANSIM v3.2.8 has no SMS-over-NAS UE support** — it cannot originate an UL NAS Transport
  with an SMS container nor process an MT DL NAS Transport. The procedure is therefore validated
  **in-process (unit + functional)**, not on a live UERANSIM UE. The network-side state machine,
  NAS encoding (PCT=0x02), and the Nsmsf + Namf_Communication SBI round-trip are exercised by
  tests; the live N1 UE leg is out of scope until a SMS-capable UE simulator is available.

## Validation

- **Unit (`shared/nas`):** UL/DL NAS Transport with `PayloadContainerType=0x02` round-trips
  byte-exact; SMS variant omits PDU-session optional IEs.
- **Unit (`nf/smsf`):** Activate creates context (201) + UDM UECM call; UplinkSMS on unknown
  context → 404 `CONTEXT_NOT_FOUND`; loopback DTE reflects MO payload into an MT N1N2 transfer.
- **Functional (godog, in-process):** SMSF registers in NRF; AMF activates SMS context; an MO
  SMS (synthetic UL NAS Transport, PCT=SMS) reaches the SMSF via UplinkSMS; the loopback DTE
  drives an MT SMS back through Namf_Communication_N1N2MessageTransfer → DL NAS Transport,
  achieving the MO + MT end-to-end round-trip required by acceptance criterion 3.
- **Acceptance mapping:** (1) NRF registration + Nsmsf Activate/UplinkSMS/MT served → covered;
  (2) AMF UL/DL NAS Transport carries SMS to/from SMSF → covered; (3) MO + MT delivered E2E via
  loopback DTE → covered by the functional scenario.
