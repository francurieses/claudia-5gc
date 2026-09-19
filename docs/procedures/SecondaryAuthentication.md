# Secondary Authentication / Authorization by a DN-AAA Server

**Spec:** TS 23.501 §5.6.6 · TS 23.502 §4.3.2.3 · TS 24.501 §6.4.1 / §8.3.5–§8.3.7 (EAP-in-5GSM) ·
RFC 3748 (EAP framing) · TS 29.502 (Nsmf_PDUSession) · TS 29.244 (N4 PFCP)

## Purpose

Some DNNs require a **DN-specific** authentication/authorization with an external **Data Network
AAA server (DN-AAA)** in addition to the primary 5G (5G-AKA / EAP-AKA') authentication. When the
PDU-session-level subscription for the DNN/S-NSSAI is marked as requiring secondary auth, the SMF
runs an EAP exchange with the DN-AAA **during PDU Session Establishment** before the session is
accepted.

Roles (TS 23.501 §5.6.6, RFC 3748):

- **UE** — EAP peer.
- **SMF** — EAP **pass-through authenticator**. It relays opaque EAP packets between the UE
  (N1 NAS, via the AMF) and the DN-AAA (N6), gates the Establishment Accept/Reject on the EAP
  result, and stores DN authorization data returned by the AAA.
- **DN-AAA** — EAP server (back-end authentication server). Reached over **N6**, typically via
  RADIUS/Diameter, either directly from the SMF or via the UPF (see below).
- **AMF** — transparent NAS relay for the 5GSM messages (existing UL/DL NAS transport path);
  it does **not** interpret the EAP payload.

This implementation follows the same posture as NSSAA (AMF-005) and EAP-AKA' (AUSF): the DN-AAA
is a **simulated in-core EAP server** that runs a single EAP round (Identity → Success/Failure).
UERANSIM v3.2.8 has no secondary-auth UE peer, so the live N1 leg is not exercised E2E; the
network-side state machine + NAS encoding are validated by unit + functional tests (see
**Known limitations**).

## Specifications

| Topic | Reference |
|---|---|
| Secondary auth/authorization architecture & roles | TS 23.501 §5.6.6 |
| Secondary auth during PDU Session Establishment (message flow) | TS 23.502 §4.3.2.3 |
| DN-AAA via external N6 / via UPF over N6 | TS 23.502 §4.3.2.3 (step notes) · TS 23.501 §5.6.6 |
| PDU SESSION AUTHENTICATION COMMAND | TS 24.501 §8.3.5 |
| PDU SESSION AUTHENTICATION COMPLETE | TS 24.501 §8.3.6 |
| PDU SESSION AUTHENTICATION RESULT | TS 24.501 §8.3.7 |
| PDU SESSION ESTABLISHMENT ACCEPT / REJECT | TS 24.501 §8.3.2 / §8.3.3 |
| EAP message IE | TS 24.501 §9.11.2.2 (LV-E in auth messages; TLV-E, IEI `0x78` in Accept/Reject) |
| 5GSM cause values | TS 24.501 §9.11.4.2 |
| N1 SM container transport (DL/UL NAS Transport) | TS 24.501 §8.2.10 / §8.2.11 |
| Nsmf_PDUSession (SM context, N1N2 relay) | TS 29.502 §5.2.2 |
| EAP packet format | RFC 3748 §4 |

## DN-AAA reachability (two N6 variants — TS 23.502 §4.3.2.3)

3GPP defines two ways for the SMF to reach the DN-AAA over N6:

1. **External DN-AAA over N6 (covered here).** The SMF has direct IP reachability to the DN-AAA
   and exchanges EAP encapsulated in RADIUS/Diameter. In this project the DN-AAA is a **simulated
   in-core EAP server** fronted behind an SMF-internal endpoint (mirrors `nf/ausf/internal/server/nssaa.go`).
2. **DN-AAA via the UPF over N6 (documented only).** The SMF sends the EAP/AAA traffic through the
   UPF acting as the N6 forwarding point toward the DN-AAA. This requires the N4 rules to permit the
   AAA traffic and the UPF to relay it. **Not implemented** in this increment — flagged as a note.
   `[VERIFY: whether the deployment ever needs the "via UPF" N6 variant, or the external-N6 variant is sufficient for all target DNNs]`

## Sequence Diagram

```mermaid
sequenceDiagram
    participant UE
    participant AMF
    participant SMF as SMF (EAP authenticator)
    participant UPF
    participant AAA as DN-AAA (simulated, N6)

    Note over UE,AMF: UE registered, primary auth complete
    UE->>AMF: PDU SESSION ESTABLISHMENT REQUEST [0xC1] (in UL NAS Transport 0x67)
    AMF->>SMF: POST /nsmf-pdusession/v1/sm-contexts {n1SmMsg, dnn, snssai, supi}  (N11)
    SMF->>SMF: N10 sm-data → DNN/S-NSSAI requires secondary auth? (mandatory gate)

    alt DNN requires secondary DN-AAA auth
        Note over SMF: EAP authenticator starts EAP (EAP-Req/Identity, id=n)
        SMF-->>AMF: N1N2MessageTransfer {n1SmMsg: PDU SESSION AUTH COMMAND [0xC5] (EAP-Req/Identity)}
        AMF->>UE: DL NAS Transport [0x68] ⊇ AUTH COMMAND (EAP-Request/Identity)   (N1)
        UE->>AMF: UL NAS Transport [0x67] ⊇ AUTH COMPLETE [0xC6] (EAP-Response/Identity)  (N1)
        AMF->>SMF: POST .../sm-contexts/{ref}/modify {n1SmMsg: AUTH COMPLETE}  (N11)

        loop EAP method rounds (opaque to SMF)
            SMF->>AAA: relay EAP-Response over N6 (RADIUS/Diameter; simulated in-core)
            AAA-->>SMF: EAP-Request (more rounds) | EAP-Success | EAP-Failure
            alt EAP-Request (more rounds)
                SMF-->>AMF: N1N2 {AUTH COMMAND [0xC5] (EAP-Request)}
                AMF->>UE: DL NAS Transport ⊇ AUTH COMMAND
                UE->>AMF: UL NAS Transport ⊇ AUTH COMPLETE [0xC6] (EAP-Response)
                AMF->>SMF: modify {AUTH COMPLETE}
            end
        end

        alt EAP-Success (authorized)
            opt terminal result before Accept
                SMF-->>AMF: N1N2 {AUTH RESULT [0xC7] (EAP-Success)}
                AMF->>UE: DL NAS Transport ⊇ AUTH RESULT (EAP-Success)
            end
            SMF->>UPF: N4 PFCP Session Establishment (PDRs/FARs/QERs)  (N4)
            UPF-->>SMF: N4 PFCP Session Establishment Response
            SMF-->>AMF: N1N2 {ESTABLISHMENT ACCEPT [0xC2] (EAP-Success, IEI 0x78)} + N2 SM
            AMF->>UE: DL NAS Transport ⊇ ESTABLISHMENT ACCEPT
        else EAP-Failure (rejected) or AAA unreachable
            SMF-->>AMF: N1N2 {ESTABLISHMENT REJECT [0xC3] (5GSM cause #29, EAP-Failure IEI 0x78)}
            AMF->>UE: DL NAS Transport ⊇ ESTABLISHMENT REJECT
            Note over SMF: no N4 session created; UE IP released
        end
    else DNN does not require secondary auth
        Note over SMF: normal PDU Session Establishment (no EAP round) — see PduSessionEstablishment.md
    end
```

Legend — mandatory vs conditional per the spec:

- **Mandatory** (always present once the DNN requires secondary auth): the sm-data gate check,
  at least one AUTH COMMAND / AUTH COMPLETE round, the terminal EAP-Success/Failure, and the
  resulting ESTABLISHMENT ACCEPT **or** REJECT.
- **Conditional**: additional EAP method rounds (0..n, method-dependent); the standalone
  AUTH RESULT [0xC7] carrying EAP-Success (the EAP-Success MAY instead be conveyed only inside the
  ESTABLISHMENT ACCEPT — TS 24.501 §6.4.1.4); the "via UPF" N6 path.

## Information Elements

### NAS message types (5GSM, TS 24.501 §8.3)

| Message | Type | Direction | Mandatory IEs | Optional IEs |
|---|---|---|---|---|
| PDU SESSION ESTABLISHMENT REQUEST | `0xC1` | UE → SMF | PDU session type, etc. (§8.3.1) | — |
| PDU SESSION AUTHENTICATION COMMAND | `0xC5` | SMF → UE | **EAP message** (§9.11.2.2, LV-E) | EPCO (IEI `0x7B`) |
| PDU SESSION AUTHENTICATION COMPLETE | `0xC6` | UE → SMF | **EAP message** (§9.11.2.2, LV-E) | EPCO (IEI `0x7B`) |
| PDU SESSION AUTHENTICATION RESULT | `0xC7` | SMF → UE | **EAP message** (§9.11.2.2, LV-E) | EPCO (IEI `0x7B`) |
| PDU SESSION ESTABLISHMENT ACCEPT | `0xC2` | SMF → UE | PDU session type, QoS rules, Session-AMBR | **EAP message** (IEI `0x78`, TLV-E, = EAP-Success) |
| PDU SESSION ESTABLISHMENT REJECT | `0xC3` | SMF → UE | **5GSM cause** (§9.11.4.2) | **EAP message** (IEI `0x78`, TLV-E, = EAP-Failure) |

Common 5GSM header (all of the above): Extended protocol discriminator `0x2E` (5GS Session
Management) · PDU session ID · PTI · Message type.

### EAP message IE (TS 24.501 §9.11.2.2)

| Field | Value / format |
|---|---|
| In AUTH COMMAND/COMPLETE/RESULT | **LV-E** — 2-octet length + EAP packet (no IEI; mandatory position) |
| In ESTABLISHMENT ACCEPT/REJECT | **TLV-E** — IEI `0x78` + 2-octet length + EAP packet (optional) |
| EAP packet | RFC 3748 §4: code (1) · identifier (1) · length (2) · type/data |
| EAP codes used | Request `0x01`, Response `0x02`, Success `0x03`, Failure `0x04` |

`[VERIFY: EAP message IEI in ESTABLISHMENT ACCEPT/REJECT is 0x78 per TS 24.501 Table 8.3.2.1.1 / 8.3.3.1.1 — confirm against the Rel-17 text before wiring the codec]`

### Key scalar IEs

| IE | Reference | Notes |
|---|---|---|
| PDU session ID | TS 24.501 §9.4 (PDU session ID octet) | Correlates all messages of the session |
| PTI (Procedure Transaction Identity) | TS 24.501 §9.6 | Set by the UE on the Establishment Request; echoed by the SMF |
| 5GSM cause | TS 24.501 §9.11.4.2 | Mandatory in ESTABLISHMENT REJECT; see Error cases |

## Error cases / rejection (TS 24.501 §9.11.4.2)

| Trigger | 5GSM cause | Resulting message | Handling |
|---|---|---|---|
| DN-AAA returns **EAP-Failure** | **#29** "User authentication or authorization failed" | ESTABLISHMENT REJECT `0xC3` + EAP-Failure (IEI `0x78`) | No N4 session; UE IP released; `result=REJECT`, `cause=29` |
| DN-AAA **unreachable / timeout** | **#29** (auth failed) or **#38** "Network failure" | ESTABLISHMENT REJECT `0xC3` (EAP-Failure optional) | SMF times out the EAP wait; treat as failure. `[VERIFY: whether to map AAA-unreachable to #29 or #38 — TS 24.501 permits #38 "Network failure"; NSSAA models unreachable as a plain failure]` |
| **Malformed EAP** packet from UE or DN-AAA | **#95** "Semantically incorrect message" or **#96** "Invalid mandatory information" | ESTABLISHMENT REJECT `0xC3` | EAP packet fails RFC 3748 length/code validation (`shared/crypto/eap.Validate`) |
| **UE aborts** (5GSM STATUS `0xD6` or no AUTH COMPLETE within timer) | **#29** / procedure abort | Session establishment aborted | SMF drops pending auth state; releases allocated IP |
| DNN requires secondary auth but subscription/DN-AAA config missing | **#31** "Request rejected, unspecified" | ESTABLISHMENT REJECT `0xC3` | Misconfiguration guard; logged `WARN` |

**Documented 5GSM cause values:** **#29** (User authentication or authorization failed — primary
failure cause), **#38** (Network failure — AAA unreachable variant), **#31** (Request rejected,
unspecified — config guard), **#95** (Semantically incorrect message — malformed EAP),
**#96** (Invalid mandatory information — malformed EAP). All per TS 24.501 §9.11.4.2.

## NF interaction map

Secondary authentication rides on the **existing** PDU Session Establishment SBI/N4 plumbing plus
one internal EAP relay; it introduces no new externally-visible NF. Operations/URIs from
`specs/3gpp-openapi/` (TS 29.502 Nsmf_PDUSession, TS 29.503 Nudm_SDM):

- `AMF → SMF: Nsmf_PDUSession_CreateSMContext (POST /nsmf-pdusession/v1/sm-contexts)` — carries the
  Establishment Request `n1SmMsg`.
- `AMF → SMF: Nsmf_PDUSession_UpdateSMContext (POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify)`
  — carries each UE AUTH COMPLETE.
- `SMF → AMF: Namf_Communication_N1N2MessageTransfer (POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages)`
  — delivers each AUTH COMMAND / AUTH RESULT / final ACCEPT|REJECT to the UE (mTLS SBI, port 8001).
- `SMF → UDM: Nudm_SDM_Get (GET /nudm-sdm/v2/{supi}/sm-data)` — the DNN/S-NSSAI subscription that
  carries the "secondary auth required" flag (same fetch already used for subscribed default QoS).
- `SMF → DN-AAA: EAP over N6` — RADIUS/Diameter in a real deployment; here an **SMF-internal
  simulated EAP server** (Identity → Success/Failure), mirroring `nf/ausf/internal/server/nssaa.go`.
- `SMF → UPF: PFCP Session Establishment (N4)` — only after EAP-Success, unchanged from
  PduSessionEstablishment.

`[VERIFY: exact Nudm_SDM sm-data field name that flags secondary auth for a DNN — TS 29.503 SessionManagementSubscriptionData / DnnConfiguration; the checked-in specs/3gpp-openapi/ did not surface a "secondaryAuth" key in a quick grep, so confirm the Rel-17 attribute name (e.g. under dnnConfigurations) before plumbing UDR→UDM→SMF]`

## Implementation notes

**Target package:** `nf/smf/internal/server/` — a new `secondary_auth.go` alongside the existing
establishment path in `server.go` (`handleCreateSMContext`, TS 29.502 §5.2.2.3.1) and
`handleUpdateSMContext`.

- **Gate check.** In `handleCreateSMContext`, after the DNN/S-NSSAI is resolved and the sm-data is
  fetched (the same N10 `Nudm_SDM_Get sm-data` call that today yields subscribed default QoS —
  see `nf/smf/internal/server/qos.go`), branch on the "secondary auth required" flag. If set, do
  **not** immediately proceed to PFCP Session Establishment; instead enter the EAP sub-procedure
  and hold the session in a `PENDING_SECONDARY_AUTH` state.
- **State machine (per PDU session).** Mirror the NSSAA AMF state machine:
  ```
  PENDING_AUTH    → AUTH COMMAND sent (EAP-Req), awaiting AUTH COMPLETE
  AWAITING_AAA    → AUTH COMPLETE received, EAP relayed to DN-AAA, awaiting result
  AUTHORIZED      → EAP-Success → proceed to N4 PFCP + ESTABLISHMENT ACCEPT
  REJECTED        → EAP-Failure/timeout → ESTABLISHMENT REJECT (5GSM cause #29)
  ```
  Store this on the `Session` context (`internal/session/`); one EAP exchange runs at a time per PSI.
- **EAP framing.** Reuse `shared/crypto/eap` (RFC 3748 Identity/Success/Failure — the same generic
  helpers the AUSF NSSAA relay uses). The EAP method is opaque to the SMF; only Identity → terminal
  Success/Failure is needed for the simulated DN-AAA. Do **not** invent a new EAP codec.
- **Simulated DN-AAA.** Add an SMF-internal EAP server function (deterministic decision, e.g. reject
  when the EAP-Response/Identity NAI contains "reject") mirroring `nf/ausf/internal/server/nssaa.go`
  — same "simulated external AAA reachable over N6" posture. Later replaceable by a real
  RADIUS/Diameter N6 client without changing the state machine.
- **NAS encoding (shared/nas TLV — Protocol Encoding Rules).** Message types `0xC5`/`0xC6`/`0xC7`
  are already defined in `shared/nas/nas.go`; the AUTH COMMAND/COMPLETE/RESULT **body encoders do
  not yet exist**. Add them next to the NSSAA codec (`shared/nas/nssaa.go`) which already has an
  `encodeEAPMessageLVE` / `decodeEAPMessageLVE` helper for the EAP message IE (§9.11.2.2, LV-E) —
  reuse it. For ESTABLISHMENT ACCEPT/REJECT the EAP message is the optional TLV-E IEI `0x78`
  (extend `pdu_session.go`; the `Cause5GSM` IEI `0x37`/reject-cause path already exists).
  All NAS is hand-written spec-faithful TLV per `shared/nas/` — no bespoke formats.
- **N1 relay via AMF.** Each AUTH COMMAND / AUTH RESULT / final ACCEPT|REJECT is pushed to the UE
  through `Namf_Communication_N1N2MessageTransfer` on the AMF's mTLS SBI (`peers.amf` = `amf:8001`,
  the same client `server.go` already uses for the DL-data-notification/paging path via
  `sbi.NewMTLSClient`). The UE's AUTH COMPLETE arrives back as an `UpdateSMContext` modify call —
  extend `handleUpdateSMContext` to recognise a `0xC6` body (it already branches on `0xC9`
  Modification Request).
- **N4 timing.** PFCP Session Establishment (`sendPFCPSessionEstablishment`, N4, `shared/pfcp` TLV
  per TS 29.244) fires **only** in the `AUTHORIZED` transition. On `REJECTED`, release the
  allocated UE IP (`IPPool.Release`) and never create the N4 session.
- **Logging.** Use `logging.NewProcedureLogger(ctx, "SecondaryAuthentication")`; NF `SMF`,
  interface `N1`/`N6`/`N4` per leg, `direction`, `spec_ref` `TS 23.502 §4.3.2.3 step X`,
  conditional fields `supi`, `pdu_session_id`, `result` (`OK`/`REJECT`/`FAILURE`), `cause`.
- **Timers.** Guard the AWAITING_AAA and PENDING_AUTH waits with a bounded timer (documented
  constant with spec ref, no magic number) so a stuck DN-AAA or a silent UE yields a clean REJECT.

## Known limitations

- **DN-AAA is a simulated in-core EAP server** for this MVP (single round: Identity →
  Success/Failure, deterministic decision). No real RADIUS/Diameter N6 client and no external
  AAA-S — same posture as NSSAA (AMF-005), EAP-AKA' (AUSF), and URSP.
- **Live N1 UE leg not exercised.** UERANSIM v3.2.8 has **no secondary-authentication peer** — it
  cannot answer a PDU SESSION AUTHENTICATION COMMAND. The network-side state machine + NAS encoding
  are validated by unit + in-process functional (godog) tests, not a live UE round-trip.
- **"DN-AAA via UPF over N6" variant is documented only**, not implemented — only the external-N6
  (SMF-direct) path is built.
- Depends on **SMF-002** (PDU Session Establishment control/data plane) being in place; secondary
  auth is an in-line gate on that flow.

## REPORT — procedure-planner
- task_id: SMF-003
- status: DONE
- file_created: docs/procedures/SecondaryAuthentication.md
- steps_in_flow: 11  ·  messages: 12  ·  error_cases: 5
- verify_items:
  - `[VERIFY]` "via UPF" N6 variant actually needed for target DNNs
  - `[VERIFY]` EAP message IEI `0x78` in ESTABLISHMENT ACCEPT/REJECT vs Rel-17 Tables 8.3.2.1.1 / 8.3.3.1.1
  - `[VERIFY]` AAA-unreachable cause mapping (#29 vs #38 Network failure)
  - `[VERIFY]` Nudm_SDM sm-data attribute name flagging secondary auth per DNN (TS 29.503 DnnConfiguration)
- acceptance_criteria_coverage: full
  - "SMF relays EAP between UE and DN-AAA over N4/N6" → sequence diagram EAP round-trip + NF interaction map + N6 variants section (relayed via N1 through AMF on the UE side and N6 to DN-AAA on the network side)
  - "Establishment rejected on AAA failure with the correct 5GSM cause" → Error cases table (5GSM cause #29 primary) + REJECT branch of the sequence diagram + IE table

## Conformance Notes — 2026-07-23

**Verdict**: CONFORMANT-WITH-NOTES (no BLOCKER, no MAJOR)

Audited files: `shared/nas/secondary_auth.go`, `nf/smf/internal/server/secondary_auth.go`,
`nf/smf/internal/server/server.go`, `nf/smf/internal/config/config.go`. Byte layouts verified
manually against TS 24.501 §8.3.3/§8.3.5-7 and §9.11.2.2 (the MCP `nas_decode`/`tlv_inspect`
tools are 5GMM/Type-4-TLV oriented and cannot validate plain 5GSM messages or the 2-octet TLV-E
length, so they were not authoritative here).

### Confirmed CONFORMANT
- 5GSM header shape `EPD 0x2E | PDU session ID | PTI | Message type` on 0xC5/0xC6/0xC7/0xC3 (§9.1.1).
- EAP message IE **LV-E** (2-octet length, no IEI) in AUTH COMMAND/COMPLETE/RESULT (§9.11.2.2).
- EAP message IE **TLV-E, IEI 0x78** in ESTABLISHMENT ACCEPT/REJECT (§9.11.2.2, Tables 8.3.2.1.1/8.3.3.1.1).
- 5GSM cause **#29 = 0x1D** "User authentication or authorization failed" — correct value, placed as
  mandatory Type-3 V (no IEI) immediately after the message type in REJECT (§8.3.3, §9.11.4.2).
- No PFCP/N4 session before EAP-Success: `sendPFCPSessionEstablishment` is reached only in
  `completeSecondaryAuth` (AUTHORIZED transition); the CreateSMContext gate returns 201 + smContextRef
  before any PCF/N4 work. On REJECT the reserved UE IPv4 and IPv6 prefix are released and no N4 session
  is created (§4.3.2.3).
- No regression: the gate `secondaryAuthRequired(dnn)` reads a map populated only from DNNs flagged
  `secondary_auth: true`; an unflagged DNN falls through to the unchanged establishment path byte-identically.
- Architecture decision (push AUTH COMMAND/RESULT/ACCEPT/REJECT via Namf_Communication_N1N2MessageTransfer
  rather than inline in the CreateSMContext response) is spec-acceptable — arguably *more* faithful to
  §4.3.2.3, where subsequent N1 SM messages are delivered via N1N2MessageTransfer and the CreateSMContext
  response only returns the SM context reference.
- spec_ref fields in the new log calls cite the correct TS/step (N1N2 push failures → TS 29.518 §5.2.2.3;
  reject → TS 24.501 §9.11.4.2; flow steps → TS 23.502 §4.3.2.3).

### Findings
| # | Severity | Finding | TS Clause | Recommendation |
|---|----------|---------|-----------|----------------|
| 1 | MINOR | In the ESTABLISHMENT ACCEPT, the EAP message IE (IEI 0x78) is appended after the DNN (0x25) and Authorized QoS flow descriptions (0x79) IEs (`secondary_auth.go:393`). Per the IE order of Table 8.3.2.1.1 the EAP message (0x78) precedes 0x79 and 0x25. The existing encoder is otherwise order-disciplined (it explicitly places 0x79 before 0x25). TS 24.007 §11.2.1.1 makes the non-imperative part generally order-tolerant, so most decoders accept it — but the project's own Nokia precedent shows strict decoders reject out-of-order IEs. | TS 24.501 §8.3.2, Table 8.3.2.1.1 | Insert the 0x78 EAP message IE into the Accept body between the S-NSSAI (0x22) and Authorized QoS flow desc (0x79) IEs, matching the table order, rather than appending it last. |
| 2 | NOTE | DN-AAA unreachable/timeout maps to cause #29 (same as EAP-Failure) at `secondary_auth.go:302,450`. Spec permits #38 "Network failure" for this case. | TS 24.501 §9.11.4.2 | Acceptable per the doc [VERIFY]; #38 is arguably more precise for unreachable/timeout. Optional hardening. |
| 3 | NOTE | New correctly-named `Cause5GSMUserAuthOrAuthorizationFailed = 0x1D` now shadows the pre-existing `Cause5GSMReactivationRequested = 0x1D` (`pdu_session.go:496`), whose name is wrong (5GSM "Reactivation requested" is #39 = 0x27, not 0x1D) and which is dead code (no callers). Pre-existing, out of scope. | TS 24.501 §9.11.4.2 | Remove/rename the misnamed dead constant in a cleanup pass to avoid two same-valued constants. |
| 4 | NOTE | The secondary-auth gate is driven by static per-DNN SMF config (`secondaryAuthDNNs`), not the UDM SM subscription data. | TS 23.501 §5.6.6 | Conformant — §5.6.6 explicitly allows the trigger to come from "local policies or the SM subscription data". Subscription-driven gating remains a future enhancement (matches the doc [VERIFY] on the Nudm_SDM attribute name). |
