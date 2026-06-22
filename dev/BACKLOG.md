# dev/BACKLOG.md — Agentic Development Backlog

Task queue for autonomous ORCHESTRATOR sessions. Derived from a TS 23.501 §5 gap
analysis, **reconciled against the live codebase** (2026-06-18).

Format: one YAML task per entry. Status values: `TODO`, `IN_PROGRESS`, `DONE`, `BLOCKED`.
Priorities: `P1` (highest) > `P2` > `P3`. The ORCHESTRATOR selects the highest-priority
`TODO` task whose `depends_on` are all `DONE`, preferring `depends_on: []`.

This backlog lists **pending work only**. Completed/pre-existing procedures (Initial &
Mobility & Periodic Registration, Service Request, PDU Session Establishment/Release,
UE-requested PDU Modification, NW-initiated QoS Mod, Xn/N2 Handover, URSP delivery,
NRF Subscribe/Notify + DNN/SNSSAI discovery, SUCI Profile A, per-DNN isolation) are
recorded in `docs/compliance-matrix.md`, not here.

Scope legend: **[proc]** = procedure on an existing NF · **[NF]** = a brand-new NF
(copy `nf/_template/`, read its CLAUDE.md) · **[dataplane]** = UPF/PFCP path (hard-stop
adjacent — see AGENTS.md).

---

## P1 — Core control-plane completeness

```yaml
- id: AMF-002
  nf: AMF
  scope: proc
  procedure: UEContextTransfer
  title: "Namf_Communication UEContextTransfer server side (TS 29.518 §5.3.2)"
  spec_ref: "TS 23.502 §4.2.2.2.3 step 6, TS 29.518 §5.3.2"
  description: >
    AMF has no inbound SBI server (namf-comm, port 8001); only the outbound client and
    OAuth2 service registration exist. POST /namf-comm/v1/ue-contexts/{id}/transfer is
    required for AMF change during mobility registration.
  acceptance_criteria:
    - AMF exposes an inbound namf-comm SBI server (mTLS + HTTP/2, h2 ALPN)
    - Endpoint returns UEContextTransferRspData with security context and PDU sessions
    - Old AMF marks the context as transferred
  depends_on: []
  status: DONE
  priority: P1
  notes: >
    DONE (Session 2, 2026-06-18). Producer side implemented: nf/amf/internal/sbi/
    (first AMF inbound SBI server, port 8001, mTLS + h2 ALPN). Endpoint
    POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer returns UeContextTransferRspData
    (mmContextList with NasSecurityMode NIAx/NEAx + kamf; sessionContextList) and marks the
    context Transferred. Causes CONTEXT_NOT_FOUND (404), MANDATORY_IE_MISSING (400).
    5 unit tests + 3 godog scenarios (in-process). Gaps left for follow-up: regRequest
    integrity replay, consumer (new-AMF) side, RegistrationStatusUpdate to release old ctx.

- id: AMF-004
  nf: AMF
  scope: proc
  procedure: NetworkTriggeredServiceRequest
  title: "CN Paging + Network-Triggered Service Request (TS 23.502 §4.2.3.3)"
  spec_ref: "TS 23.501 §5.3.3, TS 23.502 §4.2.3.3, TS 38.413 §8.5 (Paging)"
  description: >
    No paging exists. When downlink data arrives for a CM-IDLE UE, SMF must notify AMF
    (N11 N1N2MessageTransfer), AMF pages the UE over N2, and the UE performs a Service
    Request. Without this, mobile-terminated traffic to idle UEs is dropped.
  acceptance_criteria:
    - SMF/UPF detects DL data for an idle UE and triggers Namf_Communication_N1N2MessageTransfer
    - AMF emits NGAP Paging to the registered TAI list
    - UE Service Request re-activates the user-plane; DL data flows
  depends_on: []
  status: DONE
  priority: P1
  notes: >
    DONE (Session 2, 2026-06-18) — control-plane core, live-validated on UERANSIM.
    AMF: NGAP Paging builder + SendPaging (nf/amf/internal/ngap, ProcCode=24, 5G-S-TMSI
    + TAIListForPaging) and Namf_Communication_N1N2MessageTransfer producer endpoint on
    the namf-comm SBI server (CM-IDLE → 202 ATTEMPTING_TO_REACH_UE + Paging; CM-CONNECTED
    → 200 N1_N2_TRANSFER_INITIATED; unknown → 404). PendingN1N2 cleared on Service Request.
    SMF: dl-data-notification mgmt endpoint simulates the UPF DDN and calls AMF over mTLS
    SBI (SMF SBI client upgraded to mTLS). Live: SMF→AMF N1N2 returned N1_N2_TRANSFER_INITIATED
    (HTTP 200). Unit (BuildPaging round-trip, N1N2 handler) + 3 godog scenarios.
    REMAINING (UPF-001, hard-stop): the real N4 PFCP Session Report (Downlink Data Report) and
    buffered-data forwarding — the DL-data trigger is currently simulated at the SMF.

- id: UDM-001
  nf: UDM
  scope: proc
  procedure: NudmSDMSubscribe
  title: "Nudm_SDM_Subscribe/Notify (TS 29.503 §5.3.2)"
  spec_ref: "TS 23.501 §5.2.3.3, TS 29.503 §5.3.2"
  description: >
    UDM serves GET only. NFs cannot be notified of subscriber data changes in UDR
    without a restart.
  acceptance_criteria:
    - POST /nudm-sdm/v2/{supi}/sdm-subscriptions creates a subscription
    - A UDR data change triggers Nudm_SDM_Notify to the subscriber
    - Integration test verifies AMF notified within 2 s of an AMBR change
  depends_on: []
  status: DONE
  priority: P1
  notes: >
    DONE (Session 3, 2026-06-19). POST /nudm-sdm/v2/{supi}/sdm-subscriptions (201+Location+subscriptionId),
    DELETE /nudm-sdm/v2/{supi}/sdm-subscriptions/{id} (204), POST /nudm-mgmt/v1/{supi}/data-change
    (internal trigger, async fan-out to subscribers). In-memory store via subscriptionList+sync.Mutex.
    UDM MakeFIle test-functional added. 3 godog scenarios: happy path, unsubscribe, missing callbackRef.
    make build PASS · make test PASS · functional 3/3 PASS.

- id: PCF-001
  nf: PCF
  scope: proc
  procedure: AMPolicyAssociation
  title: "AM Policy Association (npcf-ampolicycontrol, TS 29.507)"
  spec_ref: "TS 23.501 §5.6.2, TS 29.507 §4.2.2"
  description: >
    PCF has SM policy and UE policy. AM Policy (RFSP, UE-AMBR, service area restrictions)
    via npcf-ampolicycontrol is missing. AMF must create the association at registration.
  acceptance_criteria:
    - POST /npcf-ampolicycontrol/v1/policies creates an AM policy association
    - Response includes RFSP index and service area restrictions
    - AMF creates the association during Initial Registration
  depends_on: []
  status: DONE
  priority: P1
  notes: >
    DONE (Session 4, 2026-06-19). PCF: handleCreateAMPolicy (POST, 201 + polAssoId + rfsp) +
    handleDeleteAMPolicy (DELETE, 204 / 404) in nf/pcf/internal/server/server.go. 4 unit tests
    (am_policy_test.go) covering happy path, missing supi/accessType, delete idempotency.
    AMF consumer: AMPolicyClient interface + HTTPAMPolicyClient in cmd/amf/clients.go;
    WithAMPolicy() on RegistrationHandler; Phase3 step 14c call (non-fatal); AMPolicyAssocID +
    RFSP fields added to UEContext. Release at UE-initiated + NW-initiated deregistration.
    ReleaseAMPolicy/ReleasePCFPolicy helpers in registration.go. make build PASS · make test PASS.

- id: AMF-003
  nf: AMF
  scope: proc
  procedure: ServiceAreaRestriction
  title: "Service Area Restriction enforcement (TS 23.501 §5.3.4)"
  spec_ref: "TS 23.501 §5.3.4, TS 23.502 §4.2.2.2.2 step 14c"
  description: >
    No restriction enforcement exists; the TA list is static. AMF must reject
    registrations from non-allowed TAs with 5GMM cause #73.
  acceptance_criteria:
    - Registration from a restricted TA rejected with cause #73
    - Allowed-TA list in Registration Accept reflects PCF policy
  depends_on: [PCF-001]
  status: DONE
  priority: P1
  notes: >
    DONE (Session 4, 2026-06-19). ServiceAreaRestriction type added to amfctx; ServAreaRes
    field in UEContext; isAllowedTA helper (ALLOWED_AREAS / NOT_ALLOWED_AREAS / empty=unrestricted);
    Phase3 enforces SAR after AM policy creation — rejects with ErrServiceAreaRestricted; NAS handler
    sends Registration Reject cause #73 (0x49, "Serving network not authorized") on that error.
    RegistrationReject struct + EncodeRegistrationReject added to shared/nas/registration.go.
    HTTPAMPolicyClient extended to decode servAreaRes from PCF response.
    6 unit tests in service_area_restriction_test.go. make build PASS · make test PASS.
    Current PCF (dev.yaml) returns no servAreaRes (unrestricted) — SAR activated by per-subscriber
    PCF config extension (future UDR integration point).

- id: SMF-002
  nf: SMF
  scope: dataplane
  procedure: IPv6PrefixDelegation
  title: "IPv6 / IPv4v6 PDU session prefix delegation (TS 23.501 §5.8.2)"
  spec_ref: "TS 23.501 §5.8.2.2, TS 23.502 §4.3.2"
  description: >
    Only IPv4 is allocated. IPv6 prefix (and IPv4v6) allocation + Router Advertisement
    on the N6 TUN is missing.
  acceptance_criteria:
    - PDU session type IPv6 / IPv4v6 allocates a /64 from a configured pool
    - SMF returns the prefix in the Establishment Accept (PDU Address IE)
    - UPF advertises the prefix (RA) on the per-DNN TUN
  depends_on: []
  status: BLOCKED
  priority: P1
  notes: >
    CONTROL-PLANE DONE, DATA-PLANE ESCALATED (Session 5, 2026-06-19). Implemented the SMF
    control-plane half: requested-type decode (nf/smf/internal/server/server.go), selectPDUSessionType
    + IPv6 /64-delegating pool + IID (nf/smf/internal/server/ipv6.go), spec-correct PDU Address IE
    (IID for IPv6, IID+IPv4 for IPv4v6 — TS 24.501 §9.11.4.10) + new
    EncodePDUSessionEstablishmentAcceptBodyWithQoSAddr in shared/nas/pdu_session.go, and the N2
    PDUSessionType IE threaded through buildPDUSessionResourceSetupRequestTransfer. Gated behind
    per-DNN `ue_ipv6_prefix` (ims=2001:db8:61::/56 in dev.yaml); IPv4 byte-identical (regression test).
    Tests: shared/nas PDU Address IE byte-exact (v4/v6/v4v6) + IPv4 no-regression; smf selectPDUSessionType
    truth table + IPv6 pool allocate/release/reuse/exhaustion; 6 godog scenarios (make -C nf/smf test-functional).
    BLOCKED on the data-plane half (HARD STOP, requires_human): installing the UE IPv6 address in the UPF
    PFCP PDR + Router Advertisement of the /64 on the per-DNN TUN. Acceptance criterion 3 (UPF advertises
    the prefix) is unmet until that human-signed-off UPF/PFCP work lands (tracked with UPF-001). See
    docs/procedures/ipv6-prefix-delegation.md (scope boundary) + dev/SESSION_LOG.md Session 5.
```

## P2 — Policy depth, security methods, and missing SBA NFs

```yaml
- id: AUSF-001
  nf: AUSF
  scope: proc
  procedure: EapAkaPrime
  title: "EAP-AKA' authentication method (TS 33.501 §6.1.3.1)"
  spec_ref: "TS 33.501 §6.1.3.1, TS 29.509"
  description: "Only 5G-AKA is implemented; EAP-AKA' (RFC 5448) round-trip is missing."
  acceptance_criteria:
    - AUSF drives EAP-Request/AKA'-Challenge ↔ EAP-Response round-trip
    - EAP-Success carries derived key material to AMF
    - Unit test covers the EAP state machine
  depends_on: []
  status: DONE
  priority: P2
  notes: >
    DONE (Session 6, 2026-06-19). New additive crypto package shared/crypto/eapaka:
    CK'/IK' derivation (TS 33.402 A.2, FC=0x20), PRF' + MK→K_encr/K_aut/K_re/MSK/EMSK
    (RFC 5448 §3.3-3.4), EAP packet codec (AT_RAND/AT_AUTN/AT_KDF/AT_KDF_INPUT/AT_MAC/AT_RES),
    K_AUSF=EMSK[0:32]. Verified byte-exact against the RFC 5448 Appendix C Case 1 golden vector.
    AUSF: handleInitAuth branches on UDM authType; new PUT …/{authCtxId}/eap-session handler
    (verify AT_MAC + AT_RES → EAP-Success + K_SEAF); AuthContext extended with EAP fields.
    UDM: GenerateAuthData returns the EAP-AKA' transformed AV (ck'/ik'/xres) when the
    subscriber's authenticationMethod=EAP_AKA_PRIME (already plumbed UDR→UDM). Cross-NF
    (AUSF+UDM), no shared crypto primitive modified (additive only). Tests: golden-vector
    + codec unit tests; 4 AUSF handler tests (success/bad-MAC/bad-RES/unknown-ctx); 5 godog
    scenarios. make build/test PASS, full go test ./... exit 0, race-clean. Not E2E on
    UERANSIM (no EAP-AKA' peer); 5G-AKA path byte-unchanged. Follow-up: AMF NAS pass-through
    of the EAP payload (transparent relay) so a real EAP-AKA' UE can be driven E2E.
    Unblocks AMF-005 (NSSAA) and SMF-003 (Secondary Auth).

- id: AMF-005
  nf: AMF
  scope: proc
  procedure: NSSAA
  title: "Network Slice-Specific Auth & Authorization (TS 23.502 §4.2.9)"
  spec_ref: "TS 23.501 §5.15.10, TS 23.502 §4.2.9, TS 29.518/29.509"
  description: >
    Slices flagged for NSSAA are not authenticated. AMF must run EAP-based slice auth
    with AAA-S via AUSF, and gate Allowed NSSAI on the result.
  acceptance_criteria:
    - AMF triggers NSSAA for S-NSSAIs marked subjectToNssaa in subscription
    - EAP round-trip to AAA-S via AUSF; slice added/removed from Allowed NSSAI on result
    - Re-auth and revocation (AAA-initiated) handled
  depends_on: [AUSF-001]
  status: DONE
  priority: P2
  notes: >
    DONE (Session 7, 2026-06-20) — control-plane core + unit/functional, no live UERANSIM
    (v3.2.8 has no NSSAA peer; same constraint as EAP-AKA'/URSP). shared/nas: NSSAA NAS
    messages COMMAND/COMPLETE/RESULT (TS 24.501 §8.2.31-33; S-NSSAI LV §9.11.2.8 + EAP
    message LV-E §9.11.2.2) byte-exact, wired into Encode/Decode dispatch. New additive
    pkg shared/crypto/eap (generic RFC 3748 Identity/Success/Failure framing). AMF: per-UE
    NSSAA state machine (nf/amf/internal/procedures/nssaa.go) — subjectToNssaa slices
    withheld from initial Allowed NSSAI (SplitPendingNSSAA, zero-regression guarded),
    StartNSSAA emits COMMAND (EAP-Req/Identity), ProcessNSSAAComplete relays EAP to AAA-S
    via AUSF and gates Allowed (success) / Rejected cause #3 (failure), Configuration
    Update Command on Allowed-NSSAI change; multi-slice queue; RevokeNSSAA + ReauthNSSAA.
    nas dispatch handles 0x51 COMPLETE + StartNSSAA after RegistrationComplete. AMF mgmt
    triggers POST /amf/v1/ue-contexts/{supi}/nssaa/{reauth|revoke}. AUSF: nausf-nssaa EAP
    relay fronting a simulated AAA-S (Identity→Success/Failure; rejects identity containing
    "reject"). UDM/UDR: subjectToNetworkSliceSpecificAuthenticationAndAuthorization plumbed
    through am-data. Tests: NAS byte-exact (5), eap pkg (3), AMF state machine (8), AUSF
    handler (3), 5 godog scenarios; make build/test PASS (race), go vet clean, gofmt clean.
    Gaps (documented): no standalone NSSAAF NF / real external AAA-S (EAP-TLS); UE-side N1
    leg unexercised; "all slices rejected → NW dereg cause #62" flagged not executed.
    Unblocks SMF-003 only via SMF-002 (still blocked); EAP relay reusable for it.

- id: PCF-002
  nf: PCF
  scope: proc
  procedure: SMPolicyControlUpdate
  title: "Npcf_SMPolicyControl Update + policy-authorized modification (TS 29.512 §5.2.2.3)"
  spec_ref: "TS 29.512 §5.2.2.3, TS 23.502 §4.3.3"
  description: >
    SMF accepts UE-requested PDU Session Modification as-is without consulting PCF.
    Add SM Policy Update so PCF can authorize/reject 5QI/AMBR changes.
  acceptance_criteria:
    - PATCH /npcf-smpolicycontrol/v1/sm-policies/{id} updates the policy
    - SMF consults PCF on UE-requested and NW-initiated modification
    - PCF can reject a requested 5QI/AMBR change
  depends_on: []
  status: DONE
  priority: P2
  notes: >
    DONE (Session 8, 2026-06-20). PCF: handleUpdateSmPolicy on the TS 29.512 §5.2.2.3 custom
    operation POST /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}/update (the backlog's
    "PATCH" shorthand; no PATCH verb is defined for this resource). Authorizes the requested
    5QI against config authorized_5qi and Session-AMBR against max_session_ambr_mbps; rejects
    with 403 REQUESTED_QOS_NOT_AUTHORIZED; a per-subscriber/DNN override supersedes the request
    (200, x5gcQosSource=PCF_OVERRIDE); 404 CONTEXT_NOT_FOUND for unknown smPolicyId. New file
    nf/pcf/internal/server/sm_policy_update.go; config Authorized5QI + MaxSessionAMBRMbps
    (nf/pcf/config/dev.yaml: [2..9] + 1000 Mbps so a 5qi=1 reject is demonstrable). SMF:
    updateSMPolicy client (mirrors createSMPolicy; fail-open when PCF absent/unreachable) wired
    into BOTH paths of handleUpdateSMContext — NW-initiated (policyUpdate) aborts with 403 and
    applies no N4/N1/N2 change on rejection; UE-requested (0xC9) reports current QoS and applies
    the PCF decision (byte-identical empty 0xCB body when no override → zero E2E regression).
    Tests: 6 PCF unit (authorize/reject-5qi/reject-ambr/no-restriction/override-wins/404) +
    3 SMF unit (NW reject/grant/fail-open); existing TestMgmtSetQoSFullFlow + TestHandleUpdateSMContext
    unaffected. make build/test PASS (race); gofmt + go vet clean. make ueransim not run —
    establishment (createSMPolicy) untouched and the UE-requested path is byte-identical for the
    default 5qi=9 session; the new NW-reject behaviour is exercised via the existing /qos mgmt API.

- id: SMF-003
  nf: SMF
  scope: proc
  procedure: SecondaryAuthentication
  title: "Secondary Authentication / DN-AAA (TS 23.502 §4.3.2.3)"
  spec_ref: "TS 23.501 §5.6.6, TS 23.502 §4.3.2.3"
  description: "DN-specific secondary auth/authorization with an external AAA during establishment."
  acceptance_criteria:
    - SMF relays EAP between UE and DN-AAA over N4/N6
    - Establishment rejected on AAA failure with the correct 5GSM cause
  depends_on: [SMF-002]
  status: TODO
  priority: P2

- id: UDR-001
  nf: UDR
  scope: proc
  procedure: PolicyDataResource
  title: "UDR Policy Data resource (TS 29.505 §6)"
  spec_ref: "TS 29.504 §5.2, TS 29.505 §6"
  description: >
    Policy Data (sm-policy, ue-policy-set, bdt) is used by bespoke PCF endpoints but not
    exposed as a first-class Nudr_DR resource.
  acceptance_criteria:
    - GET/PUT/PATCH /nudr-dr/v2/policy-data/... for sm-policy and ue-policy-set
    - PCF reads/writes policy data through Nudr_DR
  depends_on: []
  status: DONE
  priority: P2
  notes: >
    DONE (Session 9, 2026-06-21). UDR: SM Policy Data resource (TS 29.519 §5.6.2.4) —
    GET/PUT/PATCH /nudr-dr/v2/policy-data/{supi}/sm-data + PATCH on the existing
    ue-policy-set; SmPolicyData/SmPolicySnssaiData/SmPolicyDnnData added to shared/types
    (re-exported by the UDR store, mirroring PolicySubscription); store methods
    GetSmPolicyData/PutSmPolicyData/PatchSmPolicyData on InMemory + Postgres
    (subscription_sm_policy JSONB table, migration 004; PATCH merges at S-NSSAI-key
    granularity, ErrNotFound→404). PCF: UDRClient gains GetSmPolicyData/PutSmPolicyData
    (HTTPUDRClient implements the new routes); SmPolicyControl_Create reads UDR SM policy
    data as a new precedence tier (qos_source=UDR_POLICY_DATA — above subsDefQos, below the
    in-memory override) resolved by DNN; the override mgmt API (handleSet/DeleteQoSOverride)
    write-throughs to UDR so the policy survives a PCF restart. Fail-open throughout (nil
    client / 404 / error → unchanged), so zero regression when UDR absent — the default 5qi=9
    session is byte-identical (TestSmPolicyCreateNoUDRClientUnchanged). Tests: 6 UDR unit
    (handlers/store) + 4 UDR BDD scenarios (make -C nf/udr test-functional) + 5 PCF unit
    (read tier, override-beats-UDR, no-client no-regression, write-through round-trip,
    resolver). make build/test PASS (race), gofmt+vet clean. make ueransim not run — Nudr_DR
    (N36) in-process SBI, no N1/N2/N4 path touched.
    Live-validated on UERANSIM (Session 9 verification): UDR PUT/GET/PATCH round-trip; PCF read tier
    qos_source=UDR_POLICY_DATA (5qi 5 / DL 200 Mbps) at PDU establishment; override write-through to
    UDR; persistence across a PCF restart (in-memory cleared, UDR-backed policy re-read). NOTE: the
    running PCF image was initially stale (only UDR had been rebuilt) — rebuilt + recreated pcf to
    validate. Write-through made read-modify-write (manages only the PCF "0" bucket) so it no longer
    clobbers directly-provisioned per-S-NSSAI slices (fixed during verification; +1 PCF unit test).
    Follow-ups (not blockers): SmPolicyDnnData persists the QoS subset (5QI/ARP/AMBR), not the full
    TS 29.519 field set (gbrUl/gbrDl/charging); UE-policy-set PATCH is a coarse field replace; if a
    direct slice and the PCF bucket both define the same DNN, post-restart read resolution between
    them is map-order-dependent (only matters when the override is also gone from PCF memory).

- id: CHF-001
  nf: CHF
  scope: NF
  procedure: ConvergedCharging
  title: "[NEW NF] Converged Charging Function — Nchf (TS 32.290/291, TS 23.502 §4.4)"
  spec_ref: "TS 32.290, TS 32.291, TS 32.255, TS 23.502 §4.4.1"
  description: >
    No charging exists. Add a CHF NF exposing Nchf_ConvergedCharging
    (Create/Update/Release CDRs); SMF acts as CTF and reports usage per PDU session/QFI.
  acceptance_criteria:
    - CHF registered in NRF; Nchf_ConvergedCharging Create/Update/Release served
    - SMF opens a charging session at establishment and reports on modification/release
    - Quota (used units) accounted; CDR persisted (PostgreSQL)
  depends_on: [UPF-001]
  status: TODO
  priority: P2
  notes: "Online charging quota ties to UPF URR usage reporting (UPF-001)."

- id: SMSF-001
  nf: SMSF
  scope: NF
  procedure: SmsOverNas
  title: "[NEW NF] SMS over NAS — SMSF (TS 23.502 §4.13, TS 29.540)"
  spec_ref: "TS 23.501 §5.20, TS 23.502 §4.13.x, TS 29.540, TS 24.501 (SMS payload)"
  description: >
    Add an SMSF NF + AMF N1 SMS transport (NAS Transport with SMS payload) and the
    Nsmsf_SMService Activate/Send services (N20/N21).
  acceptance_criteria:
    - SMSF registered in NRF; Nsmsf_SMService Activate + UplinkSMS/MT-SMS served
    - AMF carries SMS in UL/DL NAS Transport to/from SMSF
    - MO and MT SMS delivered end-to-end (loopback DTE for test)
  depends_on: []
  status: DONE
  priority: P2
  notes: >
    DONE (Session 10, 2026-06-21). New SMSF NF (nf/smsf): Nsmsf_SMService
    Activate (POST /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}) + UDM UECM registration
    (smsf-3gpp-access), Deactivate, UplinkSMS (.../sendsms) with a loopback/echo DTE
    that reflects every MO SMS back as an MT SMS via Namf_Communication_N1N2MessageTransfer
    (TS 29.518 §5.2.2.3), plus an internal MT-SMS trigger endpoint. NRF register+heartbeat,
    mTLS+HTTP/2 SBI (port 8009), metrics 9110. AMF: handleULSMS routes UL NAS Transport
    Payload Container Type 0x02 (SMS) to the SMSF via a new HTTPSMSFClient (cfg.Peers.smsf),
    transparent relay (no SM-CP/RP parsing), fail-open when SMSF peer absent.
    Wiring: docker-compose smsf service + PCAP sidecar, pki/smsf.* (gen-pki.sh), compliance
    matrix 🟡, CLAUDIA_5GC_MANUAL §3.16 + port map + changelog. Validation: 11 smsf unit tests
    + 7 godog BDD scenarios (in-process; mock NRF/UDM/AMF) all green; go build/vet/gofmt clean.
    Live N1 UE leg out of scope — UERANSIM v3.2.8 has no SMS-over-NAS support (same posture as
    URSP/NSSAA/EAP-AKA'). Follow-ups (SMSF-002+): AMF-initiated Activate at registration,
    paging-for-SMS to CM-IDLE UE, real SMS-GMSC/SMS-IWMSC forwarding, Redis context persistence.

- id: BSF-001
  nf: BSF
  scope: NF
  procedure: BindingSupport
  title: "[NEW NF] Binding Support Function — Nbsf (TS 29.521)"
  spec_ref: "TS 23.501 §6.2.16, TS 29.521 §5"
  description: >
    No PCF binding registry. Add a BSF NF storing PCF-for-a-PDU-session bindings so NEF/AF
    can discover the serving PCF for a UE IP.
  acceptance_criteria:
    - Nbsf_Management Register/Deregister/Discovery served
    - PCF registers the binding on SM policy create; removes on delete
    - Discovery by UE IP returns the serving PCF
  depends_on: []
  status: TODO
  priority: P2

- id: NEF-001
  nf: NEF
  scope: NF
  procedure: NetworkExposure
  title: "[NEW NF] Network Exposure Function baseline — Nnef (TS 29.522)"
  spec_ref: "TS 23.501 §6.2.5, TS 23.502 §4.15, TS 29.522"
  description: >
    No northbound exposure. Add a NEF NF with a baseline Nnef_EventExposure + a
    PFD/AF-influence or QoS (AsSession with QoS) API mapped onto PCF/UDR.
  acceptance_criteria:
    - NEF registered in NRF; one northbound API (e.g. AsSessionWithQoS) served
    - Request mapped to a PCF SM policy / npcf operation
    - OAuth2-protected; AF identified
  depends_on: [BSF-001]
  status: DONE
  priority: P2
  notes: >
    DONE (Session 12, 2026-06-22). New NEF NF (nf/nef): Nnef_AFsessionWithQoS
    Create/Get/Delete (POST/GET/DELETE /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions,
    TS 29.522 §4.4.13) over mTLS+HTTP/2 (port 8011, metrics 9112). Northbound OAuth2 bearer
    verification (scope nnef-afsessionwithqos; 401 UNAUTHORIZED / 403 UNAUTHORIZED_AF, reusing
    shared/oauth2 HS256). AC1: registered in NRF as nfType=NEF (NFTypeNEF enum already present).
    AC2: AF request mapped to a PCF npcf operation — NEF consumes BSF-001 Discovery
    (GET /nbsf-management/v1/pcfBindings?ipv4Addr=) to find the serving PCF by UE IP, then POSTs
    Npcf_PolicyAuthorization_Create (TS 29.514 §5.2.2.2) to that PCF; new thin PCF endpoints
    POST/DELETE /npcf-policyauthorization/v1/app-sessions store the AppSessionContext + mint
    appSessionId. AC3: OAuth2-protected, AF identified by scsAsId + token subject. Cross-NF
    (NEF producer + PCF consumer), fail-open. Tests: 8 NEF unit + 12 BDD scenarios (124 steps,
    in-process mock BSF + recording PCF client) + 8 PCF app-session unit. SPEC-VERIFIER: CONFORMANT
    baseline, no blockers; fixed finding 2 (create-reject cause MODIFICATION_NOT_ALLOWED →
    UNAUTHORIZED_AF). Observability: ProcedureTotal{NEF,AsSessionWithQoS{Create|Get|Delete},
    result} + fivegc_nef_subscriptions_active gauge + Grafana NEF row. make build PASS; full
    go test ./... PASS; NEF/PCF/BSF race-clean. make ueransim NOT run — Nnef/Nbsf/Npcf SBA-only,
    no N1/N2/N4 path and no AF in UERANSIM (same posture as BSF-001/SMSF-001). Follow-ups: PCF
    UE-IP→SUPI resolution to bind the authorized qosReference to a DNN-scoped SM-policy override
    (currently logged only); QoS Notification Control callbacks (NEF-002); docker-compose wiring +
    PKI nef.* (NEF-005); reconcile BSF Discovery to spec'd 200+array (B-1).
    NOTE: also fixed a pre-existing build break from the BSF-001 commit (49adfe7) — 4 nf/bsf/*.go
    files used module path github.com/francurieses/claudia-5gc instead of .../5gc-rel17, breaking
    go build ./...; corrected to the dev-branch module path.

- id: UPF-001
  nf: UPF
  scope: dataplane
  procedure: UsageReporting
  title: "PFCP Usage Reporting (URR) with active reports (TS 29.244 §5.2.2.4)"
  spec_ref: "TS 29.244 §5.2.2.4, §7.5.5"
  description: >
    URRs are installed but emit no Usage Reports. Volume/time quota reporting to SMF is
    missing (prerequisite for charging).
  acceptance_criteria:
    - UPF emits PFCP Session Report (Usage Report) on threshold/periodic triggers
    - SMF consumes the report and logs volume/time
  depends_on: []
  status: TODO
  priority: P2
  notes: "HARD STOP — touches the PFCP session management path. ORCHESTRATOR must escalate (requires_human: true) for design sign-off before editing PFCP handling."

- id: UPF-002
  nf: UPF
  scope: dataplane
  procedure: UplinkClassifier
  title: "ULCL / Branching Point + I-UPF insertion (TS 23.501 §5.6.4)"
  spec_ref: "TS 23.501 §5.6.4.x, TS 23.502 §4.3.5"
  description: >
    Single-UPF only. Add Uplink Classifier (or branching point for multi-homed IPv6) to
    steer selected traffic to a local DN — the edge-computing primitive.
  acceptance_criteria:
    - SMF inserts an ULCL UPF and programs PDRs to split traffic by destination
    - Local-DN traffic egresses the I-UPF; default traffic the anchor UPF
  depends_on: [UPF-001]
  status: TODO
  priority: P2
  notes: "HARD STOP — PFCP/dataplane. Requires human design sign-off."
```

## P3 — Indirect communication, analytics, location, discovery polish

```yaml
- id: NRF-001
  nf: NRF
  scope: proc
  procedure: NFListRetrieval
  title: "NFListRetrieval + richer NFDiscover filters (TS 29.510 §5.2.2.6, §5.3.2.2)"
  spec_ref: "TS 29.510 §5.2.2.6, §6.2.3.2.3.1"
  description: >
    NFListRetrieval is not implemented and NFDiscover supports only a subset of filters
    (tai / plmn / guami missing).
  acceptance_criteria:
    - GET /nnrf-nfm/v1/nf-instances returns the instance list with paging
    - NFDiscover honours tai / plmn-list filters
  depends_on: []
  status: TODO
  priority: P3

- id: SCP-001
  nf: SCP
  scope: NF
  procedure: ServiceCommunicationProxy
  title: "[NEW NF] Service Communication Proxy — indirect comms (TS 23.501 §6.2.19)"
  spec_ref: "TS 23.501 §6.2.19, TS 29.500 §6.10 (indirect models C/D)"
  description: >
    All SBI is direct (model A/B). Add an SCP for delegated discovery + request routing
    (3gpp-Sbi-Discovery headers), routing NF-to-NF traffic through the proxy.
  acceptance_criteria:
    - SCP forwards SBI requests using 3gpp-Sbi-* routing headers
    - Delegated discovery: SCP queries NRF on behalf of the consumer
    - At least one NF pair communicates via the SCP (model D)
  depends_on: []
  status: TODO
  priority: P3

- id: NWDAF-001
  nf: NWDAF
  scope: NF
  procedure: NetworkDataAnalytics
  title: "[NEW NF] Network Data Analytics Function baseline — Nnwdaf (TS 23.288)"
  spec_ref: "TS 23.501 §6.2.18, TS 23.288, TS 29.520"
  description: >
    No analytics. Add an NWDAF with Nnwdaf_AnalyticsInfo / EventsSubscription for one
    analytics ID (e.g. NF load) consuming the existing Prometheus/observability data.
  acceptance_criteria:
    - NWDAF registered in NRF; Nnwdaf_AnalyticsInfo Request served for NF-load analytics
    - Analytics derived from collected metrics; subscription/notify supported
    - One consumer (e.g. PCF or NSSF) acts on the analytics
  depends_on: []
  status: TODO
  priority: P3

- id: LMF-001
  nf: LMF
  scope: NF
  procedure: LocationServices
  title: "[NEW NF] Location Services baseline — Nlmf (TS 23.273)"
  spec_ref: "TS 23.273 §6, TS 29.572, TS 38.413 (Location Reporting)"
  description: >
    No location services. Add an LMF + AMF Namf_Location and NGAP Location Reporting for
    a basic cell-ID positioning result.
  acceptance_criteria:
    - LMF registered in NRF; Nlmf_Location DetermineLocation served
    - AMF requests location; NGAP Location Reporting returns serving cell
    - Cell-ID position returned to the LCS client
  depends_on: []
  status: TODO
  priority: P3
```

---

## Dependency graph (quick view)

```
P1: AMF-002·  AMF-004·  UDM-001·  PCF-001 ── AMF-003
    SMF-002·
P2: AUSF-001 ── AMF-005          UPF-001 ── UPF-002
    PCF-002·  UDR-001·  SMSF-001· UPF-001 ── CHF-001
    SMF-002 ── SMF-003           BSF-001 ── NEF-001
P3: NRF-001·  SCP-001·  NWDAF-001·  LMF-001
( · = no dependencies, ready now )
```
