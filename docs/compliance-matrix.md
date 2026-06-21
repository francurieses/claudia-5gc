# Compliance Matrix — 3GPP Release 17

Compliance status by NF and procedure. **Update in every PR** that adds or modifies functionality.

Legend:
- ✅ Implemented and validated against TS
- 🟡 Partially implemented (gaps documented)
- ⏳ Pending
- ➖ Not applicable for this NF

## NRF (TS 29.510)

| Service / Operation | Section | Status | Tests | Notes |
|---|---|---|---|---|
| `nnrf-nfm` NFRegister | §5.2.2.2 | ✅ | unit, feature | PUT, returns 201 |
| `nnrf-nfm` NFUpdate | §5.2.2.3 | 🟡 | unit | Simplified PATCH (replace), no JSON Patch RFC 6902 |
| `nnrf-nfm` NFDeregister | §5.2.2.4 | ✅ | unit | DELETE |
| `nnrf-nfm` NFProfileRetrieve | §5.2.2.5 | ✅ | unit | GET single |
| `nnrf-nfm` NFListRetrieval | §5.2.2.6 | ⏳ | — | |
| `nnrf-nfm` NFStatusSubscribe | §5.2.2.7 | ✅ | unit | `internal/registry/subscriptions.go`; AMF subscribes |
| `nnrf-nfm` NFStatusUnsubscribe | §5.2.2.8 | ✅ | unit | DELETE subscription |
| `nnrf-nfm` NFStatusNotify | §5.2.2.9 | ✅ | unit | mTLS HTTP/2 callback (NF_REGISTERED / NF_DEREGISTERED) |
| `nnrf-disc` NFDiscover | §5.3.2.2 | 🟡 | unit | Only target-nf-type, requester-nf-type, service-names; missing snssais, dnn, tai filters... |
| `nnrf-disc` SCPDomainRoutingInfoGet | §5.3.2.3 | ⏳ | — | |
| OAuth2 Token endpoint | TS 33.501 §13.4.1 | ✅ | unit jwt | JWT HS256; soft enforcement (`OAUTH2_ENFORCE=true` for hard reject) |
| Heartbeat / TTL eviction | §5.2.2.3.4 | ✅ | unit registry | JSON Patch PATCH → heartbeat; eviction goroutine; `shared/nrf.Client` with `StartHeartbeat`; wired in AMF |

## AMF (TS 29.518, TS 24.501, TS 38.413)

| Procedure | Section | Status | Tests | Notes |
|---|---|---|---|---|
| Initial Registration | TS 23.502 §4.2.2.2.2 | ✅ | e2e UERANSIM | |
| PDU Session Establishment | TS 23.502 §4.3.2 | ✅ | e2e UERANSIM | |
| PDU Session Release (UE-initiated) | TS 23.502 §4.3.4.2 | ✅ | e2e UERANSIM | |
| AN Release / CM-IDLE | TS 23.502 §4.2.6 | ✅ | unit ngap | prerequisite for Service Request |
| NAS ciphering NEA2 | TS 33.501 §D | ✅ | implicit in Reg | |
| NAS integrity NIA2 | TS 33.501 §D | ✅ | implicit in Reg | |
| UE Context Release Request (gNB-init, proc=42) | TS 38.413 §8.3.4 | ✅ | unit | |
| UE Context Release (AMF-init, proc=41) | TS 38.413 §8.3.5 | ✅ | unit | |
| Initial Context Setup | TS 38.413 §8.3.1 | ✅ | implicit in Reg | |
| PDU Session Resource Setup | TS 38.413 §8.4.1 | ✅ | e2e UERANSIM | |
| PDU Session Resource Release | TS 38.413 §8.4.2 | ✅ | e2e UERANSIM | |
| Mobility Registration Update | TS 23.502 §4.2.2.2.3 | ✅ | unit nas | Skips re-auth when security context active; InitialContextSetupRequest path |
| Periodic Registration Update | TS 23.502 §4.2.2.2.4 | ✅ | unit nas | Same handler; T3512-triggered; UERANSIM: set `t3512: 30` in ue.yaml for fast test |
| Deregistration (UE-initiated) | TS 23.502 §4.2.2.3.2 | ✅ | unit nas codec | Accept, PDU session teardown, UDM UECM dereg, N2 release; UEContextReleaseCommand always sent; context deferred until ReleaseComplete |
| Deregistration (NW-initiated) | TS 23.502 §4.2.2.3.3 | ✅ | — | AMF sends DeregReqNW; UE responds with DeregAcceptNW; teardown flow identical to UE-init. Trigger: `DELETE /amf/v1/ue-contexts/{supi}` (port 9002) |
| Service Request | TS 23.502 §4.2.3 | ✅ | unit nas codec | TMSI lookup, security re-use, InitialContextSetup+ServiceAccept; PDU sessions re-established by UERANSIM |
| GUTI re-registration (Identity Request/Response) | TS 24.501 §5.5.1.2.2 | ✅ | — | After deregistration, UE re-registers with GUTI → AMF sends IdentityRequest(SUCI) → UE responds → normal auth flow resumes |
| PDU Session Resource Modify | TS 38.413 §8.2.1 | ✅ | — | NGAP Modify Request/Response; N1SM ModCmd via DL NAS Transport |
| Xn Handover | TS 23.502 §4.9.1.2 | ✅ | e2e PacketRusher | PathSwitchRequest; `make handover-test` |
| N2 Handover | TS 23.502 §4.9.1.3 | ✅ | e2e PacketRusher | HandoverRequired→Command→Notify; NH/NCC; `make handover-n2-test` |
| Namf_Communication UEContextTransfer (producer) | TS 29.518 §5.3.2 | 🟡 | unit, feature | First AMF inbound SBI server (`internal/sbi`, port 8001, mTLS+h2). Returns `UeContextTransferRspData` (mmContextList: NasSecurityMode NIAx/NEAx + kamf; sessionContextList). Marks ctx transferred. Causes `CONTEXT_NOT_FOUND`/`MANDATORY_IE_MISSING`. Gap: no `regRequest` integrity replay, no RegistrationStatusUpdate consumer |
| Namf_Communication N1N2MessageTransfer (producer) | TS 29.518 §5.2.2.3 | 🟡 | unit, feature | `POST namf-comm/v1/ue-contexts/{id}/n1-n2-messages`. CM-IDLE → 202 `ATTEMPTING_TO_REACH_UE` + NGAP Paging; CM-CONNECTED → 200 `N1_N2_TRANSFER_INITIATED`; unknown → 404. Gap: N1/N2 payload not yet forwarded on CM-CONNECTED |
| NGAP Paging | TS 38.413 §9.2.8 | ✅ | unit ngap | `BuildPaging` (ProcCode=24): 5G-S-TMSI (AMFSetID/AMFPointer/5G-TMSI) + TAIListForPaging; `SendPaging` broadcasts to gNBs covering the UE's TAC. Round-trip decode tested |
| CN Paging + NW-Triggered Service Request | TS 23.502 §4.2.3.3 | 🟡 | unit, feature | Control-plane core: SMF DL-data trigger → N1N2MessageTransfer → Paging → existing Service Request reactivates UP. DL-data detection simulated (SMF mgmt endpoint); real UPF PFCP DDN = UPF-001 |
| Network Slice-Specific Auth & Authz (NSSAA) | TS 23.502 §4.2.9 | 🟡 | unit, feature (5 godog) | NSSAA NAS messages COMMAND/COMPLETE/RESULT (TS 24.501 §8.2.31-33, S-NSSAI LV + EAP LV-E) byte-exact; per-UE state machine: subjectToNssaa slices withheld from initial Allowed NSSAI → EAP relay to AAA-S via AUSF → add to Allowed (success) / Rejected cause #3 (failure) → Configuration Update Command. Re-auth/revoke triggers (`POST /amf/v1/ue-contexts/{supi}/nssaa/{reauth\|revoke}`). AAA-S simulated behind AUSF; live N1 not exercised (UERANSIM has no NSSAA peer). agentic_verified ✅ |

## SMF (TS 29.502, TS 29.244)

| Procedure | Section | Status | Tests | Notes |
|---|---|---|---|---|
| PDU Session Establishment | TS 23.502 §4.3.2.2 | ✅ | e2e UERANSIM | |
| PDU Session Release | TS 23.502 §4.3.4 | ✅ | e2e UERANSIM | |
| AN Release (upCnxState=DEACTIVATED) | TS 29.502 §5.2.2.3.2 | ✅ | unit smf/server | PFCP deactivation |
| PFCP Session Establishment | TS 29.244 §7.5.2 | ✅ | implicit in Establishment | |
| PFCP Session Modification (activate DL) | TS 29.244 §7.5.4 | ✅ | implicit in Establishment | |
| PFCP Session Modification (deactivate DL) | TS 29.244 §7.5.4 | ✅ | implicit in AN Release | |
| PFCP Session Deletion | TS 29.244 §7.5.6 | ✅ | implicit in Release | |
| PDU Session Modification (UE-requested) | TS 23.502 §4.3.3.1 | ✅ | unit smf/server | SMF consults PCF (SM Policy Update, TS 29.512 §5.2.2.3) then applies the authorized decision; N1SM ModCmd + N2SM ModReqTransfer. Byte-identical when no PCF override (fail-open) |
| IPv6 / IPv4v6 Prefix Delegation (control plane) | TS 23.501 §5.8.2.2, TS 24.501 §9.11.4.10 | 🟡 | unit nas + smf/server, godog (6 scenarios) | SMF reads requested PDU type, `selectPDUSessionType` grants IPv4/IPv6/IPv4v6 by DNN capability, delegates /64 + IID, encodes PDU Address IE (IID for v6, IID+IPv4 for v4v6) + N2 PDUSessionType IE. IPv4 byte-identical (no regression); v6 gated behind per-DNN `ue_ipv6_prefix`. **Data-plane half (UPF IPv6 PDR + RA on TUN) escalated — hard stop, SMF-002 follow-up / UPF-001** |
| PDU Session Modification (NW-initiated, QoS) | TS 23.502 §4.3.3.2 | ✅ | e2e modified-UERANSIM (`make qos-mod-e2e`) | Trigger: `POST /nsmf-management/v1/sessions/{psi}/qos`; N4 Update QER (ack awaited) → N1SM 0xCB (IEs 0x2A/0x7A/0x79 with new 5QI) + N2SM ModReqTransfer. Modified UERANSIM now handles 0xCB and replies 0xCC (`tools/ueransim/patches/0030`). SMF now consults PCF (SM Policy Update §5.2.2.3) before applying — a denied 5QI/AMBR aborts with 403, no N4/N1/N2 change |
| Nudm_SDM Get sm-data (N10, subscribed default QoS) | TS 29.503 §6.1.6.2.7 | ✅ | unit smf/pcf | 5QI precedence: PCF override > UDM subscription > operator default; source tracked per session |
| DL-data notification → N1N2MessageTransfer (CN paging trigger) | TS 23.502 §4.2.3.3 | 🟡 | unit smf/server | `POST /nsmf-management/v1/sessions/{psi}/dl-data-notification` simulates the UPF DDN and calls AMF namf-comm over mTLS SBI. Real N4 PFCP Session Report = UPF-001 |
| PFCP Create/Update QER (QFI + MBR) | TS 29.244 §7.5.2.5 | ✅ | unit upf/pfcp (TestSessionEstablishmentStoresQER) | QER installed at establishment, updated on QoS modification |
| UPF selection | TS 23.501 §6.3.3 | ⏳ | — | hardcoded per config |

## UPF (TS 29.244, TS 29.281)

✅ Operational. PFCP + GTP-U + N6 internet verified e2e with UERANSIM.

| Feature | Section | Status | Notes |
|---|---|---|---|
| PFCP node: Heartbeat / Association | TS 29.244 §7.4 | ✅ | |
| PFCP session: PDR/FAR/QER/URR/BAR | TS 29.244 §5.2 | ✅ | URR without active reporting |
| GTP-U encap/decap N3 | TS 29.281 | ✅ | Extension header skip (TS 38.415) for 5G gNBs |
| GTP-U N9 (inter-UPF) | TS 29.281 | ⏳ | |
| QoS per QFI/5QI | TS 23.501 §5.7 | ✅ | |
| N6 internet forwarding | TS 29.281 | ✅ | TUN `upfgtp0` + iptables MASQUERADE; ping 8.8.8.8 verified |
| Usage reporting (URR) | TS 29.244 §5.2.2.4 | ⏳ | |

## AUSF (TS 29.509, TS 33.501)

🟡 5G-AKA happy path functional.

| Procedure | Section | Status | Notes |
|---|---|---|---|
| 5G-AKA initiation (→ UDM) | TS 33.501 §6.1.3.2 | ✅ | e2e UERANSIM |
| RES* verification + KAUSF derivation | TS 33.501 Annex A | ✅ | KAUSF generated in UDM; AUSF forwards it |
| SUCI deconcealment (delegated to UDM) | TS 33.501 §6.12 | ✅ | null-scheme; ECIES Profile A/B ⏳ |
| EAP-AKA' flow | TS 33.501 §6.1.3.1 | ✅ | AUSF EAP server: CK'/IK' key hierarchy (RFC 5448), EAP packet codec (AT_RAND/AT_AUTN/AT_KDF/AT_KDF_INPUT/AT_MAC/AT_RES), `PUT …/eap-session`; K_AUSF=EMSK[0:32]→K_SEAF. Golden-vector unit tests (RFC 5448 App. C Case 1) + 4 handler tests + 5 godog scenarios. Live N1 not exercised (UERANSIM has no EAP-AKA' peer). agentic_verified ✅ |
| NSSAA EAP relay (Nausf_NSSAA) | TS 23.502 §4.2.9.2, TS 29.526 | 🟡 | `POST /nausf-nssaa/v1/{supi}/authenticate`: relays the UE EAP-Response to a **simulated AAA-S** (single EAP round: Identity → Success/Failure; rejects identity containing "reject"). Generic EAP framing in `shared/crypto/eap` (RFC 3748). 3 handler tests. No standalone NSSAAF NF / real external AAA-S. agentic_verified ✅ |

## UDM (TS 29.503)

🟡 Authentication + AM data + UECM implemented.

| Service | Section | Status | Notes |
|---|---|---|---|
| Nudm_UEAuthentication (GenerateAuthData) | §5.4 | ✅ | Milenage + KDF; SQN increment in UDR; e2e UERANSIM. EAP-AKA' variant: returns transformed AV (CK'/IK', TS 33.402 A.2) when subscriber `authenticationMethod=EAP_AKA_PRIME` |
| Nudm_SDM Get AM data | §5.2 | ✅ | e2e UERANSIM |
| Nudm_SDM Subscribe/Notify | §5.3.2 / §5.3.3 | ✅ | unit, feature (3 godog scenarios) | POST `/nudm-sdm/v2/{supi}/sdm-subscriptions` (201+Location); DELETE unsubscribe (204); async fan-out via `POST /nudm-mgmt/v1/{supi}/data-change` trigger; 3 scenarios pass (happy path, unsubscribe, missing callbackRef). agentic_verified ✅ |
| Nudm_UECM Registration (AMF) | §5.3 | ✅ | PUT + DELETE (deregistration) |
| Nudm_UECM Get | §5.3 | ⏳ | |
| SUCI deconcealment (SIDF) | TS 33.501 §6.12 | ✅ | null-scheme; ECIES ⏳ |
| Nudm_NIDDAU | §5.6 | ⏳ | |

## UDR (TS 29.504, TS 29.505)

| Resource | Section | Status | Tests | Notes |
|---|---|---|---|---|
| Auth subscription GET/PATCH | TS 29.505 §5.2.2 | ✅ | e2e UERANSIM | PostgreSQL + fallback in-memory |
| AM subscription GET | TS 29.505 §5.2.2 | ✅ | e2e UERANSIM | |
| AMF UECM context PUT | TS 29.504 §5.2.2 | ✅ | e2e UERANSIM | |
| PostgreSQL persistence | TS 29.504 §4.2 | ✅ | — | pgx/v5; auto-migrate; JSONB for arrays |
| Policy data — UE Policy Set (URSP) | TS 29.519 §5.7 | ✅ | unit + functional | GET/PUT/PATCH/DELETE `/policy-data/{supi}/ue-policy-set` |
| Policy data — SM Policy Data | TS 29.519 §5.6.2.4 | ✅ | unit + 4 BDD | GET/PUT/PATCH `/policy-data/{supi}/sm-data`; per-S-NSSAI/DNN authorized 5QI/ARP/AMBR; PCF reads (tier `UDR_POLICY_DATA`) + write-throughs overrides via Nudr_DR. `subscription_sm_policy` JSONB table (migration 004) |
| Application data | TS 29.505 §7 | ⏳ | — | |
| Exposure data | TS 29.505 §8 | ⏳ | — | |

## PCF (TS 29.507, TS 29.512, TS 29.514, TS 29.525)

✅ SM Policy Control + UE Policy Control operational.

| Service | Section | Status | Notes |
|---|---|---|---|
| Npcf_SMPolicyControl Create | TS 29.512 §5.2.2.2 | ✅ | config-driven QoS/AMBR (no hardcoded values); e2e UERANSIM |
| Npcf_SMPolicyControl Update | TS 29.512 §5.2.2.3 | ✅ | `POST .../sm-policies/{id}/update` (custom op); authorizes/rejects requested 5QI + Session-AMBR (`authorized_5qi`, `max_session_ambr_mbps`); per-subscriber override supersedes; SMF consults on UE-requested + NW-initiated modification (fail-open if PCF absent); 6 pcf + 3 smf unit tests |
| Npcf_SMPolicyControl Delete | TS 29.512 §5.2.2.4 | ✅ | invoked on PDU Session Release |
| Npcf_UEPolicyControl Create | TS 29.525 §4.2.2.2 | ✅ | URSP rules from UDR or config defaults; base64 UE Policy Container |
| Npcf_UEPolicyControl Delete | TS 29.525 §4.2.2.3 | ✅ | called on deregistration |
| URSP binary codec | TS 24.526 §4.2 | ✅ | TD + RSD encoding; section management list |
| UE Policy Container IE 0x7B | TS 24.501 §9.11.4.15 | ✅ | TLV-E in RegistrationAccept + UCU Command |
| Configuration Update Command | TS 24.501 §8.2.29 | ✅ | NAS 0x54; IEI 0x7B; ACK bit |
| Configuration Update Complete | TS 24.501 §8.2.30 | ✅ | NAS 0x55; AMF increments URSPVersion |
| URSP at registration | TS 23.502 §4.2.2.2.2 step 17b | ✅ | non-fatal; PCF fallback when unavailable |
| URSP standalone UCU | TS 23.502 §4.2.4 | ✅ | push-policies management API |
| DNN-scoped SM policy override | TS 29.512 §5.2.2.2 (qosDecs) | ✅ | unit pcf/server (TestSmPolicyDNNScopedOverride); precedence supi+dnn > supi > subsDefQos > defaults |
| NW-triggered additional PDU session (URSP steering) | TS 23.503 §6.6.2 / TS 23.502 §4.3.2.2.1 | ✅ | e2e via portal `POST /api/v1/qos/nw-sessions`; UE-side URSP evaluation simulated (UERANSIM limitation); see `docs/procedures/nw-triggered-pdu-session.md` |

## NSSF (TS 29.531)

⏳ Not started.

## Cross-cutting specifications

| Topic | Spec | Status |
|---|---|---|
| TLS 1.3 mutual between NFs | TS 33.501 §13 | ✅ (NRF verifies client cert; `sbi.NewMTLSClient` for NFs) |
| OAuth2 client_credentials | TS 33.501 §13.4.1 | ✅ | unit jwt | NRF issues JWT HS256; `shared/oauth2` BearerTransport; AMF wired; soft enforcement (OAUTH2_ENFORCE=true for hard reject) |
| ProblemDetails RFC 7807 | TS 29.500 §5.2.7.2 | ✅ (in NRF) |
| Correlation-Id propagation | (local convention) | ✅ (in NRF middleware) |
| OpenAPI conformance check | TS 29.501 | ⏳ |
| Wireshark-compatible PCAPs | (local convention) | ✅ (sidecar configured) |

## Agentic Backlog — Gap Analysis

Tracked gaps queued for autonomous development. `agentic_verified` = ✅ once an
ORCHESTRATOR session has implemented and validated the procedure (see `AGENTS.md`,
`dev/BACKLOG.md`). Reconciled against live code at bootstrap (2026-06-18).

Pre-existing procedures found already implemented (removed from the backlog): Mobility/
Periodic Registration Update (AMF, §4.2.2.2.3/4), UE-requested PDU Session Modification
(SMF, §4.3.3.1), Xn + N2 Handover, NRF NFStatusSubscribe/Notify.

| Procedure / Feature | TS Reference | NF(s) | Status | Backlog | agentic_verified |
|---|---|---|---|---|---|
| Namf_Communication UEContextTransfer | TS 29.518 §5.3.2 | AMF | 🟡 Producer side done | AMF-002 | ✅ |
| CN Paging + NW-Triggered Service Request | TS 23.502 §4.2.3.3 | AMF, SMF, UPF | 🟡 Control-plane done | AMF-004 | ✅ |
| Nudm_SDM Subscribe/Notify | TS 29.503 §5.3.2 | UDM, UDR | ✅ Subscribe/Unsubscribe + async notification fan-out; 3 BDD scenarios passing | UDM-001 | ✅ |
| AM Policy Association (npcf-ampolicycontrol) | TS 29.507 §4.2.2 | PCF, AMF | ✅ Create/Delete; AMF consumer wired at Registration step 14c + Deregistration; RFSP stored in UEContext | PCF-001 | ✅ |
| Service Area Restriction | TS 23.501 §5.3.4 | AMF, PCF | ✅ isAllowedTA helper; Phase3 enforces ALLOWED_AREAS / NOT_ALLOWED_AREAS; Reject cause #73 sent if restricted; ServAreaRes stored in UEContext | AMF-003 | ✅ |
| IPv6 / IPv4v6 Prefix Delegation | TS 23.501 §5.8.2 | SMF, UPF | 🟡 Control-plane done | SMF-002 | ✅ |
| EAP-AKA' | TS 33.501 §6.1.3.1 | AUSF, UDM | ✅ Done | AUSF-001 | ✅ |
| Network Slice-Specific Auth & Auth (NSSAA) | TS 23.502 §4.2.9 | AMF, AUSF | 🟡 Control-plane | AMF-005 | ✅ |
| Npcf_SMPolicyControl Update | TS 29.512 §5.2.2.3 | PCF, SMF | ✅ Update op + QoS authorization; SMF consults on both modification paths | PCF-002 | ✅ |
| Secondary Authentication / DN-AAA | TS 23.502 §4.3.2.3 | SMF | ⏳ Missing | SMF-003 | ⏳ |
| UDR Policy Data resource | TS 29.519 §5.6.2.4 | UDR, PCF | ✅ SM Policy Data resource (GET/PUT/PATCH) + ue-policy-set PATCH; PCF reads/write-throughs SM policy via Nudr_DR (N36); 6 PCF unit + 6 UDR unit + 4 BDD | UDR-001 | ✅ |
| Converged Charging (CHF) | TS 32.290/291, §4.4 | **CHF (new)**, SMF | ⏳ Missing | CHF-001 | ⏳ |
| SMS over NAS (SMSF) | TS 23.502 §4.13 | **SMSF (new)**, AMF | ✅ Nsmsf_SMService (Activate/Deactivate/UplinkSMS + internal MT trigger); NRF reg + UDM UECM; loopback DTE MO→MT echo via Namf N1N2MessageTransfer; AMF UL NAS Transport (PCT=0x02) → Nsmsf UplinkSMS; 11 smsf unit + 7 BDD. Live N1 UE leg out of scope (UERANSIM has no SMS) | SMSF-001 | 🟡 |
| Binding Support (BSF) | TS 29.521 | **BSF (new)**, PCF | ⏳ Missing | BSF-001 | ⏳ |
| Network Exposure (NEF) | TS 29.522 | **NEF (new)** | ⏳ Missing | NEF-001 | ⏳ |
| PFCP Usage Reporting (URR) | TS 29.244 §5.2.2.4 | UPF, SMF | ⏳ Missing | UPF-001 (hard-stop) | ⏳ |
| ULCL / I-UPF (edge) | TS 23.501 §5.6.4 | UPF, SMF | ⏳ Missing | UPF-002 (hard-stop) | ⏳ |
| NFListRetrieval + richer NFDiscover filters | TS 29.510 §5.2.2.6 | NRF | ⏳ Missing | NRF-001 | ⏳ |
| Service Communication Proxy (SCP) | TS 23.501 §6.2.19 | **SCP (new)** | ⏳ Missing | SCP-001 | ⏳ |
| Network Data Analytics (NWDAF) | TS 23.288 | **NWDAF (new)** | ⏳ Missing | NWDAF-001 | ⏳ |
| Location Services (LMF) | TS 23.273 | **LMF (new)**, AMF | ⏳ Missing | LMF-001 | ⏳ |
