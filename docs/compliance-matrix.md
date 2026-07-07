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
| Initial Registration | TS 23.502 §4.2.2.2.2 | ✅ | e2e UERANSIM | Registration Accept carries the registration area TAI list (IEI 0x54, TS 24.501 §9.11.3.9) from `served_tacs` + current TAC |
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
| Service Request | TS 23.502 §4.2.3 | ✅ | unit nas/ngap/smf, live E2E | TMSI lookup, security re-use, ICS+ServiceAccept; UP re-activation per §4.2.3.2 step 12: SMF `upCnxState=ACTIVATING` → N2SM in PDUSessionResourceSetupListCxtReq → CxtRes forwarded to SMF (PFCP FAR update). Reg Accept carries TAI list (0x54) so the UE initiates SR from CM-IDLE. See docs/procedures/service-request.md |
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
| Nbsf_Management Register | TS 29.521 §5.2.2.2 | **BSF (new)** | ✅ POST /nbsf-management/v1/pcfBindings → 201 + Location + PcfBinding; mandatory-IE check (dnn/snssai/IP-or-MAC/PCF-endpoint) → 400 MANDATORY_IE_MISSING; duplicate → 403 EXISTING_BINDING_INFO_FOUND; PcfBinding field names match §6.2.6 (ipv4Addr/ipv6Prefix/macAddr48/pcfFqdn/pcfIpEndPoints) | BSF-001 | ✅ |
| Nbsf_Management Deregister | TS 29.521 §5.2.2.3 | **BSF (new)** | ✅ DELETE /nbsf-management/v1/pcfBindings/{bindingId} → 204; unknown bindingId → 404 ProblemDetails (no cause) | BSF-001 | ✅ |
| Nbsf_Management Discovery | TS 29.521 §5.2.2.4 | **BSF (new)**, NEF | ✅ GET /nbsf-management/v1/pcfBindings?ipv4Addr=… → 200 PcfBinding / 404; no query param → 400 MANDATORY_IE_MISSING. NOTE: 404-on-discovery-miss is the implementation choice; TS 29.521 §5.2.2.4 returns 200 with an array (empty/1-element) — see conformance notes | BSF-001 | ✅ |
| BSF NRF registration | TS 29.510 §6.1.6.2.2 | **BSF (new)**, NRF | ✅ nfType BSF + nfService nbsf-management (v1); register + heartbeat | BSF-001 | ✅ |
| PCF→BSF binding registration | TS 29.521 §5.2.2.2-3 / TS 29.512 §5.6.2.3 | PCF, BSF, SMF | 🟡 PCF registers binding on SmPolicyControl_Create, deregisters on _Delete (fail-open, best-effort); SMF sends SmPolicyContextData.ipv4Address (correct §5.6.2.3 field, distinct from PcfBinding.ipv4Addr); bindingId stored per smPolicyId. NOTE: PcfBindingRequest omits snssai sd-handling edge + pcfIpEndPoints; register runs in detached goroutine (response not awaited by SMF leg) | BSF-001 | ✅ |
| Nnef_AFsessionWithQoS Create | TS 29.522 §4.4.13 | **NEF (new)**, BSF, PCF | ✅ POST /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions → 201 + Location; OAuth2 scope nnef-afsessionwithqos (401 UNAUTHORIZED / 403 UNAUTHORIZED_AF); BSF Discovery by UE IP → Npcf_PolicyAuthorization_Create on the discovered PCF; 400 MANDATORY_IE_MISSING (no UE addr / no qosReference), 404 PCF_BINDING_NOT_FOUND (B-1), 403 UNAUTHORIZED_AF (PCF reject). 12 BDD + 8 PCF unit | NEF-001 | ✅ |
| Nnef_AFsessionWithQoS Get/Delete | TS 29.522 §4.4.13 | **NEF (new)**, PCF | ✅ GET …/{subscriptionId} → 200 / 404; DELETE → 204 + relay Npcf_PolicyAuthorization_Delete (idempotent) / 404 | NEF-001 | ✅ |
| NEF NRF registration | TS 29.510 §6.1.6.2.2 | **NEF (new)**, NRF | ✅ nfType NEF + nfService nnef-afsessionwithqos (v1); register + heartbeat. NFTypeNEF enum already in registry | NEF-001 | ✅ |
| Npcf_PolicyAuthorization Create/Delete (thin) | TS 29.514 §5.2.2.2 / §5.2.2.4 | PCF, NEF | 🟡 POST /npcf-policyauthorization/v1/app-sessions → 201 + Location (mints appSessionId, stores AppSessionContext); DELETE …/{appSessionId} → 204 / 404. NOTE: authorized qosReference logged but NOT yet bound to an SM-policy DNN-scoped override (UE-IP→SUPI resolution deferred); full §5.2.2.x lifecycle (Update/Subscribe/Notify) out of scope | NEF-001 | ✅ |
| PFCP Usage Reporting (URR) | TS 29.244 §5.2.2.4 | UPF, SMF | ⏳ Missing | UPF-001 (hard-stop) | ⏳ |
| ULCL / I-UPF (edge) | TS 23.501 §5.6.4 | UPF, SMF | ⏳ Missing | UPF-002 (hard-stop) | ⏳ |
| NFListRetrieval + richer NFDiscover filters | TS 29.510 §5.2.2.6 | NRF | ⏳ Missing | NRF-001 | ⏳ |
| Service Communication Proxy (SCP) | TS 23.501 §6.2.19 | **SCP (new)** | ⏳ Missing | SCP-001 | ⏳ |
| Network Data Analytics (NWDAF) | TS 23.288 | **NWDAF (new)** | ⏳ Missing | NWDAF-001 | ⏳ |
| Location Services — Nlmf_Location DetermineLocation (Cell-ID + Paging + Privacy) | TS 23.273 §6, §7.2, §9.1 / TS 29.572 §5.2.2.2, §6.1.6.2.2 / TS 29.503 §5.2.2 | **LMF**, AMF, UDM | ✅ Cell-ID positioning + Deferred MT Location + Location Privacy. `POST /nlmf-loc/v1/ue-contexts/{id}/provide-loc-info`. Privacy check (§9.1): LMF queries UDM `/nudm-sdm/v2/{supi}/lcs-privacy-data`; BLOCK_ALL→403 PRIVACY_EXCEPTION_DENIED; ALLOW_ALL proceeds; fail-open on UDM error. Mobility model: deterministic bounded per-SUPI walk anchored at the serving cell (LMF-006). NRF reg nfType=LMF + service nlmf-loc. Causes: MANDATORY_IE_MISSING→400, CONTEXT_NOT_FOUND→404, PRIVACY_EXCEPTION_DENIED→403, LOCATION_FAILURE/UE_NOT_REACHABLE→504. metric fivegc_lmf_locate_total{result}. Deferred: LPP/NRPPa, EventSubscription, CancelLocation, GMLC/N56, fine-grained lcsPrivacyExceptionList | LMF-001, LMF-002, LMF-006 | ✅ |
| Nlmf_Location EventSubscription (Create/Get/Delete) | TS 29.572 §5.2.3.2/.3/.4 / TS 29.571 §5.2 / TS 23.273 §7.2 step B2 | **LMF**, AMF, UDM | ✅ `POST /nlmf-loc/v1/subscriptions`→201+Location; `GET …/{subId}`→200 resource; `DELETE …/{subId}`→204. eventTrigger PERIODIC_REPORTING (re-locate every reportingInterval, default 10 s, notify every sample) \| AREA_OF_INTEREST (sample every samplingInterval, default 5 s, notify on polygon enter/exit via ray-casting state machine, UNKNOWN baseline suppressed). One goroutine/sub, in-memory registry (RWMutex), config `location_subscription` (intervals/max_duration_s/notification_retry). Privacy gate at Create (BLOCK_ALL→403). Causes: MANDATORY_IE_MISSING→400 (no notificationUri / no UE id / <3-vertex polygon), INVALID_MSG_FORMAT→400 (bad JSON / unknown eventTrigger), SUBSCRIPTION_NOT_FOUND→404, PRIVACY_EXCEPTION_DENIED→403. Metrics fivegc_lmf_subscription_create_total{result}, fivegc_lmf_subscriptions_active. **CONFORMANT-WITH-NOTES**: eventTrigger/notification-body/AOI-enum tokens are LMF-internal, not the canonical TS 29.572 §6.1.6.3 `LocationEventType`/`NotifiedPosInfo`/`AreaEventType` names — Nlmf YAML not synced locally; reconcile before external LCS interop (see docs/procedures/EventSubscription.md §Conformance Notes). agentic_verified ✅ | LMF-003 | ✅ |
| Nlmf_Location CancelLocation (one-shot) | TS 29.572 §5.2.2.5 | **LMF** | ✅ `POST /nlmf-loc/v1/ue-contexts/{ueContextId}/cancel-loc`→204. Aborts an in-progress DetermineLocation by firing the stored `context.CancelFunc` from the `pendingLoc` sync.Map (keyed by ueContextId); idempotent 204 no-op when nothing pending ([VERIFY] vs 404 CONTEXT_NOT_FOUND). Subscription DELETE also performs cancel-and-remove (§5.2.3.4). agentic_verified ✅ | LMF-003, LMF-004 | ✅ |
| Nlmf_Location LocationNotification (push) | TS 29.572 §6.1.6.2.4 | **LMF**→LCS consumer | ✅ LMF acts as mTLS HTTP/2 client, POSTs `{subId, notificationItems:[{locationData, areaEventInfo?}]}` to caller `notificationUri`; AOI items carry `areaEventInfo.event` (AREA_ENTERING/AREA_LEAVING). Best-effort: one retry on 5xx/transport error then drop (config notification_retry). Metric fivegc_lmf_notifications_total{event_trigger,result=OK\|RETRIED\|DROPPED}. **CONFORMANT-WITH-NOTES**: envelope follows generic TS 29.571 §5.2 convention, not the Nlmf-specific `NotifiedPosInfo` body — field-name reconciliation deferred (Nlmf YAML not present). agentic_verified ✅ | LMF-003 | ✅ |
| Deferred MT Location — Paging-then-locate for CM-IDLE UE | TS 23.273 §7.2 steps E2–E7 | AMF | ✅ `handleProvideLocInfo` detects CM-IDLE, calls `pager.SendPaging(ue)`, stores channel in `pendingLocPage` (sync.Map, keyed by AMF-UE-NGAP-ID), blocks up to T-positioning (15 s guard). On UE Service Request → `onUEReachable` callback → `sbiSrv.NotifyUEReachable` signals channel → falls through to NGAP LocationReportingControl. Timeout: 504 UE_NOT_REACHABLE. Tests: `TestProvideLocInfo_CMIdle_PagingSuccess`, `TestProvideLocInfo_CMIdle_PagingTimeout` | LMF-002 | ✅ |
| Location Privacy — Nudm_SDM lcsData (UDM producer) | TS 29.503 §5.2.2; TS 23.273 §9.1 | UDM | ✅ `GET /nudm-sdm/v2/{supi}/lcs-privacy-data` returns `{locationPrivacy: "ALLOW_ALL"}` (dev default; no DB lookup). LMF caches per-SUPI responses (5-min TTL) via HTTPUDMSDMClient. Privacy values: ALLOW_ALL (proceed), BLOCK_ALL (403 PRIVACY_EXCEPTION_DENIED). Fail-open: non-200 or network error → proceed with warning | LMF-002 | ✅ |
| Namf_Location ProvideLocationInfo (AMF producer) | TS 29.518 §5.2.2.6 | AMF, LMF | ✅ `POST /namf-loc/v1/ue-contexts/{id}/provide-loc-info` on :8001 SBI. Resolves UE, handles CM-IDLE via paging-then-locate (LMF-002), relays NGAP LocationReportingControl, blocks on pendingLoc chan (10 s impl-defined guard), returns LocationData {nrCellId, tai}. Causes: MANDATORY_IE_MISSING→400, CONTEXT_NOT_FOUND→404, UE_NOT_REACHABLE→504 (paging timeout), LOCATION_FAILURE→504 (gNB timeout) | LMF-001, LMF-002 | ✅ |
| NGAP LocationReportingControl / LocationReport | TS 38.413 §8.17.1 (ProcCode 16 / 18) | AMF | ✅ `BuildLocationReportingControl` (ProcCode=16): AMF-UE-NGAP-ID(10)+RAN-UE-NGAP-ID(85)+LocationReportingRequestType(33) EventType=Direct(0)/ReportArea=Cell(0). `extractLocationReport` (ProcCode=18): decodes UserLocationInformation(121)→UserLocationInformationNR→NRCGI (36-bit BitString→9-hex) + TAI (PLMN + 3-octet TAC). Round-trip unit tests via free5gc ngapType/libngap | LMF-001 | ✅ |
| RAN LocationReport (UERANSIM gNB) + live Cell-ID E2E | TS 38.413 §8.17 | gNB (UERANSIM), LMF, portal | ✅ gNB patch `0040-location-reporting.patch` adds `receiveLocationReportingControl` → replies `LocationReport` (serving NR-CGI + TAI), closing the live LMF→AMF→gNB→AMF→LMF flow (previously timed out: stock v3.2.8 had no handler). Validated live (`scripts/validate-ueransim-mod.sh location`) + portal UE Location map. Only EventType=Direct honored | LMF-006 | ✅ |
| RAN NRPPa-Transport (UERANSIM gNB) + live E-CID E2E | TS 38.413 §8.17.3 / TS 38.455 §8/§9 | gNB (UERANSIM), AMF, LMF | ✅ gNB patch `0041-nrppa-transport.patch` (regenerated 2026-07-01, real APER) adds `receiveDownlinkUEAssociatedNRPPaTransport` (ProcCode 8) → decodes real ASN.1-APER NRPPa-PDU and replies over `UplinkUEAssociatedNRPPaTransport` (ProcCode 50): `PositioningInformationResponse{}` (ProcCode=9) then `E-CIDMeasurementReport` (ProcCode=4) carrying a real `NG-RANAccessPointPosition` estimate (TS 38.455 §9, TS 23.032 shape; fixed "Puerta del Sol" survey point, ~90 m uncertainty) instead of synthetic neighbour RSRP. `sendNgapUeAssociated` auto-adds AMF/RAN-UE-NGAP-ID. Closes the live LMF→AMF→gNB→AMF→LMF E-CID flow (previously fell back to Cell-ID: stock v3.2.8 had no handler). C++ encoder compiled+linked (`g++ -Wall -Wextra -pedantic`, 0 warnings) and hand-verified byte-for-byte against `shared/nrppa` golden hex before capture as the committed patch. `make ueransim-build-only` compiles 0041 cleanly. Live re-capture (Wireshark's real NRPPa dissector) caught two more bugs unit tests couldn't (round-trip tests shared the same wrong assumption on both sides): `NGRANCell` CHOICE index needed 2 bits not 1 (3 real alternatives incl. an unused `choice-Extension`), and Latitude/Longitude needed plain `int64` (X.691 §10.5.7.4 length-determinant + minimal octets for range>64K) not a fixed-3-octet `OctetString` (an earlier fix mis-diagnosed an unrelated all-zero edge case as a free5gc/aper bug). Final live pcap: zero malformed packets, zero Expert Info warnings, every field byte-exact | LMF-008, LMF-004-fix | ✅ |
| NGAP NRPPa UE-Associated Transport (relay) | TS 38.413 §8.17.3 (DL ProcCode 8 / UL ProcCode 50) | AMF | ✅ `BuildDownlinkUEAssociatedNRPPaTransport` (ProcCode=8): AMF-UE-NGAP-ID(10)+RAN-UE-NGAP-ID(85)+RoutingID(89,opt)+NRPPa-PDU(46), all IE criticality=reject, msg criticality=ignore. `extractUplinkUEAssociatedNRPPaTransport` (ProcCode=50): extracts opaque NRPPa-PDU + ids. AMF is a pure relay (never decodes NRPPa). `SendDownlinkNRPPa` registers a `pendingNRPPa` chan keyed by AMF-UE-NGAP-ID; `handleUplinkUEAssociatedNRPPa` resolves it (orphan UL → `nrppa_orphan` drop). SBI producer `POST /namf-loc/v1/ue-contexts/{id}/dl-nrppa-info` (base64 NRPPa-PDU; CM-IDLE→504 NRPPA_RELAY_FAILURE, 404 CONTEXT_NOT_FOUND, 10 s guard). Round-trip unit tests via free5gc ngapType/libngap. ProcCodes 8/50 + IE ids 10/85/46/89 verified against TS 38.413 Table 9.1-1 (backlog "68/69" was wrong). agentic_verified ✅ | LMF-004 | ✅ |
| NGAP NRPPa Non-UE-Associated Transport (relay) | TS 38.413 §8.17.4 (DL ProcCode 5 / UL ProcCode 47) | AMF | ✅ `BuildDownlinkNonUEAssociatedNRPPaTransport` (ProcCode=5): RoutingID(89,opt)+NRPPa-PDU(46); `extractUplinkNonUEAssociatedNRPPaTransport` (ProcCode=47). Cell-level signalling not tied to a UE context. In the E-CID MVP the UL non-UE path logs+drops (relay to LMF deferred to pass 2); codec + dispatch exercised by unit tests. ProcCodes 5/47 verified against TS 38.413 Table 9.1-1 (backlog "66/67" was wrong). agentic_verified ✅ | LMF-004 | ✅ |
| E-CID positioning via NRPPa (quality-driven + fallback) | TS 38.455 §8/§9 / TS 23.273 §6.2.9 / TS 29.572 §5.2.2.2 | LMF, AMF, gNB | ✅ `shared/nrppa` E-CID codec rewritten 2026-07-01 as real ASN.1 APER (`github.com/free5gc/aper` Marshal/Unmarshal on hand-written TS 38.455 structs — free5gc ships no NRPPa module) — PositioningInformation{Request,Response,Failure} (ProcCode=9), E-CIDMeasurementInitiation{Request,Response,Failure} (ProcCode=2), E-CIDMeasurementReport (ProcCode=4); corrected from the prior 12/6/8 which collided with real unrelated procedures. Mandatory `NRPPaTransactionID` now encoded. LMF method selection (`selectMethod`): hAccuracy >200 or absent→Cell-ID, 0<x≤200→E-CID, <50→LPP downgraded to E-CID (LMF-005 deferred). Two synchronous rounds via AMF dl-nrppa-info: capability then E-CID measurement; position from the gNB-reported `NG-RANAccessPointPosition` (TS 38.455 §9, real optional IE — TS 38.455's `measuredResults` is E-UTRA-only and cannot legally carry NR neighbour RSRP, so the RSRP-weighted-centroid design was replaced), uncertainty clamped 50–150 m, no-AP-position fallback 300 m. NRCGI = 3-byte PLMN + 36-bit cell id (TS 38.413 §9.3.1.7). Graceful fallback to Cell-ID (HTTP 200, no 5xx) on relay error / decode error / capability=NONE / InitiationFailure / timeout / unresolvable serving cell. Privacy gate (BLOCK_ALL→403 PRIVACY_EXCEPTION_DENIED) runs before any NRPPa. Metric `fivegc_lmf_ecid_total{result}` + `fivegc_amf_nrppa_transport_total{direction,assoc}`. See docs/procedures/NRPPaRelay.md §"NRPPa fix — real APER + correct procCodes (LMF-004 fix, 2026-07-01)". agentic_verified ✅ | LMF-004, LMF-004-fix | ✅ |
| LPP relay over N1 NAS (AMF transparent relay) | TS 24.501 §8.7.4 / §9.11.3.40 (PCT=0x03) / §9.11.3.39 | AMF, LMF, gNB, UE | ✅ **Live-validated (LMF-009, 2026-07-05)**. AMF is a **pure transparent relay** — never decodes LPP. DL: `SendDownlinkLPP` wraps the opaque LPP-PDU in a DL NAS Transport with **payload container type 0x03** (`nas.PayloadContainerTypeLPP`, NOT 0x01 N1SM), SHT=0x02 ciphered, over existing NGAP DownlinkNASTransport (no new NGAP proc). UL: additive `PCT==0x03` branch (order UEPolicy 0x05 → SMS 0x02 → **LPP 0x03** → default N1SM 0x01) → `handleULLPP` resolves `pendingLPP` chan keyed by AMF-UE-NGAP-ID (orphan → `lpp_orphan` drop). Payload container **LV-E** (§9.11.3.39) byte-exact. LMF-009 adds the additive **`expectUlResponse`** field to `dl-lpp-info`: `false` → AMF sends the DL NAS Transport and returns **204 No Content** with NO `pendingLPP` waiter (`SendDownlinkLPPNoWait`, for the unsolicited ProvideAssistanceData leg — TS 37.355 assistance delivery has no response message); `true`/absent → unchanged synchronous 200 relay. Metric `fivegc_amf_lpp_transport_total{direction}`. **CONFORMANT** — the LMF-005 ALIGNED-vs-UNALIGNED PER deviation is **RESOLVED**: `shared/lpp` no longer uses `github.com/free5gc/aper`; it now encodes TS 37.355 in a hand-rolled **X.691 BASIC-PER UNALIGNED** bit codec (`shared/lpp/uper.go`) as §4 mandates. Wire-correctness proven by the **tshark 4.6.4 LPP dissector** (golden-PDU oracle `TestTsharkOracle_AllGoldenPDUs`, zero malformed) and a **live N2 pcap** (`pcap-analyzer`, SCTP PPID 60, zero malformed — the three DL LPP legs dissect as real LPP). UE patch `0042-lpp-gnss.patch` closes the live E2E loop. agentic_verified ✅ | LMF-005, LMF-009 | ✅ |
| GNSS positioning (A-GNSS via LPP, UE-assisted) | TS 37.355 §6 / TS 23.273 §6.2.10 / TS 29.572 §5.2.2.2, §6.1.6.2.2 | LMF, AMF, UE | ✅ **Live-validated (LMF-009, 2026-07-05)**: `DetermineLocation` hAccuracy=30 → **200**, `positioningDataList:["gnss"]`, uncertainty **5 m**, fix at the +25 m N/+15 m E offset from the Madrid anchor. `nf/lmf/internal/server/lpp.go` `performLPPOrFallback` now runs the **three real TS 37.355 legs** (the invented combined "AssistanceDataAndLocationRequest" is **removed**): (1) RequestCapabilities → ProvideCapabilities{GNSS supported/NONE}; (2) **ProvideAssistanceData** (gnss-ReferenceTime + gnss-ReferenceLocation anchor; DL-only, `expectUlResponse=false`, endTransaction=TRUE — no UL reply); (3) **RequestLocationInformation** (locationMeasurementsRequired + gnss-PositioningInstructions) → ProvideLocationInformation (4× GNSS-SatMeasElement code-phase pseudoranges). `shared/lpp` builds all 5 messages against real spec structures verified type-by-type vs `specs/3gpp-asn1/LPP-PDU-Definitions.asn` (TS 37.355 V19.3.0): LPP-Message 4 presence bits (not extensible); LPP-MessageBody.c1 4-bit index; TransactionNumber INTEGER(0..255) (LMF-005's 0..262143 corrected); EllipsoidPointWithAltitudeAndUncertaintyEllipsoid 10 mandatory fields; GNSS-SupportElement mandatory gnss-ID/agnss-Modes/gnss-Signals; GNSS-SatMeasElement codePhase/integerCodePhase(OPTIONAL, always sent)/codePhaseRMSError; MeasurementReferenceTime.networkTime OPTIONAL (omitted). No invented IEs; GNSS-ID enum GPS=0. Quantized-anchor rule seeds WLS/ephemeris from the wire-encoded reference location (byte-identical geometry both ends). State machine IDLE→CAPS_REQUESTED→ASSIST_SENT→MEASURE_RECEIVED→FIXED. Metric `fivegc_lmf_gnss_total{result}`. **CONFORMANT-WITH-NOTES** (OpenAPI shape only, unchanged by LMF-009): `positioningDataList:["gnss"]` uses the LMF-internal lowercase label; strict TS 29.572 §6.1.6.2.2 models it as `PositioningMethodAndUsage` objects (uppercase enum) with GNSS results in a separate `gnssPositioningDataList` (`GnssId` enum) — reconcile before external LCS interop. Two documented [VERIFY] semantic pins remain (codePhaseRMSError exponent-MSB packing k=8y+x; referenceTimeUnc scale r=0.5·(1.14^K−1) µs) — both wire-legal INTEGERs confirmed by the tshark dissector and a shared Go↔C++ formula, non-blocking. agentic_verified ✅ | LMF-005, LMF-009 | ✅ |
| GNSS → E-CID → Cell-ID fallback chain (graceful, no 5xx) | TS 23.273 §6.2.10 / §6.2.9 | LMF | ✅ **Live-validated (LMF-009, 2026-07-05)**: `LPP_GNSS_NONE=1` on the UE → ProvideCapabilities without A-GNSS → LMF `FALLBACK_ECID` → **200** (`positioningDataList:["eCID"]`, ~98 m, resolved 14 ms, no timeout, no 5xx). `selectMethod(hAccuracy)`: **< 50 m → GNSS/LPP**, **50–200 m → E-CID**, **> 200 m or absent → Cell-ID**. Each tier downgrades one step when its client is nil and on any runtime LPP failure (capability=NONE, decode error, unexpected message type, gnss-Error, < 4 usable satellites, WLS non-convergence, relay timeout/CM-IDLE, leg-2 send failure): `performLPPOrFallback` → `performECIDOrFallback` → Cell-ID, always returning **HTTP 200 LocationData** with the achieved method — **never a 5xx**. Metric `fivegc_lmf_gnss_total{result=OK|FALLBACK_ECID|FALLBACK_CELLID|FAILURE}`. agentic_verified ✅ | LMF-005, LMF-009 | ✅ |
