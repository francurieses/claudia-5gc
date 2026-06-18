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
| `nnrf-nfm` NFStatusSubscribe | §5.2.2.7 | ⏳ | — | Change notifications |
| `nnrf-nfm` NFStatusUnsubscribe | §5.2.2.8 | ⏳ | — | |
| `nnrf-nfm` NFStatusNotify | §5.2.2.9 | ⏳ | — | HTTP/2 callback client |
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
| Xn Handover | TS 23.502 §4.9.1.2 | ⏳ | — | |
| N2 Handover | TS 23.502 §4.9.1.3 | ⏳ | — | |

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
| PDU Session Modification (UE-requested) | TS 23.502 §4.3.3.1 | ✅ | unit smf/server | SMF accepts as-is; N1SM ModCmd + N2SM ModReqTransfer |
| PDU Session Modification (NW-initiated, QoS) | TS 23.502 §4.3.3.2 | ✅ | e2e modified-UERANSIM (`make qos-mod-e2e`) | Trigger: `POST /nsmf-management/v1/sessions/{psi}/qos`; N4 Update QER (ack awaited) → N1SM 0xCB (IEs 0x2A/0x7A/0x79 with new 5QI) + N2SM ModReqTransfer. Modified UERANSIM now handles 0xCB and replies 0xCC (`tools/ueransim/patches/0030`) |
| Nudm_SDM Get sm-data (N10, subscribed default QoS) | TS 29.503 §6.1.6.2.7 | ✅ | unit smf/pcf | 5QI precedence: PCF override > UDM subscription > operator default; source tracked per session |
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
| EAP-AKA' flow | TS 33.501 §6.1.3.1 | ⏳ | |

## UDM (TS 29.503)

🟡 Authentication + AM data + UECM implemented.

| Service | Section | Status | Notes |
|---|---|---|---|
| Nudm_UEAuthentication (GenerateAuthData) | §5.4 | ✅ | Milenage + KDF; SQN increment in UDR; e2e UERANSIM |
| Nudm_SDM Get AM data | §5.2 | ✅ | e2e UERANSIM |
| Nudm_SDM Subscribe/Notify | §5.2 | ⏳ | |
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
| Policy data | TS 29.505 §6 | ⏳ | — | |
| Application data | TS 29.505 §7 | ⏳ | — | |
| Exposure data | TS 29.505 §8 | ⏳ | — | |

## PCF (TS 29.507, TS 29.512, TS 29.514, TS 29.525)

✅ SM Policy Control + UE Policy Control operational.

| Service | Section | Status | Notes |
|---|---|---|---|
| Npcf_SMPolicyControl Create | TS 29.512 §5.2.2.2 | ✅ | config-driven QoS/AMBR (no hardcoded values); e2e UERANSIM |
| Npcf_SMPolicyControl Update | TS 29.512 §5.2.2.3 | ⏳ | prerequisite for PDU Session Modification |
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
