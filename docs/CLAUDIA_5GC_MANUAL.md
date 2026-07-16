# ClaudIA 5GC — Feature & Operations Manual

> Authoritative operations and feature reference for the ClaudIA 5GC project.
> Maintained automatically — see `CLAUDE.md` → **Documentation Maintenance**.
> For implementation detail behind any item here, follow the linked `nf/<nf>/CLAUDE.md`,
> `docs/procedures/*.md`, and `docs/implementation-status.md`.

---

## 1. Project Overview

**ClaudIA 5GC** is a from-scratch implementation of a **5G Core Standalone (SA)** network
conforming to **3GPP Release 17**. Network Functions run as Docker containers and communicate
over the **Service Based Architecture** (HTTP/2 + JSON over mTLS) plus the classic reference
points (NGAP/SCTP on N2, PFCP/UDP on N4, GTP-U on N3/N6/N9).

- **Language/stack**: Go 1.26.2 across all NFs; `slog` logging; `net/http` + `golang.org/x/net/http2`
  for SBI; Prometheus + OpenTelemetry→Jaeger for observability; PostgreSQL 16 + Redis 7 for state.
- **Target release**: 3GPP Release 17 (OpenAPI from `forge.3gpp.org/rep/all/5G_APIs`, branch `Rel-17`).
- **Deployment model**: Docker Compose for development; one container per NF, observability stack,
  PostgreSQL, Redis, optional UERANSIM RAN simulator, Management Portal, and MCP server.

### Architecture summary

```
        ┌──────────────────────── Control Plane (SBA, HTTP/2+mTLS) ───────────────────────┐
  UE ─Uu─ gNB ─N2(NGAP/SCTP)→ AMF ─N12→ AUSF ─N13→ UDM ─N35→ UDR
                               │  ├─N11→ SMF ─N7→ PCF ─N36→ UDR
                               │  ├─N15→ PCF
                               │  └─N22→ NSSF
            all NFs ⇄ NRF (register / discover / OAuth2 token)
        └──────────────────────────────────────────────────────────────────────────────────┘
  gNB ─N3(GTP-U)→ UPF ─N6→ Data Network          SMF ─N4(PFCP)→ UPF
```

**Operational NFs**: NRF, AMF, AUSF, UDM, UDR, SMF, PCF, UPF, NSSF.
**Tooling**: MCP server (LLM tool gateway), Management Portal (web UI), UERANSIM (RAN simulator).

### Repository structure map

```
nf/<nfname>/         One NF per folder — CLAUDE.md + Dockerfile + cmd/ + internal/ + config/ + tests/
nf/_template/        Template for new NFs
shared/              Shared libs: sbi/ logging/ observability/ types/ nas/ ngap/ pfcp/ crypto/ aka/ oauth2/ nrf/ config/
mcp/                 MCP server (standalone tooling NF): cmd/ + internal/{tools,clients,server,session}
specs/3gpp-openapi/  3GPP Rel-17 YAMLs
docs/                architecture.md · implementation-status.md · compliance-matrix.md · procedures/*.md · this manual
docs/procedures/     One .md per 3GPP procedure (sequence diagram + spec ref + IEs + error cases)
observability/       Loki + Prometheus + Grafana (dashboards) + Promtail
tools/mgmt-portal/   Web portal Go(chi)+React, port 8080
config/              operator.yaml (single source of truth for DNNs/slices) + ueransim/ + packetrusher/
docker-compose.yml   Full stack with compose profiles (core / obs / tools / multi-slice / handover / …)
dev/                 Autonomous-dev infra: BACKLOG.md, ORCHESTRATOR_PROMPT.md, SESSION_LOG.md
```

---

## 2. Network Functions Reference

All SBI servers use HTTP/2 + mTLS (TS 29.500 §4.4.1). Certs are mounted from `pki/` as
`/etc/5gc/pki/<nf>.crt` / `.key`. All NFs register with the NRF on startup and discover peers
via the NRF (no hardcoded hostnames). Every NF exposes `/metrics` (Prometheus) and a `/healthz`.

| NF | SBI port | Metrics port | Status | Backend |
|---|---|---|---|---|
| NRF | 8000 | 9100 | ✅ | Redis |
| AMF | 8001 (+9002 mgmt, 38412 N2) | 9101 | ✅ | PostgreSQL + Redis |
| AUSF | 8002 | 9102 | 🟡 | Redis |
| UDM | 8003 | 9103 | 🟡 | (via UDR) |
| SMF | 8004 | 9105 | ✅ | PostgreSQL |
| UDR | 8005 | 9104 | ✅ | PostgreSQL 16 (+ in-memory fallback) |
| PCF | 8006 | 9106 | ✅ | config + UDR |
| NSSF | 8007 | 9109 | ✅ | static config |
| UPF | 8805/udp N4, 2152/udp N3 | 9107 | ✅ | in-process PFCP table |
| MCP | 9300 (SSE) | — | ✅ | consumes NF APIs |

### 2.1 NRF — Network Repository Function

- **Role**: NF registration, discovery, status subscribe/notify, OAuth2 token issuance (AS).
- **Procedures**: NFRegister/Update/Deregister, NFDiscover (with SNSSAI + DNN filters,
  TS 29.510 §6.2.3.2.3.1), Heartbeat with TTL eviction, NFStatusSubscribe/Notify
  (TS 29.510 §5.2.2.7–9), OAuth2 `client_credentials` HS256 JWT (TS 33.501 §13.4.1).
- **SBI**: exposes `Nnrf_NFManagement`, `Nnrf_NFDiscovery`, `Nnrf_AccessToken`. Consumed by all NFs.
- **Config knobs**: `REDIS_URL`, heartbeat TTL, listen addr.
- **Isolated start**: `docker compose up -d nrf` (most NFs depend on it; start first).

### 2.2 AMF — Access and Mobility Management Function

- **Role**: N1/N2 termination, registration management, connection/mobility management, NAS security.
- **Procedures**: Initial Registration, Mobility/Periodic Registration Update, AN Release / CM-IDLE,
  UE-initiated & Network-initiated Deregistration, Service Request (incl. network-triggered/CN Paging),
  PDU Session Establishment/Release/Modification relay, Xn & N2 Handover, NSSAA slice auth
  (TS 23.502 §4.2.9), Service Area Restriction (§4.2.x), UE Configuration Update / UE Policy delivery.
- **SBI exposed**: `Namf_Communication` inbound server on **:8001** (UEContextTransfer TS 29.518 §5.3.2;
  N1N2MessageTransfer §5.2.2.3 → NGAP Paging). **:9002** management API (NW-initiated ops, UCU push).
- **SBI consumed**: Nausf (N12), Nsmf (N11), Nudm, Npcf (N15), Nnssf (N22), Nnrf.
- **Security**: NAS NIA2 + NEA2; KAMF/keys per TS 33.501.
- **Timers**: T3512, Mobile Reachable, Implicit Detach, PendingRemoval (configurable in `nf/amf/config/dev.yaml` `timers:`).
- **Isolated start**: `docker compose restart amf`.

### 2.3 AUSF — Authentication Server Function

- **Role**: Primary authentication anchor.
- **Procedures**: 5G-AKA happy path; EAP-AKA' (RFC 5448, key hierarchy in `shared/crypto/eapaka`);
  NSSAA EAP relay (`POST /nausf-nssaa/.../authenticate`, simulated AAA-S).
- **SBI**: `Nausf_UEAuthentication`, `Nausf_NSSAA` (exposed); Nudm (consumed).
- **State**: Redis auth context store (TTL 5 min, key `ausf:auth:{id}`).
- **Status**: 🟡 happy paths complete; resync/edge cases partial.

### 2.4 UDM — Unified Data Management

- **Role**: Subscription data front-end, authentication vector generation, SUCI deconcealment.
- **Procedures**: Auth (GenerateAuthData), AM data (incl. `subjectToNssaa` flag), UECM
  (registration/dereg), SDM Subscribe/Notify (TS 29.503). SUCI→SUPI deconcealment (null / Profile A / Profile B).
- **SBI**: `Nudm_UEAuthentication`, `Nudm_UECM`, `Nudm_SDM` (exposed); Nudr (consumed).
- **Config**: `hn_private_key_x25519` in `nf/udm/config/dev.yaml` (or `HN_PRIVATE_KEY_X25519` env) for SUCI Profile A.
- **Status**: 🟡.

### 2.5 UDR — Unified Data Repository

- **Role**: Persistent subscriber & policy data store.
- **Procedures**: `Nudr_DR` for subscription data and **policy data**: UE Policy Set (URSP) and
  **SM Policy Data** (`/policy-data/{supi}/sm-data` GET/PUT/PATCH, TS 29.519 §5.6.2.4 — per-S-NSSAI/DNN
  authorized QoS in `subscription_sm_policy` JSONB) consumed by PCF over N36.
- **Backend**: PostgreSQL 16 via pgx/v5, auto-migrate; in-memory fallback. `UE_COUNT` controls seeded subscribers.
- **SBI**: `Nudr_DR` (exposed). Consumed by UDM (N35) and PCF (N36).

### 2.6 SMF — Session Management Function

- **Role**: PDU session lifecycle, IP allocation, N4 control of UPF.
- **Procedures**: PDU Session Establishment, UE-requested & NW-initiated Modification (consults PCF
  SM Policy Update for QoS authorization, TS 29.512 §5.2.2.3, fail-open if PCF absent), Release;
  IPv4 allocation; IPv6/IPv4v6 prefix delegation (control plane, TS 24.501 §9.11.4.10);
  N1SM/N2SM encoding; CN Paging trigger via internal `dl-data-notification`.
- **SBI**: `Nsmf_PDUSession` on **:8004**; internal `nsmf-management/v1` (sessions, QoS, dl-data-notification).
  Consumed: Npcf (N7), Nudm, Nnrf, Namf. N4 PFCP to UPF.
- **Backend**: PostgreSQL sessions. Announces 4 S-NSSAIs on NRF.
- **Isolated start**: `docker compose restart smf`.

### 2.7 PCF — Policy Control Function

- **Role**: Policy decisions for sessions, access/mobility, and UE route selection.
- **Procedures**: SM Policy Control (N7, config-driven QoS/AMBR) + SM Policy **Update**
  (TS 29.512 §5.2.2.3 — authorizes/rejects requested 5QI + Session-AMBR); UE Policy Control N15
  (TS 29.525) + URSP delivery (TS 24.526); AM Policy Association (TS 23.502 §4.16); per-subscriber
  UDR override (write-through to UDR SM Policy Data over N36).
- **SBI**: `Npcf_SMPolicyControl` (:8006), `Npcf_UEPolicyControl`, `Npcf_AMPolicyControl`;
  plus internal `pcf-internal/v1` overrides API. Consumed: Nudr (N36), Nnrf.

### 2.8 UPF — User Plane Function

- **Role**: Packet routing/forwarding, GTP-U N3 termination, N6 egress.
- **Procedures**: PFCP session table (N4, TS 29.244); GTP-U decap/encap with extension-header skip
  (PDU Session Container type 0x85, TS 38.415); QER install for QoS; per-DNN TUN + iptables MASQUERADE;
  inline ICMP responder. e2e ping verified.
- **Interfaces**: N4 PFCP **:8805/udp**, N3 GTP-U **:2152/udp**, N6 per-DNN Docker networks.
- **Per-DNN isolation**: `internet`→`10.60.0.0/24` (TUN `upfgtp0`), `ims`→`10.61.0.0/24` (TUN `upfgtp1`).
  Source of truth `config/operator.yaml`. Known hard-stop: IPv6 PFCP PDR + UPF RA (UPF-001), URR usage reporting.

### 2.9 NSSF — Network Slice Selection Function

- **Role**: Slice selection.
- **Procedures**: `Nnssf_NSSelection_Get` — static NSSAI intersection; unknown slice → empty allowed list.
- **SBI**: `Nnssf_NSSelection` (:8007). Consumed by AMF (N22). 8 unit tests.

### 2.10 MCP — Model Context Protocol server (tooling)

- **Role**: Standalone tooling NF (not a 3GPP NF) exposing the core's internals to LLM clients.
- **Transports**: stdio (Claude Desktop/Code) + HTTP SSE (**:9300**). Identical tool registry on both.
- **See**: Section 5 for the full tool reference; `mcp/CLAUDE.md` for internals.

---

## 3. Implemented Features

Each feature: description · 3GPP spec · NFs involved · how to trigger · expected outcome ·
known limitations. The fastest validation snippets also live in the project root `CLAUDE.md`
under **Feature Validation**. Run `make up-obs` first unless noted.

### 3.1 UE Registration & Authentication

#### Initial Registration (5G-AKA)
- **Description**: SUCI→SUPI resolution, 5G-AKA mutual auth, NAS security mode, registration accept with GUTI + T3512.
- **3GPP spec**: TS 23.502 §4.2.2.2.2; TS 33.501 §6.1.3.2.
- **NFs**: gNB→AMF→AUSF→UDM→UDR; NSSF for slice selection.
- **How to trigger**: `make ueransim` (UE auto-registers).
- **Expected**: `nr-cli imsi-001010000000001 --dump` → `MM-REGISTERED/NORMAL-SERVICE`; AMF log `InitialRegistration` result OK; Jaeger trace spanning AMF→AUSF→UDM.
- **Limitations**: AUSF resync edge cases partial (🟡).

#### EAP-AKA' primary authentication
- **Description**: EAP-AKA' method (`PUT …/eap-session`) as alternative to 5G-AKA.
- **3GPP spec**: TS 33.501 §6.1.3.1; RFC 5448. `docs/procedures/eap-aka-prime.md`.
- **NFs**: AMF→AUSF→UDM. Key hierarchy in `shared/crypto/eapaka`.
- **Expected**: AUSF `eap-session` exchange; successful key derivation; UE registered.

#### SUCI Profile A (X25519 ECIES)
- **Description**: Concealed SUPI deconcealment with X25519 ECIES.
- **3GPP spec**: TS 33.501 §6.12, Annex C.3.
- **How to trigger**: `make ueransim-profile-a` (uses `config/ueransim/ue-profile-a.yaml`, `protectionScheme: 1`).
- **Expected**: `docker logs udm | grep "SUCI Profile A"` (deconcealment); AMF resolves `supi.*imsi`.
- **Limitations**: dev key pair only; clean up with `make ueransim-profile-a-down`.

#### NSSAA — Network Slice-Specific Authentication & Authorization
- **Description**: EAP-based slice auth relayed via AUSF to a (simulated) AAA-S, control plane.
- **3GPP spec**: TS 23.502 §4.2.9. `docs/procedures/nssaa.md`.
- **NFs**: AMF→AUSF (EAP relay)→AAA-S (simulated); UDM `subjectToNssaa` flag.

### 3.2 PDU Session Establishment & Release

- **Description**: UE-requested PDU session setup (IP allocation, N4 PFCP install, N2 resource setup,
  N1 PDU Session Establishment Accept) and release.
- **3GPP spec**: TS 23.502 §4.3.2 (establish) / §4.3.4 (release); QoS TS 23.501 §5.7.
- **NFs**: UE→AMF→SMF→PCF→UPF (+UDM sm-data).
- **How to trigger**:
  ```bash
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"
  ```
- **Expected**: PCF `SmPolicyCreate`/`SmPolicyDelete`; UE `uesimtun0` up with SMF-assigned IP;
  `ping -I uesimtun0 172.30.3.100` 0% loss (~1.8 ms); UPF `SessionDeletion` on release.
- **NW-initiated release** (TS 23.502 §4.3.4.3): `curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/$SUPI/pdu-sessions/1`
  → 202. The AMF sends the Release Command on N1/N2 (steps 3-4), then **waits for the UE's PDU Session
  Release Complete** (step 5) before deleting the SM context at the SMF (step 7) — which is what triggers
  the SMF's N4 teardown on the UPF (step 8). If the UE stays silent, the **T3592 guard (9 s)** releases
  the SM context anyway, so a silent UE cannot leak a session. Expected AMF log order:
  `NW PDU Session Release Command sent` → `PDU Session Release Complete received` →
  `SM context deleted at SMF` → `NW-initiated PDU Session Release complete`; then SMF
  `Nsmf_PDUSession_DeleteSMContext — releasing session` + UPF `PFCP Session deleted`.

### 3.3 PDU Session Modification (QoS)

- **Description**: UE-requested and **NW-initiated** 5QI/AMBR modification (full §4.3.3.2 flow:
  N4 QER update → N2 PDU Session Modify → NAS 0xCB).
- **3GPP spec**: TS 23.502 §4.3.3.2; TS 23.501 §5.7; TS 29.512 §5.2.2.3.
- **NFs**: SMF↔PCF↔UPF↔AMF.
- **How to trigger**:
  ```bash
  curl -sk -X POST https://localhost:8004/nsmf-management/v1/sessions/1/qos \
    -H 'Content-Type: application/json' -d '{"5qi":7,"reason":"upgrade to interactive video"}'
  ```
- **Expected**: SMF `NetworkQoSModification`; UPF `QER updated`; AMF `QoS Modification Command`.
- **5QI selection precedence**: PCF override > UDM subscription (sm-data) > operator default (`qos_source` log field).

### 3.4 Xn Handover

- **Description**: gNB-to-gNB handover with Path Switch through the core.
- **3GPP spec**: TS 23.502 §4.9.1.2.
- **NFs**: gNB(s)→AMF→SMF→UPF.
- **How to trigger**: `make handover-test` (PacketRusher scripted scenario), or Portal → PacketRusher.
- **Expected**: AMF `PathSwitchRequest` + `spec_ref.*4.9.1.2`; SMF `PATH_SWITCH_REQ`. Clean up `make handover-down`.

### 3.5 N2 Handover

- **Description**: Source/Target gNB handover via AMF (5-step NGAP flow, NH/NCC key derivation).
- **3GPP spec**: TS 23.502 §4.9.1.3.
- **NFs**: source gNB→AMF→target gNB; SMF.
- **How to trigger**: `make handover-n2-test` or Portal → PacketRusher → N2 Handover.
- **Expected**: AMF `HandoverRequired` → `HandoverCommand` → `HandoverNotify`. KgNB stored in UEContext; `pendingN2HO` state map.

### 3.6 Network Slicing (NSSF-based S-NSSAI selection)

- **Description**: Allowed NSSAI computation via NSSF; per-UE slice subscription enforced.
- **3GPP spec**: TS 23.501 §5.15; TS 29.531 (Nnssf).
- **NFs**: AMF→NSSF; UDR am-data.
- **Slices**: internet (1/000001), gold (1/000002), silver (2/000001), bronze (3/000001).
- **How to trigger**: `make ueransim-slices` then `make test-slices` (T0–T9 suite).
- **Expected**: AMF correct `AllowedNSSAI` per UE; unauthorized slice → `NSSAI_NOT_ALLOWED` (T8);
  NSSF NSSelection returns intersection.
- **PDU session on an unauthorized slice**: rejected, never silently moved to another slice.
  The AMF answers the UL NAS Transport with a DL NAS Transport carrying 5GMM cause **#90
  "payload was not forwarded"** and does not call the SMF (TS 24.501 §5.4.5.2.5). Log:
  `UE requested S-NSSAI not in Allowed NSSAI — rejecting PDU session` with `result=REJECT`,
  `cause=90` and the `allowed_nssai` the UE was actually entitled to. UERANSIM reports
  `SM forwarding failure … cause[PAYLOAD_NOT_FORWARDED]` and aborts the SM procedure.
- **Adding a slice through the portal**: the portal writes the slice to am-data (Allowed NSSAI)
  and then calls the UDR (`POST /nudr-internal/v1/subscribers/{supi}/sync-sm-data`) to re-derive
  the matching sm-data, so the slice gets a `DNNConfiguration` with a real subscribed default 5QI
  instead of leaving the SMF on `OPERATOR_DEFAULT`. The response reports `sm_data_synced`.
  The slice→QoS mapping lives only in the UDR (`store.BuildSMSubscriptions`); the portal never
  duplicates it. The resync is best-effort — a UDR that is down does not fail provisioning.
- **The slice's DNN must match the `apn` the UE requests for that slice.** sm-data is looked up
  by (DNN, S-NSSAI): a slice provisioned with `dnn=gaming` while the UE's session config says
  `apn: 'ims'` yields no match, and the SMF silently falls back to `OPERATOR_DEFAULT`.
- **Known limitations**: to make a new slice usable you must still (a) add it to the UE's
  `configured-nssai` — the Allowed NSSAI is the intersection with what the UE requests, so a
  slice the UE never asks for is never allowed; and (b) add it to `config/operator.yaml`
  (the seed source, so it survives a `make down -v` reseed), `nf/amf/config/dev.yaml`,
  `nf/nssf/config/dev.yaml` and the gNB `slices:` list, then restart those NFs.

### 3.7 QoS Policy Enforcement (PCF-driven 5QI, GBR/MBR, AMBR)

- **Description**: PCF authorizes 5QI + Session-AMBR; SMF installs via PFCP QER; subscriber default from UDM sm-data.
- **3GPP spec**: TS 23.501 §5.7; TS 29.512; TS 29.244 §7.5.2.5 (QER).
- **How to trigger / inspect**:
  ```bash
  curl -sk https://localhost:8004/nsmf-management/v1/sessions | jq
  curl -sk https://localhost:8003/nudm-sdm/v2/imsi-001010000000001/sm-data | jq
  ```
- **Expected**: UPF `qer_id` install; SMF `qos_source` = PCF_OVERRIDE | UDM_SUBSCRIPTION | OPERATOR_DEFAULT.

### 3.8 URSP Policy Delivery

- **Description**: UE Route Selection Policy delivered via UE policy delivery service — DL NAS Transport
  + UE policy container type **0x05** + MANAGE UE POLICY COMMAND (NOT Config Update Command / IEI 0x7B).
- **3GPP spec**: TS 24.526 / TS 29.525 / TS 24.501 Annex D.
- **NFs**: PCF (N15)→AMF→UE.
- **How to trigger**:
  ```bash
  make validate-ursp                 # full U0–U9 suite
  curl -X POST http://localhost:9002/amf/v1/ue-contexts/$SUPI/push-policies   # on-demand (UE CM-CONNECTED)
  ```
- **Expected**: PCF `policy association`; AMF `UE policy container sent`, `ursp_version` increments.
  Decode rules with `scripts/decode-ursp.py`. Per-subscriber override via UDR `PUT …/policy-data/{supi}/ue-policy-set`.
- **Limitations**: UERANSIM v3.2.8 has no URSP support → logs `Unhandled payload container type [5]`, does not ACK
  (unless using the `ueransim-mod` patched image).

### 3.9 NW-Triggered Additional PDU Session

- **Description**: 3GPP has no NW-initiated establishment; network steers via URSP — app detected →
  PCF DNN-scoped QoS override + URSP rule → AMF UE-policy push → UE establishes an additional PSI.
- **3GPP spec**: TS 23.503 §6.6.2 / TS 23.502 §4.3.2.2.1. `docs/procedures/nw-triggered-pdu-session.md`.
- **How to trigger**:
  ```bash
  curl -s -X POST http://localhost:8080/api/v1/qos/nw-sessions -H 'Content-Type: application/json' \
    -d '{"supi":"imsi-001010000000001","app":"cloud-gaming","dnn":"internet","sst":1,"sd":"000001","5qi":3,"ambr_uplink":"30 Mbps","ambr_downlink":"100 Mbps"}' | jq
  ```
- **Expected**: new PSI (existing untouched), `qos_source=PCF_OVERRIDE`; PCF `QoS override set`; AMF `UE policy container sent`.
- **Limitations**: verify takes ~17–25 s due to a UERANSIM UAC timing race + T3580 retransmit (UERANSIM quirk).

### 3.10 UE Configuration Update / UE Policy delivery

- **Description**: UCU command + UE policy delivery (see URSP). `docs/procedures/ue-configuration-update.md`.
- **3GPP spec**: TS 24.501 §8.2.19 (Config Update); UE policy delivery Annex D.
- **NFs**: AMF→UE (N1). Portal `/policies` triggers per-UE push.

### 3.11 Deregistration (UE- and Network-initiated)

- **Description**: UE-initiated and NW-initiated deregistration with PDU session teardown, UDM UECM dereg, N2 release.
- **3GPP spec**: TS 23.502 §4.2.2.3.
- **How to trigger (NW)**: `curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/$SUPI` (or Portal → Force Deregister).
- **Expected**: UE `MM-DEREGISTERED`; AMF `NetworkDeregistration`; clean NGAP release in PCAP.
- **Re-registration (since Jul 2026)**: the mgmt-API/portal-triggered dereg sends de-registration type
  **"re-registration required"** with **no 5GMM cause** (TS 24.501 §5.5.2.3.2), so the UE automatically
  performs a fresh Initial Registration and re-establishes its PDU sessions. Never send causes
  0x03/0x06/0x07 here — they invalidate the USIM on the UE (5U3-ROAMING-NOT-ALLOWED, no recovery until
  UE restart). UE-side auto re-registration requires the UERANSIM patch `0050-nw-dereg-reregistration.patch`
  (stock v3.2.8 left it as a TODO). Log check: UE `Initial registration required due to [DUE-TO-DEREGISTRATION]`.
- **Subscriber edits via portal**: `PUT /api/v1/subscribers/{supi}` upserts auth+AM data but **preserves the
  DB SQN** (network-managed, incremented by UDM per auth). Writing a stale SQN back rewinds it and UERANSIM
  then fails the Security Mode Command integrity check on every re-registration (it derives KAUSF from its
  own higher SQN-MS without sending a sync-failure AUTS). The portal edit form shows SQN read-only.

### 3.12 UE Context Transfer (inter-AMF)

- **Description**: Producer/old-AMF side of UE context transfer over `namf-comm`.
- **3GPP spec**: TS 29.518 §5.3.2. `docs/procedures/ue-context-transfer.md`.
- **How to trigger**:
  ```bash
  curl -sk --cert pki/smf.crt --key pki/smf.key --cacert pki/ca.crt \
    -X POST https://localhost:8001/namf-comm/v1/ue-contexts/imsi-001010000000001/transfer \
    -H 'Content-Type: application/json' -d '{"reason":"MOBI_REG"}' | jq
  ```
- **Expected**: 200 + `ueContext.mmContextList` (NasSecurityMode + kamf) + `sessionContextList`; AMF `UE context transferred`.
- **Limitations**: no `regRequest` integrity replay; no `RegistrationStatusUpdate` consumer (old context freed by implicit-detach timers).

### 3.13 CN Paging / Network-Triggered Service Request

- **Description**: SMF DL-data trigger → AMF N1N2MessageTransfer → NGAP Paging of a CM-IDLE UE.
- **3GPP spec**: TS 23.502 §4.2.3.3; NGAP Paging TS 38.413 §9.2.8. `docs/procedures/network-triggered-service-request.md`.
- **How to trigger**: force CM-IDLE via `nr-cli ... ue-release`, then SMF `dl-data-notification` (see root CLAUDE.md).
- **Expected**: AMF `NGAP Paging sent`; gNB `Paging received`.
- **Limitations**: real UPF PFCP Downlink Data Report is UPF-001 (simulated by SMF); UERANSIM UE
  still does not respond to paging — two of its blockers were removed in Jul 2026 (missing TAI
  list made the UE cancel the paging-triggered Service Request; stock gNB dropped SR initial
  messages, fixed by patch 0051), but the UE silently ignores the RRC page (suspected 5G-S-TMSI
  matching in `NasMm::handlePaging`; gNB confirms `Paging received` and relays to RRC).

### 3.13b Service Request with User-Plane Re-activation (UE-triggered)

- **Description**: a CM-IDLE UE with pending uplink data sends a Service Request; the AMF
  re-activates the flagged PDU sessions per spec: SMF `Nsmf_PDUSession_UpdateSMContext`
  (`upCnxState=ACTIVATING`) → N2SM info in the InitialContextSetupRequest
  (`PDUSessionResourceSetupListCxtReq`) → gNB CxtRes DL tunnel forwarded to SMF → PFCP FAR
  update. Requires the registration area (TAI list, IEI 0x54) in Registration Accept —
  without it the UE cancels the SR ("current TAI is not in the TAI list").
- **3GPP spec**: TS 23.502 §4.2.3.2 (steps 4/12), TS 24.501 §9.11.3.9 / §4.4.6, TS 38.413
  §9.2.2.1/§9.2.2.2. `docs/procedures/service-request.md`.
- **NFs involved**: AMF, SMF, UPF (via existing SMF PFCP modification), gNB, UE.
- **How to trigger**: `docs/validation-commands.md` §7 — force CM-IDLE via gNB `ue-release`,
  then `ping -I uesimtun0` from the UE.
- **Expected outcome**: AMF `pdu_sessions_cxt_req=1` on the ICS Request and
  `PDU session re-activated by gNB (ICS Response)`; SMF `UP re-activation` +
  `PFCP SessionModification`; ping resumes with only the first packet lost (SR latency).
- **Known limitations**: sessions the SMF fails to activate are skipped (UE may re-establish
  them itself); the SR's NAS message container (0x71) is decoded as plaintext — correct under
  the dev NEA0 null-ciphering profile. Requires UERANSIM patch `0051-gnb-amf-selection-no-nssai.patch`
  (stock v3.2.8 gNB drops initial NAS messages that carry no Requested NSSAI, so Service
  Request never reached the AMF).

### 3.14 DNN Subnet Isolation

- **Description**: Per-DNN isolated UE IP pools + dedicated N6 Docker networks + per-DNN TUN.
- **3GPP spec**: TS 23.501 §5.6.5.
- **Config**: `config/operator.yaml` `dnns:` (single source of truth) refined by SMF/UPF `dev.yaml`.
- **Expected**: SMF selects pool per `dnn`; UPF uses matching TUN (`upfgtp0` internet, `upfgtp1` ims).

### 3.15 Observability (cross-cutting)

See Section 6. Metrics (`fivegc_*`), Jaeger traces per procedure, Grafana dashboards.

### 3.16 SMS over NAS (SMSF)

- **Description**: SMS delivery over the NAS interface, anchored by the new **SMSF** NF.
  The AMF is a transparent relay: a UL NAS Transport with Payload Container Type = SMS
  (`0x02`) is forwarded opaquely to the SMSF via `Nsmsf_SMService_UplinkSMS`; MT SMS is
  delivered back through `Namf_Communication_N1N2MessageTransfer` → DL NAS Transport
  (PCT=0x02). A built-in **loopback / echo DTE** in the SMSF reflects every MO SMS back to
  the originating UE as an MT SMS, proving the full MO + MT round-trip without a real SMSC.
- **3GPP spec**: TS 23.501 §5.20, TS 23.502 §4.13, **TS 29.540** (Nsmsf_SMService),
  TS 29.518 §5.2.2.3 (N1N2MessageTransfer), TS 24.501 §8.2.10/§8.2.11 (PCT=SMS 0x02),
  TS 29.503 §5.3.2 (UDM UECM). `docs/procedures/sms-over-nas.md`.
- **NFs involved**: SMSF (new, port 8009 / metrics 9110), AMF, NRF (registration/discovery),
  UDM (UECM `smsf-3gpp-access`).
- **How to trigger** (stack running, `make up-obs`):
  ```bash
  SUPI=imsi-001010000000001
  CB="https://amf:8001/namf-comm/v1/ue-contexts/$SUPI/n1-n2-messages"
  # 1) Activate an SMS context
  docker exec amf curl -sk --http2-prior-knowledge \
    --cert /etc/5gc/pki/amf.crt --key /etc/5gc/pki/amf.key --cacert /etc/5gc/pki/ca.crt \
    -X POST https://smsf:8009/nsmsf-sms/v2/ue-contexts/$SUPI \
    -H 'Content-Type: application/json' \
    -d "{\"supi\":\"$SUPI\",\"accessType\":\"3GPP_ACCESS\",\"amfId\":\"amf-001\",\"amfCallbackUri\":\"$CB\"}"
  # 2) Submit an MO SMS → loopback DTE echoes it back as MT
  docker exec amf curl -sk --http2-prior-knowledge \
    --cert /etc/5gc/pki/amf.crt --key /etc/5gc/pki/amf.key --cacert /etc/5gc/pki/ca.crt \
    -X POST https://smsf:8009/nsmsf-sms/v2/ue-contexts/$SUPI/sendsms \
    -H 'Content-Type: application/json' \
    -d '{"smsRecordId":"rec-mo-001","smsPayload":"AQIDBA=="}'
  docker logs smsf | grep SmsOverNas        # UplinkSMS OK + echoMTSMS delivered
  docker logs amf  | grep "MT SMS"          # N1N2MessageTransfer received from SMSF
  ```
- **Expected outcome**: SMSF logs `SMS context activated`, `UplinkSMS: MO SMS received`,
  `echoMTSMS: MT SMS delivered via AMF` (result=OK); the AMF's `namf-comm` server receives
  the N1N2MessageTransfer with `n1MessageClass=SMS`, `payloadContainerType=2`.
- **Validation (no stack needed)**:
  ```bash
  go test ./nf/smsf/...                       # 11 unit tests
  go test -tags=functional ./nf/smsf/tests/...  # 7 BDD scenarios
  ```
- **Known limitations**: **UERANSIM v3.2.8 has no SMS-over-NAS UE support** — it cannot
  originate a UL NAS Transport SMS container nor process an MT DL NAS Transport, so the live
  N1 UE leg is out of scope (same posture as URSP / NSSAA / EAP-AKA'). The network-side state
  machine, NAS PCT=0x02 encoding, and the Nsmsf + Namf SBI round-trip are validated in-process.
  AMF-initiated SMS Management Activation at registration (vs. the manual Activate above) and
  real SMS-GMSC/SMS-IWMSC forwarding are follow-ups (SMSF-002+).

### 3.17 Binding Support Function (BSF) — Nbsf_Management

- **Description**: New **BSF** NF that serves as the 5GC registry of PCF-for-a-PDU-session
  bindings. When the PCF creates an SM policy association it registers a binding
  `(UE IP, DNN, S-NSSAI) → serving PCF` with the BSF; on deletion it deregisters. Consumers
  (typically NEF/AF) query the BSF with the UE IP to discover the serving PCF — the
  prerequisite for AF session with required QoS (NEF-001). The BSF is SBA-only: no N1/N2/N4
  path is touched.
- **3GPP spec**: TS 23.501 §6.2.16 (BSF description), **TS 29.521 §5** (Nbsf_Management —
  Register / Deregister / Discovery), TS 29.521 §6.2.6 (PcfBinding data type),
  TS 29.510 §6.1.6.2.2 (NRF registration, NFType BSF). `docs/procedures/binding-support.md`.
- **NFs involved**: BSF (new, SBI port **8010** / metrics **9111**), NRF (registration).
- **How to trigger** (stack running — docker-compose wiring is a follow-up):
  ```bash
  # Register a PCF binding (PCF-side, TS 29.521 §5.2.2.2):
  curl -sk -X POST https://bsf:8010/nbsf-management/v1/pcfBindings \
    -H 'Content-Type: application/json' \
    -d '{"supi":"imsi-001010000000001","ipv4Addr":"10.60.0.1","dnn":"internet",
         "snssai":{"sst":1,"sd":"000001"},
         "pcfFqdn":"pcf.5gc.mnc001.mcc001.3gppnetwork.org","pcfId":"pcf-instance-001"}'
  # → 201 Created + Location: …/pcfBindings/{bindingId} + PcfBinding body

  # Discover serving PCF by UE IP (consumer-side, TS 29.521 §5.2.2.4):
  curl -sk "https://bsf:8010/nbsf-management/v1/pcfBindings?ipv4Addr=10.60.0.1"
  # → 200 OK PcfBinding{pcfFqdn, pcfId, …}

  # Deregister (PCF teardown, TS 29.521 §5.2.2.3):
  curl -sk -X DELETE "https://bsf:8010/nbsf-management/v1/pcfBindings/{bindingId}"
  # → 204 No Content
  ```
- **Expected outcome**: BSF logs `register: PCF binding created` (result=OK), bindingId in
  Location header; `discover: binding found` (result=OK) with pcfFqdn + pcfId; `deregister:
  PCF binding removed` (result=OK); 403 `EXISTING_BINDING_INFO_FOUND` on duplicate;
  400 `MANDATORY_IE_MISSING` on missing dnn/snssai/IP key or empty GET query.
- **Validation (no stack needed)**:
  ```bash
  go test -race ./nf/bsf/...    # 14 unit tests (Register/Deregister/Discovery/errors)
  ```
- **Known limitations**:
  - **docker-compose wiring** (service + PCAP sidecar) and **PKI cert generation**
    (`pki/bsf.crt`, `pki/bsf.key`) are follow-up orchestrator tasks (BSF-004).
  - **PCF client integration** — registering/deregistering from the PCF SM policy lifecycle
    (`nf/pcf/`) is a separate pass (BSF-002) to maintain scope isolation.
  - **PostgreSQL persistence** — in-memory only for this increment; BSF-003 adds the
    `pcf_binding` table and Redis O(1) discovery cache.
  - **NEF-001** — the Discovery route is built and tested; NEF-001 consumes it unchanged.

### 3.18 PCF Policy Authorization — Npcf_PolicyAuthorization thin endpoint (NEF-001 AC2)

- **Description**: The PCF gains two new `npcf-policyauthorization` endpoints that allow the
  NEF to map an AF `AsSessionWithQoS` Create/Delete request onto a PCF policy operation.
  On Create the PCF mints an `appSessionId`, stores the `AppSessionContext` in-memory, logs
  the authorized `qosReference`, and returns `201 Created` with a `Location` header and the
  `appSessionId` in the JSON body. On Delete the PCF removes the session and returns `204`.
  Full UE-IP→SUPI resolution and DNN-scoped SM-policy binding are deferred (baseline scope).
- **3GPP spec**: **TS 29.514 §5.2.2.2** (Create), **§5.2.2.4** (Delete), **§5.6.2.3**
  (AppSessionContextReqData data type). `docs/procedures/network-exposure.md`.
- **NFs involved**: PCF (additive — new routes on existing SBI server, port **8006**).
- **How to trigger** (requires PCF running):
  ```bash
  # Create an app-session (NEF-side call, TS 29.514 §5.2.2.2):
  APP_SESSION=$(curl -sk --cert pki/pcf.crt --key pki/pcf.key --cacert pki/ca.crt \
    -X POST https://pcf:8006/npcf-policyauthorization/v1/app-sessions \
    -H 'Content-Type: application/json' \
    -d '{"ascReqData":{"aspId":"af-test","ueIpv4":"10.60.0.1",
         "qosReference":"qos-gold","dnn":"internet"}}' \
    -D - | grep -i location | awk -F/ '{print $NF}' | tr -d '\r')
  echo "appSessionId: $APP_SESSION"
  docker logs pcf | grep "app-session created"

  # Delete the app-session (TS 29.514 §5.2.2.4):
  curl -sk --cert pki/pcf.crt --key pki/pcf.key --cacert pki/ca.crt \
    -X DELETE "https://pcf:8006/npcf-policyauthorization/v1/app-sessions/$APP_SESSION"
  docker logs pcf | grep "app-session deleted"
  ```
- **Expected outcome**: PCF logs `procedure=PolicyAuthorizationCreate result=OK` with
  `app_session_id`, `ue_ipv4`, `qos_reference`; `201 Created` + `Location` header on create;
  `204 No Content` on delete; `400 MANDATORY_IE_MISSING` if `ascReqData` or UE address
  absent; `400 MANDATORY_IE_INCORRECT` on malformed JSON; `404 APP_SESSION_NOT_FOUND` on
  delete of unknown session.
- **Validation (no stack needed)**:
  ```bash
  go test -race ./nf/pcf/internal/server/... -run "TestCreateAppSession|TestDeleteAppSession"
  # 8 new unit tests (happy path, IPv6-only, dual-session, no-ascReqData,
  #   no-UE-address, malformed JSON, delete-not-found, create-then-delete)
  ```
- **Known limitations**:
  - **UE-IP→SUPI resolution**: the PCF receives only the UE IP from the NEF (the BSF binding
    carries the SUPI but the PCF does not query the BSF here). A precise DNN-scoped
    `smPolicyOverride` binding is therefore deferred. The authorized `qosReference` is stored
    and logged; a future increment will wire in the BSF/UDR lookup to apply the override.
  - **Full TS 29.514 lifecycle** (Update / Subscribe / Notify / Patch on app-sessions) is out
    of scope for the baseline increment.

### 3.19 Network Exposure Function (NEF) — Nnef_AFsessionWithQoS (NEF-001)

- **Description**: New **NEF** NF — the 5GC's secure northbound gateway between the trusted
  core and external **Application Functions (AFs)**. It exposes one baseline northbound API,
  **AsSessionWithQoS** (`Nnef_AFsessionWithQoS`): an AF requests a guaranteed QoS for an
  application flow toward a UE by supplying the **UE IP** + a `qosReference`. The AF does not
  know which PCF serves that UE; the NEF resolves it by calling **BSF Discovery**
  (`GET /nbsf-management/v1/pcfBindings?ipv4Addr=`, the §3.17 BSF) to find the serving PCF,
  then maps the request onto that PCF's **Npcf_PolicyAuthorization** Create (the §3.18 thin
  endpoint). The northbound API is **OAuth2-protected** (bearer token, scope
  `nnef-afsessionwithqos`) on top of the always-on SBA mTLS. The NEF is SBA-only: no
  N1/N2/N4 path. There is no AF in UERANSIM, so this is validated in-process (mock BSF + PCF),
  not live — the same posture as the BSF/SMSF baselines.
- **3GPP spec**: TS 23.501 §6.2.5 (NEF description), **TS 29.522 §4.4.13** (Nnef_AFsessionWithQoS
  Stage 3) + §5.14.2.1.2 (AsSessionWithQoSSubscription) + §6 (OAuth2), TS 29.521 §5.2.2.4
  (BSF Discovery consumption), TS 29.514 §5.2.2.2 (PCF leg), TS 29.510 §6.1.6.2.2 (NRF
  registration, NFType NEF). `docs/procedures/network-exposure.md`.
- **NFs involved**: NEF (new, SBI port **8011** / metrics **9112**), BSF (Discovery),
  PCF (Npcf_PolicyAuthorization), NRF (registration).
- **How to trigger** (in-process; docker-compose wiring deferred — NEF-005):
  ```bash
  # The northbound flow needs an OAuth2 bearer token (scope nnef-afsessionwithqos)
  # and a registered PCF binding in the BSF for the UE IP. Exercised end-to-end by the
  # 12-scenario BDD suite (mock BSF + recording PCF client):
  go test -tags=functional ./nf/nef/tests/features/...   # 12 scenarios / 124 steps

  # Unit tests (NEF server + PCF leg, no stack needed):
  go test ./nf/nef/internal/server/...
  go test ./nf/pcf/internal/server/... -run "TestCreateAppSession|TestDeleteAppSession"
  ```
- **Expected outcome**: NEF logs `procedure=AsSessionWithQoSCreate result=OK` with `scs_as_id`,
  `ue_ipv4`, `qos_reference`, `pcf_id`, `app_session_id`; `201 Created` + `Location:
  …/subscriptions/{subscriptionId}` on create; `200` on get; `204` on delete (relays PCF
  app-session delete). Errors: `401 UNAUTHORIZED` (no/invalid token), `403 UNAUTHORIZED_AF`
  (wrong scope, or PCF rejects authorization), `400 MANDATORY_IE_MISSING` (no UE addr / no
  `qosReference`), `404 PCF_BINDING_NOT_FOUND` (no BSF binding for the UE IP). Metrics:
  `fivegc_procedure_total{nf="NEF",procedure="AsSessionWithQoS…",result=…}` +
  `fivegc_nef_subscriptions_active`; Grafana **"NEF — Network Exposure Function"** row.
- **Known limitations**:
  - **No live AF / docker-compose wiring** (NEF-005): the NEF is not yet a compose service and
    has no PKI cert; validated in-process only.
  - **BSF Discovery 404 mapping** (B-1): TS 29.521 §5.2.2.4 strictly returns 200 with a
    `PcfBinding` array; the BSF here returns 404 on a miss and the NEF surfaces `404
    PCF_BINDING_NOT_FOUND` (the exact Rel-17 cause string is unverified).
  - **Authorized QoS not yet applied to the UE**: the PCF leg stores/logs the `qosReference`
    but does not bind it to an SM-policy override (see §3.18 limitation).
  - **No QoS Notification Control** callbacks to the AF (NEF-002); single `flowInfo`/`DATA`
    media component only.

### 3.20 Location Management Function (LMF) — Nlmf_Location DetermineLocation (LMF-001, LMF-002)

- **Description**: The **LMF** NF implements **Cell-ID positioning** + **Deferred MT Location**
  (paging-then-locate for CM-IDLE UEs) + **Location Privacy** (UDM lcsData check). The LMF is
  core-only: it never has a direct N2 to the gNB and reaches the RAN exclusively through the
  **AMF as an NGAP relay**. Flow: an LCS consumer POSTs a **DetermineLocation** request to the
  LMF; the LMF first checks UDM location privacy (`/nudm-sdm/v2/{supi}/lcs-privacy-data`); if
  allowed, calls the AMF's **Namf_Location** producer; the AMF handles CM-IDLE by paging the UE
  (NGAP Paging ProcCode=24, T-positioning 15 s guard) before sending
  **NGAP LocationReportingControl** (ProcCode=16) and correlating the **LocationReport** (ProcCode=18).
- **3GPP spec**: TS 23.273 §6/§7.2 (LMF architecture + positioning), **§7.2 steps E2–E7**
  (Deferred MT Location / paging sub-flow), **§9.1** (Location Privacy), **TS 29.572 §5.2.2.2**
  (Nlmf_Location DetermineLocation), TS 29.518 §5.2.2.6 (Namf_Location AMF producer),
  **TS 38.413 §8.17.1** (NGAP LocationReportingControl ProcCode=16 / LocationReport ProcCode=18),
  **TS 29.503 §5.2.2** (Nudm_SDM lcsData). `docs/procedures/DetermineLocation.md`.
- **NFs involved**: LMF (SBI port **8012** / metrics **9113**), AMF (Namf_Location producer +
  NGAP relay + paging), UDM (lcsData endpoint), NRF (registration), gNB (RAN).
- **How to trigger** (live, full stack):
  ```bash
  make ueransim                       # core (incl. lmf) + obs + gNB + 1 UE
  SUPI=imsi-001010000000001
  curl -sk --cert pki/smf.crt --key pki/smf.key --cacert pki/ca.crt \
    -X POST "https://localhost:8012/nlmf-loc/v1/ue-contexts/$SUPI/provide-loc-info" \
    -H 'Content-Type: application/json' \
    -d "{\"supi\":\"$SUPI\",\"req5gsLoc\":true,\"reqCurrentLoc\":true,\"supportedGADShapes\":[\"POINT\"]}"
  docker logs amf | grep "NGAP LocationReportingControl sent"   # ProcCode=16 emitted to gNB
  docker logs lmf | grep DetermineLocation
  docker logs udm | grep GetLcsPrivacyData   # privacy check log
  # Paging-then-locate (force CM-IDLE first):
  GNB=UERANSIM-gnb-1-1-1
  UEID=$(docker exec ueransim-gnb nr-cli $GNB --exec "ue-list" | grep -oE 'ue-id: [0-9]+' | head -1 | grep -oE '[0-9]+')
  docker exec ueransim-gnb nr-cli $GNB --exec "ue-release $UEID"   # → CM-IDLE
  curl -sk ... POST .../provide-loc-info ...   # LMF pages → UE reconnects → locate succeeds
  # Unit + functional (no stack):
  go test ./nf/lmf/... ./nf/amf/internal/ngap/... ./nf/amf/internal/sbi/...
  go test -tags=functional ./nf/lmf/tests/...                   # 8 scenarios
  ```
- **Expected outcome**: LMF logs `procedure=DetermineLocation` with `interface=Nlmf` (IN),
  `Namf`/`N2` (OUT), `result`, `cause`, `duration_ms`. UDM logs `GetLcsPrivacyData` per request.
  On CM-IDLE + paging success: AMF logs `paged UE reconnected` then proceeds to locate. On
  BLOCK_ALL: `403 PRIVACY_EXCEPTION_DENIED`. Metrics:
  `fivegc_lmf_locate_total{result="OK"|"REJECT"|"FAILURE"}` on :9113.
- **Known limitations**:
  - LPP/NRPPa relay (OTDOA/GNSS): deferred (only E-CID subset implemented — see §3.20.3).
  - Location privacy: only `ALLOW_ALL` vs `BLOCK_ALL` enforced; `lcsPrivacyExceptionList` (per-service-class) not yet evaluated.
  - UDM lcsData: dev endpoint always returns `ALLOW_ALL`; no database-backed subscriber policy.

### 3.20.1 Live Cell-ID E2E + UE Location map (LMF-006)

- **Description**: completes the **live** positioning flow and adds monitoring on top of LMF-001.
  - **UERANSIM gNB patch** `tools/ueransim/patches/0040-location-reporting.patch`: stock v3.2.8 gNB
    has no `LocationReportingControl` handler (it logs *"Unhandled NGAP initiating-message"* and
    never replies). The patch adds `receiveLocationReportingControl()`, which answers with a
    **LocationReport** carrying the serving NR-CGI + TAI (TS 38.413 §8.17). Rebuild:
    `make ueransim-build-only`.
  - **LMF mobility model** (`nf/lmf/internal/server/mobility.go`): cell-ID positioning carries no
    lat/lon on the wire, so the LMF synthesizes coordinates — a deterministic, bounded, per-SUPI
    walk anchored at the serving cell's configured base coordinate. Artificial values, realistic
    moving behavior; horizontal accuracy reported in `locationEstimate.uncertainty` (m). The
    authoritative output remains the serving cell. Configured in `nf/lmf/config/dev.yaml`
    (`cell_coordinates`, `default_coordinate`, `mobility.{enabled,radius_m,speed_mps}`).
  - **Portal "UE Location" page**: live Leaflet map (auto-poll 3 s) + table, backed by
    `GET /api/v1/location/summary` and `/location/ue/{supi}` (LCS-client proxy to the LMF over
    mTLS). CM-IDLE/unreachable UEs are listed with their 3GPP cause.
- **How to trigger**:
  ```bash
  make ueransim
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4 --dnn internet"
  bash scripts/validate-ueransim-mod.sh location   # NRCGI + moving-coordinate assertions
  docker logs ueransim-gnb | grep "Location Report sent"
  make portal   # → http://localhost:8080/location  (moving markers)
  ```
- **Expected outcome**: `200` LocationData with the serving `nrCellId`/`tai` and a **non-zero,
  moving** `lat/lon`; gNB logs `Location Report sent`; two polls a few seconds apart return
  different coordinates. Unit: `nf/lmf/internal/server/mobility_test.go`.
- **Known limitations**: only `EventType=Direct` (single report) is honored on the gNB; periodic /
  change-of-cell reporting is logged-and-single-shot. OSM map tiles need outbound internet.

### 3.20.2 Nlmf_Location EventSubscription + CancelLocation (LMF-003)

- **Description**: Adds a **subscription model** to the LMF so callers receive ongoing location
  updates instead of repeated one-shot queries. Two event-trigger types:
  - **PERIODIC_REPORTING**: LMF re-runs DetermineLocation at `reportingInterval` (default 10 s)
    and POSTs each result to the subscriber's `notificationUri` as a `LocationNotification` body
    (TS 29.572 §6.1.6.2.4).
  - **AREA_OF_INTEREST**: LMF samples every `samplingInterval` (default 5 s) and fires a
    notification **only on polygon enter/exit** (ray-casting state machine: UNKNOWN → IN/OUT).
    No spurious notifications while the UE is stationary.
  - **CancelLocation** (one-shot cancel): `POST /nlmf-loc/v1/ue-contexts/{id}/cancel-loc` aborts
    an in-progress DetermineLocation via a `context.CancelFunc` stored in a `sync.Map`.
  - **Subscription lifetime**: each subscription drives one goroutine; DELETE or duration expiry
    stops it. In-memory registry (`sync.RWMutex`); Redis persistence deferred.
- **3GPP spec**: TS 29.572 §5.2.3 (EventSubscription Create/Get/Delete), §5.2.2.5 (CancelLocation),
  §6.1.6.2.4 (LocationNotification body), TS 23.273 §7.2 step B2. `docs/procedures/EventSubscription.md`.
- **NFs involved**: LMF (SBI port **8012**)
- **How to trigger**:
  ```bash
  make ueransim   # LMF and gNB patch in place (LMF-006 prerequisite)

  # Create a periodic subscription (notify every 5 s):
  curl -sk --cert pki/amf.crt --key pki/amf.key --cacert pki/ca.crt \
    -X POST https://localhost:8012/nlmf-loc/v1/subscriptions \
    -H 'Content-Type: application/json' \
    -d '{"ueContextId":"imsi-001010000000001","supi":"imsi-001010000000001",
         "eventTrigger":"PERIODIC_REPORTING","reportingInterval":5,
         "notificationUri":"http://MY-SINK:9100/notify"}' -v
  # → 201 Created + Location: /nlmf-loc/v1/subscriptions/<subId>

  # List (GET) a subscription:
  curl -sk --cert pki/amf.crt --key pki/amf.key --cacert pki/ca.crt \
    https://localhost:8012/nlmf-loc/v1/subscriptions/<subId>

  # Cancel:
  curl -sk --cert pki/amf.crt --key pki/amf.key --cacert pki/ca.crt \
    -X DELETE https://localhost:8012/nlmf-loc/v1/subscriptions/<subId>

  # Unit + BDD tests (no stack needed):
  go test ./nf/lmf/internal/server/...              # 831-line subscription unit tests
  go test -tags=functional ./nf/lmf/tests/features/ # 20 scenarios (13 s)
  ```
- **Expected outcome**: `201` on create with `Location` header; periodic subscription fires
  `LocationNotification` at the configured interval; AOI subscription fires exactly once per
  boundary crossing. `DELETE` stops goroutine and returns `204`. Metrics: `fivegc_lmf_subscription_create_total{result}`, `fivegc_lmf_subscriptions_active`.
- **Known limitations**: notification delivery retries once on 5xx (no exponential backoff); no
  Redis persistence (in-memory only; subscriptions lost on LMF restart). eventTrigger/AOI enum
  tokens are LMF-internal — not yet reconciled with the canonical TS 29.572 §6.1.6.3
  `LocationEventType`/`AreaEventType` names from the 3GPP YAML (see §Conformance Notes in
  `docs/procedures/EventSubscription.md`).

### 3.20.3 NRPPa Relay — E-CID Positioning (LMF-004)

- **LMF side (PASS 2)**: `nf/lmf/internal/server/ecid.go` adds quality-driven method
  selection on the DetermineLocation request `lcsQoS.hAccuracy` (TS 23.273 §6.2.9 /
  TS 29.572): `>200 m` or absent → Cell-ID (LMF-001 path); `50–200 m` → E-CID; `<50 m` →
  LPP/GNSS desired (LMF-005, MVP downgrades to E-CID). `performECIDOrFallback` runs two
  synchronous NRPPa rounds via the AMF `SendDLNRPPa` client (`amf_client.go`): a capability
  query (`PositioningInformationRequest` → `Response.ECIDSupported`) then a measurement round
  (`E-CIDMeasurementInitiationRequest` → `E-CIDMeasurementReport`). Position comes from the
  gNB-reported **`NG-RANAccessPointPosition`** (TS 38.455 §9, a real optional IE — TS 38.455's
  `measuredResults` is E-UTRA-only and cannot carry NR neighbour RSRP, so the E-CID position
  is the gNB's own WGS84 estimate, not a computed centroid), clamps uncertainty `≤150 m` (or
  `300 m` falling back to the serving-cell anchor when the gNB reports no AP position), and
  tags `positioningDataList=["eCID"]`. Any NRPPa failure
  (capability NONE, error, or timeout) transparently **falls back to Cell-ID — never a 5xx**.
  The UDM privacy gate (BLOCK_ALL → 403 PRIVACY_EXCEPTION_DENIED) runs **before** any NRPPa.
  Metric `fivegc_lmf_ecid_total{result=OK|FALLBACK_CELLID|FAILURE}`; 5 godog scenarios
  (25/25 LMF functional pass). **Live gNB leg (UERANSIM patch 0041) deferred to LMF-008** —
  stock UERANSIM v3.2.8 has no NRPPa-Transport handler (same posture as LMF-001/LMF-006).
- **Description (PASS 1)**: Implements the **AMF side** of the NRPPa relay for E-CID positioning.
  The AMF is a **pure relay** — it does NOT decode NRPPa-PDU content (TS 38.413 §8.17.3 note).
  Additions in this pass:
  - **`shared/nrppa/` codec package** — real ASN.1 Aligned PER (APER) codec for the E-CID
    subset of NRPPa (TS 38.455 §8): PositioningInformationRequest/Response/Failure
    (ProcedureCode=9), E-CIDMeasurementInitiation{Request/Response/Failure} (ProcedureCode=2),
    E-CIDMeasurementReport (ProcedureCode=4; serving cell + optional gNB-reported
    `NG-RANAccessPointPosition`). Encoded via `github.com/free5gc/aper` Marshal/Unmarshal on
    hand-written structs mirroring the TS 38.455 ASN.1 module (`nrppa_asn1.go`) — free5gc ships
    no NRPPa module of its own, unlike NGAP. Rewritten 2026-07-01 from an earlier
    non-conformant hand-rolled TLV format that also used the wrong ProcedureCodes (12/6/8,
    colliding with real unrelated TS 38.455 procedures); see
    `docs/procedures/NRPPaRelay.md` §"NRPPa fix — real APER + correct procCodes".
  - **NGAP NRPPa Transport codec** in `nf/amf/internal/ngap/codec.go`:
    - `BuildDownlinkUEAssociatedNRPPaTransport` (ProcCode=8, AMF→gNB)
    - `BuildDownlinkNonUEAssociatedNRPPaTransport` (ProcCode=5, AMF→gNB)
    - `extractUplinkUEAssociatedNRPPaTransport` (ProcCode=50, gNB→AMF)
    - `extractUplinkNonUEAssociatedNRPPaTransport` (ProcCode=47, gNB→AMF)
    - 4 new `ProcedureCode` constants (5, 8, 47, 50) + dispatch cases in `dispatch()`.
  - **AMF NGAP server** (`nf/amf/internal/ngap/ngap.go`):
    - `NRPPaResult` struct; `pendingNRPPa sync.Map` (keyed by AMF-UE-NGAP-ID)
    - `SendDownlinkNRPPa` — inserts pending channel + writes DL NGAP PDU
    - `handleUplinkUEAssociatedNRPPa` — resolves pending channel; orphan → `nrppa_orphan` warn
    - `handleUplinkNonUEAssociatedNRPPa` — logs and drops (non-UE relay is pass 2)
  - **AMF SBI server** (`nf/amf/internal/sbi/`):
    - `NRPPaRelay` interface; `SetNRPPaRelay(r NRPPaRelay)` wiring method
    - `handleDLNRPPaInfo` — `POST /namf-loc/v1/ue-contexts/{id}/dl-nrppa-info`
      Synchronous blocking model (mirrors `handleProvideLocInfo`): relays DL NRPPa to gNB,
      blocks until UL NRPPa arrives on pendingNRPPa channel (or 10 s timeout → 504).
      Requires UE CM-CONNECTED (no paging fallback for NRPPa).
    - New SBI types: `DLNRPPaInfoReq`, `DLNRPPaInfoRsp`, `CauseNRPPaRelayFailure`
  - **Metric**: `fivegc_amf_nrppa_transport_total{direction="UL|DL",assoc="UE|NON_UE"}`
    in `shared/observability/metrics/metrics.go`.
  - **Wiring**: `sbiSrv.SetNRPPaRelay(ngapSrv)` in `nf/amf/cmd/amf/main.go`.
- **3GPP spec**: TS 38.413 §8.17.3/§8.17.4 (NGAP NRPPa Transport); TS 38.455 §8 (NRPPa
  procedures); TS 23.273 §7.2 step C; TS 29.518 §5.2.2.6 (Namf_Location extension).
  `docs/procedures/NRPPaRelay.md`.
- **NFs involved**: AMF (relay, this pass), LMF (pass 2), gNB / UERANSIM gNB patch (pass 2).
- **How to trigger** (unit tests only — pass 2 wires the LMF side):
  ```bash
  GOWORK=off go test ./shared/nrppa/...               # codec round-trip, RSRP fidelity
  GOWORK=off go test ./nf/amf/internal/ngap/... -run NRPPa   # NGAP codec + dispatch
  GOWORK=off go test ./nf/amf/internal/sbi/...  -run NRPPa   # SBI handler 200/404/400/504/503
  ```
- **Expected outcome**: all tests green. `fivegc_amf_nrppa_transport_total` counter increments
  on DL send and UL receive.
- **Known limitations**: LMF side is now wired (PASS 2 above); the UE-associated E-CID path is
  complete in-process. Non-UE-associated relay (ProcCode 5/47) is decoded and logged but not yet
  forwarded to the LMF (cell-level positioning, future). UERANSIM v3.2.8 has no NRPPa handler so
  the live E-CID leg is deferred to LMF-008 (gNB patch 0041). `fivegc_lmf_ecid_total{FAILURE}`
  is defined but not incremented (downstream Cell-ID failure is counted by
  `fivegc_lmf_locate_total{FAILURE}`). LMF has no OTel spans yet (only core NF missing traces).

### 3.20.4 Live GNSS E2E — A-GNSS via LPP (LMF-005 core + LMF-009 live)

- **Description**: UE-assisted A-GNSS positioning over LPP (TS 37.355), carried on N1 NAS with
  the AMF as a transparent relay. LMF-005 built the core (`shared/lpp` codec, AMF relay, LMF
  state machine + WLS solver); **LMF-009** made it work end-to-end against a real UE by (a)
  rewriting `shared/lpp` from `free5gc/aper` **ALIGNED PER** to a hand-rolled X.691 **BASIC-PER
  UNALIGNED** codec (`shared/lpp/uper.go`) with real TS 37.355 messages — resolving the
  aligned-vs-unaligned deviation the LMF-005 notes flagged — and (b) adding UERANSIM UE patch
  `tools/ueransim/patches/0042-lpp-gnss.patch`, an LPP responder for payload container type 3.
- **3GPP spec**: TS 37.355 §4 (UNALIGNED PER)/§5.2/§6, TS 24.501 §8.7.4/§9.11.3.40 (payload
  container type 3), TS 38.413 §8.6.2/§8.6.3 (DL/UL NAS Transport), TS 23.273 §6.2.10.
- **NFs involved**: LMF (drives 3 LPP legs + WLS fix), AMF (transparent N1 relay), gNB (opaque
  N2 relay), UE (patched UERANSIM LPP responder).
- **Wire flow (3 legs)**: Leg1 `RequestCapabilities`→`ProvideCapabilities` (sync); Leg2
  `ProvideAssistanceData` (DL-only, unsolicited — AMF `expectUlResponse=false` → 204, no
  waiter); Leg3 `RequestLocationInformation`→`ProvideLocationInformation` (sync). LPP
  transaction echo verified per TS 37.355 §5.2 (TransactionNumber 0..255, initiator=
  locationServer, UE echoes). The UE derives its synthetic GNSS measurements deterministically
  from the wire-quantized reference location (quantized-anchor rule) so the LMF's Gauss-Newton
  WLS converges to a fix near the anchor.
- **How to trigger**:
  ```bash
  make ueransim                        # LPP-patched UE (patch 0042)
  bash scripts/validate-ueransim-mod.sh gnss
  # Or directly:
  SUPI=imsi-001010000000001
  curl -sk --http2 --cert pki/smf.crt --key pki/smf.key --cacert pki/ca.crt \
    -X POST https://localhost:8012/nlmf-loc/v1/ue-contexts/$SUPI/provide-loc-info \
    -H 'Content-Type: application/json' \
    -d "{\"supi\":\"$SUPI\",\"locationQoS\":{\"hAccuracy\":30}}"
  ```
- **Expected outcome**: 200 with `positioningDataList:["gnss"]`, uncertainty ≤ 50 m (typically
  5 m). UE logs `LPP RequestCapabilities received -> ProvideCapabilities (GNSS supported)`,
  `LPP ProvideAssistanceData received`, `LPP RequestLocationInformation received ->
  ProvideLocationInformation (4 satellites)`; AMF logs `DownlinkLPP sent` + `UplinkLPP
  received` + the DL-only 204 leg; LMF logs `GNSS position calculated` (`lpp_state:FIXED`).
  Metrics `fivegc_lmf_gnss_total{OK}` + `fivegc_amf_lpp_transport_total{DL,UL}`.
- **Negative mode**: recreate the UE with env `LPP_GNSS_NONE=1` → UE reports GNSS unsupported →
  LMF logs `GNSS capability=NONE from UE` → falls back to E-CID (200, `["eCID"]`, no 5xx).
- **PER conformance**: `shared/lpp` UNALIGNED-PER output is validated byte-correct by the real
  Wireshark 4.6.4 LPP dissector — both in the `TestTsharkOracle_AllGoldenPDUs` unit test (7
  golden PDUs, zero malformed) and in a live N2 capture where tshark decoded the three DL legs
  as valid LPP with zero malformed frames (SCTP PPID 60). The two UL legs are NEA2-ciphered on
  the live link (correct per TS 33.501); their wire-correctness is proven by the golden oracle.
- **Known limitations**: A-GNSS (GPS, UE-assisted) subset only — OTDOA/DL-TDOA/DL-AoD/
  NR-multi-RTT out of scope. The synthetic constellation + pseudoranges are deterministic
  simulation values (no real GNSS receiver). `positioningDataList` uses the LMF-internal
  lowercase `"gnss"` label rather than TS 29.572's `PositioningMethodAndUsage`/
  `gnssPositioningDataList` object shape (reconcile before external LCS interop).

---

## 4. UERANSIM Integration

UERANSIM **v3.2.8** built from source via `tools/ueransim/Dockerfile`. Configs in `config/ueransim/`.

### Register a UE
```bash
make ueransim [UE_COUNT=N]          # core + obs + gNB + N UEs (auto-registers)
docker exec ueransim-ue nr-cli imsi-001010000000001 --dump   # MM-REGISTERED
```
Multi-UE: `nr-ue -c ue.yaml -n N` increments IMSI from `imsi-001010000000001`. Changing `UE_COUNT`
requires `make ueransim` (not `ueransim-only`) to reseed UDR. SUCI null-scheme (`protectionScheme: 0`);
Profile A via `config/ueransim/ue-profile-a.yaml` (`make ueransim-profile-a`).

### Establish a PDU session
```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4 --dnn internet"
```

### Trigger handover scenarios
```bash
make handover-test       # Xn (PacketRusher)
make handover-n2-test    # N2 (PacketRusher)
```
PacketRusher config `config/packetrusher/packetrusher.yaml`; Portal → PacketRusher page for live control.

### Deregister
```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "deregister normal"
```

### Multi-slice
```bash
make ueransim-slices     # 4 UEs across internet/gold/silver/bronze
make test-slices         # T0–T9 validation suite
```

### `nr-cli` commands ↔ 5GC procedures
| `nr-cli` command | 5GC procedure |
|---|---|
| (auto on boot) | Initial Registration + 5G-AKA |
| `ps-establish <type> <dnn>` | PDU Session Establishment |
| `ps-release <psi>` | PDU Session Release |
| `ps-list` | List active PDU sessions |
| `ue-release <ue-id>` (gNB) | AN Release → CM-IDLE |
| `deregister normal` | UE-initiated Deregistration |
| `--dump` | Show 5GMM/5GSM state |

---

## 5. MCP Tools Reference

MCP server: standalone tooling NF, stdio + HTTP SSE (**:9300**). Same registry on both transports.
Config: `mcp/config/{local,dev}.yaml`; client config `.mcp.json`. Tool names below are exposed as
`mcp__5gc__<tool>`. Tools never panic; failures return a structured `mcperr.Error` with a byte `offset`
where applicable.

### Group A — NAS codec & IEs (pure, `shared/nas`; TS 24.501)
| Tool | Purpose | Input (key) | Output |
|---|---|---|---|
| `nas_decode` | Decode a NAS-5GS PDU | `bytes`/hex | parsed message tree |
| `nas_encode` | Encode a NAS message | message JSON | hex PDU |
| `ie_validate` | Validate an IE against spec | IE bytes + type | valid/errors + spec_ref |
| `tlv_inspect` | Walk TLV/TV/LV-E structure | bytes | IE list with offsets |

### Group B — NF management/discovery (NRF SBI; TS 29.510)
| Tool | Purpose | Backed by |
|---|---|---|
| `nf_discover` | Discover NF instances (filters) | NRF NFDiscovery |
| `nf_list` | List registered NF instances | NRF GET nf-instances |
| `nf_status` | Status of a given NF | NRF |

### Group C — UE inspection (AMF mgmt API; TS 23.502/24.501)
| Tool | Purpose |
|---|---|
| `ue_list` | List registered UEs |
| `ue_context_get` | Full UE context by SUPI/GUTI |
| `gmm_state_get` | 5GMM state of a UE |

### Group D — Traces & procedures (Jaeger/Prometheus)
| Tool | Purpose |
|---|---|
| `trace_query` | Query Jaeger traces |
| `procedure_summary` | Summarize a procedure run |

### Group E — Crypto (pure; TS 33.501)
| Tool | Purpose |
|---|---|
| `milenage_run` | MILENAGE f1–f5 |
| `aka_full_run` | Full 5G-AKA vector derivation |
| `kdf_compute` | TS 33.501 Annex A KDFs |
| `suci_derive` | SUCI conceal/deconceal |
| `res_star_verify` | Verify RES* |
| `xres_star_compute` | Compute XRES* |

### Group F — Metrics/KPIs (Prometheus)
| Tool | Purpose |
|---|---|
| `metric_query` | PromQL query |
| `alert_list` | Active Prometheus alerts |
| `kpi_snapshot` | 5GC KPI snapshot |

### Group H — QoS write tools (PCF internal + AMF + UERANSIM; TS 29.512 / 23.502 §4.3.3.2)
| Tool | Purpose |
|---|---|
| `qos_policy_set` / `qos_policy_get` / `qos_policy_delete` | Manage PCF QoS overrides |
| `pdu_session_establish_with_qos` | Establish a session with a QoS profile |
| `pdu_session_qos_modify` | NW-initiated 5QI/AMBR modification |

### Group I — Session/subscription QoS (SMF `nsmf-management` + UDM SDM; TS 23.501 §5.7 / 29.503)
| Tool | Purpose |
|---|---|
| `pdu_session_list` | List active PDU sessions |
| `pdu_session_qos_get` / `pdu_session_qos_set` | Read/set a session's QoS |
| `subscription_qos_get` | Subscriber default QoS from UDM |

### Group U — UERANSIM control
| Tool | Purpose |
|---|---|
| `ueransim_status` | UERANSIM container/UE status |
| `ueransim_ue_register` / `ueransim_ue_deregister` | Register/deregister a UE |
| `ueransim_pdu_session_establish` | Establish a PDU session via nr-cli |
| `ueransim_run_scenario` | Run a scripted scenario |

> Example invocation (stateless SSE / curl):
> ```bash
> curl -s -X POST http://localhost:9300/mcp -H 'Content-Type: application/json' \
>   -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nf_list","arguments":{}}}'
> ```
<!-- TODO: per-tool input/output JSON schemas — see live `GET http://localhost:9300/mcp/tools` for the authoritative manifest. -->

---

## 6. Observability & Debugging

Three pillars wired from Day 0 (see `docs/architecture.md` §Observability), plus per-NF PCAP sidecars.

### Prometheus metrics (`fivegc_*` family, scraped per NF)
| Metric | Meaning |
|---|---|
| `fivegc_sbi_requests_total` / `fivegc_sbi_request_duration_seconds` | SBI request count / latency histogram |
| `fivegc_procedure_total` | Per-procedure completions (with result label) |
| `fivegc_nas_messages_total` / `fivegc_ngap_messages_total` | NAS / NGAP message counts |
| `fivegc_authentication_total` | Authentication attempts/results |
| `fivegc_pdu_session_total` / `fivegc_pdu_sessions_active` | PDU session events / gauge |
| `fivegc_handover_total` | Handover events |
| `fivegc_nf_discovery_total` | NRF discovery calls |
| `fivegc_upf_gtp_bytes_total` / `fivegc_upf_gtp_packets_total` / `fivegc_upf_packet_drops_total` | UPF data plane |
| `fivegc_upf_pfcp_sessions_active` | UPF PFCP session gauge |

Metrics ports: NRF 9100, AMF 9101, AUSF 9102, UDM 9103, UDR 9104, SMF 9105, PCF 9106, UPF 9107, NSSF 9109.
Prometheus UI: `http://localhost:9090`.

### Jaeger traces (`http://localhost:16686`)
Per-procedure trace with spans per SBI call and per N1/N2/N4 message. E2E tracing instrumented across
AMF/AUSF/UDM/SMF/NRF via `otelhttp` middleware + procedure spans (OTLP HTTP :4318 / gRPC :4317).

### Grafana dashboards (`http://localhost:3000`, admin/admin via env)
| Dashboard | Shows |
|---|---|
| `5g-kpi-overview.json` | Top-level KPIs (registrations, sessions, success rates) |
| `message-results.json` | NAS/NGAP message results |
| `slice-session-analytics.json` | Per-slice session analytics |
| `upf-dataplane.json` | UPF GTP-U/PFCP throughput, drops |
| `sbi-timeline.json` | SBI request timeline |
| `ue-connections.json` | UE connection/registration state |
| `nf-resource-health.json` | Per-NF resource/health |

### Logs
JSON to stdout per NF (`slog` via `shared/logging`), scraped by Promtail → Loki → Grafana.
Mandatory fields: `nf`, `procedure`, `correlation_id`, `interface`, `direction`, `spec_ref`
(see root CLAUDE.md). Level via `LOG_LEVEL`. Tail with `docker logs <nf>` or `make logs`.

### PCAP
tcpdump sidecars (5 min/file, max 12): `./scripts/pcap-control.sh [status|pause|resume|rotate|list] [nf]`.
See `docs/pcap-diagnostics.md` for NGAP/HTTP2 troubleshooting.

### Common failure patterns
| Symptom | Likely cause / fix |
|---|---|
| `http2: unsupported scheme` | NRF URL missing `https://` (fixed; invariant in implementation-status §NRF Registration) |
| TLS handshake fails to NRF | NF used `NewHTTP2Client` instead of `NewMTLSClient` — must use mTLS when cert/key present |
| `NegotiatedProtocol != h2` | Set `TLSConfig` (with `NextProtos:["h2"]`) before `http2.ConfigureServer` |
| `Unhandled payload container type [5]` on UE | URSP delivered; UERANSIM v3.2.8 has no URSP support (expected, unless `ueransim-mod`) |
| `NSSAI_NOT_ALLOWED` | UE requested an unsubscribed slice — check UDR am-data / NSSF |

---

## 7. Configuration Reference

### Environment variables (across NFs / compose)
| Variable | Type | Used by | Description |
|---|---|---|---|
| `LISTEN_ADDR` | host:port | all NFs | SBI listen address |
| `METRICS_ADDRESS` | host:port | all NFs | Prometheus `/metrics` listen address |
| `LOG_LEVEL` | enum (debug/info/warn/error) | all NFs | slog level |
| `NRF_ADDR` / `NRF_URL` | host:port / URL | all NFs | NRF endpoint for register/discover |
| `AMF_ADDR` / `AMF_URL` | host:port / URL | SMF, portal, MCP | AMF endpoint |
| `SMF_ADDR` / `SMF_URL` | host:port / URL | AMF, portal, MCP | SMF endpoint |
| `UDM_ADDR` / `UDM_URL` | host:port / URL | AUSF, portal | UDM endpoint |
| `PCF_URL` | URL | SMF, AMF | PCF endpoint |
| `LMF_URL` | URL | portal | LMF endpoint for the UE Location page (Nlmf_Location; default `https://lmf:8012`) |
| `DATABASE_URL` | DSN | AMF, SMF, UDR | PostgreSQL connection |
| `REDIS_URL` | URL | NRF, AMF, AUSF | Redis connection |
| `OPERATOR_CONFIG_PATH` / `NF_CONFIGS_PATH` | path | NFs, portal | Path to `config/operator.yaml` / per-NF configs |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `JAEGER_ADDR` | URL | all NFs | OTLP→Jaeger exporter |
| `PROMETHEUS_ADDR` / `PROMETHEUS_URL` | URL | MCP, portal | Prometheus query endpoint |
| `URSP_ENABLED` | bool | PCF/AMF | Toggle URSP delivery |
| `UE_COUNT` | int (default 1) | UERANSIM / UDR seeding | Number of UEs to simulate/seed |
| `HN_PRIVATE_KEY_X25519` | hex | UDM | Home network private key for SUCI Profile A |
| `MCP_TRANSPORT` | enum (stdio/sse/both) | MCP | Transport selection |
| `PORTAL_CERT_FILE` / `PORTAL_KEY_FILE` | path | mgmt-portal | TLS cert/key |
| `POSTGRES_USER/PASSWORD/DB` | string | postgres | DB bootstrap |
| `GF_SECURITY_ADMIN_USER/PASSWORD`, `GF_USERS_ALLOW_SIGN_UP` | string/bool | grafana | Grafana admin |
| `COLLECTOR_OTLP_ENABLED` | bool | jaeger | Enable OTLP collector |

Per-NF YAML config lives in `nf/<nf>/config/dev.yaml`; operator-wide topology (DNNs, slices) in
`config/operator.yaml` (single source of truth).

Notable per-NF YAML keys added recently:

| Key | File | Description |
|---|---|---|
| `served_tacs` (list of ints, default `[1]`) | `nf/amf/config/dev.yaml` | Registration area advertised as the TAI list (IEI 0x54) in every Registration Accept. Must cover every TAC the connected gNBs broadcast; the UE's current TAC is always appended if missing. Ref: TS 24.501 §9.11.3.9 |

### Docker Compose service & port map
| Service | Container | Published ports |
|---|---|---|
| nrf | nrf | 8000 (SBI), 9100 (metrics) |
| amf | amf | 38412/sctp (N2), 8001 (SBI), 9002 (mgmt), 9101 (metrics) |
| ausf | ausf | 8002, 9102 |
| udm | udm | 8003, 9103 |
| udr | udr | 8005, 9104 |
| smf | smf | 8004, 9105 |
| pcf | pcf | 8006, 9106 |
| upf | upf | 8805/udp (N4), 2152/udp (N3), 9107 |
| nssf | nssf | 8007, 9109 |
| smsf | smsf | 8009 (SBI Nsmsf), 9110 (metrics) |
| nef | nef | 8011 (SBI Nnef), 9112 (metrics) |
| lmf | lmf | 8012 (SBI Nlmf), 9113 (metrics) |
| mcp | mcp | 9300 (SSE) |
| mgmt-portal | mgmt-portal | 8080 |
| loki | loki | 3100 |
| prometheus | prometheus | 9090 |
| grafana | grafana | 3000 |
| jaeger | jaeger | 16686 (UI), 4318 (OTLP HTTP), 4317 (OTLP gRPC) |
| postgres | postgres | 5432 |
| redis | redis | 6379 |
| ueransim-gnb / ueransim-ue | (profiles) | RAN simulator |

Compose **profiles**: `core`, `obs`, `tools`, `multi-slice`, `suci-profile-a`, `handover`, plus PCAP sidecars.

**Reserved ports (NF built + tested in-process; docker-compose wiring deferred):**
`bsf` — 8010 (SBI Nbsf) / 9111 (metrics) (BSF-004); `nef` — 8011 (SBI Nnef) / 9112 (metrics) (NEF-005).

### TLS / PKI
mTLS everywhere on SBI (TS 33.501 §13). Certs in `pki/`, mounted as `/etc/5gc/pki/<nf>.crt|.key`;
CA `pki/ca.crt`. Regenerate dev certs with `make pki`. OAuth2 tokens issued by NRF (HS256 JWT).

### Network topology (Docker)
| Network | Subnet | Purpose |
|---|---|---|
| sbi-net | 10.45.0.0/24 | SBI between CP NFs + postgres/redis/obs |
| n2-net | 10.45.1.0/24 | NGAP/SCTP gNB↔AMF |
| n4-net | 10.45.2.0/24 | PFCP SMF↔UPF |
| n3-net | 10.45.3.0/24 | GTP-U gNB↔UPF |
| n6-net / n6-ims-net | 10.45.6.0/24 / per-DNN | UPF egress to DN (per-DNN isolation) |
| n9-net | 10.45.9.0/24 | inter-UPF GTP-U (future) |

Per-DNN UE pools: internet `10.60.0.0/24` (N6 `172.30.6.0/24`), ims `10.61.0.0/24` (N6 `172.30.7.0/24`).

---

## 8. Development & Contribution Guide

Workflow for a new procedure (do not skip steps — see root CLAUDE.md):
1. `docs/procedures/<procedure>.md` — Mermaid sequence diagram + spec ref + IE table + error cases.
2. `.feature` Cucumber file — happy path + errors.
3. Implement handler + state machine + SBI calls in `internal/`.
4. godog step definitions.
5. Integration test (UERANSIM/gNBSim/PacketRusher).
6. PCAP validation (`docs/pcap-diagnostics.md`).
7. Update `docs/compliance-matrix.md`.

### Add a new NF
- Copy `nf/_template/` and read its `CLAUDE.md`.
- Provide: canonical JSON logs, NRF registration on startup, `/metrics`, PCAP sidecar in docker-compose,
  mTLS SBI server (set `TLSConfig` with `NextProtos:["h2"]` **before** `http2.ConfigureServer`).
- Use `sbi.NewMTLSClient` for outbound SBI when cert/key are configured.

### Add a new SBI endpoint
- Validate the new message with `tools/compliance-checker`.
- When modifying OpenAPI schema → regenerate types + run all NF tests (`make sync-openapi` for YAMLs).
- Keep SBI and reference points in separate handlers/packages.

### Add a new MCP tool
- Register it once in the MCP `registerTools` (both transports share one registry).
- Pure tools (no network) belong to Group A and must never panic — return `mcperr.Error`.
- Do not add an MCP SDK dependency (hand-rolled JSON-RPC on net/http).
- Document it in **Section 5** of this manual.

### Testing approach
| Level | Tooling | Command |
|---|---|---|
| Unit | `go test` (-race) | `make test` (per NF) |
| Functional (BDD) | godog | `make test-functional` (NRF in-process; AMF needs `E2E_TEST=1` + stack) |
| Integration | testcontainers-go | per-NF `make test-functional` |
| E2E | UERANSIM / PacketRusher | `make ueransim`, `make test-slices`, `make handover-test`, `make validate-ursp` |
| Lint | golangci-lint | `make lint` (CI fails on warnings) |

### Autonomous development
Backlog & orchestration in `dev/` (`BACKLOG.md`, `ORCHESTRATOR_PROMPT.md`, `SESSION_LOG.md`);
agent roles in `AGENTS.md`. After big changes run `/graphify . --update` (knowledge graph in `graphify-out/`).

---

## Changelog
<!-- Entries are appended automatically by the agent after each feature session. Format: -->
<!-- - [YYYY-MM-DD] <NF or domain>: <brief description of what changed> -->
- [2026-06-21] docs: initial CLAUDIA_5GC_MANUAL generated from full codebase audit (all 9 NFs + MCP + portal + observability).
- [2026-06-21] smsf,amf: SMS over NAS — new SMSF NF (Nsmsf_SMService Activate/Deactivate/UplinkSMS + loopback DTE MT echo, NRF reg, UDM UECM); AMF UL NAS Transport (PCT=0x02) → Nsmsf UplinkSMS relay; docker-compose service + PCAP sidecar + PKI; 11 unit + 7 BDD scenarios [TS 23.502 §4.13 / TS 29.540].
- [2026-06-21] amf: fix stale PDU session leak on UE reconnect — when a UE reconnects (Docker restart, abrupt disconnect) without sending Deregistration, the new registration now atomically displaces the old UEContext and asynchronously releases its PDU sessions at the SMF (IP pool freed, PFCP deleted). `Manager.Remove` now guards against accidentally erasing a SUPI/DB slot already claimed by the new context.
- [2026-06-21] bsf: new BSF NF (BSF-001) — Nbsf_Management Register/Deregister/Discovery (TS 29.521 §5), in-memory binding store with ipv4/supi indices, NRF registration (NFType BSF), mTLS+HTTP/2 SBI server on port 8010, Prometheus metrics on port 9111, 14 unit tests [TS 23.501 §6.2.16 / TS 29.521 §5]. docker-compose wiring + PCF client integration are follow-up passes (BSF-002, BSF-004).
- [2026-06-22] pcf: NEF-001 AC2 — thin Npcf_PolicyAuthorization Create+Delete (POST/DELETE /npcf-policyauthorization/v1/app-sessions) added to PCF SBI server; AppSessionContext+AppSessionContextReqData types; in-memory appSessions map; 8 new unit tests; pre-existing bsf_client_test.go stale module-path import fixed [TS 29.514 §5.2.2.2, §5.2.2.4].
- [2026-06-22] nef: new NEF NF (NEF-001) — Nnef_AFsessionWithQoS Create/Get/Delete (TS 29.522 §4.4.13) on mTLS+HTTP/2 SBI port 8011 / metrics 9112; OAuth2 northbound (scope nnef-afsessionwithqos; 401/403); BSF Discovery (Nbsf §5.2.2.4) → Npcf_PolicyAuthorization_Create (TS 29.514) on the serving PCF; NRF registration (NFType NEF); in-memory subscription store + fivegc_nef_subscriptions_active gauge + Grafana NEF row; 8 unit + 12 BDD scenarios. Fixed create-reject cause MODIFICATION_NOT_ALLOWED→UNAUTHORIZED_AF (spec-verifier) and a pre-existing BSF-001 build break (4 nf/bsf/*.go files used the claudia-5gc module path instead of 5gc-rel17). docker-compose wiring + PKI deferred (NEF-005) [TS 23.501 §6.2.5 / TS 29.522 §4.4.13].
- [2026-06-23] ci,build: catch all-NF build failures before compose-up — new `go-build` CI job (`GOWORK=off go build ./nf/... ./shared/...`) + docker matrix expanded to all 12 core NFs; root cause of the bsf/nef CI break was main's module path (claudia-5gc) vs merged-in 5gc-rel17 import paths. Fixed the stragglers on main and made `scripts/release-public.sh` auto-rewrite `5gc-rel17`→`claudia-5gc` + compile-gate before publishing.
- [2026-06-23] docs,template: aligned `nf/_template/` with the real root-module build (Dockerfile `GO_VERSION=1.26.2` + `COPY go.mod go.sum*`+`shared/`; added the missing Makefile) and added a §0 New NF Checklist (no per-NF go.mod, root-module import paths, `GOWORK=off go mod tidy`, wire into CI matrix + docker-compose + Makefile, verify with go build + make docker). Root CLAUDE.md "New NF" rule expanded accordingly.
- [2026-06-23] lmf,amf: new **LMF** NF (LMF-001) — Nlmf_Location DetermineLocation (Cell-ID MVP, TS 29.572 §5.2.2.2) on mTLS+HTTP/2 SBI :8012 / metrics :9113, NRF registration (NFType=LMF, service nlmf-loc), `fivegc_lmf_locate_total{result}` + Grafana LMF row. AMF additions: Namf_Location producer (`POST /namf-loc/v1/ue-contexts/{id}/provide-loc-info` on :8001, TS 29.518 §5.2.2.6) + NGAP **LocationReportingControl** builder (ProcCode=16) & **LocationReport** decoder (ProcCode=18, UserLocationInformationNR→NRCGI+TAI, TS 38.413 §8.17.1) with a `sync.Map` AMF-UE-NGAP-ID→chan correlation (10 s timeout). Wired into docker-compose (lmf + lmf-pcap, profile core), CI docker matrix, Makefile NFS, PKI (pki/lmf.crt/key). 9 AMF unit + 6 LMF unit + 6 LMF BDD scenarios. Live: AMF→gNB control emit verified; UERANSIM v3.2.8 has no LocationReport handler so the RAN→AMF leg is unit/functional-tested (codec round-trip). Also fixed a pre-existing Prometheus scrape gap (8 NFs incl. smf/pcf/upf/nssf/smsf/bsf/nef were not scraped) [TS 23.273 / TS 29.572 / TS 29.518 / TS 38.413].
- [2026-06-23] lmf,ueransim,portal: **live Location Reporting E2E** (LMF-006) — UERANSIM gNB patch `0040-location-reporting.patch` adds the missing NGAP `LocationReportingControl` handler (replies with a `LocationReport` carrying serving NR-CGI+TAI, TS 38.413 §8.17), closing the live LMF Cell-ID flow that previously timed out. LMF gains a synthetic **mobility model** (`internal/server/mobility.go`): deterministic, bounded, per-SUPI walk anchored at the serving cell (`cell_coordinates`/`default_coordinate`/`mobility` in dev.yaml) — artificial but realistically moving lat/lon, accuracy in `locationEstimate.uncertainty`. Management portal adds a **UE Location** page (live Leaflet map + table, auto-poll 3 s) via `GET /api/v1/location/{summary,ue/{supi}}` (mTLS LCS-client proxy) + new `LMF_URL` env. Corrected the stale BACKLOG/doc note that claimed UERANSIM answered LocationReportingControl. Unit: `nf/lmf/.../mobility_test.go`; validation: `scripts/validate-ueransim-mod.sh location`.
- [2026-06-24] lmf,amf,udm: **Deferred MT Location + Location Privacy** (LMF-002) — (A) AMF `handleProvideLocInfo` no longer immediately rejects CM-IDLE UEs: it pages the UE via NGAP Paging (ProcCode=24) using the existing `Pager` interface, stores a `chan struct{}` in `pendingLocPage` (sync.Map keyed by AMF-UE-NGAP-ID), and blocks up to T-positioning (15 s guard, `pageTimeout` constant); the UE's Service Request fires `onUEReachable` → `sbiSrv.NotifyUEReachable` → channel signal → falls through to NGAP LocationReportingControl. Timeout → 504 UE_NOT_REACHABLE. New public method `NotifyUEReachable` on `amfsbi.Server`; forward declaration in `cmd/amf/main.go` to avoid import cycle. (B) UDM gains `GET /nudm-sdm/v2/{supi}/lcs-privacy-data` (always returns `ALLOW_ALL` in dev). LMF gains `UDMSDMClient` interface + `HTTPUDMSDMClient` (5-min per-SUPI cache, fail-open); before calling AMF, LMF checks `cfg.PrivacyCheck && udmClient.GetLcsPrivacyData` — `BLOCK_ALL` → 403 PRIVACY_EXCEPTION_DENIED, any other value or error → proceed. New `privacy_check: true` in `nf/lmf/config/dev.yaml`; `peers.udm: "udm:8003"`. Tests: 2 new AMF unit (paging timeout + paging success), 2 new LMF unit (privacy denied + privacy allowed), 2 new LMF BDD scenarios (Scenarios 7+8), LMF BDD step defs extended with `fakeUDMClient`. Build gate clean [TS 23.273 §7.2 E2–E7 / §9.1 / TS 29.503 §5.2.2].
- [2026-06-27] lmf: **Nlmf_Location EventSubscription + CancelLocation** (LMF-003) — LMF gains a subscription model (TS 29.572 §5.2.3) with two event-trigger types: `PERIODIC_REPORTING` (re-locate at `reportingInterval`, notify every sample) and `AREA_OF_INTEREST` (sample at `samplingInterval`, notify only on polygon entry/exit via ray-casting state machine IN/OUT/UNKNOWN). One goroutine per subscription, in-memory registry (`sync.RWMutex`). Privacy gate at Create (BLOCK_ALL→403). **CancelLocation** (one-shot cancel) via `POST /nlmf-loc/v1/ue-contexts/{id}/cancel-loc` fires a stored `context.CancelFunc`. Notification delivery: mTLS HTTP/2 client posting `LocationNotification` body, retry-once on 5xx. New endpoints: `POST/GET/DELETE /nlmf-loc/v1/subscriptions[/{subId}]` + `POST …/cancel-loc`. Config: `location_subscription` block in `dev.yaml`. Metrics: `fivegc_lmf_subscription_create_total{result}` + `fivegc_lmf_subscriptions_active`; 2 Grafana panels. 20 BDD scenarios (12 EventSubscription + 8 DetermineLocation), all pass. `docs/procedures/EventSubscription.md` with Mermaid diagram. Compliance matrix rows: EventSubscription + CancelLocation [TS 29.572 §5.2.3/§5.2.2.5 / TS 23.273 §7.2 step B2].
- [2026-06-27] amf,shared: **NRPPa Relay E-CID PASS 1** (LMF-004) — AMF-side NRPPa relay: new `shared/nrppa/` codec (7 message types, compact TLV wire format, RSRP fidelity, 13 unit tests); 4 NGAP ProcedureCode constants (DL-NonUE=5, DL-UE=8, UL-NonUE=47, UL-UE=50); BuildDownlink{UE,NonUE}AssociatedNRPPaTransport builders + extractUplink extractors + dispatch cases in AMF ngap package; `NRPPaResult` + `pendingNRPPa sync.Map` + `SendDownlinkNRPPa` + `handleUplink{UE,NonUE}AssociatedNRPPa` in ngap.Server; `NRPPaRelay` interface + `handleDLNRPPaInfo` POST handler on `namf-loc/v1/ue-contexts/{id}/dl-nrppa-info` (synchronous blocking model, 10 s guard, mirrors ProvideLocInfo); `DLNRPPaInfoReq/Rsp` SBI types; `fivegc_amf_nrppa_transport_total{direction,assoc}` metric; wired with `SetNRPPaRelay(ngapSrv)` in main.go. 5 NGAP codec unit tests + 7 SBI handler tests (200/404/400/503/504). AMF build + race-test green [TS 38.413 §8.17.3/§8.17.4 / TS 38.455 §8 / TS 23.273 §7.2 step C / TS 29.518 §5.2.2.6].
- [2026-06-27] lmf,amf,shared: **NRPPa Relay E-CID positioning COMPLETE** (LMF-004) — LMF side (PASS 2) added on top of the AMF/`shared/nrppa` PASS 1: quality-driven method selection (`lcsQoS.hAccuracy` 50–200 m → E-CID, >200 m → Cell-ID; `nf/lmf/internal/server/ecid.go`), two synchronous NRPPa rounds via the AMF `SendDLNRPPa` client (capability + measurement), weighted-centroid RSRP fix (uncertainty ≤150 m, `positioningDataList=["eCID"]`), transparent Cell-ID fallback on any NRPPa failure (never 5xx), privacy gate before NRPPa. Metric `fivegc_lmf_ecid_total{result}` + 4 Grafana panels. 5 godog scenarios (25/25 LMF functional pass). SPEC-VERIFIER CONFORMANT (ProcCodes 5/8/47/50 confirmed; the backlog's "66–69" was wrong). Live gNB leg (UERANSIM patch 0041) deferred to LMF-008 [TS 38.455 §8 / TS 38.413 §8.17.3 / TS 23.273 §6.2.9 / TS 29.572 §5.2.2.2]. docs: update CLAUDIA_5GC_MANUAL
- [2026-06-28] lmf,ueransim: **live E-CID E2E** (LMF-008) — UERANSIM gNB patch `0041-nrppa-transport.patch` adds the missing NGAP `DownlinkUEAssociatedNRPPaTransport` handler (ProcCode 8): the gNB decodes the `shared/nrppa` E-CID wire format and replies over `UplinkUEAssociatedNRPPaTransport` (ProcCode 50) with `PositioningInformationResponse{E-CID supported}` then `E-CIDMeasurementReport` carrying synthetic RSRP (serving −70 dBm, 2 neighbours −90 dBm; NRCGI = config PLMN + `nci<<4`, so `nrcgiToHex` matches `cell_coordinates`). `sendNgapUeAssociated` auto-inserts AMF/RAN-UE-NGAP-ID; the patch pushes only the NRPPa-PDU IE (id 46). This closes the live LMF→AMF→gNB→AMF→LMF E-CID flow that LMF-004 left falling back to Cell-ID (stock v3.2.8 had no NRPPa handler). `make ueransim-build-only` compiles `0041` cleanly. New `scripts/validate-ueransim-mod.sh nrppa` scenario, validated live: `DetermineLocation` with `{"locationQoS":{"hAccuracy":100}}` → 200 `positioningDataList:["eCID"]`, uncertainty 150 m ≤150, serving `000000010`; gNB+AMF logs show both NRPPa rounds. No Go code changed (core-side was LMF-004) [TS 38.455 §8 / TS 38.413 §8.17.3 / TS 23.273 §6.2.9]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-01] lmf,amf,ueransim,shared: **NRPPa E-CID fix — real APER + correct ProcedureCodes** (LMF-004 fix) — pcap analysis found `shared/nrppa/` was a hand-rolled TLV format (not real APER despite its doc comment) with `ProcedureCode` constants (12/6/8) colliding with real unrelated TS 38.455 procedures, dissecting as malformed once real IE content was present. Rewrote `shared/nrppa/nrppa_asn1.go` as hand-written Go structs (`aper:"..."` tags) mirroring the TS 38.455 ASN.1 module, encoded via `github.com/free5gc/aper` Marshal/Unmarshal (free5gc has no NRPPa module). Corrected ProcedureCodes: positioningInformationExchange=9, e-CIDMeasurementInitiation=2, e-CIDMeasurementReport=4 (TS 38.455 Table 9.1-1); added the previously-omitted mandatory `NRPPaTransactionID`. Fixed a self-inflicted double extension-bit bug from over-tagging primitive wrappers (both the wrapper struct and its inner field tagged `valueExt`), verified via isolated `aper.MarshalWithParams` byte comparisons. Replaced the RSRP-weighted-centroid position algorithm (which had no spec-legal wire representation — TS 38.455's `measuredResults` IE is E-UTRA-only) with the real, optional `NG-RANAccessPointPosition` IE (TS 38.455 §9, TS 23.032 Ellipsoid-Point-with-Uncertainty-Ellipse shape) that the gNB reports; `nf/lmf/internal/server/ecid.go` `computeECIDPosition` uses it (clamped 50–150 m) or falls back to the serving-cell anchor (300 m). `tools/ueransim/patches/0041-nrppa-transport.patch` regenerated from scratch against the new Go encoder — compiled+linked in a real UERANSIM v3.2.8+patches source tree (`g++ -Wall -Wextra -pedantic`, 0 warnings). New regression tests: `TestGoldenECIDMeasurementReport`, `TestProcedureCodesMatchSpec`, AP-position round-trip tests [TS 38.455 §8/§9, TS 38.413 §8.17.3, TS 23.273 §6.2.9, TS 23.032 §6.2/§6.7]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-01] lmf,ueransim,shared: **NRPPa E-CID fix follow-up — two more bugs found only by live pcap re-capture** — the round-trip unit tests above kept passing throughout both bugs (encode and decode shared the same wrong assumption each time), so only decoding a fresh capture with Wireshark's independent NRPPa ASN.1 dissector caught them. (1) `NGRANCell` CHOICE index (`eUTRA-CellID`/`nR-CellID`/`choice-Extension`, 3 real alternatives) was tagged `valueUB:1` (2 alternatives, 1 bit) instead of `valueUB:2` (3 alternatives, 2 bits) — even though this codec never constructs `choice-Extension`, the wire WIDTH must still reflect all 3 alternatives; Wireshark decoded the branch as `choice-Extension` instead of `nR-CellID` and every downstream bit (the entire `NG-RANAccessPointPosition`) came out as garbage. (2) `Latitude`/`Longitude` had been "fixed" as a 3-octet `aper.OctetString` based on a wrong diagnosis of an unrelated all-zero-value edge case (`"bits value is over capacity"`) — a websearch of X.691 §10.5.7.4 confirmed free5gc/aper's actual behaviour for constrained-INTEGER ranges >64K (an octet-aligned length-determinant + minimal octets for the specific value) IS the correct X.691 procedure, not a library bug; reverted to plain `int64` fields, and the gNB patch's C++ now mirrors the same length-determinant shape. Both fixed, gNB patch 0041 rebuilt+recompiled+recaptured: final live pcap shows zero malformed packets, zero Expert Info warnings, and every `NG-RANAccessPointPosition` field decodes byte-exact (`latitude=3767118`, `longitude=-172609`, `uncertaintySemi-major/minor=25`, `confidence=68`). See `docs/procedures/NRPPaRelay.md` §7 for the full narrative. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-01] lmf,amf,shared: **LPP relay — GNSS positioning via N1** (LMF-005) — LPP (LTE Positioning Protocol, TS 37.355) over the N1 NAS interface with the AMF as a transparent relay. New `shared/lpp/` package: hand-written APER structs (`github.com/free5gc/aper`, same family as NGAP/NRPPa) for the A-GNSS message subset (RequestCapabilities, ProvideCapabilities, ProvideAssistanceData+RequestLocationInformation, ProvideLocationInformation) + WGS84↔ECEF conversions + synthetic ephemeris + Gauss-Newton weighted-least-squares GNSS solver (`SolveWLS`), golden-hex codec tests. AMF: **additive** `PayloadContainerType == 0x03` (LPP) branch in `handleULNASTransport` (existing N1SM/SMS/UEPolicy branches byte-identical), `SendDownlinkLPP` (builds `DLNASTransport{PayloadContainerType: 0x03}`), `pendingLPP sync.Map` correlation keyed by AMF-UE-NGAP-ID, and `POST /namf-loc/v1/ue-contexts/{id}/dl-lpp-info` synchronous relay handler (10 s guard, mirrors `dl-nrppa-info`); `LPPRelay` interface + `SetLPPRelay` wiring. **CRITICAL spec correction:** the backlog descriptor's "payload container type 0x01" is wrong (0x01 = N1 SM information → would misroute to SMF); the spec-correct value is **0x03** (TS 24.501 §9.11.3.40), already defined as `nas.PayloadContainerTypeLPP`. LMF: `methodLPP` selection band (hAccuracy <50 m; 50–200 m stays E-CID, >200 m/absent stays Cell-ID), `performLPPOrFallback` (RequestCapabilities → if GNSS supported: assistance + measurement → WLS fix uncertainty ≤50 m; else transparent fallback GNSS→E-CID→Cell-ID, never 5xx), per-SUPI state machine (IDLE→CAPS_REQUESTED→ASSIST_SENT→MEASURE_RECEIVED→FIXED), `SendDLLPP` AMF client + `SetLPPClient`; `LocationData.positioningDataList:["gnss"]`. Metrics `fivegc_lmf_gnss_total{result}` (OK/FALLBACK_ECID/FALLBACK_CELLID) + `fivegc_amf_lpp_transport_total{direction}` + 4 Grafana panels. 6 BDD scenarios (31/31 LMF functional pass); full AMF `-race` suite + live `validate-ueransim-mod.sh location`+`nrppa` re-run against the LMF-005 images → no regression in the N1/location/NRPPa paths. SPEC-VERIFIER **CONFORMANT-WITH-NOTES** (0x03 confirmed on both legs; aligned-vs-unaligned PER wire-fidelity documented as a known deviation, same posture as `shared/nrppa`). Deferred (follow-up, mirrors LMF-008 after LMF-004): UERANSIM UE patch `0042` + live GNSS E2E [TS 37.355 / TS 24.501 §8.7.4 §9.11.3.40 / TS 38.413 §8.6.2 §8.6.3 / TS 23.273 §6.2.10 §7.2 / TS 29.572 §5.2.2.2 / TS 29.518 §5.2.2.6]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-03] observability: **Grafana dashboard audit + fixes** (branch `fable-grafana-check`, full live-traffic verification — see `FABLE_GRAFANA_AUDIT.md`) — 7 dashboards / 91 panels audited against a running stack; 33 panels fixed in 5 per-dashboard commits: (1) all 15 "Success/Reject/Fallback Rate" stats replaced `clamp_min(denom,1)` (which degenerated percentages at lab traffic rates, e.g. 100% auth success displayed as 0.34%) with `100 * (sum(rate(num)) or vector(0)) / (sum(rate(den)) > 0)`; (2) plain shared-registry gauges (`fivegc_upf_pfcp_sessions_active`, `_bsf_bindings_`, `_nef_subscriptions_`, `_lmf_subscriptions_`) are exported as 0 by all 13 NFs — panels scoped to the owning NF via `{nf="..."}`; (3) dead GC panel (`go_gc_duration_seconds{quantile="0.99"}` doesn't exist → `quantile="1"`); (4) unit fixes (`ops`→`opm` for ×60 queries, `Mbits`→`bps` for throughput, RSS to raw bytes, `round(increase(...))`). Flagged-not-fixed code gaps: `SBIRequestsTotal`/`SBIRequestDurationSeconds`/`NGAPMessagesTotal` defined but never incremented (8 permanently-empty SBI panels; `metrics.SBIMiddleware` has no call sites); `ProcedureTotal` never emitted for ServiceRequest / NetworkDeregistration / any SMSF procedure; `fivegc_handover_total` only counts OK; `fivegc_ue_connected` over-counts stale N2 contexts (read 7 with 1 live UE); no QoS-modification metric exists (NW-initiated 5QI changes are invisible to Prometheus).
- [2026-07-05] lmf,amf,shared,ueransim: **Live GNSS E2E — LPP UNALIGNED-PER rewrite + UE patch 0042** (LMF-009) — closed the live A-GNSS loop LMF-005 left falling back to E-CID (stock UERANSIM v3.2.8 had no LPP handler). **Resolved the aligned-vs-unaligned PER deviation** LMF-005 flagged: `shared/lpp` no longer uses `github.com/free5gc/aper` (ALIGNED PER); rewritten as a hand-rolled X.691 **BASIC-PER UNALIGNED** bit codec (`shared/lpp/uper.go`) with real TS 37.355 messages — the invented "combined AssistanceDataAndLocationRequest" is gone, replaced by real `ProvideAssistanceData` (DL-only, unsolicited) + `RequestLocationInformation`. Wire flow is now **3 legs**: RequestCapabilities→ProvideCapabilities, ProvideAssistanceData (AMF `expectUlResponse=false` → 204, no waiter), RequestLocationInformation→ProvideLocationInformation; LPP transactions per §5.2 (TransactionNumber 0..255, initiator=locationServer, UE echoes; LMF-005's 0..262143 fixed). UE derives synthetic measurements deterministically from the wire-quantized reference location (quantized-anchor rule) so WLS converges near the anchor. New `tools/ueransim/patches/0042-lpp-gnss.patch` — UE NAS LPP responder for payload container type 3, C++ mirror of the Go codec byte-for-byte (compiles via `make ueransim-build-only`); `LPP_GNSS_NONE=1` negative mode. Vendored TS 37.355 V19.3.0 ASN.1 at `specs/3gpp-asn1/LPP-PDU-Definitions.asn`. **Zero malformed ASN.1** confirmed by the real Wireshark 4.6.4 LPP dissector: `TestTsharkOracle_AllGoldenPDUs` (7 golden PDUs) + a live N2 capture where the 3 DL legs dissect as valid LPP (SCTP PPID 60); UL legs NEA2-ciphered (proven by the oracle). Live: `validate-ueransim-mod.sh gnss` → 200 `positioningDataList:["gnss"]`, uncertainty 5 m; GNSS=NONE → fallback E-CID (200, no 5xx); `location`/`nrppa` no regression. 31/31 LMF + AMF functional pass. SPEC-VERIFIER **CONFORMANT** (all 5 messages verified against the vendored module; payload container type 0x03 both legs) [TS 37.355 §4/§5.2/§6, TS 24.501 §8.7.4/§9.11.3.40, TS 38.413 §8.6.2/§8.6.3, TS 23.273 §6.2.10]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-06] amf,shared,ueransim,portal: **Fix portal subscriber edits bricking UEs** — editing any subscriber in the mgmt portal left that UE unable to ever re-register (stuck 5U3/5U2, "SMC integrity check failed"). Four root causes fixed: (1) AMF mgmt-API NW-dereg sent 5GMM cause 0x06 "Illegal ME" + re-registration-not-required → UE invalidated its USIM (5U3-ROAMING-NOT-ALLOWED) per TS 24.501 §5.5.2.3.4; now sends **no cause + "re-registration required"**. (2) `shared/nas` encoded the re-registration-required flag on bit 4 (0x08 = switch-off) instead of bit 3 (0x04) per TS 24.501 §9.11.3.20 (+ regression test). (3) Stock UERANSIM v3.2.8 never implemented re-registration on NW dereg (`// TODO` in `receiveDeregistrationRequest`) — new patch `0050-nw-dereg-reregistration.patch` enters MM-DEREGISTERED/NORMAL-SERVICE and triggers Initial Registration (DUE-TO-DEREGISTRATION). (4) The portal `PUT /subscribers/{supi}` wrote the form's stale SQN back to `subscription_auth`, rewinding the UDM-incremented counter — UERANSIM derives KAUSF from its own higher SQN-MS (no AUTS resync) so every subsequent Security Mode Command failed integrity; `UpsertSubscriber` now preserves the DB SQN on update (SQN read-only in the edit form) and update rejects empty k/opc. Validated live E2E: portal edit → `{"deregistered":true}` → UE logs `DUE-TO-DEREGISTRATION` → RM-REGISTERED/5U1-UPDATED, PDU sessions re-established, slice change visible in next registration, SQN monotonic. Known pre-existing gaps noted: AMF Registration Accept carries no TAI list (UERANSIM cancels Service Request from CM-IDLE: "current TAI is not in the TAI list"); AMF serial NGAP loop can back up minutes under burst when CreateSMContext is slow [TS 24.501 §5.5.2.3.2/§9.11.3.20, TS 23.502 §4.2.2.3.3, TS 33.501 §6.1.3.2]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-07] amf,shared: **Registration Accept now carries the registration area TAI list (IEI 0x54)** — closes the 2026-07-06 known gap where UERANSIM cancelled Service Request from CM-IDLE ("current TAI is not in the TAI list"). New `nas.EncodeTAIList` (type-00 partial list, TS 24.501 §9.11.3.9) + `served_tacs` config key in `nf/amf/config/dev.yaml` (default `[1]`); the UE's current TAC is always included. Wire-validated: Wireshark dissects the 0x54 IE (PLMN 001/01, TAC 1) in the live Registration Accept; the UE now initiates and completes Service Request. Unit tests: `TestEncodeTAIList_Type00Wire`, `TestRegistrationAccept_TAIList`, `TestBuildTAIList_*` [TS 24.501 §9.11.3.9/§5.5.1.2.4]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-07] amf: **NGAP dispatch no longer serializes all UEs behind one slow SBI call** — closes the 2026-07-06 known gap where the single per-association read loop blocked for minutes under registration/PDU-establishment bursts when `CreateSMContext` was slow. Blocking NAS work (InitialUEMessage, UplinkNASTransport, AN-release SMF notification) now runs on a per-UE serial FIFO (`UEContext.EnqueueSerial`): per-UE arrival order (and `SecurityCtx.UplinkCount`) is preserved, different UEs process concurrently. Regression tests (with `-race`): `TestUplinkNASTransport_SlowUEDoesNotBlockOthers`, `TestEnqueueSerial_PerUEOrdering`; live stack exercises the new path for registration/SR/release [TS 38.412 §7, TS 24.501 §4.4.3]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-07] amf,smf,shared,ueransim: **Service Request now re-activates the user plane via N2SM info in InitialContextSetupRequest (TS 23.502 §4.2.3.2 step 12)** — replaces the UERANSIM-side re-establishment workaround noted in docs/validation-commands.md §7.5. AMF fetches the session's `PDUSessionResourceSetupRequestTransfer` from SMF (`upCnxState=ACTIVATING`, new SMF branch) for each PSI in the SR's Uplink Data Status and encodes `PDUSessionResourceSetupListCxtReq` (IE 71, spec position between GUAMI and AllowedNSSAI); the previously-ignored ICS Response is now decoded and its CxtRes DL tunnel forwarded to SMF → PFCP FAR update. En route, fixed two `shared/nas` Service Request decode bugs found by pcap: 5G-S-TMSI read as 1-byte LV instead of LV-E, and the NAS message container (0x71, TLV-E) — where UERANSIM carries the real Uplink Data Status — not parsed. Also new UERANSIM patch `0051-gnb-amf-selection-no-nssai.patch`: stock v3.2.8 gNB dropped any initial NAS message without Requested NSSAI ("AMF selection failed"), so SR never reached the AMF. The old APER suspicion did **not** reproduce: live pcap shows zero malformed frames; Wireshark fully dissects the CxtReq transfer (UL TEID) and CxtRes (DL TEID). Live E2E: ping from CM-IDLE → SR → ICS `pdu_sessions_cxt_req=1` → gNB CxtRes → SMF `PFCP SessionModification` → 0% loss. Unit tests: ICS CxtReq/CxtRes codec round-trips, SMF ACTIVATING handler, UERANSIM-wire SR decode [TS 23.502 §4.2.3.2, TS 29.502 §5.2.2.3.2.2, TS 38.413 §9.2.2.1, TS 24.501 §4.4.6/§9.11.3.33]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-10] amf,smf,shared: **E2E Registration + PDU Establishment 3GPP conformance audit (real-UE readiness)** — branch `audit/e2e-registration-pdu-3gpp`; full message/IE review of Initial Registration and PDU Session Establishment against TS 24.501/23.502/38.413/29.502, focus on the post-InitialContextSetup UE-context path. Seven deviations fixed: (1) Requested NSSAI IEI corrected 0x6D→**0x2F** (TS 24.501 Table 8.2.6.1.1) — the decoder had never matched any UE's Requested NSSAI (UERANSIM sends 0x2F); masked by the "no requested → all subscribed" fallback, so multi-slice tests passed while slice intersection was silently dead. (2) Security Mode Command now carries **IMEISV request (0xE-)** and **Additional 5G security information (0x36) with RINMR** — a real UE sends only cleartext IEs in the unprotected initial Registration Request (TS 24.501 §4.4.6), so without RINMR the AMF never saw Requested NSSAI/5GMM capability; the mislabelled `HashAMF` field (0x36 is not HashAMF in 5GS) was replaced by the typed `Additional5GSecurityInfo`. (3) `handleSecurityModeComplete` now processes the message body: the retransmitted full Registration Request in the NAS message container updates `ue.RequestedNSSAI` before Phase3 computes the Allowed NSSAI, and the IMEISV is decoded (new BCD digit decode in `DecodeMobileIdentity`) and stored as `ue.PEI`. (4) InitialContextSetupRequest **UE-AMBR** no longer hardcoded 1 Gbps: the UDM am-data `subscribedUeAmbr` (TS 29.571 BitRate strings; previously parsed-then-dropped) now reaches the gNB (TS 38.413 §9.3.1.58), with 1 Gbps fallback when absent. (5) `PDUSessionResourceFailedToSetupListSURes` in the PDU Session Resource Setup Response is now parsed; failed PSIs are released at the SMF (DeleteSMContext → frees UE IP + PFCP) and removed from the UE context instead of dangling (TS 23.502 §4.3.2.2.1 step 16). (6) GBR 5QIs (1–4/65–67/71–76/82–85) in the N2SM QosFlowSetupRequestList now include the mandatory **GBR QoS Flow Information** (TS 38.413 §9.3.1.12) — a real gNB rejects a GBR flow without it. (7) Registration Request decoder hardened for real-UE optional IEs: LADN indication (0x74/0x7E) skipped as TLV-E (1-byte skip shifted the parser), bogus 0x1x→0x10 IEI remap removed, 5GMM capability (0x10) stored. UERANSIM interop verified in source (`.fork`): RINMR/IMEISV-request/NAS-message-container all handled by v3.2.8. Known gaps flagged, not fixed: no Nudm_SDM Subscribe after am-data fetch; no ePCO in the Establishment Accept (real UEs get no DNS server via PCO); UE Radio Capability not forwarded in later HandoverRequest. New regression tests: `shared/nas/conformance_audit_test.go`, `nf/amf/internal/ngap/conformance_audit_test.go`, `nf/smf/internal/server/gbr_qos_test.go`, `nf/amf/cmd/amf/clients_test.go` [TS 24.501 §4.4.6/§5.4.2/§8.2.25/Table 8.2.6.1.1, TS 38.413 §9.3.1.12/§9.3.1.58/§8.4.1, TS 23.502 §4.2.2.2.2/§4.3.2.2.1]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-15] amf: **Fix real-UE registration loop — DL NAS security header type under NEA0** — a real Nokia UE (UPV lab, `null_ciphering: true`) authenticated and completed Security Mode, but silently discarded every Registration Accept and re-registered every ~20 s with a fresh SUCI (no Registration Complete, no PDU session, gNB releasing it on `user-inactivity`). Root cause in `nf/amf/internal/nas/nas.go` `sendNASSecured`: when the selected cipher is 5G-EA0 it downgraded the DL security header type from **0x02** (integrity protected and ciphered) to **0x01** (integrity only). Per TS 24.501 §4.4.5 every DL NAS message after security activation must be **0x02 even with 5G-EA0** (the null cipher is a no-op; the inner PDU stays plaintext, so Wireshark visibility is unchanged). UERANSIM leniently accepts 0x01, masking the bug in the lab; a real UE strictly requires 0x02. Pcap-confirmed (Registration Accept frames carried `sec-hdr 1`). Fix: always use SHT 0x02 in `sendNASSecured` — covers Registration Accept and all post-SMC DL NAS (incl. `sendNASSecuredViaDownlink`); `unwrapNASSecurity` already handled UL 0x02 under NEA0. This matches the behavior already documented in `nf/amf/CLAUDE.md §7`. Regression test `TestSendNASSecured_SecurityHeaderTypeAlways02` (NEA0 + NEA2) [TS 24.501 §4.4.5/§9.3.1, TS 33.501 §6.7.2]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-16] amf: **Fix NW-initiated PDU Session Release — SMF DeleteSMContext failed with "context canceled"** — releasing a PDU session from the network (`DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}`) left the session alive in the SMF and the PFCP session installed on the UPF: the AMF logged `SMF DeleteSMContext failed on NW PDU release … error: context canceled` ~5 ms after the Release Command. Two defects in `InitiateNetworkPDUSessionRelease` (`nf/amf/internal/nas/nas.go`): (1) the SM context deletion ran in a goroutine bound to the **triggering HTTP request's context**, which the mgmt handler cancels the instant it returns 202 — the SBI DELETE to `nsmf-pdusession` was aborted mid-flight, every time (the UE-initiated path shares the goroutine shape and is hardened the same way). (2) The deletion was fired **immediately after** the Release Command, inverting TS 23.502 §4.3.4.3: the SM context release is step 7 (`Nsmf_PDUSession_UpdateSMContext`, which drives the step-8 N4 teardown) and must follow the UE's **PDU Session Release Complete** (step 5), not race the step-3 N2 command. Fix: the release is now tracked in `Handler.pendingRelease` between the Release Command and the UE's confirmation; the 5GSM Release Complete (0xD4, previously only logged) completes it, deleting the SM context on a context detached from the trigger (`context.WithoutCancel` + 10 s timeout) and only then dropping the session from the UE context. A **T3592 guard (9 s, TS 24.501 §10.3)** completes the release anyway if the UE never answers, so a silent UE cannot leak a session; completion is idempotent, so the Release-Complete/guard race is safe. Validated live E2E: AMF `NW PDU Session Release Command sent` → `PDU Session Release Complete received` → `SM context deleted at SMF` (OK) → SMF `releasing session` + `PFCP SessionDeletion sent` → UPF `PFCP Session deleted` (SEID freed, UE IP returned to pool); SMF session count 11→10, zero `DeleteSMContext failed`. Regression tests (`nf/amf/internal/nas/pdu_session_release_test.go`, `-race`): ordering, cancelled-trigger survival, T3592 guard, idempotency, 0xD4 wiring [TS 23.502 §4.3.4.3, TS 24.501 §8.3.9/§8.3.10/§10.3, TS 29.502 §5.2.2.3.3]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-16] amf,shared: **Fix infinite registration loop after AMF restart — wrong reject for an unknown 5G-GUTI** — after any AMF restart (`LoadFromStore` purges all UE contexts by design), every still-registered UE was bricked in a permanent ~75 s loop: `Service Request: TMSI not found — sending ServiceReject` → UE `Service Reject ignored since the MM state is not MM_SERVICE_REQUEST_INITIATED` → `MM Status [MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE]` → T3512 expiry → repeat forever, never re-registering. Root cause in `handleInitialUEMessage` (`nf/amf/internal/ngap/ngap.go`): the TMSI-not-found branch fired whenever the InitialUEMessage carried a 5G-S-TMSI and **always** sent a Service Reject — regardless of which NAS message was inside. A UE performing a mobility/periodic registration update is in 5GMM-REGISTERED-INITIATED, where a SERVICE REJECT is not a valid response (TS 24.501 §5.6.1.5.2 applies only in 5GMM-SERVICE-REQUEST-INITIATED), so it discarded it. Fix: new `nas.PeekMessageType` reads the initial NAS message type without verifying integrity — valid because per TS 24.501 §4.4.5 an initial NAS message is integrity protected but *not* ciphered, so the inner header is plaintext (returns ok=false rather than guessing when unreadable) — and `rejectForUnknownTMSI` selects the reject: **Registration Request → REGISTRATION REJECT 5GMM cause #10 "Implicitly de-registered"** (TS 24.501 §5.5.1.3.5 → UE enters 5GMM-DEREGISTERED.NORMAL-SERVICE and performs a fresh initial registration with SUCI), **Service Request / CP Service Request / unreadable → SERVICE REJECT cause #9** (unchanged). Verified against UERANSIM v3.2.8 source (`receiveMobilityRegistrationReject`: cause #10 → `switchMmState(MM_DEREGISTERED_NORMAL_SERVICE)`). Second defect fixed in the same branch: after sending the reject the AMF deleted its temp context but left the gNB's RRC/NGAP connection up, so the UE's re-registration arrived as an `UplinkNASTransport for unknown AMF UE NGAP ID` and was dropped (~16 s T3510 stall); the AMF now sends a **UEContextReleaseCommand** (TS 38.413 §8.3.3, NAS normal-release cause) addressing the gNB directly — `SendUEContextReleaseCommandForUE` resolves the gNB via `ue.GNBAddr`, which a temp context never has, so it silently skipped the release *and* returned nil, leaking the temp context — with `PendingRemoval` + watchdog backstop. Live E2E: all 4 UEs recovered (`Periodic Registration failed [IMPLICITY_DEREGISTERED]` → `Sending Initial Registration` → registered), zero `unknown AMF UE NGAP ID` warnings (was one per reject). Residual: UERANSIM fires its re-registration instantly instead of waiting for the RRC release, so its first attempt races and it recovers on T3511 (~11 s) instead of immediately — a UE-side quirk, not a core defect. Tests: `shared/nas/peek_test.go` (plain/integrity-protected/ciphered/short), `nf/amf/internal/ngap/unknown_tmsi_reject_test.go` (reject selection per message type + wire-decodability) [TS 24.501 §4.4.5/§5.5.1.3.5/§5.6.1.5.2/§9.11.3.2, TS 38.413 §8.3.3/§9.3.1.2]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-16] amf: **AMF restart no longer orphans SMF/UPF sessions (TS 23.007 §16)** — `Manager.LoadFromStore` purges every persisted UE context on startup by design (after a restart all gNB SCTP associations are gone, so the contexts are stale), but those PostgreSQL rows were the AMF's *only* record of which PDU sessions existed: purging them without telling the SMF orphaned an SMF session + a UPF PFCP session + a UE IP **per PDU session, permanently, on every restart**. Symptom: duplicate live sessions for the same SUPI/PSI accumulating in `GET /nsmf-management/v1/sessions` (e.g. `imsi-…0001` psi 1 on both `10.60.0.5` and `10.60.0.7`) and IP pools draining. Fix: `LoadFromStore` now calls `releaseStaleSMContexts` **before** `PurgeAllUEContexts` — new `store.ListAllUEContexts` (all rows regardless of 5GMM state; a UE can own PDU sessions outside 5GMM-REGISTERED) feeds a `DeleteSMContext` per session, which drives the SMF's N4 teardown and frees the UE IP. The releaser is injected via `Manager.SetSMContextReleaser` (wired in `cmd/amf/main.go` with a 5 s per-call timeout) so `internal/context` keeps no dependency on the SBI layer; nil releaser = no-op for tests/dev. Best-effort by design: list or release failures are logged and the purge proceeds, so a booting or unreachable SMF can never block AMF startup. Live E2E: session established → `docker compose restart amf` → `amf: released stale SM contexts from previous run released=1 failed=0` before the purge → SMF session count 1→0 → UPF `PFCP Session deleted` (SEID 17); previously that session leaked forever. Tests (`nf/amf/internal/context/startup_sm_release_test.go`, `-race`): release-before-purge ordering, release failure still purges, list failure still purges, no-releaser no-op, empty smContextRef skipped [TS 23.007 §16, TS 29.502 §5.2.2.3.3]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-16] amf,shared,mgmt-portal: **Unauthorized S-NSSAI no longer silently substituted; portal subscriber delete no longer orphans rows** — reported as "a slice added from the portal is not properly set and cannot be used". Two independent defects. (1) `resolveSessionSNSSAI` (`nf/amf/internal/nas/nas.go`) answered a PDU Session Establishment Request whose S-NSSAI was outside the UE's Allowed NSSAI by **substituting `allowed[0]`** and establishing the session anyway: the AMF logged a WARN and then reported `SMF CreateSMContext succeeded`, so the UE, the SMF and the portal all saw a healthy session sitting on a slice nobody asked for, with the wrong QoS and UP path — the substitution masked every other slice misconfiguration behind an apparent success. Per TS 24.501 §5.4.5.2.5 the AMF must **not** forward the 5GSM message and must answer with a DL NAS TRANSPORT carrying 5GMM cause **#90 "payload was not forwarded"**, echoing the payload container back. The resolver's bool return flipped from "was overridden" to "is authorised" (zero S-NSSAI on failure, so a missed check cannot silently proceed); the caller now rejects via new `rejectULNASTransport`. The two legitimate fallbacks are preserved and are *not* authorisation failures: UE omits the S-NSSAI → first allowed slice; no Allowed NSSAI on the context → honour the request rather than block on missing state. `shared/nas`: `DLNASTransport` gained the **5GMM cause IE (IEI 0x58, TV — 2 bytes, no length octet)**, absent from the codec, placed after the PDU session ID per Table 8.7.2.1.1; new causes #90/#91/#92. Note `DLNASTransport.Cause5GSM` still encodes IEI 0x37, which Table 8.7.2.1.1 assigns to the back-off timer — pre-existing, unused on this path, left untouched. Live E2E (UE4, portal-added gaming slice 1/001234 absent from `ue-bronze.yaml` `configured-nssai`): AMF `… rejecting PDU session result=REJECT cause=90 allowed_nssai=1/000001,3/000001`, **zero** SMF involvement, and UERANSIM independently decoded it — `SM forwarding failure for message type[193] with cause[PAYLOAD_NOT_FORWARDED]` → `Aborting SM procedure` — confirming the 0x58 TV encoding interoperates with a third-party decoder; regression-checked that an authorised slice (1/000001) still establishes normally (PSI 3, 10.60.0.2). (2) `Store.DeleteSubscriber` (`tools/mgmt-portal/internal/store/store.go`) deleted only 3 of the 6 `subscription_*` tables — it removed `subscription_smf` but not the similarly-named and distinct `subscription_sm` (session management subscription data), and never `subscription_policy` / `subscription_sm_policy` — so a deleted SUPI left orphaned sm-data and URSP/SM-policy rows that a re-created SUPI silently inherited. All six are now reaped; `subscription_policy.supi` is nullable and `DELETE … WHERE supi = $1` never matches the NULL operator-default row (verified live). Tests: `nf/amf/internal/nas/session_snssai_test.go` (authorised → subscription entry incl. operator DNN; unauthorised → rejected with zero S-NSSAI; SST-match/SD-mismatch; the two fallbacks), `shared/nas/transport_test.go` (0x58 TV layout + IE order, IEI absent when nil, cause values) — `resolveSessionSNSSAI` previously had **zero** coverage [TS 24.501 §5.4.5.2.5/§8.7.2/§9.11.3.2 Table 9.11.3.2.1, TS 23.501 §5.15.5.2.1, TS 23.502 §4.3.2.2.1]. Not fixed here, documented in §3.6: the portal still writes no `subscription_sm` for a new slice, and the AMF/NSSF/gNB slice lists remain static YAML requiring a restart. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-16] udr,mgmt-portal,config: **Portal-provisioned slices now get session management data (no more silent OPERATOR_DEFAULT QoS)** — completes the slice-usability work started by the Allowed-NSSAI reject fix. The portal provisions a slice by writing `subscription_am` straight to PostgreSQL, but `subscription_sm` (the per-slice `DNNConfiguration` + subscribed default 5QI/AMBR the SMF reads over N10, TS 29.503 §6.1.6.2.7) was only ever generated by the UDR's startup seed, which **skips already-provisioned subscribers**. A slice added through the portal therefore reached the UE's Allowed NSSAI but had no sm-data entry: `fetchSubscribedQoS` (`nf/smf/internal/server/qos.go`) missed, returned nil, and the session came up on `OPERATOR_DEFAULT` QoS instead of the subscribed profile — silently, since a miss is not logged. Live proof before the fix: UE4's portal-added `1/001234` was absent from its `sm_data` while present in `subscription_am`. Fix keeps the slice→QoS mapping in **one** place: the sm-data derivation was factored out of `SeedTestSubscriberWithNSSAI` into exported `store.BuildSMSubscriptions` (now also honouring the portal's per-slice DNN — `SNSSAISubscribed.DNN` — instead of hardcoding `"internet"`, so a slice with a non-default DNN gets a matching `DNNConfiguration`), plus `store.SyncSMDataFromAM` which re-derives sm-data from the slices currently in am-data. Exposed as a new **internal, non-3GPP** UDR endpoint `POST /nudr-internal/v1/subscribers/{supi}/sync-sm-data`, which the portal calls after every subscriber create/update (`syncSMData` in `internal/api/subscribers.go`, best-effort like the existing `deregisterUE` — the am-data write is already committed and a down UDR must not fail provisioning; `PUT` now returns `sm_data_synced`). Deliberately **not** duplicated in the portal: it is a separate Go module whose Dockerfile only copies `tools/mgmt-portal`, so it cannot import `shared/`, and `nf/udr/internal/store` is import-restricted — a copy drifted from the real `DefaultQoSForSlice` within minutes while being written (silver is 5QI **8** not 80; bronze falls through to the **default** 5QI 9; gold's ARP is `MAY_PREEMPT`), which is exactly the failure mode this avoids. New portal env var `UDR_URL` (`https://udr:8005` — UDR is on **8005**, not UDM's 8003) wired in docker-compose. `config/operator.yaml` gains `1/001234`: it is the seed source, and being the only file missing that slice meant every `make down -v` reseed dropped it while AMF/NSSF/gNB configs kept it. Live E2E: portal `PUT` adding `1/001234` to `imsi-…0001` → `{"sm_data_synced":true}` → UDR `sm-data resynced from am-data slice_count=2` → `subscription_sm` shows `1/000001 dnns=internet, 1/001234 dnns=ims` with a non-zero 5QI → UE re-registers → **the ~1/sec PDU-session reject loop stops (0 in 60 s)** and PSI 2 comes up PS-ACTIVE on `sd: 0x001234` → SMF logs `subscribed default QoS fetched` for **both** `dnn=internet` and `dnn=ims`, i.e. no fallback. Also documented (§3.6): the slice's DNN must match the `apn` the UE requests for that slice — sm-data is keyed by (DNN, S-NSSAI), so `dnn=gaming` against a UE asking `apn: 'ims'` still falls back to OPERATOR_DEFAULT (observed live during validation). Tests: `nf/udr/internal/store/sm_data_sync_test.go` — portal DNN keys the DNNConfiguration, empty DNN still defaults to internet (seed unchanged), per-slice 5QI/AMBR pinned to the UDR's real defaults, resync adds a new slice, resync drops a revoked slice, unknown SUPI errors [TS 29.503 §6.1.6.2.7, TS 29.505 §5.2.3, TS 23.501 §5.15]. docs: update CLAUDIA_5GC_MANUAL
