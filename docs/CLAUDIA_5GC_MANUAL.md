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
  IPv4 allocation; IPv6/IPv4v6 prefix delegation (control plane, TS 24.501 §9.11.4.10, plus the
  data-plane UE IP Address IE the SMF installs at UPF PFCP establishment, SMF-002 §3.22);
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
  inline ICMP responder. e2e ping verified. IPv6/IPv4v6 UE IP Address IE parsing + per-session
  RFC 4861 Router Advertisement advertiser (see §3.22, SMF-002).
- **Interfaces**: N4 PFCP **:8805/udp**, N3 GTP-U **:2152/udp**, N6 per-DNN Docker networks.
- **Per-DNN isolation**: `internet`→`10.60.0.0/24` (TUN `upfgtp0`), `ims`→`10.61.0.0/24` (TUN `upfgtp1`).
  Source of truth `config/operator.yaml`. **URR usage reporting is implemented** (see §3.21, UPF-001).

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
  # New (2026-07-23): pick the PDU session family with "pdu_session_type": "IPv4" (default) | "IPv6" | "IPv4v6"
  #   -d '{"supi":"imsi-001010000000001","app":"cloud-gaming","dnn":"internet","sst":1,"sd":"000001","5qi":3,"pdu_session_type":"IPv4v6"}'
  ```
- **Expected**: new PSI (existing untouched), `qos_source=PCF_OVERRIDE`; PCF `QoS override set`; AMF `UE policy container sent`.
  The `ue_establish` step detail echoes the exact `ps-establish <type> …` used.
- **Portal**: `/qos` → **NW-Triggered PDU Session** panel now has a **PDU session type** selector
  (IPv4/IPv6/IPv4v6); and `/ueransim` → per-UE **nr-cli** dialog → *PDU Session — Establish* has an
  IPv4/IPv6/IPv4v6 toggle + DNN input. IPv6/IPv4v6 require the patched UERANSIM (patch 0060) and a
  DNN with `ue_ipv6_prefix` (all four seeded DNNs have one); the type is validated server-side
  (`normalizePDUSessionType`, `internal/api/nwsessions.go`).
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

- **Description**: Per-DNN isolated UE IP pools + dedicated N6 Docker networks + per-DNN TUN. Each
  DNN also carries an IPv6 base prefix (`ue_ipv6_prefix`, SMF-002) the SMF delegates per-session
  `/64`s from — all four seeded DNNs have one configured (`internet`=`2001:db8:60::/56`,
  `ims`=`2001:db8:61::/56`, `gaming`=`2001:db8:62::/56`, `gold`=`2001:db8:63::/56`).
- **3GPP spec**: TS 23.501 §5.6.5 (IPv6: §5.8.2.2).
- **Config**: `config/operator.yaml` `dnns:` (single source of truth) refined by SMF/UPF `dev.yaml`.
  Editable live from the portal `/slices` DNN form (add or edit) — see Section 5/7.
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

### 3.21 PFCP Usage Reporting — URR with active Usage Reports (UPF-001)

- **Description**: The SMF installs a **Usage Reporting Rule (URR)** in the PFCP Session
  Establishment Request (URR ID 1; Measurement Method VOLUM+DURAT; Reporting Triggers
  PERIO+VOLTH; Volume Threshold + Measurement Period from config). The UPF measures per-session
  uplink/downlink volume + packet counts on the GTP-U datapath and, on a **volume-threshold
  (VOLTH)** crossing or a **periodic (PERIO)** timer, emits a **PFCP Session Report Request
  (msg type 56)** carrying a Usage Report IE (URR ID, UR-SEQN, Usage Report Trigger, Volume
  Measurement, Duration Measurement) to the SMF. The SMF's persistent PFCP receiver (:8805)
  consumes it, logs total/UL/DL volume + duration + trigger, and replies with a **Session Report
  Response (msg type 57, Cause = Request accepted)**; unknown SEID → Cause = Session context not
  found (no session fabricated). The VOLTH baseline is re-armed after each report. This is the
  prerequisite (and charging hook point) for future Nchf converged charging.
- **3GPP spec**: TS 29.244 §5.2.2.4 (URR handling), §7.5.5 (Session Report Request), §7.5.8/§7.5.9
  (Usage Report / Session Report Response), §8.2.13 (Volume Threshold), §8.2.5 (Volume Measurement),
  §8.2.41/§8.2.44 (Reporting/Usage Report Triggers). UR-SEQN is IE type **104** (not Sequence
  Number type 52).
- **NFs involved**: UPF (measure + emit) → SMF (install URR + consume). N4 PFCP/UDP only, no SBI.
- **How to trigger**:
  ```bash
  make ueransim UE_COUNT=1
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4 --dnn internet"
  # generate >1 MB of user-plane traffic to cross the VOLTH threshold:
  docker exec ueransim-ue ping -I uesimtun0 -c 900 -s 1400 -i 0.003 172.30.3.100
  docker logs upf | grep "Session Report Request sent"    # trigger VOLTH / PERIO, ur_seqn, volumes
  docker logs smf | grep "Usage Report consumed"          # total/UL/DL volume + duration_s
  ```
- **Expected outcome**: UPF logs `PFCP Session Report Request sent` (trigger VOLTH at ≥1 MB, PERIO
  every 60 s) and `PFCP Session Report Response received` (cause 1); SMF logs `PFCP Usage Report
  consumed` with matching volume/duration. Metrics: `fivegc_upf_usage_reports_total{trigger}` and
  `fivegc_procedure_total{nf="SMF",procedure="UsageReporting",result="OK"}` (equal counts). Grafana:
  UPF dashboard "Usage Reporting (PFCP N4)" row. On the wire (N4 UDP/8805): well-formed msg type
  56/57 pairs, zero malformed frames, UR-SEQN dissects as IE type 104.
- **Known limitations**: Volume Measurement is cumulative-since-session-start (delta accounting to be
  added before Nchf charging); single URR per session (id 1); the SMF advertises F-SEID node IP
  0.0.0.0 so the UPF learns the SMF report address from the establishment transport source IP; the
  UPF reporter sweep is a background goroutine with no OTel span.

### 3.22 IPv6/IPv4v6 PDU Session Prefix Delegation — data plane (SMF-002)

- **Description**: Completes the IPv6/IPv4v6 PDU session flow whose control-plane half (requested
  type decode, `/64` + IID allocation, PDU Address IE, N2 `PDUSessionType`) shipped earlier. The
  SMF's `sendPFCPSessionEstablishment` now builds a **granted-type-aware PFCP UE IP Address IE**
  (TS 29.244 §8.2.62): IPv4-only keeps the pre-existing flags `0x02` (byte-identical, zero
  regression); IPv6-only sends flags `0x01` with the full 128-bit UE address (delegated `/64`
  network + the SMF's `::1` interface identifier); IPv4v6 sends flags `0x03` with both. IPv6-only
  sessions now also trigger the PFCP establishment call (previously gated off when there was no
  IPv4 pool address). The UPF parses the V6 address field plus the PDI's Network Instance (DNN)
  into `Session.UEIPv6`/`Session.DNN`, and — new package `nf/upf/internal/ra` — builds a spec-exact
  **RFC 4861 ICMPv6 Router Advertisement** (Prefix Information option, L=1/A=1, `/64`, ICMPv6
  pseudo-header checksum) and starts a **per-session advertiser goroutine**: periodic (bounded
  `ra.MaxRtrAdvInterval` = 30 s) once the DL tunnel (DL TEID + gNB IP) is known from PFCP Session
  Modification, plus an immediate unicast RA when an ICMPv6 Router Solicitation (type 133) is
  decapsulated from the uplink. The RA is delivered **downlink over N3 GTP-U to the gNB** (the
  spec-correct recipient is the UE, not the N6 TUN). The advertiser is stopped on PFCP Session
  Deletion. Human sign-off (2026-07-22) authorized crossing the PFCP-session-management-path hard
  stop, same precedent as UPF-001.
- **3GPP spec**: TS 23.501 §5.8.2.2 / §5.8.2.2.2; TS 23.502 §4.3.2; TS 29.244 §8.2.62 (UE IP
  Address IE); RFC 4861 §4.1/§4.2/§4.6.2/§6.2.1/§6.2.6 (RS/RA, Prefix Information option, timers);
  RFC 4443 §2.3 (ICMPv6 checksum); RFC 4862 (SLAAC).
- **NFs involved**: SMF (`nf/smf/internal/server/ipv6.go` `buildUEIPAddressIE`/`ueIPv6Address`,
  `server.go` `sendPFCPSessionEstablishment`) → UPF (`nf/upf/internal/pfcp/server.go`
  `handleSessionEstablishment`, `startRAAdvertiser`/`emitRA`/`TriggerSolicitedRA`;
  `nf/upf/internal/gtpu/server.go` `SendDownlink`/`handleInnerIPv6`; `nf/upf/internal/ra`).
- **How to trigger**: live, via a patched UERANSIM UE (`tools/ueransim/patches/0060-ipv6-pdu-session.patch`
  — see §4a). Requires all four seeded DNNs to have `ue_ipv6_prefix` configured (they do, see
  Section 7):
  ```bash
  make ueransim   # standard UE registers with its default (IPv4) session
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4v6 --dnn internet --sst 1 --sd 000001"
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"    # session-type: IPv4v6, address: 10.60.0.x + iid ::1
  docker exec ueransim-ue ip -6 addr show dev uesimtun1               # global 2001:db8:60::1/64, SLAAC-derived
  docker exec ueransim-ue ip -6 route show dev uesimtun1              # default via fe80::1 proto ra (RA-installed)
  ```
  Unit + PFCP-round-trip coverage (still the byte-exact source of truth for the wire format):
  ```bash
  go test ./nf/upf/internal/ra/...          # RFC 4861 RA/RS byte-exact codec (13 tests)
  go test ./nf/upf/internal/pfcp/...        # PFCP parsing + advertiser lifecycle (5 new tests)
  go test ./nf/smf/internal/server/... -run BuildUEIPAddressIE   # granted-type-aware IE (5 tests)
  ```
- **Expected outcome**: `nf/upf/internal/pfcp/ipv6_ra_test.go` drives a real PFCP/UDP Session
  Establishment carrying an IPv6 UE IP Address IE + DNN, then a Session Modification that learns
  the DL tunnel — the RA advertiser is proven to **skip** ticks silently before the tunnel is known
  and to **emit** a well-formed RA (ICMPv6 type 134 at the expected offset) once it is; a
  `TriggerSolicitedRA` call proves the unicast path (RA destination = the solicitation's source);
  Session Deletion proves the advertiser goroutine stops. `nf/smf/internal/server/ipv6_test.go`
  proves the IPv4 UE IP Address IE bytes are unchanged from before IPv6 support existed.
  Live (2026-07-22, patched UERANSIM): a granted IPv4v6 session got TUN address `10.60.0.2` +
  kernel-SLAAC'd `2001:db8:60::1/64` (`valid_lft`/`preferred_lft` matching the RA's configured
  2592000s/604800s to the second) and a RA-installed default route (`expires 1798s`, matching the
  1800s Router Lifetime) — proof the full NAS→PFCP→RA→SLAAC chain works end-to-end, not just unit
  tests. The original PSI (IPv4, `internet`) was untouched throughout (regression-free).
- **N6 forwarding + egress**: general IPv6 forwarding to N6 with `ip6tables` MASQUERADE is now
  implemented (§3.22b) — a UE with an IPv6/IPv4v6 session reaches the N6 bridge gateway
  (`ping -6 fd00:6::1`), not just the router address. Reaching the *real* public IPv6 internet
  additionally depends on the Docker **host** having IPv6 + NAT66 (environment-dependent; absent on
  the WSL2 dev host).
- **Known limitations**: one `/64` per PDU session (no multi-prefix PIO); the gaming/gold DNNs have
  no N6 Docker network at all (IPv4 or IPv6), so egress there is unavailable for both families
  until their networks are added (see §3.14).

### 3.22a Two live bugs found validating SMF-002/UERANSIM-0060 (2026-07-23)

Found and fixed while checking why the UE's IPv6 address "looked wrong" and the portal showed
`ue_ip: "<nil>"` for a pure-IPv6 session:

1. **UPF `Session.UEIPv6`/`UEIP` corruption from a reused UDP buffer.** `nf/upf/internal/pfcp/server.go`
   `Server.Start` reuses one 2048-byte buffer for every `ReadFromUDP` call; go-pfcp's
   `UEIPAddress()` IE decode returns `net.IP` slices that **alias** that buffer
   (`net.IP.To16()` doesn't copy a 16-octet input), so every later PFCP message — any session,
   including heartbeats — silently overwrote every previously-stored session's IP in place. Latent
   since before SMF-002 (`UEIP` is normally read once, synchronously, right after establishment);
   the new per-session RA advertiser goroutine was the first code to hold onto and **re-read** the
   value on a delay, which is what exposed it — two concurrent IPv6 sessions' `/64` prefixes
   visibly swapped/corrupted in the RA every other ~5s tick (byte-level: the "wrong" value was
   always the *other* session's address, offset — a classic shared-buffer tell). Fixed by
   deep-copying (`make`+`copy`) `ueIP`/`ueIPv6` in `handleSessionEstablishment`, mirroring the
   `GNBIP` copy pattern already present a few lines below. Also added `seid`/`dlTEID`/`gnbIP` to
   the "Router Advertisement sent" log line — their absence is what made this take an extra round
   to diagnose.
2. **SMF `persistSession` wrote the literal string `"<nil>"` into Postgres.** `sess.UEIP.String()`
   was called unconditionally; Go's `net.IP.String()` returns `"<nil>"` (not `""`) for a nil IP,
   and a pure-IPv6 session has no IPv4 `UEIP` at all. Fixed by guarding `sess.UEIP != nil` and
   falling back to the derived full IPv6 address (`ueIPv6Address(sess.UEIPv6Prefix)`) so the
   portal shows something meaningful and the row isn't hidden by the `WHERE ue_ip != ''` filter
   `tools/mgmt-portal/internal/store/store.go` `ListSessions` applies.
3. **A fifth UERANSIM IPv4-only guard**, on the gNB's uplink **data-plane** path this time, not
   session setup: `gnb/gtp/task.cpp` `GtpTask::handleUplinkData` silently dropped any uplink
   packet whose IP version nibble wasn't 4 — found only after fixing the first four (the
   session-establishment-time guards, patch `0060`) let a `ping6` actually reach the gNB, where it
   then vanished with zero log trace and zero error, making it look like a UPF problem. Folded
   into `tools/ueransim/patches/0060-ipv6-pdu-session.patch` (see `tools/ueransim/CLAUDE.md`).

Both live E2E, re-validated after all three fixes (`make ueransim` + patched UERANSIM):
`ps-establish IPv4v6 --dnn internet --sst 1 --sd 000001` → `2001:db8:60::1/64` SLAAC address
stable across 4+ RA cycles (previously alternated with a corrupted value every other tick) →
`ping -6 -c 4 fe80::1%uesimtun1` → **4/4 received, 0% loss** → portal `GET /api/v1/sessions`
shows `"ue_ip":"2001:db8:60:1::1"` for a pure-IPv6 session (previously `"<nil>"`). IPv4 path
(`ps-establish IPv4`, `ping 10.60.0.254`) reconfirmed byte-identical/unaffected throughout.

### 3.22b IPv6 N6 forwarding + internet egress (2026-07-23)

- **Description**: general IPv6 uplink forwarding to N6 with `ip6tables` MASQUERADE, mirroring the
  IPv4 N6 data path. A UE with an IPv6/IPv4v6 PDU session can now reach the N6 network (the
  simulated internet edge), not just the UPF's own router address. Completes the IPv6 data plane
  begun by SMF-002 (RA/SLAAC) and the §3.22a echo responder.
- **3GPP spec**: TS 23.501 §5.8.2.2 / §5.6.5 (per-DNN N6). RFC 4862 (SLAAC), RFC 4861 (RA).
- **NFs / components involved**:
  - UPF `nf/upf/internal/tun/tun.go` `SetupIPv6` — per-DNN, called from `cmd/upf/main.go` when the
    DNN has a `ue_ipv6_prefix`: enables `net.ipv6.conf.{all,<tun>}.forwarding`, assigns the router
    address `<prefix-network>::fe/<len>` (`nodad`) so the whole delegated pool is on-link via the
    TUN, and installs `ip6tables -t nat POSTROUTING -s <prefix> ! -o <tun> -j MASQUERADE`.
  - UPF `nf/upf/internal/gtpu/server.go` — uplink `handleInnerIPv6` forwards general IPv6 to the
    TUN selected by UE **source** prefix (`tunRouteForIPv6`); downlink `startTUNReader` branches on
    IP version and matches IPv6 dst by delegated /64 via `SessionTable.GetByUEIPv6Prefix` (new
    `byUEIPv6Net` index — the UE forms its own SLAAC IID, so match by prefix not exact address).
  - `docker-compose.yml` — `n6-net`/`n6-ims-net` gained `enable_ipv6: true` + a ULA subnet
    (`fd00:6::/64` gw `fd00:6::1`, `fd00:7::/64` gw `fd00:7::1`) giving the UPF an IPv6 default
    route out the bridge; the `upf` service gained
    `net.ipv6.conf.all.{disable_ipv6=0,forwarding=1}` sysctls (see Section 7).
- **How to trigger** (patched UERANSIM):
  ```bash
  make ueransim
  docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4v6 --dnn internet --sst 1 --sd 000001"
  # wait for SLAAC on the new uesimtunN, then ping the N6 bridge gateway:
  docker exec ueransim-ue ping -6 -c 4 fd00:6::1
  docker exec upf ip6tables -t nat -L POSTROUTING -v -n | grep MASQUERADE   # counters increment
  ```
  **Applying the docker-compose network change** (IPAM change needs the network recreated; only the
  UPF attaches to the N6 networks):
  ```bash
  docker stop upf upf-pcap && docker rm upf upf-pcap
  docker network rm 5gc-n6 5gc-n6-ims
  docker compose --profile core up -d upf upf-pcap
  ```
- **Expected outcome**: `4/4 received, 0% loss, ttl=63` — the **63** (one hop decrement from 64)
  proves the packet was kernel-forwarded through the UPF, not answered by the inline echo
  responder. UPF logs `N6 TUN IPv6 ready` per DNN at startup.
- **Validated live (2026-07-23)**: IPv4v6 and pure-IPv6 sessions both egress to `fd00:6::1` at
  0% loss; MASQUERADE counters increment; IPv4 N6 (`ping 172.30.6.1`) unaffected.
- **Known limitations**: egress reaches the N6 bridge gateway (the simulated internet edge).
  Reaching the *real* public IPv6 internet additionally requires the Docker **host** to have IPv6
  connectivity + NAT66 — environment-dependent, absent on the WSL2 dev host (so `fd00:6::1` is the
  furthest reachable target). The UPF-side data plane is complete and would egress the moment the
  host provides an IPv6 route. Only `internet`/`ims` have N6 Docker networks (IPv4 and IPv6);
  `gaming`/`gold` have none.
- **Portal management (2026-07-22 follow-up)**: `ue_ipv6_prefix` is now a first-class portal-managed
  DNN field, not just hand-edited YAML — see `tools/mgmt-portal/internal/config/nfconfig.go`
  (`OperatorDNN`/`SMFDNNEntry`/`UPFDNNEntry`/`DNNInfo` gained the field; `validateIPv6Prefix`
  enforces the `/8`-`/64`-multiple-of-8 constraint server-side, mirroring `IPv6Pool`), `PUT
  /api/v1/dnns/{name}` (`internal/api/dnns.go`, propagates to operator.yaml+SMF+UPF, optional
  smf/upf restart), and the `/slices` DNN add/edit form + table column (`web/src/pages/Slices.tsx`).
  All four seeded DNNs were backfilled with a prefix (see Section 7 config reference) so IPv6/IPv4v6
  is now selectable network-wide, not just on `ims`.

### 3.23 Secondary Authentication / DN-AAA (SMF-003)

- **Description**: DN-specific secondary authentication/authorization during PDU Session
  Establishment. When a DNN is flagged for secondary auth, the SMF acts as the EAP
  authenticator (TS 33.501 pass-through), relaying EAP between the UE (N1, carried in the
  5GSM PDU SESSION AUTHENTICATION COMMAND `0xC5` / COMPLETE `0xC6` messages) and a DN-AAA
  server (N6). On EAP-Success the PDU Session Establishment Accept carries the EAP-Success
  and the session is established; on EAP-Failure or DN-AAA unreachable/timeout the SMF
  returns a PDU Session Establishment Reject (`0xC3`) with 5GSM cause **#29** "User
  authentication or authorization failed" and no N4/PFCP session is created (the allocated
  UE IP is released). A DNN **not** flagged for secondary auth establishes exactly as before
  (no EAP exchange — byte-identical, zero regression).
- **3GPP spec**: TS 23.501 §5.6.6, TS 23.502 §4.3.2.3, TS 24.501 (EAP message IE §9.11.2.2,
  5GSM cause §9.11.4.2).
- **NFs / components involved**:
  - SMF `nf/smf/internal/server/secondary_auth.go` — per-session secondary-auth state
    machine (pending-EAP map keyed by SUPI+PSI), the `DNAAAClient` seam (interface fronting
    a simulated in-core DN-AAA EAP server; swappable for a real RADIUS/Diameter N6 client),
    EAP start/relay, and the proceed-to-N4 vs reject decision. Gate is in
    `handleCreateSMContext`; the UE's AUTH COMPLETE (`0xC6`) is dispatched from
    `handleUpdateSMContext`. The AUTH COMMAND/RESULT/REJECT and terminal ACCEPT are pushed
    via `Namf_Communication_N1N2MessageTransfer` (mirroring the paging path), because the
    AMF's existing CreateSMContext caller unconditionally wraps the inline return as an
    Establishment Accept.
  - `shared/nas/secondary_auth.go` — new spec-faithful 5GSM codecs: PDU SESSION
    AUTHENTICATION COMMAND/COMPLETE/RESULT (`0xC5`/`0xC6`/`0xC7`) encode/decode/wrap, EAP
    message IE (LV-E mandatory form in the auth messages; TLV-E IEI `0x78` optional form in
    ACCEPT/REJECT — ordered before the Authorized QoS flow descriptions `0x79` and DNN `0x25`
    IEs per TS 24.501 Table 8.3.2.1.1), `WrapPDUSessionEstablishmentRejectBody` (`0xC3`),
    and `Cause5GSMUserAuthOrAuthorizationFailed = 0x1D` (#29).
  - Reuses `shared/crypto/eap` (RFC 3748 framing) and the existing `encodeEAPMessageLVE`
    helper — the same EAP plumbing built for AUSF-001 (EAP-AKA') and AMF-005 (NSSAA).
  - Config: per-DNN `secondary_auth` (bool, default false) + `dn_aaa_unreachable` (dev/test
    knob) under `dnns:` in `nf/smf/internal/config/config.go` (see Section 7).
- **How to trigger** (in-process; no live UE peer exists — see limitations): the network-side
  state machine is validated by unit tests (`nf/smf/internal/server/secondary_auth_test.go`,
  `shared/nas/secondary_auth_test.go`) and 4 godog scenarios
  (`nf/smf/tests/features/secondary_authentication.feature`):
  ```bash
  cd nf/smf && make test && make test-functional
  ```
- **Expected outcome**: happy path → EAP-Success → session established with EAP-Success in the
  Accept; EAP-Failure or DN-AAA unreachable → Establishment Reject with 5GSM cause #29;
  DNN without secondary auth → normal establishment, no EAP. Metrics:
  `fivegc_procedure_total{nf="SMF",procedure="SecondaryAuthentication",result="OK|REJECT"}`
  and gauge `fivegc_smf_secondary_auth_pending` (DN-AAA exchanges in flight). Grafana:
  "SMF — Secondary Authentication / DN-AAA" row in `5g-kpi-overview.json` (success rate,
  pending gauge, rate-by-result). OTel span carries `result`/`cause`/`spec_ref` attributes.
- **Known limitations**: the DN-AAA is a **simulated in-core EAP server** (same posture as the
  AUSF-simulated AAA-S for NSSAA); no real external RADIUS/Diameter DN-AAA. The live N1 UE leg
  is not exercised — UERANSIM v3.2.8 has no secondary-authentication UE support (same as
  NSSAA / EAP-AKA' / URSP). No live DNN is flagged for secondary auth in the shipped
  `dev.yaml`/docker-compose (deliberate, to keep the E2E `internet` path untouched); a test-only
  DNN is constructed in-test. Full live delivery additionally needs the AMF's N1N2 producer to
  forward the N1/N2 payload on the CM-CONNECTED path (pre-existing AMF gap, follow-up).

### 3.24 Public Warning System — Write-Replace Warning / PWS Cancel (AMF-007)

- **Description**: ETWS/CMAS-style emergency broadcast (earthquake/tsunami/presidential alert)
  delivered to every gNB connected to the AMF, independent of any UE registration, slice, or PDU
  session (TS 23.501 §5.20). The management portal plays the **CBC (Cell Broadcast Centre)** role
  — 3GPP does not standardize a CBC↔AMF protocol for 5GC, so (mirroring the DN-AAA/AAA-S in-core
  simulation precedent from SMF-003/AMF-005) the portal calls the AMF's internal mgmt API
  directly; no new NF and no invented wire protocol. The AMF builds a real NGAP **Write-Replace
  Warning Request** (ProcCode 51, non-UE-associated Class 1) and fans it out to every gNB in its
  `s.gnbs` registry — reusing the exact broadcast pattern already proven by `SendPaging` — then
  aggregates each gNB's **Write-Replace Warning Response** (`BroadcastCompletedAreaList`) keyed
  solely by `(MessageIdentifier, SerialNumber)` (no AMF/RAN-UE-NGAP-ID, since this is not
  UE-associated). A **Stop Broadcast** action sends **PWS Cancel Request** (ProcCode 32) and
  aggregates **PWS Cancel Response** (`BroadcastCancelledAreaList`) the same way. A new UERANSIM
  gNB patch decodes both requests, logs the warning, and replies per spec.
- **3GPP spec**: TS 23.041 (PWS technical realization), TS 38.413 §8.9.1 (Write-Replace Warning),
  §8.9.2 (PWS Cancel), TS 23.501 §5.20 (broadcast to the whole Warning Area).
- **NFs / components involved**:
  - AMF `nf/amf/internal/ngap/pws.go` — `BuildWriteReplaceWarningRequest`/`BuildPWSCancelRequest`
    (ASN.1 APER via `github.com/free5gc/ngap`+`aper`, no bespoke codec — both message types and
    every IE already exist in the vendored library), `SendWriteReplaceWarning`/`SendPWSCancel`
    (broadcast fan-out over `s.gnbs`), `handleWriteReplaceWarningResponse`/`handlePWSCancelResponse`
    (fan-in), and the CBS Message Information Page framing for `WarningMessageContents`
    (`encodeWarningMessageContentPages`/`DecodeWarningMessageContentPages`, TS 23.041 §9.4.2.2.5 —
    see the fix note below). `PWSKey{MessageIdentifier, SerialNumber}` is the sole correlation key.
  - AMF mgmt API (`:9002`, `nf/amf/cmd/amf/main.go`): `POST /amf/v1/pws/broadcast` (202,
    3GPP-legal defaults filled for any omitted field), `POST /amf/v1/pws/cancel` (202 known /
    404 `ErrPWSBroadcastNotFound`), `GET /amf/v1/pws/broadcast` (list) and
    `GET /amf/v1/pws/broadcast/{messageId}/{serialNumber}` (per-gNB status poll).
  - `tools/ueransim/patches/0070-pws-write-replace-warning.patch` — gNB `radio.cpp` handlers for
    `WriteReplaceWarningRequest`/`PWSCancelRequest` (stock UERANSIM drops both as "Unhandled NGAP
    initiating-message"), decoding the CBS page structure and replying with the matching
    SuccessfulOutcome (`BroadcastCompletedAreaList`/`BroadcastCancelledAreaList`, `tAI*NR` variant).
  - Portal `tools/mgmt-portal/internal/api/pws.go` + `web/src/pages/PublicWarning.tsx` — "Public
    Warning System" page: form pre-filled with 3GPP-legal defaults for every Write-Replace Warning
    IE, editable message text, Send + Stop Broadcast buttons, live per-gNB completion table.
  - `docs/procedures/PublicWarningSystem.md` — full sequence diagram, IE tables, spec-verifier
    conformance notes, and the CBC-role architecture-decision writeup.
- **How to trigger**:
  ```bash
  make ueransim
  # GSM 7-bit, Spanish (language named directly in the DCS coding group, 0x04):
  curl -X POST http://localhost:9002/amf/v1/pws/broadcast \
    -H 'Content-Type: application/json' \
    -d '{"messageIdentifier":4370,"serialNumber":1,"dataCodingScheme":4,"messageText":"Alerta: terremoto, protéjase"}'
  # UCS2 + Japanese (DCS 0x11 — 2-char ISO 639 prefix precedes the UCS2 body):
  curl -X POST http://localhost:9002/amf/v1/pws/broadcast \
    -H 'Content-Type: application/json' \
    -d '{"messageIdentifier":4371,"serialNumber":1,"dataCodingScheme":17,"language":"ja","messageText":"警報: 高台へ避難してください"}'
  curl http://localhost:9002/amf/v1/pws/broadcast/4370/1   # poll per-gNB completion
  curl -X POST http://localhost:9002/amf/v1/pws/cancel \
    -H 'Content-Type: application/json' -d '{"messageIdentifier":4370,"serialNumber":1}'
  # Portal: http://localhost:8080/pws — Alphabet + Language selectors derive the DCS
  ```
- **Expected outcome**: `202 {gnbs_targeted, messageIdentifier, serialNumber}` on broadcast; the
  status-poll endpoint shows `gnbs_completed` incrementing as each gNB's Write-Replace Warning
  Response arrives with a decoded `BroadcastCompletedAreaList`; `docker logs ueransim-gnb` shows
  the decoded warning text; `docker logs amf | grep PublicWarningSystem` shows the fan-out +
  fan-in. Cancel: `404` for an unknown `(messageIdentifier, serialNumber)`.
- **Language selection**: the message language is set via the portal's **Alphabet + Language**
  selectors, which derive the CBS Data Coding Scheme (TS 23.038 §5) — GSM 7-bit names the language
  in the DCS byte itself (coding groups 0x00-0x0F / 0x20-0x24: German … Icelandic, Unspecified),
  while UCS2 with a language uses DCS 0x11 (a 2-char ISO 639 prefix inside the message, needed for
  non-Latin scripts). The AMF mgmt API accepts an optional `language` (ISO 639) field used for the
  0x11 prefix; both AMF and gNB logs report the resolved `language`.
- **CBC persistence + re-drive**: the AMF's PWS registry is in-memory (it is a stateless relay —
  TS 23.041 puts durable warning state at the CBC), so the portal (playing the CBC) persists every
  broadcast in Postgres (`pws_broadcasts`) and reconciles it with the AMF's live per-gNB status. The
  broadcast list therefore **survives an AMF restart**: a warning the AMF no longer knows shows a
  **Stored — resend to re-establish** badge (`live:false`). `POST /api/v1/pws/resend` (portal
  Resend button) re-drives a stored warning to the gNBs — the CBC re-broadcast after an AMF/gNB
  restart (TS 23.007 §16). The list also now shows each warning's text, language, and DCS.
- **Known limitations**: no standardized 3GPP CBC↔AMF protocol exists for 5GC (portal plays the
  CBC role directly — a documented simplification, not a bug); `WarningSecurityInfo` is a
  zero-filled dev placeholder, not a real ETWS digital signature; no GSM7 language-indication
  prefix (DCS 0x10) or national-language single/locking-shift alphabet tables (TS 23.038 §6.2.1.2);
  PWS Restart Indication (§8.9.3) / PWS Failure Indication (§8.9.4, Class 2) are not implemented;
  the UE air-interface leg (SIB10/11/12) is out of scope — UERANSIM UEs do not surface received
  ETWS/CMAS SIBs.
  - **Live-pcap-caught fix (2026-07-27)**: the first live capture showed Wireshark flagging
    `WriteReplaceWarningRequest` as a **Malformed Packet** — `WarningMessageContents` was sent as
    raw text, and TS 23.041 §9.4.2.2.5 mandates a CBS Message Information Page container (1-octet
    Number-of-Pages + N×(82-octet content, 1-octet length)); the dissector read the first text byte
    as an out-of-range page count. Fixed on both the Go encoder and the gNB decoder (patch 0070
    regenerated from a clean `dev/clone-fork.sh` tree); re-captured live with zero expert-info
    warnings. See `docs/procedures/PublicWarningSystem.md` "Post-audit fixes" for the full narrative.
  - **Alphabet fix (2026-07-28)**: the page framing above was correct, but `WarningMessageContents`
    was still written as raw unpacked octets regardless of DataCodingScheme — with the portal's
    default DCS (0x00) declaring the GSM 7-bit default alphabet, Wireshark's CBS dissector tried to
    septet-unpack plain ASCII and never showed readable text. Also found: DCS 0x00 means CBS
    language **"German"**, not "unspecified", per TS 23.038 §5 Table 5 (the CBS DCS table differs
    from the SMS one — groups 0000-0011 are the language table, not "General Data Coding"). Fixed
    with a new `shared/gsm7` package (character tables + septet pack/unpack, verified against the
    spec's own worked examples, plus the full CBS DCS coding-group table) wired into
    `encodeGSM7Pages`/`encode8BitPages`/`encodeUCS2Pages`; portal default DCS moved to 0x0F (GSM7,
    language unspecified) with a 3-preset dropdown (GSM7/8-bit/UCS2) replacing the bare number
    input; gNB patch 0070 now reads DataCodingScheme and decodes to match. See
    `docs/procedures/PublicWarningSystem.md` "Post-audit fixes — 2026-07-28" for the full narrative.
  - **Language selection (2026-07-28)**: building on the alphabet fix, the portal's DCS field was
    replaced by **Alphabet + Language** selectors deriving the DCS (TS 23.038 §5). GSM 7-bit uses
    the language coding groups (DCS 0x00-0x0F/0x20-0x24 — the language is in the byte); UCS2 with a
    language uses DCS 0x11 with a 2-octet ISO 639 prefix (`shared/gsm7/language.go`
    `EncodeUCS2LanguagePrefix`/`DecodeUCS2LanguagePrefix`, wired into the AMF `encodeUCS2Pages`).
    The AMF mgmt API gained a `language` field; AMF + gNB logs emit `language[…]`. Round-trip unit
    tests cover the UCS2+language prefix; the gNB patch was regenerated and recompiled clean.

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

# IPv6 / IPv4v6 (SMF-002, patch 0060-ipv6-pdu-session.patch — stock UERANSIM only ever
# requested/accepted IPv4; the patch removes 4 artificial guards, see tools/ueransim/CLAUDE.md):
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4v6 --dnn internet --sst 1 --sd 000001"
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"                    # session-type: IPv4v6
docker exec ueransim-ue ip -6 addr show dev uesimtun1                              # SLAAC global address
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

### 3.25 Management Portal (professional view, PORTAL-UI-01…21)

The operator UI: `make portal` → **http://localhost:8080** (Go chi backend + React 18/Vite/Tailwind
frontend, embedded into the Go binary). Changelog of the redesign: see the `mgmt-portal` entries
under *Changelog*; design contract: `tools/mgmt-portal/web/STYLE_GUIDE.md`.

- **Navigation.** 13 pages in 6 domain groups (Overview · Data & Config · Runtime · Test UEs ·
  Operations · Safety) with collapsible sections; the active group auto-expands, every destination
  is ≤2 clicks away. Below `lg` the sidebar becomes an overlay drawer (focus-trapped, ESC closes).
  Routes are unchanged from the pre-redesign IA, so old bookmarks still work.
- **Deep links / F5.** The Go router serves the SPA shell for any non-API GET navigation and a JSON
  404 for `/api/**` + `/ws/**`, so refreshing on `/qos`, `/subscribers`, … works
  (`internal/api/router.go` `spaFallback`, regression-tested in `router_test.go`).
- **Theming.** Two-state Light/Dark toggle in the header; the choice persists in `localStorage.theme`
  and overrides the OS, while a first visit follows `prefers-color-scheme`. An inline bootstrap in
  `index.html` sets the class before the stylesheet paints (no flash of the wrong theme).
  No "System" option by design.
- **Design system.** 41 semantic tokens (`web/src/index.css`, light `:root` + dark `.dark`) mapped to
  Tailwind utilities, plus a primitive layer (`web/src/components/ui/`) — Button/IconButton, Input,
  Checkbox, Select, SegmentedControl, Field, Card, Section, PageHeader, Badge, Table, Tabs,
  Disclosure, Loading, EmptyState/DegradedState/ErrorState, Toast, Modal/Dialog/ConfirmDialog,
  ChartWrapper, RangeControl. Pages compose primitives; **raw palette utilities are banned** and
  machine-checked (see below). Every foreground token is contrast-verified in both themes.
- **Charts.** The Dashboard answers "is the core healthy right now?" with six 3GPP-grounded range
  charts fed by the curated `GET /api/v1/metrics/range` endpoint (whitelist, no arbitrary PromQL):
  UEs registered and Initial Registration success rate (TS 28.554 §5.1), procedure results by
  outcome (TS 23.502), active PDU sessions (§5.2), 5G-AKA authentications by result
  (TS 33.501 §6.1.3.2) and N3 user-plane throughput UL/DL (§5.3). Presets 15 m/1 h/6 h/24 h plus a
  validated custom range, a sliding window while polling, per-chart accessible table fallback, and
  "Prometheus unavailable" rendered distinctly from a zero line (an idle success-rate window is a
  gap, never a 0/100% line).
- **Instant KPIs.** The KPI row above the charts carries six `StatCard`s: the four operational counts
  (NFs online, provisioned subscribers, active PDU sessions, NFs via NRF) plus two **instant
  5-minute success rates** from `GET /api/v1/metrics/summary` — Initial Registration
  (`fivegc_procedure_total`, TS 28.554 §5.1) and PDU session establishment (`fivegc_pdu_session_total`,
  §5.2). Both are **nullable**: a window with no attempts, an empty result, or a non-finite sample
  renders **"—"**, never a fabricated 0%/100%. The summary's PDU-session fallback now sums
  `fivegc_pdu_sessions_active` (the long-dead `smf_sessions_total` count is gone).
- **Accessibility bar.** WCAG 2.1 AA: visible focus everywhere, keyboard-operable overlays that trap
  focus / close on ESC / restore focus, accessible names on icon-only controls, status never
  conveyed by colour alone, `prefers-reduced-motion` honoured. No text below `text-xs`;
  no light/thin weights (projector legibility).
- **Verification** (no frontend test runner, by design — from `tools/mgmt-portal/web`):
  `npm run build` (tsc + vite) **and** the three `STYLE_GUIDE.md` § 10 enforcement commands — the
  raw-colour grep, the fill-as-text grep, and `node scripts/contrast-audit.mjs` (38 WCAG pairs ×
  2 themes, exit 1 on failure). Backend: `go test ./internal/...` (includes `router_test.go`,
  `client_test.go`, `metrics_test.go`).

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
| `n4.report_listen` (default `0.0.0.0:8805`) | `nf/smf/config/dev.yaml` | Bind address of the SMF persistent PFCP receiver that consumes UPF Session Report Requests (URR usage reports). Intra-Docker-network UDP — no published port needed. Ref: TS 29.244 §6.2.1 (UPF-001) |
| `n4.volume_threshold_bytes` (default `1000000`) | `nf/smf/config/dev.yaml` | Volume Threshold installed in the URR — UPF emits a VOLTH Usage Report once cumulative session volume crosses this many bytes (re-arms after each report). Ref: TS 29.244 §8.2.13 (UPF-001) |
| `n4.measurement_period_seconds` (default `60`) | `nf/smf/config/dev.yaml` | Measurement Period installed in the URR — UPF emits a PERIO Usage Report every N seconds. Ref: TS 29.244 §8.2.42 (UPF-001) |
| `dnns[].ue_ipv6_prefix` (e.g. `2001:db8:61::/56`) | `nf/upf/config/dev.yaml` | Per-DNN IPv6 base prefix anchor, mirroring the SMF's pool of the same key — used as a config-drift guard/log for the Router Advertisement advertiser; the `/64` actually advertised always comes from the PFCP UE IP Address IE. Ref: TS 23.501 §5.8.2.2 (SMF-002) |
| `dnns[].secondary_auth` (bool, default `false`) | `nf/smf/config/dev.yaml` | When true, the SMF triggers DN-AAA secondary authentication (EAP round-trip) during PDU Session Establishment for that DNN; false (all shipped DNNs) = normal establishment, no EAP. Ref: TS 23.501 §5.6.6, TS 23.502 §4.3.2.3 (SMF-003) |
| `dnns[].dn_aaa_unreachable` (bool, default `false`) | `nf/smf/config/dev.yaml` | Dev/test knob: simulates the DN-AAA being unreachable so establishment is rejected with 5GSM cause #29. For local testing of the failure path only. Ref: TS 24.501 §9.11.4.2 (SMF-003) |
| `dnns[].ue_ipv6_prefix` (e.g. `2001:db8:60::/56`) | `nf/smf/config/dev.yaml`, `config/operator.yaml` | Base IPv6 prefix (CIDR, length `/8`-`/64`, multiple of 8) the SMF's `IPv6Pool` delegates per-session `/64`s from for IPv6/IPv4v6 PDU sessions. Empty/absent = the DNN is IPv4-only and v6 requests are downgraded. All four seeded DNNs (`internet`=`2001:db8:60::/56`, `ims`=`2001:db8:61::/56`, `gaming`=`2001:db8:62::/56`, `gold`=`2001:db8:63::/56`) now have one configured. Manageable from the portal `/slices` DNN edit form (`PUT /api/v1/dnns/{name}`) — writes `operator.yaml`+SMF+UPF in one call; SMF/UPF only read config at startup, so check "Restart SMF and UPF" to apply. Ref: TS 23.501 §5.8.2.2 (SMF-002) |

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
| n6-net / n6-ims-net | 172.30.6.0/24 + `fd00:6::/64` / 172.30.7.0/24 + `fd00:7::/64` | UPF egress to DN (per-DNN isolation); `enable_ipv6: true` with ULA gateway `fd00:6::1`/`fd00:7::1` for IPv6 egress (§3.22b) |
| n9-net | 10.45.9.0/24 | inter-UPF GTP-U (future) |

Per-DNN UE pools: internet `10.60.0.0/24` + `2001:db8:60::/56` (N6 `172.30.6.0/24` + `fd00:6::/64`),
ims `10.61.0.0/24` + `2001:db8:61::/56` (N6 `172.30.7.0/24` + `fd00:7::/64`).

The **upf** service sets `net.ipv4.ip_forward=1` plus (for IPv6 N6, §3.22b)
`net.ipv6.conf.all.disable_ipv6=0` and `net.ipv6.conf.all.forwarding=1` under `sysctls:`.

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
- [2026-07-03] observability: **Grafana dashboard audit + fixes** (branch `fable-grafana-check`, full live-traffic verification) — 7 dashboards / 91 panels audited against a running stack; 33 panels fixed in 5 per-dashboard commits: (1) all 15 "Success/Reject/Fallback Rate" stats replaced `clamp_min(denom,1)` (which degenerated percentages at lab traffic rates, e.g. 100% auth success displayed as 0.34%) with `100 * (sum(rate(num)) or vector(0)) / (sum(rate(den)) > 0)`; (2) plain shared-registry gauges (`fivegc_upf_pfcp_sessions_active`, `_bsf_bindings_`, `_nef_subscriptions_`, `_lmf_subscriptions_`) are exported as 0 by all 13 NFs — panels scoped to the owning NF via `{nf="..."}`; (3) dead GC panel (`go_gc_duration_seconds{quantile="0.99"}` doesn't exist → `quantile="1"`); (4) unit fixes (`ops`→`opm` for ×60 queries, `Mbits`→`bps` for throughput, RSS to raw bytes, `round(increase(...))`). Flagged-not-fixed code gaps: `SBIRequestsTotal`/`SBIRequestDurationSeconds`/`NGAPMessagesTotal` defined but never incremented (8 permanently-empty SBI panels; `metrics.SBIMiddleware` has no call sites); `ProcedureTotal` never emitted for ServiceRequest / NetworkDeregistration / any SMSF procedure; `fivegc_handover_total` only counts OK; `fivegc_ue_connected` over-counts stale N2 contexts (read 7 with 1 live UE); no QoS-modification metric exists (NW-initiated 5QI changes are invisible to Prometheus).
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
- [2026-07-21] upf,smf: **PFCP Usage Reporting (URR) with active Usage Reports** (UPF-001, TS 29.244 §5.2.2.4/§7.5.5) — URRs were installed nowhere and emitted no reports, blocking charging. The SMF now installs a **Create URR** (URR ID 1; Measurement Method VOLUM+DURAT; Reporting Triggers PERIO+VOLTH; Volume Threshold + Measurement Period from new `n4.{volume_threshold_bytes,measurement_period_seconds}` config) in the PFCP Session Establishment Request, referenced from the Create PDR. The UPF parses it (`URRState` on the session, `SMFAddr` learned from the establishment transport source IP), counts per-session UL/DL volume+packets on the GTP-U datapath (`handlePacket` UL, `sendGTPU` DL), and a `runUsageReporter` sweep goroutine (2 s tick) emits a **PFCP Session Report Request (msg 56)** with a Usage Report IE (URR ID, **UR-SEQN IE type 104**, Usage Report Trigger 3-octet, Volume Measurement TOVOL/ULVOL/DLVOL+pkts, Duration Measurement) on a VOLTH crossing (baseline re-armed after each report) or the PERIO timer. The SMF gained its **first persistent PFCP receiver** (`StartPFCPReceiver` on `0.0.0.0:8805`, wired in `cmd/smf/main.go` — intra-Docker-network UDP, no docker-compose change) whose `consumeSessionReport` seam matches the SEID→session, logs total/UL/DL volume+duration+trigger, increments `fivegc_procedure_total{nf=SMF,procedure=UsageReporting}`, and replies **Session Report Response (msg 57)** Cause=Request-accepted (or Session-context-not-found on an unknown SEID, no session fabricated). New metric `fivegc_upf_usage_reports_total{trigger}` + Grafana UPF "Usage Reporting (PFCP N4)" row. **Human sign-off obtained for this PFCP-path exception.** spec-verifier caught + fixed a BLOCKER (UR-SEQN was encoded as Sequence Number IE type 52 instead of UR-SEQN type 104). Live E2E (`make ueransim UE_COUNT=1` + >1 MB ping): UPF emitted 27 reports = SMF consumed 27 (VOLTH at 1.41 MB, re-armed + fired again at 2.49 MB; PERIO every 60 s); pcap-analyzer **✅ Correct flow, 0 malformed frames, UR-SEQN dissects as IE type 104**. Tests: 8 UPF unit (`nf/upf/internal/pfcp/urr_test.go`) + 7 SMF unit (`pfcp_report_test.go`) + 5 godog (`usage_reporting.feature`). Also fixed a pre-existing `-race` flake in `nf/upf/internal/pfcp/qer_test.go` (unsynchronised QER read) and the stale BSF-001 backlog entry (was TODO, implemented in Session 11). Follow-ups: cumulative→delta volume for Nchf charging, multi-URR/session, real F-SEID node address, UPF reporter OTel span [TS 29.244 §5.2.2.4, §7.5.5, §7.5.8, §7.5.9, §8.2.5/§8.2.13/§8.2.41/§8.2.44]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-22] smf,upf: **IPv6/IPv4v6 PDU Session Prefix Delegation — data plane completed** (SMF-002, TS 23.501 §5.8.2.2/§5.8.2.2.2, TS 29.244 §8.2.62, RFC 4861/4862) — completes the control-plane-only IPv6 support shipped earlier under the same PFCP-path hard-stop exception precedent as UPF-001 (human sign-off 2026-07-22). SMF: `sendPFCPSessionEstablishment` now builds a granted-type-aware PFCP UE IP Address IE via new `buildUEIPAddressIE`/`ueIPv6Address` (`nf/smf/internal/server/ipv6.go`) — IPv4-only keeps flags `0x02` byte-identical to before (zero regression, proven by test), IPv6-only sends flags `0x01` with the full 128-bit address (delegated `/64` + the SMF's `::1` IID), IPv4v6 sends flags `0x03` with both; IPv6-only sessions now also trigger PFCP establishment (previously gated off with no IPv4 address). UPF: `handleSessionEstablishment` parses the V6 UE IP Address IE field plus the PDI's Network Instance (DNN) into new `Session.UEIPv6`/`Session.DNN` fields; new package `nf/upf/internal/ra` hand-builds a spec-exact **RFC 4861 ICMPv6 Router Advertisement** (Prefix Information option L=1/A=1, `/64`, RFC 4443 §2.3 pseudo-header checksum) and parses Router Solicitations (type 133); a new per-session advertiser goroutine (`startRAAdvertiser`/`emitRA`, bounded `ra.MaxRtrAdvInterval`=30s, RFC 4861 §6.2.1) sends it **downlink over N3 GTP-U to the gNB** once the DL tunnel is known from PFCP Session Modification, plus an immediate unicast RA (`TriggerSolicitedRA`) when a Router Solicitation is decapsulated from the uplink (`gtpu.handleInnerIPv6`, a minimal IPv6 hook alongside the untouched IPv4 decap path — no general IPv6 N6 forwarding added). New seam: `pfcp.RASender` interface implemented by `gtpu.Server.SendDownlink`, wired via `pfcpSrv.SetRASender(gtpuSrv)`/`gtpuSrv.SetPFCPServer(pfcpSrv)` in `cmd/upf/main.go` before either server starts — keeps `pfcp` from importing `gtpu`. New UPF config `dnns[].ue_ipv6_prefix` mirrors the SMF's per-DNN IPv6 pool as a config-drift guard/log (the advertised `/64` always comes from the PFCP IE, never this config). Advertiser is stopped on PFCP Session Deletion (`sess.raCancel`). No live IPv6-capable UE/gNB exists yet (UERANSIM v3.2.8 is IPv4-only on N1/N2) — validated by 13 `ra` unit tests (RA/RS byte-exact codec, checksum, defaults) + 5 new `pfcp` tests (real PFCP/UDP round trip: IPv6/DNN parsing, IPv4 unchanged, skip-until-DL-tunnel-known, immediate solicited RA, advertiser stops on deletion) + 6 new SMF tests (`buildUEIPAddressIE` flags/fields per granted type, IPv4 byte-for-byte reference match). All packages green with `-race`; `GOWORK=off go build ./nf/... ./shared/...` clean. [TS 23.501 §5.8.2.2/§5.8.2.2.2, TS 23.502 §4.3.2, TS 29.244 §8.2.62, RFC 4861 §4.1/§4.2/§4.6.2/§6.2.1/§6.2.6, RFC 4443 §2.3, RFC 4862]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-22] mgmt-portal,smf,upf,config: **Per-DNN IPv6 prefix now portal-manageable; all four DNNs backfilled with one** — SMF-002's `ue_ipv6_prefix` was previously hand-edited YAML available only on `ims`. `tools/mgmt-portal/internal/config/nfconfig.go`: `OperatorDNN`/`SMFDNNEntry`/`UPFDNNEntry`/`DNNInfo` gained a `UEIPv6Prefix` field (round-tripped through `operator.yaml`+`nf/smf/config/dev.yaml`+`nf/upf/config/dev.yaml`, `,omitempty` so IPv4-only DNNs are untouched); new `validateIPv6Prefix` mirrors the constraint enforced by `nf/smf/internal/server/ipv6.go`'s `IPv6Pool` (CIDR, length `/8`-`/64`, multiple of 8) since the portal is a separate Go module and cannot import that `internal/` package. `GetAllDNNs` now also reads SMF's DNN list (previously only operator.yaml+UPF) so a prefix set directly in `nf/smf/config/dev.yaml` (as `ims`'s was) still surfaces even before operator.yaml is backfilled. `UpdateDNNDescription` replaced by `UpdateDNN(name, description, ipv6Prefix)`, propagating a changed prefix to all three files; an empty prefix clears IPv6 support for that DNN (downgrade to IPv4-only). API: `PUT /api/v1/dnns/{name}` body gained `ue_ipv6_prefix` + `restart` (previously description-only, no restart path existed); restarts `upf` then `smf` like the add-DNN flow, since both only read this config at startup. Frontend (`web/src/pages/Slices.tsx`): the DNN add/edit form gained an always-visible IPv6 Prefix input (unlike UE IP Pool/N6 Network, which stay creation-only since changing them can strand active sessions) plus a restart checkbox that now also shows in edit mode; DNN table gained an IPv6 Prefix column. Data: `internet`/`gaming`/`gold` backfilled with `2001:db8:{60,62,63}::/56` (mirroring `ims`'s existing `2001:db8:61::/56`, and each DNN's last IPv4-pool octet) in `config/operator.yaml` + `nf/smf/config/dev.yaml` + `nf/upf/config/dev.yaml`, so IPv6/IPv4v6 PDU sessions are now selectable on every DNN, not just `ims`. Validated: `go build`/`go vet` clean on `tools/mgmt-portal/...`; `npx tsc --noEmit` clean on the frontend; `go test ./nf/smf/... ./nf/upf/...` still green (no behavioral change to the NFs themselves, config-only). No live portal E2E run (requires the stack up); config file correctness verified by inspection + the same `NewIPv6Pool` constraints the SMF already enforces at startup. [TS 23.501 §5.8.2.2]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-22] ueransim: **UERANSIM can now request/accept IPv4, IPv6, and IPv4v6 PDU sessions — new patch `0060-ipv6-pdu-session.patch`** — closes the live-testing gap noted in SMF-002's known limitations. Investigation found stock v3.2.8's NAS/ASN.1 layers already fully supported IPv6/IPv4v6 wire encoding (`nas::EPduSessionType`, `IEPduAddress`, gNB's `PduSessionTypeFromAsn`) — the UE was blocked by **four separate artificial "IPv4 only" guards**, not a real protocol gap: (1) `NasSm::allocatePduSessionId` and (2) `NasSm::sendEstablishmentRequest` (`ue/nas/sm/{allocation,establishment}.cpp`) rejected any `config.type != IPV4` and the latter also **hardcoded** `IPV4` into the outgoing request regardless of what was configured; (3) the `nr-cli ps-establish <type>` parser (`lib/app/cli_cmd.cpp`) already parsed the type positional arg but then threw it away, always rejecting anything but `"IPv4"`; (4) the gNB's `NgapTask::setupPduSessionResource` (`gnb/ngap/session.cpp`) independently rejected any `PduSessionType != IPv4` in the NGAP PDU Session Resource Setup path, found only after fixing (1)-(3) exposed it live (`PDU session resource could not setup: Only IPv4 is supported`). All four now accept IPv4/IPv6/IPv4v6 (Ethernet/Unstructured remain unsupported, out of scope). New TUN IPv6 path (`ue/tun/config.cpp` `ConfigureTunIpv6`/`ConfigureTunUpOnly`, wired from `ue/app/task.cpp` `setupTunInterface`): the PDU Address IE for IPv6/IPv4v6 carries only the 8-octet interface identifier (TS 24.501 §9.11.4.10.1, never the /64 prefix), so instead of a static address the UE sets it as an `ip -6 token`, enables `accept_ra=2`+`autoconf=1`, and lets the **kernel's own IPv6 stack perform real SLAAC** once the UPF's Router Advertisement (SMF-002) arrives over the GTP-U tunnel — no bespoke RA/SLAAC parsing added on the UE side, deliberately reusing what Linux already does. `utils::OctetStringToIp`/new `Ipv6IidToToken` extended for 8-octet (IID) and 12-octet (IID+IPv4) PDU Address IE lengths (`ps-list`/JSON display only — was a raw hex dump before). IPv4 path is byte-for-byte unchanged (same log format, same TUN codepath) — proven live, not just by inspection. Live E2E (`make ueransim` + `nr-cli ps-establish IPv4v6 --dnn internet --sst 1 --sd 000001`): PSI1 (IPv4, `internet`) stayed `PS-ACTIVE`/`10.60.0.1` throughout; the new PSI came up `PS-ACTIVE`/`session-type: IPv4v6`/`10.60.0.2 + iid ::0:0:0:1`, and `ip -6 addr show` on the UE showed a genuine **kernel-SLAAC'd** `2001:db8:60::1/64` (`valid_lft 2591999s`/`preferred_lft 604799s`, matching the RA's configured 2592000s/604800s to the second) plus a RA-installed default route (`expires 1798s`, matching the 1800s Router Lifetime) — the full NAS→PFCP→RA→SLAAC chain proven end-to-end on real UE/gNB/kernel code, not just unit tests. Ping beyond the UPF still 100% loss (expected — no ICMPv6 echo responder on the N6 side, a UPF-scope follow-up, not a UERANSIM gap). Build validated via the real CI path (`make ueransim-build-only` / `docker build -f tools/ueransim/Dockerfile`), zero patch-apply fuzz across all 10 patches in filename order. [TS 23.501 §5.8.2.2.2, TS 24.501 §9.11.4.10.1, RFC 4862 §5.3]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-23] upf,smf,ueransim: **Two live bugs found + fixed validating the previous session's IPv6/IPv4v6 work: UPF session-data corruption, "<nil>" in the portal, and a 5th UERANSIM IPv4-only guard blocking ping** (see `docs/CLAUDIA_5GC_MANUAL.md` §3.22a for full detail). (1) `nf/upf/internal/pfcp/server.go` `Server.Start` reuses a single 2048-byte UDP read buffer across the whole PFCP receive loop; go-pfcp's `UEIPAddress()` decode returns `net.IP` slices that **alias** it (`net.IP.To16()` doesn't copy a 16-octet input), so every later PFCP message silently overwrote every previously-stored session's `UEIPv6`/`UEIP` in place — latent since before SMF-002 (`UEIP` was only ever read once, synchronously), exposed by the new per-session RA advertiser goroutine which is the first code to re-read it on a delay: two concurrent IPv6 sessions' delegated `/64`s visibly swapped in the RA every other ~5s tick. Fixed by deep-copying (`make`+`copy`) `ueIP`/`ueIPv6` in `handleSessionEstablishment`, mirroring the `GNBIP` copy pattern already present a few lines below; also added `seid`/`dlTEID`/`gnbIP` to the RA-sent log line (their absence cost an extra debugging round). (2) `nf/smf/internal/server/server.go` `persistSession` called `sess.UEIP.String()` unconditionally — Go's `net.IP.String()` returns the literal `"<nil>"` (not `""`) for a nil IP, and a pure-IPv6 session has no IPv4 `UEIP`, so `"<nil>"` was written straight into the Postgres `ue_ip` column and shown verbatim by the portal's Dashboard/Sessions/UERANSim pages. Fixed by guarding `sess.UEIP != nil` and falling back to the derived full IPv6 address (`ueIPv6Address(sess.UEIPv6Prefix)`) so the row also isn't dropped by the portal's `WHERE ue_ip != ''` filter. (3) A **fifth** UERANSIM IPv4-only guard, this time on the gNB's uplink **data-plane** path (not session setup): `gnb/gtp/task.cpp` `GtpTask::handleUplinkData` silently dropped any uplink packet whose IP version nibble wasn't 4, with zero log trace — found only after the 4 previous guards (patch `0060`) let a `ping6` actually reach the gNB, where it then vanished, making it look like a UPF-side problem. Folded into `tools/ueransim/patches/0060-ipv6-pdu-session.patch` (now 14 files, was 13). Re-validated live end-to-end after all three fixes: `2001:db8:60::1/64` SLAAC address stable across 4+ RA cycles (no more alternating corruption), `ping -6 -c 4 fe80::1%uesimtun1` → **4/4 received, 0% loss**, portal shows `"ue_ip":"2001:db8:60:1::1"` for a pure-IPv6 session. IPv4 path reconfirmed byte-identical throughout both debugging rounds. Real internet egress over IPv6 still needs docker-compose IPv6 network changes (hard stop, not done here). [TS 29.244 §8.2.62, RFC 4443 §2.3/§4.1/§4.2]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-23] upf,docker-compose: **IPv6 N6 forwarding + internet egress** (TS 23.501 §5.8.2.2/§5.6.5) — closes the last SMF-002/IPv6 gap (previously a docker-compose hard-stop; human sign-off obtained). A UE with an IPv6/IPv4v6 PDU session now reaches the N6 network, not just the UPF router address. UPF: new `tun.SetupIPv6` (per-DNN, called from `cmd/upf/main.go` when a DNN has `ue_ipv6_prefix`) enables `net.ipv6.conf.{all,<tun>}.forwarding`, assigns the router address `<prefix-network>::fe/<len>` (`nodad`) so the whole delegated pool is on-link via the TUN, and installs `ip6tables -t nat POSTROUTING -s <prefix> ! -o <tun> -j MASQUERADE`. `gtpu.handleInnerIPv6` now forwards general IPv6 uplink to the TUN selected by UE source prefix (`tunRouteForIPv6`) after the RS/echo fast paths; `gtpu.startTUNReader` branches on IP version and matches IPv6 downlink dst by delegated /64 via new `SessionTable.GetByUEIPv6Prefix`/`byUEIPv6Net` (the UE forms its own SLAAC IID, so match by prefix, not exact address). `docker-compose.yml`: `n6-net`/`n6-ims-net` gained `enable_ipv6: true` + ULA subnets (`fd00:6::/64` gw `fd00:6::1`, `fd00:7::/64` gw `fd00:7::1`) for the UPF's IPv6 default route, and the `upf` service gained `net.ipv6.conf.all.{disable_ipv6=0,forwarding=1}` sysctls (recreate the N6 networks to apply — only the UPF attaches). Live E2E (2026-07-23): IPv4v6 **and** pure-IPv6 sessions → `ping -6 fd00:6::1` (N6 bridge gateway) → **4/4 received, 0% loss, ttl=63** (one hop decrement = kernel-forwarded, not the inline echo responder); MASQUERADE counters increment; inline echo to `fe80::1` and IPv4 N6 (`ping 172.30.6.1`) both unaffected. `go build`/`go vet`/`go test ./nf/upf/...` clean. Limitation: egress reaches the N6 bridge gateway (simulated internet edge); real public-IPv6 egress additionally needs the Docker host to have IPv6 + NAT66 (absent on the WSL2 dev host). [TS 23.501 §5.8.2.2/§5.6.5, RFC 4861/4862]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-23] mgmt-portal: **Portal UI to establish IPv6/IPv4v6 PDU sessions** — two entry points, matching the new UERANSIM patch-0060 capability. (1) `/ueransim` per-UE **nr-cli** dialog: the *PDU Session — Establish* section replaced its single `ps-establish IPv4` button with an **IPv4/IPv6/IPv4v6 type toggle** + DNN input, sending `ps-establish <type> --dnn <dnn>` via the existing generic nr-cli endpoint (pure frontend — `web/src/pages/UERANSim.tsx`). (2) `/qos` **NW-Triggered PDU Session** panel: added a **PDU session type** selector threaded into `POST /api/v1/qos/nw-sessions` via new optional `pdu_session_type` field (`web/src/pages/QoS.tsx`, `web/src/lib/api.ts` `NWSessionRequest`+`PDUSessionType`). Backend `internal/api/nwsessions.go`: `nwSessionRequest.PDUSessionType` + `normalizePDUSessionType` (whitelist IPv4/IPv6/IPv4v6, empty→IPv4 for back-compat, rejects anything else with a clear step detail) — `stepUEEstablish` now builds `ps-establish <type>` instead of the hardcoded IPv4. Live validated: portal nr-cli `ps-establish IPv6 --dnn internet` → IPv6 session; `nw-sessions` with `pdu_session_type=IPv4v6` → PSI ACTIVE `10.60.0.2 + iid ::0:0:0:1` (step detail `ps-establish IPv4v6 --sst 1 --sd 1 --dnn internet`); invalid `IPv7` rejected. `go build`/`go vet` clean; `tsc --noEmit` clean. [TS 23.501 §5.8.2.2, TS 24.501 §9.11.4.11]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-23] smf: **Secondary Authentication / DN-AAA** (SMF-003, TS 23.501 §5.6.6, TS 23.502 §4.3.2.3) — the SMF now acts as EAP authenticator during PDU Session Establishment for DNNs flagged `secondary_auth`. New `nf/smf/internal/server/secondary_auth.go` runs a per-session EAP state machine relaying EAP between the UE (N1, new 5GSM PDU SESSION AUTHENTICATION COMMAND `0xC5` / COMPLETE `0xC6` / RESULT `0xC7` codecs in `shared/nas/secondary_auth.go`) and a simulated in-core DN-AAA (N6, behind a swappable `DNAAAClient` seam), reusing the `shared/crypto/eap` framing built for AUSF-001/AMF-005. On EAP-Success the Establishment Accept carries the EAP-Success (EAP IE `0x78` ordered before `0x79`/`0x25` per TS 24.501 Table 8.3.2.1.1); on EAP-Failure or DN-AAA unreachable the SMF returns Establishment Reject `0xC3` with 5GSM cause **#29** and no N4 session (UE IP released). AUTH COMMAND/RESULT/REJECT are delivered via `Namf_Communication_N1N2MessageTransfer` (the AMF caller unconditionally wraps the inline CreateSMContext return as an Accept). A DNN without the flag establishes byte-identically (zero regression). Per-DNN config `secondary_auth`/`dn_aaa_unreachable`. Metrics `fivegc_procedure_total{procedure="SecondaryAuthentication"}` + gauge `fivegc_smf_secondary_auth_pending` + Grafana "SMF — Secondary Authentication / DN-AAA" row (3 panels) + OTel span attrs (result/cause/spec_ref). spec-verifier CONFORMANT-WITH-NOTES (0 blockers; MINOR EAP-IE-order fix applied). Tests: 6 shared/nas codec + 5 SMF state-machine unit + 4 godog scenarios, all green with `-race`. Live N1 UE leg out of scope (UERANSIM v3.2.8 has no secondary-auth peer, same posture as NSSAA/EAP-AKA'/URSP); DN-AAA is a simulated in-core EAP server. [TS 23.501 §5.6.6, TS 23.502 §4.3.2.3, TS 24.501 §9.11.2.2/§9.11.4.2]. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-27] amf,ueransim,mgmt-portal: **Public Warning System — NGAP Write-Replace Warning / PWS Cancel** (AMF-007, TS 23.041, TS 38.413 §8.9.1/§8.9.2) — ETWS/CMAS-style broadcast to every connected gNB, non-UE-associated, independent of registration/slice/PDU session (TS 23.501 §5.20). Portal plays the CBC role via the AMF's internal mgmt API (`:9002`) — no new NF, no invented protocol (3GPP has no standardized CBC↔AMF wire format for 5GC; same in-core-simulation posture as DN-AAA/AAA-S). New `nf/amf/internal/ngap/pws.go`: `BuildWriteReplaceWarningRequest`/`BuildPWSCancelRequest` (ProcCode 51/32, ASN.1 APER via the already-vendored `github.com/free5gc/ngap`+`aper` — both message types and all 12 IEs already existed in the library, so this is pure wiring, not a new codec), broadcast fan-out over the existing `s.gnbs` registry (reusing `SendPaging`'s pattern exactly), fan-in keyed by `PWSKey{MessageIdentifier, SerialNumber}` (no AMF/RAN-UE-NGAP-ID — Class 1 non-UE-associated). Mgmt API: `POST /amf/v1/pws/broadcast` (202, defaults-filled), `POST /amf/v1/pws/cancel` (202/404 `ErrPWSBroadcastNotFound`), `GET /amf/v1/pws/broadcast[/{id}/{serial}]` status poll. New `tools/ueransim/patches/0070-pws-write-replace-warning.patch`: gNB decodes both requests (stock UERANSIM drops them as "Unhandled NGAP initiating-message") and replies with `BroadcastCompletedAreaList`/`BroadcastCancelledAreaList`. Portal: `/pws` page (`PublicWarning.tsx`) — form with 3GPP-legal defaults for every IE, Send + Stop buttons, live per-gNB completion table. spec-verifier audited CONFORMANT-WITH-NOTES (0 blockers; 1 MINOR — `CancelAllWarningMessages` criticality `ignore`→`reject` per TS 38.413 §9.2.1 — fixed). **Live pcap caught + fixed a real BLOCKER the unit round-trip tests couldn't see**: `WarningMessageContents` was sent as raw text with no framing; TS 23.041 §9.4.2.2.5 mandates a CBS Message Information Page container (1-octet Number-of-Pages + N×(82-octet content, 1-octet length)) and Wireshark's dissector read the first text byte as an out-of-range page count, flagging the frame **Malformed**. Fixed on both the Go encoder (`encodeWarningMessageContentPages`/`DecodeWarningMessageContentPages`, new `TestEncodeDecodeWarningMessageContentPages`) and the gNB decoder (patch 0070 regenerated from a clean `dev/clone-fork.sh` baseline so the diff stays correctly-headed); re-captured live (`pws-verify3.pcap`) with **zero expert-info warnings** on both the broadcast and cancel legs. Tests: unit (NGAP round-trip + CBS page codec) + 5 godog scenarios (2 E2E-gated per the project's established `pendingIfNoE2E` convention, matching NSSAA/service-request) + live E2E via `make ueransim`. Known limitations: `WarningSecurityInfo` zero-filled dev placeholder (not a real ETWS signature); per-page content bytes still raw octets, not GSM-7-packed (framing is now correct, alphabet packing is not); PWS Restart/Failure Indication (Class 2, §8.9.3/§8.9.4) not implemented; UE air-interface leg (SIB10/11/12) out of scope. See `docs/procedures/PublicWarningSystem.md` for the full sequence diagram, IE tables, and post-audit fix narrative. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-28] amf,ueransim,mgmt-portal,shared: **Public Warning System — GSM7/8-bit/UCS2 alphabet-correct encoding** (TS 23.038 §5/§6.1.2.2/§6.2.1) — the 2026-07-27 CBS page-framing fix made the Write-Replace Warning Request well-formed, but Wireshark still couldn't display readable text: `WarningMessageContents` was still written as raw unpacked octets regardless of `DataCodingScheme`, and the portal's default DCS (0x00) declares the GSM 7-bit default alphabet (septet-packed per TS 23.038 §6.1.2.2.1), so the dissector tried to septet-unpack plain ASCII into garbage. Also found: DCS 0x00 means CBS language **"German"**, not "unspecified" — the CBS DCS table (TS 23.038 §5 Table 5) differs from the SMS DCS table; coding groups 0000-0011 are the language-indication table, not "General Data Coding" (that's group 01xx for CBS). Fixed with a new `shared/gsm7` package: GSM 7-bit default alphabet basic + extension character tables transcribed directly from the primary-source TS 23.038 V9.1.1 §6.2.1/§6.2.1.1 tables, `PackSeptets`/`UnpackSeptets` verified bit-for-bit against the spec's own worked examples ("two characters in two octets", "eight characters in seven octets"), and `AlphabetFromCBSDCS` implementing the full CBS DCS coding-group table (language groups, general data coding 01xx, UDH 1001, data-coding/message-class 1111, reserved-groups-default-to-GSM7). `nf/amf/internal/ngap/pws.go`'s `encodeWarningMessageContentPages`/`DecodeWarningMessageContentPages` now take the DCS byte and dispatch to `encodeGSM7Pages` (93 septets/page), `encode8BitPages` (unchanged raw-octet path, 82/page), or `encodeUCS2Pages` (41 chars/page, UTF-16BE) — the CBS-Message-Information-Length trailing octet stays an *octet* count in every case (TS 23.041 §9.3.20); GSM7 decode derives the septet count as `floor(octetCount*8/7)` to match a real dissector, a documented inherent ambiguity at 8-septet boundaries (property of the CBS wire format, not a bug). Portal (`PublicWarning.tsx`) and AMF mgmt-API default DCS moved `0x00→0x0F` (GSM7, language unspecified); the DCS field became a 3-preset dropdown (GSM7 0x0F / 8-bit 0xF4 / UCS2 0x48) instead of a bare number input an operator could mismatch against the broadcast text. `tools/ueransim/patches/0070-pws-write-replace-warning.patch` (gNB `radio.cpp`) now reads `DataCodingScheme` (previously ignored) and GSM7-unpacks/UCS2-decodes the page content to match — regenerated via the same baseline-diff technique as the 2026-07-27 framing fix (pristine clone → commit after patches 0001-0060 → overlay updated radio.cpp/task.hpp/transport.cpp → `git diff` against that baseline), verified to apply cleanly from a fresh clone and compile via `make ueransim-build-only`. Tests: `shared/gsm7` unit tests (packing worked examples, round-trip incl. extension-table/non-ASCII, unmappable-character `?` fallback, full DCS coding-group table) + `nf/amf/internal/ngap` per-alphabet page-boundary round-trip tests (93 septets/page GSM7, 41 chars/page UCS2, 82 octets/page 8-bit), all green. Known limitations (unchanged from documented gaps, now narrower): no national-language single/locking-shift tables (TS 23.038 §6.2.1.2); "message preceded by language indication" text-prefix framing (DCS 0x10/0x11-0x1F) not parsed/stripped; UERANSIM gNB's UCS2 decode is BMP-only (log-display path only, not a byte-exact decode). See `docs/procedures/PublicWarningSystem.md` "Post-audit fixes — 2026-07-28" for the full narrative. docs: update CLAUDIA_5GC_MANUAL
- [2026-07-28] amf,ueransim,mgmt-portal,shared: **Public Warning System — language selection** (TS 23.038 §5). Building on the same-day alphabet fix, the portal's Data Coding Scheme control was replaced with **Alphabet + Language** selectors that derive the DCS byte (shown read-only). The CBS DCS conveys language two ways, both now exposed: (a) the GSM 7-bit **language coding groups** (groups 0000 → DCS 0x00-0x0F, 0010 → DCS 0x20-0x24) name the language directly in the DCS byte — German(0x00) … Polish(0x0E), Unspecified(0x0F), Czech(0x20), Hebrew, Arabic, Russian, Icelandic(0x24) — no content change; (b) the UCS2 **language-indication prefix** (DCS 0x11) prepends the two ISO 639 characters GSM7-packed into 2 octets before the UCS2 body, the only way to tag a language for non-Latin scripts (Japanese/Chinese/Korean/Arabic-script/…). New `shared/gsm7/language.go`: `LanguageNameFromCBSDCS` (DCS→name for logs), `EncodeUCS2LanguagePrefix`/`DecodeUCS2LanguagePrefix` (2-octet prefix, verified round-trip incl. the 2-zero-pad-bit octet-boundary rule). `nf/amf/internal/ngap/pws.go`: `encodeWarningMessageContentPages`/`DecodeWarningMessageContentPages` + `encodeUCS2Pages`/`decodeUCS2Pages` gained the language prefix (page-0 only, reducing that page to 40 UCS2 chars), `WriteReplaceWarningParams.LanguageISO639`, and a `language` + `data_coding_scheme` field on the `PublicWarningSystem` log. AMF mgmt API `POST /amf/v1/pws/broadcast` gained an optional `language` (ISO 639) field used only for DCS 0x11. Portal `PublicWarning.tsx`: Alphabet dropdown (GSM 7-bit / UCS2 / 8-bit) + Language dropdown (coding-group languages under GSM7, all incl. CJK under UCS2, disabled under 8-bit), `computeDcs(alphabet, language)`, derived-DCS shown in the help text; `api.ts` `PWSBroadcastRequest.language`. gNB patch `0070-pws-write-replace-warning.patch` (radio.cpp): `CbsLanguageNameFromDcs` + UCS2 0x11 prefix stripping/decode, `language[…]` in the log line — regenerated via the baseline-diff technique, applies cleanly from a fresh clone, recompiled with `make ueransim-build-only`. Tests: `shared/gsm7` (LanguageNameFromCBSDCS table, UCS2 prefix round-trip) + `nf/amf/internal/ngap` (UCS2+language page round-trip, `pwsLanguageLabel`), all green; `go build`/`go vet`/`tsc --noEmit` clean. Remaining gaps: GSM7 language-indication prefix (DCS 0x10) and national-language single/locking-shift tables (TS 23.038 §6.2.1.2) not implemented. See `docs/procedures/PublicWarningSystem.md` "Language selection — 2026-07-28". docs: update CLAUDIA_5GC_MANUAL
- [2026-07-28] mgmt-portal: **Public Warning System — CBC persistence + re-drive** (TS 23.041, TS 23.007 §16). The AMF's PWS registry is in-memory and lost on restart; persisting it in the AMF is the wrong place (it is a stateless relay, and its per-gNB map is keyed by the gNB SCTP address that changes on re-association). 3GPP puts durable warning state at the CBC, which the portal plays — so the portal now owns it. New Postgres `pws_broadcasts` table (`store.Migrate`, Write-Replace upsert keyed by message-identifier+serial) storing full warning content (DCS, language, warning type, text, area TACs, cancelled flag). Portal handlers rewritten: `POST /api/v1/pws/broadcast` proxies the AMF **and** persists on acceptance; `POST /api/v1/pws/cancel` marks the store cancelled (even when the AMF 404s post-restart); `GET /api/v1/pws/broadcast` returns the **merge** of the CBC store (authoritative content + cancelled) with the AMF's live per-gNB status — each entry gains `live` (AMF has runtime state), `stored`, and the `data_coding_scheme`/`language`/`warning_type`/`message_text` the AMF status omits; new `POST /api/v1/pws/resend` re-drives a stored warning from the DB back through the AMF broadcast API. Portal UI (`PublicWarning.tsx`): a warning with `live:false` (AMF restarted) shows a **Stored — resend to re-establish** badge + a **Resend** button, and cards now display the message text, language, and DCS. The AMF is unchanged (its in-memory registry stays the transient relay view). Tests: 5 portal unit tests (merge live-overlay/stored-only/AMF-only/newest-first + request↔store round-trip with AMF-default fill); `go build`/`vet`/`tsc --noEmit` clean. **Live-verified end-to-end**: broadcast → persisted `live:true` completed 1/1 → `docker restart amf` (AMF list empties to `[]`) → portal still lists the warning `live:false stored:true` with content intact → resend → re-established `live:true` completed 1/1, gNB logs the decoded warning. Remaining gap: NGAP PWS Restart/Failure Indication (§8.9.3/§8.9.4, gNB-restart signalling) still not implemented. See `docs/procedures/PublicWarningSystem.md` "CBC persistence + re-drive — 2026-07-28". docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase A — design tokens + light/dark theme + grouped navigation** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md`, backlog PORTAL-UI-01). The portal was dark-only by construction: `tailwind.config.js` was empty, `index.css` was 14 lines, and ~1,100 hardcoded colour utilities were scattered across 13 pages with zero `dark:` variants. Phase A lays the foundation. **Tokens:** `web/src/index.css` now declares 39 semantic CSS variables for **both** themes (background/foreground/card/card-fg/muted/muted-fg/border/border-strong/input/input-border/ring, brand primary|secondary|accent with their on-colours, destructive, status success|warning|danger|info x {fg,surface,border}, log surface, overlay scrim, chart-1..5); token parity is mechanically verified (39 light == 39 dark). `web/tailwind.config.js` maps each token to semantic utilities (`bg-card`, `text-muted-fg`, `border-border`, `text-success-fg`, `border-l-chart-N`, `bg-log-bg`, `bg-overlay/60`), adds Fira Sans / Fira Code font tokens, `darkMode: 'class'`, and radius/shadow tokens. **Contrast:** 27 foreground/UI pairs x 2 themes audited programmatically against the emitted CSS — 0 failures (body text >=4.5:1, focus ring / input border / chart series >=3:1). The skill-flagged accent `#EA580C` was **kept** with a `#0F172A` label (5.0:1) rather than dropped. **Theming:** `web/index.html` gains an inline synchronous anti-FOUC bootstrap (stored `localStorage.theme` wins, else `prefers-color-scheme`; sets `html.dark` + `style.colorScheme` before the stylesheet) plus Fira Sans/Fira Code from Google Fonts with the 300 weight dropped (projector-safe) and `meta color-scheme`; the built `index.html` keeps the inline script ahead of the injected stylesheet. New `web/src/lib/theme.ts` (resolve/apply/persist + a `useTheme` hook that follows live OS changes only while no explicit preference is stored, with cross-tab sync) and `web/src/components/ThemeToggle.tsx` (icon-only, action-describing `aria-label`, 44x44 target). **Navigation:** `App.tsx` regroups the 13 destinations into 6 domain groups (Overview / Data & Config / Runtime / Test UEs / Operations / Safety) with collapsible sections that auto-expand for the active route, a header bar carrying the theme toggle, a skip link, and a responsive overlay drawer below `lg` (ESC + backdrop + focus move-in/restore). **Routes are unchanged** from the old IA, so no redirects are needed. The IA lives in the React-free `web/src/lib/navigation.ts`. The four shared components were reworked onto tokens: Badge (semantic variants with legacy aliases so unmigrated pages still build, optional icon so status is never colour-only), StatCard (`variant` enum), PageHeader (eyebrow), NFStatusCard (chart-ramp identity accent + explicit icon and screen-reader text per status instead of a colour-only dot). `web/STYLE_GUIDE.md` and the `components/ui/` primitive layer are the next task (PORTAL-UI-02). Verification: `npm run build` PASS (1678 modules), embedded `internal/assets/static` regenerated, `go build ./...` + `go test ./internal/...` PASS, dependency lists unchanged, raw-colour audit clean on every Phase-A file, anti-FOUC decision table 7/7 and nav-IA invariants 12/12 PASS. Remaining for later phases: page migrations (raw colours still present in the 13 pages), the Go SPA-fallback/deep-link fix, metrics charts, and the accessibility/responsive sweeps. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase B — primitive component layer + `STYLE_GUIDE.md`** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase B, backlog PORTAL-UI-02). Phase A left 13 pages each hand-rolling their own buttons, tables, overlays, toasts and loading/error markup against raw colour utilities; Phase B builds the shared layer they migrate onto. New `web/src/components/ui/` (20 files, barrel `ui/index.ts`, plus the dependency-free `web/src/lib/cn.ts` class joiner — **no new npm dependencies**): `Button` (`primary|secondary|destructive|ghost|icon`, sizes, `loading`) + `IconButton` whose mandatory `label` prop makes an unlabelled icon-only control impossible; `Input`/`Textarea`/`Select` (`invalid` → `aria-invalid` + danger border) and `Field`, a render-prop wrapper that hands the control its `id`/`aria-describedby`/`invalid` so label+error+helper wiring cannot be forgotten; `Card`, `Section` (Card + title/actions, `bare` for nesting) and a reworked `PageHeader`; `Badge` (semantic variants + legacy aliases + optional icon so status is never colour-only); the `Table` family (`Table/TableHead/TableBody/TableRow/TableHeaderCell/TableCell/TableEmptyRow`, one density + hover + `mono` + `caption` + horizontal scroll inside the container, never the page); `Tabs` (ARIA tabs, roving tabindex, Arrow/Home/End); the four states kept deliberately distinct — `Loading`/`Skeleton`, `EmptyState` (*backend answered, no data*), `DegradedState` (*backend unavailable*, the CLAUDE.md §10 case) and `ErrorState`; `ToastProvider`/`useToast` (per-toast `role=status`/`role=alert`, auto-dismiss incl. `duration:0`, max 4, labelled dismiss) mounted once in `main.tsx`; the overlay framework `useFocusTrap` (initial focus, Tab/Shift-Tab cycling, ESC, restore-to-trigger on unmount) + `Modal` (portal, backdrop, scroll lock, ESC, focus trap) + `Dialog` (labelled header/body/footer) + `ConfirmDialog` (`role=alertdialog`); and `ChartWrapper` + `useChartTheme`, which resolve the `--c-chart-1..5`/border/muted-fg/card/fg tokens at runtime so Recharts axis/grid/tooltip flip with the theme, render `state="unavailable"` when Prometheus is down **instead of a misleading zero line**, and expose a keyboard-operable (`aria-pressed`) tabular fallback. The four Phase-A components were finished onto the layer: `Badge`/`PageHeader` now live in `ui/` with back-compat re-export shims at their old paths, `StatCard` dropped its raw-colour `color` prop (callers use `variant`, the Dashboard already did), `NFStatusCard` composes `Card`+`Badge` (icon + text + `sr-only` word per status), `ThemeToggle` uses `IconButton`. New `web/STYLE_GUIDE.md` is the layer's source of truth: principles, the full 39-token table for both themes, a **measured** contrast table (27 pairs x 2 themes computed from the emitted CSS — 0 failures; body ≥4.5:1, ring/input-border/chart ≥3:1), typography/spacing/radii/shadow scales, the focus+motion contract, a component catalogue with usage snippets and do/don'ts, the empty-vs-degraded decision table, forms/overlays/toasts/charts conventions, the WCAG 2.1 AA checklist, a 9-step "build a new component" recipe, and the `grep -rnE '(bg|text|border|…)-(gray|slate|red|…)-[0-9]{2,3}' src --include='*.tsx'` enforcement command with its recorded result. Verification: `npm run build` PASS (tsc -b + vite, 1684 modules, embedded `internal/assets/static` regenerated); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); `package.json`/`package-lock` dependency lists UNCHANGED; raw-colour audit over `src/components/ui/**`, the reworked `src/components/*.tsx`, `main.tsx` and `lib/cn.ts` → **0 hits**; emitted CSS confirmed to contain the newly-used token classes. Pages remain on their old markup until PORTAL-UI-03…15 (still the raw-colour backlog); the dialog focus/ESC/restore contract and both-theme rendering are code-level verified only — no browser in this environment, so those stay manual gates as in Phase A. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(1) — Services page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-03). First of the 13 page migrations; behaviour is unchanged, only the markup/design layer moved. `web/src/pages/Services.tsx` now composes `PageHeader` (eyebrow "Runtime" + the running/total subtitle), `Button` for Refresh, the `Table` family (Container/Image/State/Status/Uptime/Actions) with `TableCell mono` on the image, `IconButton` for Start/Stop/Restart and a `Badge` per container state. Status is no longer colour-only: `running` → success + CheckCircle, `exited`/`dead` → danger + XCircle, anything else → neutral + Circle, and an in-flight start/stop/restart shows the pending verb ("starting"/"stopping"/"restarting") on a warning badge with a spinner, replacing the bare `Loader`. Icon-only controls now carry a per-container accessible name (`Start nrf`, `Stop upf`, `Restart smf`) — the old `title`-only buttons were unlabelled to a screen reader. The four states the guide keeps distinct are now explicit: initial load → `TableEmptyRow` + `Loading rows`, empty answer → `EmptyState` ("No containers found… Docker socket mounted?"), failed fetch → `DegradedState` ("Docker socket unavailable" + Retry), and mutation failures raise a non-auto-dismissing (`duration: 0`) error `toast` via the Phase-B `useToast` — previously a failed start/stop/restart was silent. Preserved verbatim: the 5 s `refetchInterval` polling, NF-order sorting, running/total count, `svc.status` and `svc.uptime || '—'`. Raw-colour grep over the page → **0 hits** (was 13) and `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/Services.tsx` at 0. Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); `package.json`/`package-lock` dependency lists UNCHANGED. Manual/browser gates remain (no browser here): both-theme rendering and the CLAUDE.md §5 "Services" behaviour checklist (start/stop/restart per container, 5 s polling, uptime) are code-level verified only; per plan risk 9 that checklist is the regression control. Remaining pages PORTAL-UI-04…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(2) — Sessions page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-04). `web/src/pages/Sessions.tsx` now composes `PageHeader` (eyebrow "Runtime"), two `Section bare` blocks (PDU sessions, AMF UE contexts) each containing the `Table` family with a `caption`, `TableCell mono` for SUPI/UE IP/TEID/TMSI, a `Badge` for the S-NSSAI (`info`, label carries SST/SD) and a GMM-state `Badge` whose colour is paired with an icon and the state name (`REGISTERED` success+CheckCircle2, `DEREGISTERED` danger+XCircle, `*-INITIATED` warning+Clock, unknown neutral+Circle) — previously colour-only `blue/green/yellow/red` text and chips. **Empty vs degraded are now distinct per table:** a failed fetch (PostgreSQL unreachable/dropped → 5xx) renders `DegradedState` with the error text and a Retry button, while a successful empty answer renders `EmptyState` ("No active PDU sessions" / "No UE contexts"); initial load uses `TableEmptyRow` + `Loading rows` skeletons. Preserved verbatim: both 5 s `refetchInterval`s, the SUPI→DNN→UE IP→Slice→UL TEID→Since session columns, the SUPI→TMSI→GMM State→Last Seen context columns, `formatHex` TEID/TMSI zero-padding (extracted to one helper), `—` for a null TMSI and `toLocaleString()` timestamps. Raw-colour grep over the page → **0 hits** (was 20) and `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/Sessions.tsx` at 0. Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated and confirmed to contain both new degraded titles); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. **Known limitation (recorded, not fixed — out of the web scope of this task):** `handleListSessions`/`handleListUEContexts` return `200 []` when `Deps.Store == nil` (Postgres unreachable at portal startup — `cmd/mgmt-portal/main.go` leaves `db` nil), so that specific case is indistinguishable from a genuinely empty result and renders `EmptyState`; only a post-startup DB failure (5xx) reaches `DegradedState`. Truly flagging `Store==nil` as degraded needs a backend capability signal (e.g. `/api/v1/health` reporting dependency availability); unlike the Services page, mapping "empty" to degraded would be wrong here because an idle stack legitimately has no sessions/contexts. Manual browser gates remain (no browser here): both-theme rendering and the CLAUDE.md §5 "Sessions" checklist are code-level verified only. Remaining pages PORTAL-UI-05…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(3) — Logs page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-05). `web/src/pages/Logs.tsx` now uses `PageHeader` (eyebrow "Operations") with `Button` actions (Export, Clear, Pause/Resume — the toggle is `aria-pressed` and switches to `primary` when paused), a `Card` holding two `Field`s (Container `Select`, Filter `Input`) so both controls finally have real `<label>`s — the old toolbar had a placeholder-only input and a fully unlabelled `<select>` — and the `log-surface` component class (`--c-log-bg`/`--c-log-fg` + Fira Code 0.8rem/1.5) so the terminal is **theme-aware in both light and dark** instead of the hardcoded `bg-gray-950`. Log level colours now resolve through semantic tokens (`error`→`text-danger-fg`, `warn`/`warning`→`text-warning-fg`, `info`→`text-log-fg`, `debug`→`text-muted-fg`) and the level word is always printed beside the line, so severity never depends on colour alone. **New WebSocket connection state** (`connecting | open | closed`) is tracked via `onopen`/`onclose` and shown as an always-visible `Badge` (Connecting info+spinner, Connected success+Wifi, Disconnected danger+WifiOff); a drop additionally renders a `DegradedState` banner ("Log stream disconnected", noting the automatic reconnect) while the buffered lines stay readable — previously a lost socket was completely invisible. Also fixed the "waiting for log lines" copy so an over-narrow filter reports "No lines match …" instead of pretending the stream is still waiting. Preserved verbatim: the `parseLogLine` JSON parsing, 2000-line cap, 3 s reconnect loop, pause holding new lines, raw-line substring filter, auto-scroll while unpaused, Blob/text export to `<container>-logs.txt`, `tail=200`, the container list intersected with the NF allow-list, and the 400–600 px terminal bounds. Raw-colour grep over the page → **0 hits** (was 15) and `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/Logs.tsx` at 0. Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated; emitted CSS confirmed to contain the compiled `.log-surface` rule and the new bundle the connection strings); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Manual browser gates remain (no browser here): both-theme log-surface legibility, the live disconnect/reconnect badge and the CLAUDE.md §5 "Logs" checklist (WS streaming, pause/resume, export, JSON parsing) are code-level verified only. Remaining pages PORTAL-UI-06…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(4) — PCAP page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-06). The master-detail layout (a hand-rolled left NF list plus an ad-hoc capture panel) is replaced by the `Tabs` primitive — one tab per sidecar (CORE + the 13 NFs), each carrying a compact `REC`/`PAUSED` `Badge` so a live capture is visible without opening the tab — with the selected sidecar's controls and file list in the tab panel. `web/src/pages/PCAP.tsx` now uses `PageHeader` (eyebrow "Operations") with an active-capture `Badge` action, `Button` for Start/Pause/Resume/Rotate/Stop (loading state per action), the `Table` family for the capture files (mono filename, size/modified in muted text, sortable File header with `aria-sort`), `IconButton` (per-container labels `Download <file>` / `Delete <file>`, ghost variant), `Badge` for capture state (Capturing/Paused/Stopped, always colour + icon + text), `Loading`/`TableEmptyRow` while fetching or empty, `ErrorState` with Retry if the file list fails, `DegradedState` if the sidecar status fetch fails, and a token-tinted info `Card` for the bulk-action bar. **Destructive actions moved off `window.confirm` onto `ConfirmDialog`** (single-file and bulk delete, `role=alertdialog`, `loading` bound to the mutation), and mutation failures now raise a non-auto-dismissing error `toast` — previously the page reported nothing at all on failure. The capture-state dot, the blue/red/green action buttons and the hand-rolled bulk bar are gone; the four sidecar action buttons now use semantic variants (`primary`/`secondary`/`destructive`). Preserved verbatim: the 5 s `pcap-status` and 5 s `pcap-files` polling, `sortNewest` toggle, select-all/row selection semantics, `formatBytes` (B/KB/MB), `toLocaleString()` timestamps, the new/oldest-first sort, per-file download (`pcapDownloadURL`) and bulk ZIP download, and the exact start/pause/resume/stop/rotate action gating (Start only when idle, Pause/Stop/Rotate only while capturing, Stop also while paused). Raw-colour grep over the page → **0 hits** (was 52) and `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/PCAP.tsx` at 0 (the purged utilities are visible as a CSS-size drop in the rebuilt bundle). Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated; emitted CSS confirmed to contain the new `accent-primary` rule binding the file checkboxes to the primary token); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Behaviour change (deliberate, from the plan's "tabs → `Tabs`" instruction): the sidecar selector is now a tablist rather than a vertical list, so **CORE is selected by default** instead of no selection, and the page scrolls in the main pane instead of using a fixed-height two-pane split. Manual browser gates remain (no browser here): both-theme rendering, the tab keyboard walk, and the CLAUDE.md §5 "PCAP" checklist (status, start/stop, files, download) are code-level verified only. Remaining pages PORTAL-UI-07…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(5) — Subscribers page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-07). `web/src/pages/Subscribers.tsx` now composes PageHeader (eyebrow "Data & Config", Refresh + New Subscriber buttons), a `Card` create/edit form built from `Field`+`Input` (SUPI/K/OPc/AMF/SQN/AMBR UL/AMBR DL — every control now has a real `<label>` and hint wiring, where the old form had a bespoke local `Field` and a single unlabelled "AMBR UL / DL" pair), slice selection as `Button` toggles with `aria-pressed` plus a `Field`-wrapped per-slice DNN `Select` (options from `GET /api/v1/dnns`), the `Table` family for the subscriber list (mono SUPI/K, slice `Badge`s mapped to the semantic variants internet→info / gold→warning / silver→neutral / bronze→success with the slice name as the label, DNN in muted mono, AMBR with `tabular-nums`) and `IconButton` row actions. **Every ad-hoc notification/error path became a primitive:** the green/yellow "slice-update" banner is now a `toast` (success when the UE was deregistered and will re-register, warning when it is not registered and the change applies next time) — the same toast covers the RFSP flow; create/update/delete/RFSP failures raise non-auto-dismissing error toasts where the old page showed inline red text (or nothing at all for delete/RFSP-reset); the list-fetch failure is an `ErrorState` with Retry instead of an in-table error row; initial load is `TableEmptyRow`+`Loading rows`; an empty list is `TableEmptyRow`. **Cascade delete moved from an inline Confirm/Cancel pair to `ConfirmDialog`** (`role=alertdialog`, explicitly stating the SUPI is removed from the authentication, access-mobility, session-management and policy subscription tables, `loading` bound to the mutation). The **RFSP inline editor** is rebuilt on `Field`+`Input`+`IconButton`: it still reads the effective value (`override` vs operator default), shows the value with an explicit "override"/"(default)" label (never colour-only — was a purple pill), validates 1–256 through `Field`'s error slot, keeps `autoFocus` and the Enter-saves / Escape-cancels keys, and keeps the reset-to-default action only when an override exists. **SQN read-only notice preserved and expanded:** on edit the field is disabled with a hint explaining the UDM increments SQN per authentication and that writing a stale value back would break UE re-registration (the `PUT` still sends the form, and the backend's `UpsertSubscriber(…, preserveSQN=true)` keeps the DB value). Preserved verbatim: the `SLICE_PRESETS`/`sliceName` mapping, `staleTime: 0` on the subscriber list and `staleTime: 15_000` on RFSP, per-slice DNN defaulting to the first available DNN when toggled on, and the whole create/update/delete/RFSP call shapes. Raw-colour grep over the page → **0 hits** (was 46) and `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/Subscribers.tsx` at 0 (emitted CSS dropped ~0.6 kB of now-purged palette utilities). Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated and confirmed to contain the new dialog/notice strings); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Manual browser gates remain (no browser here): both-theme rendering, the RFSP keyboard walk (Enter/Escape/autoFocus) and the CLAUDE.md §5 "Subscribers" checklist (CRUD, RFSP, SQN preservation, dereg trigger) are code-level verified only. Remaining pages PORTAL-UI-08…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(6) — Slices page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-08). `web/src/pages/Slices.tsx` now composes one `PageHeader` (eyebrow "Data & Config", title "Network Slices", `Add Slice` action) over two blocks — the S-NSSAI `Table` (mono SST/SD, `Type` `Badge` on the semantic `info` variant with the SST name as its label, the per-row "Restart NFs to apply changes" note, and a per-row labelled `IconButton` delete) and a `Section bare` "Data Networks (DNNs)" whose `Add DNN` action opens a `Card` form built from `Field`+`Input`+`Select` (DNN name, UE IP pool, N6 Docker network, description, IPv6 prefix, restart checkbox) with the 7-column DNN `Table` (mono name/pool/prefix/N6/TUN+Docker net, IPv6 Prefix column, truncated description, `IconButton` edit/delete). **The IPv6 prefix is now validated inline through `Field`:** a `validateIPv6Prefix` helper mirrors the portal backend's own validator (`internal/config/nfconfig.go`) — an optional IPv6 CIDR whose length is a multiple of 8 in [8,64], the constraint the SMF `IPv6Pool` enforces when delegating per-session /64s (TS 23.501 §5.8.2.2) — the message appears on blur or on submit, the control gets `aria-invalid` plus the danger border, and submit is blocked; the submitted value is trimmed so a stray space cannot reach `net.ParseCIDR`. Previously the field had no client validation and relied on the backend's failure. **Both delete flows moved off the inline Confirm/Cancel pairs onto `ConfirmDialog`** (`role=alertdialog`, `loading` bound to the mutation) and kept their "Restart NFs" checkboxes in the dialog body: the slice dialog spells out the AMF/SMF/NSSF config removal, the DNN dialog the operator.yaml + SMF + UPF + Docker-network removal. **Every ad-hoc notice/error path became a primitive:** the green "containers restarted" banner and the green/yellow DNN banner are now `toast`s (success carrying the restart list, warning with `duration: 0` when the API reports `docker_errors`, since a partial Docker failure must be acknowledged); add/delete slice and add/update/delete DNN failures raise non-auto-dismissing error toasts (several were silent before); both list fetches render `ErrorState` + Retry instead of silently showing an empty table. Preserved verbatim: `GET /slices`, `POST /slices` with `restart`, `DELETE /slices/{sst}/{sd}?restart=`, the `next_ue_pool`/`next_n6_network` prefill on add, the lowercase `[a-z0-9-]` DNN-name filter, the edit-mode lock on the DNN name with creation-only UE IP pool / N6 network fields, the exact `PUT /dnns/{name}` body (`description` + `ue_ipv6_prefix` + `restart`), the SD `maxLength` of 6, and the empty-prefix-=-IPv4-only semantics. Raw-colour grep over the page → **0 hits** (was 63) and `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/Slices.tsx` at 0. Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated and confirmed to contain the new dialog/validator/marker strings); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Manual browser gates remain (no browser here): both-theme rendering, the `ConfirmDialog` focus-trap/ESC walk and the CLAUDE.md §5 "Slices" checklist (slice CRUD, DNN lifecycle incl. `ue_ipv6_prefix` validation) are code-level verified only. Remaining pages PORTAL-UI-09…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(7) — Policies page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-09). `web/src/pages/Policies.tsx` now composes a `PageHeader` (eyebrow "Data & Config") plus two `Section bare` blocks ("Policy Templates", "Per-Subscriber Policies") with their title, description and action buttons. **The four slice cards lost their colour-coded headers** (blue/amber/slate/orange `SLICE_HEADER`/`SLICE_BADGE` utilities): slice identity is a semantic `Badge` (internet→info, gold→warning, silver→neutral, bronze→success) whose *label* carries the slice name and SST/SD, so it survives greyscale (WCAG 1.4.1); the cards are `Card interactive` in a responsive grid, keep the Show/Hide JSON-rules disclosure (now `aria-expanded`/`aria-controls` with an always-present body), and keep Apply to UE / Edit / Delete with accessible names. The **3GPP spec reference** panel is kept but rebuilt on tokens — a `Card padded={false}` disclosure whose delivery-path lines and two URSP encoding tables (previously raw `text-blue-300`/`text-purple-400` cells and hand-rolled `<table>`s) now use the `Table` family with captions and `scope="col"`. The per-subscriber divider list became the `Table` family (expand toggle, SUPI, precedence, rules, actions) with the JSON in an expanded detail row, and an empty SUPI reads "Default (all subscribers)" as text rather than a purple pill. **All three hand-rolled `fixed inset-0` overlays — ApplyTemplate, TemplateEditor, PolicyEditor — are now the `Dialog` primitive**, inheriting the portal/backdrop/scroll-lock/ESC/focus-trap/focus-restore contract, and their bespoke `INPUT`/`TEXTAREA` class constants are `Field` + `Input`/`Select`/`Textarea` with real labels and hints. **Push and Apply flows (and every mutation failure) are toasts now:** the inline "✓ Sent"/"✗ error" push status, the green/amber "Policy pushed/stored" banner and the editors' inline `saveError` blocks are gone, and delete/push failures that reported nothing now raise non-auto-dismissing error toasts. The **JSON rules editors** were hardened: the textarea holds its text locally, propagates only successfully parsed rules, shows "Invalid JSON — fix it to save these rules." through `Field`'s error slot (aria-invalid + role=alert) and blocks Save while invalid — previously an unparsable edit could silently save a stale ruleset. **Template and policy deletion moved from unconfirmed inline buttons to `ConfirmDialog`** (`role=alertdialog`, loading bound to the mutation); the policy dialog records that nothing is pushed to the UE. Fetch failures render `ErrorState` + Retry, an empty template list an `EmptyState` with a New Template action, and the policies table `TableEmptyRow` (+ `Loading rows`). Preserved verbatim: getPolicyTemplates/getPolicies, create/update/delete template, create/update/delete policy, `pushPolicies`, `applyPolicyTemplate`, the customize path (`createPolicy` → `pushPolicies` → `{status:'pushed'}`), the `ue-contexts` query, EMPTY_TEMPLATE/EMPTY_POLICY/EMPTY_RULE/EMPTY_RSD, SLICE_LABEL/SLICE_NAMES, the precedence 1–255 inputs, and the apply-result wording (pushed = NAS ConfigurationUpdateCommand, TS 24.501 §8.2.29; stored = backend warning). Raw-colour grep over the page → **0 hits** (was 114 — the largest single drop of the rollout) and the emitted CSS fell 2.25 kB from the purged palette utilities; `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/Policies.tsx` at 0. Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated and confirmed to contain the new dialog/validator/spec strings); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Manual browser gates remain (no browser here): both-theme rendering, the three dialogs' focus-trap/ESC/restore walks and the CLAUDE.md §5 "Policies" checklist (template CRUD/apply, UE push) are code-level verified only. Remaining pages PORTAL-UI-10…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(8) — UERANSIM page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-10). `web/src/pages/UERANSim.tsx` now composes a `PageHeader` (eyebrow "Test UEs", conditional Launch gNB / Launch UE + Refresh `Button`s) over three `Section bare` blocks — Test Scenarios, Containers, Registered UEs — plus the inline log panel. **Both hand-rolled `fixed inset-0` overlays (the NR-CLI console and the Ping test) are now the `Dialog` primitive**, so they gain the portal/backdrop/scroll-lock/ESC/focus-trap/focus-restore contract that only backdrop-click previously provided, with labelled close buttons and `Field`+`Input`/`Select` bodies (the PSI/5QI/DNN/type/target/count controls finally have real labels). The colour-coded command-chip helper (`gray/blue/orange/red/green/purple/indigo`) became a mono `CommandButton` over semantic `Button` variants — deregistration commands are `destructive`, `ps-establish` is the `primary` action, the rest `secondary` — so command families stay distinguishable via their group heading and the destructive tone rather than hue. **The IPv4/IPv6/IPv4v6 PDU-session type selector is a native `role="radiogroup"` of `accent-primary` radios** (arrow-key navigable, visible focus) instead of hand-rolled segmented buttons, while still building `ps-establish <type> --dnn <dnn>`. **Status is never colour-only any more:** the 5GMM state, scenario state, container state and the per-scenario container list all pair a semantic `Badge`/icon with the state word (the 1.5 px green/grey dot is now a CheckCircle2/Circle/XCircle icon plus an `sr-only` state, and the "not created" wording survives). The UE table and the nested PDU-session table use the `Table` family (captions, `scope="col"`, mono cells) and the row-expand control is a labelled `IconButton` with `aria-expanded`/`aria-controls` (the row stays clickable for pointer users, as the page's own hint promises). **The inline log panel is theme-aware** via the `.log-surface` class with semantic level colours (error/warn/info/debug) plus the printed level word, and keeps `tail=200`, the 2000-line cap, the 3 s reconnect loop, substring filtering, Clear/Close and auto-scroll — with a **new visible WebSocket state badge** (Connecting/Connected/Disconnected, a drop is no longer invisible) and a "no lines match the filter" message distinct from "waiting for logs". The scenario/container/UE blocks gained explicit `ErrorState` + Retry (the page previously had no error handling at all, so a failed fetch looked like an empty list), `Loading` skeletons and `EmptyState`s, and container/scenario start-stop failures now raise non-auto-dismissing error toasts where they were previously silent. Preserved verbatim: all six info/status commands, the four deregister variants, ps-establish/ps-release/ps-release-all/ps-modify(+`--5qi`)/ursp-show/ursp-match/ursp-establish/custom, `availablePsis` (index+1, `[1]` when empty), exit-code handling (`Error: …` + exit `-1`, `(exit N)` marker), TMSI/UL-TEID hex padding, `toLocaleTimeString`/`toLocaleString`, ping defaults (8.8.8.8, count 4, `[4,8,16]`, Enter-to-ping), the multi-session source-IP picker, the not-created scenario hint, `up <uptime>`, the Launch gNB/UE conditions, both 5 s `refetchInterval`s and the deregister/command hint paragraph — all 17 nr-cli literals and the API call shapes were diffed old-vs-new and match. Raw-colour grep over the page → **0 hits** (was 112 — measured at the pre-migration commit) and the emitted CSS fell 1.52 kB from the purged palette utilities; `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/UERANSim.tsx` at 0. Rollout burn-down: 668 → 233 raw-colour hits, with QoS, PacketRusher, PublicWarning, Location and Dashboard (PORTAL-UI-11…15) remaining. Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated and confirmed to contain the new dialog/state/command strings); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Manual browser gates remain (no browser here): both-theme rendering, the two dialogs' focus-trap/ESC/restore walks, live WebSocket streaming/reconnect, and the CLAUDE.md §5 "UERANSIM" checklist (scenario start/stop, nr-cli incl. the ps-establish type selector, ping) are code-level verified only. Remaining pages PORTAL-UI-11…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(9) — PacketRusher page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-11). `web/src/pages/PacketRusher.tsx` now composes a `PageHeader` (eyebrow "Test UEs", Show/Hide Logs + Clear All + Refresh `Button`s), the URSP-incompatibility and shared-IPs notices as `Card`s with a semantic `Badge` + text, the Xn/N2 `Card` grid, and `Section bare` blocks for Logs, Mobility Validation and Quick Reference. **The hand-rolled log tab strip is now the `Tabs` primitive** (ARIA tablist, roving tabindex, Arrow/Home/End, `aria-selected`/`aria-controls`) with the active tab's log panel as its panel; the strip's duplicate "Clear all" was dropped because the PageHeader Clear All drives the same reset. Scenario cards express state through a semantic `Badge` (running→success+CheckCircle2, paused→warning+Pause, exited/ready→neutral+Circle, not created→danger+XCircle) instead of the colour-coded border plus legacy `green/yellow/gray/red` aliases, and their actions map to semantic `Button` variants (Start/Resume `primary`, Pause `secondary`, Stop `destructive`, Logs `secondary`/`primary` with `aria-expanded`). The peer-running and container-not-created notices became `Badge`+text pairs (no raw blue/yellow surfaces), the per-card red mutation-error box was replaced by non-auto-dismissing error toasts, and the status query gained `ErrorState` + Retry and `Loading` skeletons (a failed fetch previously rendered as two "unknown" cards). The **log panel** renders on the theme-aware `.log-surface` class (was a hardcoded `bg-gray-950`), levels map to semantic tokens with the level word always printed, mobility highlighting uses `text-info-fg` — measured **5.96:1 light / 7.41:1 dark** against the log surface, where the old `text-cyan-300` had no token equivalent and was theme-blind — and a **new connection `Badge`** (Connecting/Connected/Disconnected) makes a dead socket visible; Pause/Resume is a `Button` with `aria-pressed` (plus a PAUSED `Badge`), Clear is a ghost `Button`, and an empty panel distinguishes "no lines match the filter" from "waiting for logs". The mobility checklist keeps its per-scenario AMF scoping and freeze-on-stop semantics, with progress as a `Badge` (`n/total`, success + icon only when complete) so completion is never colour-only. Preserved verbatim: both checkpoint tables (labels, patterns, spec refs), the mobility keyword list, the four tab ids, `tail=0` (checklist) / `tail=300` (display), the 3000-line cap, the 3 s reconnect, the 3 s `refetchInterval`, the clear/reset keys and all eight `pr*` mutation call shapes. Raw-colour grep over the page → **0 hits** (was 70, measured at the pre-migration commit) and the emitted CSS fell 1.83 kB from the purged palette utilities; `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/PacketRusher.tsx` at 0, and its measured contrast table gained the status-on-log-surface rows. **Contrast finding recorded for PORTAL-UI-19:** `success-fg` on the *light* log surface measures **4.46:1** (0.04 below the 4.5:1 body-text bar, because `--c-log-bg` #EEF2F7 is darker than the page background); the guide now carries that caveat and the one known call site is the ping `time=` colouring in `UERANSim.tsx`. Rollout burn-down: 668 → 163 raw-colour hits, with QoS, PublicWarning, Location and Dashboard (PORTAL-UI-12…15) remaining. Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated and confirmed to contain the new badge/notice/filter strings); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Manual browser gates remain (no browser here): both-theme rendering, the tab keyboard walk, live WebSocket streaming/reconnect/pause, and the CLAUDE.md §5 "PacketRusher" checklist are code-level verified only. Remaining pages PORTAL-UI-12…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(10) — QoS / PDU Sessions page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-12). `web/src/pages/QoS.tsx` now composes a `PageHeader` (eyebrow "Runtime" + Refresh with a loading state) over the `Table`-family session table, the NW-triggered and E2E panels, and two `Dialog`s. **5QI is no longer colour-coded only:** the badge label carries the number *and* the TS 23.501 Table 5.7.4-1 category (`5QI 9 · Non-GBR`) with GBR→success, delay-critical GBR→warning, non-GBR→info and operator-defined→neutral variants, so the encoding survives greyscale; session state is an icon+label Badge (ACTIVE→success+CheckCircle2, else warning+Clock), S-NSSAI an info Badge, and SUPI is visually truncated while the full value stays available to assistive tech. **Both right-side drawers are now the `Dialog` primitive** (the plan's "Modify-QoS drawer on Dialog"), gaining portal/backdrop/scroll-lock/ESC/focus-trap/focus-restore with a labelled close, and **the two-step modify flow is preserved**: Apply is disabled until a reason is entered and the 5QI actually changes, then an in-dialog confirmation naming both 5QIs, the PSI and the SUPI gates the mutation (loading-bound Confirm / Cancel). The inspector keeps its SUPI lookup (`enabled: !!lookup`, `retry:false`), gained an `EmptyState` for an empty answer, a danger Badge for the not-found error and per-slice `Card`s whose diff/matches notices are Badge+text instead of green/yellow boxes. **The page-local toast state and fixed bottom-right div were replaced by the `Toast` primitive** (success + non-auto-dismissing error), and the two long-running panels are token-styled disclosures (`aria-expanded`/`aria-controls`) because the primitive layer still has no Disclosure component (recorded for PORTAL-UI-19). The NW-triggered form is now `Field`+`Input`/`Select` with real labels (UE, app, DNN, PDU session type, S-NSSAI, 5QI, AMBR UL/DL), app presets are `Button`s with `aria-pressed`, step results pair an icon with an `sr-only` succeeded/failed word, and the **partial-failure path gained a Retry action** (re-runs the orchestration beside the failed-step summary) as the task required; the E2E panel gained a pass-count Badge (danger when a step failed) and `sr-only` step state words, and the sessions fetch gained `ErrorState` + Retry and `Loading` skeletons (the page previously had no error handling at all). Preserved verbatim: FIVEQI_NAMES, SELECTOR_GROUPS, APP_PRESETS, VALIDATION_STEPS, NW_STEP_LABELS, both validation `reason` strings, every API call shape, the 10 s `refetchInterval`, and the whole E2E `run()` orchestration (failFrom/skipped semantics, `original === 7 ? 8 : 7` test 5QI, MANUAL_OVERRIDE verification, revert) — all diffed old-vs-new. Raw-colour grep over the page → **0 hits** (was 103, measured at the pre-migration commit) and the emitted CSS fell 3.36 kB from the purged palette utilities (the largest single drop of the rollout); `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/QoS.tsx` at 0. Rollout burn-down: 668 → 60 raw-colour hits, with PublicWarning, Location and Dashboard (PORTAL-UI-13…15) remaining. Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated and confirmed to contain the new dialog/badge/step strings); `go build ./...` + `go test ./internal/...` PASS in the module; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Manual browser gates remain (no browser here): both-theme rendering, the two dialogs' focus-trap/ESC/restore walks, and the CLAUDE.md §5 "QoS" checklist (10 s refresh, modify flow with reason+confirmation, inspector, both panels) are code-level verified only. Remaining pages PORTAL-UI-13…15 still carry raw colours. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(11) — Public Warning page migrated onto the primitive layer** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-13). `web/src/pages/PublicWarning.tsx` now composes a `PageHeader` (eyebrow "Safety", Refresh `Button` bound to `isFetching`) over two `Section`s — "Compose Warning" and "Broadcasts" — plus a shared `ConfirmDialog`. **The compose form is `Field`+`Input`/`Select`/`Textarea` with real labels** (msgId, serial, warning type, alphabet, language, repetition period, broadcast count, message text), replacing the page-local `Field` shim and the raw `inputCls`/`bg-gray-800` controls; the Alphabet→language shrinking rule and the derived `computeDcs` byte are unchanged (DCS still printed read-only in the help text), and the language control gained a hint + `aria-describedby` for the 8-bit-disabled case. **Status is no longer colour-only:** the lifecycle `broadcastStatus` (Cancelled / Stored — AMF restarted, resend to re-establish / No gNB connected / Completed — broadcasting / Pending gNB ack) now returns a semantic `Badge` variant + icon (`neutral`+Ban, `warning`+RotateCw, `warning`+WifiOff, `success`+CheckCircle2, `warning`+Clock) instead of a raw class string, and the per-gNB dot became an icon + state word pair (completed/cancelled/failed/pending) on `success-fg`/`muted-fg`/`danger-fg`/`warning-fg`. **Cancel and Resend moved behind `ConfirmDialog`** (the plan's requirement): one dialog is driven by a `{kind, mid, sn}` target — destructive for PWS Cancel (TS 38.413 §8.9.2), non-destructive for the CBC re-drive of a stored warning (TS 23.007 §16) — naming the target msgId/serial, with the confirm button loading-bound and the dialog held open on failure. **The page-local `flash` state and its green/red banner became the `Toast` primitive** (success and non-auto-dismissing error variants, every message's information preserved: title "Broadcast sent"/"Cancel sent"/"Re-broadcast", description carrying msgId/serial/gNB count). The broadcasts list uses the `Card` surface and gained the four distinct states: `Loading` skeletons on first fetch, `ErrorState` + Retry on a failed fetch (previously an unrecoverable error line), `EmptyState` for a genuinely empty answer, else the cards. Preserved verbatim: the `DEFAULTS`/`WARNING_TYPES`/`ALPHABETS`/`LANGUAGES` tables, `languagesFor`, `computeDcs`, the 3 s `refetchInterval`, all three mutation call shapes (`pwsBroadcast({...form, dataCodingScheme, language})`, `pwsCancel(mid, sn)`, `pwsResend(mid, sn)`), the query invalidation and the per-gNB rendering condition. Raw-colour grep over the page → **0 hits** (was 33); `STYLE_GUIDE.md` § Enforcement's recorded-result table now lists `src/pages/PublicWarning.tsx` at 0 (only Location/Dashboard remain). `tools/mgmt-portal/CLAUDE.md` §5 gained the missing Public Warning row so the per-page behaviour checklist the acceptance criteria reference actually exists. Verification: `npm run build` PASS (tsc -b + vite; emitted CSS 42.53→40.26 kB = -2.27 kB of purged palette utilities, embedded `internal/assets/static` regenerated and confirmed to contain the new dialog/empty-state/badge strings); portal `go build ./...` + `go test ./internal/...` PASS; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Not verifiable here (no browser): both-theme rendering, the ConfirmDialog focus-trap/ESC/restore walk, and the §5 checklist (broadcast form defaults, live/stored flags, cancel+resend) are code-level verified only (plan risk 9 — the manual checklist is the regression control).
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(12) — UE Location page migrated onto the primitive layer, Leaflet dark-mode decision** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-14). `web/src/pages/Location.tsx` now composes a `PageHeader` (eyebrow "Test UEs", located/idle-unreachable `Badge`s → `success`+CheckCircle2 / `warning`+WifiOff), the Leaflet map in a `Card padded={false}` (`h-[460px] overflow-hidden`, so tiles inherit the standard surface/radius/border), the map-licence footnote in `text-muted-fg`, and the UE table on the `Table` family (caption, `scope="col"`, mono SUPI/NR cell/TAC-PLMN/lat/lon) with `Loading` skeletons, `TableEmptyRow` for an empty answer and `ErrorState`+Retry in place of the old inline red text. SUPI is visually truncated with the full value behind `sr-only` + `title` (the QoS convention). Status is no longer colour-only: the located badge is `success`+CheckCircle2, and an unreachable UE's badge pairs the LMF `cause`/5GMM state with WifiOff on `warning`. **Leaflet dark-mode decision (the plan's Phase-C requirement):** the light OpenStreetMap tile layer remains the single tile source and the dark theme inverts it with a CSS filter scoped to the **tile pane only** — `.dark .leaflet-tile-pane { filter: invert(1) hue-rotate(180deg) brightness(.92) contrast(.9) saturate(.75) }` in `src/index.css`. The dark tile-provider URL was rejected: it adds a runtime network dependency, a second attribution line and different offline behaviour for no gain. Scoping the filter to the pane (Leaflet's own `.leaflet-tile { filter: inherit }` propagates it) leaves the overlay/tooltip/control panes untouched, so markers stay readable. **The last raw hex colours in `src/` are gone:** the accuracy circle (`#3b82f6`) and located marker (`#16a34a`/`#22c55e`) now resolve from `useChartTheme()` (`series[0]`/`series[2]`), which re-evaluates on a theme flip — react-leaflet's `usePathOptions` re-applies `setStyle` on re-render, so a **live theme toggle re-styles the paths**; Leaflet needs concrete values, not classes. Leaflet's light-default vendor chrome is re-tinted with tokens in `index.css` (zoom bar, attribution, tooltip + arrow, container background/`font-family`), those rules deliberately **outside `@layer components`** because Tailwind hoists that layer ahead of the imported `leaflet.css` and an equal-specificity rule there is resolved in Leaflet's favour (verified against the emitted CSS: the base `.leaflet-container` rule lands after the vendor rules). Decision recorded in `STYLE_GUIDE.md` §7 (new "Map panel (Leaflet)" subsection) and §12 (the "Leaflet dark tiles" open decision is now closed); `tools/mgmt-portal/CLAUDE.md` §5 gained the missing UE Location row. Preserved verbatim: `MADRID`, `GMM_STATES`, `shortSupi`, `FitOnce` (first-render-only auto-fit), the 3 s `refetchInterval`, the `reachable && lat/lon != null` filter, `MapContainer center/zoom/scrollWheelZoom`, the OSM tile URL + attribution, marker/circle radius and fillOpacity/weight, the tooltip content, the 8 table columns, `toFixed(5)`, `Math.round(accuracy)` and `toLocaleTimeString()`. Raw-colour grep over the page → **0 hits** (was 15) and 0 hex literals; `STYLE_GUIDE.md` §10 recorded result now lists `src/pages/Location.tsx` at 0 (only Dashboard/PORTAL-UI-15 remains). Verification: `npm run build` PASS (tsc -b + vite; emitted CSS 41.32→41.39 kB, embedded `internal/assets/static` regenerated and confirmed to contain the new map/state strings); portal `go build ./...` + `go test ./internal/...` PASS; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Not verifiable here (no browser): the map's visual coherence in both themes (tile filter + marker contrast), the live theme-toggle re-style, and the §5 checklist are code-level verified only (plan risk 9 — the manual checklist is the regression control); tile appearance also needs outbound internet.
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase C(13) — Dashboard migrated onto the primitive layer (Phase C page rollout complete)** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase C, backlog PORTAL-UI-15). `web/src/pages/Dashboard.tsx` now composes a `PageHeader` (eyebrow "Overview"), the 4 KPI `StatCard`s (unchanged — Phase A had already moved them onto the `variant` enum), a **reserved Metrics grid**, the NF `Section` (9 `NFStatusCard`s) and the sessions `Section` with the `Table` family. **Phase F slots reserved** (the plan's Phase-C requirement): a `Section bare headingLevel={2} title="Metrics"` holds a `grid-cols-1 lg:grid-cols-3` of dashed-border `Card`s naming the three answers the dashboard must give (AMF registrations trend / failing procedures by result / UEs registered trend — PRD S16), each with its icon + description, so PORTAL-UI-18 becomes a drop-in that does not re-lay-out the page; the convention (dashed `Card` for reserved space, never a faked `ChartWrapper` state) is recorded in `STYLE_GUIDE.md` §7. **Every block gained its standard states** instead of the ad-hoc markup: the NF grid's 9 `animate-pulse` `bg-gray-900` divs are `Skeleton className="h-24 rounded-card"`, and the grid now distinguishes `DegradedState`+Retry (NRF discovery failed) from `EmptyState` ("No network functions discovered") and from the loading skeletons; the sessions block gained `Loading` skeletons and a `DegradedState`+Retry (PostgreSQL store unavailable — the old page rendered a failed fetch as "No active PDU sessions", i.e. it misreported a backend failure as an empty result) alongside the in-table empty row. The hand-rolled `<table>`/`<thead>` became the `Table` family (caption, `scope="col"`, mono SUPI/UE-IP cells, `text-muted-fg` timestamps) and the `Slice` column is an `info` `Badge` carrying `SST:x/SD:y` (the Sessions-page convention) instead of raw `SST:{sst} SD:{sd}` text — the old blue/green `text-blue-300`/`text-green-300` identifier colours are gone. **This closes the Phase C rollout: the § Enforcement grep over every `src/**/*.tsx` now returns 0 hits** (Dashboard was 12; burn-down 668 → 0), and `STYLE_GUIDE.md` §10 records the all-pages row. Preserved verbatim: the five queries and their `refetchInterval`s (nf-status 8 s; metrics-summary / sessions / ue-contexts 10 s; subscribers 30 s), `upCount = healthz_ok || metrics_ok`, the `?? 13` NF total, the `gmm_state === 1` registered count, all four KPI titles/values/subs/variants (`success`/`warning`, `info`, `accent`, default), `sessions?.length ?? metrics?.pdu_sessions ?? '—'`, the `slice(0, 8)` preview, `toLocaleTimeString()` and the five column headers. Verification: `npm run build` PASS (tsc -b + vite; emitted CSS 41.39→40.72 kB = -0.67 kB of purged palette utilities, embedded `internal/assets/static` regenerated and confirmed to contain the new reserved-slot/state strings and `border-dashed`); portal `go build ./...` + `go test ./internal/...` PASS; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no dependency change. Not verifiable here (no browser): both-theme rendering and the CLAUDE.md §5 Dashboard checklist are code-level verified only (plan risk 9 — the manual checklist is the regression control). Remaining Phase C-adjacent work: PORTAL-UI-16 (SPA fallback), PORTAL-UI-17 (metrics-range backend), PORTAL-UI-18 (charts), then PORTAL-UI-19 (Phase G sweeps + guide finalisation).
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase D — SPA deep-link / F5 fallback fixed in the Go router** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase D, backlog PORTAL-UI-16). The portal's `r.NotFound(http.FileServer(staticFS).ServeHTTP)` served the embedded bundle as a plain file server, so a browser refresh (F5) on any client-side route answered Go's `404 page not found` in `text/plain` instead of the React shell — the PRD's problem #1 (deep links dead). `internal/api/router.go` now installs a `spaFallback(staticFS)` handler with a defined resolution order: **(1)** the `/api`, `/api/**`, `/ws` and `/ws/**` namespaces always return a machine-readable JSON 404 (`{"error":"not found"}`, `application/json`) — an unknown API endpoint must not answer with the SPA shell; **(2)** a real asset that exists on disk (the hashed `assets/*.js`/`*.css`, fonts) wins and is served by the file server unchanged; **(3)** otherwise a **GET/HEAD navigation** — one whose `Accept` allows HTML (`text/html`, `application/xhtml+xml`, or `*/*`, the last so a manual `curl /qos` check works) — receives the embedded `index.html` through `http.ServeContent` (so `Content-Type: text/html; charset=utf-8`, `HEAD`, and `Range` are handled correctly), letting the client-side router render the deep-linked view; **(4)** anything else (a non-HTML fetch, a non-GET method) is a JSON 404. A missing `index.html` (unbuilt dev bundle) degrades to a JSON 404 rather than an empty `200`. Verified that chi invokes the **root** `NotFound` for unmatched paths inside mounted subrouters too — a probe confirmed `/api/v1/unknown`, `/api/nope`, `/ws/bad` and `/qos` all reached it — so one handler covers both the top level and the `/api/v1` group (no per-group `NotFound` needed). New `internal/api/router_test.go` (the plan's Phase-D test artifact) builds `NewRouter(Deps{}, http.FS(os.DirFS(tmp)))` over a temp `index.html` + one hashed asset and covers: deep link `/qos` → 200 `text/html` containing `<div id="root">`; `/` → the shell; `/api/v1/unknown` → 404 JSON with an `error` field and **no** shell leakage; the reserved namespaces `/api/v1/nope`/`/api/nope`/`/api`/`/ws/bad`/`/ws` → 404 JSON whatever the `Accept`; a real `/assets/app-abc123.js` → the asset bytes, never HTML; a JSON client on `/qos` → 404 JSON; and a missing-`index.html` router → 404 JSON; plus an `acceptsHTML` table test. `internal/api/pws_test.go` was left untouched and still passes. Verification: `go test ./internal/...` and `go test -race ./internal/...` PASS in the module, `go vet ./...` + `go build ./...` PASS; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no frontend build, no `package.json`/`go.mod` change, no NF code. Not verifiable here (no browser/live stack): the actual F5 walkthrough on a running portal — the router-level `httptest` assertions are the regression control. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase E — curated metrics-range backend for the dashboard charts** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase E, backlog PORTAL-UI-17). The portal had only instant Prometheus queries (`Client.Query` + `GET /api/v1/metrics/summary`), so the dashboard could not draw a trend. **`prometheus.Client.QueryRange(ctx, expr, start, end, stepSeconds)`** now calls the Prometheus HTTP API `/api/v1/query_range` (start/end as Unix seconds, step as `<n>s`), checks the HTTP status (the instant `Query` does not need to — `Summary` ignores failures) and decodes the `matrix` result into `[]MatrixSeries` (`{metric, values:[[unix_ts,"value"],…]}`). **The new endpoint `GET /api/v1/metrics/range?metric=<key>&from=<ts>&to=<ts>[&step=<s>]` is deliberately curated, not a PromQL proxy**: an unauthenticated UI able to submit free-form range queries is an injection/DoS surface (plan risk O2 — a long range query is expensive), so callers pick one of eight whitelisted keys (`ue_registered`, `ue_registered_by_slice`, `amf_registrations`, `procedure_rates_by_result`, `sbi_request_rate`, `sbi_latency_p99`, `pdu_sessions_active`, `authentication_rate`), each mapping to a **fixed expression** over the shared `fivegc_*` registry (`shared/observability/metrics`). `from`/`to` accept RFC3339 (what `Date.toISOString()` produces) or Unix seconds; `step` is optional and validated to **1–604800 s**, and when omitted the server computes `(to - from)/600` clamped to the same bounds (the plan's downsample step), so a 24 h window returns ~600 points instead of 8 640. Rate-based expressions contain a `$rate` token that the handler substitutes with `max(4×step, 30 s)`, so a downsampled series averages over an interval proportional to how often it is sampled. A window wider than **15 days** is rejected with 400 — Prometheus keeps 15 d by default (`observability/prometheus` + docker-compose set no retention override), so a wider range can only return nothing; the UI surfaces that as "beyond retention" rather than an empty frame (PRD §5.2). The response is the chart-friendly `{"metric","step","series":[{"name","points":[[t,v],…]}]}`; multi-series expressions get deterministic Prometheus-style names (`procedure_rates_by_result{result="OK"}`) with `__name__`/`job`/`instance` stripped, and **non-finite samples (`NaN`/`±Inf`, which JSON cannot encode) are omitted rather than coerced to zero** — a gap is the truthful "no data" (PRD §5.2/S19). Degradation is explicit: `Prometheus == nil` → **503** (distinct from a 200 with `series: []`, so "backend down" and "no data" are visually distinct), upstream failure → **502**, and every validation error → **400** before Prometheus is contacted. Verification: new `internal/prometheus/client_test.go` (4 tests: path + `query`/`start`/`end`/`step` params + matrix decode against an `httptest` fake; HTTP 400 → error; non-JSON → decode error; empty matrix → no series) and new `internal/api/metrics_test.go` (7 handler tests + 5 helper tests: route registration, a 13-case validation table asserting Prometheus is never called for bad input, the response shape + default step 6 s + injected `[30s]` window, empty result → `"series":[]`, NaN/±Inf dropped, nil client → 503, upstream 500 → 502, and unit tests for step resolution, time parsing, series naming, point filtering and expression expansion). `pws_test.go` and `router_test.go` untouched and still pass. `go test ./internal/...` + `go test -race` PASS; portal `go build ./...` + `go vet ./...` PASS; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no frontend change, no `package.json`/`go.mod` change, no NF code. `tools/mgmt-portal/CLAUDE.md` §4 documents the endpoint and its keys and §10 records the 503; the pre-existing `gofmt` misalignment in `internal/prometheus/client.go` (`MetricsSummary`) was fixed in passing. Not verifiable here (no live stack): the endpoint against a real Prometheus — the `httptest` fakes are the regression control; PORTAL-UI-18 (frontend charts + range control) is the consumer. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase F — Dashboard charts + range control (the reserved slots are live)** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase F, backlog PORTAL-UI-18). The Dashboard's three dashed placeholder cards (PORTAL-UI-15) are now real `ChartWrapper` charts fed by the PORTAL-UI-17 curated range endpoint, answering PRD S16: **AMF registrations** (`amf_registrations`), **Procedure results** by outcome (`procedure_rates_by_result`) and **UEs registered** (`ue_registered`, integer axis) — the grid stays `lg:grid-cols-3`, so Phase C's promise that Phase F would be a drop-in held. **New `lib/metricsRange.ts`** (React-free, the `navigation.ts` pattern) holds the pure logic: `RANGE_PRESETS` (15 m/1 h/6 h/24 h, default 1 h), `resolveRangeWindow`, `validateCustomRange`, `toDateTimeLocal`, `rangeLabel`, `seriesLabel` (`key{result="OK"}` → `OK`), `mergeSeries` (matrix series merged onto their shared timestamp grid), `isEmptySeries`, `chartSpanMs`, `formatTick`/`formatRangePoint`/`formatRangeValue`. **New `RangeControl` primitive** (`components/ui/RangeControl.tsx`, exported from the barrel): the PRD S17 preset buttons (`aria-pressed`, default 1 h) plus a custom `from`/`to` datetime picker whose draft is validated before it is applied — both ends present, end > start, **≥10 s** (the scrape interval) and **≤15 d** (Prometheus retention, matching the backend 400) — with the message announced via `role="alert"` and an invalid draft never applied. **Refresh model (PRD §5.2):** preset charts poll every 10 s with the query key holding only *(metric, preset id)* — the window is recomputed as `to = now` inside `queryFn`, so the chart slides forward without the selection resetting or flickering; a custom range is absolute and stops polling. **No-data discipline:** `mergeSeries` leaves a missing sample absent (Recharts gap) and `ChartWrapper` maps states `loading → isLoading`, `unavailable → request error` (the backend's 400/502/503 message is shown, so "backend down" is never a zero line), `empty → no samples`, else `ready`. **Accessibility:** every chart passes a `table` fallback (Time + one column per series) and an `ariaLabel`; multi-series charts additionally use a **dash-pattern discriminator** (solid / `6 3` / `2 4`) with a legend labelled in `text-fg` (small legend text must clear 4.5:1, which series colours 2/5 do not — the ramp is contrast-verified at 3:1 as a line/marker), and `ChartWrapper` now links its `role="img"` region to the description with `aria-describedby`. `lib/api.ts` gained `getMetricsRange(metric, from, to, step?)` + `MetricsMetric`/`MetricsRangeSeries`/`MetricsRange` mirroring the backend whitelist. Verified: `tsc -b` + `vite build` PASS (2278 modules; embedded `internal/assets/static` regenerated clean — single hashed JS/CSS pair, bundle 934 kB / 260 kB gzip now that Recharts is actually imported, emitted CSS 40.67 kB; asset grep confirms the new strings); the React-free helpers were exercised directly under `node --experimental-strip-types` (29 assertions: preset windows, local-time custom parsing, all five validation outcomes, series naming/merging/span/empty, tick + value formatting — all pass); raw-colour grep over the new/changed files and all of `src/**/*.tsx` → **0 hits**; portal `go build ./...` + `go test ./internal/...` PASS; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no new npm dependency (`package.json`/`package-lock` unchanged). `web/STYLE_GUIDE.md` §7 gained the RangeControl + Dashboard-chart conventions and §10 the PORTAL-UI-18 audit rows; `tools/mgmt-portal/CLAUDE.md` §3 (new files) and §5 (Dashboard) updated. Not verifiable here (no browser/live stack): both-theme chart rendering, the F5/deep-link chart path and the PRD S16–S19 visual checks (Prometheus live vs stopped, 24 h responsiveness) are code-level verified only — the plan's manual gates; PORTAL-UI-19 (Phase G sweeps) is the last task. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-16] mgmt-portal: **professional-view redesign, Phase G — a11y/contrast/responsive sweeps + STYLE_GUIDE finalised; the redesign is complete** (plan `.tmp/.ai/workspace/plans/mgmt-portal-ui-redesign.md` Phase G, backlog PORTAL-UI-19). The final task of the 19-task redesign: it closes the primitive-layer findings the page rollout recorded, sweeps the frontend for accessibility/contrast/responsive defects, and finalises the contract docs. **A real WCAG 1.4.3 defect was found and fixed.** The audits the guide describes were only partly machine-checkable, so a dependency-free `web/scripts/contrast-audit.mjs` now parses the `--c-*` triplets out of `src/index.css` (comment-stripped, both `:root` and `.dark`), asserts both palettes define the same token set, and checks **38 sanctioned pairs × 2 themes = 76 checks** (≥4.5:1 body, ≥3:1 large/UI-boundary/graphic) with a non-zero exit on failure. Running it exposed what neither the raw-colour grep nor the manually-maintained contrast table could see: **`text-primary` (`#2563EB`) is only 3.45:1 on the dark page and 3.03:1 on a dark card**, so the header wordmark and the primary `StatCard` failed AA in dark mode. The fix adds two text-role tokens beside the fill tokens — **`--c-primary-text`** (`#1D4ED8` light / `#60A5FA` dark, ≥5.2:1 on `bg`/`card`/`muted`) and **`--c-accent-text`** (`#9A3412` / `#FB923C`, ≥5.9:1), mapped to `text-primary-text`/`text-accent-text` and applied to `App.tsx`'s brand line and `StatCard`'s primary/accent values; `primary`/`accent` stay fills (`bg-primary`, `bg-accent`). Token count 39 → 41, both palettes still complete. **Contrast caveat resolved:** `success-fg` on the *light* log surface (4.46:1) is now explicitly **not** a log-surface token — the one call site (the ping `time=` colouring in `UERANSim.tsx`) moved to `text-fg`, and the pair is deliberately absent from the sanctioned list so the audit cannot bless a new misuse. **A11y sweep:** the below-`lg` navigation drawer now uses `useFocusTrap` (focus moves in, Tab cycles inside, ESC closes and restores focus) instead of a bare keydown listener, satisfying the overlay contract for the last non-`Modal` overlay; every `IconButton` still carries a required `label` (audited), every raw `<input>` now lives in the primitive layer, and the twelve sub-`text-xs` sizes (`text-[0.6rem]`/`[0.65rem]`/`[0.7rem]`/`[10px]`) scattered across Logs/UERANSim/PacketRusher/Policies were raised to `text-xs` — the guide already banned sub-12 px text for projector legibility. **Primitive consolidation (the findings the rollout deferred):** new **`Checkbox`** (Slices ×4, PCAP ×2 incl. a native `indeterminate` select-all, Policies ×1 — the six-plus repeated className strings are gone), new **`Disclosure`** (the QoS local component ×2 and the Policies `SpecReference` card-disclosure, one controlled/uncontrolled `aria-expanded`/`aria-controls` primitive), new **`SegmentedControl`** (native radios in a `fieldset`/`legend` with a peer-rendered focus ring; replaces the UERANSim PDU-session-type radiogroup *and* the QoS `Select` that duplicated it, so the two pickers finally match), and new shared **`src/lib/format.ts`** (`formatBytes`, `formatHex32`) replacing the per-page copies in PCAP/Sessions/UERANSim. The `Badge` legacy aliases (`green|red|yellow|blue|gray`) and the now-unused `components/Badge.tsx` + `components/PageHeader.tsx` shims were deleted (a page using one no longer compiles). **Docs:** `web/STYLE_GUIDE.md` finalised — new § 13 *Anticipated surfaces* (map panels, query forms, config forms, long-running orchestration status, data-dense tables) and § 14 *Phase-2 basic view* considerations; § 12 is now *Decisions (closed)* (accent kept as a fill + new text token; Google Fonts kept with system fallbacks; large-volume tables closed; formatting helpers resolved to `lib/format.ts`; old-URL redirects closed by PORTAL-UI-16); the token/contrast tables carry the measured values from the script; § 10 now documents **three** enforcement commands (raw-colour grep, the new fill-as-text grep, the contrast audit) and records the all-`src` clean result; the component catalogue documents Checkbox/Disclosure/SegmentedControl and the `primary-text`/`accent-text` rule. `docs/CLAUDIA_5GC_MANUAL.md` gained **§ 3.25 Management Portal (professional view)** (IA, theming, design system, charts, a11y bar, verification commands) and `tools/mgmt-portal/CLAUDE.md` §2/§3/§11 now point at the primitive layer + STYLE_GUIDE as the source of truth (new files, the three commands, the no-raw-`<input>`/`<button>` rule). Verification: `npm run build` PASS (tsc -b + vite, embedded `internal/assets/static` regenerated clean); all three enforcement commands CLEAN — raw-colour grep 0 hits over `src/**/*.tsx` + `src/**/*.ts`, fill-as-text grep 0, `node scripts/contrast-audit.mjs` → **76 checks passed, 0 failures**; portal `go build ./...` + `go test ./internal/...` PASS; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no new npm dependency (`package.json`/`package-lock` unchanged). Not verifiable here (no browser/live stack): the PRD S20–S23 manual checks — a keyboard-only walk of all 13 pages, the seven-overlay ESC/focus walk, both-theme rendering, the 1280/1024/768/1920 + projector sweep, and the live-vs-stopped Prometheus chart states — are code-level verified only (the plan's risk 9; the per-page `CLAUDE.md` §5 checklists remain the regression control).
- [2026-09-18] mgmt-portal: **Dashboard 3GPP-grounded 6-chart KPI rework** (plan `.tmp/.ai/workspace/plans/portal-dashboard-3gpp-kpi-rework.md`, backlog PORTAL-UI-20). The Dashboard "Metrics" panel grows from three to six charts, each a TS 28.554-grounded KPI ordered control plane → security → user plane: **UEs registered** (`ue_registered`, count), **Initial Registration success rate** (`registration_success_rate`, percent), **Procedure results** by outcome (`procedure_rates_by_result`, rate), **PDU sessions active** (`pdu_sessions_active`, count), **5G-AKA authentications** (`authentication_rate`, by result) and **N3 user-plane throughput** (`upf_gtp_throughput`, UL/DL bits/s). Two new curated whitelist keys were added to `internal/api/metrics.go` — `registration_success_rate` = `100 × OK-rate / total-rate` over `fivegc_procedure_total{nf="AMF",procedure="InitialRegistration"}` (TS 28.554 §5.1) and `upf_gtp_throughput` = `sum by (direction)(rate(fivegc_upf_gtp_bytes_total))*8` (TS 28.554 §5.3) — so the browser still never submits arbitrary PromQL (PORTAL-UI-17 contract). `MetricChart` gained **`percent`** (fixed `[0, 100]` domain, `%` ticks, `n.nn %` tooltip) and **`throughput`** (new `formatBitsPerSec` in `lib/format.ts`, SI bps→Tbps) axis modes; the `rate`/`count` rendering is byte-unchanged. No-data discipline is preserved: a window with no registration attempts yields `0/0 = NaN`, which the backend drops, so the success-rate chart shows a **gap**, never a 0%/100% line; Prometheus down → per-chart `unavailable`; no samples → `empty` (the throughput chart's empty copy states real user-plane traffic — e.g. a UERANSIM ping — is required). Tests: `internal/api/metrics_test.go` gained a new-key acceptance test, the direction-labelled `upf_gtp_throughput{direction="uplink"|"downlink"}` series-naming test, and an expression-pinning test asserting the `result="OK"`/`procedure="InitialRegistration"` selectors and the injected `[30s]` rate window with no remaining `$rate` token. Docs: `tools/mgmt-portal/CLAUDE.md` §4 (two new keys) + §5 (Dashboard row), `web/STYLE_GUIDE.md` §7 (6-chart table + axis modes) + §10 (recorded results), and `docs/implementation-status.md`. Verification: `npm run build` PASS; the three STYLE_GUIDE §10 enforcement commands CLEAN (0 raw-colour hits, 0 fill-as-text uses, `76 checks passed, 0 failures`); portal `go test ./internal/...` PASS; repo-root `make build` + `make test` PASS (`make lint` N/A — golangci-lint not installed, pre-existing); no new npm dependency. No `compliance-matrix.md` row — the portal is a dev tool and the KPI *formulas* follow TS 28.554 at clause-family level. docs: update CLAUDIA_5GC_MANUAL
- [2026-09-18] mgmt-portal: **Dashboard instant 5-minute success-rate KPI cards + truthful session-count fallback** (backlog PORTAL-UI-21). The Dashboard KPI row grows from four to six `StatCard`s with two instant success rates computed over a fixed **`[5m]`** window (≈30 scrapes at the 10 s interval): **Initial Registration** (`100 × OK-rate / total-rate` over `fivegc_procedure_total{nf="AMF",procedure="InitialRegistration"}`, TS 28.554 §5.1) and **PDU session establishment** (`100 × OK-rate / total-rate` over `fivegc_pdu_session_total`, §5.2), both surfaced by `GET /api/v1/metrics/summary` as `registration_success_pct` / `pdu_session_establishment_success_pct`. Both are **nullable `*float64`**: a window with no attempts (0/0 = NaN), an empty Prometheus result, or a non-finite sample all decode to `null`, and the card renders **"—"** — never a fabricated 0%/100% (`formatSuccessPct` in `Dashboard.tsx`). `prometheus.Client.Summary` also gained a one-line fix for a dead fallback: `count(smf_sessions_total)` (a series that no longer exists, so it always read 0) is now `sum(fivegc_pdu_sessions_active) or vector(0)`. Tests: `internal/prometheus/client_test.go` gained numeric-parse + NaN/empty → nil coverage and pins the corrected fallback expression and the `[5m]`/OK/InitialRegistration selectors; `internal/api/metrics_test.go` asserts `/metrics/summary` exposes both snake_case keys (numeric vs `null`). Live-verified against the running multi-slice stack: idle window → both `null`; forced NW-dereg → UE re-registration → both `100`; `pdu_sessions` now `5` (was 0). Frontend gate: `npm run build` + the three `STYLE_GUIDE.md` §10 commands clean (0 raw-colour, 0 fill-as-text, 76/76 contrast). No NF/shared/docker-compose change; no new dependency. docs: update CLAUDIA_5GC_MANUAL
