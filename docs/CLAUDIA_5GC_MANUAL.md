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
- **NW-initiated release**: `curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/$SUPI/pdu-sessions/1`.

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
- **Limitations**: real UPF PFCP Downlink Data Report is UPF-001 (simulated by SMF); UERANSIM UE does not auto-respond to paging.

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
