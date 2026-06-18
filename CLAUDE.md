# CLAUDE.md — 5GC Rel-17

From-scratch implementation of a **5G Core Standalone** conforming to **3GPP Release 17**.
NFs in Docker containers. SBA communication (HTTP/2 + JSON) + classic reference points
(NGAP/SCTP N2, PFCP/UDP N4, GTP-U N3/N6/N9).

**Master plan**: `PLAN_5GC_REL17.md`. **Implementation status**: see `docs/implementation-status.md`.

## Layout

```
nf/<nfname>/         One NF per folder — CLAUDE.md + Dockerfile + cmd/ + internal/ + config/ + tests/
shared/              Shared libraries: sbi/ logging/ observability/ types/ nas/ ngap/ pfcp/
specs/3gpp-openapi/  3GPP Rel-17 YAMLs
docs/procedures/     One .md per 3GPP procedure
observability/       Loki + Prometheus + Grafana + Promtail
tools/mgmt-portal/   Web portal Go+React, port 8080
nf/_template/        Template for new NFs
```

## Required Stack

- **Go 1.26.2** for all NFs. `ARG GO_VERSION=1.26.2` in Dockerfiles.
- **slog** (stdlib). Do not use logrus / zap / zerolog.
- **net/http + golang.org/x/net/http2** for SBI. Do not use gin / echo / fiber / chi in NFs.
- **Prometheus** (`prometheus/client_golang`). **OpenTelemetry** (`go.opentelemetry.io/otel`) → Jaeger.
- **PostgreSQL 16** for persistence, **Redis 7** for state caches.
- **godog** (BDD), **testcontainers-go** (integration tests).
- UPF future: Rust + eBPF/XDP. Until then, Go.
- **Exception `tools/mgmt-portal/`**: chi + gorilla/websocket + React 18 + Vite + Tailwind — forbidden in NFs.

## Code Conventions

- `gofmt` + `goimports` mandatory (pre-commit). `golangci-lint` — CI fails on warnings.
- Errors: `fmt.Errorf("amf: register UE: %w", err)`.
- Every blocking or network function: `ctx context.Context` as first parameter.
- No `panic` in production (yes in init and tests).
- Packages: lowercase, one word. Exported types: doc comment. Receivers: one character.
- `cmd/<name>/main.go` short: config → logger → server → signals → shutdown. Logic in `internal/`.

## Logging — Required Format

Structured JSON to stdout. Use `logging.NewProcedureLogger(ctx, "InitialRegistration")`.

Mandatory fields per procedure:

| Field | Value |
|---|---|
| `nf` | Uppercase: `AMF`, `SMF`, `NRF`, ... |
| `procedure` | CamelCase: `InitialRegistration`, `PduSessionEstablishment` |
| `correlation_id` | ULID via `X-Correlation-Id` header |
| `interface` | `N1`, `N2`, `N4`, `Namf`, `Nsmf`, ... |
| `direction` | `IN` or `OUT` |
| `spec_ref` | `TS 23.502 §4.2.2.2.2 step 5` |

Conditional fields: `supi`, `guti`, `pei`, `amf_ue_ngap_id`, `ran_ue_ngap_id`, `pdu_session_id`,
`seid`, `message_type`, `result` (`OK`/`REJECT`/`FAILURE`), `cause`, `duration_ms`.

## Make Commands

NF-level: `make build` · `make test` · `make test-functional` · `make lint` · `make docker` · `make run`

| Root Target | Action |
|---|---|
| `make up` / `make up-obs` | core / + observability |
| `make down` | docker-compose down -v |
| `make ueransim [UE_COUNT=N]` | core + obs + gNB + N UEs |
| `make ueransim-slices` | core + obs + 4 UEs multi-slice |
| `make test-slices` | suite T0–T9 |
| `make portal` | build portal + up-obs + mgmt-portal |
| `make pki` | regenerate dev certificates |
| `make sync-openapi` | download 3GPP YAMLs |
| `make handover-test` | core + obs + PacketRusher Xn handover scenario |
| `make handover-down` | stop handover profile containers |

**UERANSIM**: v3.2.8 built from source. `UE_COUNT` (default 1) controls number of UEs; changing requires `make ueransim` (not `ueransim-only`) to reseed UDR. SUCI: `protectionScheme: 0` (null-scheme). MSIN BCD low-nibble-first: `0000000001` → `[00 00 00 00 10]`. For SUCI Profile A (X25519): use `config/ueransim/ue-profile-a.yaml` with `protectionScheme: 1`.

## Workflow — Implementing a New Procedure

1. `docs/procedures/<procedure>.md` — sequence diagram (Mermaid) + spec ref + IEs + error cases.
2. `.feature` Cucumber — happy path + errors.
3. Implement handler + state machine + SBI calls.
4. Step definitions godog.
5. Integration test UERANSIM/gNBSim.
6. PCAP validation. See `docs/pcap-diagnostics.md`.
7. `docs/compliance-matrix.md` — mark as implemented.

**Do not skip steps.** §1 prevents misunderstandings; §7 prevents traceability debt.

## Claude Code Rules

- New NF → copy `nf/_template/` and read its CLAUDE.md.
- Before implementing a procedure → read the referenced 3GPP TS.
- When modifying OpenAPI schema → regenerate types + run all NF tests.
- When adding new SBI message → validate with `tools/compliance-checker`.
- Do not copy code from Open5GS (AGPL). free5GC (Apache-2.0) is the preferred codec reference.
- Commits: `feat(amf): implement X [TS 23.502 §4.2.2.2.2]`.
- Do not introduce new dependencies without justifying them in the PR.
- After any big change (new NF, new procedure, refactor touching multiple packages,
  new shared library) → run `/graphify . --update` to keep the knowledge graph current.
  See **Knowledge Graph** below.

## Knowledge Graph (graphify)

The repo is indexed as a navigable knowledge graph under `graphify-out/`
(`graph.html` interactive view · `GRAPH_REPORT.md` audit · `graph.json` raw data).
It captures NF coupling, god nodes, and cross-community bridges across the Go code + docs.

- **Keep it fresh.** After every big change to the code, run `/graphify . --update` so the
  graph re-extracts only new/changed files. Always work against the updated graph version.
- **Query before spelunking.** For any architecture or "what connects to what" question,
  prefer `/graphify query "<question>"` over a manual grep sweep — `graphify-out/graph.json`
  already exists, so questions are answered against the graph first.
- Do not commit `graphify-out/` build artifacts unless the team decides to track them.

## Anti-Patterns

- ❌ Business logic in `cmd/`. Everything goes to `internal/`.
- ❌ `fmt.Println` / `log.Printf`. Only `slog` via helper.
- ❌ Magic numbers for 3GPP timers — constants with doc + spec ref.
- ❌ Hardcoded hostnames — discover via NRF.
- ❌ Optional TLS — SBA always mTLS.
- ❌ Order-dependent tests.
- ❌ Mixing SBI and reference points in the same handler — separate packages.
- ❌ Service mesh (Istio/Linkerd).

## 3GPP References

| Topic | Spec |
|---|---|
| Architecture | TS 23.501 |
| Procedures | TS 23.502 |
| Policy & charging | TS 23.503 |
| NAS-5GS (N1) | TS 24.501 |
| NGAP (N2) | TS 38.413 |
| PFCP (N4) | TS 29.244 |
| GTP-U (N3/N9) | TS 29.281 |
| Security | TS 33.501 |
| SBA framework | TS 29.500, 29.501 |
| Common SBI types | TS 29.571 |

OpenAPI YAML: https://forge.3gpp.org/rep/all/5G_APIs (branch `Rel-17`).

## Feature Validation

Quick-reference for validating each recently implemented feature. Run `make up-obs` first unless stated otherwise.

### PCF SM Policy Lifecycle (TS 29.512 §5.2.2)
```bash
make ueransim
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
docker logs pcf | grep SmPolicyCreate    # should appear on session establishment
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"
docker logs pcf | grep SmPolicyDelete    # should appear on session release
```

### NW-Initiated Deregistration (TS 23.502 §4.2.2.3.3)
```bash
make ueransim
# Force deregistration via management API (port 9002):
SUPI=imsi-001010000000001
curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/$SUPI
# Or use the portal at http://localhost:8080/ueransim → Force Deregister
docker exec ueransim-ue nr-cli --dump    # UE should show MM-DEREGISTERED
docker logs amf | grep NetworkDeregistration
```

### NW-Initiated PDU Session Release (TS 23.502 §4.3.4.3)
```bash
make ueransim
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
SUPI=imsi-001010000000001
curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/$SUPI/pdu-sessions/1
docker logs upf | grep SessionDeletion   # PFCP entry cleaned
docker logs amf | grep PDUSessionRelease
```

### Xn Handover (TS 23.502 §4.9.1.2)
```bash
make handover-test
# PacketRusher executes a scripted Xn handover scenario.
# Expected in AMF logs:
docker logs amf | grep PathSwitchRequest
docker logs amf | grep "spec_ref.*4.9.1.2"
docker logs smf | grep PATH_SWITCH_REQ
# Clean up:
make handover-down
```
PacketRusher config: `config/packetrusher/packetrusher.yaml`. Compose service profile: `handover`.

Portal UI: navigate to **PacketRusher** (`http://localhost:8080/packetrusher`) to start/stop/pause
Xn and N2 scenarios, stream live logs (PacketRusher + AMF + SMF tabs), and watch the auto-detected
mobility-event checklist (UE Registered → PDU Session → HO Triggered → Path Switch → Complete).

### N2 Handover via Portal (TS 23.502 §4.9.1.3)
```bash
# Build image first (only needed once):
make handover-test   # builds packetrusher-local image; then stop if desired
# Use portal PacketRusher page → N2 Handover → Start
# Or CLI:
make handover-n2-test
docker logs amf | grep HandoverRequired
docker logs amf | grep HandoverCommand
docker logs amf | grep HandoverNotify
make handover-n2-down
```

### NRF NFStatusSubscribe/Notify (TS 29.510 §5.2.2.7-9)
```bash
make ueransim
# Kill SMF to trigger NF_DEREGISTERED notification:
docker stop smf
# NRF heartbeat eviction fires after TTL; or trigger deregister manually.
docker logs amf | grep "NF status notification"
docker logs nrf | grep NF_DEREGISTERED
# Restart SMF to confirm NF_REGISTERED notification:
docker start smf
docker logs amf | grep NF_REGISTERED
```

### NRF NFDiscover DNN Filter (TS 29.510 §6.2.3.2.3.1)
```bash
make ueransim
# SMF registers with dnnList=["internet"] on NRF startup.
# Verify DNN filter works:
curl -sk "https://localhost:8443/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&dnn=internet" | jq '.nfInstances | length'  # expect 1
curl -sk "https://localhost:8443/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&dnn=voip"    | jq '.nfInstances | length'  # expect 0
# BDD test (in-process, no stack needed):
cd nf/nrf && make test-functional
```

### SUCI Profile A — X25519 ECIES (TS 33.501 §6.12, Annex C.3)
```bash
# UE config: config/ueransim/ue-profile-a.yaml  (protectionScheme: 1)
# Dev key pair — TS 33.501 Annex C.3 published test vector (not a secret; included for out-of-the-box dev use):
#   private: see nf/udm/config/dev.yaml (hn_private_key_x25519)
#   public:  61cdb319f72eddfbac55c06c3ec38d15828880a259cbc11cc03ca92abb60fb5e

# CLI:
make ueransim-profile-a        # core + obs + gnb + ueransim-ue-profile-a
docker logs ueransim-ue-profile-a   # watch nr-ue registration
docker logs udm | grep "SUCI Profile A"   # deconcealment log
docker logs amf | grep "supi.*imsi"       # resolved SUPI in AMF
make ueransim-profile-a-down   # stop

# Portal (run make ueransim-profile-a or make full once to create containers):
# http://localhost:8080/ueransim → Scenarios → SUCI Profile A → Start
```
Home network private key loaded from `nf/udm/config/dev.yaml` (`hn_private_key_x25519`) or `HN_PRIVATE_KEY_X25519` env var.
Docker-compose profile: `suci-profile-a`. Container: `ueransim-ue-profile-a`. Shares `ueransim-gnb` with standard scenario.

### URSP Policy Delivery (TS 24.526 / TS 29.525)
```bash
make ueransim

# Full end-to-end validation suite (U0–U9):
make validate-ursp

# Codec-only unit tests (no stack needed):
make test-ursp-codec

# Manual checks:
SUPI=imsi-001010000000001
docker logs pcf | grep "policy association"          # N15 at registration
docker logs amf | grep "UE policy container sent"    # DL NAS Transport, payload container type 0x05

# URSP is delivered via the UE policy delivery service (TS 24.501 Annex D):
# a MANAGE UE POLICY COMMAND in a DL NAS Transport (payload container type 0x05).
# NOT the Configuration Update Command, NOT IEI 0x7B. UERANSIM v3.2.8 has no
# URSP support, so it logs "Unhandled payload container type [5]" and does not ACK.

# On-demand push (UE must be CM-CONNECTED):
curl -X POST http://localhost:9002/amf/v1/ue-contexts/$SUPI/push-policies
docker logs amf | grep "ursp_version"                # increments on each send

# Decode the UE Policy Container (human-readable URSP rules):
docker exec amf curl -sk --http2-prior-knowledge \
  -X POST https://pcf:8006/npcf-ue-policy-control/v1/ue-policies \
  -H 'Content-Type: application/json' \
  -d "{\"supi\":\"$SUPI\",\"servingPlmn\":\"00101\"}" | \
  python3 scripts/decode-ursp.py

# Per-subscriber override via UDR API:
curl -X PUT http://localhost:8003/nudr-dr/v2/policy-data/$SUPI/ue-policy-set \
  -H "Content-Type: application/json" \
  -d '{"precedence":10,"rules":[{"precedence":10,"traffic_descriptor":{"dnns":["ims"]},"route_sel_descriptors":[{"precedence":1,"ssc_mode":1,"snssai":{"sst":1,"sd":"000002"},"dnn":"ims","pdu_session_type":1}]}]}'

# Portal: http://localhost:8080/policies
#   → Policy Templates section: 4 slice cards (Internet/Gold/Silver/Bronze)
#     Each card: view JSON rules, edit, Apply to UE button
#   → Apply to UE dialog: pick registered UE, optionally customise rules,
#     see 3GPP spec reference (IEI types, delivery path), click Apply & Push
#   → Per-Subscriber Policies section: list active overrides with Push button

# API: apply a template to a UE via portal:
curl -X POST http://localhost:8080/api/v1/policy-templates/<template-id>/apply \
  -H "Content-Type: application/json" \
  -d "{\"supi\":\"$SUPI\"}"
# Returns: {"status":"pushed"} or {"status":"stored","warning":"..."}
```

### PDU Session QoS Management (TS 23.501 §5.7 / TS 23.502 §4.3.3.2)
```bash
make ueransim
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"

# 5QI selection at establishment: PCF override > UDM subscription (sm-data) > operator default.
docker logs smf | grep "subscribed default QoS"     # N10 Nudm_SDM sm-data fetch
docker logs smf | grep qos_source                   # PCF_OVERRIDE | UDM_SUBSCRIPTION | OPERATOR_DEFAULT
docker logs upf | grep "qer_id"                     # QER installed (TS 29.244 §7.5.2.5)

# Session inspection (SMF management API — internal, not 3GPP):
curl -sk https://localhost:8004/nsmf-management/v1/sessions | jq

# NW-initiated 5QI modification (full §4.3.3.2 flow: N4 QER → N2 Modify → NAS 0xCB):
curl -sk -X POST https://localhost:8004/nsmf-management/v1/sessions/1/qos \
  -H 'Content-Type: application/json' \
  -d '{"5qi":7,"reason":"upgrade to interactive video"}'
docker logs smf | grep NetworkQoSModification
docker logs upf | grep "QER updated"
docker logs amf | grep "QoS Modification Command"

# Subscriber default QoS from UDM:
curl -sk https://localhost:8003/nudm-sdm/v2/imsi-001010000000001/sm-data | jq

# MCP tools: pdu_session_list, pdu_session_qos_get, pdu_session_qos_set, subscription_qos_get.
# Portal: http://localhost:8080/qos — session table, Modify QoS drawer,
#   subscription inspector, collapsible E2E validation panel.

# Unit tests:
go test ./shared/nas/ ./nf/smf/internal/server/ ./nf/upf/internal/pfcp/ ./nf/pcf/internal/server/
```

### NW-Triggered Additional PDU Session (TS 23.503 §6.6.2 / TS 23.502 §4.3.2.2.1)
```bash
make ueransim
# 3GPP has no NW-initiated PDU Session Establishment — the network steers the UE via URSP:
# app detected → PCF DNN-scoped QoS override + URSP rule → AMF UE-policy push (DL NAS 0x05)
# → UE-requested establishment of an ADDITIONAL PSI. UE-side URSP evaluation is simulated
# via nr-cli (UERANSIM v3.2.8 has no URSP). See docs/procedures/nw-triggered-pdu-session.md.

# One-shot trigger (orchestrates the 5 steps and verifies the new PSI):
curl -s -X POST http://localhost:8080/api/v1/qos/nw-sessions \
  -H 'Content-Type: application/json' \
  -d '{"supi":"imsi-001010000000001","app":"cloud-gaming","dnn":"internet",
       "sst":1,"sd":"000001","5qi":3,"ambr_uplink":"30 Mbps","ambr_downlink":"100 Mbps"}' | jq
# Expected: success=true, new pdu_session_id (existing sessions untouched), qos_source=PCF_OVERRIDE.
# NOTE: verify takes ~17-25 s — UERANSIM bars the first nr-cli ps-establish on a UAC
# timing race and retransmits on T3580 (+16 s). This is a UERANSIM quirk, not a core issue.

docker logs pcf | grep "QoS override set"            # DNN-scoped override stored
docker logs amf | grep "UE policy container sent"    # URSP delivery (ursp_version increments)
docker logs smf | grep qos_source                    # new session → PCF_OVERRIDE
curl -s http://localhost:8080/api/v1/qos/sessions | jq   # additional PSI listed

# DNN-scoped PCF override directly (internal API):
docker exec amf wget -qO- --no-check-certificate \
  https://pcf:8006/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override?dnn=internet

# Portal: http://localhost:8080/qos → "NW-Triggered PDU Session" panel —
#   UE picker, app presets (cloud-gaming/voice-call/video-stream/ims-signalling → 5QI),
#   DNN + S-NSSAI + AMBR form, live 5-step orchestration checklist.

# Unit tests (DNN-scoped override precedence):
go test ./nf/pcf/internal/server/ -run "TestSmPolicyDNNScopedOverride|TestQoSOverrideAPIDNNScope"
```

### DNN Subnet Isolation (TS 23.501 §5.6.5)
Each DNN has an isolated UE IP pool and a dedicated N6 Docker network.

| DNN | UE Subnet | TUN | N6 Docker Network |
|---|---|---|---|
| `internet` | `10.60.0.0/24` | `upfgtp0` @ `10.60.0.254/24` | `5gc-n6` (`172.30.6.0/24`) |
| `ims` | `10.61.0.0/24` | `upfgtp1` @ `10.61.0.254/24` | `5gc-n6-ims` (`172.30.7.0/24`) |

**Single source of truth**: `config/operator.yaml` `dnns:` section.
Per-NF YAML (`nf/smf/config/dev.yaml`, `nf/upf/config/dev.yaml`) refines pool/TUN details.

**Adding a new DNN** (e.g., `mms`):
1. Add entry in `config/operator.yaml` under `dnns:` with `ue_ip_pool: "10.62.0.0/24"` and `n6_network: "172.30.8.0/24"`
2. Add entry in `nf/smf/config/dev.yaml` under `dnns:` with matching `ue_ip_pool`
3. Add entry in `nf/upf/config/dev.yaml` under `dnns:` with `tun_name: "upfgtp2"`, `tun_addr: "10.62.0.254/24"`, `gateway_ip: "172.30.8.1"`
4. Add `n6-mms-net` (subnet `172.30.8.0/24`) in `docker-compose.yml` and attach UPF to it
5. `make down && make up` (or `make ueransim`)

```bash
# Verify DNN subnet isolation after make ueransim:
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
docker logs smf | grep '"dnn":"internet"'   # pool selected
docker logs upf | grep "upfgtp0"           # TUN used for internet

# IMS session (requires UE config with dnn=ims):
docker logs smf | grep '"dnn":"ims"'        # ims pool
docker logs upf | grep "upfgtp1"           # TUN used for IMS
```

### BDD Functional Tests
```bash
# NRF — 3 scenarios, fully in-process (no running stack needed):
cd nf/nrf && make test-functional

# AMF — 3 scenarios, require E2E_TEST=1 + running UERANSIM stack:
make ueransim
cd nf/amf && E2E_TEST=1 make test-functional
# Without E2E_TEST=1 all scenarios report as pending (expected — exit 0).
cd nf/amf && make test-functional
```

## PCAP

Sidecar tcpdump (5 min/file, max 12). `./scripts/pcap-control.sh [status|pause|resume|rotate|list] [nf]`.
See `docs/pcap-diagnostics.md` for NGAP/HTTP2 troubleshooting.
Every new NF: canonical logs + NRF registration + `/metrics` Prometheus + PCAP sidecar in docker-compose.
