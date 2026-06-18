# ClaudIA 5GC Rel-17 — From-Scratch Implementation

ClaudIA 5GC Standalone implementation conforming to 3GPP Release 17, containerized with Docker, observable end-to-end, and managed via a centralized web portal.

> **Current status**: NRF + AMF + SMF + UPF + PCF + UDM + AUSF + NSSF + UDR operational. E2E integration with UERANSIM verified. Network slicing: 4 slices (internet/gold/silver/bronze) with per-DNN subnet isolation. Implemented procedures include PCF SM policy lifecycle, NW-initiated deregistration and PDU session release, Xn and N2 handover, NRF NFStatusSubscribe/Notify, DNN- and SNSSAI-filtered NRF discovery, SUCI Profile A (X25519), full URSP policy delivery (UE policy container), PDU session QoS management, and NW-triggered additional PDU sessions. Tooling: web management portal in `tools/mgmt-portal`, an MCP server in `mcp/` exposing the core to LLM clients, and PacketRusher-driven handover scenarios.

---

## Prerequisites

The following tools must be installed and accessible to your user (not just root) before running any `make` target.

| Tool | Minimum version | Notes |
|------|----------------|-------|
| **Docker Engine** | 24.x | Must be usable without `sudo` — see [Docker permissions](#docker-permission-denied-make-fails-on-docker-build) below |
| **Docker Compose** | v2 (plugin) | Comes bundled with Docker Desktop / Engine ≥ 24 |
| **Make** | GNU Make 4.x | `sudo apt install make` on Debian/Ubuntu |
| **npm** | 18+ (Node LTS) | **Cannot run as root** — install via [nvm](https://github.com/nvm-sh/nvm) or the distro package, not via `sudo npm` |

> **Why no `sudo make`?** The portal frontend build calls `npm`, which refuses to run as root by default. Running `sudo make` causes the portal build to fail even if Docker works. The correct fix is to add your user to the `docker` group (see below) so you can run `make` as your regular user.

---

## Quickstart

```bash
# 1. Generate dev PKI (CA + cert per NF) — first time only
make pki

# 2. Bring up the full stack: NFs + obs + portal + UERANSIM 4 UEs multi-slice
make full

# 3. Access the services
open http://localhost:8080   # Management portal
open http://localhost:3000   # Grafana (admin/admin)
open http://localhost:16686  # Jaeger (tracing)

# 4. Validate network slicing (T0–T9)
make test-slices

# 5. Bring everything down
make full-down
```

> **Alternative quickstarts:**
> ```bash
> make portal         # Core + observability + portal (no UERANSIM)
> make ueransim-slices  # Core + obs + 4 UEs multi-slice (no portal)
> make up-obs         # Core + observability only
> ```

---

## Troubleshooting

### Docker permission denied — `make` fails on `docker build`

**Symptom:**
```
ERROR: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

**Cause:** Your user is not in the `docker` group.

**Fix:**
```bash
sudo usermod -aG docker $USER   # add yourself to the docker group
newgrp docker                   # activate the new group in the current shell
make full                        # retry — no sudo needed
```

If `newgrp docker` does not help, log out and back in, then retry.

> Do **not** use `sudo make`. That breaks the portal's npm build step.

---

## ClaudIA 5GC Management Portal — `http://localhost:8080`

The web portal centralizes all core operations: no CLI commands needed to manage subscribers, containers, or slices.

### Quick Access

```bash
make portal          # Bring up core + observability + portal (build included)
make docker-portal   # Build portal image only
make portal-build    # Alias for docker-portal
```

### Available Pages

| Page | URL | Description |
|--------|-----|-------------|
| **Dashboard** | `/` | Real-time KPIs: NFs online/total, provisioned subscribers, active PDU sessions. Status grid for all 9 NFs with per-NF healthz and Prometheus indicators |
| **Subscribers** | `/subscribers` | Full CRUD for subscribers from PostgreSQL. Create/edit/delete UEs with SUPI, K, OPc, NSSAI, AMBR. UEs seeded by UERANSIM appear automatically |
| **Network Slices** | `/slices` | Configured S-NSSAIs across AMF, SMF, and NSSF. Edit YAML configs per-NF with optional auto-restart on save |
| **Services** | `/services` | Start/Stop/Restart any Docker container in the compose project. Shows running/total count and uptime per container |
| **Sessions** | `/sessions` | Active PDU sessions and UE contexts read live from PostgreSQL |
| **QoS** | `/qos` | PDU session table with 5QI per session color-coded by category (GBR / Non-GBR / Delay-critical, TS 23.501 Table 5.7.4-1). **Modify QoS drawer**: NW-initiated 5QI change (TS 23.502 §4.3.3.2). **Subscription QoS inspector**: look up UDM SM subscription defaults per SUPI (TS 29.503). **NW-Triggered PDU Session panel**: orchestrate an additional PSI via URSP steering with 5-step live checklist (TS 23.503 §6.6.2). **E2E validation panel**: automated end-to-end QoS verification |
| **Policies** | `/policies` | **Policy Templates**: 4 slice-scoped URSP templates (internet / gold / silver / bronze) — create, edit, delete JSON rule sets. **Apply to UE dialog**: pick a registered UE, optionally customize rules, view the 3GPP delivery path (PCF N15 → AMF → DL NAS Transport), and push in one click. **Per-subscriber overrides**: list active per-SUPI policies with inline Push button. Collapsible spec reference showing IEI encoding and delivery flow (TS 24.526 / TS 29.525 / TS 24.501 Annex D) |
| **UERANSIM** | `/ueransim` | **Test Scenarios panel**: Standard / Multi-Slice / SUCI Profile A — one-click Start/Stop with automatic conflict resolution. Per-container start/stop, live log streaming, **ping test** (selectable source UE IP), `nr-cli` commands (ps-establish, ps-release, deregister, ps-list), PDU session details per UE. **Force Deregister** via AMF management API |
| **PacketRusher** | `/packetrusher` | Xn Handover (TS 23.502 §4.9.1.2) and N2 Handover (TS 23.502 §4.9.1.3) scenario control — Start/Stop/Pause/Resume per scenario. **Live log tabs**: PacketRusher (Xn), PacketRusher (N2), AMF, SMF. **Mobility event checklist**: auto-detected checkpoints from live logs (UE Registered → PDU Session → HO Triggered → Path Switch / HandoverCommand → Handover Complete) |
| **Logs** | `/logs` | Real-time log streaming via Docker API. Per-container selector, text filter, pause, export. Structured JSON parsing with level-based colorization |
| **PCAP** | `/pcap` | On-demand tcpdump per NF sidecar (off by default). Start/Stop, 5-minute rotating files, direct `.pcap` download |

### Portal Architecture

```
Browser (React 18 + Vite + Tailwind CSS)
    ↕ REST /api/v1/*
    ↕ WebSocket /ws/logs/{container}
Go Backend (tools/mgmt-portal, port 8080)
    ├── PostgreSQL 16 ─── Subscribers, PDU sessions, UE contexts
    ├── Docker socket ──── Container lifecycle + exec (nr-cli)
    ├── NRF HTTP/2 ─────── NF registry status
    └── Prometheus HTTP ── Metrics summary
```

The Go binary embeds compiled React assets (`embed.FS`). Single container, no separate static server.

---

## Make Commands

### Full Stack

| Command | Description |
|---------|-------------|
| `make full` | **Build + bring up ALL**: NFs + observability + portal + UERANSIM 4 UEs multi-slice |
| `make full-down` | Stop and clean volumes for full stack |

### Core and Observability

| Command | Description |
|---------|-------------|
| `make up` | Bring up core (NFs) only |
| `make up-obs` | Bring up core + observability (Loki, Prometheus, Grafana, Jaeger) |
| `make down` | Stop all and clean volumes |

### Management Portal

| Command | Description |
|---------|-------------|
| `make portal` | Build image + bring up core + obs + portal |
| `make docker-portal` | Build portal Docker image only |
| `make portal-build` | Alias for `docker-portal` |

### UERANSIM

| Command | Description |
|---------|-------------|
| `make ueransim` | Bring up core + obs + UERANSIM (gNB + N UEs). Accepts `UE_COUNT=N` |
| `make ueransim-ursp` | Build + bring up the full core + obs + UERANSIM **with URSP delivery** (default) |
| `make ueransim-no-ursp` | Build + bring up the full core + obs + UERANSIM **without URSP delivery** |
| `make ueransim-only` | Bring up UERANSIM only (without touching core). Accepts `UE_COUNT=N` |
| `make ueransim-down` | Stop UERANSIM containers |
| `make ueransim-slices` | Bring up core + obs + 4 UEs multi-slice (internet/gold/silver/bronze) |
| `make ueransim-slices-down` | Stop multi-slice profile containers |
| `make ueransim-profile-a` | Bring up core + obs + gNB + SUCI Profile A UE (X25519 ECIES, TS 33.501 §C.3) |
| `make ueransim-profile-a-down` | Stop SUCI Profile A containers |
| `make logs-slices` | Tail logs from 4 multi-slice UEs |
| `make test-slices` | Run T0–T9 validation suite |

### Xn & N2 Handover

| Command | Description |
|---------|-------------|
| `make handover-test` | Core + obs + PacketRusher Xn handover scenario (TS 23.502 §4.9.1.2) |
| `make handover-n2-test` | Core + obs + PacketRusher N2 handover scenario (TS 23.502 §4.9.1.3) |
| `make handover-down` | Stop Xn handover profile containers |
| `make handover-n2-down` | Stop N2 handover profile containers |

### Compile With / Without URSP Policy Delivery

The full core can be built and run in two scenarios so you can compare behaviour
with and without **URSP** (UE Route Selection Policy) delivery. Both targets
rebuild the images and bring up core + observability + UERANSIM — they differ only
in whether the AMF requests URSP from the PCF (N15) and delivers a UE policy
container to the UE.

| Command | Scenario |
|---------|----------|
| `make ueransim-ursp` | **With URSP** — AMF fetches URSP over N15 and delivers it via DL NAS Transport (payload container type `0x05`, a MANAGE UE POLICY COMMAND per TS 24.501 Annex D) |
| `make ueransim-no-ursp` | **Without URSP** — AMF makes no N15 call and delivers no UE policy container; the rest of the core runs identically |

Both accept `UE_COUNT=N`. The PCF keeps serving SM policy (N7) in both scenarios;
only URSP delivery is toggled.

```bash
# With URSP (default behaviour)
make ueransim-ursp
docker logs amf | grep "UE policy container sent"     # confirms delivery

# Without URSP
make ueransim-no-ursp
docker logs amf | grep "URSP delivery disabled"       # confirms it is off
```

**How the toggle works.** The AMF reads the `URSP_ENABLED` environment variable
(default `true`), which the two make targets set for you. You can also flip it on
any compose command, or persist it in the AMF config:

```bash
URSP_ENABLED=false make up-obs        # ad-hoc, any target
```
```yaml
# nf/amf/config/dev.yaml
features:
  ursp_enabled: false                 # env var overrides this
```

Resolution order: `URSP_ENABLED` env → `features.ursp_enabled` in the AMF config →
default (enabled).

> **Note:** UERANSIM v3.2.8 does not implement the UE policy delivery service, so in
> the *with URSP* scenario it logs `Unhandled DL NAS Transport payload container
> type [5]` and does not ACK. The AMF still emits a spec-correct, Wireshark-decodable
> PDU; a real UE would apply the rules and reply with MANAGE UE POLICY COMPLETE.
> Decode the container with `python3 scripts/decode-ursp.py` (see `make validate-ursp`).

### Security Debug Flags (AMF)

The AMF config (`nf/amf/config/dev.yaml`) exposes a `security:` block with optional
overrides for development and Wireshark tracing. **Never enable these in production.**

#### `null_ciphering` — NEA0 no-encryption mode

```yaml
# nf/amf/config/dev.yaml
security:
  null_ciphering: true   # default: false
```

When `true`, the AMF negotiates **NEA0** (null ciphering) with every UE during the
Security Mode Command (TS 33.501 §6.7.2). Integrity protection continues to use the
best algorithm the UE supports (NIA2 or NIA1) — IA0 is never selected alongside EA0
in non-emergency registrations as required by TS 33.501 §6.7.2. The result: NAS
payloads are sent and received as plain text, so **Wireshark decodes them without any
key export or NAS decryption plugin**.

> **Why keep integrity on?** TS 33.501 §6.7.2 forbids the combination EA0+IA0 in
> normal registrations. UERANSIM enforces this and would reject a Security Mode Command
> that proposed both null ciphering and null integrity. Keeping NIA2/NIA1 satisfies the
> spec while still giving you unencrypted NAS for capture analysis.

**How to enable:**

```bash
# Option 1 — edit config (persisted)
# Set null_ciphering: true in nf/amf/config/dev.yaml, then rebuild:
make docker && make ueransim

# Option 2 — env var (no rebuild needed, overrides config file)
NEA0_DEBUG=true make ueransim
# or on a running stack:
docker compose -f docker/docker-compose.yml stop amf
NEA0_DEBUG=true docker compose -f docker/docker-compose.yml up -d amf

# Confirm it is active:
docker logs amf | grep "null_ciphering"
# Expected: {"level":"WARN","nf":"AMF","msg":"null_ciphering enabled — NEA0 forced; production use forbidden"}
```

**How to disable:**

```bash
# Set null_ciphering: false (or remove the key) in nf/amf/config/dev.yaml
# and restart (or unset NEA0_DEBUG).
make docker && make ueransim
```

> **Never enable in production.** With null ciphering active, all NAS traffic
> (including authentication vectors and NAS PDUs) is transmitted in the clear over the
> air interface.

---

### Build and Tests

| Command | Description |
|---------|-------------|
| `make build` | Build all NFs |
| `make test` | Unit tests for all NFs |
| `make lint` | golangci-lint for all NFs |
| `make docker` | Build all Docker images |
| `make pki` | Generate dev PKI (CA + cert per NF) |

---

## Implemented NFs

| NF | Status | Features |
|----|--------|----------|
| NRF | ✅ Operational | Register/Discover/Deregister + Heartbeat + OAuth2 JWT + mTLS; Redis backend (TTL-eviction); NFStatusSubscribe/Notify; DNN + SNSSAI + service-name discovery filters |
| AMF | ✅ Operational | Registration, PDU Session Est./Mod./Release, Deregistration (UE + NW-initiated), Service Request, AN Release, Xn Handover (PathSwitchRequest), N2 Handover (NH/NCC security), NW-initiated QoS modification, URSP/UE-policy delivery (DL NAS Transport, payload container 0x05) — NAS security NIA2+NEA2; NSSAI + NSSF; lifecycle timers (T3512/MobileReachable/ImplicitDetach/PendingRemoval); PostgreSQL UE contexts + Redis TMSI |
| SMF | ✅ Operational | PDU Session Establishment + Modification, NW-initiated 5QI modification (N4 QER → N2 → NAS), PCF SM policy create/delete lifecycle, UDM sm-data QoS, per-DNN IP allocation, N1SM/N2SM encoding verified e2e; PATH_SWITCH_REQ handling; 4 SNSSAIs + DNN list on NRF; nsmf-management API; PostgreSQL sessions |
| NSSF | ✅ Operational | Nnssf_NSSelection_Get (TS 29.531); static NSSAI intersection; NRF registration; 8 unit tests |
| PCF | ✅ Operational | SM Policy Control (N7, config-driven QoS/AMBR), UE Policy Control N15 (TS 29.525) + URSP delivery (TS 24.526), DNN-scoped QoS overrides, per-subscriber UDR override |
| UPF | ✅ Operational | PFCP session table, GTP-U decap/encap (ext-header skip), QER install/update, per-DNN TUN + iptables MASQUERADE, DNN subnet isolation, e2e ping verified |
| UDR | ✅ Operational | PostgreSQL 16 + fallback in-memory, auto-migrate; NSSAI profiles + per-subscriber URSP/policy data |
| AUSF | 🟡 MVP | 5G-AKA happy path; Redis auth context store (TTL 5 min) |
| UDM | 🟡 MVP | Auth + AM data + UECM + SDM sm-data; SUCI deconcealment (null-scheme + Profile A X25519) |

---

## Network Slicing

Four development slices (TS 23.501 §5.15):

| Slice | SST | SD | Type | Assigned IMSI |
|-------|-----|----|------|---------------|
| internet | 1 | 000001 | eMBB default | imsi-001010000000001 |
| gold | 1 | 000002 | eMBB premium | imsi-001010000000002 |
| silver | 2 | 000001 | URLLC | imsi-001010000000003 |
| bronze | 3 | 000001 | MIoT | imsi-001010000000004 |

```bash
# Multi-slice quickstart
make ueransim-slices      # core + obs + 4 UEs
make test-slices          # suite T0–T9 (wait ~2 min)
make logs-slices          # tail logs

# Or manage from the portal:
make portal               # http://localhost:8080/ueransim
```

### How NSSAI Validation Works (TS 23.502 §4.2.2.2.2 + §4.2.9)

1. UE sends `RequestedNSSAI` in Registration Request.
2. AMF calls NSSF (`GET /nnssf-nsselection/v2/...`) with requested NSSAI.
3. NSSF returns intersection with config's `allowed_slices`.
4. AMF intersects NSSF result with UDM subscription → `AllowedNSSAI`.
5. Empty `AllowedNSSAI` → log `NSSAI_NOT_ALLOWED`.

---

## UERANSIM

### Single UE Mode

```bash
# First time (builds everything)
make ueransim

# Subsequent times (launch only, faster)
make ueransim-only

# Multiple UEs (UDR auto-seeds N subscribers)
make ueransim UE_COUNT=4

# Verify registration
docker exec ueransim-ue nr-cli --dump
docker exec ueransim-ue ip a | grep uesimtun

# Bring down
make down
```

### SUCI Profile A (X25519 ECIES)

Validates SUCI deconcealment with protection scheme 1 (TS 33.501 §C.3). The UE sends a SUCI instead of a plaintext SUPI; UDM decrypts it using the home network private key.

```bash
# CLI
make ueransim-profile-a
docker logs ueransim-ue-profile-a        # confirm MM-REGISTERED
docker logs udm | grep "SUCI Profile A"  # deconcealment in UDM
docker logs amf | grep "supi.*imsi"      # resolved SUPI in AMF
make ueransim-profile-a-down

# Portal — after make ueransim-profile-a (or make full) has created containers:
# http://localhost:8080/ueransim  →  Scenarios  →  SUCI Profile A  →  Start
```

The portal's **Scenarios** panel lets you switch between Standard, Multi-Slice, and SUCI Profile A with one click — it automatically stops conflicting containers before starting the new scenario.

### nr-cli Commands

```bash
# From CLI (equivalent to using portal at /ueransim)
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "deregister"
docker exec ueransim-ue nr-cli --dump    # list all active UEs
```

> The `/ueransim` portal executes these same commands via Docker exec API.

---

## Tests

### Unit Tests

```bash
go test ./...
go test ./shared/nas/...              # NAS codec
go test ./nf/amf/internal/ngap/...   # NGAP codec AMF
go test ./nf/smf/internal/server/... # SMF handlers + N2SM APER
go test ./shared/crypto/...           # SUCI deconcealment, NIA2, NEA2
```

### BDD Functional Tests (godog)

```bash
# NRF — 3 in-process scenarios (no running stack needed):
cd nf/nrf && make test-functional

# AMF — 3 E2E scenarios (require UERANSIM running):
make ueransim
cd nf/amf && E2E_TEST=1 make test-functional
# Without E2E_TEST=1: scenarios report as pending (exit 0 — expected).
```

### Multi-Slice Validation Suite (T0–T9)

```bash
make test-slices   # or: ./scripts/test-slices.sh
```

| Test | What It Validates |
|------|------------|
| T0 | `multi-slice` profile containers are running |
| T1 | NRF — SMF announces 4 SNSSAIs |
| T2 | NSSF — NSSelection returns correct slices |
| T3 | UDR — each SUPI has correct NSSAI profile |
| T4 | 4 UEs reach `MM-REGISTERED` (timeout 45 s) |
| T5 | AMF — correct `AllowedNSSAI`; no spurious rejections |
| T6 | PDU sessions established; SMF logs per IMSI |
| T7 | `uesimtun0` active + ping from each UE |
| T8 | Unauthorized UE for gold → `NSSAI_NOT_ALLOWED` |
| T9 | Prometheus metrics accessible on all containers |

### Feature Validation Quick Reference

| Feature | Command / Check |
|---------|-----------------|
| PCF SM policy create | `docker logs pcf \| grep SmPolicyCreate` on `ps-establish` |
| PCF SM policy delete | `docker logs pcf \| grep SmPolicyDelete` on `ps-release` |
| NW-initiated deregistration | `curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/<supi>` → `MM-DEREGISTERED` |
| NW-initiated PDU release | `curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/<supi>/pdu-sessions/1` |
| Xn Handover | `make handover-test` → `docker logs amf \| grep PathSwitchRequest` |
| N2 Handover | `make handover-n2-test` → `docker logs amf \| grep HandoverCommand` |
| NRF NFStatusSubscribe/Notify | `docker stop smf` → `docker logs amf \| grep "NF status notification"` |
| NRF DNN filter | `curl ".../nf-instances?...&dnn=internet"` returns SMF; `dnn=voip` returns empty |
| SUCI Profile A | `UE_CONFIG=config/ueransim/ue-profile-a.yaml make ueransim-only` → registration succeeds |
| URSP policy delivery | `make validate-ursp`; `docker logs amf \| grep "UE policy container sent"` |
| PDU session QoS | `docker logs smf \| grep qos_source` (PCF_OVERRIDE / UDM_SUBSCRIPTION / OPERATOR_DEFAULT) |
| NW-initiated QoS mod | `POST .../sessions/1/qos` → `docker logs amf \| grep "QoS Modification Command"` |
| NW-triggered PDU session | portal `/qos` → NW-Triggered panel, or `POST /api/v1/qos/nw-sessions` |
| DNN subnet isolation | `docker logs upf \| grep upfgtp0` (internet) / `upfgtp1` (ims) |
| NRF BDD (in-process) | `cd nf/nrf && make test-functional` — 3/3 passing |
| AMF BDD (E2E) | `make ueransim && cd nf/amf && E2E_TEST=1 make test-functional` |

---

## Observability

| Service | URL | Description |
|----------|-----|-------------|
| **Portal** | http://localhost:8080 | Centralized web management |
| **Grafana** | http://localhost:3000 | Dashboards (admin/admin) |
| **Jaeger** | http://localhost:16686 | Distributed tracing |
| **Prometheus** | http://localhost:9090 | Raw metrics |
| **Loki** | via Grafana | Structured JSON logs |

---

## Repository Structure

```
nf/<nfname>/            One folder per NF
shared/                 Shared libraries (NAS/NGAP/PFCP codecs, logging, crypto)
mcp/                    MCP server — exposes the core to LLM clients (stdio + HTTP/SSE)
tools/mgmt-portal/      Web management portal (React + Go, port 8080)
tools/ueransim/         UERANSIM build + 5GC patch set
docker/packetrusher/    PacketRusher image build
observability/          Loki, Prometheus, Grafana, Promtail configs
config/ueransim/        UERANSIM gNB and UE configurations
config/packetrusher/    PacketRusher handover scenario configs
scripts/                Utilities (PKI, test-slices, pcap-control)
docs/procedures/        3GPP procedure documentation (Mermaid + spec refs)
specs/3gpp-openapi/     OpenAPI YAMLs downloaded from forge.3gpp.org Rel-17
pki/                    Dev certificates (gitignored except public CA)
```

See `CLAUDE.md` for detailed conventions and `tools/mgmt-portal/CLAUDE.md` for portal details.

---

## Stack

- **Go 1.26.2** (control plane NFs) — `slog`, `net/http` + `golang.org/x/net/http2` for SBI
- **React 18 + Vite + Tailwind CSS** (portal frontend; Go + chi + gorilla/websocket backend)
- **Docker + Docker Compose** (orchestration; one container per NF + PCAP sidecars)
- **PostgreSQL 16 + Redis 7** (persistence and state caches)
- **Loki + Promtail + Grafana + Prometheus + Jaeger** (observability — 7 Grafana dashboards incl. 5G KPI overview)
- **OpenTelemetry + OTLP** (distributed tracing across all NFs → Jaeger)
- **UERANSIM v3.2.8** (RAN simulator, built from source + 5GC patch set — see [Third-Party Tools](#third-party-tools))
- **PacketRusher** (gNB/UE load tool for Xn/N2 handover scenarios)
- **MCP server** (`mcp/`) — Model Context Protocol server exposing the core to LLM clients (stdio + HTTP/SSE)
- **godog + testcontainers-go** (BDD and integration tests)

## Create a New NF

```bash
./scripts/new-nf.sh <nfname>   # copy _template and rename
cd nf/<nfname>
# Edit CLAUDE.md with NF-specific context
make build && make test
```

## Third-Party Tools

This project uses the following open-source tools, built from their upstream sources at
image-build time (no source is vendored into this repository). Their respective licenses apply.

| Tool | Used for | Repository | License |
|------|----------|------------|---------|
| **UERANSIM** | gNB + UE simulator for E2E registration, PDU sessions, network slicing, and SUCI scenarios. | [github.com/aligungr/UERANSIM](https://github.com/aligungr/UERANSIM) | GPL-3.0 |
| **PacketRusher** | gNB/UE tool driving the Xn and N2 handover scenarios. | [github.com/HewlettPackard/PacketRusher](https://github.com/HewlettPackard/PacketRusher) | Apache-2.0 |

---

## License

[Apache-2.0](LICENSE) — see the `LICENSE` file for the full text.

All original code in this repository is copyright © 2026 Francisco Curieses and released under Apache-2.0.

**Third-party protocol codecs (all Apache-2.0 or MIT compatible):**

| Library | Purpose | License |
|---------|---------|---------|
| [`github.com/free5gc/aper`](https://github.com/free5gc/aper) | APER encoder/decoder (NGAP) | Apache-2.0 |
| [`github.com/free5gc/ngap`](https://github.com/free5gc/ngap) | NGAP PDU type definitions | Apache-2.0 |
| [`github.com/wmnsk/go-pfcp`](https://github.com/wmnsk/go-pfcp) | PFCP session messages | MIT |
