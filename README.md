<!-- tier: public -->
# ClaudIA 5GC

[![CI](https://github.com/francurieses/claudia-5gc/actions/workflows/ci.yml/badge.svg)](https://github.com/francurieses/claudia-5gc/actions/workflows/ci.yml)
![Go 1.26.2](https://img.shields.io/badge/Go-1.26.2-00ADD8?logo=go&logoColor=white)
![3GPP Rel-17](https://img.shields.io/badge/3GPP-Rel--17-blue)
![Docker Compose](https://img.shields.io/badge/deploy-Docker%20Compose-2496ED?logo=docker&logoColor=white)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

**A from-scratch, spec-faithful 5G Core (Standalone, 3GPP Rel-17) in Go — 13 network functions in Docker, Wireshark-clean N1/N2/N4/N3, validated with UERANSIM, PacketRusher, and a commercial gNB with COTS 5G handsets.**

[Quickstart](#quickstart) · [Network Functions](#network-functions) · [Features](#features) · [Docs](#documentation)

## Why ClaudIA 5GC

ClaudIA 5GC is an open-source 5G Core built to be developed and operated with AI, not just run next to it. An integrated MCP server lets LLM clients inspect, test and control the core in natural language, covering NF status, NAS decoding, traces and QoS policy. The same AI-assisted workflow shortens the path from idea to validated feature. New procedures and NFs take a fraction of the time of traditional telecom development, so innovation and validation move faster. The cloud-native, containerized SBA scales horizontally, one NF per container. A web portal handles day-to-day operation, and logs, metrics, traces and dashboards come wired in by default. The result is a Release 17 core you can bring up in minutes and debug, extend and automate, with people and AI agents working on the same system.

## Architecture

```mermaid
flowchart LR
  subgraph RAN["RAN / UE"]
    UE["UE<br/>UERANSIM · PacketRusher · COTS"] -- "NR" --- GNB["gNB"]
  end
  UE -. "N1 · NAS (over N2)" .- AMF
  GNB -- "N2 · NGAP/SCTP" --> AMF
  GNB -- "N3 · GTP-U" --> UPF

  subgraph SBA["Service-Based Architecture · HTTP/2 + mTLS"]
    NRF["NRF<br/>Nnrf · every NF registers + discovers"]
    AMF -- "N12 · Nausf" --> AUSF -- "N13 · Nudm" --> UDM -- "N35 · Nudr" --> UDR
    AMF -- "N8 · Nudm" --> UDM
    AMF -- "N22 · Nnssf" --> NSSF
    AMF <-- "N11 · Nsmf / Namf" --> SMF
    SMF -- "N10 · Nudm" --> UDM
    SMF -- "N7 · Npcf" --> PCF
    AMF -- "N15 · Npcf" --> PCF
    PCF -- "N36 · Nudr" --> UDR
    PCF -- "Nbsf" --> BSF
    NEF -- "Nbsf" --> BSF
    NEF -- "N30 · Npcf" --> PCF
    AMF <-- "NL1 · Nlmf / Namf" --> LMF
    LMF -- "Nudm" --> UDM
    AMF <-- "N20 · Nsmsf / Namf" --> SMSF
    SMSF -- "N21 · Nudm" --> UDM
  end

  AF["AF (external)"] -- "N33 · Nnef" --> NEF
  SMF -- "N4 · PFCP/UDP" --> UPF
  UPF -- "N6" --> DN[("DNNs<br/>internet · ims")]

  PG[("PostgreSQL")] -.- UDR & AMF & SMF
  REDIS[("Redis")] -.- AMF & NRF

  subgraph MGMT["Management plane (non-3GPP)"]
    OBS["Loki · Prometheus · Grafana · Jaeger"]
    PORTAL["Management portal"]
    MCP["MCP server"]
  end
  MGMT -. "metrics · logs · traces · NF APIs" .-> SBA
```

Every NF registers with and discovers its peers through the NRF (Nnrf edges omitted). PostgreSQL and Redis are per-NF state stores, not SBI peers; there is no UDSF. The portal and MCP server are management-plane clients that call NF APIs directly rather than through the NEF. Full diagrams and per-NF detail: [`docs/architecture.md`](docs/architecture.md).

## Quickstart

Prerequisites: Docker ≥ 24 usable without `sudo`, Docker Compose v2, GNU Make (Node 18+ only for the portal). Details and troubleshooting: [`docs/getting-started.md`](docs/getting-started.md#prerequisites).

The core deploys **standalone** by default: the 13 NFs plus PostgreSQL and Redis, with no RAN simulator built or started. Point any gNB at the AMF (`N2`, `38412/sctp`) and it shows up on the portal's **gNBs (RAN)** page.

```bash
git clone https://github.com/francurieses/claudia-5gc && cd claudia-5gc
make pki        # dev CA + one certificate per NF (first time only)
make 5gcsa     # standalone core + observability + management portal
curl -s localhost:9002/amf/v1/ran/gnbs | jq '.gnbs'   # gNBs attached to the AMF (empty until one connects)
make down       # stop and remove volumes
```

Add `MCP=on` to also deploy the MCP server container (SSE on `:9300`, e.g. `make 5gcsa MCP=on`); it combines with `RAN=`, for example `make 5gcsa RAN=both MCP=on`.

`make up` starts the core only; `make up-obs` adds observability.

### Add a RAN simulator (optional)

Pick the deployment mode with `RAN=` on `make up`, `make up-obs` or `make 5gcsa`:

| Mode | Command | Starts |
|------|---------|--------|
| Standalone (default) | `make 5gcsa` | Core only |
| + UERANSIM | `make 5gcsa RAN=ueransim` | Core + UERANSIM gNB + `UE_COUNT` UEs |
| + PacketRusher | `make 5gcsa RAN=packetrusher` | Core + PacketRusher (`PR_SCENARIO=xn\|n2\|none`, default `xn`) |
| + both | `make 5gcsa RAN=both` | Core + UERANSIM + PacketRusher |
| + MCP server | `make 5gcsa MCP=on` (any mode) | Adds the MCP server container, SSE at http://localhost:9300 |

```bash
make ueransim                                               # shortcut for: make up-obs RAN=ueransim
docker exec ueransim-ue nr-cli --dump                       # the UE reaches MM-REGISTERED
docker exec ueransim-ue ping -I uesimtun0 -c3 8.8.8.8       # user-plane through the UPF
make handover-test                                          # PacketRusher Xn handover (handover-n2-test for N2)
```

The portal detects the mode at runtime: in standalone mode the UERANSIM and PacketRusher pages are hidden, and the **gNBs (RAN)** page (gNB, IP address, status, slices, UEs) is available in every mode. Want everything (portal + 4 slices with one UE each)? `make full`.

| Service | URL |
|---------|-----|
| Management portal | http://localhost:8080 |
| Grafana (admin/admin, dev only) | http://localhost:3000 |
| Jaeger | http://localhost:16686 |
| Prometheus | http://localhost:9090 |
| MCP server (with `MCP=on`) | http://localhost:9300 (`/mcp/health`) |

## Screenshots

<!-- TODO(maintainer): add docs/assets/*.png — portal dashboard, UE Location map, Grafana 5G KPI dashboard, Wireshark NGAP/NAS decode. -->
Screenshots are coming soon. Run `make full` to see the portal, Grafana and Jaeger yourself.

## Network Functions

✅ operational · 🟡 implemented with documented scope limits (see [implementation status](docs/implementation-status.md)).

| NF | | Services / interfaces | Highlights |
|----|---|-----------------------|------------|
| [NRF](nf/nrf/) | ✅ | `Nnrf_NFManagement`, `Nnrf_NFDiscovery`, OAuth2 | Heartbeat eviction, Subscribe/Notify, DNN/S-NSSAI filters, Redis registry |
| [AMF](nf/amf/) | ✅ | N1, N2, `Namf_*` | Registration, Service Request, Xn/N2 handover, paging, NSSAA, PWS, UE context transfer |
| [SMF](nf/smf/) | ✅ | N4, `Nsmf_*` | PDU sessions IPv4/IPv6/IPv4v6, QoS modification, secondary auth, per-DNN pools |
| [UPF](nf/upf/) | ✅ | N3, N4, N6, N9-ready | GTP-U, QER/URR, per-DNN TUN, IPv6 egress |
| [AUSF](nf/ausf/) | 🟡 | `Nausf_UEAuthentication` | 5G-AKA, EAP-AKA′, NSSAA relay |
| [UDM](nf/udm/) | 🟡 | `Nudm_UEAU/UECM/SDM` | SUCI null + Profile A, SDM Subscribe/Notify, LCS privacy |
| [UDR](nf/udr/) | ✅ | `Nudr_DataRepository` | PostgreSQL, subscriber + policy data |
| [PCF](nf/pcf/) | ✅ | N7, N15, `Npcf_*` | SM policy lifecycle, AM policy, URSP, DNN-scoped QoS overrides |
| [NSSF](nf/nssf/) | ✅ | `Nnssf_NSSelection` | Allowed-NSSAI selection |
| [SMSF](nf/smsf/) | 🟡 | `Nsmsf_SMService` | SMS over NAS |
| [BSF](nf/bsf/) | ✅ | `Nbsf_Management` | PCF binding registry |
| [NEF](nf/nef/) | 🟡 | `Nnef_AFsessionWithQoS` | AF-requested QoS via BSF + PCF |
| [LMF](nf/lmf/) | 🟡 | `Nlmf_Location` | Cell-ID, E-CID (NRPPa), A-GNSS (LPP), event subscriptions |
| [MCP](mcp/) | ✅ | stdio + HTTP/SSE `:9300` | LLM-facing tool server (not a 3GPP NF) |

## Features

Feature descriptions with how to try each one: [`docs/features.md`](docs/features.md). Clause-level conformance and per-procedure designs (sequence diagrams, IEs, error cases) are part of the [members documentation](https://www.claudia5gc.dev/docs/members/).

### Registration & security

| Feature | Spec |
|---------|------|
| Initial, mobility and periodic registration; UE- and NW-initiated deregistration | TS 23.502 §4.2.2 |
| 5G-AKA, SUCI null-scheme and Profile A (X25519) | TS 33.501 §6.1, §6.12 |
| NAS security NIA1/NIA2 + NEA0/NEA1/NEA2 | TS 33.501 §6.7 |

<details><summary>More registration & security</summary>

| Feature | Spec |
|---------|------|
| EAP-AKA′ | RFC 5448, TS 33.501 §6.1.3.1 |
| Network Slice-Specific Authentication (NSSAA) | TS 23.502 §4.2.9 |
| Service Area Restriction | TS 23.501 §5.3.4 |
| UE configuration update | TS 23.502 §4.2.4 |

</details>

### Session management

| Feature | Spec |
|---------|------|
| PDU session establishment, modification, release — IPv4, IPv6, IPv4v6 | TS 23.502 §4.3.2–4.3.4 |
| 5QI selection (PCF > UDM > default), QER, NW-initiated QoS modification | TS 23.501 §5.7, TS 23.502 §4.3.3.2 |
| Per-DNN subnet isolation (internet / ims) | TS 23.501 §5.6.5 |

<details><summary>More session management</summary>

| Feature | Spec |
|---------|------|
| Secondary authentication / DN-AAA | TS 23.502 §4.3.2.3 |
| PFCP usage reporting (URR) | TS 29.244 §5.2.2.4 |
| NW-triggered additional PDU session (via URSP) | TS 23.503 §6.6.2 |

</details>

### Mobility & connection management

| Feature | Spec |
|---------|------|
| AN release → CM-IDLE, Service Request with UP re-activation | TS 23.502 §4.2.3 |
| CN paging / network-triggered Service Request | TS 23.502 §4.2.3.3 |
| Xn handover (PathSwitch) and N2 handover | TS 23.502 §4.9.1.2, §4.9.1.3 |

<details><summary>More mobility</summary>

| Feature | Spec |
|---------|------|
| UE context transfer (`Namf_Communication`) | TS 29.518 §5.3.2 |
| Lifecycle timers T3512, mobile-reachable, implicit detach | TS 23.502 §4.2.2.2.4 |

</details>

### Policy, location, messaging and exposure

<details><summary>Policy</summary>

| Feature | Spec |
|---------|------|
| SM policy create / update / delete | TS 29.512 §5.2.2 |
| AM policy association | TS 29.507 |
| URSP delivery in a UE policy container (MANAGE UE POLICY COMMAND) | TS 24.501 Annex D, TS 29.525 |

</details>

<details><summary>Location</summary>

| Feature | Spec |
|---------|------|
| Cell-ID positioning, deferred MT location with paging | TS 23.273 §6, §7.2 |
| Enhanced Cell-ID via NRPPa relay (APER) | TS 38.455 |
| A-GNSS via LPP relay over N1 | TS 37.355 |
| Event subscription, cancel, location privacy | TS 29.572 §5.2.3 |

</details>

<details><summary>Messaging & exposure</summary>

| Feature | Spec |
|---------|------|
| SMS over NAS (SMSF) | TS 23.502 §4.13.3, TS 23.501 §5.20 |
| Public Warning System (Write-Replace Warning / Cancel) | TS 23.041, TS 38.413 §8.9 |
| PCF binding (BSF) and AF session with QoS (NEF) | TS 29.521, TS 29.522 §4.4.13 |

</details>

<details><summary>Service-based architecture</summary>

| Feature | Spec |
|---------|------|
| NF register, discover, subscribe, heartbeat | TS 29.510 §5 |
| OAuth2 + mTLS over HTTP/2 | TS 29.500 §4.4, TS 33.501 §13 |

</details>

## Management portal

`make 5gcsa` (or `make full`) serves the portal at http://localhost:8080 — light/dark themes, 14 pages in 6 groups: dashboard with 3GPP KPI charts (TS 28.554), subscribers, slices, services, gNBs (RAN), sessions, QoS, policies, UE location, logs, PCAP and Public Warning, plus UERANSIM and PacketRusher when those simulators are deployed. Details: [`tools/mgmt-portal/`](tools/mgmt-portal/).

## AI-native development

The MCP server in [`mcp/`](mcp/) speaks stdio and HTTP/SSE (`:9300`) and offers tools for NAS encode/decode, NF discovery, UE and session inspection, traces and KPIs, QoS control and UERANSIM control.

## Repository layout

```
nf/<name>/           One folder per NF (Dockerfile, cmd/, internal/, config/, tests/)
nf/_template/        Template for new NFs (scripts/new-nf.sh)
shared/              nas · ngap · nrppa · lpp · pfcp · gsm7 · crypto · aka · oauth2 · sbi · nrf · logging · observability · types
mcp/                 MCP server
tools/mgmt-portal/   Management portal (Go + React)
tools/ueransim/      UERANSIM build + patch set
observability/       Loki, Prometheus, Grafana, Promtail
config/              Operator, UERANSIM and PacketRusher configs
docs/                Getting started, architecture, features, configuration, status
specs/3gpp-openapi/  3GPP Rel-17 OpenAPI YAMLs
scripts/             PKI, test suites, PCAP control
```

## Documentation

| Doc | What it is for |
|-----|----------------|
| [`docs/getting-started.md`](docs/getting-started.md) | Prerequisites, Make reference, scenarios, UERANSIM usage |
| [`docs/architecture.md`](docs/architecture.md) | Architecture, deployment modes, networks, ports |
| [`docs/configuration.md`](docs/configuration.md) | Operator config, environment variables, PKI |
| [`docs/features.md`](docs/features.md) | What the core does and how to try each feature |
| [`docs/implementation-status.md`](docs/implementation-status.md) | What is implemented per NF, portal pages |
| [`docs/portal.md`](docs/portal.md) · [`docs/mcp-tools.md`](docs/mcp-tools.md) · [`docs/observability.md`](docs/observability.md) | Management portal, MCP server, metrics / traces / logs |
| [`docs/ran-integration-guide.md`](docs/ran-integration-guide.md) | Connecting a real gNB and UEs |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) · [`docs/performance/summary.md`](docs/performance/summary.md) | Common problems; headline throughput |
| [Members documentation](https://www.claudia5gc.dev/docs/members/) | Procedure designs, clause-level conformance, validation recipes, PCAP diagnostics (login required) |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md) | Contribution rules, security policy |

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Commits look like `feat(amf): implement X [TS 23.502 §4.2.2.2.2]`. Each new procedure follows the same flow: procedure doc → Cucumber feature → implementation → step definitions → integration test → PCAP validation → conformance update.

## License

[Apache-2.0](LICENSE). Original code © 2026 Francisco Curieses. No Open5GS (AGPL) code is used.

| Third-party | Use | License |
|-------------|-----|---------|
| [UERANSIM](https://github.com/aligungr/UERANSIM) | RAN simulator, built at image time, not vendored | GPL-3.0 |
| [PacketRusher](https://github.com/HewlettPackard/PacketRusher) | Xn / N2 handover scenarios, built at image time | Apache-2.0 |
| [free5gc/aper](https://github.com/free5gc/aper), [free5gc/ngap](https://github.com/free5gc/ngap) | APER codec and NGAP types (codec reference) | Apache-2.0 |
| [wmnsk/go-pfcp](https://github.com/wmnsk/go-pfcp) | PFCP messages | MIT |
| [ishidawataru/sctp](https://github.com/ishidawataru/sctp) | SCTP sockets for N2 | Apache-2.0 |
