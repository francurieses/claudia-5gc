<!-- tier: public -->
# Management portal

The operator UI for the running core: `make 5gcsa` (builds the portal, starts the core with
observability and the portal) → **http://localhost:8080**.

## Pages

| Group | Page | What it does |
|---|---|---|
| Overview | Dashboard | KPI cards (NFs online, subscribers, active sessions, 5-minute registration and PDU-session success rates), metric range charts (15 m, 1 h, 6 h, 24 h or custom), NF cards, recent sessions |
| Data & Config | Subscribers | create / edit / delete subscribers: per-slice DNNs, RFSP override; edits keep the network-managed SQN |
| | Network Slices | tabs *Slices* (add/remove S-NSSAI), *DNNs* (add/edit incl. IPv6 prefix), *Session-AMBR* (per slice/DNN, revert, apply to active sessions) |
| | Policies | URSP templates, per-subscriber policies, apply and push to a UE |
| Runtime | Services | start / stop / restart NF containers (restarts the PCAP sidecar too) |
| | Sessions | live PDU sessions and AMF UE contexts, force deregister |
| | QoS | live SMF QoS, modify a flow, subscription inspector, network-triggered additional PDU session |
| | gNBs (RAN) | gNBs connected over N2: ID, PLMN, TAs/slices, state, UE counts |
| | UE Location | LMF positions on a map plus table |
| Test tools | UERANSIM | scenarios, container grid, UEs table, ping, nr-cli, inline logs |
| | PacketRusher | Xn / N2 mobility scenarios, log viewer, checklist |
| Operations | Logs | live Docker logs per container |
| | PCAP | start / stop / rotate captures, list and download |
| Safety | Public Warning | cell-broadcast console: compose, per-gNB status, cancel, resend |

## Good to know

- **Deployment-aware.** The portal detects which RAN simulators are running. In a core-only
  deployment (`RAN=none`, the default) the UERANSIM and PacketRusher pages are hidden and their
  actions return `409 RAN_TOOL_NOT_DEPLOYED`. Force a mode with `PORTAL_RAN_TOOLS`
  (`auto` | `none` | `ueransim` | `packetrusher` | `both`).
- **Directory name.** The portal finds the simulators by Docker Compose project name; if you cloned into a differently named directory it may report core-only — set `PORTAL_RAN_TOOLS`.
- **Dark and light themes.** The header toggle persists; first visit follows the OS.
- **Metrics.** Charts use a curated Prometheus endpoint; an empty window shows a gap, never a fake 0 %.
- **Accessibility.** Built to WCAG 2.1 AA: keyboard operable, visible focus, status not conveyed by colour alone.
- **Multiple AMFs.** Set `AMF_MGMT_URLS` (comma list) to aggregate gNBs from several AMFs.
- **Database health.** `GET /api/v1/health` always answers 200 with `{"status":"ok","store":"up"|"down"}`; `store` is `down` when PostgreSQL was unreachable (the portal retries at start-up before degrading), and store-backed pages and MCP tools then report the store as unavailable.
- **Auth.** The portal is a lab tool: do not expose port 8080 to untrusted networks.

See [`configuration.md`](configuration.md) for portal environment variables and
[`observability.md`](observability.md) for the underlying metrics.
