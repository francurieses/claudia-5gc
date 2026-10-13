<!-- tier: public -->
# Implementation Status — 5GC Rel-17

What is implemented in ClaudIA 5GC, how complete each network function is, and which 3GPP
specifications it follows. For code conventions and workflow, see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

Legend: ✅ complete for the supported scope · 🟡 working, with documented gaps.

---

## Operational NFs

| NF | Status | Notes | 3GPP specs |
|---|---|---|---|
| NRF | ✅ | Register / Discover / Deregister, heartbeat eviction, OAuth2 access tokens, mTLS, Redis-backed state | TS 29.510 |
| AMF | ✅ | Registration and mobility (incl. periodic update), PDU session establishment/release/modification relay, NAS security (NIA2/NEA2), slice (NSSAI) validation via NSSF, slice-specific authentication (NSSAA), CN paging and service request, O&M-triggered AN release, runtime timer config (T3512 / mobile reachable / implicit detach), Xn and N2 handover, UE context transfer, Public Warning System broadcast, PostgreSQL UE contexts | TS 23.501, TS 23.502, TS 24.501, TS 38.413, TS 29.518, TS 33.501 |
| AUSF | 🟡 | 5G-AKA, EAP-AKA′, NSSAA EAP relay (simulated AAA server), SUCI null-scheme and Profile A | TS 33.501, TS 29.509, RFC 5448 |
| UDM | 🟡 | Authentication data, access & mobility data, UE context management, subscription data notifications, SUCI deconcealment | TS 29.503, TS 33.501 |
| UDR | ✅ | PostgreSQL-backed subscriber and policy data (UE policy / URSP, SM policy), per slice/DNN Session-AMBR, auto-migrated, seeded subscribers | TS 29.504, TS 29.519 |
| SMF | ✅ | PDU session establishment and modification, IPv4 and IPv6/IPv4v6 addressing, QoS authorisation via PCF, usage reporting, Session-AMBR provisioning, PFCP node recovery, secondary authentication (DN-AAA, simulated) | TS 23.501, TS 23.502, TS 29.502, TS 29.244, TS 24.501 |
| PCF | ✅ | SM policy control and update (5QI, Session-AMBR), UE policy delivery (URSP), AM policy association, per-subscriber overrides | TS 29.512, TS 29.525, TS 24.526, TS 29.507 |
| UPF | ✅ | GTP-U forwarding, PFCP sessions, usage reporting, IPv6 router advertisements, downlink checksum repair, Session-AMBR / QER MBR enforcement, high-rate datapath | TS 29.244, TS 29.281, TS 23.501 |
| NSSF | ✅ | Network slice selection (static NSSAI intersection), NRF registration | TS 29.531 |
| SMSF | 🟡 | SMS over NAS (activate / deactivate / uplink SMS) with a loopback echo; no live UE leg (UERANSIM has no SMS over NAS) | TS 29.540, TS 23.502 |
| BSF | ✅ | Binding registration, deregistration and discovery; PCF binds sessions automatically | TS 29.521 |
| NEF | 🟡 | AF session with required QoS (create / get / delete) with OAuth2, mapped onto PCF policy authorization | TS 29.522, TS 29.514 |
| LMF | 🟡 | UE location: Cell-ID, E-CID (NRPPa) and GNSS (LPP) with automatic fallback; periodic and area-of-interest event subscriptions. MT location paging and GMLC interface not yet implemented | TS 29.572, TS 38.455, TS 37.355, TS 23.273 |
| MCP | ✅ | AI-tooling server (stdio + SSE, port 9300): NAS codec, NF discovery, UE inspection, QoS, crypto, metrics, status and analysis tools, network-control tools, runtime-config and subscriber tools (74 tools) | — |

Per-procedure conformance, sequence diagrams and validation recipes are part of the
members documentation. See the [documentation overview](https://www.claudia5gc.dev/docs/members/).

## Web Management Portal

`http://localhost:8080` after `make 5gcsa`. Token-based light/dark theme, grouped navigation
and live data from the running core.

| Page | What it does |
|--------|--------|
| Dashboard | KPI cards (registered UEs, active sessions, 5-minute registration and PDU-session success rates), metric range charts (15 m to 24 h or custom), NF health cards, recent PDU sessions |
| Subscribers | Create, edit and delete subscribers (per-slice DNNs, RFSP override) |
| Network Slices | Add/remove S-NSSAIs, DNN lifecycle incl. IPv6 prefix, per slice/DNN Session-AMBR |
| Services | Start, stop and restart NF containers |
| Sessions | Live PDU sessions and AMF UE contexts |
| QoS | Live SMF QoS, modify a flow, subscription inspector, network-triggered additional PDU session (URSP) |
| Policies | URSP templates and per-subscriber policies; apply and push to the UE |
| UERANSIM | Run scenarios, container grid, UEs table, ping, nr-cli, inline logs |
| PacketRusher | Xn / N2 mobility scenarios with log viewer and checklist |
| Logs | Streaming Docker logs |
| PCAP | Start / stop / rotate packet captures, list and download files |
| Public Warning | Cell-broadcast console: compose, per-gNB status, cancel, resend |
| UE Location | LMF positions on a map, with a table |

---

## UERANSIM Integration

- UERANSIM v3.2.8 built from source (GitHub tarball) via `tools/ueransim/Dockerfile`.
- `make ueransim [UE_COUNT=N]` — brings up core + observability + gNB + N UEs.
- Config: `config/ueransim/gnb.yaml`, `config/ueransim/ue.yaml`.
- SUCI: `protectionScheme: 0` (null-scheme). MSIN `0000000001` in BCD low-nibble-first → bytes `[00 00 00 00 10]`.
- Multi-UE: `nr-ue -c ue.yaml -n N` increments IMSI from `imsi-001010000000001`. Changing `UE_COUNT` requires `make ueransim` (not `ueransim-only`) to reseed UDR.

### Multi-Slice (TS 23.501 §5.15)

Four development slices:

| Slice | SST | SD | Type | Assigned UE |
|---|---|---|---|---|
| internet | 1 | 000001 | eMBB default | `imsi-…201` — internet only |
| gold | 1 | 000002 | eMBB premium | `imsi-…202` — internet + gold |
| silver | 2 | 000001 | URLLC | `imsi-…203` — internet + silver |
| bronze | 3 | 000001 | MIoT | `imsi-…204` — internet + bronze |

Multi-slice gNB (`gnb-ms.yaml`): NCI `0x000000100` (gNB-ID `0x10`), GTP IP `172.30.3.4`, own compose aliases — it coexists with `gnb.yaml` (NCI `0x000000010`). SUPIs 201–204 are seeded via UDR `SEED_EXTRA_SUPIS` (cyclic slice profile by MSIN); other dev SUPIs: Profile A 301, `ue-unauth` 401, PacketRusher 101.

```bash
make ueransim-slices       # bring up core + obs + 4 UEs
make test-slices           # suite T0–T9
make ueransim-slices-down
make ueransim-all          # every UERANSIM scenario together; ueransim-status / ueransim-all-down / ueransim-iperf
```

### Test Suite T0–T9 (`scripts/test-slices.sh`)

| Test | What It Validates |
|---|---|
| T0 | All 10 containers in `multi-slice` profile are running |
| T1 | NRF — SMF announces 4 SNSSAIs |
| T2 | NSSF — NSSelection returns correct slices; unknown slice → empty |
| T3 | UDR — each SUPI has correct NSSAI profile in `am-data` |
| T4 | 4 UEs reach `MM-REGISTERED` (timeout 45 s) |
| T5 | AMF — correct `AllowedNSSAI` per UE; no spurious `NSSAI_NOT_ALLOWED` |
| T6 | PDU sessions established; SMF has logs per IMSI |
| T7 | `uesimtun0` active + ping `172.30.3.100` from each UE |
| T8 | Rejection test: `ue-unauth.yaml` (IMSI-1 requests gold) → `NSSAI_NOT_ALLOWED` |
| T9 | Prometheus metrics accessible on all containers |
