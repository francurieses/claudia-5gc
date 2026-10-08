<!-- tier: public -->
# Configuration

Where to change what. Ports, networks and the NF list are in [`architecture.md`](architecture.md);
first-run steps are in [`getting-started.md`](getting-started.md).

## Operator config — slices, DNNs, PLMN

`config/operator.yaml` is the **single source of truth** for the PLMN, network slices, DNNs and
the optional per-slice/DNN Session-AMBR seed (`slice_dnn_qos`). Per-NF files
(`nf/<nf>/config/dev.yaml`) refine it (SMF address pools, UPF TUN devices).

Add a DNN or slice:
1. Edit `config/operator.yaml` (or use Portal → Network Slices, which writes the operator file plus SMF and UPF config).
2. Check the SMF pool and UPF TUN entries in the per-NF `dev.yaml`.
3. For a new DNN, add its N6 network in `docker-compose.yml`.
4. Restart SMF and UPF (they read config at start-up); `make down && make up` reseeds the subscriber database.

A slice is only usable when the UE also lists it in its `configured-nssai` and the AMF, NSSF and gNB
configs carry it. The slice's DNN must equal the `apn` the UE requests, otherwise the SMF falls
back to the operator-default QoS. Details on slices: [`getting-started.md`](getting-started.md) → *Network slicing*.

## Environment variables

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
| `PCF_ADDR` | URL | MCP | PCF internal-API endpoint (QoS override tools) |
| `PORTAL_ADDR` | URL | MCP | Management-portal endpoint (UERANSIM control tools) |
| `CONFIG_PATH` | path | NRF, AUSF | Explicit YAML config file (default: image `config/`) |
| `HEALTHCHECK_ADDR` | host:port | NRF, MCP | Container health-probe listen address |
| `MCP_SSE_LISTEN_ADDR` | host:port | MCP | SSE transport listen address (default `:9300`) |
| `MCP_BEARER_TOKEN` | string | MCP | Bearer token required on the SSE transport (unset = no auth, lab only) |
| `LMF_URL` | URL | portal | LMF endpoint for the UE Location page (Nlmf_Location; default `https://lmf:8012`) |
| `DATABASE_URL` | DSN | AMF, SMF, UDR | PostgreSQL connection |
| `REDIS_URL` | URL | NRF, AMF, AUSF | Redis connection |
| `OPERATOR_CONFIG_PATH` / `NF_CONFIGS_PATH` | path | NFs, portal | Path to `config/operator.yaml` / per-NF configs |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `JAEGER_ADDR` | URL | all NFs | OTLP→Jaeger exporter |
| `PROMETHEUS_ADDR` / `PROMETHEUS_URL` | URL | MCP, portal | Prometheus query endpoint |
| `URSP_ENABLED` | bool | PCF/AMF | Toggle URSP delivery |
| `UE_COUNT` | int (default 1) | UERANSIM / UDR seeding | Number of UEs to simulate/seed |
| `RAN` | enum `none`\|`ueransim`\|`packetrusher`\|`both` (default `none`) | root Makefile | Which RAN simulators start next to the core |
| `PR_SCENARIO` | enum `xn`\|`n2`\|`none` (default `xn`) | root Makefile | PacketRusher scenario started by `RAN=packetrusher\|both` (`none` = create only) |
| `MCP` | `on`\|`off` (default `off`) | root Makefile | Deploy the MCP server container (profile `tools`, SSE `:9300`) with `make up\|up-obs\|5gcsa` |
| `SEED_EXTRA_SUPIS` | comma list of `imsi-<15 digits>` (default `imsi-001010000000101,imsi-001010000000201,…202,…203,…204,imsi-001010000000301,imsi-001010000000401`) | UDR | Extra dev subscribers seeded outside the `UE_COUNT` range: 101 PacketRusher, 201–204 multi-slice UEs, 301 SUCI Profile A UE, 401 `ue-unauth` (test-slices T8). Each gets the cyclic multi-slice profile by MSIN (`(msin-1) % number_of_profiles`); invalid entries are skipped with a warning. UDR skips SUPIs already provisioned in Postgres |
| `PORTAL_RAN_TOOLS` | enum `auto`\|`none`\|`ueransim`\|`packetrusher`\|`both` (default `auto`) | mgmt-portal | Force the detected RAN-tool deployment mode; `auto` probes Docker |
| `AMF_MGMT_URLS` | comma list of URLs (default = `AMF_URL`) | mgmt-portal | AMF management endpoints aggregated by the gNBs page (`GET /api/v1/ran/gnbs`) |
| `HN_PRIVATE_KEY_X25519` | hex | UDM | Home network private key for SUCI Profile A |
| `MCP_TRANSPORT` | enum (stdio/sse/both) | MCP | Transport selection |
| `PORTAL_CERT_FILE` / `PORTAL_KEY_FILE` | path | mgmt-portal | TLS cert/key |
| `POSTGRES_USER/PASSWORD/DB` | string | postgres | DB bootstrap |
| `GF_SECURITY_ADMIN_USER/PASSWORD`, `GF_USERS_ALLOW_SIGN_UP` | string/bool | grafana | Grafana admin |
| `COLLECTOR_OTLP_ENABLED` | bool | jaeger | Enable OTLP collector |

Per-NF YAML config lives in `nf/<nf>/config/dev.yaml`.

## Notable YAML keys

| Key | File | Description |
|---|---|---|
| `served_tacs` (list of ints, default `[1]`) | `nf/amf/config/dev.yaml` | Registration area advertised as the TAI list (IEI 0x54) in every Registration Accept. Must cover every TAC the connected gNBs broadcast; the UE's current TAC is always appended if missing. Ref: TS 24.501 §9.11.3.9 |
| `n4.report_listen` (default `0.0.0.0:8805`) | `nf/smf/config/dev.yaml` | Bind address of the SMF persistent PFCP receiver that consumes UPF Session Report Requests (URR usage reports). Intra-Docker-network UDP — no published port needed. Ref: TS 29.244 §6.2.1 |
| `n4.volume_threshold_bytes` (default `1000000`) | `nf/smf/config/dev.yaml` | Volume Threshold installed in the URR — UPF emits a VOLTH Usage Report once cumulative session volume crosses this many bytes (re-arms after each report). Ref: TS 29.244 §8.2.13 |
| `n4.heartbeat_interval_seconds` (default `2`) | `nf/smf/config/dev.yaml` | PFCP Heartbeat period towards the UPF. Zero = default |
| `n4.t1_seconds` (default `3`), `n4.n1_retransmissions` (default `3`) | `nf/smf/config/dev.yaml` | PFCP T1 response timeout and N1 retransmission count for Association Setup / Heartbeat (TS 29.244 §6.4); N1 loss = peer failure |
| `n4.association_retry_initial_seconds` (default `1`), `n4.association_retry_max_seconds` (default `5`) | `nf/smf/config/dev.yaml` | Association Setup retry back-off bounds. The 30 s release guard is a constant, not configurable |
| `PFCP_TIMEOUT` (default `20`), `PFCP_SETTLE` (default `3`) | env of `scripts/services-restart-check.sh` | After an smf/upf restart: max wait for the UPF log `PFCP AssociationSetup accepted`, then settle time before the E2E check |
| `n4.measurement_period_seconds` (default `60`) | `nf/smf/config/dev.yaml` | Measurement Period installed in the URR — UPF emits a PERIO Usage Report every N seconds. Ref: TS 29.244 §8.2.42 |
| `UPF_PPROF_ADDR` (default empty = off, e.g. `0.0.0.0:6060`) | env of `upf` | Optional pprof HTTP listener (`/debug/pprof/`), not published to the host: fetch from inside the UPF netns. `LOG_LEVEL` is also honoured by the UPF. |
| `GOGC` (optional, read by the Go runtime) | env of `upf` | Go GC target; only reported in the `UPF runtime` startup log |
| `n3.socket_buffer_bytes` (code default `0` = kernel default; `dev.yaml` `8388608`) | `nf/upf/config/dev.yaml` | SO_RCVBUF/SO_SNDBUF of the GTP-U UDP socket; absorbs bursts (drops show as Udp RcvbufErrors). |
| `n6.tun_mtu` (code default `0` = kernel default 1500; `dev.yaml` `1456`), `n6.tun_txqueuelen` (`0` = kernel default; `dev.yaml` `1000`), `n6.tcp_mss_clamp` (code default `false`; `dev.yaml` `true`) | `nf/upf/config/dev.yaml` | N6 TUN MTU (1500 - 44 B N3 overhead so DL never fragments), TUN tx queue length, TCP MSS clamp on the TUN. |
| `slice_dnn_qos` (list of `{sst, sd, dnn, session_ambr{uplink,downlink}}`, optional, top-level) | `config/operator.yaml` | Seed of the UDR table `slice_dnn_qos` (per-slice/DNN subscribed Session-AMBR, BitRate strings e.g. `100 Mbps`); absent entries fall back to `DefaultAMBRForSlice`; never overwrites portal-edited rows |
| `n6.l4_checksum_repair` (default `true`, also when absent) | `nf/upf/config/dev.yaml` | Verify/repair TCP/UDP checksums of N6 downlink packets before GTP-U encapsulation; `false` forwards unmodified. Needed on Docker Desktop for Mac; may be disabled on native Linux. Ref: RFC 1071, TS 29.281 §5 |
| `qos.mbr_enforcement` (default `true`), `qos.burst_ms` (default `100`, clamped 1..1000, floor 4500 bytes) | `nf/upf/config/dev.yaml` | Police traffic above the QER MBR / Session-AMBR; `false` = line-rate forwarding (Gate CLOSED still enforced). `burst_ms` = token-bucket depth in ms of traffic at the MBR. Both are logged in the `UPF runtime` startup log. Ref: TS 23.501 §5.7.1.8, TS 29.244 §5.4.4 |
| `dnns[].ue_ipv6_prefix` (e.g. `2001:db8:61::/56`) | `nf/upf/config/dev.yaml` | Per-DNN IPv6 base prefix anchor, mirroring the SMF's pool of the same key — used as a config-drift guard/log for the Router Advertisement advertiser; the `/64` actually advertised always comes from the PFCP UE IP Address IE. Ref: TS 23.501 §5.8.2.2 |
| `dnns[].secondary_auth` (bool, default `false`) | `nf/smf/config/dev.yaml` | When true, the SMF triggers DN-AAA secondary authentication (EAP round-trip) during PDU Session Establishment for that DNN; false (all shipped DNNs) = normal establishment, no EAP. Ref: TS 23.501 §5.6.6, TS 23.502 §4.3.2.3 |
| `dnns[].dn_aaa_unreachable` (bool, default `false`) | `nf/smf/config/dev.yaml` | Dev/test knob: simulates the DN-AAA being unreachable so establishment is rejected with 5GSM cause #29. For local testing of the failure path only. Ref: TS 24.501 §9.11.4.2 |
| `dnns[].ue_ipv6_prefix` (e.g. `2001:db8:60::/56`) | `nf/smf/config/dev.yaml`, `config/operator.yaml` | Base IPv6 prefix (CIDR, length `/8`-`/64`, multiple of 8) the SMF's `IPv6Pool` delegates per-session `/64`s from for IPv6/IPv4v6 PDU sessions. Empty/absent = the DNN is IPv4-only and v6 requests are downgraded. All four seeded DNNs (`internet`=`2001:db8:60::/56`, `ims`=`2001:db8:61::/56`, `gaming`=`2001:db8:62::/56`, `gold`=`2001:db8:63::/56`) now have one configured. Manageable from the portal `/slices` DNN edit form (`PUT /api/v1/dnns/{name}`) — writes `operator.yaml`+SMF+UPF in one call; SMF/UPF only read config at startup, so check "Restart SMF and UPF" to apply. Ref: TS 23.501 §5.8.2.2 |

## Build and security switches

- **URSP delivery** is a build-time switch — see [`getting-started.md`](getting-started.md) → *Compile with / without URSP policy delivery*.
- **AMF `null_ciphering`** (NEA0) is a development switch for simulators that require it — see
  [`getting-started.md`](getting-started.md) → *Security debug flags (AMF)*. Never enable it outside a lab.

## TLS / PKI

All SBI traffic uses mutual TLS over HTTP/2. Certificates are in `pki/`, mounted into each
container as `/etc/5gc/pki/<nf>.crt|.key`; the CA is `pki/ca.crt`. `make pki` regenerates the
development PKI. OAuth2 access tokens are issued by the NRF.

## Compose profiles

`core`, `obs`, `tools`, `multi-slice`, `suci-profile-a`, `integration-ueransim`, `handover`,
`perf` (opt-in benchmarking; always combine with `core`). Most users just run the `make` targets
listed in [`getting-started.md`](getting-started.md).
