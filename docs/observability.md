<!-- tier: public -->
# Observability

Metrics, traces, logs and packet captures are available from day one. Start the stack with
`make up-obs` (core + observability) or `make ueransim` (adds a gNB and UEs).

| Tool | URL | What you get |
|---|---|---|
| Grafana | `http://localhost:3000` (admin/admin, set via env) | dashboards below |
| Prometheus | `http://localhost:9090` | `fivegc_*` metrics, alerts |
| Jaeger | `http://localhost:16686` | one trace per procedure, a span per SBI call and per N1/N2/N4 message |
| Loki (in Grafana) | `http://localhost:3100` | structured logs from every NF |
| Portal | `http://localhost:8080` | Dashboard KPIs and range charts, streaming logs, PCAP control |

## Metrics

Every NF serves `/metrics` (ports: NRF 9100, AMF 9101, AUSF 9102, UDM 9103, UDR 9104, SMF 9105,
PCF 9106, UPF 9107, NSSF 9109, SMSF 9110, BSF 9111, NEF 9112, LMF 9113). Main families:

| Metric | Meaning |
|---|---|
| `fivegc_sbi_requests_total`, `fivegc_sbi_request_duration_seconds` | SBI request count and latency |
| `fivegc_procedure_total{procedure,result}` | procedure completions (`OK` / `REJECT` / `FAILURE`) |
| `fivegc_nas_messages_total`, `fivegc_ngap_messages_total` | NAS / NGAP message counts |
| `fivegc_authentication_total` | authentication attempts and results |
| `fivegc_pdu_session_total`, `fivegc_pdu_sessions_active` | PDU session events and gauge |
| `fivegc_ue_registered`, `fivegc_ue_registered_by_slice` | registered UEs (total / per S-NSSAI) |
| `fivegc_handover_total{ho_type,result}` | Xn / N2 handovers |
| `fivegc_nf_instances_registered` | NF instances registered at the NRF |
| `fivegc_upf_gtp_bytes_total`, `fivegc_upf_gtp_packets_total`, `fivegc_upf_packet_drops_total{reason}` | UPF data plane |
| `fivegc_upf_pfcp_sessions_active` | UPF PFCP sessions |

## Grafana dashboards

| Dashboard | Shows |
|---|---|
| 5g-kpi-overview | registrations, sessions, success rates, handover rate |
| message-results | NAS / NGAP / procedure results |
| slice-session-analytics | per-slice session analytics |
| upf-dataplane | GTP-U / PFCP throughput, drops, AMBR enforcement |
| sbi-timeline | SBI request timeline |
| ue-connections | UE registration and connection state |
| nf-resource-health | per-NF resource and health |

## Logs

Every NF writes structured JSON to stdout. Mandatory fields: `nf`, `procedure`, `correlation_id`
(a ULID carried in `X-Correlation-Id`), `interface` (`N1`, `N2`, `N4`, `Namf`, …), `direction`
(`IN` / `OUT`) and `spec_ref` (the 3GPP clause). Optional: `supi`, `guti`, `pdu_session_id`,
`seid`, `result`, `cause`, `duration_ms`. Set the level with `LOG_LEVEL`.

```bash
docker logs amf | grep InitialRegistration
make logs                      # follow all NFs
```

Logs are shipped by Promtail to Loki and searchable in Grafana (Explore → Loki). The portal's
**Logs** page streams them live.

## Packet captures

Each NF has a tcpdump sidecar (5 minutes per file, last 12 kept) writing to `./pcaps/<nf>/`:

```bash
./scripts/pcap-control.sh status
./scripts/pcap-control.sh rotate amf      # start a fresh file
./scripts/pcap-control.sh list amf
```

Open the files in Wireshark (NGAP, NAS-5GS, HTTP/2 and PFCP decode natively). The portal's
**PCAP** page offers the same controls with download.
