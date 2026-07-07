# FABLE Grafana Dashboard Audit — 2026-07-03

Branch: `fable-grafana-check` (from `dev`; `observability/` was byte-identical between `main` and `dev` at audit time).
Audit method: **live functional verification** — full stack (`make ueransim`) + UERANSIM UE traffic + PacketRusher Xn handover + direct Nlmf/Nnrf/Nnef/Nsmsf API calls, with every panel's PromQL executed against the running Prometheus (and spot-checked through Grafana's own `/api/ds/query`).

## 1. Executive summary

| | Count |
|---|---|
| Dashboards reviewed | **7** (all provisioned in the live Grafana 10.4.1; no unversioned dashboards found) |
| Panels reviewed | **91** (84 Prometheus, 5 Loki, 1 Jaeger traces, 1 mixed) |
| Panels with defects found | **41** |
| Panels **fixed** on this branch (5 commits, one per dashboard) | **33** |
| Panels flagged for human review (not fixable in JSON — missing instrumentation or judgment calls) | **~16** (see §4/§5) |

**Two systemic root causes explain most breakage:**

1. **`clamp_min(denominator, 1)` in every "Success Rate" stat.** `rate()` values in a lab are ≪ 1 req/s, so the clamp dominated the denominator and the "percentage" degenerated into the raw numerator rate: with 100 % of authentications succeeding, the Authentication Success Rate panel displayed **0.34 %**. All 15 rate stats were rewritten to `100 * (sum(rate(num)) or vector(0)) / (sum(rate(den)) > 0)` — true percentage when attempts exist, honest *No data* when idle. Verified live: LMF locate success went from 0 → **100 %** on screen.
2. **Shared metrics registry exports every plain gauge from every NF.** `shared/observability/metrics/metrics.go` uses one package-level registry; unlabelled gauges (`fivegc_upf_pfcp_sessions_active`, `fivegc_bsf_bindings_active`, `fivegc_nef_subscriptions_active`, `fivegc_lmf_subscriptions_active`) are therefore scraped as `0` from **all 13 NFs**. Unfiltered stat panels received 13 series (12 stray zeros). Fixed by scoping to the owning NF's scrape label (`{nf="UPF"}` etc.).

**One systemic blind spot (code, not JSON):** `SBIRequestsTotal`, `SBIRequestDurationSeconds` and `NGAPMessagesTotal` are defined in `metrics.go` but have **zero call sites** — `metrics.SBIMiddleware` exists and is never wired into any NF server. Eight SBI panels across two dashboards can never show data (§4).

## 2. Dashboard inventory

All files under `observability/grafana/dashboards/`, provisioned via `provisioning/dashboards/providers.yaml` (30 s reload). Datasource refs use a hidden `DS_PROMETHEUS` datasource-type template variable — resolves correctly (verified live; not a defect).

| Dashboard file | UID | Panels | Types | Status after audit |
|---|---|---|---|---|
| `5g-kpi-overview.json` | `5gc-kpi-overview` | 38 | stat, timeseries | 18 panels fixed; SBI (3) + SMSF (3) dead-metric panels flagged |
| `message-results.json` | `5gc-message-results` | 11 | timeseries, table, piechart, heatmap, traces | 4 fixed (units); 5 SBI dead-metric panels flagged |
| `nf-resource-health.json` | `5gc-nf-resource-health` | 8 | stat, timeseries | 2 fixed (dead GC quantile, RSS unit) |
| `sbi-timeline.json` | `5gc-sbi-timeline` | 3 | logs, stat, table (Loki) | OK — verified rendering live log lines |
| `slice-session-analytics.json` | `5gc-slice-session` | 11 | stat, timeseries, piechart, bargauge | queries OK; CM-IDLE panels poisoned by `ue_connected` exporter bug (flagged) |
| `ue-connections.json` | `5gc-ue-connections` | 10 | stat, timeseries, logs, piechart | 5 fixed; 2 dead-procedure panels flagged |
| `upf-dataplane.json` | `5gc-upf-dataplane` | 10 | stat, timeseries | 4 fixed |

Full panel-by-panel inventory (ID, type, title, PromQL, unit, thresholds) captured during the audit; per-panel findings below reference dashboard + panel ID.

## 3. Findings

Severity: **H** = panel shows wrong/no data for its stated KPI; **M** = misleading display; **L** = cosmetic.

| Dashboard | Panel (id) | Issue type | Sev | Fixed? | Notes |
|---|---|---|---|---|---|
| 5g-kpi-overview | Registration Success Rate (1) | broken query (`clamp_min(x,1)`) | H | **Y** | Showed ~0 % with successful registrations. Verified live before/after. |
| 5g-kpi-overview | Authentication Success Rate (2) | broken query | H | **Y** | Displayed **0.34 %** while auth success was 100 %. |
| 5g-kpi-overview | PDU Session Success Rate (3) | broken query | H | **Y** | Displayed 0.70 % under same bug. |
| 5g-kpi-overview | Handover Success Rate (4) | broken query | H | **Y** | Also: `fivegc_handover_total` only ever increments `result="OK"` — a failed HO is invisible (flagged, code). |
| 5g-kpi-overview | SBI Error Rate % (5) | dead metric | H | N (code) | `fivegc_sbi_requests_total` never emitted (no `SBIMiddleware` call sites). Query pattern fixed anyway. |
| 5g-kpi-overview | SBI Latency P95/P99 (12, 13) | dead metric | H | N (code) | `fivegc_sbi_request_duration_seconds` never emitted. |
| 5g-kpi-overview | Active PCF Bindings (16) | 13-series gauge fan-out | M | **Y** | Now `{nf="BSF"}` → exactly 1 series (=2 live bindings). |
| 5g-kpi-overview | BSF Register Success Rate (17) | broken query | H | **Y** | Was 0.69 % with 100 % success. |
| 5g-kpi-overview | Active AF Subscriptions (19) | 13-series gauge fan-out | M | **Y** | `{nf="NEF"}`. |
| 5g-kpi-overview | NEF Create Success Rate (20) | broken query (empty-numerator) | H | **Y** | With only REJECTs, old query returned *No data* instead of 0 %. Verified: now 0 % with live 401 rejects. |
| 5g-kpi-overview | SMS Activate / Uplink SMS Success (22, 23) + SMSF rate (24) | dead metric | H | N (code) | **SMSF increments no metrics at all** (`nf/smsf` only starts the metrics server). Query pattern fixed; panels stay empty until instrumented. |
| 5g-kpi-overview | LMF DetermineLocation Success/Reject (25, 26) | broken query | H | **Y** | Live before/after: 0 → **100 %** with 5 OK locates. |
| 5g-kpi-overview | LMF Active Location Subscriptions (28) | 13-series gauge fan-out | M | **Y** | `{nf="LMF"}` → 1 (live subscription). |
| 5g-kpi-overview | E-CID Success/Fallback (31, 32) | broken query | H | **Y** | Verified live: 100 % after two hAccuracy=100 m locates ran the real NRPPa E-CID path. |
| 5g-kpi-overview | GNSS Success/Fallback (35, 36) | broken query | H | **Y** | Live GNSS request (hAccuracy=20 m) produced `FALLBACK_ECID` — fallback panel responds. |
| message-results | NAS Message Rate (2), NAS Success vs Failure (3), SBI Request Rate (6), SBI 2xx/4xx/5xx (7) | wrong unit (`ops` = ops/s for ×60 per-minute values) | M | **Y** | Unit → `opm`. |
| message-results | SBI panels (6, 7, 8 heatmap, 14, 15) | dead metric | H | N (code) | Same never-wired SBI metrics. |
| message-results | Procedure Success Rate (11) | 0/0 → NaN series noise | L | N | Cosmetic gaps when a procedure is idle; acceptable, flagged only. |
| nf-resource-health | GC Pause P99 (5) | label mismatch → permanently empty | H | **Y** | Go client exports quantiles 0/0.25/0.5/0.75/**1** — no 0.99. Now `quantile="1"`, retitled "GC Pause Max". Verified: 13 series with real values. |
| nf-resource-health | Memory RSS (3) | unit mismatch (MiB value, decimal-MB unit) | L | **Y** | Raw bytes + unit `bytes`. |
| ue-connections | UEs Connected (2), UE Count (5), CM piechart (8) | exporter accuracy | H | N (code) | `fivegc_ue_connected` read **7** with exactly 1 live UE — `ConnectedCount()` counts stale N2 UE contexts that survive gNB restarts/re-registrations. Also poisons slice-session panels 3 & 9 (CM-IDLE % pinned at 0 by `clamp_min`). |
| ue-connections | Registrations OK/Failed 5m (3, 4) | extrapolated fractions | L | **Y** | `increase()` showed "5.17" registrations; wrapped in `round()`. |
| ue-connections | Registration/SR/Dereg rate (6, 9, 10) | wrong unit | M | **Y** | `ops` → `opm`. |
| ue-connections | Service Request Rate (9) | dead procedure label | H | N (code) | AMF handles Service Request but never calls `ProcedureTotal.WithLabelValues(_, "ServiceRequest", _)`. Verified live: AN release + reconnect produced no series. |
| ue-connections | NW-Deregistration Rate (10) | dead procedure label | H | N (code) | `"NetworkDeregistration"` never emitted either. |
| upf-dataplane | Active PFCP Sessions (1, 9) | 13-series gauge fan-out | M | **Y** | `{nf="UPF"}` → 1 series (=2 live sessions, matches SMF). |
| upf-dataplane | GTP-U Throughput (5, 6) | wrong unit (`Mbits` size unit on a rate, double conversion) | M | **Y** | Query yields bit/s, unit `bps`; verified live at ~37.9 kb/s during ping runs. |
| upf-dataplane | PDU Session Establishment Rate "SMF → UPF" (10) | misleading title | L | N (judgment) | Queries `fivegc_pdu_session_total` (SMF SM-level counter, not N4). Recommend retitle "PDU Session Establishment Rate (SMF)" or move to a session dashboard. |

Not changed (correct as found): all Loki panels on `sbi-timeline` and `ue-connections`; slice-analytics slice/DNN panels (verified: 1 UE in SST=1/SD=000001, sessions split `internet`/`ims`); NF discovery panels (verified moving at 0.009 req/s during manual discovery calls); NF instance panels (10 NF types); thresholds elsewhere are sensible; dashboard refresh (5–10 s) and time windows (15–30 m) are sane; legends are all human-readable label templates.

## 4. KPI coverage gaps

**Panels exist, metric never emitted (dead panels — need code instrumentation, not JSON):**

| Metric | Where it should come from | Blocked panels |
|---|---|---|
| `fivegc_sbi_requests_total`, `fivegc_sbi_request_duration_seconds` | `metrics.SBIMiddleware` — defined in `shared/observability/metrics/metrics.go:282` but **zero call sites** in any NF | kpi 5/12/13, message-results 6/7/8/14/15 |
| `fivegc_procedure_total{procedure="ServiceRequest"}` | AMF NAS handler | ue-connections 9 |
| `fivegc_procedure_total{procedure="NetworkDeregistration"}` | AMF mgmt API / NAS | ue-connections 10 |
| `fivegc_procedure_total{nf="SMSF",…}` | SMSF handlers (currently emit nothing) | kpi 22/23/24 |
| `fivegc_handover_total{result!="OK"}` | AMF HO failure paths (only OK is incremented) | failure half of kpi 4/11 |

**Recommendation:** wire `SBIMiddleware` per route (path templates already exist in each NF's mux registration — one wrap per `mux.HandleFunc`) and add the four missing `ProcedureTotal` increments. Good fit for the `observability-agent`.

**Metric exists, no panel (blind spots):**

- `fivegc_ngap_messages_total` — defined **and also never incremented** (dead code + no panel). Either instrument NGAP send/recv in AMF or delete the metric.
- QoS modification success/failure (`NetworkQoSModification` appears in logs only — no metric, no panel). This audit triggered two live NW-initiated 5QI modifications; they are invisible to Prometheus/Grafana.
- `fivegc_upf_packet_drops_total{reason="no_route"}` has code paths but no live sample yet (only `no_session` seen); panel exists and works.

**Standard 5GC KPI checklist:** registration ✓, auth ✓, PDU establishment ✓ (rate; **no latency histogram exists for any procedure** — consider `fivegc_procedure_duration_seconds`), active UEs ✓, active sessions ✓, handover ✓ (success only), QoS modification ✗ (blind spot above), NF availability ✓, SBI latency/error ✗ (dead metrics above).

## 5. Exporter-accuracy issues flagged (not dashboard bugs)

1. **`fivegc_ue_connected` over-counts** (read 7, truth 1): `mgr.ConnectedCount()` (`nf/amf/cmd/amf/main.go:990`) includes stale UE contexts left by gNB restarts / repeated registrations. Makes "UEs Connected", "CM-CONNECTED vs CM-IDLE" and "CM-IDLE %" wrong on two dashboards. Needs AMF context cleanup or a gauge derived from live NGAP associations.
2. **Counters reset on `docker compose up --build`** — `make handover-test` recreated all core containers mid-audit and zeroed every counter. Expected Prometheus behavior (`rate()` handles resets) but worth knowing when reading stat panels that use `increase()`.

## 6. Verification log (live traffic generated)

Environment: full core (13 NFs healthy in Prometheus `up`), Grafana 10.4.1, Prometheus scrape 10 s.

| # | Action | Observed effect on panels |
|---|---|---|
| 1 | `make ueransim` → UE `imsi-001010000000001` registered, 2 PDU sessions auto-established (`internet` 10.60.0.1 + `ims` 10.61.0.1), third via `nr-cli ps-establish IPv4` | `fivegc_ue_registered`=1, `fivegc_pdu_sessions_active` split by DNN (1/1) on kpi 6/10, slice 2/7, "Total Registered UEs"=1 |
| 2 | Rogue UE `imsi-001010000000099` (not in UDR) left retrying | `InitialRegistration FAILURE` counting up; AUSF "UDM auth data request failed"; failure series on kpi 7 (0.018/s) and ue-connections 4 ("Failed (last 5m)" — showed 5.17 pre-fix, whole numbers post-fix) |
| 3 | ICMP floods through `uesimtun0`/`uesimtun1` (≈5 pkt/s, 800 B) | UPF UL/DL packet rate 5.7 pps, throughput 37.9 kb/s per direction, per-DNN split visible; drops panel shows `no_session` (45 drops from pre-restart stale tunnels) |
| 4 | 2× NW-initiated QoS modification (5QI 7 → 9) via MCP `pdu_session_qos_modify` | PCF/SMF/UPF/AMF logs OK — **no metric moved** (QoS-mod blind spot, §4) |
| 5 | PacketRusher Xn handover (needed `URSP_ENABLED=false`; its UE fatals on the AMF's URSP DL NAS Transport 0x05 — same class of quirk as UERANSIM's "Unhandled payload container type [5]") | `fivegc_handover_total{ho_type="xn",result="OK"}`=1 → kpi 4/11 respond |
| 6 | 5× `Nlmf` DetermineLocation (Cell-ID), 2× hAccuracy=100 (E-CID/NRPPa), 1× hAccuracy=20 (GNSS→FALLBACK_ECID), 1× unknown-UE (404) | `lmf_locate_total` OK=5/FAILURE=1, `lmf_ecid_total` OK, `lmf_gnss_total` FALLBACK_ECID, `amf_nrppa_transport_total` UL/DL=4/4, `amf_lpp_transport_total` DL=1 — kpi 25–38 all populated; success stats read **100 %** post-fix (0 % / empty pre-fix) |
| 7 | LMF periodic EventSubscription (10 s interval, unreachable sink) | `lmf_subscriptions_active{nf="LMF"}`=1, notifications `DROPPED` at 0.1/s on kpi 29/30 — watched moving live |
| 8 | NEF `AsSessionWithQoS` creates without valid OAuth scope (401×3) | `procedure_total{nf="NEF",result="REJECT"}` — kpi 21 rate responds; kpi 20 now correctly reads 0 % (was *No data*). NEF **success** path not exercised (token scope rejected) — success-rate=100 % case unverified live for NEF only |
| 9 | 6× NRF NFDiscover (incl. dnn=voip) | `fivegc_nf_discovery_total` per target type at 0.009 req/s on kpi 14 / slice 11. Note: core NFs discover so rarely in steady state that this panel is near-zero in normal operation |
| 10 | gNB `ue-release` + UE auto-reconnect | UE back CM-CONNECTED but **no** `ServiceRequest` series appeared — confirmed dead panel ue-connections 9 (§4) |
| 11 | Post-fix re-verification of all 33 fixed panels | Every fixed query re-executed against Prometheus and spot-checked through Grafana `/api/ds/query` after the 30 s provisioning reload: LMF locate 100 %, E-CID 100 %, BSF=2 / UPF=2 / LMF=1 single-series gauges, GC pause max 0.8–8.8 ms across 13 NFs, throughput in bps moving with pings |

**Unverified against live data** (explicitly): SMSF success paths, NEF success path, N2 handover (only Xn exercised), `no_route` drop reason, Jaeger traces panel (datasource loads; no trace-level assertion made).

## 7. Caveats / environment notes

- `make handover-test` rebuilds and **recreates the whole core** (`up -d --build`), resetting counters and breaking existing UERANSIM tunnels — run it before, not during, metric inspection.
- PacketRusher (`packetrusher` container) fatals on the URSP UE-policy DL NAS Transport; handover validation requires `URSP_ENABLED=false` on the AMF. The AMF in the running stack was left with URSP re-enabled (repo default) after the audit; `nf/amf/config/dev.yaml` is untouched.
- Single-file bind mounts (e.g. the AMF config) keep the old inode after `sed -i`; a container **recreate** (not restart) is needed to pick up edits.
