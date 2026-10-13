<!-- tier: public -->
# MCP server and tools

The MCP server exposes the 5G core to AI clients (Claude Code, Claude Desktop, and any MCP client). It speaks **stdio** and **HTTP SSE on port 9300**; both transports share one tool registry. Tool names appear to clients as `mcp__5gc__<tool>`.

## Start it

```bash
make mcp-start        # add the MCP container to a running core
make 5gcsa MCP=on     # or deploy it together with the stack
make mcp-e2e          # live smoke test of every tool (MUTATE=1 also runs state changes)
# modes: MUTATE=1 DISRUPT=1 LAB_URL=<lab instance> (see the members documentation for the full recipe)
```

Client set-up (Claude Code, Claude Desktop, others): [`mcp/docs/clients.md`](../mcp/docs/clients.md).

## Access and roles

The server decides what a client may run before any tool starts. Three settings do this:

| Setting | Values | Effect |
|---|---|---|
| `access_mode` (env `MCP_ACCESS_MODE`) | `read-only` (code default) · `operator` (dev default) · `lab` | The highest risk the server exposes. Higher tools are hidden and refused. |
| Bearer token (`MCP_BEARER_TOKEN`, `MCP_TOKEN_VIEWER`, `MCP_TOKEN_OPERATOR`, `MCP_TOKEN_ADMIN`) | token → role | `viewer` runs read-only tools; `operator` runs up to DISRUPTIVE; `admin` runs ADMIN. Unset = no auth (lab only). |
| `allow_service_control` | `true` / `false` (default) | Must be `true` for `nf_service_control`, in addition to the admin role and `lab` mode. |

A DISRUPTIVE or ADMIN call without `confirm: true` returns a **dry-run**: what it would change, and nothing is sent. Confirmed calls are spaced by a minimum interval (default 2 s). Every state change is audited (`mcp_audit_log`). Subscriber keys are never returned. The full rules are in the manual, §5.2.

## Tools (73)

Risk: **READ** changes nothing · **MUTATING** changes a stored setting · **DISRUPTIVE** changes live traffic or registrations (needs `confirm`) · **ADMIN** controls NF processes.

### NAS, NGAP and PFCP codecs (pure)

| Tool | Risk | Purpose |
|---|---|---|
| `nas_decode` | READ | Decode a NAS-5GS PDU from hex; reports the message type, IEs and the offset of the first error. |
| `nas_encode` | READ | Encode a NAS message from its type and body. |
| `ie_validate` | READ | Validate one IE against TS 24.501; reports the first error offset. |
| `tlv_inspect` | READ | Walk the TLV, TV and LV-E structure of a NAS buffer. |
| `ngap_decode` | READ | Decode one NGAP PDU (N2) from hex: pdu type, procedure, criticality and IEs in wire order. Decode only. |
| `pfcp_decode` | READ | Decode one PFCP message (N4) from hex: header and IE tree, nested for grouped IEs. Decode only. |

### 5G-AKA and key derivation (pure)

| Tool | Risk | Purpose |
|---|---|---|
| `milenage_run` | READ | Run MILENAGE f1 to f5* for K, OPc, RAND, SQN and AMF. |
| `suci_derive` | READ | Derive a SUCI from a SUPI and the home-network public key (Profile A or B). |
| `xres_star_compute` | READ | Compute XRES* from an authentication vector. |
| `res_star_verify` | READ | Verify RES* against XRES* and HRES*. |
| `kdf_compute` | READ | Run one 3GPP key derivation function (TS 33.220 Annex B). |
| `aka_full_run` | READ | Run a complete 5G-AKA exchange on test vectors. |

### NRF discovery

| Tool | Risk | Purpose |
|---|---|---|
| `nf_discover` | READ | Discover NF instances by type, service, DNN and S-NSSAI (snssais as a JSON array or a string). |
| `nf_list` | READ | List the NF profiles registered in the NRF. Default: `{count, nfInstances:[{instance_id,nf_type,nf_status,services[]}]}`; `detail: true` returns the full NRF profiles. |
| `nf_status` | READ | Status of one NF instance. |

### UE contexts (AMF)

| Tool | Risk | Purpose |
|---|---|---|
| `ue_list` | READ | List UE contexts with SUPI, GUTI, 5GMM and CM state. Filters: gmm_state, cm_state (case-insensitive, optional `5GMM-`/`CM-` prefix). `pdu_session_ids` is a list of integers; PSIs outside 1-15 go to `pdu_session_ids_invalid`; a zero registration time is null. |
| `ue_context_get` | READ | Full UE context by SUPI or by 5G-GUTI (as ue_list shows it). |
| `ran_gnb_list` | READ | gNBs connected over N2 and recently disconnected (TS 38.413 §8.7.1). |

### Traces (Jaeger)

| Tool | Risk | Purpose |
|---|---|---|
| `trace_query` | READ | Jaeger traces by service and tag. format timeline (default) or raw; at most 50 traces. |

### Metrics (Prometheus)

| Tool | Risk | Purpose |
|---|---|---|
| `metric_query` | READ | PromQL instant query, or a range query with start, end and step. At most max_series series (default 50). NaN and ±Inf samples are returned as null (instant value and range points `[ts, number\|null]`; range values are numbers). Every NF exports every shared gauge, so filter with `nf="<owner>"`. |
| `kpi_snapshot` | READ | Key KPIs in one call: registration and authentication success, connected UEs, active PDU sessions, active UPF PFCP sessions. A KPI with no data is null and explained in the sibling `unavailable` map, never 0. `avg_registration_latency_ms` and `sbi_error_rate` are always null (SBI metrics are registered but not exported). `nf` only affects `registration_success_rate`. |
| `alert_list` | READ | Firing Prometheus alerts. |
| `upf_stats` | READ | UPF user-plane counters over a window (default 5 m, max 1 h; optional `dnn`): active PFCP sessions, throughput per DNN `{ul,dl}` in bit/s, packets per second, drops per reason, usage reports and L4 checksums repaired (TS 29.244 §5.2). A value with no data is null and explained in `unavailable`. |

### PCF QoS overrides

| Tool | Risk | Purpose |
|---|---|---|
| `qos_policy_get` | READ | PCF QoS override for a SUPI, optionally per DNN. Reports is_override:false when none is set; no default is invented. |
| `qos_policy_set` | MUTATING | Set a PCF QoS override (5QI, AMBR, ARP) for a SUPI, optionally per DNN. Applies to the next session. |
| `qos_policy_delete` | MUTATING | Remove a PCF QoS override. Idempotent. |
| `qos_policy_list` | READ | List every per-subscriber PCF QoS override (optionally one SUPI): supi, dnn, 5qi, arp, ambr_ul, ambr_dl; null where the override does not set them. An empty list means no override. |

### PDU sessions and subscription QoS (SMF, UDM)

| Tool | Risk | Purpose |
|---|---|---|
| `pdu_session_list` | READ | Active PDU sessions held by the SMF. |
| `pdu_session_qos_get` | READ | QoS state of one session: 5QI, AMBR, source and PFCP QER. |
| `pdu_session_qos_set` | DISRUPTIVE | Change the 5QI and AMBR of an active session through the SMF (TS 23.502 §4.3.3.2). persist_policy also writes the PCF override. |
| `subscription_qos_get` | READ | Subscription QoS from UDM: default 5QI and ARP per slice. |
| `subscription_am_get` | READ | Access and mobility subscription of a SUPI from the UDM (Nudm_SDM `am-data`, TS 29.503), passed through unchanged. An unknown SUPI returns error -32000. |

### Status (NRF, portal, Prometheus)

| Tool | Risk | Purpose |
|---|---|---|
| `core_health` | READ | Health of every NF in the NRF: a live mTLS /healthz on each SBI address, plus Prometheus up. A `dependencies` block reports portal (reachable, store), Loki, Jaeger and Prometheus (2 s probe each). |
| `deployment_status` | READ | Deployment mode and reported services, from the portal. |
| `subscriber_list` | READ | Subscribers from the UDR. K, OPc, OP and SQN are always redacted. Error `PORTAL_STORE_UNAVAILABLE` (-32000, hint `docker restart mgmt-portal`) when the portal store is down. |
| `subscriber_get` | READ | One subscriber and its RFSP override. Secrets redacted. Same `PORTAL_STORE_UNAVAILABLE` error when the store is down. |
| `config_view` | READ | Slices, DNNs, slice QoS and policy templates. Each is tagged runtime or restart_required. Only `policy_templates` carries `PORTAL_STORE_UNAVAILABLE` when the store is down; other sections stay readable. |
| `pws_list` | READ | PWS broadcasts in the portal's CBC store. |
| `mcp_info` | READ | The MCP server itself: version, build commit, access mode, caller role, tool and alias counts, tools hidden by the access mode, and a 2 s parallel reachability probe of every upstream (NRF, AMF, SMF, UDM, PCF, BSF, NEF, SMSF, portal, Prometheus, Loki, Jaeger) with latency.
| `slice_status` | READ | Per S-NSSAI (optional `sst`, `sd`): registered UEs, active sessions per DNN, configured session AMBR and supporting gNBs (TS 23.501 §5.15). |
| `pcf_binding_list` | READ | PCF bindings from the BSF (Nbsf_Management discovery, TS 29.521) by `supi`, `ue_ip` or `dnn`; with no filter, one lookup per SMF session UE IP. Returns the bindings, the BSF active-binding gauge and what was queried. Each lookup is a real discovery; a miss is counted by the BSF as a rejected discovery. |

### Analysis and PCAP

| Tool | Risk | Purpose |
|---|---|---|
| `log_query` | READ | LogQL query on the NF logs in Loki. Window at most 1 h, at most 500 lines. |
| `procedure_timeline` | READ | One procedure run from its logs and Jaeger spans, by correlation_id or SUPI. Flags the first REJECT or FAILURE. |
| `ue_diagnose` | READ | One-call UE diagnosis across AMF, SMF, PCF, UDM and recent failures. Returns findings with their spec clause; upstream failures are listed, not hidden. `recent_errors` are grouped rows `{nf,procedure,result,msg,spec_ref,count,first,last}` (top 10 by count) from the last 15 min of Loki (limit 200); `logs_truncated` is true when the cap is hit. A CM-IDLE UE gets a finding to page first with `ue_page`: this AMF does not page for network-initiated modification. |
| `procedure_stats` | READ | Procedure OK, REJECT and FAILURE counts, success percentage and rate, from fivegc_procedure_total. `include_zero` (default false) keeps the all-zero rows. |
| `pcap_list` | READ | PCAP capture state per NF sidecar, and the capture files of one NF. |
| `core_consistency_check` | READ | Cross-checks AMF, SMF, UPF, BSF, NRF and Prometheus counts and returns counts plus findings `{severity,check,detail,spec_ref}`: PDU sessions without a matching SMF session or UE, SMF vs UPF session count, BSF binding count, NF missing from the NRF, scrape targets down. An unreachable source is a warning, not a pass. |
| `error_summary` | READ | REJECT and FAILURE log lines of the last window (default 15 m, max 1 h; optional `nf`, `top` 1-50, default 10) grouped by NF, procedure, result, cause and spec clause, sorted by count, with one example correlation id and last-seen time (empty when the log line has none). |
| `n4_session_get` | READ | PFCP session as the UPF holds it, compared with the SMF view. Give `supi` + `pdu_session_id`, or `seid` (decimal or 0x-hex), or `ue_ip`; mixing the forms is refused. Returns `upf`, `smf` and `smf_mismatches` (`cp_seid`, `ue_ip`, `ul_teid`, `qer_count`, `qers[N]`, `qers[N].mbr_ul_kbps`/`mbr_dl_kbps`/`qfi`/`gate_ul`/`gate_dl`). Errors `CONTEXT_NOT_FOUND`, `AMBIGUOUS_SESSION`, `N4_SESSION_NOT_FOUND`, `AMBIGUOUS_N4_SESSION`; an upstream failure names `data.upstream` (prometheus, upf, smf). |
| `pcap_control` | MUTATING | Start, stop, pause, resume or rotate the tcpdump capture of one NF sidecar. |

### Core-side control (changes live state)

| Tool | Risk | Purpose |
|---|---|---|
| `ue_deregister_nw` | DISRUPTIVE | Network-initiated deregistration with re-registration required (TS 23.502 §4.2.2.3.3). |
| `pdu_session_release_nw` | DISRUPTIVE | Network-initiated release of one PDU session (TS 23.502 §4.3.4.3). |
| `ue_policy_push` | DISRUPTIVE | Push the current URSP to a registered UE. Deferred, not failed, for a CM-IDLE UE (TS 23.502 §4.2.4.3). |
| `ue_page` | DISRUPTIVE | Page a CM-IDLE UE for one PDU session (TS 23.502 §4.2.3.3). |
| `nssaa_trigger` | DISRUPTIVE | Slice re-authentication or revocation for one S-NSSAI (TS 23.502 §4.2.9.3 and §4.2.9.4). |
| `pws_broadcast` | DISRUPTIVE | Start a Public Warning System broadcast (Write-Replace Warning, TS 38.413 §8.9.1). |
| `pws_cancel` | DISRUPTIVE | Cancel a PWS broadcast (PWS Cancel, TS 38.413 §8.9.2). |
| `ue_an_release_nw` | DISRUPTIVE | Network-initiated AN release of a CM-CONNECTED UE (TS 23.502 §4.2.6 step 2): the AMF sends a UE Context Release Command (cause misc/om-intervention) and the UE goes CM-IDLE while staying RM-REGISTERED; its PDU sessions are deactivated, not released. Refuses a CM-IDLE UE. Use `ue_page` to bring it back. |
| `ue_location_get` | DISRUPTIVE | Locate a UE through the portal and the LMF (NGAP Location Reporting, TS 23.273 §6.10.1, TS 38.413 §8.12): reports whether the UE is reachable and its position. The UE must be known to the AMF. |
| `af_qos_session_create` | DISRUPTIVE | Create an AF session with required QoS at the NEF (Nnef_AFsessionWithQoS, TS 29.522 §4.4.13) for a UE IPv4 address. The dry-run checks the address against the SMF sessions. The server first gets an OAuth2 token (client credentials, scope `nnef-afsessionwithqos`) from the NRF. |
| `af_qos_session_get` | READ | Read one AF session with required QoS from the NEF (TS 29.522 §4.4.13). |
| `af_qos_session_delete` | DISRUPTIVE | Delete an AF session with required QoS at the NEF (TS 29.522 §4.4.13). |
| `pws_resend` | DISRUPTIVE | Re-send an existing PWS broadcast to the gNBs (Write-Replace Warning, TS 38.413 §8.9.1) through the portal. |
| `sms_send_mt` | DISRUPTIVE | Send a mobile-terminated SMS to a UE through the SMSF (TS 23.502 §4.13.3). The text is base64, 1 to 255 decoded bytes. A UE without SMS activation returns `CONTEXT_NOT_FOUND`. |

`ue_an_release_nw` needs a CM-CONNECTED UE and refuses a CM-IDLE one. With the default lab configuration the `af_qos_session_*` tools fail with NEF HTTP 401, because the NRF and the NEF use different OAuth2 signing secrets; align them before use. `sms_send_mt` returns `CONTEXT_NOT_FOUND` for a UE without SMS activation.

### Runtime configuration, simulators, audit

| Tool | Risk | Purpose |
|---|---|---|
| `slice_session_ambr_set` | DISRUPTIVE | Set or revert the session AMBR of a slice and DNN (BitRate strings). The stored value is MUTATING; apply_to_active renegotiates the live sessions and is DISRUPTIVE. |
| `rfsp_override_set` | DISRUPTIVE | Set (1-256) or clear the RFSP index of a subscriber. The UE is deregistered to apply it; the dry-run says so. |
| `ursp_template_apply` | DISRUPTIVE | Apply a URSP policy template to a subscriber (UE Configuration Update). Invoke and dry-run plan return `PORTAL_STORE_UNAVAILABLE` when the portal store is down. |
| `nf_service_control` | ADMIN | Start, stop or restart an NF container. Needs access_mode lab, allow_service_control: true and an admin token. Protected services need force. |
| `mcp_audit_log` | READ | Newest audit entries of state-changing calls: tool, risk, role, session, outcome and input hash. Stateless HTTP calls are labelled session `http:<ip>` with a `remote_addr` field. |
| `nf_log_level` | MUTATING | Read (no level) or set an NF's log level for a TTL (default 900 s, max 3600 s). The NF reverts to its startup level when the TTL ends. |
| `amf_timer_config` | MUTATING | Read (no arguments) or set the AMF runtime timers: T3512 (`t3512_secs`, 60-86400 s, exactly representable in GPRS timer 3), `mobile_reachable_guard_secs` (0-3600, 0 is lab-only; mobile reachable = T3512 + guard) and `implicit_detach_secs` (60-86400). `reset:true` restores the YAML values. Runtime only (lost on AMF restart); a UE learns the new T3512 in its next Registration Accept. The read is READ-class and callable in read-only mode but not listed there. |
| `subscriber_profile_update` | DISRUPTIVE | Change `ambr_ul`/`ambr_dl` (BitRate strings such as "100 Mbps") and/or `slices` of one subscriber. Keys and identity cannot be changed here. The portal deregisters the UE, which must re-register. The dry-run shows the redacted record. |
| `subscriber_provision` | ADMIN | Create a NEW subscriber (`supi`, `k`, `opc`, optional `sqn`, `amf`, `profile`); an existing SUPI is refused. Keys are never echoed, logged or kept in the audit log. Needs access_mode lab and an admin token. |
| `subscriber_delete` | ADMIN | Delete a subscriber from the UDR; an unknown SUPI is refused. A UE registered now keeps its AMF context until its next authentication. Needs access_mode lab and an admin token. |

## Deprecated aliases

| Alias | Replacement |
|---|---|
| `gmm_state_get` | `ue_context_get` — Projection of the UE context; the full context now carries the same fields. |
| `procedure_summary` | `procedure_stats` — Raw PromQL moved to metric_query; the procedure mode is procedure_stats. |
| `pdu_session_qos_modify` | `pdu_session_qos_set` — Now drives the SMF (TS 23.502 §4.3.3.2), not the AMF PATCH; persists the PCF override like before. |

## Removed

On 2026-10-09 the UERANSIM control tools (`ueransim_*`) and `pdu_session_establish_with_qos` were removed. Drive UE and gNB simulation with the make targets and the management portal; MCP acts on the core.

