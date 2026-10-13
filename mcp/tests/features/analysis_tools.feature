Feature: MCP analysis and status tools against mocked upstreams (wave-1 fixes)
  As an operator debugging the 5G core through an LLM client
  I want ue_diagnose, procedure_stats and subscriber_list to report the true core state
  So that CM-IDLE UEs, newest errors, grouped errors and a down subscriber store are never misreported

  Background:
    Given the MCP analysis tools run against mocked AMF, SMF, Loki, Prometheus and portal upstreams
    And the AMF mock knows UE "imsi-001010000000001" in 5GMM state "5GMM-REGISTERED"

  # ---- D1: CM state names (TS 23.502 §4.3.3.2) --------------------------------

  Scenario: ue_diagnose reports a CM-IDLE finding when the AMF says CM-IDLE and a PDU session is active
    Given the AMF mock reports cm_state "CM-IDLE" for the UE
    And the SMF mock reports 1 active PDU session for the UE
    When I call "ue_diagnose" with arguments {"supi":"imsi-001010000000001"}
    Then the call succeeds
    And the findings contain a message mentioning "CM-IDLE" with spec_ref "TS 23.502 §4.3.3.2"

  Scenario: ue_diagnose raises no CM-IDLE finding for a CM-CONNECTED UE with a PDU session
    Given the AMF mock reports cm_state "CM-CONNECTED" for the UE
    And the SMF mock reports 1 active PDU session for the UE
    When I call "ue_diagnose" with arguments {"supi":"imsi-001010000000001"}
    Then the call succeeds
    And the findings contain no message mentioning "CM-IDLE"

  # ---- D2: newest Loki line (direction=backward) -------------------------------

  Scenario: ue_diagnose latest-error finding refers to the newest Loki line
    Given the AMF mock reports cm_state "CM-CONNECTED" for the UE
    And the Loki mock returns error lines newest first with msg "B" newest and msg "A" oldest
    When I call "ue_diagnose" with arguments {"supi":"imsi-001010000000001"}
    Then the call succeeds
    And the Loki mock was queried with direction "backward"
    And the latest-error finding refers to msg "B"

  # ---- D3: recent_errors grouping ----------------------------------------------

  Scenario: ue_diagnose groups 25 identical error lines into one recent_errors row
    Given the AMF mock reports cm_state "CM-CONNECTED" for the UE
    And the Loki mock returns 25 identical error lines for nf "AMF", procedure "InitialRegistration", result "REJECT", msg "udm unreachable"
    When I call "ue_diagnose" with arguments {"supi":"imsi-001010000000001"}
    Then the call succeeds
    And recent_errors has exactly 1 row
    And the recent_errors row 1 has count 25 and non-empty first and last timestamps

  Scenario: ue_diagnose returns at most the top 10 grouped error kinds by count
    Given the AMF mock reports cm_state "CM-CONNECTED" for the UE
    And the Loki mock returns 12 distinct error kinds with decreasing counts
    When I call "ue_diagnose" with arguments {"supi":"imsi-001010000000001"}
    Then the call succeeds
    And recent_errors has at most 10 rows
    And recent_errors rows are ordered by descending count

  # ---- Error path: unknown SUPI ------------------------------------------------

  Scenario: ue_diagnose for a SUPI unknown to the AMF returns a not-registered finding without failing
    Given the AMF mock answers 404 for UE "imsi-001010000000099"
    When I call "ue_diagnose" with arguments {"supi":"imsi-001010000000099"}
    Then the call succeeds
    And the findings contain a message mentioning "not found in the AMF" with spec_ref "TS 23.502 §4.2.2.2"
    And no panic occurred in the tool

  # ---- procedure_stats include_zero --------------------------------------------

  Scenario: procedure_stats omits all-zero rows by default
    Given the Prometheus mock returns procedure "InitialRegistration" with OK 10 and procedure "ServiceRequest" with all counts 0
    When I call "procedure_stats" with arguments {"nf":"AMF"}
    Then the call succeeds
    And the procedure_stats rows contain "InitialRegistration"
    And the procedure_stats rows do not contain "ServiceRequest"

  Scenario: procedure_stats include_zero true returns the all-zero rows too
    Given the Prometheus mock returns procedure "InitialRegistration" with OK 10 and procedure "ServiceRequest" with all counts 0
    When I call "procedure_stats" with arguments {"nf":"AMF","include_zero":true}
    Then the call succeeds
    And the procedure_stats rows contain "InitialRegistration"
    And the procedure_stats rows contain "ServiceRequest"

  # ---- Rejection: portal store down --------------------------------------------

  Scenario: subscriber_list refuses with PORTAL_STORE_UNAVAILABLE when the portal store is down
    Given the portal mock health returns {"status":"ok","store":"down"}
    When I call "subscriber_list" with arguments {}
    Then the call is refused with code -32000 and message "PORTAL_STORE_UNAVAILABLE"
    And the result is not an empty subscriber list

  Scenario: subscriber_list returns the mocked subscribers when the portal store is up
    Given the portal mock health returns {"status":"ok","store":"up"}
    And the portal mock holds subscribers "imsi-001010000000001" and "imsi-001010000000002"
    When I call "subscriber_list" with arguments {}
    Then the call succeeds
    And the subscriber list contains "imsi-001010000000001"
    And the subscriber list contains "imsi-001010000000002"
    And the subscriber list contains no key material

  # =============================================================================
  # MCP-009 (wave 2): seven READ_ONLY status/analysis tools, no NF change.
  # Refs: TS 23.501 §5.15 (slices); TS 29.503 (UDM SDM am-data); TS 29.521 §5.2.2.4
  # (BSF PcfBinding discovery); TS 29.244 §5.2 (UPF counters).
  # Every PromQL filters nf=<owner> because every NF exports every shared gauge.
  # =============================================================================

  # ---- upf_stats ---------------------------------------------------------------

  @mcp009
  Scenario: upf_stats reads pfcp_sessions_active from the UPF series only and ignores other NFs
    Given the Prometheus mock returns gauge "fivegc_upf_pfcp_sessions_active" with value 0 for nf "SMF" and value 2 for nf "UPF"
    When I call "upf_stats" with arguments {}
    Then the call succeeds
    And the result field "pfcp_sessions_active" equals 2
    And every PromQL sent to the Prometheus mock filters nf="UPF"
    And the result contains the keys "throughput_bps", "packets_pps", "drops", "usage_reports", "l4_checksum_repaired"

  @mcp009
  Scenario: upf_stats defaults the window to 5m and reports per-DNN throughput
    Given the Prometheus mock returns UPF throughput for dnn "internet" with ul 1000 and dl 2000
    When I call "upf_stats" with arguments {"dnn":"internet"}
    Then the call succeeds
    And the Prometheus mock was queried with range window "5m"
    And the result throughput_bps for dnn "internet" has ul 1000 and dl 2000

  @mcp009
  Scenario: upf_stats rejects a window above the 1h maximum
    When I call "upf_stats" with arguments {"window":"2h"}
    Then the call is refused with code -32602
    And the Prometheus mock received no query

  # ---- core_consistency_check --------------------------------------------------

  @mcp009
  Scenario: core_consistency_check reports no error finding on a consistent core
    Given the AMF mock holds UEs "imsi-001010000000001" and "imsi-001010000000002" each with pdu_session_ids "AQ=="
    And the SMF mock holds sessions for "imsi-001010000000001" and "imsi-001010000000002" with PDU session id 1
    And the Prometheus mock returns gauge "fivegc_upf_pfcp_sessions_active" with value 2 for nf "UPF"
    And the Prometheus mock returns gauge "fivegc_bsf_bindings_active" with value 2 for nf "BSF"
    When I call "core_consistency_check" with arguments {}
    Then the call succeeds
    And the counts report amf_ues 2, amf_psis 2, smf_sessions 2, upf_pfcp_sessions 2 and bsf_bindings 2
    And no finding has severity "error"

  @mcp009
  Scenario: core_consistency_check accepts AMF pdu_session_ids given as an integer array
    Given the AMF mock holds UE "imsi-001010000000001" with pdu_session_ids [1]
    And the SMF mock holds sessions for "imsi-001010000000001" with PDU session id 1
    And the Prometheus mock returns gauge "fivegc_upf_pfcp_sessions_active" with value 1 for nf "UPF"
    When I call "core_consistency_check" with arguments {}
    Then the call succeeds
    And the counts report amf_psis 1
    And no finding has severity "error"

  @mcp009
  Scenario: core_consistency_check flags an SMF session whose SUPI the AMF does not know
    Given the AMF mock holds UE "imsi-001010000000001" with pdu_session_ids [1]
    And the SMF mock holds sessions for "imsi-001010000000001" and "imsi-001010000000077" with PDU session id 1
    And the Prometheus mock returns gauge "fivegc_upf_pfcp_sessions_active" with value 2 for nf "UPF"
    When I call "core_consistency_check" with arguments {}
    Then the call succeeds
    And a finding has severity "error" and check "smf_session_without_amf_ue"
    And that finding has a non-empty detail and a non-empty spec_ref

  @mcp009
  Scenario: core_consistency_check flags an SMF session count that differs from the UPF PFCP session gauge
    Given the AMF mock holds UEs "imsi-001010000000001" and "imsi-001010000000002" each with pdu_session_ids "AQ=="
    And the SMF mock holds sessions for "imsi-001010000000001" and "imsi-001010000000002" with PDU session id 1
    And the Prometheus mock returns gauge "fivegc_upf_pfcp_sessions_active" with value 1 for nf "UPF"
    When I call "core_consistency_check" with arguments {}
    Then the call succeeds
    And a finding has severity "error" and check "smf_upf_session_count"

  @mcp009
  Scenario: core_consistency_check flags an AMF PDU session id with no SMF session
    Given the AMF mock holds UE "imsi-001010000000001" with pdu_session_ids [1]
    And the SMF mock holds no sessions
    And the Prometheus mock returns gauge "fivegc_upf_pfcp_sessions_active" with value 0 for nf "UPF"
    When I call "core_consistency_check" with arguments {}
    Then the call succeeds
    And a finding has check "amf_psi_without_smf_session"

  @mcp009
  Scenario: core_consistency_check is allowed under the read-only access mode
    Given the MCP guard runs with access_mode "read-only"
    And the AMF mock holds UE "imsi-001010000000001" with pdu_session_ids [1]
    And the SMF mock holds sessions for "imsi-001010000000001" with PDU session id 1
    And the Prometheus mock returns gauge "fivegc_upf_pfcp_sessions_active" with value 1 for nf "UPF"
    When I call "core_consistency_check" with arguments {}
    Then the call succeeds
    And "core_consistency_check" is listed in tools/list

  # ---- error_summary -----------------------------------------------------------

  @mcp009
  Scenario: error_summary returns the Loki vector groups as rows ordered by count descending
    Given the Loki instant-query mock returns a vector with group nf "AMF", procedure "InitialRegistration", result "REJECT", cause "22", spec_ref "TS 23.502 §4.2.2.2.2" and count 3
    And the Loki instant-query mock also returns group nf "SMF", procedure "PduSessionEstablishment", result "FAILURE", cause "N4 timeout", spec_ref "TS 23.502 §4.3.2.2.1" and count 7
    When I call "error_summary" with arguments {}
    Then the call succeeds
    And the error_summary has exactly 2 rows
    And error_summary row 1 has nf "SMF" and count 7
    And error_summary row 2 has nf "AMF" and count 3
    And every error_summary row has the keys "nf", "procedure", "result", "cause", "spec_ref", "count", "example_correlation_id", "last_seen"
    And the Loki mock was queried at "/loki/api/v1/query" with a "count_over_time" expression over window "15m"

  @mcp009
  Scenario: error_summary rejects a window above the 1h maximum
    When I call "error_summary" with arguments {"window":"2h"}
    Then the call is refused with code -32602

  @mcp009
  Scenario Outline: error_summary rejects a top value outside 1 to 50
    When I call "error_summary" with arguments {"top":<top>}
    Then the call is refused with code -32602

    Examples:
      | top |
      | 0   |
      | 51  |

  # ---- mcp_info ----------------------------------------------------------------

  @mcp009
  Scenario: mcp_info counts tools and aliases consistently with tools/list
    When I call "mcp_info" with arguments {}
    Then the call succeeds
    And the result contains the keys "version", "build_commit", "access_mode", "caller_role", "tool_count", "alias_count", "upstreams"
    And tool_count plus alias_count equals the number of names in tools/list

  @mcp009
  Scenario: mcp_info reports an unreachable upstream as reachable false without failing
    Given the mocked AMF upstream is shut down
    When I call "mcp_info" with arguments {}
    Then the call succeeds
    And the upstream "amf" is reported with reachable false
    And the upstream "prometheus" is reported with reachable true and a latency_ms

  # ---- slice_status ------------------------------------------------------------

  @mcp009
  Scenario: slice_status for sst 1 sd 000001 combines registered UEs, sessions per DNN, AMBR and gNBs
    Given the Prometheus mock returns fivegc_ue_registered_by_slice for nf "AMF" snssai sst 1 sd "000001" with value 2
    And the SMF mock holds 2 sessions on dnn "internet" in slice sst 1 sd "000001"
    And the portal mock returns slice QoS for sst 1 sd "000001" with a Session-AMBR
    And the AMF mock lists a gNB supporting slice sst 1 sd "000001"
    When I call "slice_status" with arguments {"sst":1,"sd":"000001"}
    Then the call succeeds
    And the slice_status has exactly 1 entry for snssai sst 1 sd "000001"
    And that entry has registered_ues 2 and active_sessions_by_dnn "internet" 2
    And that entry has a non-empty session_ambr_config and gnbs_supporting 1

  @mcp009
  Scenario: slice_status rejects an sd that is not 6 hexadecimal digits
    When I call "slice_status" with arguments {"sst":1,"sd":"0001"}
    Then the call is refused with code -32602

  # ---- subscription_am_get -----------------------------------------------------

  @mcp009
  Scenario: subscription_am_get passes the UDM SDM am-data through
    Given the UDM mock answers GET "/nudm-sdm/v2/imsi-001010000000001/am-data" with nssai defaultSingleNssais sst 1 sd "000001"
    When I call "subscription_am_get" with arguments {"supi":"imsi-001010000000001"}
    Then the call succeeds
    And the result nssai.defaultSingleNssais contains sst 1 sd "000001"

  @mcp009
  Scenario: subscription_am_get rejects a malformed SUPI
    When I call "subscription_am_get" with arguments {"supi":"not-a-supi"}
    Then the call is refused with code -32602
    And the UDM mock received no request

  @mcp009
  Scenario: subscription_am_get returns a structured error when the UDM answers 404
    Given the UDM mock answers 404 for GET "/nudm-sdm/v2/imsi-001010000000099/am-data"
    When I call "subscription_am_get" with arguments {"supi":"imsi-001010000000099"}
    Then the call is refused with code -32000
    And no panic occurred in the tool

  # ---- pcf_binding_list --------------------------------------------------------

  @mcp009
  Scenario: pcf_binding_list with a supi filter returns the single matching binding
    Given the BSF mock answers GET "/nbsf-management/v1/pcfBindings" for supi "imsi-001010000000001" with binding ipv4Addr "10.60.0.1", dnn "internet", snssai sst 1 sd "000001"
    And the Prometheus mock returns gauge "fivegc_bsf_bindings_active" with value 2 for nf "BSF"
    When I call "pcf_binding_list" with arguments {"supi":"imsi-001010000000001"}
    Then the call succeeds
    And the pcf_binding_list has exactly 1 binding for supi "imsi-001010000000001"
    And each binding has the keys "bindingId", "supi", "ipv4Addr", "dnn", "snssai", "pcfFqdn", "pcfId"
    And the result bindings_active equals 2

  @mcp009
  Scenario: pcf_binding_list without a filter queries the BSF once per SMF session ueIp
    Given the SMF mock holds sessions with ueIp "10.60.0.1" and "10.60.0.2"
    And the BSF mock answers a binding for each of the ueIps "10.60.0.1" and "10.60.0.2"
    When I call "pcf_binding_list" with arguments {}
    Then the call succeeds
    And the BSF mock received exactly 2 queries each carrying an "ipv4Addr" query parameter
    And the pcf_binding_list has exactly 2 bindings

  @mcp009
  Scenario: pcf_binding_list treats a BSF 404 for a filter as an empty list, not an error
    Given the BSF mock answers 404 for GET "/nbsf-management/v1/pcfBindings"
    When I call "pcf_binding_list" with arguments {"supi":"imsi-001010000000099"}
    Then the call succeeds
    And the pcf_binding_list has exactly 0 bindings

  @mcp009
  Scenario: pcf_binding_list rejects a malformed ue_ip
    When I call "pcf_binding_list" with arguments {"ue_ip":"999.1.1.1"}
    Then the call is refused with code -32602
    And the BSF mock received no request
