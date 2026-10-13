@mcp012
Feature: MCP n4_session_get compares the SMF session view with the UPF PFCP session state (read-only)
  As an operator debugging the 5G core through an LLM client
  I want n4_session_get to read the PFCP session held by the UPF and diff it against the SMF view
  So that a Session-AMBR change, a stale TEID or a missing N4 session is visible without a PCAP
  # Refs: TS 29.244 §5.2 (Packet Forwarding Model, PDR/FAR/QER/URR per PFCP session),
  # TS 29.244 §7.5.2 (PFCP Session Establishment Request, Create QER §7.5.2.5),
  # TS 29.244 §7.5.4.5 (Update QER), §8.2.7 (Gate Status), §8.2.8 (MBR), §8.2.89 (QFI);
  # TS 23.501 §5.7.1.8 (Session-AMBR enforced by the UPF).
  # Design contract: docs/procedures/n4-session-inspection.md (§4.4, §4.5, §5.2, §7.6 D1-D5).
  # Read-only: no PFCP message and no state change at any NF.

  Background:
    Given the MCP n4 inspection tool runs against mocked SMF, Prometheus and UPF admin upstreams
    And the MCP guard runs with access_mode "operator"
    And the Prometheus mock resolves nf "upf" to the UPF admin mock
    And the SMF mock holds session PDU session id 1 for "imsi-001010000000001" with seid 9, upfTeid 4097, ueIp "10.60.0.2" and pfcpQers [{qerId 1, role session-ambr, gateUl OPEN, gateDl OPEN, mbrUlKbps 100000, mbrDlKbps 100000}, {qerId 2, role qos-flow, qfi 1, gateUl OPEN, gateDl OPEN}]

  # ---- Happy path: lookup by PSI (path A) ----------------------------------------------

  Scenario: n4_session_get by pdu_session_id returns both views and an empty smf_mismatches when SMF and UPF agree
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4097, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 100000, gate_ul OPEN, gate_dl OPEN}, {qer_id 2, qfi 1, has_mbr false, gate_ul OPEN, gate_dl OPEN}]
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call succeeds
    And the result contains the keys "upf", "smf", "smf_mismatches"
    And the result upf has exactly 2 qers
    And the result smf_mismatches is an empty array
    And the SMF mock received exactly 1 GET to "/nsmf-management/v1/sessions/1"
    And the UPF admin mock received exactly 1 GET to "/admin/v1/n4-sessions" with query seid "9"
    And the UPF admin mock received no request other than GET

  # ---- Happy path: lookup by seid and by ue_ip (path B) ---------------------------------

  Scenario: n4_session_get by seid queries the UPF first and then joins the SMF session with the same seid
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4097, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 100000, gate_ul OPEN, gate_dl OPEN}, {qer_id 2, qfi 1, has_mbr false, gate_ul OPEN, gate_dl OPEN}]
    When I call "n4_session_get" with arguments {"seid":9}
    Then the call succeeds
    And the result upf has exactly 2 qers
    And the result smf_mismatches is an empty array
    And the UPF admin mock received exactly 1 GET to "/admin/v1/n4-sessions" with query seid "9"
    And the SMF mock received exactly 1 GET to "/nsmf-management/v1/sessions/1"

  Scenario: n4_session_get by ue_ip finds the UPF session by UE address and joins the SMF session through its cp_seid
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4097, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 100000, gate_ul OPEN, gate_dl OPEN}, {qer_id 2, qfi 1, has_mbr false, gate_ul OPEN, gate_dl OPEN}]
    When I call "n4_session_get" with arguments {"ue_ip":"10.60.0.2"}
    Then the call succeeds
    And the result upf has exactly 2 qers
    And the result smf_mismatches is an empty array
    And the UPF admin mock received exactly 1 GET to "/admin/v1/n4-sessions" with query ue_ip "10.60.0.2"

  # ---- Diff: every mismatch kind in docs/procedures/n4-session-inspection.md §4.5 ---------

  Scenario: n4_session_get reports an MBR downlink mismatch between the SMF QER 1 and the UPF QER 1 (Update QER not applied)
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4097, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 30000, gate_ul OPEN, gate_dl OPEN}, {qer_id 2, qfi 1, has_mbr false, gate_ul OPEN, gate_dl OPEN}]
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call succeeds
    And the result smf_mismatches has exactly 1 entry
    And the smf_mismatches entry 1 has field "qers[1].mbr_dl_kbps", smf 100000 and upf 30000

  Scenario: n4_session_get reports a QFI mismatch on the QoS-flow QER
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4097, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 100000, gate_ul OPEN, gate_dl OPEN}, {qer_id 2, qfi 5, has_mbr false, gate_ul OPEN, gate_dl OPEN}]
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call succeeds
    And the result smf_mismatches has exactly 1 entry
    And the smf_mismatches entry 1 has field "qers[2].qfi", smf 1 and upf 5

  Scenario: n4_session_get reports a CLOSED gate at the UPF that the SMF never asked for
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4097, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 100000, gate_ul OPEN, gate_dl OPEN}, {qer_id 2, qfi 1, has_mbr false, gate_ul OPEN, gate_dl CLOSED}]
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call succeeds
    And the result smf_mismatches has exactly 1 entry
    And the smf_mismatches entry 1 has field "qers[2].gate_dl", smf "OPEN" and upf "CLOSED"

  Scenario: n4_session_get reports an uplink TEID mismatch between the SMF upfTeid and the UPF ul_teid
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4098, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 100000, gate_ul OPEN, gate_dl OPEN}, {qer_id 2, qfi 1, has_mbr false, gate_ul OPEN, gate_dl OPEN}]
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call succeeds
    And the result smf_mismatches has exactly 1 entry
    And the smf_mismatches entry 1 has field "ul_teid", smf 4097 and upf 4098

  Scenario: n4_session_get reports a QER count mismatch and the QER missing at the UPF
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4097, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 100000, gate_ul OPEN, gate_dl OPEN}]
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call succeeds
    And the smf_mismatches contain field "qer_count" with smf 2 and upf 1
    And the smf_mismatches contain field "qers[2]" with smf "present" and upf null

  # ---- Error path: SMF side --------------------------------------------------------------

  Scenario: n4_session_get maps an SMF 404 to a CONTEXT_NOT_FOUND tool error and never queries the UPF
    Given the SMF mock answers 404 for GET "/nsmf-management/v1/sessions/1"
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call is refused with code -32000
    And the error data code is "CONTEXT_NOT_FOUND"
    And the UPF admin mock received no request

  Scenario: n4_session_get maps an SMF 409 to an AMBIGUOUS_SESSION tool error when no supi disambiguates the PDU session id
    Given the SMF mock answers 409 with cause "AMBIGUOUS_SESSION" for GET "/nsmf-management/v1/sessions/1"
    When I call "n4_session_get" with arguments {"pdu_session_id":1}
    Then the call is refused with code -32000
    And the error data code is "AMBIGUOUS_SESSION"
    And the error data pdu_session_id is 1
    And the UPF admin mock received no request

  # ---- Error path: N4 inconsistencies ----------------------------------------------------

  Scenario: n4_session_get returns N4_SESSION_NOT_FOUND with the SMF view when the SMF session has no PFCP session at the UPF
    Given the UPF admin mock holds no sessions
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call is refused with code -32000
    And the error data code is "N4_SESSION_NOT_FOUND"
    And the error data carries the SMF view with seid 9
    And the error data seid is 9

  Scenario: n4_session_get returns AMBIGUOUS_N4_SESSION when the UPF returns more than one session for the query
    Given the UPF admin mock holds a session with cp_seid 9, up_seid 9, ul_teid 4097, ue_ipv4 "10.60.0.2" and qers [{qer_id 1, has_mbr true, mbr_ul_kbps 100000, mbr_dl_kbps 100000, gate_ul OPEN, gate_dl OPEN}, {qer_id 2, qfi 1, has_mbr false, gate_ul OPEN, gate_dl OPEN}]
    And the UPF admin mock also holds a session with cp_seid 10, up_seid 10 and ue_ipv4 "10.60.0.2"
    When I call "n4_session_get" with arguments {"ue_ip":"10.60.0.2"}
    Then the call is refused with code -32000
    And the error data code is "AMBIGUOUS_N4_SESSION"
    And the error data seids are [9,10]

  Scenario: n4_session_get returns CONTEXT_NOT_FOUND with the UPF view for a UPF session that has no SMF session (orphan)
    Given the UPF admin mock holds a session with cp_seid 77, up_seid 77, ul_teid 5000, ue_ipv4 "10.60.0.9" and qers [{qer_id 1, has_mbr false, gate_ul OPEN, gate_dl OPEN}]
    And the SMF mock holds no session with seid 77
    When I call "n4_session_get" with arguments {"seid":77}
    Then the call is refused with code -32000
    And the error data code is "CONTEXT_NOT_FOUND"
    And the error data seid is 77
    And the error data carries the UPF view with cp_seid 77

  Scenario: n4_session_get returns N4_SESSION_NOT_FOUND with a null SMF view when neither the UPF nor the SMF holds the seid
    Given the UPF admin mock holds no sessions
    And the SMF mock holds no session with seid 4242
    When I call "n4_session_get" with arguments {"seid":4242}
    Then the call is refused with code -32000
    And the error data code is "N4_SESSION_NOT_FOUND"
    And the error data seid is 4242
    And the error data smf is null

  # ---- Error path: upstream failures -----------------------------------------------------

  Scenario: n4_session_get reports an upstream error naming prometheus when the UPF target cannot be resolved
    Given the Prometheus mock has no target for nf "upf"
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call is refused with code -32000
    And the error data upstream is "prometheus"
    And the UPF admin mock received no request

  Scenario: n4_session_get reports an upstream error naming the UPF when the UPF admin endpoint is unreachable
    Given the UPF admin mock is shut down
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call is refused with code -32000
    And the error data upstream is "upf"

  # ---- Rejection: argument validation (-32602, rejected before any I/O) -------------------

  Scenario: n4_session_get without any lookup argument is rejected with -32602
    When I call "n4_session_get" with arguments {}
    Then the call is refused with code -32602
    And the SMF mock received no request
    And the UPF admin mock received no request

  Scenario: n4_session_get with supi only is rejected with -32602 because the SMF endpoint is keyed by PDU session id
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001"}
    Then the call is refused with code -32602
    And the SMF mock received no request

  Scenario: n4_session_get mixing a PDU-session-id lookup with a seid lookup is rejected with -32602 (D1)
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1,"seid":9}
    Then the call is refused with code -32602
    And the SMF mock received no request
    And the UPF admin mock received no request

  Scenario: n4_session_get mixing a PDU-session-id lookup with a ue_ip lookup is rejected with -32602 (D1)
    When I call "n4_session_get" with arguments {"pdu_session_id":1,"ue_ip":"10.60.0.2"}
    Then the call is refused with code -32602
    And the SMF mock received no request
    And the UPF admin mock received no request

  Scenario: n4_session_get with pdu_session_id 16 is rejected with -32602 because a PDU Session ID is 1..15
    When I call "n4_session_get" with arguments {"pdu_session_id":16}
    Then the call is refused with code -32602
    And the SMF mock received no request

  Scenario: n4_session_get with a ue_ip that is not an IP literal is rejected with -32602
    When I call "n4_session_get" with arguments {"ue_ip":"not-an-ip"}
    Then the call is refused with code -32602
    And the UPF admin mock received no request

  # ---- Registry: READ_ONLY, visible in every access mode ---------------------------------

  Scenario: n4_session_get is READ_ONLY and is listed in tools/list in read-only access mode
    Given the MCP guard runs with access_mode "read-only"
    When I list the tools
    Then the tool list contains "n4_session_get"
    And the tool "n4_session_get" has risk "READ_ONLY"

  Scenario: n4_session_get needs no confirm and leaves no audit entry
    When I call "n4_session_get" with arguments {"seid":4242}
    Then the call is not a dry run
    And the audit log has no entry for "n4_session_get"

  # ---- Live E2E (manual): mirrors the MCP-012 live acceptance criterion -------------------

  @e2e @manual
  Scenario: Live - Session-AMBR change reaches the UPF QER 1 and is reverted (S1 PSI 1)
    Given the live stack is up with UE "imsi-001010000000001" holding PDU session 1
    When I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the call succeeds
    And the result upf has exactly 2 qers
    And the result smf_mismatches is an empty array
    When I record the current Session-AMBR of the slice of the UE
    And I call "slice_session_ambr_set" for that slice and DNN with downlink "30 Mbps", apply_to_active true and confirm true
    And I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the UPF qer 1 mbr_dl_kbps is 30000
    And the result smf_mismatches is an empty array
    When I call "slice_session_ambr_set" with the recorded Session-AMBR, apply_to_active true and confirm true
    And I call "n4_session_get" with arguments {"supi":"imsi-001010000000001","pdu_session_id":1}
    Then the UPF qer 1 mbr_dl_kbps equals the recorded value
    And the result smf_mismatches is an empty array
    And the procedure_summary shows zero failures for the run
