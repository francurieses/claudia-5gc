@mcp_roaming
Feature: MCP roaming_status reports the N32 roaming state, roaming UEs and home-routed sessions (read-only)
  As an operator debugging roaming through an LLM client
  I want roaming_status to join the portal, Prometheus, AMF and SMF views in one snapshot
  So that the N32 link, the partner contexts, the TLS rejects and the roaming UEs are visible without a PCAP
  # Refs: TS 29.573 §5.2.2 (N32-c Security Capability Negotiation), §5.3.3 (N32-f forwarding in TLS mode),
  # TS 33.501 §13.1.2 (N32 TLS, SEPP-SEPP PLMN checks), TS 23.501 §4.2.4 (roaming architecture),
  # TS 23.502 §4.3.2.2.2 (home-routed PDU Session), TS 23.003 §2.2 (IMSI = MCC+MNC+MSIN).
  # Design contract: docs/procedures/RoamingStatus.md (§4 output fields, §5 degradation D1-D9).
  # Read-only: no N32 or SBI signalling and no state change at any NF.

  Background:
    Given the MCP roaming status tool runs against mocked portal, Prometheus, AMF and SMF upstreams
    And the MCP guard runs with access_mode "viewer"
    And the portal mock reports roaming deployed with link state "UP", local_plmn "001/001" and partner_plmn "001/002"
    And the portal mock reports for SEPP "sepp" an n32 partner "001/002" with state "ESTABLISHED"
    And the Prometheus mock holds fivegc_sepp_n32c_context_established 1 for role "sepp" and peer_plmn "001/002"
    And the Prometheus mock holds fivegc_sepp_n32c_context_established 1 for role "hsepp" and peer_plmn "001/001"
    And the Prometheus mock holds fivegc_sepp_n32c_handshake_total result "ok" 3 and result "reject" 1 for role "sepp" and peer_plmn "001/002"
    And the Prometheus mock holds fivegc_sepp_n32f_messages_total direction "out" result "ok" 7, direction "in" result "ok" 5 and direction "in" result "reject" 2 for role "sepp" and peer_plmn "001/002"
    And the Prometheus mock holds fivegc_sepp_n32_tls_reject_total reason "not_partner" 2 for role "sepp"
    And the AMF mock holds UEs "imsi-001010000000001" and "imsi-001020000000007"
    And the SMF mock holds a session for "imsi-001020000000007" with pdu_session_id 1, dnn "internet" and ue_ip "10.60.0.9"

  # ---- Happy path ----------------------------------------------------------------------

  Scenario: roaming_status joins link, partner context, counters, roaming UE and home-routed session when every source is up
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result field "deployed" is true
    And the result field "local_plmn" is "001-001"
    And the result field "link.state" is "UP"
    And the result field "partners[0].plmn" is "001-002"
    And the result partner "001-002" on sepp "sepp" has context_state "ESTABLISHED" and context_established true
    And the result partner "001-002" on sepp "hsepp" has context_established true
    And the result partner "001-002" on sepp "sepp" has handshakes ok 3, reject 1, failure 0
    And the result partner "001-002" on sepp "sepp" has n32f out_ok 7, in_ok 5, reject 2, failure 0
    And the result field "tls_rejects.sepp.not_partner" is 2
    And the result field "roaming_ues.available" is true
    And the result field "roaming_ues.count" is 1
    And the result field "roaming_ues.ues[0].supi" is "imsi-001020000000007"
    And the result field "roaming_ues.ues[0].home_plmn" is "001-002"
    And the result field "home_routed_sessions.available" is true
    And the result field "home_routed_sessions.count" is 1
    And the result field "home_routed_sessions.sessions[0].supi" is "imsi-001020000000007"
    And the result field "home_routed_sessions.note" is not empty
    And the result field "sources.portal" is "ok"
    And the result field "sources.prometheus" is "ok"
    And the result field "sources.amf" is "ok"
    And the result field "sources.smf" is "ok"

  Scenario: the Prometheus peer_plmn label "001/002" is normalised to "001-002" and the values other and unknown are not partners
    Given the Prometheus mock also holds fivegc_sepp_n32f_messages_total for role "sepp" and peer_plmn "other" and peer_plmn "unknown"
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result partners contain exactly the plmns "001-002"

  # ---- partner_plmn filter and input validation (D1, D9) -------------------------------

  Scenario: partner_plmn "001-002" selects only that partner and its roamers
    Given the Prometheus mock also holds fivegc_sepp_n32c_context_established 1 for role "sepp" and peer_plmn "001/003"
    When I call "roaming_status" with arguments {"partner_plmn":"001-002"}
    Then the call succeeds
    And the result partners contain exactly the plmns "001-002"
    And the result field "roaming_ues.count" is 1

  Scenario: partner_plmn "001-02" is compared after padding the MNC to 3 digits
    When I call "roaming_status" with arguments {"partner_plmn":"001-02"}
    Then the call succeeds
    And the result partners contain exactly the plmns "001-002"

  Scenario: partner_plmn unknown to every source returns empty partners and zero counts
    When I call "roaming_status" with arguments {"partner_plmn":"999-99"}
    Then the call succeeds
    And the result partners is an empty array
    And the result field "roaming_ues.count" is 0
    And the result field "home_routed_sessions.count" is 0

  Scenario Outline: partner_plmn that fails ^\d{3}-\d{2,3}$ is rejected as invalid params before any source is called
    When I call "roaming_status" with arguments {"partner_plmn":"<value>"}
    Then the call fails with an invalid-params error
    And the portal mock, the Prometheus mock, the AMF mock and the SMF mock received no request

    Examples:
      | value  |
      | 1-2    |
      | abc    |
      | 001/02 |
      | 001-2  |

  # ---- No roaming deployed (D4) --------------------------------------------------------

  Scenario: no SEPP series and portal NOT_DEPLOYED is a success with deployed false and no error
    Given the portal mock reports roaming not deployed with link state "NOT_DEPLOYED"
    And the Prometheus mock holds no fivegc_sepp series
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result field "deployed" is false
    And the result field "message" contains "roaming profile"
    And the result field "message" contains "--profile roaming"

  # ---- Degradation (D2, D3, D5, D6, D7, D8) --------------------------------------------

  Scenario: portal down still succeeds with the portal source error and Prometheus counters present
    Given the portal mock is unreachable
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result field "sources.portal" is an error string
    And the result field "link.state" is empty
    And the result partner "001-002" on sepp "sepp" has no context_state
    And the result partner "001-002" on sepp "sepp" has context_established true
    And the result partner "001-002" on sepp "sepp" has handshakes ok 3, reject 1, failure 0
    And the result field "tls_rejects.sepp.not_partner" is 2

  Scenario: Prometheus down still succeeds with counters unavailable and portal state present
    Given the Prometheus mock is unreachable
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result field "sources.prometheus" is an error string
    And the result field "link.state" is "UP"
    And the result partner "001-002" on sepp "sepp" has context_state "ESTABLISHED"
    And the result partner "001-002" on sepp "sepp" has no context_established
    And the result partner "001-002" on sepp "sepp" has no handshakes
    And the result has no "tls_rejects" entries

  Scenario: portal and Prometheus both down still succeeds with every SEPP block unavailable
    Given the portal mock is unreachable
    And the Prometheus mock is unreachable
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result field "sources.portal" is an error string
    And the result field "sources.prometheus" is an error string
    And the result partners is an empty array
    And the result field "deployed" is false
    And the result field "message" contains "unreachable"

  Scenario: AMF unreachable marks roaming_ues unavailable, home_routed_sessions still come from the SMF, and leaves the other blocks intact
    Given the AMF mock is unreachable
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result field "roaming_ues.available" is false
    And the result field "roaming_ues.error" is not empty
    And the result field "home_routed_sessions.available" is true
    And the result field "home_routed_sessions.count" is 1
    And the result field "sources.amf" is an error string
    And the result field "link.state" is "UP"
    And the result partner "001-002" on sepp "sepp" has context_established true
    And the result field "sources.smf" is "ok"

  Scenario: SMF unreachable marks home_routed_sessions unavailable and leaves roaming_ues intact
    Given the SMF mock is unreachable
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result field "home_routed_sessions.available" is false
    And the result field "home_routed_sessions.error" is not empty
    And the result field "sources.smf" is an error string
    And the result field "roaming_ues.available" is true
    And the result field "roaming_ues.count" is 1

  Scenario: local PLMN unknown makes roaming_ues and home_routed_sessions unavailable with the reason
    Given the portal mock is unreachable
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And the result field "local_plmn" is empty
    And the result field "roaming_ues.available" is false
    And the result field "roaming_ues.error" is "local PLMN unknown"
    And the result field "home_routed_sessions.available" is false
    And the result field "home_routed_sessions.error" is "local PLMN unknown"

  # ---- Read-only guard -----------------------------------------------------------------

  Scenario: roaming_status is READ_ONLY, needs no confirmation and is listed in the viewer access mode
    When I list the tools for access_mode "viewer"
    Then the tool "roaming_status" is listed
    And the tool "roaming_status" has risk "READ_ONLY"
    When I call "roaming_status" with arguments {}
    Then the call succeeds
    And no audit entry is recorded
    And the portal mock, the Prometheus mock, the AMF mock and the SMF mock received no request other than GET
