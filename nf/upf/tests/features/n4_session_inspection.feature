# UPF N4 session inspection: read-only admin view over the PFCP SessionTable (task MCP-012, UPF side)
#
# Design contract: docs/procedures/n4-session-inspection.md (sections 4.1-4.3, 5.1, 7.1-7.4).
# Step definitions live in n4_session_inspection_steps_test.go (build tag `functional`;
# run with `make -C nf/upf test-functional`).
#
# This is an O&M / admin read path, not a 3GPP procedure: no PFCP message is sent by the endpoint.
# The data it shows is the PFCP session state installed by the SMF.
#
# Spec refs: TS 29.244 §5.2 (Packet Forwarding Model), §5.2.1A (PDR handling), §5.2.2 (URR handling),
#            TS 29.244 §5.2.5 (QER handling),
#            TS 29.244 §7.5.2 (PFCP Session Establishment Request), §7.5.2.2 (Create PDR),
#            TS 29.244 §7.5.2.4 (Create URR), §7.5.2.5 (Create QER), §7.5.4.5 (Update QER),
#            TS 29.244 §7.5.6 (PFCP Session Deletion Request),
#            TS 29.244 §8.2.7 (Gate Status), §8.2.8 (MBR, kbps), §8.2.89 (QFI),
#            TS 29.244 §8.2.37 (F-SEID), §8.2.62 (UE IP Address), §8.2.3 (F-TEID),
#            TS 23.501 §5.8.2.2.2 (IPv6 prefix: a /64 per session, matched by prefix).
#
# Harness contract for the godog suite (in-process, no real network except loopback):
#   - PFCP: sessions are created with real PFCP Session Establishment / Modification / Deletion
#     messages over loopback UDP against an in-process pfcp.Server (same as ambr_enforcement_steps_test.go),
#     or inserted with SessionTable.Add where a scenario says "inserted directly".
#   - Admin endpoint: the admin handler (admin.NewN4SessionsHandler) is wrapped in an httptest.Server and
#     queried with GET /admin/v1/n4-sessions[?seid=][&ue_ip=]. The handler reads the same SessionTable
#     instance the PFCP server writes.
#   - Metrics server scenarios use metrics.MetricsServerWithAdmin on an httptest-style listener.
#   - Scenarios tagged @e2e @manual need the live UERANSIM stack and are gated by E2E_TEST=1
#     (reported pending/skipped when unset).
#   - Fixture session "S": CP SEID 0x9, UP SEID 0x9 (this UPF uses UP SEID = CP SEID), UE IPv4 10.60.0.7,
#     DNN "internet", UL TEID 0x1001, DL TEID 0x2002, gNB N3 IP 172.30.3.10,
#     PDR 1 (Source Interface ACCESS, QER IDs 1,2), QER 1 (Session-AMBR: MBR 8000/8000 kbps, no QFI),
#     QER 2 (QFI 1, no MBR), both gates OPEN.

@MCP-012
Feature: UPF read-only N4 session admin view
  As an operator or the MCP n4_session_get tool
  I want to read what the UPF actually holds for each PFCP session
  So that I can prove an SMF change (e.g. a Session-AMBR update) reached the UPF QERs

  Background:
    Given a UPF PFCP server with an empty SessionTable
    And the N4 session admin endpoint "/admin/v1/n4-sessions" is served over HTTP from the same SessionTable

  # ---- Happy path: view of an established session (TS 29.244 §5.2, §7.5.2.2, §7.5.2.5) ----

  @happy
  Scenario: Unfiltered GET lists an established session with both QERs, gates OPEN, PDR to QER lists, SEIDs, TEIDs, UE IPv4 and DNN
    # TS 29.244 §7.5.2.5: QER 1 carries the Session-AMBR (MBR, no QFI); QER 2 carries the QFI (no MBR)
    # TS 29.244 §7.5.2.2: PDR 1 lists QER IDs 1 and 2
    Given the SMF has established PFCP session "S" with
      | rule       | id | gate_ul | gate_dl | mbr_ul_kbps | mbr_dl_kbps | qfi    | pdr_qer_ids |
      | Create PDR | 1  |         |         |             |             |        | 1,2         |
      | Create QER | 1  | OPEN    | OPEN    | 8000        | 8000        | absent |             |
      | Create QER | 2  | OPEN    | OPEN    | absent      | absent      | 1      |             |
    When the client sends GET "/admin/v1/n4-sessions"
    Then the response status is 200 and Content-Type is "application/json"
    And the response has count 1 and 1 element in "sessions"
    And the session has cp_seid 9 and up_seid 9 and ue_ipv4 "10.60.0.7" and dnn "internet"
    And the session has ul_teid 0x1001
    And the session lists 2 QERs sorted by qer_id
    And QER 1 has has_mbr true and mbr_ul_kbps 8000 and mbr_dl_kbps 8000 and no qfi
    And QER 2 has qfi 1 and has_mbr false
    And QER 1 and QER 2 have gate_ul "OPEN" and gate_dl "OPEN"
    And PDR 1 has source_interface "ACCESS" and qer_ids 1,2 in that order

  @happy
  Scenario: DL TEID and gNB N3 address appear after the SMF sets the downlink tunnel with Update FAR
    # TS 29.244 §7.5.4.3 / §8.2.56: Outer Header Creation (TEID + IPv4) learned in Session Modification
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    And the SMF sends a PFCP Session Modification Request with Update FAR Outer Header Creation TEID 0x2002 and gNB address "172.30.3.10"
    When the client sends GET "/admin/v1/n4-sessions"
    Then the response status is 200
    And the session has dl_teid 0x2002 and gnb_n3_ip "172.30.3.10"

  @happy
  Scenario: Session without a delegated IPv6 prefix omits ue_ipv6
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the client sends GET "/admin/v1/n4-sessions"
    Then the session has no field "ue_ipv6"

  @happy
  Scenario: URR configuration is reported when a Create URR was installed
    # TS 29.244 §7.5.2.4 Create URR; §8.2.13 Volume Threshold, §8.2.41 Reporting Triggers (VOLTH)
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2 and URR 1 with Measurement Method VOLUM and Reporting Triggers VOLTH and Volume Threshold 1000000 bytes
    When the client sends GET "/admin/v1/n4-sessions"
    Then the session urr has installed true and urr_id 1 and measure_volume true and trigger_volth true
    And the session urr has volume_threshold_bytes 1000000

  @happy
  Scenario: Sessions are returned sorted by up_seid ascending
    Given sessions with UP SEID 0x30, 0x10 and 0x20 were inserted directly into the SessionTable
    When the client sends GET "/admin/v1/n4-sessions"
    Then the response has count 3
    And the sessions are listed in the order of up_seid 16, 32, 48

  # ---- Update QER is reflected (TS 29.244 §7.5.4.5) ----

  @happy
  Scenario: Update QER MBR change is reflected on the next GET
    # Mirrors the live acceptance step: slice_session_ambr_set apply_to_active 30 Mbps -> QER 1 mbr_dl_kbps 30000
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    And the client sent GET "/admin/v1/n4-sessions" and saw QER 1 with mbr_dl_kbps 8000
    When the SMF sends a PFCP Session Modification Request with Update QER 1 MBR 8000 kbps UL and 30000 kbps DL and no QFI
    Then the PFCP Session Modification Response has Cause 1 "Request accepted"
    When the client sends GET "/admin/v1/n4-sessions"
    Then QER 1 has mbr_ul_kbps 8000 and mbr_dl_kbps 30000
    And QER 2 has qfi 1 and has_mbr false

  @happy
  Scenario: Update QER Gate Status CLOSED is reflected as gate "CLOSED"
    # TS 29.244 §8.2.7
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the SMF sends a PFCP Session Modification Request with Update QER 2 Gate Status UL CLOSED DL OPEN
    And the client sends GET "/admin/v1/n4-sessions"
    Then QER 2 has gate_ul "CLOSED" and gate_dl "OPEN"
    And QER 1 has gate_ul "OPEN" and gate_dl "OPEN"

  @happy
  Scenario: A Gate Status spare value is reported as CLOSED
    # TS 29.244 §8.2.7: spare values 2 and 3 are interpreted as CLOSED (normalised at parse time)
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the SMF sends a PFCP Session Modification Request with Update QER 2 Gate Status octet with spare UL value 2 and DL OPEN
    And the client sends GET "/admin/v1/n4-sessions"
    Then QER 2 has gate_ul "CLOSED" and gate_dl "OPEN"

  # ---- Filters (design section 4.1) ----

  @happy
  Scenario Outline: Filter by seid matches the session, decimal or 0x-hex
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    And a second PFCP session with SEID 0x77 and UE IPv4 "10.60.0.8" exists
    When the client sends GET "/admin/v1/n4-sessions?seid=<seid>"
    Then the response status is 200
    And the response has count 1
    And the session has cp_seid 9

    Examples:
      | seid |
      | 9    |
      | 0x9  |
      | 0X9  |

  @happy
  Scenario: Filter by seid matches the UP SEID as well as the CP SEID
    # Design 4.1: matches either; here the CP and UP SEIDs differ (session inserted directly)
    Given a session with CP SEID 0x100 and UP SEID 0x200 was inserted directly into the SessionTable
    When the client sends GET "/admin/v1/n4-sessions?seid=0x100"
    Then the response has count 1 and the session has cp_seid 256 and up_seid 512
    When the client sends GET "/admin/v1/n4-sessions?seid=512"
    Then the response has count 1 and the session has cp_seid 256 and up_seid 512

  @happy
  Scenario: Filter by ue_ip with an IPv4 address matches exactly
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    And a second PFCP session with SEID 0x77 and UE IPv4 "10.60.0.8" exists
    When the client sends GET "/admin/v1/n4-sessions?ue_ip=10.60.0.8"
    Then the response has count 1
    And the session has cp_seid 119 and ue_ipv4 "10.60.0.8"

  @happy
  Scenario: Filter by ue_ip with an IPv6 address inside the delegated /64 matches the session
    # TS 23.501 §5.8.2.2.2: the UE forms its own IID, so match by the session's /64 (same rule as the DL fast path)
    Given a session with SEID 0x55 and delegated UE IPv6 "2001:db8:60:1::1" was inserted directly into the SessionTable
    When the client sends GET "/admin/v1/n4-sessions?ue_ip=2001:db8:60:1:aaaa:bbbb:cccc:dddd"
    Then the response has count 1
    And the session has cp_seid 85 and ue_ipv6 "2001:db8:60:1::1"

  @happy
  Scenario: Filter by ue_ip with an IPv6 address outside the delegated /64 returns count 0
    Given a session with SEID 0x55 and delegated UE IPv6 "2001:db8:60:1::1" was inserted directly into the SessionTable
    When the client sends GET "/admin/v1/n4-sessions?ue_ip=2001:db8:60:2::1"
    Then the response status is 200
    And the response has count 0 and "sessions" is an empty JSON array

  @happy
  Scenario: seid and ue_ip filters are AND-combined
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    And a second PFCP session with SEID 0x77 and UE IPv4 "10.60.0.8" exists
    When the client sends GET "/admin/v1/n4-sessions?seid=9&ue_ip=10.60.0.8"
    Then the response status is 200
    And the response has count 0 and "sessions" is an empty JSON array
    When the client sends GET "/admin/v1/n4-sessions?seid=9&ue_ip=10.60.0.7"
    Then the response has count 1

  @happy
  Scenario Outline: A valid filter that matches nothing returns 200 with count 0 and an empty array
    # Design 5.1: not an error, and never "sessions": null
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the client sends GET "/admin/v1/n4-sessions?<query>"
    Then the response status is 200
    And the response has count 0 and "sessions" is an empty JSON array

    Examples:
      | query            |
      | seid=999         |
      | seid=0xffff      |
      | ue_ip=10.60.0.99 |

  @happy
  Scenario: Empty SessionTable returns count 0 and an empty array
    When the client sends GET "/admin/v1/n4-sessions"
    Then the response status is 200
    And the response has count 0 and "sessions" is an empty JSON array

  @happy
  Scenario: seid 0 means any session
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the client sends GET "/admin/v1/n4-sessions?seid=0"
    Then the response has count 1

  # ---- Session lifecycle ----

  @happy
  Scenario: A session deleted with PFCP Session Deletion is no longer listed
    # TS 29.244 §7.5.6
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the SMF sends a PFCP Session Deletion Request
    Then the PFCP Session Deletion Response has Cause 1 "Request accepted"
    When the client sends GET "/admin/v1/n4-sessions"
    Then the response has count 0 and "sessions" is an empty JSON array
    When the client sends GET "/admin/v1/n4-sessions?seid=9"
    Then the response has count 0

  # ---- Deep copy and concurrency (design 7.1, 7.2) ----

  @happy
  Scenario: Mutating the returned description does not change the live session
    # Design 7.1 deep-copy rule: no aliasing of IPs, QER ID slices or maps
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When SessionTable.Describe is called and the returned QER IDs, QER list, PDR list and address strings are modified
    And SessionTable.Describe is called again
    Then the second description equals the first original description
    And the live session still stores QER 1 with MBR UL 8000 kbps and MBR DL 8000 kbps and no QFI
    And PDR 1 still references QER IDs 1 and 2 in that order

  @happy
  Scenario: A later live change does not alter a description already taken
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    And SessionTable.Describe was called and the result kept
    When the SMF sends a PFCP Session Modification Request with Update QER 1 MBR 4000 kbps UL and 4000 kbps DL and no QFI
    Then the kept description still shows QER 1 with mbr_ul_kbps 8000 and mbr_dl_kbps 8000

  @happy
  Scenario: URR volume and packet counters are reported from the live atomics
    # Counters are cumulative since establishment (not since the last report); read with atomic Load
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2 and URR 1 with Measurement Method VOLUM
    And 3 uplink packets totalling 3000 bytes and 2 downlink packets totalling 1200 bytes were accounted to the session
    When the client sends GET "/admin/v1/n4-sessions"
    Then the session urr has ul_volume_bytes 3000 and ul_packets 3
    And the session urr has dl_volume_bytes 1200 and dl_packets 2

  @happy
  Scenario: Describe does not race with concurrent datapath counters and session store or delete
    # Run under -race; design 7.2
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2 and URR 1 with Measurement Method VOLUM
    When 4 goroutines account URR volume and 2 goroutines store and delete other sessions while Describe is called 200 times
    Then every Describe call returns without error and without a data race

  @happy
  Scenario: The admin view sends no PFCP message
    # Design 1 and 9: read-only, no N4 traffic
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    And the count of PFCP messages sent by the UPF is recorded
    When the client sends GET "/admin/v1/n4-sessions"
    Then the UPF sent no PFCP message since the count was recorded

  # ---- Spec-deviation / invalid request rejections (design 5.1) ----

  @rejection
  Scenario Outline: An unparsable seid is rejected with 400 problem+json INVALID_QUERY_PARAM
    # Base 0 parsing is forbidden: "010", "0o7" and "0b1" are not accepted forms
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the client sends GET "/admin/v1/n4-sessions?seid=<seid>"
    Then the response status is 400 and Content-Type is "application/problem+json"
    And the problem cause is "INVALID_QUERY_PARAM"
    And the problem invalidParams contains param "seid"
    And SessionTable.Describe was not called

    Examples:
      | seid                 |
      | xyz                  |
      | -1                   |
      | 0xZZ                 |
      | 0x                   |
      | 0o7                  |
      | 0b1                  |
      | 1.5                  |
      | 18446744073709551616 |
      | 0x10000000000000000  |

  @rejection
  Scenario Outline: An unparsable ue_ip is rejected with 400 problem+json INVALID_QUERY_PARAM
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the client sends GET "/admin/v1/n4-sessions?ue_ip=<ue_ip>"
    Then the response status is 400 and Content-Type is "application/problem+json"
    And the problem cause is "INVALID_QUERY_PARAM"
    And the problem invalidParams contains param "ue_ip"
    And SessionTable.Describe was not called

    Examples:
      | ue_ip           |
      | not-an-ip       |
      | 10.60.0        |
      | 10.60.0.256     |
      | 2001:db8::zz    |
      | 10.60.0.0/24    |

  @rejection
  Scenario Outline: A method other than GET is rejected with 405 and Allow GET
    # Produced by the handler (method-less ServeMux pattern), so HEAD is rejected too
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the client sends <method> "/admin/v1/n4-sessions"
    Then the response status is 405
    And the response header "Allow" is "GET"
    And SessionTable.Describe was not called
    And the live SessionTable still holds 1 session

    Examples:
      | method |
      | POST   |
      | PUT    |
      | DELETE |
      | PATCH  |
      | HEAD   |

  @rejection
  Scenario: Unknown path under /admin/ is answered 404 by the server mux
    When the client sends GET "/admin/v1/n4-sessions/does-not-exist"
    Then the response status is 404

  @error
  Scenario: The request body of a GET is ignored
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the client sends GET "/admin/v1/n4-sessions" with a JSON body "{\"seid\": 12345}"
    Then the response status is 200
    And the response has count 1

  # ---- Observability (design 7.3) ----

  @happy
  Scenario: A successful request is logged with the canonical N4SessionInspection fields
    Given the SMF has established PFCP session "S" with the Session-AMBR QER 1 and the flow QER 2
    When the client sends GET "/admin/v1/n4-sessions?seid=9" with header "X-Correlation-Id" "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    Then the UPF logs a line with procedure "N4SessionInspection", interface "OAM", direction "IN" and spec_ref "TS 29.244 §5.2"
    And that log line carries result "OK", count 1, seid "9" and correlation_id "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    And that log line carries the "nf" key exactly once

  @rejection
  Scenario: A rejected request is logged with result REJECT and the cause
    When the client sends GET "/admin/v1/n4-sessions?seid=xyz"
    Then the UPF logs a line with procedure "N4SessionInspection", interface "OAM" and direction "IN"
    And that log line carries result "REJECT" and cause "INVALID_QUERY_PARAM"

  # ---- Metrics server: admin route plumbing (design 7.4) ----

  @happy
  Scenario: An /admin/ route is mounted alongside /metrics and /admin/v1/log-level
    Given a metrics server built with MetricsServerWithAdmin and the admin route "/admin/v1/n4-sessions"
    When the client sends GET "/metrics"
    Then the response status is 200
    When the client sends GET "/admin/v1/log-level"
    Then the response status is 200
    When the client sends GET "/admin/v1/n4-sessions"
    Then the response status is 200
    And the response has count 0 and "sessions" is an empty JSON array

  @rejection
  Scenario: A route outside /admin/ is ignored and not mounted
    Given a metrics server built with MetricsServerWithAdmin and the admin route "/internal/n4-sessions"
    When the client sends GET "/internal/n4-sessions"
    Then the response status is 404
    And building the server did not panic

  @rejection
  Scenario: A duplicate admin route is ignored without a panic
    Given a metrics server built with MetricsServerWithAdmin and the admin routes "/admin/v1/n4-sessions" twice
    Then building the server did not panic
    When the client sends GET "/admin/v1/n4-sessions"
    Then the response status is 200

  @rejection
  Scenario: A route that would shadow /admin/v1/log-level is ignored
    Given a metrics server built with MetricsServerWithAdmin and the admin route "/admin/v1/log-level" with a custom handler
    When the client sends GET "/admin/v1/log-level"
    Then the response is served by the original log-level handler
    And building the server did not panic

  @rejection
  Scenario: A route with a nil handler is ignored without a panic
    Given a metrics server built with MetricsServerWithAdmin and the admin route "/admin/v1/n4-sessions" with a nil handler
    Then building the server did not panic
    When the client sends GET "/admin/v1/n4-sessions"
    Then the response status is 404

  @happy
  Scenario: MetricsServerWithAdmin without extra routes behaves as before
    # Source compatibility: existing two-argument callers and MetricsServer(addr) are unchanged
    Given a metrics server built with MetricsServerWithAdmin and no admin routes
    When the client sends GET "/metrics"
    Then the response status is 200
    When the client sends GET "/healthz"
    Then the response status is 200

  # ---- Live acceptance criteria (manual; needs `make ueransim`) ----

  @e2e @manual
  Scenario: The running UPF lists one N4 session per active PDU session
    # Acceptance criterion 3 (UPF half); design section 8 live step 1
    Given E2E_TEST is set to "1" and the UERANSIM stack is up with one UE holding PDU session 1
    When GET "http://upf:9107/admin/v1/n4-sessions" is requested
    Then the response status is 200
    And the response count equals the number of active PDU sessions reported by "ueransim_status"
    And each session lists 2 QERs: QER 1 with has_mbr true and no qfi, QER 2 with qfi 1 and has_mbr false
    And every QER has gate_ul "OPEN" and gate_dl "OPEN"
    And the UPF log shows procedure "N4SessionInspection" with result "OK" and a single "nf" key
    And "procedure_summary" reports zero failures for the run

  @e2e @manual
  Scenario: A live Session-AMBR change applied to active sessions is visible in the UPF QER and then reverted
    # Acceptance criterion 3: slice_session_ambr_set apply_to_active 30 Mbps -> QER mbr_dl_kbps 30000, then reverted
    Given E2E_TEST is set to "1" and the UERANSIM stack is up with one UE holding PDU session 1
    And the current Session-AMBR of the slice and the UPF QER 1 mbr_dl_kbps were recorded
    When the Session-AMBR downlink is set to "30 Mbps" with apply_to_active
    Then GET "http://upf:9107/admin/v1/n4-sessions" shows QER 1 with mbr_dl_kbps 30000
    When the Session-AMBR is reverted to the recorded value with apply_to_active
    Then GET "http://upf:9107/admin/v1/n4-sessions" shows QER 1 with the originally recorded mbr_dl_kbps
