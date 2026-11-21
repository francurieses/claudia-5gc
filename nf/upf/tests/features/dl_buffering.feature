# UPF downlink buffering and Downlink Data Report (SMF-011, UPF side)
# (TS 23.501 §5.8.2.19.2; TS 23.502 §4.2.3.3 step 2a; TS 29.244 §5.2.3.1, §5.2.4.1,
#  §7.5.2.6 Create BAR, §7.5.4.3 Update FAR, §7.5.8 Session Report Request DLDR,
#  §8.2.26 Apply Action)
#
# Design contract: docs/procedures/network-triggered-service-request.md ("UPF buffering rules (SMF-011)").
# Harness (in-process, loopback only): real PFCP Server + GTP-U datapath; a fake SMF PFCP peer on
# loopback UDP records Session Report Requests; DL packets are injected into the TUN-side handler;
# the gNB N3 endpoint is a loopback UDP socket capturing GTP-U. Metrics read from the registry.
# Fixture: session with PDR 2 (Source Interface Core, UE IP 10.60.0.7) -> FAR 1 (DL, BAR ID 1),
# PDR 1 (Access, UL TEID) -> FAR 2 (FORW, Core); DL buffer limit set to 3 packets for the suite.
# Drop-reason label: the procedure doc names reason="buffer_full" for overflow; the task brief
# said "limit". The doc is the contract, so this file asserts "buffer_full" (see report).

Feature: UPF downlink buffering and Downlink Data Report
  As the UPF
  I want to buffer downlink packets of a session whose FAR is BUFF+NOCP and notify the SMF once
  So that no packet is lost while the UE is paged (TS 23.501 §5.8.2.19.2)

  Background:
    Given an in-process UPF with a PFCP server and a fake SMF PFCP peer recording Session Report Requests
    And the UPF DL buffer limit is 3 packets
    And a PFCP session with DL PDR 2 for UE IP 10.60.0.7 referencing FAR 1 with BAR ID 1 and UL PDR 1 referencing FAR 2
    And FAR 1 has Apply Action BUFF+NOCP

  @SMF-011
  Scenario: First DL packet is buffered not dropped and triggers exactly one Session Report Request with DLDR for PDR 2
    When a DL packet "P1" for UE IP 10.60.0.7 arrives from the N6 side
    Then the packet is buffered and not counted as dropped
    And the fake SMF receives exactly one Session Report Request with Report Type DLDR
    And the Downlink Data Report names PDR ID 2
    And the metric "fivegc_upf_dl_buffered_packets_total" is 1

  @SMF-011
  Scenario: Further DL packets in the same buffering period are buffered without another report
    Given a DL packet "P1" for UE IP 10.60.0.7 was buffered and reported
    When DL packets "P2" and "P3" arrive for UE IP 10.60.0.7
    Then the buffer holds "P1", "P2", "P3" in that order
    And the fake SMF has received exactly one Session Report Request in total
    And the metric "fivegc_upf_dl_buffered_packets_total" is 3

  @SMF-011
  Scenario: Buffer limit reached drops the excess packet and increments the drop counter
    Given DL packets "P1", "P2", "P3" are buffered
    When a DL packet "P4" arrives for UE IP 10.60.0.7
    Then "P4" is discarded and the buffer still holds "P1", "P2", "P3" in that order
    And the metric "fivegc_upf_dl_buffer_dropped_total" with reason "buffer_full" is 1
    And the fake SMF has received exactly one Session Report Request in total

  @SMF-011
  Scenario: Update FAR to FORW with Outer Header Creation flushes the buffer in FIFO order, first packet included
    Given DL packets "P1", "P2", "P3" are buffered
    When the SMF sends a PFCP Session Modification Request with Update FAR 1 Apply Action FORW and Outer Header Creation to the gNB N3 tunnel
    Then the gNB tunnel endpoint receives GTP-U packets carrying "P1", "P2", "P3" in that order
    And the buffer is empty
    And "P1" is received first and no buffered packet is dropped

  @SMF-011
  Scenario: A DL packet arriving after the flush is forwarded behind the flushed packets
    Given DL packets "P1", "P2" are buffered
    When the SMF sends a PFCP Session Modification Request with Update FAR 1 Apply Action FORW and Outer Header Creation to the gNB N3 tunnel
    And a DL packet "P3" arrives for UE IP 10.60.0.7
    Then the gNB tunnel endpoint receives GTP-U packets carrying "P1", "P2", "P3" in that order

  @SMF-011
  Scenario: Update FAR to DROP discards the buffer and counts the discarded packets
    Given DL packets "P1", "P2" are buffered
    When the SMF sends a PFCP Session Modification Request with Update FAR 1 Apply Action DROP
    Then the buffer is empty and nothing is forwarded to the gNB tunnel endpoint
    And the metric "fivegc_upf_dl_buffer_dropped_total" with reason "far_drop" is 2

  @SMF-011
  Scenario: PFCP Session Deletion discards the buffer and counts the discarded packets
    Given DL packets "P1", "P2" are buffered
    When the SMF sends a PFCP Session Deletion Request for the session
    Then the buffer is gone and nothing is forwarded to the gNB tunnel endpoint
    And the metric "fivegc_upf_dl_buffer_dropped_total" with reason "session_deleted" is 2

  @SMF-011
  Scenario: SMF rejects the Session Report Request with a Cause other than 1 and the buffer is discarded
    Given the fake SMF answers Session Report Requests with Cause 65 "Session context not found"
    When a DL packet "P1" for UE IP 10.60.0.7 arrives from the N6 side
    Then the buffer is empty
    And the metric "fivegc_upf_dl_buffer_dropped_total" with reason "cp_rejected" is 1

  @SMF-011
  Scenario: BUFF without NOCP buffers silently and sends no Session Report Request
    Given FAR 1 has Apply Action BUFF without NOCP
    When a DL packet "P1" for UE IP 10.60.0.7 arrives from the N6 side
    Then the packet is buffered
    And the fake SMF receives no Session Report Request

  @SMF-011
  Scenario: Buffer metrics are exposed on /metrics
    When the UPF metrics endpoint is scraped
    Then the exposition contains the counter "fivegc_upf_dl_buffered_packets_total"
    And the exposition contains the counter "fivegc_upf_dl_buffer_dropped_total"
    And the gauge "fivegc_upf_dl_buffer_limit_packets" equals 3
