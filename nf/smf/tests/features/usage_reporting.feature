# PFCP Usage Reporting — SMF consumption of UPF Session Report Requests
# (TS 29.244 §5.2.2.4, §7.5.5 Session Report Request, §7.5.8 Usage Report IE,
#  §7.5.9 Session Report Response, §8.2.44 Usage Report Trigger, §8.2.5 Volume
#  Measurement, §8.2.42 Duration Measurement)
#
# Scope: these scenarios exercise the SMF-side persistent PFCP receiver
# (0.0.0.0:8805) that matches an inbound Session Report Request to a session
# by CP F-SEID, parses the Usage Report (trigger, volume, duration), logs it,
# and answers with a Session Report Response. The UPF's measurement and
# report-emission side (volume counters, threshold arming, periodic timer)
# is covered separately by UPF Go unit tests, not by this feature.

Feature: PFCP Usage Reporting consumption at the SMF
  As the SMF
  I want to consume PFCP Session Report Requests carrying Usage Reports
  So that per-session volume and duration are logged as a prerequisite for charging (TS 32.255)

  Background:
    Given an active PDU session with CP F-SEID "0x1001" and installed URR id 1

  Scenario: Volume-threshold Usage Report is consumed and logged
    When the SMF receives a PFCP Session Report Request for SEID "0x1001" with Usage Report trigger "VOLTH", URR id 1, UR-SEQN 1, Volume Measurement total 524288 bytes UL 400000 DL 124288 bytes, and Duration Measurement 30 seconds
    Then the SMF logs the usage report with total volume 524288 bytes and duration 30 seconds for that session
    And the SMF returns a PFCP Session Report Response with Cause "Request accepted"

  Scenario: Periodic Usage Report is consumed and logged
    When the SMF receives a PFCP Session Report Request for SEID "0x1001" with Usage Report trigger "PERIO", URR id 1, UR-SEQN 2, Volume Measurement total 1048576 bytes UL 800000 DL 248576 bytes, and Duration Measurement 60 seconds
    Then the SMF logs the usage report with total volume 1048576 bytes and duration 60 seconds for that session
    And the SMF returns a PFCP Session Report Response with Cause "Request accepted"

  Scenario: Session Report Request for an unknown SEID is rejected as session not found
    When the SMF receives a PFCP Session Report Request for SEID "0xDEADBEEF" with Usage Report trigger "VOLTH", URR id 1, UR-SEQN 1, Volume Measurement total 100000 bytes UL 60000 DL 40000 bytes, and Duration Measurement 10 seconds
    Then the SMF returns a PFCP Session Report Response with Cause "Session context not found"
    And no new session is created for SEID "0xDEADBEEF"

  Scenario: Usage Report referencing an unknown URR id is handled without a crash
    When the SMF receives a PFCP Session Report Request for SEID "0x1001" with Usage Report trigger "VOLTH", URR id 99, UR-SEQN 1, Volume Measurement total 200000 bytes UL 100000 DL 100000 bytes, and Duration Measurement 5 seconds
    Then the SMF does not panic and returns a well-formed PFCP Session Report Response
    And the SMF logs a warning about the unknown URR id 99 for SEID "0x1001"

  Scenario: Two consecutive Usage Reports for the same session are consumed independently
    When the SMF receives a PFCP Session Report Request for SEID "0x1001" with Usage Report trigger "VOLTH", URR id 1, UR-SEQN 1, Volume Measurement total 300000 bytes UL 200000 DL 100000 bytes, and Duration Measurement 15 seconds
    And the SMF receives a PFCP Session Report Request for SEID "0x1001" with Usage Report trigger "PERIO", URR id 1, UR-SEQN 2, Volume Measurement total 700000 bytes UL 500000 DL 200000 bytes, and Duration Measurement 45 seconds
    Then the SMF logs 2 usage reports for SEID "0x1001"
    And the SMF returns a PFCP Session Report Response with Cause "Request accepted" for each request
