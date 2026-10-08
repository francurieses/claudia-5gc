# PFCP Node-Level Recovery — SMF-initiated Association Setup, Heartbeat and
# UPF-restart detection with release of the affected PDU sessions (SMF-004)
# (TS 29.244 §6.2.2 Heartbeat Procedure, §6.2.6.2 PFCP Association Setup
#  (CP function initiated), §6.4 Reliable Delivery (T1/N1), §7.4.2 Heartbeat
#  Request/Response, §7.4.4 Association Setup Request/Response, §8.2.1 Cause,
#  §8.2.65 Recovery Time Stamp; TS 23.007 §19A PFCP based restart procedures;
#  TS 23.527 §4.2 N4 Failure and Restart Detection, §4.3 UPF restoration;
#  TS 23.502 §4.3.4.2 SMF-requested PDU Session Release)
#
# Scope: these scenarios exercise the SMF-side PFCP node supervisor in-process
# against a fake UPF on a loopback UDP socket and a fake AMF management API
# (httptest) with short T1 / N1 / heartbeat / retry timer overrides. Recovery is
# by RELEASE only (no PFCP session restoration, human decision 2026-10-05).
# The release is driven through the AMF management API
# DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi} (documented deviation from
# Namf_Communication_N1N2MessageTransfer); when it fails the SMF releases the SM
# context locally. The Recovery Time Stamp in Association Setup messages is NOT a
# restart indicator (TS 23.007 §19A): the baseline and detection come from
# Heartbeat Request/Response exchanges only.
# Out of scope: UPF-side Recovery Time Stamp emission (UPF Go unit tests), the
# AMF N1/N2 release legs (AMF tests), and the live E2E
# "SERVICES=upf make services-restart-check" (ping PASS after UPF restart),
# which is run against the UERANSIM stack and is not part of this feature.

Feature: PFCP node-level recovery at the SMF
  As the SMF
  I want to associate with the UPF, supervise it with Heartbeats and detect a UPF restart or failure
  So that PDU sessions lost with the UPF are released and the UE can re-establish a working session (TS 23.527 §4.2, §4.3)

  Background:
    Given a fake UPF PFCP peer listening on a loopback UDP socket with Recovery Time Stamp "T0"
    And a fake AMF management API that accepts PDU session release requests with 202
    And the SMF PFCP node supervisor is configured with the fake UPF as peer and short T1, N1, heartbeat interval and association retry timers
    And the SMF has Recovery Time Stamp "S0"

  Scenario: Association Setup then Heartbeat establishes the UPF Recovery Time Stamp baseline
    When the SMF PFCP node supervisor is started
    Then the fake UPF receives a PFCP Association Setup Request with Node ID and Recovery Time Stamp "S0"
    And the fake UPF answers with a PFCP Association Setup Response with Cause "Request accepted" and Recovery Time Stamp "T0"
    And the fake UPF then receives a PFCP Heartbeat Request carrying Recovery Time Stamp "S0"
    And the fake UPF answers with a PFCP Heartbeat Response carrying Recovery Time Stamp "T0"
    And the SMF PFCP association state is "ASSOCIATED"
    And the SMF tracked UPF Recovery Time Stamp baseline is "T0"
    And the SMF logs procedure "PfcpAssociationSetup" with result "OK" and spec_ref "TS 29.244 §6.2.6.2"

  Scenario: Association Setup is retried until the silent UPF answers
    Given the fake UPF drops the first 2 PFCP Association Setup Requests without answering
    When the SMF PFCP node supervisor is started
    Then the SMF retransmits the PFCP Association Setup Request with the same sequence number after T1, up to N1 retransmissions
    And the SMF logs procedure "PfcpAssociationSetup" with result "FAILURE" and cause "PEER_NOT_RESPONDING"
    And the SMF retries the PFCP Association Setup with backoff and no PFCP Heartbeat Request is sent before the association is accepted
    When the fake UPF starts answering PFCP Association Setup Requests with Cause "Request accepted"
    Then the SMF PFCP association state becomes "ASSOCIATED" within the deadline
    And the SMF sends a PFCP Heartbeat Request immediately after the association is accepted

  Scenario: Association Setup rejected by the UPF is not treated as associated and is retried
    Given the fake UPF answers PFCP Association Setup Requests with Cause "Request rejected"
    When the SMF PFCP node supervisor is started
    Then the SMF PFCP association state stays "SETUP_PENDING"
    And the SMF logs procedure "PfcpAssociationSetup" with result "REJECT" and cause 64
    And the SMF sends no PFCP Heartbeat Request
    And the SMF sends another PFCP Association Setup Request after the retry backoff
    And the SMF increments fivegc_procedure_total for nf "SMF" procedure "PfcpAssociationSetup" with result "REJECT"

  Scenario: Steady Heartbeats with an unchanged Recovery Time Stamp cause no release
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the SMF holds 2 active PDU sessions established on the UPF
    When the fake UPF answers 3 consecutive periodic PFCP Heartbeat Requests with Recovery Time Stamp "T0"
    Then the SMF PFCP association state is "ASSOCIATED"
    And the fake AMF management API receives 0 release requests
    And both PDU sessions remain in state "ACTIVE"
    And the SMF does not log procedure "PfcpNodeLevelRecovery"

  Scenario: UPF restart detected from a changed Recovery Time Stamp releases the affected sessions once
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the SMF holds 2 active PDU sessions "imsi-001010000000001" PSI 1 and "imsi-001010000000002" PSI 1 established on the UPF before Recovery Time Stamp "T1"
    When the fake UPF restarts and answers the next PFCP Heartbeat Request with the newer Recovery Time Stamp "T1"
    Then the SMF logs procedure "PfcpNodeLevelRecovery" with cause "PEER_RESTART", old_rts "T0" and new_rts "T1"
    And the SMF logs spec_ref "TS 23.527 §4.2"
    And the fake AMF management API receives exactly one DELETE "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"
    And the fake AMF management API receives exactly one DELETE "/amf/v1/ue-contexts/imsi-001010000000002/pdu-sessions/1"
    And each release request carries the same X-Correlation-Id header
    And no PFCP Session Deletion Request is sent to the UPF for the released sessions
    And the SMF re-runs PFCP Association Setup with the fake UPF
    And the SMF tracked UPF Recovery Time Stamp baseline becomes "T1" after the next Heartbeat Response
    When the fake UPF answers 2 further PFCP Heartbeat Requests with Recovery Time Stamp "T1"
    Then the fake AMF management API still has exactly one release request per session

  Scenario: Session established after the new UPF Recovery Time Stamp survives the restart detection
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the SMF holds a PDU session "imsi-001010000000001" PSI 1 established on the UPF before Recovery Time Stamp "T1"
    And the SMF holds a PDU session "imsi-001010000000003" PSI 1 established on the UPF at or after Recovery Time Stamp "T1"
    When the fake UPF answers the next PFCP Heartbeat Request with the newer Recovery Time Stamp "T1"
    Then the fake AMF management API receives exactly one DELETE "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"
    And the fake AMF management API receives no release request for "imsi-001010000000003"
    And the PDU session of "imsi-001010000000003" remains in state "ACTIVE"

  Scenario: Heartbeat loss after N1 retransmissions marks the association down and releases all sessions
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the SMF holds 2 active PDU sessions established on the UPF
    When the fake UPF stops answering PFCP Heartbeat Requests
    Then the SMF retransmits the PFCP Heartbeat Request with the same sequence number after T1, N1 times
    And the SMF logs procedure "PfcpNodeLevelRecovery" with cause "PEER_NOT_RESPONDING"
    And the SMF PFCP association state leaves "ASSOCIATED"
    And the fake AMF management API receives exactly one release request for each of the 2 PDU sessions
    And the SMF increments fivegc_procedure_total for nf "SMF" procedure "PfcpHeartbeat" with result "FAILURE"
    And the SMF retries PFCP Association Setup with backoff
    When the fake UPF starts answering again
    Then the SMF PFCP association state becomes "ASSOCIATED" within the deadline

  Scenario: AMF management release failure falls back to local release of the SM context
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the fake AMF management API answers release requests with 404
    And the SMF holds an active PDU session "imsi-001010000000001" PSI 1 with an allocated UE IP established on the UPF before Recovery Time Stamp "T1"
    When the fake UPF answers the next PFCP Heartbeat Request with the newer Recovery Time Stamp "T1"
    Then the fake AMF management API receives exactly one DELETE "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"
    And the SMF releases the SM context locally and the session is removed from the SMF session table
    And the UE IP address is returned to the IP pool
    And the SMF logs procedure "PfcpNodeLevelRecovery" with result "FAILURE" and cause "AMF_RELEASE_FAILED"

  Scenario: AMF management API server error also falls back to local release
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the fake AMF management API answers release requests with 500
    And the SMF holds an active PDU session "imsi-001010000000001" PSI 1 with an allocated UE IP established on the UPF before Recovery Time Stamp "T1"
    When the fake UPF answers the next PFCP Heartbeat Request with the newer Recovery Time Stamp "T1"
    Then the SMF releases the SM context locally and the session is removed from the SMF session table
    And the UE IP address is returned to the IP pool

  Scenario: Heartbeat Response without Recovery Time Stamp counts as liveness but detects no restart
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the SMF holds an active PDU session "imsi-001010000000001" PSI 1 established on the UPF
    When the fake UPF answers the next PFCP Heartbeat Request with a Heartbeat Response that has no Recovery Time Stamp
    Then the SMF logs a warning with cause "RTS_MISSING" that restart detection is disabled
    And the SMF PFCP association state is "ASSOCIATED"
    And the SMF tracked UPF Recovery Time Stamp baseline is still "T0"
    And the fake AMF management API receives 0 release requests
    And the PDU session of "imsi-001010000000001" remains in state "ACTIVE"
    And the SMF does not log procedure "PfcpNodeLevelRecovery"

  Scenario: Inbound Heartbeat Request from the UPF is answered with the SMF Recovery Time Stamp
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    When the fake UPF sends a PFCP Heartbeat Request with sequence number 77 and Recovery Time Stamp "T0" to the SMF PFCP receiver
    Then the SMF returns a PFCP Heartbeat Response with sequence number 77 and Recovery Time Stamp "S0"
    And the SMF PFCP association state is "ASSOCIATED"
    And the fake AMF management API receives 0 release requests

  Scenario: Inbound Heartbeat Request carrying a changed Recovery Time Stamp triggers restart detection
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the SMF holds an active PDU session "imsi-001010000000001" PSI 1 established on the UPF before Recovery Time Stamp "T1"
    When the fake UPF sends a PFCP Heartbeat Request with sequence number 78 and the newer Recovery Time Stamp "T1" to the SMF PFCP receiver
    Then the SMF returns a PFCP Heartbeat Response with sequence number 78 and Recovery Time Stamp "S0"
    And the SMF logs procedure "PfcpNodeLevelRecovery" with cause "PEER_RESTART"
    And the fake AMF management API receives exactly one DELETE "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1"

  Scenario: Recovery Time Stamp in the Association Setup Response is not used for restart detection
    Given the SMF is associated with the fake UPF with baseline Recovery Time Stamp "T0"
    And the SMF holds an active PDU session "imsi-001010000000001" PSI 1 established on the UPF
    When the SMF re-runs PFCP Association Setup and the fake UPF answers with Cause "Request accepted" and a different Recovery Time Stamp "T1"
    Then the SMF logs the UPF Recovery Time Stamp "T1" from the Association Setup Response for observability only
    And the SMF does not log procedure "PfcpNodeLevelRecovery" with cause "PEER_RESTART"
    And the SMF tracked UPF Recovery Time Stamp baseline is not "T1" until a Heartbeat Response carries it
    And the fake AMF management API receives 0 release requests
    And the PDU session of "imsi-001010000000001" remains in state "ACTIVE"
