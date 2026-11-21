# SMF Restart Recovery -- release of orphaned PDU sessions after an SMF restart (SMF-012)
# (TS 23.527 §4.4.2 SMF restart; TS 29.244 §6.2.6.2.2 PFCP Association Setup (CP function
#  initiated), UPF purges sessions of a re-associating Node ID; TS 23.502 §4.3.4.2
#  SMF-requested PDU Session Release; TS 24.501 §6.3.3.3 / 5GSM cause #39 "reactivation requested")
#
# Scope: in-process SMF with a fake UPF (loopback UDP) and a fake AMF management API (httptest)
# with short retry/backoff and association gate timer overrides. Orphans come from the
# persisted store of the previous run. Release uses
# DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}?cause=39 (documented deviation from
# Namf_Communication_N1N2MessageTransfer). Out of scope: AMF N1/N2 legs (AMF features).

Feature: SMF restart recovery of PDU sessions
  As the SMF
  I want to release PDU sessions persisted by a previous run towards the AMF with 5GSM cause #39
  So that the UE re-establishes sessions the restarted SMF and UPF no longer hold (TS 23.527 §4.4.2)

  Background:
    Given a fake UPF PFCP peer listening on a loopback UDP socket
    And a fake AMF management API recording PDU session release requests
    And the SMF store holds 2 PDU sessions of a previous run "imsi-001010000000001" PSI 1 and "imsi-001010000000002" PSI 2
    And the SMF orphan release retry timers and association gate timeout are short

  Scenario: Restarted SMF with 2 persisted sessions releases both with cause 39 after the first PFCP Association Setup Response
    Given the fake AMF management API accepts PDU session release requests with 202
    When the SMF is started
    Then the fake UPF receives a PFCP Association Setup Request
    And no release request reaches the fake AMF before the fake UPF answers with a PFCP Association Setup Response with Cause "Request accepted"
    And the fake AMF receives DELETE "/amf/v1/ue-contexts/imsi-001010000000001/pdu-sessions/1" with query "cause=39"
    And the fake AMF receives DELETE "/amf/v1/ue-contexts/imsi-001010000000002/pdu-sessions/2" with query "cause=39"
    And the SMF logs procedure "SmfRestartRecovery" with result "OK" and spec_ref "TS 23.527 §4.4.2"
    And the SMF summary reports orphans 2, released 2, already_released 0, failed 0

  Scenario: AMF unavailable with 503 then 202 is retried and the orphan is released
    Given the fake AMF management API answers 503 then 202 for PSI 1 of "imsi-001010000000001"
    And the fake AMF management API accepts the release of "imsi-001010000000002" PSI 2 with 202
    When the SMF is started and associated with the fake UPF
    Then the fake AMF receives 2 DELETE requests with query "cause=39" for "imsi-001010000000001" PSI 1
    And the second request is sent after the retry backoff
    And the SMF summary reports orphans 2, released 2, already_released 0, failed 0

  Scenario: AMF answers 404 so the orphan is counted as already released without retry
    Given the fake AMF management API answers 404 for PSI 1 of "imsi-001010000000001"
    And the fake AMF management API accepts the release of "imsi-001010000000002" PSI 2 with 202
    When the SMF is started and associated with the fake UPF
    Then the fake AMF receives exactly 1 DELETE request for "imsi-001010000000001" PSI 1
    And the SMF logs result "OK" with cause "ALREADY_RELEASED" for "imsi-001010000000001"
    And the SMF summary reports orphans 2, released 1, already_released 1, failed 0

  Scenario: AMF retries exhausted logs FAILURE and the SMF keeps running
    Given the fake AMF management API answers 503 for every request
    When the SMF is started and associated with the fake UPF
    Then the fake AMF receives the configured maximum number of DELETE requests for each of the 2 sessions
    And the SMF logs result "FAILURE" with cause "AMF_RELEASE_FAILED"
    And the SMF summary reports orphans 2, released 0, already_released 0, failed 2
    And the SMF SBI server still answers requests
    And the SMF PFCP association state is "ASSOCIATED"

  Scenario: CreateSMContext before the first PFCP association waits and proceeds once associated
    Given the fake UPF delays its PFCP Association Setup Response
    And the SMF is started
    When a CreateSMContext request for "imsi-001010000000003" PSI 5 arrives before the first association completes
    Then the fake UPF receives no PFCP Session Establishment Request before the Association Setup Response
    And the fake UPF answers the PFCP Association Setup Response within the association gate timeout
    And the fake UPF then receives a PFCP Session Establishment Request for PSI 5
    And the CreateSMContext request succeeds with HTTP status 201

  Scenario: CreateSMContext is rejected when the PFCP association does not complete within the gate
    Given the fake UPF never answers PFCP Association Setup Requests
    And the SMF is started
    When a CreateSMContext request for "imsi-001010000000003" PSI 5 arrives before the first association completes
    Then the CreateSMContext request is rejected after the association gate timeout with PDU SESSION ESTABLISHMENT REJECT 5GSM cause 26
    And the fake UPF receives no PFCP Session Establishment Request
    And no SM context is stored for "imsi-001010000000003" PSI 5
