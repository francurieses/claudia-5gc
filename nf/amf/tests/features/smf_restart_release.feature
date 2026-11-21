Feature: Release of orphaned PDU sessions after an SMF restart with 5GSM cause #39 (TS 23.502 §4.3.4.2)
  As the AMF receiving an internal mgmt release request from a restarted SMF
  I want to release orphaned PDU sessions with 5GSM cause #39 "reactivation requested"
  So that the UE re-establishes the PDU session instead of keeping a stale one

  # Internal (non-3GPP) mgmt API on :9002:
  #   DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}[?cause=<5gsm-cause>]
  # Accepted cause set {36, 39}; absent = 36.
  # spec_ref: TS 23.502 §4.3.4.2; TS 24.501 §6.3.3.2, §6.3.3.3, §5.6.1.4; TS 38.413 §8.4.2

  Background:
    Given the AMF mgmt server is running
    And a UE "imsi-001010000000001" is registered with an active NAS security context
    And the UE has an established PDU session 1 on DNN "internet"

  # --- CM-CONNECTED path: TS 23.502 §4.3.4.2 steps 4-7; TS 38.413 §8.4.2 ---
  Scenario: Connected UE, release with 5GSM cause 39 sends Release Command and removes the PSI
    Given the UE is CM-CONNECTED
    And the SMF answers ReleaseSMContext for PDU session 1 with 404 "CONTEXT_NOT_FOUND"
    When the SMF sends DELETE for PDU session 1 with cause 39
    Then the mgmt response status is 202
    And the AMF sends an NGAP PDU Session Resource Release Command for PDU session 1
    And the NAS PDU SESSION RELEASE COMMAND carries 5GSM cause 0x27 and PTI 0
    And the PDU SESSION RELEASE COMMAND is delivered in a ciphered DL NAS Transport with PDU session ID 1
    When the gNB returns the PDU Session Resource Release Response and the UE sends a PDU SESSION RELEASE COMPLETE
    Then the AMF calls ReleaseSMContext for PDU session 1 and the 404 is tolerated
    And PDU session 1 is removed from the UE context

  # --- CM-IDLE + #39: network triggered Service Request, TS 23.502 §4.3.4.2 step 4 ---
  Scenario: Idle UE, release with 5GSM cause 39 pages the UE and delivers the Release Command after Service Accept
    Given the UE is CM-IDLE
    When the SMF sends DELETE for PDU session 1 with cause 39
    Then the mgmt response status is 202
    And the AMF emits an NGAP Paging for the UE
    And the AMF sends no NGAP PDU Session Resource Release Command
    When the UE answers with a Service Request with service type "mobile terminated services" and Uplink Data Status for PDU session 1
    Then the AMF does not request upCnxState "ACTIVATING" from the SMF for PDU session 1
    And the AMF sends a Service Accept
    And after the Service Accept the AMF sends a DL NAS Transport with PDU SESSION RELEASE COMMAND for PDU session 1 with 5GSM cause 0x27
    And the AMF sends no NGAP PDU Session Resource Release Command
    When the UE sends a PDU SESSION RELEASE COMPLETE for PDU session 1
    Then PDU session 1 is removed from the UE context

  # --- CM-IDLE + #36: skip N1 delivery, TS 24.501 §6.3.3.2, §5.6.1.4 ---
  Scenario: Idle UE, release with 5GSM cause 36 is released locally without paging
    Given the UE is CM-IDLE
    And the SMF answers ReleaseSMContext for PDU session 1 with 204
    When the SMF sends DELETE for PDU session 1 with cause 36
    Then the mgmt response status is 202
    And the AMF does not emit a Paging
    And PDU session 1 is removed from the UE context

  Scenario: Idle UE, release without a cause parameter defaults to 5GSM cause 36 and is released locally
    Given the UE is CM-IDLE
    And the SMF answers ReleaseSMContext for PDU session 1 with 204
    When the SMF sends DELETE for PDU session 1 without a cause
    Then the mgmt response status is 202
    And the AMF does not emit a Paging
    And PDU session 1 is removed from the UE context

  # --- Paging guard expiry ---
  Scenario: Idle UE never answers paging, the PSI is released locally after the paging guard
    Given the UE is CM-IDLE
    And the SMF answers ReleaseSMContext for PDU session 1 with 204
    When the SMF sends DELETE for PDU session 1 with cause 39
    Then the mgmt response status is 202
    And the AMF emits an NGAP Paging for the UE
    When the paging guard expires without a Service Request
    Then PDU session 1 is removed from the UE context
    And the AMF sends no DL NAS Transport for PDU session 1

  # --- Idempotency ---
  Scenario: Repeated DELETE while the release is pending returns 202 and sends no second Release Command
    Given the UE is CM-CONNECTED
    When the SMF sends DELETE for PDU session 1 with cause 39
    And the SMF sends DELETE for PDU session 1 with cause 39 again
    Then the mgmt response status is 202
    And the AMF sent exactly one NGAP PDU Session Resource Release Command for PDU session 1

  # --- Spec-deviation / input rejection ---
  Scenario: Release of an unknown PDU session ID returns 404
    When the SMF sends DELETE for PDU session 9 with cause 39
    Then the mgmt response status is 404
    And the AMF sends no NGAP PDU Session Resource Release Command

  Scenario: Release for an unknown SUPI returns 404
    When the SMF sends DELETE for unknown UE "imsi-001010000000999" PDU session 1 with cause 39
    Then the mgmt response status is 404

  Scenario: Unsupported 5GSM cause 40 is rejected with 400
    Given the UE is CM-CONNECTED
    When the SMF sends DELETE for PDU session 1 with cause 40
    Then the mgmt response status is 400
    And the AMF sends no NGAP PDU Session Resource Release Command
    And PDU session 1 is kept in the UE context

  # --- Stale-reference rule: TS 23.502 §4.3.4.2; SMF restart orphan detection ---
  Scenario: Service Request where the SMF returns 404 for the old SM context starts release with cause 39
    Given the UE is CM-IDLE
    And the SMF answers UpdateSMContext and ActivateSMContext for PDU session 1 with 404 "CONTEXT_NOT_FOUND"
    When the UE sends a Service Request with Uplink Data Status for PDU session 1
    Then the AMF reports PDU session 1 as not re-activated in the Service Accept
    And the AMF starts a release of PDU session 1 with 5GSM cause 39
    And a PDU SESSION RELEASE COMMAND with 5GSM cause 0x27 is delivered for PDU session 1

  # --- SMF unreachable: PSI kept, TS 24.501 §5.6.1.4 ---
  Scenario: Service Request while the SMF is unreachable reports reactivation failed and keeps the PSI
    Given the UE is CM-IDLE
    And the SMF is not reachable
    When the UE sends a Service Request with Uplink Data Status for PDU session 1
    Then the AMF reports PDU session 1 as not re-activated in the Service Accept
    And PDU session 1 is kept in the UE context
    And the AMF starts no release of PDU session 1
