Feature: SMF N2 / Xn handover user plane: synchronous DL path switch, target-failed PDU sessions (SMF-005)
  As the SMF serving an AMF that completes a handover
  I want to move the UPF downlink FAR to the target gNB before I answer, and to release or deactivate PDU sessions the target could not set up
  So that DL user plane works after the handover and the AMF only sees success when N4 succeeded
  (TS 23.502 §4.9.1.3.2 steps 9-12, §4.9.1.3.3 (Handover Complete, N4 Session Modification), §4.9.1.2.2 steps 2-6,
   §4.3.7, §4.3.4.2; TS 29.502 §5.2.2.3.3 (Xn), §5.2.2.3.4 (N2), §6.1.6.2, §6.1.6.3, §6.1.7.3;
   TS 29.244 §7.5.4, §7.5.4.3, §7.5.5, §8.2.1, §8.2.26, §8.2.56;
   design: docs/procedures/N2Handover.md D1, D2, D3, rule R1, error table E-T1..E-T22)
  Out of scope (no scenario): indirect data forwarding (O1), End Marker / SNDEM (O2), DL buffering (O3).
  Acceptance criterion "human approval recorded for the PFCP changes" is a process gate, not a runtime behaviour: it is
  recorded in the Status line of docs/procedures/N2Handover.md and has no scenario.
  The fake UPF is RESPONDING: it answers PFCP Session Modification Requests with a configurable PFCP Cause, or stays silent.

  Background:
    Given an SMF with an active PDU session "sm-ctx-1" with PDU session id 1 and a stored UPF PFCP session
    And the PFCP client towards the UPF is a recording fake
    And the fake UPF answers PFCP Session Modification Requests with PFCP Cause 1
    And the AMF management API is a recording fake that accepts PDU session release requests
    And the session UP security enforcement policy is not "Required"

  # ===== D1 N2 COMPLETED: DL path switch (TS 23.502 §4.9.1.3.3; TS 29.502 §5.2.2.3.4; TS 29.244 §7.5.4) ====

  @happy @D1
  Scenario: hoState COMPLETED after PREPARED switches the DL FAR to the stored target tunnel and answers 200 only after the UPF responded
    Given the session "sm-ctx-1" has hoState "PREPARED" and a stored target DL NG-U tunnel
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response hoState is "COMPLETED"
    And exactly one PFCP Session Modification Request is sent to the UPF
    And that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action FORW
    And that Update FAR carries Update Forwarding Parameters with Outer Header Creation GTP-U/UDP/IPv4 with the stored target TEID and the stored target gNB IP
    And that PFCP Session Modification Request carries no Create PDR, Update PDR, Create QER or Update QER
    And the SMF answered the AMF only after the fake UPF had answered the PFCP Session Modification Request
    And the session HOState is "COMPLETED"
    And the stored target tunnel is cleared on the session
    And the SMF does not log a WARN with dl_switch "pending-human-approval"

  @happy @D1
  Scenario: the N2 DL switch is logged on N4 with the canonical fields
    Given the session "sm-ctx-1" has hoState "PREPARED" and a stored target DL NG-U tunnel
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the SMF logs procedure "N2Handover" interface "N4" direction "OUT" message_type "PFCPSessionModificationRequest" with spec_ref "TS 23.502 §4.9.1.3.3 (N4 Session Modification); TS 29.244 §7.5.4"
    And the SMF logs procedure "N2Handover" interface "N4" direction "IN" message_type "PFCPSessionModificationResponse" with pfcp_cause 1 and spec_ref "TS 29.244 §7.5.5"
    And the SMF logs procedure "N2Handover" interface "Nsmf" direction "OUT" with dl_switch "done"

  @happy @D1 @E-T7
  Scenario: a repeated hoState COMPLETED after a successful switch is idempotent and sends no second PFCP
    Given the session "sm-ctx-1" has hoState "PREPARED" and a stored target DL NG-U tunnel
    And the AMF sent UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and the SMF answered 200
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response hoState is "COMPLETED"
    And exactly one PFCP Session Modification Request has been sent to the UPF in total

  @fallback @D1 @E-T8
  Scenario: hoState COMPLETED on a session that was not PREPARED but has a stored target tunnel still switches the DL FAR with a WARN
    Given the session "sm-ctx-1" has hoState "NONE" and a stored target DL NG-U tunnel
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response hoState is "COMPLETED"
    And exactly one PFCP Session Modification Request is sent to the UPF
    And that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action FORW
    And the SMF logs a WARN that the previous HOState was not "PREPARED"

  @error @D1 @E-T1 @E-T3
  Scenario Outline: UPF answers the DL switch with a non-accepted PFCP Cause so the SMF answers 500 SYSTEM_FAILURE without n2SmInfo and keeps the handover state
    Given the session "sm-ctx-1" has hoState "PREPARED" and a stored target DL NG-U tunnel
    And the fake UPF answers PFCP Session Modification Requests with PFCP Cause <pfcp_cause>
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 500 with Content-Type "application/json" and a SmContextUpdateError with error.cause "SYSTEM_FAILURE"
    And the response has no n2SmInfo
    And exactly one PFCP Session Modification Request is sent to the UPF
    And the session HOState is "PREPARED"
    And the target tunnel is still stored on the session
    And the session state is "ACTIVE"
    And the SMF logs an ERROR with dl_switch "failed" and pfcp_cause <pfcp_cause>

    Examples:
      | pfcp_cause | meaning                                  |
      | 64         | Request rejected (reason not specified)  |
      | 65         | Session context not found                |
      | 69         | Mandatory IE incorrect                   |
      | 73         | Rule creation/modification Failure       |

  @error @D1
  Scenario: UPF answers the DL switch without a Cause IE so the SMF answers 500 SYSTEM_FAILURE
    Given the session "sm-ctx-1" has hoState "PREPARED" and a stored target DL NG-U tunnel
    And the fake UPF answers PFCP Session Modification Requests without a Cause IE
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 500 with Content-Type "application/json" and a SmContextUpdateError with error.cause "SYSTEM_FAILURE"
    And the response has no n2SmInfo
    And the SMF logs an ERROR with dl_switch "failed" and pfcp_cause "missing"
    And the session HOState is "PREPARED"

  @error @D1 @E-T2
  Scenario: UPF does not answer the DL switch so the SMF answers 504 UPF_NOT_RESPONDING within the handover N4 budget
    Given the session "sm-ctx-1" has hoState "PREPARED" and a stored target DL NG-U tunnel
    And the fake UPF does not answer PFCP Session Modification Requests
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 504 with Content-Type "application/json" and a SmContextUpdateError with error.cause "UPF_NOT_RESPONDING"
    And the response has no n2SmInfo
    And the SMF answered the AMF within 2 seconds, below the AMF handover UpdateSMContext timeout
    And the session HOState is "PREPARED"
    And the target tunnel is still stored on the session
    And the SMF logs an ERROR with dl_switch "failed" and cause "pfcp-timeout"

  @reject @D1 @E-T6
  Scenario: hoState COMPLETED without a stored target tunnel is rejected with 500 SYSTEM_FAILURE and sends no PFCP
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 500 with Content-Type "application/json" and a SmContextUpdateError with error.cause "SYSTEM_FAILURE"
    And the response has no n2SmInfo
    And the SMF sends zero PFCP messages to the UPF
    And the SMF logs a WARN with detail "no target tunnel"

  @reject @D1 @E-T5
  Scenario: hoState COMPLETED on a RELEASING session is rejected with 409 SmContextUpdateError and sends no PFCP
    Given the session "sm-ctx-1" has hoState "PREPARED" and a stored target DL NG-U tunnel
    And the session "sm-ctx-1" is in state "RELEASING"
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 409 with Content-Type "application/json" and a SmContextUpdateError with error.cause "PDU_SESSION_RELEASING"
    And the response has no n2SmInfo
    And the SMF sends zero PFCP messages to the UPF
    And the session state is "RELEASING"

  @error @D1 @E-T4
  Scenario: hoState COMPLETED for an unknown SM context is rejected with 404 and sends no PFCP
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 404 with Content-Type "application/json" and a SmContextUpdateError with error.cause "CONTEXT_NOT_FOUND"
    And the response has no n2SmInfo
    And the SMF sends zero PFCP messages to the UPF

  # ===== D2 Xn PATH_SWITCH_REQ: synchronous (TS 23.502 §4.9.1.2.2 steps 3, 4, 6; TS 29.502 §5.2.2.3.3) ====

  @happy @D2
  Scenario: PATH_SWITCH_REQ answers PATH_SWITCH_REQ_ACK only after the UPF responded to the DL switch
    When the AMF sends UpdateSMContext for "sm-ctx-1" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and a valid PathSwitchRequestTransfer
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response n2SmInfoType is "PATH_SWITCH_REQ_ACK"
    And the response n2SmInfo is the base64 of a PathSwitchRequestAcknowledgeTransfer that decodes with free5gc/ngap using valueExt
    And exactly one PFCP Session Modification Request is sent to the UPF
    And that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action FORW
    And that Update FAR carries Update Forwarding Parameters with Outer Header Creation GTP-U/UDP/IPv4 with the target DL F-TEID of the PathSwitchRequestTransfer
    And the SMF answered the AMF only after the fake UPF had answered the PFCP Session Modification Request

  @error @D2 @E-T10
  Scenario Outline: PATH_SWITCH_REQ with a non-accepted PFCP Cause is answered 500 SYSTEM_FAILURE with PATH_SWITCH_REQ_FAIL
    Given the fake UPF answers PFCP Session Modification Requests with PFCP Cause <pfcp_cause>
    When the AMF sends UpdateSMContext for "sm-ctx-1" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and a valid PathSwitchRequestTransfer
    Then the SMF responds 500 with Content-Type "application/json" and a SmContextUpdateError with error.cause "SYSTEM_FAILURE"
    And the response n2SmInfoType is "PATH_SWITCH_REQ_FAIL"
    And the response n2SmInfo is the base64 of a PathSwitchRequestUnsuccessfulTransfer with radioNetwork Cause "ho-failure-in-target-5GC-ngran-node-or-target-system" (7)
    And exactly one PFCP Session Modification Request is sent to the UPF
    And the session state is "ACTIVE"

    Examples:
      | pfcp_cause |
      | 64         |
      | 65         |
      | 73         |

  @error @D2 @E-T11
  Scenario: PATH_SWITCH_REQ with a silent UPF is answered 504 UPF_NOT_RESPONDING with PATH_SWITCH_REQ_FAIL
    Given the fake UPF does not answer PFCP Session Modification Requests
    When the AMF sends UpdateSMContext for "sm-ctx-1" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and a valid PathSwitchRequestTransfer
    Then the SMF responds 504 with Content-Type "application/json" and a SmContextUpdateError with error.cause "UPF_NOT_RESPONDING"
    And the response n2SmInfoType is "PATH_SWITCH_REQ_FAIL"
    And the response n2SmInfo is the base64 of a PathSwitchRequestUnsuccessfulTransfer with radioNetwork Cause "ho-failure-in-target-5GC-ngran-node-or-target-system" (7)
    And the SMF answered the AMF within 2 seconds, below the AMF handover UpdateSMContext timeout

  @reject @D2 @E-T12
  Scenario: PATH_SWITCH_REQ with an undecodable PathSwitchRequestTransfer is rejected with 422 PATH_SWITCH_REQ_FAIL and sends no PFCP
    When the AMF sends UpdateSMContext for "sm-ctx-1" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and the n2SmInfo bytes "ffffffff"
    Then the SMF responds 422 with Content-Type "application/json" and a SmContextUpdateError
    And the response n2SmInfoType is "PATH_SWITCH_REQ_FAIL"
    And the response n2SmInfo is the base64 of a PathSwitchRequestUnsuccessfulTransfer with Cause "protocol" "semantic-error"
    And the SMF sends zero PFCP messages to the UPF

  @reject @D2 @E-T5
  Scenario: PATH_SWITCH_REQ on a RELEASING session is rejected with 409 PATH_SWITCH_REQ_FAIL and sends no PFCP
    Given the session "sm-ctx-1" is in state "RELEASING"
    When the AMF sends UpdateSMContext for "sm-ctx-1" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and a valid PathSwitchRequestTransfer
    Then the SMF responds 409 with Content-Type "application/json" and a SmContextUpdateError with error.cause "PDU_SESSION_RELEASING"
    And the response n2SmInfoType is "PATH_SWITCH_REQ_FAIL"
    And the SMF sends zero PFCP messages to the UPF

  @error @D2 @E-T4
  Scenario: PATH_SWITCH_REQ for an unknown SM context is rejected with 404 and sends no PFCP
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and a valid PathSwitchRequestTransfer
    Then the SMF responds 404 with a ProblemDetails cause "CONTEXT_NOT_FOUND"
    And the SMF sends zero PFCP messages to the UPF

  # ===== D3 Xn PATH_SWITCH_SETUP_FAIL: 204 then deactivate or release (TS 23.502 §4.9.1.2.2 step 2, §4.3.7, §4.3.4.2; TS 29.502 §5.2.2.3.3) ====

  @happy @D3 @E-T17
  Scenario: PATH_SWITCH_SETUP_FAIL returns 204 No Content, then deactivates the UP connection with one PFCP Update FAR DROP and State IDLE
    When the AMF sends UpdateSMContext for "sm-ctx-1" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a valid PathSwitchRequestSetupFailedTransfer
    Then the SMF responds 204 with no body
    And within 2 seconds exactly one PFCP Session Modification Request is sent to the UPF
    And that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action DROP
    And that Update FAR carries no Update Forwarding Parameters
    And within 2 seconds the session state is "IDLE"
    And the session is not released
    And the AMF management API receives no PDU session release request
    And the relayed Cause is logged at INFO
    And the SMF logs procedure "XnHandover" with target_failed_action "deactivate" and up_deactivation "done"

  @error @D3 @E-T17
  Scenario Outline: PATH_SWITCH_SETUP_FAIL deactivation that the UPF rejects or ignores is still answered 204 and only logged
    Given <upf_mode>
    When the AMF sends UpdateSMContext for "sm-ctx-1" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a valid PathSwitchRequestSetupFailedTransfer
    Then the SMF responds 204 with no body
    And within 2 seconds exactly one PFCP Session Modification Request is sent to the UPF
    And within 2 seconds the SMF logs a WARN with up_deactivation "failed"
    And the session state is not "IDLE"
    And the AMF management API receives no PDU session release request

    Examples:
      | upf_mode                                                              |
      | the fake UPF answers PFCP Session Modification Requests with PFCP Cause 64 |
      | the fake UPF does not answer PFCP Session Modification Requests       |

  @happy @D3 @R1 @E-T18
  Scenario Outline: PATH_SWITCH_SETUP_FAIL with an UP security cause and UP security enforcement Required releases the PDU session via the AMF and sends no PFCP
    Given the session UP security enforcement policy is "Required"
    When the AMF sends UpdateSMContext for "sm-ctx-1" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a PathSwitchRequestSetupFailedTransfer with radioNetwork Cause "<cause>"
    Then the SMF responds 204 with no body
    And within 2 seconds the AMF management API receives a PDU session release request for the SUPI of "sm-ctx-1" and PDU session id 1
    And the SMF sends zero PFCP messages to the UPF
    And the SMF logs procedure "XnHandover" with target_failed_action "release"

    Examples:
      | cause                                      |
      | up-integrity-protection-not-possible       |
      | up-confidentiality-protection-not-possible |

  @fallback @D3 @R1 @E-T18
  Scenario: PATH_SWITCH_SETUP_FAIL release that the AMF fails falls back to deactivation
    Given the session UP security enforcement policy is "Required"
    And the AMF management API is a recording fake that fails PDU session release requests
    When the AMF sends UpdateSMContext for "sm-ctx-1" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a PathSwitchRequestSetupFailedTransfer with radioNetwork Cause "up-integrity-protection-not-possible"
    Then the SMF responds 204 with no body
    And within 2 seconds the AMF management API receives a PDU session release request for the SUPI of "sm-ctx-1" and PDU session id 1
    And within 2 seconds exactly one PFCP Session Modification Request is sent to the UPF
    And that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action DROP
    And the SMF logs a WARN about the failed release

  @happy @D3 @R1
  Scenario Outline: PATH_SWITCH_SETUP_FAIL deactivates instead of releasing when the rule R1 release condition is not fully met
    Given the session UP security enforcement policy is <policy>
    When the AMF sends UpdateSMContext for "sm-ctx-1" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a PathSwitchRequestSetupFailedTransfer with radioNetwork Cause "<cause>"
    Then the SMF responds 204 with no body
    And within 2 seconds exactly one PFCP Session Modification Request is sent to the UPF
    And that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action DROP
    And the AMF management API receives no PDU session release request

    Examples:
      | policy           | cause                                      |
      | not "Required"   | up-integrity-protection-not-possible       |
      | not "Required"   | up-confidentiality-protection-not-possible |
      | "Required"       | radio-resources-not-available              |
      | "Required"       | unspecified                                |

  @reject @D3 @E-T19
  Scenario: PATH_SWITCH_SETUP_FAIL on a RELEASING session is answered 204 and takes no deactivation or release action
    Given the session "sm-ctx-1" is in state "RELEASING"
    When the AMF sends UpdateSMContext for "sm-ctx-1" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a valid PathSwitchRequestSetupFailedTransfer
    Then the SMF responds 204 with no body
    And the SMF sends zero PFCP messages to the UPF
    And the AMF management API receives no PDU session release request
    And the session state is "RELEASING"

  # ===== D3 N2 HANDOVER_RES_ALLOC_FAIL: error answer, no PFCP (TS 23.502 §4.9.1.3.2 step 10; TS 29.502 §5.2.2.3.4) ====

  @happy @D3 @E-T13
  Scenario: HANDOVER_RES_ALLOC_FAIL returns 403 HANDOVER_RESOURCE_ALLOCATION_FAILURE with a HANDOVER_PREP_FAIL transfer, resets HOState to NONE and sends no PFCP
    Given the session "sm-ctx-1" has a stored target DL NG-U tunnel from an earlier HANDOVER_REQ_ACK
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a valid HandoverResourceAllocationUnsuccessfulTransfer
    Then the SMF responds 403 with Content-Type "application/json" and a SmContextUpdateError with error.cause "HANDOVER_RESOURCE_ALLOCATION_FAILURE"
    And the response n2SmInfoType is "HANDOVER_PREP_FAIL"
    And the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer that decodes with free5gc/ngap using valueExt
    And that HandoverPreparationUnsuccessfulTransfer carries the same Cause as the HandoverResourceAllocationUnsuccessfulTransfer of the request
    And the session HOState is "NONE"
    And the session HOTargetGNBIP and HOTargetDLTEID are cleared
    And the session is marked as target-failed
    And the SMF sends zero PFCP messages to the UPF
    And the session state is unchanged
    And the SMF logs an INFO with followup "await-amf-deactivation"
    And the SMF does not log a WARN with followup "release-or-deactivate-pending"

  @happy @D3 @E-T13
  Scenario Outline: HANDOVER_RES_ALLOC_FAIL relays the target Cause into the HANDOVER_PREP_FAIL transfer
    Given the session "sm-ctx-1" has a stored target DL NG-U tunnel from an earlier HANDOVER_REQ_ACK
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a HandoverResourceAllocationUnsuccessfulTransfer with radioNetwork Cause "<cause>"
    Then the SMF responds 403 with Content-Type "application/json" and a SmContextUpdateError with error.cause "HANDOVER_RESOURCE_ALLOCATION_FAILURE"
    And the response n2SmInfoType is "HANDOVER_PREP_FAIL"
    And that HandoverPreparationUnsuccessfulTransfer carries the radioNetwork Cause "<cause>"
    And the SMF sends zero PFCP messages to the UPF

    Examples:
      | cause                                      |
      | radio-resources-not-available              |
      | up-integrity-protection-not-possible       |
      | unspecified                                |

  @fallback @D3 @E-T14
  Scenario: HANDOVER_RES_ALLOC_FAIL with an undecodable transfer is answered 403 with radioNetwork cause 7 and a WARN, and sends no PFCP
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and the n2SmInfo bytes "ffffffff"
    Then the SMF responds 403 with Content-Type "application/json" and a SmContextUpdateError with error.cause "HANDOVER_RESOURCE_ALLOCATION_FAILURE"
    And the response n2SmInfoType is "HANDOVER_PREP_FAIL"
    And the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer with radioNetwork Cause "ho-failure-in-target-5GC-ngran-node-or-target-system" (7)
    And the session HOState is "NONE"
    And the undecodable transfer is logged with level WARN
    And the SMF sends zero PFCP messages to the UPF

  @reject @D3 @E-T5
  Scenario: HANDOVER_RES_ALLOC_FAIL on a RELEASING session is answered normally but takes no deactivation or release decision and sends no PFCP
    Given the session "sm-ctx-1" is in state "RELEASING"
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a valid HandoverResourceAllocationUnsuccessfulTransfer
    Then the SMF responds 403 with Content-Type "application/json" and a SmContextUpdateError with error.cause "HANDOVER_RESOURCE_ALLOCATION_FAILURE"
    And the SMF sends zero PFCP messages to the UPF
    And the session state is "RELEASING"

  @happy @D3 @E-T15
  Scenario: after HANDOVER_RES_ALLOC_FAIL the AMF indication upCnxState DEACTIVATED deactivates the UP connection with PFCP Update FAR DROP
    Given the session "sm-ctx-1" has a stored target DL NG-U tunnel from an earlier HANDOVER_REQ_ACK
    And the AMF sent UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a valid HandoverResourceAllocationUnsuccessfulTransfer
    And the SMF sent zero PFCP messages to the UPF so far
    When the AMF sends UpdateSMContext for "sm-ctx-1" with upCnxState "DEACTIVATED"
    Then the SMF responds 200
    And within 2 seconds exactly one PFCP Session Modification Request is sent to the UPF
    And that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action DROP
    And the session state is "IDLE"
    And the session is not released
    And the AMF management API receives no PDU session release request
    And the session is no longer marked as target-failed
    And the SMF logs procedure "N2Handover" with up_cnx_state "DEACTIVATED" and target_failed_action "deactivate"

  @happy @D3 @R1 @E-T16
  Scenario: after HANDOVER_RES_ALLOC_FAIL with an UP security cause and enforcement Required the AMF indication releases the PDU session and sends no PFCP
    Given the session UP security enforcement policy is "Required"
    And the session "sm-ctx-1" has a stored target DL NG-U tunnel from an earlier HANDOVER_REQ_ACK
    And the AMF sent UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a HandoverResourceAllocationUnsuccessfulTransfer with radioNetwork Cause "up-confidentiality-protection-not-possible"
    When the AMF sends UpdateSMContext for "sm-ctx-1" with upCnxState "DEACTIVATED"
    Then the SMF responds 200
    And within 2 seconds the AMF management API receives a PDU session release request for the SUPI of "sm-ctx-1" and PDU session id 1
    And the SMF sends zero PFCP messages to the UPF
    And the SMF logs procedure "N2Handover" with up_cnx_state "DEACTIVATED" and target_failed_action "release"

  @fallback @D3 @R1 @E-T16
  Scenario: after HANDOVER_RES_ALLOC_FAIL a failed AMF release falls back to deactivation with PFCP Update FAR DROP
    Given the session UP security enforcement policy is "Required"
    And the AMF management API is a recording fake that fails PDU session release requests
    And the session "sm-ctx-1" has a stored target DL NG-U tunnel from an earlier HANDOVER_REQ_ACK
    And the AMF sent UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a HandoverResourceAllocationUnsuccessfulTransfer with radioNetwork Cause "up-integrity-protection-not-possible"
    When the AMF sends UpdateSMContext for "sm-ctx-1" with upCnxState "DEACTIVATED"
    Then the SMF responds 200
    And within 2 seconds the AMF management API receives a PDU session release request for the SUPI of "sm-ctx-1" and PDU session id 1
    And within 2 seconds exactly one PFCP Session Modification Request is sent to the UPF
    And that PFCP Session Modification Request carries Update FAR with FAR ID 1 and Apply Action DROP
    And the SMF logs a WARN about the failed release

  @happy @D3 @E-T22
  Scenario: without the AMF indication a target-failed N2 PDU session is left untouched
    Given the session "sm-ctx-1" has a stored target DL NG-U tunnel from an earlier HANDOVER_REQ_ACK
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a valid HandoverResourceAllocationUnsuccessfulTransfer
    Then the SMF responds 403 with Content-Type "application/json" and a SmContextUpdateError with error.cause "HANDOVER_RESOURCE_ALLOCATION_FAILURE"
    And the SMF sends zero PFCP messages to the UPF
    And the AMF management API receives no PDU session release request
    And the session state is unchanged

  @error @D3 @E-T4
  Scenario: HANDOVER_RES_ALLOC_FAIL for an unknown SM context is rejected with 404 and sends no PFCP
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a valid HandoverResourceAllocationUnsuccessfulTransfer
    Then the SMF responds 404 with Content-Type "application/json" and a SmContextUpdateError with error.cause "CONTEXT_NOT_FOUND"
    And the SMF sends zero PFCP messages to the UPF

  # ===== Live DL user plane after an N2 handover (acceptance criterion 2). Needs the running stack; skipped unless E2E_TEST=1 ====

  @e2e @D1
  Scenario: DL user plane keeps working after an N2 handover driven by PacketRusher
    Given the live 5GC stack is running with PacketRusher in the N2 handover scenario
    And a UE has an established PDU session and DL traffic towards the UE IP is running
    When the N2 handover completes at HANDOVER NOTIFY
    Then the SMF logs one N2Handover PFCP Session Modification Request followed by dl_switch "done" for the PDU session
    And the UPF logs "PFCP Session DL tunnel updated" with the target gNB IP
    And downlink GTP-U packets reach the target gNB tunnel after the handover
    And procedure_summary reports zero failures for N2HandoverDLSwitch
