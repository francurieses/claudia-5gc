Feature: SMF Nsmf_PDUSession_UpdateSMContext responses for handover N2 SM information (AMF-012 companion)
  As the SMF serving an AMF that waits for the UpdateSMContext response during handover
  I want to answer PATH_SWITCH_REQ, HANDOVER_REQ_ACK and PATH_SWITCH_SETUP_FAIL with the N2 SM information the AMF relays
  So that the PATH SWITCH REQUEST ACKNOWLEDGE and the HANDOVER COMMAND carry SMF-built transfers
  (TS 23.502 §4.9.1.2.2 steps 2-6, §4.9.1.3.2 steps 3-12, §4.9.1.3.3; TS 29.502 §5.2.2.3.3 (Xn), §5.2.2.3.4 (N2),
   §6.1.6.2 (SmContextUpdatedData / SmContextUpdateError), §6.1.6.3 (N2SmInfoType / HoState); TS 38.413 §9.3.4;
   design: docs/procedures/XnHandover.md §4.6, §4.7, §7.4.6, §7.8 item 10)
  SBI response construction only. The N2 SM information and the SBI answers of the preparation legs (PREPARING,
  HANDOVER_REQ_ACK) are asserted here, and those legs send no PFCP. The legs that DO send PFCP since SMF-005
  (hoState COMPLETED, PATH_SWITCH_REQ, PATH_SWITCH_SETUP_FAIL, HANDOVER_RES_ALLOC_FAIL, and the later upCnxState
  DEACTIVATED of a target-failed PDU session) are specified in n2_handover_user_plane.feature
  (design: docs/procedures/N2Handover.md). Here, the fake UPF answers those PFCP requests so the SBI answer can be built.

  Background:
    Given an SMF with an active PDU session "sm-ctx-1" with PDU session id 1 and a stored UPF PFCP session
    And the PFCP client towards the UPF is a recording fake

  Scenario: PATH_SWITCH_REQ returns 200 with a decodable PathSwitchRequestAcknowledgeTransfer
    Given the fake UPF answers PFCP Session Modification Requests with PFCP Cause 1
    When the AMF sends UpdateSMContext for "sm-ctx-1" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and a valid PathSwitchRequestTransfer
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response n2SmInfoType is "PATH_SWITCH_REQ_ACK"
    And the response n2SmInfo is the base64 of a PathSwitchRequestAcknowledgeTransfer that decodes with free5gc/ngap using valueExt
    And exactly one PFCP Session Modification Request is sent to the UPF with the target DL F-TEID
    # PFCP content and ordering (answer only after the UPF response): n2_handover_user_plane.feature, D2

  Scenario: HANDOVER_REQ_ACK returns 200 with a HandoverCommandTransfer, stores the target tunnel and sends no PFCP
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and a valid HandoverRequestAcknowledgeTransfer
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response hoState is "PREPARED"
    And the response n2SmInfoType is "HANDOVER_CMD"
    And the response n2SmInfo is the base64 of a HandoverCommandTransfer that decodes with free5gc/ngap using valueExt
    And the target DL NG-U tunnel (GTP-U address and TEID) of the transfer is stored on the session
    And the SMF sends zero PFCP messages to the UPF
    And the session state is unchanged

  # Removed (SMF-005): "PATH_SWITCH_SETUP_FAIL returns 200 and sends no PFCP". Now 204 + deactivate/release:
  # see n2_handover_user_plane.feature (D3).

  Scenario: HANDOVER_REQ_ACK with an undecodable transfer is rejected with 422 SmContextUpdateError and HANDOVER_PREP_FAIL
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and the n2SmInfo bytes "ffffffff"
    Then the SMF responds 422 with Content-Type "application/json" and a SmContextUpdateError
    And the response n2SmInfoType is "HANDOVER_PREP_FAIL"
    And the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer with Cause "protocol" "semantic-error"
    And the SMF sends zero PFCP messages to the UPF
    And no target tunnel is stored on the session

  Scenario: HANDOVER_REQ_ACK for an unknown SM context is rejected with 404 SmContextUpdateError and HANDOVER_PREP_FAIL
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and a valid HandoverRequestAcknowledgeTransfer
    Then the SMF responds 404 with Content-Type "application/json" and a SmContextUpdateError with error.cause "CONTEXT_NOT_FOUND"
    And the response n2SmInfoType is "HANDOVER_PREP_FAIL"
    And the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer with radioNetwork Cause "unknown-PDU-session-ID" (26)
    And the SMF sends zero PFCP messages to the UPF

  Scenario: PATH_SWITCH_REQ for an unknown SM context is rejected with 404
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with toBeSwitched true, n2SmInfoType "PATH_SWITCH_REQ" and a valid PathSwitchRequestTransfer
    Then the SMF responds 404 with a ProblemDetails cause "CONTEXT_NOT_FOUND"
    And the SMF sends zero PFCP messages to the UPF

  # ===== N2 PREPARING at HANDOVER REQUIRED (TS 23.502 §4.9.1.3.2 steps 3 and 6; TS 29.502 §5.2.2.3.4) ====

  @happy
  Scenario: PREPARING with HANDOVER_REQUIRED and a direct forwarding path returns PDU_RES_SETUP_REQ without DataForwardingNotPossible
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARING", n2SmInfoType "HANDOVER_REQUIRED", a valid HandoverRequiredTransfer carrying DirectForwardingPathAvailability and a targetId
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response hoState is "PREPARING"
    And the response n2SmInfoType is "PDU_RES_SETUP_REQ"
    And the response n2SmInfo is the base64 of a PDUSessionResourceSetupRequestTransfer that decodes with free5gc/ngap using valueExt
    And the transfer UL NG-U UP TNL Information carries the UPF N3 address and the UL TEID of the session
    And the transfer does not contain the IE DataForwardingNotPossible (id 127)
    And the transfer carries QFI 1 with the session 5QI and the session AMBR
    And the session HOState is "PREPARING" and HODirectForwarding is true
    And the SMF sends zero PFCP messages to the UPF
    And the SMF logs interface "Nsmf" direction "IN" spec_ref "TS 23.502 §4.9.1.3.2 step 3" and direction "OUT" spec_ref "TS 23.502 §4.9.1.3.2 step 6" with data_forwarding "direct"

  @happy
  Scenario Outline: PREPARING without a direct forwarding path returns a transfer with DataForwardingNotPossible in ASN.1 IE order
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARING" and <request>
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response n2SmInfoType is "PDU_RES_SETUP_REQ"
    And the response n2SmInfo is the base64 of a PDUSessionResourceSetupRequestTransfer that decodes with free5gc/ngap using valueExt
    And the transfer contains the IE DataForwardingNotPossible (id 127) with value data-forwarding-not-possible (0) and criticality reject
    And the transfer IEs appear in this order:
      | IE                                      | id  |
      | PDUSessionAggregateMaximumBitRate       | 130 |
      | ULNGUUPTNLInformation                   | 139 |
      | DataForwardingNotPossible               | 127 |
      | PDUSessionType                          | 134 |
      | QosFlowSetupRequestList                 | 136 |
    And the session HOState is "PREPARING" and HODirectForwarding is false
    And the SMF sends zero PFCP messages to the UPF
    And the SMF logs data_forwarding "not-possible"

    Examples:
      | request                                                                                                  |
      | n2SmInfoType "HANDOVER_REQUIRED" and a valid HandoverRequiredTransfer without DirectForwardingPathAvailability |
      | no n2SmInfo                                                                                              |

  @error
  Scenario: PREPARING for an unknown SM context is rejected with 404 SmContextUpdateError and HANDOVER_PREP_FAIL cause unknown-PDU-session-ID
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with hoState "PREPARING", n2SmInfoType "HANDOVER_REQUIRED" and a valid HandoverRequiredTransfer
    Then the SMF responds 404 with Content-Type "application/json" and a SmContextUpdateError with error.cause "CONTEXT_NOT_FOUND"
    And the response n2SmInfoType is "HANDOVER_PREP_FAIL"
    And the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer with radioNetwork Cause "unknown-PDU-session-ID" (26)
    And the SMF sends zero PFCP messages to the UPF

  @reject
  Scenario: PREPARING with an undecodable HandoverRequiredTransfer is rejected with 422 SmContextUpdateError and HANDOVER_PREP_FAIL
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARING", n2SmInfoType "HANDOVER_REQUIRED" and the n2SmInfo bytes "ffffffff"
    Then the SMF responds 422 with Content-Type "application/json" and a SmContextUpdateError
    And the response n2SmInfoType is "HANDOVER_PREP_FAIL"
    And the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer with Cause "protocol" "semantic-error"
    And the session HOState is not "PREPARING"
    And the SMF sends zero PFCP messages to the UPF

  # ===== N2 HANDOVER_REQ_ACK: data forwarding (TS 23.502 §4.9.1.3.2 steps 10 and 12; TS 38.413 §9.3.4.10) ====

  @happy
  Scenario: HANDOVER_REQ_ACK after direct-forwarding PREPARING returns the forwarding tunnel and the QoS Flow to be Forwarded List
    Given the session "sm-ctx-1" was prepared with hoState "PREPARING" and DirectForwardingPathAvailability
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and a valid HandoverRequestAcknowledgeTransfer with DL Forwarding UP TNL Information "10.0.0.9"/TEID 0x1234 and QFI 1 with DataForwardingAccepted
    Then the SMF responds 200 with a JSON SmContextUpdatedData
    And the response n2SmInfoType is "HANDOVER_CMD"
    And the response n2SmInfo is the base64 of a HandoverCommandTransfer that decodes with free5gc/ngap using valueExt
    And the HandoverCommandTransfer DLForwardingUPTNLInformation equals the GTP tunnel "10.0.0.9"/TEID 0x1234
    And the HandoverCommandTransfer QosFlowToBeForwardedList contains exactly QFI 1
    And the session HOState is "PREPARED"
    And the SMF sends zero PFCP messages to the UPF

  @happy
  Scenario: HANDOVER_REQ_ACK after direct-forwarding PREPARING without any DataForwardingAccepted flow returns an empty HandoverCommandTransfer
    Given the session "sm-ctx-1" was prepared with hoState "PREPARING" and DirectForwardingPathAvailability
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and a valid HandoverRequestAcknowledgeTransfer with DL Forwarding UP TNL Information "10.0.0.9"/TEID 0x1234 and QFI 1 without DataForwardingAccepted
    Then the response n2SmInfoType is "HANDOVER_CMD"
    And the HandoverCommandTransfer carries neither DLForwardingUPTNLInformation nor QosFlowToBeForwardedList
    And the SMF sends zero PFCP messages to the UPF

  @happy
  Scenario: HANDOVER_REQ_ACK without direct forwarding returns an empty HandoverCommandTransfer
    Given the session "sm-ctx-1" was prepared with hoState "PREPARING" and no DirectForwardingPathAvailability
    When the AMF sends UpdateSMContext for "sm-ctx-1" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and a valid HandoverRequestAcknowledgeTransfer with DL Forwarding UP TNL Information "10.0.0.9"/TEID 0x1234 and QFI 1 with DataForwardingAccepted
    Then the response n2SmInfoType is "HANDOVER_CMD"
    And the HandoverCommandTransfer carries neither DLForwardingUPTNLInformation nor QosFlowToBeForwardedList
    And the SMF logs data_forwarding "none" with the reason
    And the SMF sends zero PFCP messages to the UPF

  # ===== N2 HANDOVER_REQ_ACK error answers are SmContextUpdateError (TS 29.502 §6.1.6.2) ====

  @error
  Scenario Outline: HANDOVER_REQ_ACK failures are SmContextUpdateError JSON with a decodable HandoverPreparationUnsuccessfulTransfer, not problem+json
    When the AMF sends UpdateSMContext for "<sm_context>" with hoState "PREPARED", n2SmInfoType "HANDOVER_REQ_ACK" and <transfer>
    Then the SMF responds <status> with Content-Type "application/json" and a SmContextUpdateError
    And the response n2SmInfoType is "HANDOVER_PREP_FAIL"
    And the response n2SmInfo is the base64 of a HandoverPreparationUnsuccessfulTransfer that decodes with free5gc/ngap using valueExt
    And that transfer carries Cause <cause>
    And the SMF sends zero PFCP messages to the UPF

    Examples:
      | sm_context     | transfer                                          | status | cause                                         |
      | sm-ctx-unknown | a valid HandoverRequestAcknowledgeTransfer        | 404    | radioNetwork "unknown-PDU-session-ID" (26)    |
      | sm-ctx-1       | the n2SmInfo bytes "ffffffff"                     | 422    | protocol "semantic-error"                     |

  # ===== PATH_SWITCH_SETUP_FAIL unknown session (TS 29.502 §5.2.2.3.3) ====

  @error
  Scenario: PATH_SWITCH_SETUP_FAIL for an unknown SM context is rejected with 404 SmContextUpdateError without n2SmInfo
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with failedToBeSwitched true, n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and a valid PathSwitchRequestSetupFailedTransfer
    Then the SMF responds 404 with Content-Type "application/json" and a SmContextUpdateError with error.cause "CONTEXT_NOT_FOUND"
    And the response has no n2SmInfo
    And the SMF sends zero PFCP messages to the UPF

  # ===== N2 HANDOVER_RES_ALLOC_FAIL (TS 23.502 §4.9.1.3.2 step 10; TS 29.502 §5.2.2.3.4) ====

  # Removed (SMF-005): "returns 200 hoState CANCELLED" (happy) and its undecodable-transfer variant. The SMF now
  # answers 403 HANDOVER_RESOURCE_ALLOCATION_FAILURE + HANDOVER_PREP_FAIL with HOState NONE and still no PFCP:
  # see n2_handover_user_plane.feature (D3, E-T13, E-T14).

  @error
  Scenario: HANDOVER_RES_ALLOC_FAIL for an unknown SM context is rejected with 404 SmContextUpdateError
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with hoState "PREPARED", n2SmInfoType "HANDOVER_RES_ALLOC_FAIL" and a valid HandoverResourceAllocationUnsuccessfulTransfer
    Then the SMF responds 404 with Content-Type "application/json" and a SmContextUpdateError with error.cause "CONTEXT_NOT_FOUND"
    And the SMF sends zero PFCP messages to the UPF

  # ===== N2 COMPLETED (TS 23.502 §4.9.1.3.3 (Handover Complete); TS 29.502 §5.2.2.3.4) ====

  # Removed (SMF-005): "hoState COMPLETED ... sends no PFCP" (happy) and the not-PREPARED variant. COMPLETED now
  # performs the synchronous DL switch (one PFCP Session Modification); the not-PREPARED-without-tunnel case is a
  # 500 SYSTEM_FAILURE (E-T6), with a tunnel a WARN-and-switch (E-T8): see n2_handover_user_plane.feature (D1).

  @error
  Scenario: hoState COMPLETED for an unknown SM context is rejected with 404 SmContextUpdateError
    When the AMF sends UpdateSMContext for "sm-ctx-unknown" with hoState "COMPLETED" and no n2SmInfo
    Then the SMF responds 404 with Content-Type "application/json" and a SmContextUpdateError with error.cause "CONTEXT_NOT_FOUND"
    And the response has no n2SmInfo
    And the SMF sends zero PFCP messages to the UPF
