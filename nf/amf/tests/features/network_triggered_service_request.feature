Feature: CN Paging + Network-Triggered Service Request (TS 23.502 §4.2.3.3)
  As the AMF receiving a Namf_Communication_N1N2MessageTransfer from the SMF
  I want to page a CM-IDLE UE over N2 and reach a CM-CONNECTED UE directly
  So that mobile-terminated data triggers the UE to re-activate its user plane

  Background:
    Given the AMF inbound namf-comm SBI server is running
    And a UE "imsi-001010000000001" is registered with an active NAS security context
    And the UE has an established PDU session 1 on DNN "internet"

  # TS 23.502 §4.2.3.3 — DL data for an idle UE triggers paging
  Scenario: N1N2MessageTransfer for a CM-IDLE UE triggers NGAP Paging
    Given the UE is CM-IDLE
    When the SMF POSTs an N1N2MessageTransfer for PDU session 1
    Then the response status is 202
    And the N1N2 transfer cause is "ATTEMPTING_TO_REACH_UE"
    And the AMF emits an NGAP Paging for the UE

  # TS 23.502 §4.2.3.3 — UE already reachable, no paging
  Scenario: N1N2MessageTransfer for a CM-CONNECTED UE is delivered without paging
    Given the UE is CM-CONNECTED
    When the SMF POSTs an N1N2MessageTransfer for PDU session 1
    Then the response status is 200
    And the N1N2 transfer cause is "N1_N2_TRANSFER_INITIATED"
    And the AMF does not emit a Paging

  # Error path: unknown UE
  Scenario: N1N2MessageTransfer for an unknown UE is rejected
    When the SMF POSTs an N1N2MessageTransfer for an unknown UE
    Then the response status is 404
    And the problem detail cause is "CONTEXT_NOT_FOUND"

  # ---------------------------------------------------------------------------
  # Paged Service Request: user-plane re-activation (AMF-006)
  # TS 23.502 §4.2.3.3 step 6 -> §4.2.3.2 steps 4/12; TS 24.501 §5.6.1.4.1.
  # The AMF records the PDU sessions it paged for (N1N2MessageTransfer) and, on
  # the UE's next Service Request, re-activates union(Uplink Data Status PSIs,
  # paged PSIs) via Nsmf_PDUSession_UpdateSMContext upCnxState=ACTIVATING.
  # ---------------------------------------------------------------------------

  # TS 23.502 §4.2.3.3 step 6; TS 24.501 §9.11.3.50 (Service type 2 = mobile terminated services)
  Scenario: Paged Service Request without Uplink Data Status re-activates the paged PDU session
    Given the UE is CM-IDLE
    And the SMF will return an N2SM PDUSessionResourceSetupRequestTransfer for PDU session 1 on activation
    And the SMF POSTs an N1N2MessageTransfer for PDU session 1
    And the AMF emits an NGAP Paging for the UE
    When the UE sends a Service Request with service type "mobile terminated services" and no Uplink Data Status
    Then the AMF requests upCnxState "ACTIVATING" from the SMF for PDU session 1 exactly once
    And the InitialContextSetupRequest carries PDU session 1 in the PDUSessionResourceSetupListCxtReq
    And the AMF sends a Service Accept
    And the UE has no paged PDU sessions pending

  # TS 23.502 §4.2.3.2 step 4/12: PSIs from Uplink Data Status and from paging are merged
  Scenario: Paged PDU session and Uplink Data Status PDU session are both re-activated exactly once in ascending order
    Given the UE has an established PDU session 2 on DNN "internet"
    And the UE is CM-IDLE
    And the SMF will return an N2SM PDUSessionResourceSetupRequestTransfer for PDU session 1 on activation
    And the SMF will return an N2SM PDUSessionResourceSetupRequestTransfer for PDU session 2 on activation
    And the SMF POSTs an N1N2MessageTransfer for PDU session 1
    When the UE sends a Service Request with service type "mobile terminated services" and Uplink Data Status flagging PDU sessions 1 and 2
    Then the AMF requests upCnxState "ACTIVATING" from the SMF for PDU session 1 exactly once
    And the AMF requests upCnxState "ACTIVATING" from the SMF for PDU session 2 exactly once
    And the InitialContextSetupRequest carries PDU sessions 1,2 in ascending order in the PDUSessionResourceSetupListCxtReq
    And the UE has no paged PDU sessions pending

  # TS 23.502 §4.2.3.2 step 4: SMF failure is not fatal for the Service Request
  Scenario: SMF activation failure for the paged PDU session still yields a Service Accept
    Given the UE is CM-IDLE
    And the SMF will fail the activation of PDU session 1
    And the SMF POSTs an N1N2MessageTransfer for PDU session 1
    When the UE sends a Service Request with service type "mobile terminated services" and no Uplink Data Status
    Then the AMF requests upCnxState "ACTIVATING" from the SMF for PDU session 1 exactly once
    And the AMF sends a Service Accept
    And the InitialContextSetupRequest carries no PDUSessionResourceSetupListCxtReq
    And the UE has no paged PDU sessions pending

  # Edge: paged PSI released between paging and Service Request is skipped
  # TS 24.501 §5.6.1.4.1 (only existing PDU sessions can be re-activated)
  Scenario: Paged PDU session no longer in the UE context is skipped
    Given the UE is CM-IDLE
    And the SMF POSTs an N1N2MessageTransfer for PDU session 1
    And PDU session 1 is released from the UE context before the Service Request
    When the UE sends a Service Request with service type "mobile terminated services" and no Uplink Data Status
    Then the AMF sends no activation request to the SMF for PDU session 1
    And the AMF sends a Service Accept
    And the InitialContextSetupRequest carries no PDUSessionResourceSetupListCxtReq
    And the UE has no paged PDU sessions pending

  # Regression: signalling-only SR with nothing paged carries no PDU session list
  # TS 23.502 §4.2.3.2; TS 24.501 §5.6.1.4.1
  Scenario: Signalling-only Service Request with no pending page carries no PDU session list
    Given the UE is CM-IDLE
    And no PDU session is pending as paged for the UE
    When the UE sends a Service Request with service type "signalling" and no Uplink Data Status
    Then the AMF sends no activation request to the SMF for PDU session 1
    And the InitialContextSetupRequest carries no PDUSessionResourceSetupListCxtReq
    And the AMF sends a Service Accept

  # Live path: UERANSIM answers the RRC page. Requires the running stack.
  # TS 38.413 §9.2.4.1 / §8.5.1; TS 38.331 §5.3.2; TS 23.502 §4.2.3.3
  @e2e
  Scenario: Live UERANSIM UE answers the page with a Service Request (IDLE-PAGING) and the user plane is re-activated
    Given a running 5GC with AMF, SMF, UPF, and NRF
    And a UERANSIM gNB is connected to the AMF
    And the UE is forced to CM-IDLE by an AN Release
    When the SMF triggers a dl-data-notification for PDU session 1
    Then the UE logs "Responding to received Paging" and sends a Service Request due to IDLE-PAGING
    And the InitialContextSetupRequest carries PDU session 1 in the PDUSessionResourceSetupListCxtReq
