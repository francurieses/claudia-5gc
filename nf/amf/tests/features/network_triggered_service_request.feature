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
