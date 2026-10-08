Feature: Service Accept IEs and local release of PDU sessions the UE reports inactive (TS 24.501 §5.6.1.4.1)
  As the AMF accepting a Service Request
  I want the Service Accept to carry the PDU session status and PDU session reactivation result IEs
  And to locally release, also at the SMF, every PDU session the UE reports as inactive
  So that the UE and the network agree on which PDU sessions exist and which user planes are up

  # In-process: the real nasmsg.Handler is driven with an integrity-protected
  # Service Request; the SMF is an httptest server (UpdateSMContext ACTIVATING
  # + SM context release). Wire format of the IEs: TS 24.501 §8.2.17.1.1,
  # §9.11.3.44 (IEI 0x50), §9.11.3.42 (IEI 0x26).

  Background:
    Given the AMF inbound namf-comm SBI server is running
    And a UE "imsi-001010000000001" is registered with an active NAS security context
    And the UE has an established PDU session 1 on DNN "internet"
    And the UE has an established PDU session 2 on DNN "internet"
    And the UE is CM-IDLE

  # Happy path: both IEs present, all sessions active and re-activated.
  # TS 24.501 §5.6.1.4.1 (b) PDU session status, (uplink data status) reactivation result
  Scenario: Service Accept echoes PDU session status and reports successful reactivation
    Given the SMF will return an N2SM PDUSessionResourceSetupRequestTransfer for PDU session 1 on activation
    When the UE sends a Service Request with service type "data", Uplink Data Status "1" and PDU session status "1,2"
    Then the AMF sends a Service Accept
    And the Service Accept carries a PDU session status IE flagging PDU sessions "1,2"
    And the Service Accept carries a PDU session reactivation result IE flagging PDU sessions ""
    And the InitialContextSetupRequest carries PDU session 1 in the PDUSessionResourceSetupListCxtReq
    And the AMF releases no SM context at the SMF

  # Rejection path: a PDU session the UE reports inactive is released locally
  # in the AMF and the SMF is told to release the SM context.
  # TS 24.501 §5.6.1.4.1 (a); TS 23.502 §4.2.3.2; TS 29.502 §5.2.2.4
  Scenario: PDU session reported inactive by the UE is released in the AMF and at the SMF
    When the UE sends a Service Request with service type "signalling", Uplink Data Status "" and PDU session status "1"
    Then the AMF sends a Service Accept
    And the AMF releases the SM context of PDU session 2 at the SMF
    And PDU session 2 is no longer in the UE context
    And PDU session 1 is still in the UE context
    And the Service Accept carries a PDU session status IE flagging PDU sessions "1"
    And the Service Accept carries no PDU session reactivation result IE

  # Error path: SMF activation fails -> reactivation result bit = 1 for that PSI.
  # TS 24.501 §9.11.3.42 (1 = establishment of user-plane resources failed or not performed)
  Scenario: Failed user-plane re-activation is reported in the reactivation result
    Given the SMF will return an N2SM PDUSessionResourceSetupRequestTransfer for PDU session 1 on activation
    And the SMF will fail the activation of PDU session 2
    When the UE sends a Service Request with service type "data", Uplink Data Status "1,2" and PDU session status "1,2"
    Then the AMF sends a Service Accept
    And the InitialContextSetupRequest carries PDU session 1 in the PDUSessionResourceSetupListCxtReq
    And the Service Accept carries a PDU session reactivation result IE flagging PDU sessions "2"
    And the Service Accept carries a PDU session status IE flagging PDU sessions "1,2"

  # Rejection path: Uplink Data Status names a PSI the UE also reports inactive:
  # it is released, not activated, and the reactivation result flags it.
  Scenario: PDU session flagged for uplink data but reported inactive is released and reported not reactivated
    Given the SMF will return an N2SM PDUSessionResourceSetupRequestTransfer for PDU session 1 on activation
    And the SMF will return an N2SM PDUSessionResourceSetupRequestTransfer for PDU session 2 on activation
    When the UE sends a Service Request with service type "data", Uplink Data Status "1,2" and PDU session status "1"
    Then the AMF sends a Service Accept
    And the AMF sends no activation request to the SMF for PDU session 2
    And the AMF releases the SM context of PDU session 2 at the SMF
    And the InitialContextSetupRequest carries PDU session 1 in the PDUSessionResourceSetupListCxtReq
    And the Service Accept carries a PDU session reactivation result IE flagging PDU sessions "2"
    And the Service Accept carries a PDU session status IE flagging PDU sessions "1"

  # Paged PSI reported inactive: released locally instead of activated (AMF-006 only skipped it).
  # TS 23.502 §4.2.3.3 step 6; TS 24.501 §5.6.1.4.1
  Scenario: Paged PDU session reported inactive is released, not activated
    Given the SMF POSTs an N1N2MessageTransfer for PDU session 2
    When the UE sends a Service Request with service type "mobile terminated services", Uplink Data Status "" and PDU session status "1"
    Then the AMF sends a Service Accept
    And the AMF sends no activation request to the SMF for PDU session 2
    And the AMF releases the SM context of PDU session 2 at the SMF
    And the InitialContextSetupRequest carries no PDUSessionResourceSetupListCxtReq
    And the UE has no paged PDU sessions pending

  # Regression: an SR without either IE gets an empty Service Accept and no release.
  Scenario: Service Request without PDU session status or Uplink Data Status yields an empty Service Accept
    When the UE sends a Service Request with service type "signalling", Uplink Data Status "" and PDU session status ""
    Then the AMF sends a Service Accept
    And the Service Accept carries no PDU session status IE
    And the Service Accept carries no PDU session reactivation result IE
    And the AMF releases no SM context at the SMF
