Feature: UE Context Transfer — producer side (TS 29.518 §5.3.2)
  As the old AMF that previously served a UE
  I want to answer a new AMF's Namf_Communication_UEContextTransfer request
  So that the UE's MM security context and PDU session contexts move to the new AMF
  without re-authenticating the UE

  Background:
    Given the AMF inbound namf-comm SBI server is running
    And a UE "imsi-001010000000001" is registered with an active NAS security context
    And the UE has an established PDU session 1 on DNN "internet"

  # TS 29.518 §5.3.2 / TS 23.502 §4.2.2.2.3 — happy path
  Scenario: New AMF retrieves the UE context by GUTI
    When a new AMF POSTs a UEContextTransfer request for the UE with reason "MOBI_REG"
    Then the response status is 200
    And the response carries the UE security context with the selected NAS algorithms
    And the response lists PDU session context 1 with DNN "internet"
    And the old AMF marks the UE context as transferred

  # Error path: unknown UE
  Scenario: Transfer request for an unknown UE is rejected
    When a new AMF POSTs a UEContextTransfer request for an unknown UE
    Then the response status is 404
    And the problem detail cause is "CONTEXT_NOT_FOUND"

  # Error path: mandatory IE missing
  Scenario: Transfer request without a reason is rejected
    When a new AMF POSTs a UEContextTransfer request with no reason
    Then the response status is 400
    And the problem detail cause is "MANDATORY_IE_MISSING"
