Feature: EAP-AKA' authentication (TS 33.501 §6.1.3.1 / RFC 5448)
  As a SEAF/AMF
  I want the AUSF to run the EAP-AKA' method end to end
  So that subscribers provisioned for EAP-AKA' can be authenticated and a kSeaf derived

  Background:
    Given a clean AUSF instance is running
    And the UDM is provisioned for subscriber "imsi-001010000000099" with method "EAP_AKA_PRIME"

  Scenario: Successful EAP-AKA' round-trip yields kSeaf
    When AMF initiates authentication for "imsi-001010000000099"
    Then the response status is 201
    And the response authType is "EAP_AKA_PRIME"
    And the response contains an EAP-Request AKA-Challenge payload
    And the response has an eap-session link
    When the UE computes a correct EAP-Response and AMF submits it
    Then the eap-session response status is 200
    And the authResult is "AUTHENTICATION_SUCCESS"
    And the response contains a non-empty kSeaf
    And the response contains the EAP-Success payload

  Scenario: Tampered AT_MAC is rejected
    When AMF initiates authentication for "imsi-001010000000099"
    Then the response status is 201
    When the UE submits an EAP-Response with a corrupted AT_MAC
    Then the authResult is "AUTHENTICATION_FAILURE"
    And no kSeaf is returned

  Scenario: Wrong RES is rejected
    When AMF initiates authentication for "imsi-001010000000099"
    Then the response status is 201
    When the UE submits an EAP-Response with an incorrect RES
    Then the authResult is "AUTHENTICATION_FAILURE"

  Scenario: EAP-Response for an unknown auth context is rejected
    When AMF submits an EAP-Response for auth context "does-not-exist"
    Then the eap-session response status is 404
    And the cause is "CONTEXT_NOT_FOUND"

  Scenario: 5G-AKA subscribers are unaffected by EAP-AKA' support
    Given the UDM is provisioned for subscriber "imsi-001010000000001" with method "5G_AKA"
    When AMF initiates authentication for "imsi-001010000000001"
    Then the response status is 201
    And the response authType is "5G_AKA"
