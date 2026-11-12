Feature: Nnssaaf_NSSAA slice-specific authentication hosted by the AUSF (TS 29.526 §5.2.2 / TS 23.502 §4.2.9.2)
  As the AMF relaying the UE's slice-specific EAP exchange
  I want to create and confirm slice authentication contexts on the Nnssaaf_NSSAA API
  So that an S-NSSAI subject to NSSAA is authorized or rejected by the AAA-S

  # spec_ref: TS 29.526 §5.2.2.2   (Slice-Specific Authentication: POST /slice-authentications -> 201 SliceAuthContext + Location)
  # spec_ref: TS 29.526 §5.2.2.2.1 step 3b (AAA-S rejects -> 403 SLICE_AUTH_REJECTED)
  # spec_ref: TS 29.526 §5.2.2.3   (confirmation: PUT /slice-authentications/{authCtxId} -> 200 SliceAuthConfirmationResponse)
  # spec_ref: TS 29.526 §6.1.7.3 Table 6.1.7.3-1 (application errors), TS 29.571 §5.2.4.1 (ProblemDetails)
  # spec_ref: TS 23.502 §4.2.9.2   (NSSAA procedure; EAP relayed AMF -> NSSAAF -> AAA-S)
  # endpoint: POST /nnssaaf-nssaa/v1/slice-authentications -> 201 | 400 | 403
  # endpoint: PUT  /nnssaaf-nssaa/v1/slice-authentications/{authCtxId} -> 200 | 400 | 404
  # endpoint: POST /nausf-nssaa/v1/{supi}/authenticate (legacy relay, unchanged)

  Background:
    Given a clean AUSF with the Nnssaaf_NSSAA service is running

  Scenario: Slice authentication of an authorized identity is created with 201 and a terminal EAP-Success
    When the AMF creates a slice authentication for GPSI "msisdn-34600000001" S-NSSAI sst 1 sd "000001" with EAP identity "user@slice.example"
    Then the response status is 201
    And the response has a Location header ending with the authCtxId
    And the SliceAuthContext echoes GPSI "msisdn-34600000001" and S-NSSAI sst 1 sd "000001"
    And the eapMessage carries EAP code "Success"

  Scenario: Slice authentication refused by the AAA-S is rejected with 403 SLICE_AUTH_REJECTED
    When the AMF creates a slice authentication for GPSI "msisdn-34600000001" S-NSSAI sst 1 sd "000001" with EAP identity "reject-user@slice.example"
    Then the response status is 403
    And the problem cause is "SLICE_AUTH_REJECTED"

  Scenario: Two-round slice authentication returns an EAP-Request and the confirmation PUT completes with 200 EAP_SUCCESS
    When the AMF creates a slice authentication for GPSI "msisdn-34600000001" S-NSSAI sst 1 sd "000001" with EAP identity "challenge-user@slice.example"
    Then the response status is 201
    And the response has a Location header ending with the authCtxId
    And the eapMessage carries EAP code "Request"
    When the UE answers the EAP-Request and the AMF confirms the slice authentication
    Then the response status is 200
    And the authResult is "EAP_SUCCESS"
    And the eapMessage carries EAP code "Success"

  Scenario: Slice authentication with a null eapIdRsp starts the exchange with an EAP-Request/Identity
    When the AMF creates a slice authentication for GPSI "msisdn-34600000001" S-NSSAI sst 1 sd "000001" with a null eapIdRsp
    Then the response status is 201
    And the eapMessage carries EAP code "Request"

  Scenario: Confirmation for an unknown authCtxId is rejected with 404 CONTEXT_NOT_FOUND
    When the AMF confirms the unknown authCtxId "does-not-exist" for GPSI "msisdn-34600000001" S-NSSAI sst 1 sd "000001"
    Then the response status is 404
    And the problem cause is "CONTEXT_NOT_FOUND"

  Scenario: Confirmation with a mismatching S-NSSAI is rejected with 400 and the context is kept for the matching confirmation
    When the AMF creates a slice authentication for GPSI "msisdn-34600000001" S-NSSAI sst 1 sd "000001" with EAP identity "challenge-user@slice.example"
    Then the response status is 201
    When the UE answers the EAP-Request and the AMF confirms the slice authentication using S-NSSAI sst 2 sd "000002"
    Then the response status is 400
    And the problem cause is "MANDATORY_IE_INCORRECT"
    When the UE answers the EAP-Request and the AMF confirms the slice authentication
    Then the response status is 200
    And the authResult is "EAP_SUCCESS"

  Scenario: Slice authentication without the mandatory gpsi is rejected with 400 MANDATORY_IE_INCORRECT
    When the AMF creates a slice authentication without gpsi for S-NSSAI sst 1 sd "000001" with EAP identity "user@slice.example"
    Then the response status is 400
    And the problem cause is "MANDATORY_IE_INCORRECT"
    And the problem invalidParams names "/gpsi"

  Scenario: The legacy NSSAA relay route is unchanged
    When the AMF relays EAP identity "user@slice.example" to the legacy NSSAA route for "imsi-001010000000001"
    Then the response status is 200
    And the authResult is "EAP_SUCCESS"
    When the AMF relays EAP identity "reject-user@slice.example" to the legacy NSSAA route for "imsi-001010000000001"
    Then the response status is 200
    And the authResult is "EAP_FAILURE"
