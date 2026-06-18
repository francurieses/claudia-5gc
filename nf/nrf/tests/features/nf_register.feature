Feature: NRF NF Registration (TS 29.510 §5.2.2.2)
  As an NF in the 5G Core
  I want to register my profile in the NRF
  So that other NFs can discover me

  Background:
    Given a clean NRF instance is running

  Scenario: Successful registration of an AMF
    Given an NF profile for AMF with instance id "00000000-0000-4000-8000-000000000010"
    When the NF sends an NFRegister request
    Then the NRF responds with status 201 Created
    And the response body contains the same nfInstanceId
    And the Location header is "/nnrf-nfm/v1/nf-instances/00000000-0000-4000-8000-000000000010"
    And the NF appears in subsequent NFDiscover queries for type "AMF"

  Scenario: Mismatched nfInstanceId between URI and body is rejected
    Given an NF profile for AMF with instance id "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    When the NF sends an NFRegister request to URI for "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    Then the NRF responds with status 400 Bad Request
    And the cause is "MANDATORY_IE_INCORRECT"

  Scenario: Discovery filters by service name
    Given two AMFs registered, only one advertises "namf-comm" service
    When an SMF queries NFDiscover for AMFs with service-names="namf-comm"
    Then exactly 1 NF instance is returned
