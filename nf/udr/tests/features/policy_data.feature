Feature: Nudr_DataRepository Policy Data — SM Policy Data resource (TS 29.504 §5.2.13 / TS 29.519)
  As a PCF
  I want to read and write SM policy data through the UDR
  So that per-subscriber/per-DNN QoS policy is repository-backed and survives a PCF restart

  Background:
    Given a clean UDR instance is running

  Scenario: Provision and retrieve SM policy data
    When the PCF PUTs SM policy data for "imsi-001010000000001" slice "1-000001" dnn "internet" with 5qi 7
    Then the policy-data response status is 204
    When the PCF GETs SM policy data for "imsi-001010000000001"
    Then the policy-data response status is 200
    And the SM policy data has 5qi 7 for slice "1-000001" dnn "internet"

  Scenario: PATCH merges a new slice without dropping existing ones
    Given SM policy data for "imsi-001010000000001" slice "1-000001" dnn "internet" with 5qi 7 is provisioned
    When the PCF PATCHes SM policy data for "imsi-001010000000001" slice "2-000001" dnn "ims" with 5qi 1
    Then the policy-data response status is 204
    When the PCF GETs SM policy data for "imsi-001010000000001"
    Then the policy-data response status is 200
    And the SM policy data has 5qi 7 for slice "1-000001" dnn "internet"
    And the SM policy data has 5qi 1 for slice "2-000001" dnn "ims"

  Scenario: GET SM policy data for an unprovisioned subscriber is 404
    When the PCF GETs SM policy data for "imsi-001019999999999"
    Then the policy-data response status is 404

  Scenario: PATCH UE policy set updates the URSP rule precedence
    Given UE policy set for "imsi-001010000000001" with precedence 10 is provisioned
    When the PCF PATCHes UE policy set for "imsi-001010000000001" with precedence 5
    Then the policy-data response status is 204
    When the PCF GETs UE policy set for "imsi-001010000000001"
    Then the policy-data response status is 200
    And the UE policy set precedence is 5
