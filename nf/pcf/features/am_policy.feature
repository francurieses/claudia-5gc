Feature: Npcf_AMPolicyControl — AM Policy Association (TS 29.507 §4.2.2)
  As an AMF
  I want to create an AM Policy Association with PCF at UE registration
  So that the RFSP index and service area restrictions can govern the UE's radio access

  Scenario: Successful AM policy association creation
    Given a PCF instance with default configuration
    When AMF creates an AM policy association for "imsi-001010000000001" with accessType "3GPP_ACCESS"
    Then the response status is 201
    And the response body contains a polAssoId
    And the Location header points to the AM policy resource

  Scenario: AM policy association delete
    Given a PCF instance with default configuration
    And an existing AM policy association for "imsi-001010000000001"
    When AMF deletes the AM policy association
    Then the delete response status is 204

  Scenario: Missing supi is rejected
    Given a PCF instance with default configuration
    When AMF creates an AM policy association without a supi
    Then the response status is 400
    And the cause is "MANDATORY_IE_MISSING"
