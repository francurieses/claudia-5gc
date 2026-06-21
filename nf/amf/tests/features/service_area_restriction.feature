Feature: Service Area Restriction enforcement (TS 23.501 §5.3.4)
  As a network operator
  I want the AMF to enforce Service Area Restrictions from PCF
  So that UEs cannot register from non-allowed Tracking Areas

  Scenario: Registration from an allowed TA succeeds
    Given the PCF grants access to TAC "000001" for the UE
    When the UE sends a Registration Request from TAC "000001"
    Then the AMF accepts the registration
    And the UE receives a Registration Accept

  Scenario: Registration from a restricted TA is rejected with cause 73
    Given the PCF only allows TAC "000001" for the UE
    When the UE sends a Registration Request from TAC "000002"
    Then the AMF rejects the registration
    And the UE receives a Registration Reject with 5GMM cause 73

  Scenario: No service area restriction means unrestricted access
    Given the PCF returns no service area restriction for the UE
    When the UE sends a Registration Request from any TAC
    Then the AMF accepts the registration
