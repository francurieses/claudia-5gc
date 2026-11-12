Feature: Service Area Restriction enforcement (TS 23.501 §5.3.4, TS 24.501 §5.3.5, §5.6.1.5)
  As a network operator
  I want the AMF to convey and enforce Service Area Restrictions from PCF
  So that a UE in a Non-Allowed Area may register but cannot start signalling/data services

  Scenario: Registration from an allowed TA succeeds
    Given the PCF grants access to TAC "000001" for the UE
    When the UE sends a Registration Request from TAC "000001"
    Then the AMF accepts the registration
    And the Registration Accept carries a Service area list of the allowed area with TAC "000001"

  Scenario: Registration from a restricted TA is accepted with the service area list
    Given the PCF only allows TAC "000001" for the UE
    When the UE sends a Registration Request from TAC "000002"
    Then the AMF accepts the registration
    And the Registration Accept carries a Service area list of the allowed area with TAC "000001"

  Scenario: Registration from a non-allowed TA is accepted with the non-allowed area list
    Given the PCF marks TAC "000002" as a non-allowed area for the UE
    When the UE sends a Registration Request from TAC "000002"
    Then the AMF accepts the registration
    And the Registration Accept carries a Service area list of the non-allowed area with TAC "000002"

  Scenario: No service area restriction means unrestricted access
    Given the PCF returns no service area restriction for the UE
    When the UE sends a Registration Request from any TAC
    Then the AMF accepts the registration
    And the Registration Accept carries no Service area list

  Scenario: Service Request for signalling from a non-allowed TA is rejected with cause 28
    Given the PCF marks TAC "000002" as a non-allowed area for the UE
    When a registered UE in TAC "000002" sends a Service Request with service type "signalling"
    Then the AMF sends a Service Reject with 5GMM cause 28
    And the AMF sends no Initial Context Setup Request

  Scenario: Service Request for mobile terminated services from a non-allowed TA continues
    Given the PCF marks TAC "000002" as a non-allowed area for the UE
    When a registered UE in TAC "000002" sends a Service Request with service type "mobile terminated services"
    Then the AMF sends an Initial Context Setup Request carrying the Service Accept
