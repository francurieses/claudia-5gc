Feature: Npcf_SMPolicyControl — SM Policy Association Update (TS 29.512 §5.2.2.3)
  As an SMF
  I want to consult the PCF when a PDU session's QoS is modified
  So that the PCF authorises or rejects the requested 5QI / Session-AMBR change

  Background:
    Given a PCF instance with an existing SM policy for "imsi-001010000000001" on dnn "internet"

  Scenario: PCF authorises a permitted 5QI change
    Given the PCF authorised 5QI set is "7,8,9"
    When the SMF requests an SM policy update with 5QI 7
    Then the update response status is 200
    And the decision 5QI is 7

  Scenario: PCF rejects a 5QI that is not authorised
    Given the PCF authorised 5QI set is "8,9"
    When the SMF requests an SM policy update with 5QI 1
    Then the update response status is 403
    And the update cause is "REQUESTED_QOS_NOT_AUTHORIZED"

  Scenario: PCF rejects a Session-AMBR over the configured ceiling
    Given the PCF max Session-AMBR is 100 Mbps
    When the SMF requests an SM policy update with uplink "500 Mbps"
    Then the update response status is 403
    And the update cause is "REQUESTED_QOS_NOT_AUTHORIZED"

  Scenario: No authorised set configured allows any valid 5QI
    Given the PCF has no authorised 5QI restriction
    When the SMF requests an SM policy update with 5QI 5
    Then the update response status is 200
    And the decision 5QI is 5

  Scenario: A per-subscriber override still wins over the requested value
    Given a per-subscriber override sets 5QI 2 for "imsi-001010000000001"
    When the SMF requests an SM policy update with 5QI 7
    Then the update response status is 200
    And the decision 5QI is 2

  Scenario: Update for an unknown smPolicyId is rejected
    When the SMF requests an SM policy update for an unknown smPolicyId
    Then the update response status is 404
    And the update cause is "CONTEXT_NOT_FOUND"
