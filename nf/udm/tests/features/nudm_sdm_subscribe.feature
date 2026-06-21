Feature: Nudm_SDM Subscribe / Notify (TS 29.503 §5.3.2 / §5.3.3)
  As an AMF
  I want to subscribe to UDM for subscriber data change notifications
  So that I can refresh cached AM/SM data without restarting

  Background:
    Given a clean UDM instance is running

  Scenario: Successful subscription and notification delivery
    Given subscriber "imsi-001010000000001" exists
    And a callback listener is started
    When AMF subscribes to SDM changes for "imsi-001010000000001" with the callback URI
    Then the response status is 201
    And the response contains a subscriptionId
    And the Location header contains the subscriptionId
    When a data change is triggered for "imsi-001010000000001"
    Then the callback listener receives a ModificationNotification within 2 seconds

  Scenario: Unsubscribe stops future notifications
    Given subscriber "imsi-001010000000001" exists
    And a callback listener is started
    And AMF has subscribed to SDM changes for "imsi-001010000000001" with the callback URI
    When AMF unsubscribes using the subscriptionId
    Then the unsubscribe response status is 204
    When a data change is triggered for "imsi-001010000000001"
    Then the callback listener receives no notification within 500 milliseconds

  Scenario: Subscribe with missing callbackReference is rejected
    Given subscriber "imsi-001010000000001" exists
    When AMF subscribes without a callbackReference
    Then the response status is 400
    And the cause is "MANDATORY_IE_MISSING"
