Feature: Nudm_SDM Get AM data, subscribed UE-AMBR (TS 29.503 §5.2.2.2.3, TS 29.571 §5.5.2, TS 23.501 §5.7.2.6)
  As an AMF
  I want the UDM to serve the subscribed UE-AMBR provisioned in the UDR
  So that the UE-AMBR sent to the NG-RAN equals the subscription

  Background:
    Given a clean UDM instance is running
    And subscriber "imsi-001010000000001" exists

  Scenario: Provisioned subscribedUeAmbr in Kbps is passed through
    Given the UDR am-data for "imsi-001010000000001" has subscribedUeAmbr uplink "50000 Kbps" and downlink "200000 Kbps"
    When AMF sends GET am-data for "imsi-001010000000001"
    Then the response status is 200
    And the am-data subscribedUeAmbr uplink is "50000 Kbps"
    And the am-data subscribedUeAmbr downlink is "200000 Kbps"

  Scenario: BitRate units are converted to Kbps with ceiling rounding
    Given the UDR am-data for "imsi-001010000000001" has subscribedUeAmbr uplink "2 Gbps" and downlink "1.5 Mbps"
    When AMF sends GET am-data for "imsi-001010000000001"
    Then the response status is 200
    And the am-data subscribedUeAmbr uplink is "2000000 Kbps"
    And the am-data subscribedUeAmbr downlink is "1500 Kbps"

  Scenario: Decimal bps value is rounded up to the next Kbps
    Given the UDR am-data for "imsi-001010000000001" has subscribedUeAmbr uplink "1500 bps" and downlink "0.1 Gbps"
    When AMF sends GET am-data for "imsi-001010000000001"
    Then the response status is 200
    And the am-data subscribedUeAmbr uplink is "2 Kbps"
    And the am-data subscribedUeAmbr downlink is "100000 Kbps"

  Scenario: Absent subscribedUeAmbr falls back to the 100000 Kbps default
    Given the UDR am-data for "imsi-001010000000001" has no subscribedUeAmbr
    When AMF sends GET am-data for "imsi-001010000000001"
    Then the response status is 200
    And the am-data subscribedUeAmbr uplink is "100000 Kbps"
    And the am-data subscribedUeAmbr downlink is "100000 Kbps"

  Scenario: Malformed BitRate falls back to default for that direction only and logs a WARN
    Given the UDR am-data for "imsi-001010000000001" has subscribedUeAmbr uplink "100000Kbps" and downlink "300000 Kbps"
    When AMF sends GET am-data for "imsi-001010000000001"
    Then the response status is 200
    And the am-data subscribedUeAmbr uplink is "100000 Kbps"
    And the am-data subscribedUeAmbr downlink is "300000 Kbps"
    And the UDM logs a WARN with cause "MANDATORY_IE_INCORRECT" for direction "uplink"

  Scenario: Zero BitRate falls back to default for that direction and logs a WARN
    Given the UDR am-data for "imsi-001010000000001" has subscribedUeAmbr uplink "0 Kbps" and downlink "300000 Kbps"
    When AMF sends GET am-data for "imsi-001010000000001"
    Then the response status is 200
    And the am-data subscribedUeAmbr uplink is "100000 Kbps"
    And the am-data subscribedUeAmbr downlink is "300000 Kbps"
    And the UDM logs a WARN with cause "MANDATORY_IE_INCORRECT" for direction "uplink"

  Scenario: Overflowing BitRate above 1 Pbps falls back to default for that direction and logs a WARN
    Given the UDR am-data for "imsi-001010000000001" has subscribedUeAmbr uplink "300000 Kbps" and downlink "2000 Tbps"
    When AMF sends GET am-data for "imsi-001010000000001"
    Then the response status is 200
    And the am-data subscribedUeAmbr uplink is "300000 Kbps"
    And the am-data subscribedUeAmbr downlink is "100000 Kbps"
    And the UDM logs a WARN with cause "MANDATORY_IE_INCORRECT" for direction "downlink"

  Scenario: UDR returns 404 for am-data
    Given the UDR returns 404 for am-data of "imsi-001010000000001"
    When AMF sends GET am-data for "imsi-001010000000001"
    Then the response status is 404
    And the cause is "RESOURCE_URI_STRUCTURE_NOT_FOUND"
