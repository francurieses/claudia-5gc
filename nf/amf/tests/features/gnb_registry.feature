Feature: gNB registry — NG Setup decode and TNL association lifecycle (TS 38.413 §8.7.1)
  As an operator using the management portal or MCP
  I want the AMF to report every gNB connected over N2 with its identity, address and status
  So that I can see which RAN nodes are attached in any deployment mode

  Background:
    Given the AMF gNB registry is empty

  # TS 38.413 §8.7.1 — NG Setup completes, the gNB becomes operational
  Scenario: A gNB completes NG Setup and is listed as NG_READY
    Given a gNB with ID 1 (32 bits) named "gnb-a" connects from "172.30.1.20" port 48211
    When the gNB completes NG Setup with TAC 1 and slice SST 1 SD "000001"
    Then the gNB list contains 1 gNB
    And gNB "gnb-a" has state "NG_READY"
    And gNB "gnb-a" reports PLMN "001"/"01", gNB ID 1 with bit length 32 and TAC 1 with slice SST 1 SD "000001"
    And gNB "gnb-a" reports remote address "172.30.1.20" port 48211

  # TS 38.413 §8.7.1 — the association exists but NG Setup has not happened yet
  Scenario: An SCTP association without NG Setup is listed as SCTP_UP
    Given a gNB named "gnb-b" connects from "172.30.1.21" port 48212
    Then gNB "gnb-b" has state "SCTP_UP"

  # TS 38.412 §7 — association loss
  Scenario: A closed association is kept as DISCONNECTED and pruned after the retention window
    Given a gNB named "gnb-a" is NG_READY
    When the SCTP association closes with reason "sctp_closed"
    Then gNB "gnb-a" has state "DISCONNECTED" with reason "sctp_closed"
    When 16 minutes pass
    Then the gNB list contains 0 gNBs

  Scenario: The same gNB reconnecting shows as a single row
    Given a gNB named "gnb-a" is NG_READY
    And the SCTP association closes with reason "sctp_closed"
    When a gNB with the same ID reconnects and completes NG Setup
    Then the gNB list contains 1 gNB
    And gNB "gnb-a" has state "NG_READY"

  # TS 38.413 §8.7.4 — observed only, no acknowledge
  Scenario: An NG Reset is recorded without changing the state
    Given a gNB named "gnb-a" is NG_READY
    When the gNB sends an NG Reset
    Then gNB "gnb-a" has state "NG_READY"
    And gNB "gnb-a" reports 1 NG Reset

  Scenario: The management endpoint returns an empty array when no gNB is connected
    When I request the gNB list from the management API
    Then the gNB list response status is 200
    And the gNB list response has an empty "gnbs" array
