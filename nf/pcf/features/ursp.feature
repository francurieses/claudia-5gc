Feature: URSP Policy Delivery (TS 23.503 §6.6 / TS 24.526 / TS 29.525)
  As a 5GC operator
  I want URSP rules to be delivered to UEs at registration and on-demand
  So that UEs route application traffic to the correct network slice

  Background:
    Given a running 5GC with PCF, AMF, UDR, and NRF
    And default URSP rules are configured in PCF dev.yaml
      | precedence | match_all | ssc_mode | sst | sd     | dnn      | pdu_type |
      | 255        | true      | 1        | 1   | 000001 | internet | 1        |

  Scenario: URSP delivered at registration via RegistrationAccept IEI 0x7B
    When UE "imsi-001010000000001" initiates Initial Registration
    Then PCF N15 creates a policy association for "imsi-001010000000001"
    And the RegistrationAccept contains IEI 0x7B with non-zero length
    And PCF logs contain "UEPolicyControl_Create responded"
    And AMF logs contain "policy_container_bytes"

  Scenario: Per-subscriber URSP override is used when available
    Given subscriber "imsi-001010000000001" has a policy override in UDR
      | precedence | dnn | sst | sd     |
      | 10         | ims | 1   | 000002 |
    When AMF calls PCF N15 for "imsi-001010000000001"
    Then PCF returns rules from UDR (not config defaults)
    And PCF logs contain "using per-subscriber URSP rules from UDR"

  Scenario: Operator pushes URSP update via UCU to a CM-CONNECTED UE
    Given UE "imsi-001010000000001" is MM-REGISTERED and CM-CONNECTED
    When the operator POSTs to "/amf/v1/ue-contexts/imsi-001010000000001/push-policies"
    Then the response status is 204
    And the AMF sends a ConfigurationUpdateCommand (0x54) with IEI 0x7B
    And the UE responds with ConfigurationUpdateComplete (0x55)
    And AMF logs contain "ConfigurationUpdateComplete received — URSP delivered"
    And AMF logs contain "ursp_version"

  Scenario: UCU returns 409 when UE is CM-IDLE
    Given UE "imsi-001010000000001" is MM-REGISTERED and CM-IDLE
    When the operator POSTs to "/amf/v1/ue-contexts/imsi-001010000000001/push-policies"
    Then the response status is 409
    And AMF logs contain "UE CM-IDLE — UCU deferred"

  Scenario: PCF falls back to config defaults when subscriber has no UDR override
    Given subscriber "imsi-001010000000002" has no policy override in UDR
    When AMF calls PCF N15 for "imsi-001010000000002"
    Then PCF logs contain "using config default URSP rules"
    And the returned uePolicySectionContent is non-empty

  Scenario: Registration succeeds even when PCF is unavailable
    Given PCF is stopped
    When UE "imsi-001010000000001" initiates Initial Registration
    Then the Registration Accept is sent without IEI 0x7B
    And AMF logs contain "PCF N15 CreateUEPolicyAssociation failed (non-fatal)"
    And UE reaches MM-REGISTERED state
