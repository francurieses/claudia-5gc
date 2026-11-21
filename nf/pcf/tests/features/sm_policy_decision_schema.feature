@functional @pcf-004
Feature: Npcf_SMPolicyControl — SmPolicyDecision schema conformance (PCF-004)
  As an SMF
  I want the SmPolicyDecision returned by Create and Update to match the OpenAPI schema
  So that strict consumers can decode QosData, Arp, SessionRule and PccRule without errors
  Spec: TS 29.512 §5.6.2.4 (SmPolicyDecision), §5.6.2.7 (PccRule), §5.6.2.8 (QosData),
        §5.6.2.9 (SessionRule); TS 29.571 §5.4.4.7 (Arp), §5.4.3.x (PreemptionCapability, PreemptionVulnerability)

  Background:
    Given a PCF instance with an existing SM policy for "imsi-001010000000001" on dnn "internet"

  Scenario: SmPolicyControl_Create 201 decision is schema-conformant
    When the SMF creates an SM policy for "imsi-001010000000001" on dnn "internet"
    Then the create response status is 201
    And every qosDecs entry has a qosId equal to its map key
    And every qosDecs Arp has a priorityLevel, a preemptCap in "NOT_PREEMPT,MAY_PREEMPT" and a preemptVuln in "NOT_PREEMPTABLE,PREEMPTABLE"
    And every sessRules entry has a sessRuleId equal to its map key
    And every pccRules entry has a pccRuleId equal to its map key
    And every pccRules entry has refQosData with exactly one item naming an existing qosDecs key
    And every pccRules flowInfos item uses "flowDescription" and never "flowDesc"
    And every pccRules flowInfos item has a non-empty "flowDescription"

  Scenario: SmPolicyControl_Update 200 decision is schema-conformant
    Given the PCF has no authorised 5QI restriction
    When the SMF requests an SM policy update with 5QI 7
    Then the update response status is 200
    And every qosDecs entry has a qosId equal to its map key
    And every qosDecs Arp has a priorityLevel, a preemptCap in "NOT_PREEMPT,MAY_PREEMPT" and a preemptVuln in "NOT_PREEMPTABLE,PREEMPTABLE"
    And every sessRules entry has a sessRuleId equal to its map key
    And every pccRules entry has a pccRuleId equal to its map key
    And every pccRules entry has refQosData with exactly one item naming an existing qosDecs key
    And every pccRules flowInfos item uses "flowDescription" and never "flowDesc"

  Scenario: Configured MAY_PREEMPT and PREEMPTABLE are echoed in the decision
    Given the PCF default SM policy has arp_preempt_cap "MAY_PREEMPT" and arp_preempt_vuln "PREEMPTABLE"
    When the SMF creates an SM policy for "imsi-001010000000001" on dnn "internet"
    Then the create response status is 201
    And every qosDecs Arp has preemptCap "MAY_PREEMPT" and preemptVuln "PREEMPTABLE"

  Scenario: Empty preempt configuration defaults to NOT_PREEMPT and NOT_PREEMPTABLE
    Given the PCF default SM policy has arp_preempt_cap "" and arp_preempt_vuln ""
    When the SMF creates an SM policy for "imsi-001010000000001" on dnn "internet"
    Then the create response status is 201
    And every qosDecs Arp has preemptCap "NOT_PREEMPT" and preemptVuln "NOT_PREEMPTABLE"

  Scenario: Empty configured flow description omits flowInfos from the PCC rule
    Given the PCF default SM policy has flow_description ""
    When the SMF creates an SM policy for "imsi-001010000000001" on dnn "internet"
    Then the create response status is 201
    And no pccRules entry has a flowInfos attribute
    And no flowInfos item with an empty "flowDescription" is emitted

  Scenario: Invalid arp_preempt_cap fails configuration validation
    When the PCF configuration is validated with default_sm_policy arp_preempt_cap "SOMETIMES"
    Then the configuration validation fails with an error naming "arp_preempt_cap"

  Scenario: Invalid arp_preempt_vuln fails configuration validation
    When the PCF configuration is validated with default_sm_policy arp_preempt_vuln "MAYBE"
    Then the configuration validation fails with an error naming "arp_preempt_vuln"
