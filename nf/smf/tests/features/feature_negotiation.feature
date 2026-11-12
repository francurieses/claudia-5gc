# SBI feature negotiation — Nsmf_PDUSession producer side (SMF)
# (TS 29.500 §6.6.2 supportedFeatures negotiation, §5.2.7.2 schema-violating IE
#  -> 400 INVALID_MSG_FORMAT; TS 29.571 §5.2.2 SupportedFeatures; TS 29.502
#  SmContextCreateData / SmContextCreatedData)
#
# Design contract: docs/procedures/feature-negotiation.md (rules R1-R10).
# Release profile gates wire behaviour (decision D1): under profile rel17 (default,
# frozen baseline) a request whose supportedFeatures is absent or "" is answered
# WITHOUT supportedFeatures (today's bytes); under rel19 the response always carries
# it ("0" when nothing is negotiated). Rules R5/R6/R7 are therefore profile-gated.
# A non-empty offer (including "0", "000") is answered with the intersection under
# both profiles; non-hex -> 400 INVALID_MSG_FORMAT under both.
# F1 is a symbolic feature present since Rel-17 (bit 1), F9 a symbolic feature
# introduced in Rel-19 (bit 9). Wire form: lowercase hex, leading zeros trimmed,
# empty set = "0" (F1 = "1", F9 = "100", F1+F9 = "101"). Real per-API feature
# tables arrive with REL19-2.7. There is NO "mandatory feature missing"
# rejection in TS 29.500 §6.6.2: the only error path is a non-hex value.

@rel19 @feature-negotiation
Feature: SMF feature negotiation on CreateSMContext (supportedFeatures)
  As the SMF acting as Nsmf_PDUSession producer
  I want to answer the AMF's supportedFeatures offer with the intersection of both sides
  So that Rel-18/19 behaviour is enabled only when the AMF signals support and Rel-17 peers keep baseline behaviour

  Background:
    Given a test Nsmf_PDUSession feature catalog where F1 is bit 1 (Rel-17) and F9 is bit 9 (Rel-19)
    And the SMF SBI server is running for feature negotiation

  # R2 — Rel-17 AMF <-> Rel-19 SMF
  Scenario: Rel-17 AMF offering only F1 to a Rel-19 SMF negotiates F1 alone
    Given the SMF runs with release profile "rel19"
    When the AMF POSTs CreateSMContext with supportedFeatures "1"
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is "1"
    And the SM context stores the negotiated feature set "1"
    And the SMF sends no F9-tied IE in responses for that SM context
    And a FeatureNegotiation log has features_local "101", features_peer "1", features_negotiated "1" and result "OK"
    And the FeatureNegotiation counter with result "OK" increased by 1

  # R1 — Rel-19 AMF <-> Rel-17 SMF
  Scenario: Rel-19 AMF offering F1 and F9 to a Rel-17 SMF negotiates F1 alone
    Given the SMF runs with release profile "rel17"
    When the AMF POSTs CreateSMContext with supportedFeatures "101"
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is "1"
    And the SM context stores the negotiated feature set "1"
    And a FeatureNegotiation log has features_local "1", features_peer "101", features_negotiated "1" and result "OK"

  # R3 — both Rel-19
  Scenario: Rel-19 AMF and Rel-19 SMF negotiate F1 and F9
    Given the SMF runs with release profile "rel19"
    When the AMF POSTs CreateSMContext with supportedFeatures "101"
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is "101"
    And the SM context stores the negotiated feature set "101"

  # R4 — intersection respected, undefined bits never echoed
  Scenario: Undefined high bit in the offer is dropped from the intersection
    Given the SMF runs with release profile "rel19"
    When the AMF POSTs CreateSMContext with supportedFeatures "8000000001"
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is "1"
    And the SM context stores the negotiated feature set "1"

  # R5, R6, R7 (profile-gated, D1) — rel19 profile: spec-literal, response always carries supportedFeatures
  Scenario Outline: Rel-19 profile: empty or absent offer yields baseline behaviour and "0" in the response
    Given the SMF runs with release profile "rel19"
    When the AMF POSTs CreateSMContext with supportedFeatures <offer>
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is "0"
    And the SM context stores the negotiated feature set "0"
    And the SMF sends no F9-tied IE in responses for that SM context
    And a FeatureNegotiation log has features_negotiated "0" and result "OK"

    Examples:
      | offer                     |
      | absent                    |
      | ""                        |
      | "0"                       |
      | "000"                     |

  # R5, R6 (profile-gated, D1) — rel17 profile: frozen baseline, response byte-identical to today (no supportedFeatures)
  Scenario Outline: Rel-17 profile: absent or empty offer yields a response without supportedFeatures
    Given the SMF runs with release profile "rel17"
    When the AMF POSTs CreateSMContext with supportedFeatures <offer>
    Then the SMF responds 201 Created
    And the SmContextCreatedData has no supportedFeatures attribute
    And the SM context stores the negotiated feature set "0"
    And the SmContextCreatedData is byte-identical to the pre-negotiation baseline
    And the SMF sends no F9-tied IE in responses for that SM context

    Examples:
      | offer  |
      | absent |
      | ""     |

  # R7 (profile-gated, D1) — rel17 profile: an explicit value, even "0", is non-empty and is answered with the intersection
  Scenario: Rel-17 profile: explicit offer "0" is still answered "0"
    Given the SMF runs with release profile "rel17"
    When the AMF POSTs CreateSMContext with supportedFeatures "0"
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is "0"
    And the SM context stores the negotiated feature set "0"

  # R8 — case-insensitive parse, canonical output
  Scenario Outline: Uppercase and leading-zero offers are accepted and answered in canonical lowercase hex
    Given the SMF runs with release profile "rel19"
    When the AMF POSTs CreateSMContext with supportedFeatures <offer>
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is <answer>

    Examples:
      | offer   | answer |
      | "101"   | "101"  |
      | "0001"  | "1"    |
      | "00101" | "101"  |
      | "1B"    | "1"    |

  # TS 29.500 §6.6.2 — unknown attributes and values shall be ignored
  Scenario: Unknown JSON attributes in SmContextCreateData are tolerated
    Given the SMF runs with release profile "rel19"
    When the AMF POSTs CreateSMContext with supportedFeatures "1" and an unknown JSON attribute "futureRel20Attr"
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is "1"
    And the unknown attribute "futureRel20Attr" is not echoed in the SmContextCreatedData

  # Error path: R10 / TS 29.500 §5.2.7.2
  Scenario Outline: Non-hex supportedFeatures is rejected with 400 INVALID_MSG_FORMAT
    Given the SMF runs with release profile "rel19"
    When the AMF POSTs CreateSMContext with supportedFeatures <offer>
    Then the SMF responds 400 Bad Request
    And the ProblemDetails cause is "INVALID_MSG_FORMAT"
    And the ProblemDetails invalidParams first param is "/supportedFeatures"
    And no SM context is created
    And a FeatureNegotiation log has features_peer <offer>, cause "INVALID_MSG_FORMAT", spec_ref "TS 29.500 §5.2.7.2" and result "REJECT"
    And the FeatureNegotiation counter with result "REJECT" increased by 1

    Examples:
      | offer  |
      | "zz"   |
      | "0x1"  |
      | "1 01" |

  # Fallback: no rejection for a peer lacking features — rule "no mandatory feature missing"
  Scenario: Peer lacking every feature the SMF supports is not rejected
    Given the SMF runs with release profile "rel19"
    When the AMF POSTs CreateSMContext with supportedFeatures "2"
    Then the SMF responds 201 Created
    And the SmContextCreatedData supportedFeatures is "0"
    And the SM context stores the negotiated feature set "0"
