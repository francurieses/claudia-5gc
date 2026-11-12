# SBI feature negotiation — AMF as Nsmf_PDUSession consumer and Namf_Communication producer
# (TS 29.500 §6.6.2 supportedFeatures negotiation, §5.2.7.2 schema-violating IE
#  -> 400 INVALID_MSG_FORMAT; TS 29.571 §5.2.2 SupportedFeatures; TS 29.502
#  SmContextCreateData / SmContextCreatedData; TS 29.518 UeContextTransferReqData /
#  UeContextTransferRspData)
#
# Design contract: docs/procedures/feature-negotiation.md (rules R1-R15).
# Release profile gates wire behaviour. D1 (producer, Namf_Communication): under
# rel17 (default, frozen baseline) a request with absent/"" supportedFeatures gets a
# response WITHOUT supportedFeatures; under rel19 the response always carries it
# ("0" when nothing is negotiated); a non-empty value (incl. "0") is answered with
# the intersection under both; non-hex -> 400 INVALID_MSG_FORMAT under both.
# D2 (consumer, Nsmf_PDUSession): a rel17 AMF sends NO supportedFeatures in
# SmContextCreateData (byte-identical to today), so its negotiated set is "0"
# whatever the SMF answers (R14); a rel19 AMF sends its offered set.
# F1 is a symbolic feature present since Rel-17 (bit 1), F9 a symbolic feature
# introduced in Rel-19 (bit 9). Wire form: lowercase hex, leading zeros trimmed,
# empty set = "0" (F1 = "1", F9 = "100", F1+F9 = "101"). Real per-API feature
# tables arrive with REL19-2.7. There is no "mandatory feature missing" rejection.

@rel19 @feature-negotiation
Feature: AMF feature negotiation (supportedFeatures) as SMF consumer and as Namf producer
  As the AMF
  I want to offer my supportedFeatures to the SMF and answer other AMFs' offers with the intersection
  So that Rel-19 behaviour is used only when the peer signals support, and legacy peers get baseline behaviour

  Background:
    Given a test Nsmf_PDUSession feature catalog where F1 is bit 1 (Rel-17) and F9 is bit 9 (Rel-19)
    And a test Namf_Communication feature catalog where F1 is bit 1 (Rel-17) and F9 is bit 9 (Rel-19)

  # ---- AMF as Nsmf_PDUSession consumer (R1, R2, R11, R12, R13) ----

  # R1 — Rel-19 AMF <-> Rel-17 SMF (mock)
  @nsmf-consumer
  Scenario: Rel-19 AMF offers F1 and F9 and a Rel-17 SMF answers F1
    Given the AMF runs with release profile "rel19"
    And a mock SMF answers CreateSMContext with 201 and supportedFeatures "1"
    When the AMF creates an SM context for PDU session 1
    Then the mock SMF received supportedFeatures "101" in SmContextCreateData
    And the AMF stores the negotiated feature set "1" on PDU session 1
    And the AMF sends no F9-tied IE in later SmContextUpdateData for PDU session 1
    And a consumer FeatureNegotiation log has features_local "101", features_peer "1", features_negotiated "1" and result "OK"
    And the AMF FeatureNegotiation counter with result "OK" increased by 1

  # R2, R14 (D2) — rel17-profile AMF sends no supportedFeatures, so nothing is negotiated whatever the SMF answers
  @nsmf-consumer
  Scenario: Rel-17 AMF sends no supportedFeatures to a Rel-19 SMF and negotiates the empty set
    Given the AMF runs with release profile "rel17"
    And a mock SMF answers CreateSMContext with 201 and supportedFeatures "1"
    When the AMF creates an SM context for PDU session 1
    Then the mock SMF received SmContextCreateData without a supportedFeatures attribute
    And the mock SMF received a request body byte-identical to the pre-negotiation baseline
    And the AMF stores the negotiated feature set "0" on PDU session 1

  # R11 — extra bits in the answer are ignored (rel19 offers "101"; feature 40 (top bit of "8000000101") was never offered)
  @nsmf-consumer
  Scenario: SMF answer containing a bit the AMF never offered is ignored
    Given the AMF runs with release profile "rel19"
    And a mock SMF answers CreateSMContext with 201 and supportedFeatures "8000000101"
    When the AMF creates an SM context for PDU session 1
    Then the mock SMF received supportedFeatures "101" in SmContextCreateData
    And the AMF stores the negotiated feature set "101" on PDU session 1

  # R12 — legacy producer
  @nsmf-consumer
  Scenario: Legacy SMF answering without supportedFeatures leaves the negotiated set empty
    Given the AMF runs with release profile "rel19"
    And a mock SMF answers CreateSMContext with 201 and no supportedFeatures
    When the AMF creates an SM context for PDU session 1
    Then the PDU session establishment succeeds
    And the AMF stores the negotiated feature set "0" on PDU session 1
    And the AMF sends no F9-tied IE in later SmContextUpdateData for PDU session 1

  # R13 — fail closed, do not fail the procedure
  @nsmf-consumer
  Scenario: SMF answer with non-hex supportedFeatures is treated as no features without failing the session
    Given the AMF runs with release profile "rel19"
    And a mock SMF answers CreateSMContext with 201 and supportedFeatures "zz"
    When the AMF creates an SM context for PDU session 1
    Then the PDU session establishment succeeds
    And the AMF stores the negotiated feature set "0" on PDU session 1
    And a consumer FeatureNegotiation log has features_peer "zz" and result "FAILURE"
    And the AMF FeatureNegotiation counter with result "FAILURE" increased by 1

  # TS 29.500 §6.6.2 — unknown attributes ignored
  @nsmf-consumer
  Scenario: Unknown JSON attributes in SmContextCreatedData are tolerated
    Given the AMF runs with release profile "rel19"
    And a mock SMF answers CreateSMContext with 201, supportedFeatures "1" and an unknown JSON attribute "futureRel20Attr"
    When the AMF creates an SM context for PDU session 1
    Then the PDU session establishment succeeds
    And the AMF stores the negotiated feature set "1" on PDU session 1

  # ---- AMF as Namf_Communication producer (UEContextTransfer custom operation) ----

  @namf-producer
  Scenario Outline: Old AMF answers a UEContextTransfer offer with the intersection
    Given the AMF runs with release profile "<profile>"
    And the AMF inbound namf-comm SBI server is running for feature negotiation
    And a UE "imsi-001010000000001" is registered with an active NAS security context for feature negotiation
    When a new AMF POSTs a UEContextTransfer request with reason "MOBI_REG" and supportedFeatures "<offer>"
    Then the UEContextTransfer response is 200 with supportedFeatures "<answer>"
    And a producer FeatureNegotiation log has features_peer "<offer>", features_negotiated "<answer>" and result "OK"
    And the AMF FeatureNegotiation counter with result "OK" increased by 1

    Examples:
      | profile | offer      | answer |
      | rel19   | 101        | 101    |
      | rel17   | 101        | 1      |
      | rel19   | 1          | 1      |
      | rel19   | 1B         | 1      |
      | rel19   | 8000000001 | 1      |
      | rel19   | 0          | 0      |

  # D1 — rel19 profile: response always carries supportedFeatures
  @namf-producer
  Scenario: Rel-19 profile: UEContextTransfer without supportedFeatures is answered with baseline "0"
    Given the AMF runs with release profile "rel19"
    And the AMF inbound namf-comm SBI server is running for feature negotiation
    And a UE "imsi-001010000000001" is registered with an active NAS security context for feature negotiation
    When a new AMF POSTs a UEContextTransfer request with reason "MOBI_REG" and no supportedFeatures
    Then the UEContextTransfer response is 200 with supportedFeatures "0"

  # D1 — rel17 profile: frozen baseline, response without supportedFeatures (today's bytes)
  @namf-producer
  Scenario: Rel-17 profile: UEContextTransfer without supportedFeatures is answered without supportedFeatures
    Given the AMF runs with release profile "rel17"
    And the AMF inbound namf-comm SBI server is running for feature negotiation
    And a UE "imsi-001010000000001" is registered with an active NAS security context for feature negotiation
    When a new AMF POSTs a UEContextTransfer request with reason "MOBI_REG" and no supportedFeatures
    Then the UEContextTransfer response is 200
    And the UeContextTransferRspData has no supportedFeatures attribute

  @namf-producer
  Scenario: UEContextTransfer with unknown JSON attributes is tolerated
    Given the AMF runs with release profile "rel19"
    And the AMF inbound namf-comm SBI server is running for feature negotiation
    And a UE "imsi-001010000000001" is registered with an active NAS security context for feature negotiation
    When a new AMF POSTs a UEContextTransfer request with reason "MOBI_REG", supportedFeatures "1" and an unknown JSON attribute "futureRel20Attr"
    Then the UEContextTransfer response is 200 with supportedFeatures "1"

  # Error path: TS 29.500 §5.2.7.2
  @namf-producer
  Scenario Outline: UEContextTransfer with non-hex supportedFeatures is rejected with 400 INVALID_MSG_FORMAT
    Given the AMF runs with release profile "rel19"
    And the AMF inbound namf-comm SBI server is running for feature negotiation
    And a UE "imsi-001010000000001" is registered with an active NAS security context for feature negotiation
    When a new AMF POSTs a UEContextTransfer request with reason "MOBI_REG" and supportedFeatures "<offer>"
    Then the UEContextTransfer response is 400 with ProblemDetails cause "INVALID_MSG_FORMAT" and invalidParams first param "/supportedFeatures"
    And the old AMF does not mark the UE context as transferred for feature negotiation
    And a producer FeatureNegotiation log has features_peer "<offer>", cause "INVALID_MSG_FORMAT", spec_ref "TS 29.500 §5.2.7.2" and result "REJECT"
    And the AMF FeatureNegotiation counter with result "REJECT" increased by 1

    Examples:
      | offer |
      | zz    |
      | 0x1   |

  # Fallback: no rejection for a peer lacking features
  @namf-producer
  Scenario: UEContextTransfer from a peer lacking every supported feature is not rejected
    Given the AMF runs with release profile "rel19"
    And the AMF inbound namf-comm SBI server is running for feature negotiation
    And a UE "imsi-001010000000001" is registered with an active NAS security context for feature negotiation
    When a new AMF POSTs a UEContextTransfer request with reason "MOBI_REG" and supportedFeatures "2"
    Then the UEContextTransfer response is 200 with supportedFeatures "0"
