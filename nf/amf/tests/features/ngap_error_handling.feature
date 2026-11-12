Feature: NGAP error handling — transfer syntax, abstract syntax and AP ID errors (TS 38.413 §10, §8.7.5)
  As an operator connecting real gNBs over N2
  I want the AMF to answer erroneous NGAP PDUs with ERROR INDICATION or a failure message as TS 38.413 §10 requires
  So that a malformed or partly not-understood PDU is never silently dropped or half-processed

  Background:
    Given the AMF NGAP server has a gNB connected over a fake SCTP association
    And the gNB has completed NG Setup
    And a UE is registered with AMF UE NGAP ID 1 and RAN UE NGAP ID 101 on that gNB

  # TS 38.413 §10.2 — transfer syntax error, IDs cannot be decoded -> non-UE-associated ERROR INDICATION
  Scenario: Undecodable NGAP PDU is answered with a non-UE-associated ERROR INDICATION cause transfer-syntax-error
    When the gNB sends a PDU of 7 random bytes that is not valid APER
    Then the AMF sends an ERROR INDICATION to the gNB
    And the ERROR INDICATION has Cause protocol "transfer-syntax-error"
    And the ERROR INDICATION contains neither AMF UE NGAP ID nor RAN UE NGAP ID
    And the AMF sends exactly 1 NGAP message to the gNB

  # TS 38.413 §10.3.4.2 — reject, initiating message without failure message (class 2), UE-associated
  Scenario: Unknown IE with criticality reject in UPLINK NAS TRANSPORT triggers ERROR INDICATION and the message is not processed
    When the gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID 1 and RAN UE NGAP ID 101 carrying an unknown IE id 65000 with criticality "reject"
    Then the AMF sends an ERROR INDICATION to the gNB
    And the ERROR INDICATION contains AMF UE NGAP ID 1 and RAN UE NGAP ID 101
    And the ERROR INDICATION Criticality Diagnostics has Procedure Code 46, Triggering Message "initiating message" and Procedure Criticality "ignore"
    And the Criticality Diagnostics lists IE id 65000 with IE Criticality "reject" and Type of Error "not-understood"
    And the ERROR INDICATION has Cause protocol "abstract-syntax-error-reject"
    And the NAS PDU of the UPLINK NAS TRANSPORT was not delivered to the NAS layer

  # TS 38.413 §10.3.4.2 — reject, initiating message with failure message
  Scenario: Unknown IE with criticality reject in HANDOVER REQUIRED triggers HANDOVER PREPARATION FAILURE with Criticality Diagnostics
    Given a second gNB has completed NG Setup
    When the gNB sends a HANDOVER REQUIRED for AMF UE NGAP ID 1 carrying an unknown IE id 65000 with criticality "reject"
    Then the AMF sends a HANDOVER PREPARATION FAILURE to the gNB
    And the HANDOVER PREPARATION FAILURE Criticality Diagnostics lists IE id 65000 with IE Criticality "reject" and Type of Error "not-understood"
    And the AMF sends no HANDOVER REQUEST to the second gNB
    And the AMF sends no ERROR INDICATION to the gNB

  # TS 38.413 §10.3.4.2 + §8.7.1.3 — reject in NG SETUP REQUEST: NG SETUP FAILURE with Cause + Criticality Diagnostics
  Scenario: Unknown IE with criticality reject in NG SETUP REQUEST triggers NG SETUP FAILURE with Criticality Diagnostics
    Given a new gNB association that has not yet performed NG Setup
    When that gNB sends an NG SETUP REQUEST carrying an unknown IE id 65000 with criticality "reject"
    Then the AMF sends an NG SETUP FAILURE on that association
    And the NG SETUP FAILURE has Cause protocol "abstract-syntax-error-reject"
    And the NG SETUP FAILURE Criticality Diagnostics lists IE id 65000 with IE Criticality "reject" and Type of Error "not-understood"
    And the AMF sends no ERROR INDICATION on that association
    And the gNB is not listed as "NG_READY"

  # TS 38.413 §10.3.4.2 — notify, class 2 initiating message: processed, then ERROR INDICATION
  Scenario: Unknown IE with criticality notify in UPLINK NAS TRANSPORT is processed and reported with ERROR INDICATION
    When the gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID 1 and RAN UE NGAP ID 101 carrying an unknown IE id 65000 with criticality "notify"
    Then the NAS PDU of the UPLINK NAS TRANSPORT was delivered to the NAS layer
    And the AMF sends an ERROR INDICATION to the gNB
    And the ERROR INDICATION contains AMF UE NGAP ID 1 and RAN UE NGAP ID 101
    And the ERROR INDICATION Criticality Diagnostics has Procedure Criticality "ignore"
    And the Criticality Diagnostics lists IE id 65000 with IE Criticality "notify" and Type of Error "not-understood"
    And the ERROR INDICATION has Cause protocol "abstract-syntax-error-ignore-and-notify"

  # TS 38.413 §10.3.4.2 — ignore: processed silently
  Scenario: Unknown IE with criticality ignore in UPLINK NAS TRANSPORT is processed silently
    When the gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID 1 and RAN UE NGAP ID 101 carrying an unknown IE id 65000 with criticality "ignore"
    Then the NAS PDU of the UPLINK NAS TRANSPORT was delivered to the NAS layer
    And the AMF sends no ERROR INDICATION to the gNB

  # TS 38.413 §10.3.4.2 — reject/notify/ignore matrix for a class 2 initiating message
  Scenario Outline: Unknown IE criticality matrix for UE CONTEXT RELEASE REQUEST (class 2 initiating message)
    When the gNB sends a UE CONTEXT RELEASE REQUEST for AMF UE NGAP ID 1 and RAN UE NGAP ID 101 carrying an unknown IE id 65001 with criticality "<criticality>"
    Then the message is processed with its understood IEs "<processed>"
    And the AMF sends an ERROR INDICATION "<error_indication>"

    Examples:
      | criticality | processed | error_indication |
      | reject      | no        | yes              |
      | notify      | yes       | yes              |
      | ignore      | yes       | no               |

  # TS 38.413 §10.3.4.2 — unknown IE in a response message
  Scenario: Unknown IE with criticality reject in a response message is local error handling without ERROR INDICATION
    Given the AMF has sent an INITIAL CONTEXT SETUP REQUEST for AMF UE NGAP ID 1
    When the gNB sends an INITIAL CONTEXT SETUP RESPONSE for AMF UE NGAP ID 1 and RAN UE NGAP ID 101 carrying an unknown IE id 65000 with criticality "reject"
    Then the AMF sends no ERROR INDICATION to the gNB
    And the Initial Context Setup procedure is marked as unsuccessfully terminated in the AMF log

  # TS 38.413 §10.3.5 — missing mandatory IE, reject, class 2 initiating message
  Scenario: Missing mandatory IE with criticality reject in UPLINK NAS TRANSPORT triggers ERROR INDICATION type of error missing
    When the gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID 1 and RAN UE NGAP ID 101 lacking the mandatory NAS-PDU IE id 38
    Then the AMF sends an ERROR INDICATION to the gNB
    And the ERROR INDICATION contains AMF UE NGAP ID 1 and RAN UE NGAP ID 101
    And the Criticality Diagnostics lists IE id 38 with IE Criticality "reject" and Type of Error "missing"
    And the ERROR INDICATION Criticality Diagnostics has Procedure Code 46 and Triggering Message "initiating message"
    And no NAS PDU is delivered to the NAS layer

  # TS 38.413 §10.3.5 — missing mandatory IE, reject, message with failure message
  Scenario: Missing mandatory IE with criticality reject in HANDOVER REQUIRED triggers HANDOVER PREPARATION FAILURE type of error missing
    Given a second gNB has completed NG Setup
    When the gNB sends a HANDOVER REQUIRED for AMF UE NGAP ID 1 lacking the mandatory Target ID IE id 105
    Then the AMF sends a HANDOVER PREPARATION FAILURE to the gNB
    And the HANDOVER PREPARATION FAILURE Criticality Diagnostics lists IE id 105 with IE Criticality "reject" and Type of Error "missing"

  # TS 38.413 §10.5 — an erroneous ERROR INDICATION is never answered with an ERROR INDICATION
  Scenario: Received ERROR INDICATION carrying an unknown IE with criticality reject is not answered
    When the gNB sends an ERROR INDICATION with Cause protocol "semantic-error" carrying an unknown IE id 65000 with criticality "reject"
    Then the AMF sends no ERROR INDICATION to the gNB
    And the AMF logs the received ERROR INDICATION without taking recovery action

  # TS 38.413 §10.5 — transfer syntax error in a PDU identifiable as ERROR INDICATION
  Scenario: Undecodable PDU identifiable as ERROR INDICATION is not answered
    When the gNB sends a truncated ERROR INDICATION PDU that fails APER decoding but has procedure code 9
    Then the AMF sends no ERROR INDICATION to the gNB
    And the AMF logs the transfer syntax error with spec_ref "TS 38.413 §10.2"

  # TS 38.413 §10.6, §8.7.5.2 — unknown local AP ID in a non-last UE-associated message
  Scenario: UPLINK NAS TRANSPORT with unknown AMF UE NGAP ID triggers ERROR INDICATION cause unknown-local-UE-NGAP-ID
    When the gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID 999 and RAN UE NGAP ID 555
    Then the AMF sends an ERROR INDICATION to the gNB
    And the ERROR INDICATION contains AMF UE NGAP ID 999 and RAN UE NGAP ID 555
    And the ERROR INDICATION has Cause radio network "unknown-local-UE-NGAP-ID"
    And the UE with AMF UE NGAP ID 1 is still registered

  # TS 38.413 §10.6 — last message of a procedure: local release only
  Scenario: UE CONTEXT RELEASE COMPLETE with unknown AMF UE NGAP ID is released locally without ERROR INDICATION
    When the gNB sends a UE CONTEXT RELEASE COMPLETE for AMF UE NGAP ID 999 and RAN UE NGAP ID 555
    Then the AMF sends no ERROR INDICATION to the gNB

  # TS 38.413 §10 — regression: well-formed PDUs must not produce ERROR INDICATION
  Scenario: Well-formed UPLINK NAS TRANSPORT is processed and produces no ERROR INDICATION
    When the gNB sends a well-formed UPLINK NAS TRANSPORT for AMF UE NGAP ID 1 and RAN UE NGAP ID 101
    Then the NAS PDU of the UPLINK NAS TRANSPORT was delivered to the NAS layer
    And the AMF sends no ERROR INDICATION to the gNB
    And the AMF sends 0 NGAP messages to the gNB
