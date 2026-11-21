@AMF-008
Feature: NG Reset initiated by the NG-RAN node — NG RESET ACKNOWLEDGE and UE-associated release (TS 38.413 §8.7.4.2.2)
  As a gNB that lost UE-associated NG state
  I want the AMF to release the indicated UE-associated logical NG-connections and acknowledge
  So that the affected UEs become CM-IDLE, stay 5GMM-REGISTERED and can be reached again by paging

  # Design: docs/procedures/NGReset.md. NG RESET is non-UE-associated (procedure code 20, class 1,
  # no UnsuccessfulOutcome). No NAS message and no 5GMM/5GSM cause applies; causes below are NGAP causes.
  # The AMF never sends UE CONTEXT RELEASE COMMAND for the reset associations (release is local).

  Background:
    Given a gNB named "gnb-a" is NG_READY
    And a UE "imsi-001010000000001" is registered with an active NAS security context
    And the UE has an established PDU session 1 on DNN "internet"
    And the UE is CM-CONNECTED
    And the UE is served by gNB "gnb-a"
    And an SMF mock records Nsmf UpdateSMContext requests

  # TS 38.413 §8.7.4.2.2, §9.2.6.1, §9.2.6.2; TS 23.501 §5.3.3.2
  Scenario: NG Reset reset-all is answered with NG Reset Acknowledge without a UE list and all UEs of the gNB go CM-IDLE
    Given a second UE "imsi-001010000000002" is registered, CM-CONNECTED and served by gNB "gnb-a"
    When gNB "gnb-a" sends an NG Reset with Reset Type nG-Interface reset-all
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the NG RESET ACKNOWLEDGE is sent with SCTP PPID 60
    And the NG RESET ACKNOWLEDGE carries no UE-associated Logical NG-connection List
    And the UE "imsi-001010000000001" becomes CM-IDLE within the test deadline
    And the UE "imsi-001010000000002" becomes CM-IDLE within the test deadline
    And the UE context is still present and RM-REGISTERED
    And gNB "gnb-a" has state "NG_READY"

  # TS 38.413 §8.7.4.2.2 "after it has released them" — the ACK follows the local release
  Scenario: NG Reset does not trigger UE CONTEXT RELEASE COMMAND for the reset associations
    When gNB "gnb-a" sends an NG Reset with Reset Type nG-Interface reset-all
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the AMF sends no UE CONTEXT RELEASE COMMAND
    And the AMF sends no ERROR INDICATION

  # TS 38.413 §8.7.4.2.2; docs/procedures/NGReset.md §4.2 / §5
  Scenario: NG Reset with a UE-associated logical NG-connection list releases only the listed UEs and echoes the list
    Given a second UE "imsi-001010000000002" is registered, CM-CONNECTED and served by gNB "gnb-a"
    And a third UE "imsi-001010000000003" is registered, CM-CONNECTED and served by gNB "gnb-a"
    When gNB "gnb-a" sends an NG Reset with Reset Type partOfNG-Interface listing the NGAP IDs of the UE "imsi-001010000000001" and only the RAN UE NGAP ID of the UE "imsi-001010000000002"
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the NG RESET ACKNOWLEDGE carries the same 2 list items in the same order with the same ID presence as the NG RESET
    And the UE "imsi-001010000000001" becomes CM-IDLE within the test deadline
    And the UE "imsi-001010000000002" becomes CM-IDLE within the test deadline
    And the UE "imsi-001010000000003" is still CM-CONNECTED
    And the UE "imsi-001010000000001" context is still present and RM-REGISTERED
    And the AMF sends no UE CONTEXT RELEASE COMMAND

  # TS 38.413 §8.7.4.2.2 "shall include also unknown UE-associated logical NG-connections"; §10.6 does not apply
  Scenario: NG Reset list items with unknown NGAP IDs are echoed in the acknowledge without release or Error Indication
    When gNB "gnb-a" sends an NG Reset with Reset Type partOfNG-Interface listing the NGAP IDs of the UE "imsi-001010000000001" followed by an unknown AMF UE NGAP ID 999999 and an unknown RAN UE NGAP ID 888
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the NG RESET ACKNOWLEDGE carries the same 3 list items in the same order with the same ID presence as the NG RESET
    And the UE becomes CM-IDLE within the test deadline
    And the AMF sends no ERROR INDICATION

  Scenario: NG Reset list containing only unknown NGAP IDs releases nothing and is still acknowledged
    When gNB "gnb-a" sends an NG Reset with Reset Type partOfNG-Interface listing only the unknown AMF UE NGAP ID 999999
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the NG RESET ACKNOWLEDGE carries the same 1 list items in the same order with the same ID presence as the NG RESET
    And the UE is still CM-CONNECTED
    And the AMF sends no ERROR INDICATION

  # docs/procedures/NGReset.md §5 (idempotent retry)
  Scenario: A repeated NG Reset for already released associations is acknowledged again and releases nothing
    Given gNB "gnb-a" sent an NG Reset with Reset Type partOfNG-Interface listing the NGAP IDs of the UE "imsi-001010000000001"
    When gNB "gnb-a" sends the same NG Reset again
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the NG RESET ACKNOWLEDGE carries the same 1 list items in the same order with the same ID presence as the NG RESET
    And the UE is still CM-IDLE

  # TS 38.413 §8.7.4.3 [VERIFY clause label]; docs/procedures/NGReset.md §5
  Scenario: NG Reset list item with neither AMF UE NGAP ID nor RAN UE NGAP ID is ignored and omitted from the acknowledge
    When gNB "gnb-a" sends an NG Reset with Reset Type partOfNG-Interface listing one item with neither AMF UE NGAP ID nor RAN UE NGAP ID
    Then the AMF sends no UE CONTEXT RELEASE COMMAND
    And the UE is still CM-CONNECTED
    And the NG RESET ACKNOWLEDGE carries no UE-associated Logical NG-connection List
    And the AMF sends no ERROR INDICATION

  # TS 38.413 §8.7.4.2.2 (reset is per NG interface)
  Scenario: NG Reset reset-all from one gNB leaves UEs served by another gNB untouched
    Given a gNB named "gnb-b" is NG_READY
    And a second UE "imsi-001010000000002" is registered, CM-CONNECTED and served by gNB "gnb-b"
    When gNB "gnb-a" sends an NG Reset with Reset Type nG-Interface reset-all
    Then the UE "imsi-001010000000001" becomes CM-IDLE within the test deadline
    And the UE "imsi-001010000000002" is still CM-CONNECTED

  Scenario: NG Reset listing the AMF UE NGAP ID of a UE served by another gNB treats it as unknown, echoes it and releases nothing
    Given a gNB named "gnb-b" is NG_READY
    And a second UE "imsi-001010000000002" is registered, CM-CONNECTED and served by gNB "gnb-b"
    When gNB "gnb-a" sends an NG Reset with Reset Type partOfNG-Interface listing only the AMF UE NGAP ID of the UE "imsi-001010000000002"
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the NG RESET ACKNOWLEDGE carries the same 1 list items in the same order with the same ID presence as the NG RESET
    And the UE "imsi-001010000000002" is still CM-CONNECTED

  # TS 23.502 §4.2.6 steps 5-7; TS 29.502 §5.2.2.3.2 (project decision, docs/procedures/NGReset.md §1)
  Scenario: NG Reset notifies the SMF with upCnxState DEACTIVATED once per PDU session of each released UE
    Given the UE has an established PDU session 2 on DNN "internet"
    When gNB "gnb-a" sends an NG Reset with Reset Type nG-Interface reset-all
    Then the UE becomes CM-IDLE within the test deadline
    And the AMF requests upCnxState "DEACTIVATED" from the SMF for PDU session 1 exactly once
    And the AMF requests upCnxState "DEACTIVATED" from the SMF for PDU session 2 exactly once

  Scenario: NG Reset does not notify the SMF for a UE that is not listed
    Given a second UE "imsi-001010000000002" is registered, CM-CONNECTED and served by gNB "gnb-a"
    When gNB "gnb-a" sends an NG Reset with Reset Type partOfNG-Interface listing the NGAP IDs of the UE "imsi-001010000000002"
    Then the UE "imsi-001010000000002" becomes CM-IDLE within the test deadline
    And the AMF sends no upCnxState "DEACTIVATED" request to the SMF for the UE "imsi-001010000000001"

  # docs/procedures/NGReset.md §5 (SMF failure does not undo the release)
  Scenario: SMF unreachable during NG Reset does not prevent the acknowledge or the CM-IDLE transition
    Given the SMF is not reachable
    When gNB "gnb-a" sends an NG Reset with Reset Type nG-Interface reset-all
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the UE becomes CM-IDLE within the test deadline
    And the UE context is still present and RM-REGISTERED
    And the AMF attempted the SMF deactivation of the UE "imsi-001010000000001" and the UE is still CM-IDLE

  # Acceptance criterion: gNB registry reflects the reset (TS 38.413 §8.7.4; project registry)
  Scenario: The gNB registry counts each NG Reset and the gNB stays NG_READY
    When gNB "gnb-a" sends an NG Reset with Reset Type nG-Interface reset-all
    And gNB "gnb-a" sends an NG Reset with Reset Type nG-Interface reset-all
    Then gNB "gnb-a" reports 2 NG Reset
    And gNB "gnb-a" has state "NG_READY"

  # TS 38.413 §10.3.5, §10.3.4.2, §8.7.5; docs/procedures/NGReset.md §5 — Reset Type (IE 88) is criticality reject
  Scenario: NG Reset without the mandatory Reset Type IE is rejected with ERROR INDICATION, no acknowledge and no release
    When gNB "gnb-a" sends an NG Reset without the Reset Type IE
    Then the AMF sends an ERROR INDICATION to gNB "gnb-a" with Cause protocol "abstract-syntax-error-reject"
    And the AMF sends no NG RESET ACKNOWLEDGE
    And the UE is still CM-CONNECTED
    And gNB "gnb-a" has recorded no NG Reset
    And the AMF sends no upCnxState "DEACTIVATED" request to the SMF

  # TS 38.413 §10.3.4.2 / §10.3.6 [VERIFY cause value]
  Scenario: NG Reset with an unknown Reset Type alternative is rejected with ERROR INDICATION and releases nothing
    When gNB "gnb-a" sends an NG Reset with an unknown Reset Type choice extension
    Then the AMF sends an ERROR INDICATION to gNB "gnb-a" with Cause protocol "abstract-syntax-error-reject"
    And the AMF sends no NG RESET ACKNOWLEDGE
    And the UE is still CM-CONNECTED

  # TS 38.413 §10.2 — SIZE(1..65536) violated by an empty list
  Scenario: NG Reset with an empty UE-associated logical NG-connection list is rejected as a transfer syntax error
    When gNB "gnb-a" sends an NG Reset with Reset Type partOfNG-Interface and an empty list
    Then the AMF sends an ERROR INDICATION to gNB "gnb-a" with Cause protocol "transfer-syntax-error"
    And the AMF sends no NG RESET ACKNOWLEDGE
    And the UE is still CM-CONNECTED

  # TS 38.413 §10.3.5 — Cause (IE 15) has criticality ignore
  Scenario: NG Reset without the Cause IE is processed normally
    When gNB "gnb-a" sends an NG Reset without the Cause IE with Reset Type nG-Interface reset-all
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the UE becomes CM-IDLE within the test deadline

  # docs/procedures/NGReset.md §5 (deregistration owns the sessions)
  Scenario: NG Reset of a UE with a deregistration in flight removes the context without SMF deactivation
    Given a deregistration is pending for the UE
    When gNB "gnb-a" sends an NG Reset with Reset Type nG-Interface reset-all
    Then the AMF sends an NG RESET ACKNOWLEDGE with procedure code 20 as SuccessfulOutcome
    And the UE context is removed
    And the AMF sends no UE CONTEXT RELEASE COMMAND
    And the AMF sends no upCnxState "DEACTIVATED" request to the SMF
