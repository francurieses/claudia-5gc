@AMF-037
Feature: UDM-triggered Network-initiated Deregistration (TS 23.502 §4.2.2.3.3, §4.11.1.3.2, §4.11.1.5.3; TS 24.501 §5.5.2.3)
  As the UDM revoking or invalidating a UE's AMF registration
  I want to send Nudm_UECM_DeregistrationNotification to the AMF
  So that the AMF de-registers the UE (explicitly or implicitly) and cleans up SM, PCF, SDM and N2 state

  # Design: docs/procedures/network-deregistration.md (§1.1 decision table, §5 error cases).
  # Callback: POST /namf-callback/v1/udm-uecm/dereg-notify/{supi} (TS 29.503 §5.3.2.3, §6.2.6.3.3).
  # The DEREGISTRATION REQUEST sent by the AMF never carries a 5GMM cause in this procedure.
  # The AMF never sends Nudm_UECM_Deregistration (UECM DELETE) back to the UDM in this procedure.

  Background:
    Given the AMF inbound namf-comm SBI server is running
    And a UE "imsi-001010000000001" is registered with an active NAS security context
    And the UE has an established PDU session 1 on DNN "internet"
    And an SMF mock records Nsmf ReleaseSMContext requests
    And a PCF mock records Npcf AM policy and UE policy delete requests
    And a UDM mock records Nudm SDM unsubscribe and UECM delete requests

  # TS 23.502 §4.2.2.3.3 steps 1-7; TS 24.501 §5.5.2.3.1; TS 29.503 §5.3.2.3
  Scenario: SUBSCRIPTION_WITHDRAWN for a CM-CONNECTED UE sends DEREGISTRATION REQUEST re-registration not required and releases SM and PCF right after the send
    Given the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "SUBSCRIPTION_WITHDRAWN"
    Then the response status is 204
    And the AMF sends exactly one DL NAS DEREGISTRATION REQUEST (UE terminated) to the UE
    And the DEREGISTRATION REQUEST de-registration type indicates "re-registration not required" and access type "3GPP access"
    And the DEREGISTRATION REQUEST carries no 5GMM cause IE
    And the DEREGISTRATION REQUEST is integrity protected and ciphered with SHT 2
    And the UE is in 5GMM-DEREGISTERED-INITIATED
    And the AMF releases the SM context of PDU session 1 at the SMF
    And the AMF deletes the AM policy association and the UE policy association at the PCF
    And the AMF unsubscribes the SDM subscription at the UDM exactly once
    And the AMF does not send a UECM DELETE to the UDM

  # TS 23.502 §4.2.2.3.3 step 7; TS 24.501 §5.5.2.3.2; TS 38.413 §9.3.1.2 (Cause nas/deregister)
  Scenario: DEREGISTRATION ACCEPT after UDM-triggered deregistration releases the N2 connection with cause nas deregister and removes the context
    Given the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    And the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "SUBSCRIPTION_WITHDRAWN"
    When the UE answers with a DEREGISTRATION ACCEPT
    Then the AMF sends a UE CONTEXT RELEASE COMMAND with Cause nas "deregister" to the serving gNB
    And the UE CONTEXT RELEASE COMMAND is sent with SCTP PPID 60
    And the UE is marked for removal
    And after the UE CONTEXT RELEASE COMPLETE the UE context is removed from the AMF
    And the AMF does not send a UECM DELETE to the UDM

  # TS 29.503 §6.2.6.3.3 (reRegistrationRequired); TS 24.501 §5.5.2.3.2
  Scenario: REREGISTRATION_REQUIRED for a CM-CONNECTED UE sends DEREGISTRATION REQUEST re-registration required
    Given the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "REREGISTRATION_REQUIRED"
    Then the response status is 204
    And the AMF sends exactly one DL NAS DEREGISTRATION REQUEST (UE terminated) to the UE
    And the DEREGISTRATION REQUEST de-registration type indicates "re-registration required" and access type "3GPP access"
    And the DEREGISTRATION REQUEST carries no 5GMM cause IE
    And the AMF releases the SM context of PDU session 1 at the SMF
    And the AMF deletes the AM policy association and the UE policy association at the PCF
    And the AMF unsubscribes the SDM subscription at the UDM exactly once
    And the AMF does not send a UECM DELETE to the UDM

  # TS 23.502 §4.2.2.3.3 step 2 (implicit de-registration); TS 24.501 §5.5.2.3.1 NOTE 1
  Scenario: SUBSCRIPTION_WITHDRAWN for a CM-IDLE UE de-registers implicitly without NAS or paging
    Given the UE is CM-IDLE
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "SUBSCRIPTION_WITHDRAWN"
    Then the response status is 204
    And the AMF sends no NAS message to the UE
    And the AMF sends no NGAP Paging
    And the AMF releases the SM context of PDU session 1 at the SMF
    And the AMF deletes the AM policy association and the UE policy association at the PCF
    And the AMF unsubscribes the SDM subscription at the UDM exactly once
    And the AMF does not send a UECM DELETE to the UDM
    And the UE context is removed from the AMF

  # TS 23.502 §4.2.2.3.3 step 2 (implicit); TS 29.503 §6.2.6.3.3
  Scenario: REREGISTRATION_REQUIRED for a CM-IDLE UE de-registers implicitly without NAS or paging
    Given the UE is CM-IDLE
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "REREGISTRATION_REQUIRED"
    Then the response status is 204
    And the AMF sends no NAS message to the UE
    And the AMF sends no NGAP Paging
    And the AMF releases the SM context of PDU session 1 at the SMF
    And the UE context is removed from the AMF

  # TS 23.502 §4.11.1.3.2 step 15, §4.11.1.5.3 step 13: SM contexts are kept (moved to EPS by the SMF+PGW-C)
  Scenario Outline: EPS interworking deregReason <reason> keeps SM contexts, terminates PCF associations and removes the context silently
    Given the UE is <cm_state>
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "<reason>"
    Then the response status is 204
    And the AMF sends no NAS message to the UE
    And the AMF sends no Nsmf ReleaseSMContext for PDU session 1
    And the AMF deletes the AM policy association and the UE policy association at the PCF
    And the AMF unsubscribes the SDM subscription at the UDM exactly once
    And the AMF does not send a UECM DELETE to the UDM
    And the UE context is removed from the AMF

    Examples:
      | reason                                           | cm_state       |
      | 5GS_TO_EPS_MOBILITY                              | CM-IDLE        |
      | 5GS_TO_EPS_MOBILITY                              | CM-CONNECTED   |
      | 5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION      | CM-IDLE        |
      | 5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION      | CM-CONNECTED   |

  # AMF is 3GPP-only: no non-3GPP registration exists (docs §1.1 last row)
  Scenario: dereg-notify with accessType NON_3GPP_ACCESS is a no-op answered 204
    Given the UE is CM-CONNECTED
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "SUBSCRIPTION_WITHDRAWN" and accessType "NON_3GPP_ACCESS"
    Then the response status is 204
    And the AMF sends no NAS message to the UE
    And the AMF sends no Nsmf ReleaseSMContext for PDU session 1
    And the AMF sends no Npcf delete and no Nudm SDM unsubscribe
    And the UE context is intact and the UE remains 5GMM-REGISTERED

  # Spec-deviation rejection: TS 29.503 §6.2.6.3.3 deregReason is mandatory in DeregistrationData
  Scenario: dereg-notify without deregReason is rejected with 400 MANDATORY_IE_MISSING
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with a body lacking deregReason
    Then the response status is 400
    And the ProblemDetails cause is "MANDATORY_IE_MISSING"
    And the AMF sends no NAS message to the UE
    And the AMF sends no Nsmf ReleaseSMContext for PDU session 1
    And the UE context is intact and the UE remains 5GMM-REGISTERED

  # Spec-deviation rejection: TS 29.503 callback 404 for an unknown UE
  Scenario: dereg-notify for an unknown SUPI is rejected with 404 CONTEXT_NOT_FOUND
    When the UDM POSTs a dereg-notify for SUPI "imsi-001019999999999" with deregReason "SUBSCRIPTION_WITHDRAWN"
    Then the response status is 404
    And the ProblemDetails cause is "CONTEXT_NOT_FOUND"
    And the AMF sends no NAS message to the UE

  # TS 24.501 §5.5.2.3.5 a): rel19, T3522 retransmitted 4 times, 5th expiry aborts
  Scenario: rel19 T3522 expiring five times aborts UDM-triggered deregistration with N2 release and without UECM DELETE
    Given the release profile is "rel19"
    And the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    And the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "SUBSCRIPTION_WITHDRAWN"
    When T3522 expires 4 times and the UE never answers
    Then the AMF has retransmitted the same DEREGISTRATION REQUEST 4 times
    When T3522 expires the 5th time
    Then the AMF sends a UE CONTEXT RELEASE COMMAND with Cause nas "deregister" to the serving gNB
    And the UE is 5GMM-DEREGISTERED
    And the AMF does not send a UECM DELETE to the UDM
    And the UE context is removed from the AMF after the UE CONTEXT RELEASE COMPLETE

  # TS 24.501 §5.5.2.3.5 a) with rel17 byte identity: no retransmissions, one local-abort guard of 5 x T3522
  Scenario: rel17 UDM-triggered deregistration sends no T3522 retransmission and the 5 x T3522 local-abort guard completes the teardown
    Given the release profile is "rel17"
    And the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    And the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "SUBSCRIPTION_WITHDRAWN"
    When the T3522 period elapses 4 times without a UE answer
    Then the AMF has sent exactly one DEREGISTRATION REQUEST in total
    When the local-abort guard of 5 x T3522 expires
    Then the AMF sends a UE CONTEXT RELEASE COMMAND with Cause nas "deregister" to the serving gNB
    And the AMF does not send a UECM DELETE to the UDM
    And the UE context is removed from the AMF after the UE CONTEXT RELEASE COMPLETE

  # TS 24.501 §5.5.2.3.5 b) lower layer failure; docs §5
  Scenario: DEREGISTRATION REQUEST downlink send failure falls back to implicit teardown
    Given the UE is CM-CONNECTED
    And the serving gNB N2 association is unavailable for NAS delivery
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "SUBSCRIPTION_WITHDRAWN"
    Then the response status is 204
    And the AMF logs the DEREGISTRATION REQUEST send with result "FAILURE"
    And the AMF releases the SM context of PDU session 1 at the SMF
    And the AMF deletes the AM policy association and the UE policy association at the PCF
    And the AMF unsubscribes the SDM subscription at the UDM exactly once
    And the AMF does not send a UECM DELETE to the UDM
    And the UE context is removed from the AMF

  # TS 23.502 §4.2.2.2.2 step 14d: behaviour unchanged by AMF-037 slice A
  Scenario: Regression - UE_INITIAL_REGISTRATION keeps releasing SM contexts silently with no NAS and no PCF change
    Given the UE is CM-IDLE
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "UE_INITIAL_REGISTRATION"
    Then the response status is 204
    And the AMF sends no NAS message to the UE
    And the AMF releases the SM context of PDU session 1 at the SMF
    And the AMF unsubscribes the SDM subscription at the UDM exactly once
    And the AMF does not send a UECM DELETE to the UDM
    And the UE context is removed from the AMF

  # Same decision-table row as above: UE_REGISTRATION_AREA_CHANGE stays unchanged (SM contexts kept)
  Scenario: Regression - UE_REGISTRATION_AREA_CHANGE keeps SM contexts and sends no PCF delete
    Given the UE is CM-IDLE
    When the UDM POSTs a dereg-notify for SUPI "imsi-001010000000001" with deregReason "UE_REGISTRATION_AREA_CHANGE"
    Then the response status is 204
    And the AMF sends no NAS message to the UE
    And the AMF sends no Nsmf ReleaseSMContext for PDU session 1
    And the AMF sends no Npcf delete
    And the AMF does not send a UECM DELETE to the UDM

  # TS 24.501 §5.6.1.5.2 / §5.5.1.3.5; docs §5 (accepted, no tombstone)
  Scenario: SERVICE REQUEST from an implicitly de-registered UE is rejected with 5GMM cause 9
    Given the UE is CM-IDLE
    And the UDM POSTed a dereg-notify for SUPI "imsi-001010000000001" with deregReason "SUBSCRIPTION_WITHDRAWN"
    When the UE sends a SERVICE REQUEST with its former 5G-S-TMSI
    Then the AMF returns a SERVICE REJECT with 5GMM cause 9
    And the AMF releases the N2 connection of the temporary context
