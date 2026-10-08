Feature: Handover — synchronous SMF leg: SMF-provided N2 SM transfers, PATH_SWITCH_SETUP_FAIL, HANDOVER_CMD, PREPARING / RES_ALLOC_FAIL / COMPLETED legs (TS 23.502 §4.9.1.2.2 steps 2-7, §4.9.1.3.2 steps 3-12, §4.9.1.3.3; TS 29.502 §5.2.2.3.3, §5.2.2.3.4; TS 38.413 §8.4.1-§8.4.4, §9.3.4)
  As an AMF performing Xn and N2 handover for a UE with several PDU sessions
  I want to wait for each Nsmf_PDUSession_UpdateSMContext response and relay the SMF-returned N2 SM information
  So that the PATH SWITCH REQUEST ACKNOWLEDGE and the HANDOVER COMMAND reflect what the SMF really did per PDU session
  (AMF-012; design: docs/procedures/XnHandover.md §2 (d)(e), §4.6-4.8, §5.1 E1-E20, §7.4, §7.8)
  (AMF-012 follow-up: N2 PREPARING leg at HANDOVER REQUIRED (steps 3-8), target-failed PSIs of the
   HANDOVER REQUEST ACKNOWLEDGE (step 10), COMPLETED leg after HANDOVER NOTIFY (§4.9.1.3.3);
   the SMF exchange of the Ack is "steps 10-12", the whole leg incl. the Ack "steps 9-12")
  (AMF-012 acceptance criteria:
   AC1 "AMF waits for each UpdateSMContext response and puts the SMF-returned N2 SM info into the Ack / Released list";
   AC2 "Failed-to-Setup PSIs forwarded to the SMF; sessions not listed in the request released";
   AC3 "HandoverCommandTransfer comes from the SMF (n2SmInfoType HANDOVER_CMD)")
  Note on AC2 "released": per procedure doc §7.4.4 the AMF sends Nsmf_PDUSession_UpdateSMContext with
  upCnxState DEACTIVATED (never ReleaseSMContext); the decision to release the PDU session stays with the SMF.

  Background:
    Given the AMF NGAP builders are available
    And UE with SUPI "imsi-001010000000001" has AMF UE NGAP ID 1 and RAN UE NGAP ID 1 on source gNB "gnb-source"
    And target gNB "gnb-target" completed NG Setup with the AMF
    And the UE has a KAMF and an Allowed NSSAI of SST 1 SD "000001"
    And the UE has PDU session id 1 on S-NSSAI SST 1 SD "000001"
    And the UE has PDU session id 2 on S-NSSAI SST 1 SD "000001"
    And the UE has PDU session id 3 on S-NSSAI SST 1 SD "000001"
    And the UE has Security Capabilities stored in the AMF
    And an Initial Context Setup established a KgNB of 256 bits so the NH chain holds NH1 = KNH(KAMF, KgNB) with NCC 1
    And the SMF is replaced by an injectable fake that records every Nsmf_PDUSession_UpdateSMContext request and answers per PDU session id
    And the SMF UpdateSMContext wait per PDU session is bounded by a short test timeout

  # ===== Xn: path switch, SMF-provided Ack transfers (AC1) =========================================

  # TS 23.502 §4.9.1.2.2 step 2 + step 7; doc §7.8 item 1
  @happy @xn
  Scenario: Xn path switch puts the SMF PathSwitchRequestAcknowledgeTransfer bytes of each PDU session into the Ack Switched List
    Given the SMF fake answers PDU session ids 1 and 2 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK" and a distinct valid non-empty PathSwitchRequestAcknowledgeTransfer each
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the IEs appear in this order:
      | IE                                 | id |
      | AMFUENGAPID                        | 10 |
      | RANUENGAPID                        | 85 |
      | SecurityContext                    | 93 |
      | PDUSessionResourceSwitchedList     | 77 |
      | AllowedNSSAI                       | 0  |
    And the Switched List item for PDU session id 1 carries exactly the bytes returned by the SMF for PDU session id 1
    And the Switched List item for PDU session id 2 carries exactly the bytes returned by the SMF for PDU session id 2
    And the SMF fake received one UpdateSMContext per PDU session with n2SmInfoType "PATH_SWITCH_REQ" and toBeSwitched true
    And each PATH_SWITCH_REQ n2SmInfo equals the PathSwitchRequestTransfer of that PDU session in the PATH SWITCH REQUEST

  # AC1 "waits": the Ack is not written before the SMF answered
  @happy @xn @sync
  Scenario: Path Switch Request Acknowledge is written only after every SMF response has returned
    Given the SMF fake blocks the answer for PDU session id 2 until released by the test
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2
    When the AMF handles the PATH SWITCH REQUEST
    And the SMF fake has received the UpdateSMContext requests for PDU session ids 1 and 2
    Then no NGAP message is written to the target gNB connection yet
    When the test releases the SMF fake answer for PDU session id 2 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the Ack was written after the last SMF response was returned

  # ===== Xn: SMF rejects PSIs (AC1) ================================================================

  # doc §5.1 E5: 404 -> unknown-PDU-session-ID; §7.8 item 2
  @error @xn
  Scenario: SMF answers 404 for one PDU session so the Ack carries it in the Released List PSAck with cause unknown-PDU-session-ID
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the SMF fake answers PDU session id 2 with 404 and ProblemDetails cause "CONTEXT_NOT_FOUND" without n2SmInfo
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the IEs appear in this order:
      | IE                                  | id |
      | AMFUENGAPID                         | 10 |
      | RANUENGAPID                         | 85 |
      | SecurityContext                     | 93 |
      | PDUSessionResourceSwitchedList      | 77 |
      | PDUSessionResourceReleasedListPSAck | 68 |
      | AllowedNSSAI                        | 0  |
    And the PDUSessionResourceSwitchedList contains only PDU session id 1
    And the PDUSessionResourceReleasedListPSAck contains PDU session id 2 with radioNetwork cause "unknown-PDU-session-ID"
    And the UE RAN UE NGAP ID is 7 and its serving gNB is "gnb-target"

  # doc §5.1 E6
  @error @xn
  Scenario: SMF answers 500 for one PDU session so the Ack carries it in the Released List PSAck with cause ho-failure-in-target-5GC-ngran-node-or-target-system
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the SMF fake answers PDU session id 2 with 500 and no n2SmInfo
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the PDUSessionResourceSwitchedList contains only PDU session id 1
    And the PDUSessionResourceReleasedListPSAck contains PDU session id 2 with radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system"

  # doc §5.1 E4
  @error @xn
  Scenario: SMF PathSwitchRequestUnsuccessfulTransfer with PATH_SWITCH_REQ_FAIL is forwarded verbatim into the Released List PSAck
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the SMF fake answers PDU session id 2 with 500 n2SmInfoType "PATH_SWITCH_REQ_FAIL" and a valid PathSwitchRequestUnsuccessfulTransfer with radioNetwork cause "unspecified"
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the PDUSessionResourceReleasedListPSAck item for PDU session id 2 carries exactly the bytes returned by the SMF for PDU session id 2

  # doc §5.1 E7: timeout of a single PSI
  @error @xn @timeout
  Scenario: SMF does not answer one PDU session within the timeout so the Ack releases it with cause ho-failure-in-target-5GC-ngran-node-or-target-system
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the SMF fake never answers PDU session id 2
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB within the test deadline
    And the PDUSessionResourceReleasedListPSAck contains PDU session id 2 with radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system"
    And the error is logged with cause "smf-timeout"

  # doc §5.1 E8: no PSI switched
  @reject @xn
  Scenario Outline: SMF rejects every requested PDU session so the AMF sends PATH SWITCH REQUEST FAILURE with all PSIs in the Released List PSFail
    Given the SMF fake answers PDU session ids 1 and 2 with <smf_outcome>
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the message is an unsuccessfulOutcome of procedure code 25
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 1 with radioNetwork cause "<cause>"
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 2 with radioNetwork cause "<cause>"
    And no PATH SWITCH REQUEST ACKNOWLEDGE is sent
    And the UE is not re-bound to the target gNB
    And the Next Hop Chaining Count of the UE is unchanged
    And the SMF fake received no UpdateSMContext with upCnxState "DEACTIVATED"
    And the failure is logged with result "REJECT" and cause "smf-rejected-all"

    Examples:
      | smf_outcome                          | cause                                                |
      | 404 and no n2SmInfo                  | unknown-PDU-session-ID                               |
      | 500 and no n2SmInfo                  | ho-failure-in-target-5GC-ngran-node-or-target-system |
      | no answer within the test timeout    | ho-failure-in-target-5GC-ngran-node-or-target-system |
      | a transport error                    | ho-failure-in-target-5GC-ngran-node-or-target-system |

  # doc §5 / §7.4.2: unknown PSI + SMF-failed PSI, none switched
  @reject @xn
  Scenario: PATH SWITCH REQUEST FAILURE lists both the PDU session unknown to the AMF and the one the SMF rejected
    Given the SMF fake answers PDU session id 1 with 500 and no n2SmInfo
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 11
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 11 with radioNetwork cause "unknown-PDU-session-ID"
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 1 with radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system"
    And the SMF fake received no UpdateSMContext for PDU session id 11

  # doc §7.4.2 NH/NCC ordering: pre-check before the SMF leg
  @reject @xn @security-context
  Scenario: Missing security context rejects the path switch before any SMF call
    Given the UE has no KgNB so the NH chain was never initialised
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 1 with misc cause "unspecified"
    And the SMF fake received no UpdateSMContext request

  # ===== Xn: NCC is advanced only for an Ack =======================================================

  @happy @xn @nh-ncc
  Scenario: NCC advances once after the SMF leg when the Ack is built
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    When the AMF handles the PATH SWITCH REQUEST
    Then the Security Context Next Hop Chaining Count is 2
    And the Security Context NH equals KNH(KAMF, KNH(KAMF, KgNB))

  # ===== Xn: Failed to Setup List PSReq forwarded (AC2) ===========================================

  # doc §7.3 / §7.4.3; §7.8 item 4
  @happy @xn @failed-to-setup
  Scenario: Failed-to-Setup PDU session is forwarded to the SMF as PATH_SWITCH_SETUP_FAIL and absent from the Switched and Released lists
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the SMF fake answers PDU session id 2 with 200 and no body
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1 and a Failed to Setup List PSReq with PDU session id 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the SMF fake received exactly one UpdateSMContext for PDU session id 2 with n2SmInfoType "PATH_SWITCH_SETUP_FAIL" and failedToBeSwitched true
    And that n2SmInfo equals the PathSwitchRequestSetupFailedTransfer of PDU session id 2 in the PATH SWITCH REQUEST
    And the PDUSessionResourceSwitchedList contains only PDU session id 1
    And the message does not contain the "PDUSessionResourceReleasedListPSAck" IE (id 68)

  @error @xn @failed-to-setup
  Scenario Outline: SMF failure on PATH_SWITCH_SETUP_FAIL does not change the Ack
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the SMF fake answers the PATH_SWITCH_SETUP_FAIL of PDU session id 2 with <smf_outcome>
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1 and a Failed to Setup List PSReq with PDU session id 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the IEs appear in this order:
      | IE                                 | id |
      | AMFUENGAPID                        | 10 |
      | RANUENGAPID                        | 85 |
      | SecurityContext                    | 93 |
      | PDUSessionResourceSwitchedList     | 77 |
      | AllowedNSSAI                       | 0  |
    And the PDUSessionResourceSwitchedList contains only PDU session id 1
    And the outcome of the PATH_SWITCH_SETUP_FAIL call is logged with level WARN

    Examples:
      | smf_outcome                       |
      | 422                               |
      | 500                               |
      | no answer within the test timeout |

  # doc §5.1 E11
  @error @xn @failed-to-setup
  Scenario: Failed-to-Setup PDU session unknown to the AMF triggers no SMF call
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1 and a Failed to Setup List PSReq with PDU session id 11
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the SMF fake received no UpdateSMContext for PDU session id 11
    And a WARN is logged with pdu_session_id 11

  # doc §5.1 E12
  @reject @xn @failed-to-setup
  Scenario: PDU session present in both the To Be Switched list and the Failed to Setup list yields PATH SWITCH REQUEST FAILURE multiple-PDU-session-ID-instances
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2 and a Failed to Setup List PSReq with PDU session id 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 2 with radioNetwork cause "multiple-PDU-session-ID-instances"
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 1 with misc cause "unspecified"
    And the SMF fake received no UpdateSMContext request
    And the UE is not re-bound to the target gNB

  # ===== Xn: sessions not listed in the request (AC2) =============================================

  # doc §7.4.4: DEACTIVATED, never DeleteSMContext
  @happy @xn @not-listed
  Scenario: PDU session in neither request list gets exactly one UpdateSMContext upCnxState DEACTIVATED after a successful Ack
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the SMF fake eventually received exactly one UpdateSMContext with upCnxState "DEACTIVATED" for PDU session id 2
    And the SMF fake eventually received exactly one UpdateSMContext with upCnxState "DEACTIVATED" for PDU session id 3
    And those DEACTIVATED requests carry no n2SmInfo
    And the DEACTIVATED requests were sent after the Ack was written
    And the SMF fake received no DeleteSMContext or ReleaseSMContext request
    And the UE still holds PDU session ids 1, 2 and 3

  @happy @xn @not-listed
  Scenario: PDU session in the Failed to Setup list is not additionally deactivated as a not-listed session
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1 and a Failed to Setup List PSReq with PDU session id 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the SMF fake eventually received exactly one UpdateSMContext with upCnxState "DEACTIVATED" for PDU session id 3
    And the SMF fake received no UpdateSMContext with upCnxState "DEACTIVATED" for PDU session id 2

  # doc §5.1 E13
  @error @xn @not-listed
  Scenario: Failure of the DEACTIVATED call for a not-listed session does not affect the already sent Ack
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the SMF fake answers the DEACTIVATED request of PDU session id 2 with 500
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the UE RAN UE NGAP ID is 7 and its serving gNB is "gnb-target"
    And the UE still holds PDU session id 2
    And the DEACTIVATED failure is logged with level WARN

  @reject @xn @not-listed
  Scenario: No DEACTIVATED call is made for not-listed sessions when the path switch fails
    Given the SMF fake answers PDU session id 1 with 500 and no n2SmInfo
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the SMF fake received no UpdateSMContext with upCnxState "DEACTIVATED"
    And the UE still holds PDU session ids 1, 2 and 3

  # ===== Xn: compatibility fallback (doc §5.1 E2, E3) =============================================

  @fallback @xn
  Scenario Outline: SMF success without usable n2SmInfo falls back to an empty PathSwitchRequestAcknowledgeTransfer
    Given the SMF fake answers PDU session id 1 with <smf_answer>
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the PDUSessionResourceSwitchedList contains 1 item for PDU session id 1
    And the Switched List item for PDU session id 1 carries an empty PathSwitchRequestAcknowledgeTransfer
    And the UE RAN UE NGAP ID is 7 and its serving gNB is "gnb-target"
    And the fallback is logged with level <level>

    Examples:
      | smf_answer                                                              | level |
      | 200 with an empty body                                                  | WARN  |
      | 204 No Content                                                          | WARN  |
      | 200 n2SmInfoType "PATH_SWITCH_REQ_ACK" and undecodable n2SmInfo bytes   | ERROR |
      | 200 n2SmInfoType "HANDOVER_CMD" and a valid n2SmInfo                    | ERROR |

  @fallback @xn
  Scenario: Undecodable SMF bytes are never forwarded into the Ack
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK" and the n2SmInfo bytes "ffffffff"
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    When the AMF handles the PATH SWITCH REQUEST
    Then the encoded PDU decodes cleanly with free5gc/ngap
    And no item of the Ack contains the bytes "ffffffff"

  @fallback @xn
  Scenario: Undecodable PATH_SWITCH_REQ_FAIL bytes are ignored and the AMF builds the Cause itself
    Given the SMF fake answers PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    And the SMF fake answers PDU session id 2 with 500 n2SmInfoType "PATH_SWITCH_REQ_FAIL" and the n2SmInfo bytes "ffffffff"
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 1 and 2
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the PDUSessionResourceReleasedListPSAck contains PDU session id 2 with radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system"
    And no item of the Ack contains the bytes "ffffffff"

  # doc §7.4.1: nil hook = no SMF configured keeps today's behaviour
  @fallback @xn
  Scenario: No SMF configured keeps the empty transfer and switches the session
    Given no SMF hook is configured in the AMF
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the Switched List item for PDU session id 1 carries an empty PathSwitchRequestAcknowledgeTransfer
    And a WARN is logged that no SMF is configured

  # ===== SCTP association not blocked (doc §7.4.1, §7.8 item 7) ====================================

  @happy @xn @non-blocking
  Scenario: A pending SMF call of one UE does not block NGAP processing of another UE on the same association
    Given a second UE with SUPI "imsi-001010000000002" has AMF UE NGAP ID 2 and RAN UE NGAP ID 2 on source gNB "gnb-source"
    And the SMF fake blocks the answer for PDU session id 1 of UE "imsi-001010000000001" until released by the test
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 1
    And the AMF handles the PATH SWITCH REQUEST
    And the SMF fake has received the UpdateSMContext request for PDU session id 1 of UE "imsi-001010000000001"
    When the source gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID 2 on the same SCTP association
    Then the AMF has dispatched that NGAP message for UE "imsi-001010000000002" while the SMF call of UE "imsi-001010000000001" is still pending
    When the test releases the SMF fake answer for PDU session id 1 with 200 n2SmInfoType "PATH_SWITCH_REQ_ACK"
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB

  # ===== N2 handover: SMF leg at HANDOVER REQUEST ACKNOWLEDGE (AC3) ================================

  # doc §7.4.5 + §7.8 item 8
  @happy @n2
  Scenario: HANDOVER REQUEST ACKNOWLEDGE triggers UpdateSMContext HANDOVER_REQ_ACK with hoState PREPARED and the target's transfer
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session ids 1 and 2 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a distinct valid HandoverCommandTransfer each
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids 1 and 2
    When the AMF handles both messages
    Then the SMF fake received exactly one UpdateSMContext per admitted PDU session with hoState "PREPARED" and n2SmInfoType "HANDOVER_REQ_ACK"
    And each HANDOVER_REQ_ACK n2SmInfo equals the HandoverRequestAcknowledgeTransfer of that PDU session in the HANDOVER REQUEST ACKNOWLEDGE

  @happy @n2
  Scenario: HANDOVER COMMAND items carry the HandoverCommandTransfer bytes returned by the SMF
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session ids 1 and 2 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a distinct valid HandoverCommandTransfer each
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids 1 and 2
    When the AMF handles both messages
    Then the AMF sends a HANDOVER COMMAND to the source gNB
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the HANDOVER COMMAND IEs appear in this order:
      | IE                                       | id  |
      | AMFUENGAPID                              | 10  |
      | RANUENGAPID                              | 85  |
      | HandoverType                             | 29  |
      | PDUSessionResourceHandoverList           | 59  |
      | TargetToSourceTransparentContainer       | 106 |
    And the PDUSessionResourceHandoverList (id 59) item for PDU session id 1 carries exactly the bytes returned by the SMF for PDU session id 1
    And the PDUSessionResourceHandoverList (id 59) item for PDU session id 2 carries exactly the bytes returned by the SMF for PDU session id 2
    And the HANDOVER COMMAND was written after every SMF response had returned
    And the HANDOVER COMMAND written to the source gNB carries SCTP PPID 60

  # doc §5.1 E15
  @fallback @n2
  Scenario Outline: SMF success without a usable HANDOVER_CMD falls back to an empty HandoverCommandTransfer
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with <smf_answer>
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1
    When the AMF handles both messages
    Then the AMF sends a HANDOVER COMMAND to the source gNB
    And the PDUSessionResourceHandoverList (id 59) item for PDU session id 1 carries an empty HandoverCommandTransfer
    And the fallback is logged with level <level>

    Examples:
      | smf_answer                                                       | level |
      | 200 hoState "PREPARED" without n2SmInfo                          | WARN  |
      | 200 n2SmInfoType "HANDOVER_CMD" and undecodable n2SmInfo bytes   | ERROR |
      | 200 n2SmInfoType "PATH_SWITCH_REQ_ACK" and a valid n2SmInfo      | ERROR |

  @fallback @n2
  Scenario: Undecodable SMF HandoverCommandTransfer bytes are never forwarded to the source gNB
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 n2SmInfoType "HANDOVER_CMD" and the n2SmInfo bytes "ffffffff"
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1
    When the AMF handles both messages
    Then no item of the HANDOVER COMMAND contains the bytes "ffffffff"

  # doc §4.8 + §5.1 E16-E18; §7.8 item 9
  @error @n2
  Scenario Outline: SMF rejects one admitted PDU session so the HANDOVER COMMAND lists it in the PDU Session Resource To Release List HOCmd
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the SMF fake answers PDU session id 2 with <smf_outcome>
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids 1 and 2
    When the AMF handles both messages
    Then the AMF sends a HANDOVER COMMAND to the source gNB
    And the HANDOVER COMMAND IEs appear in this order:
      | IE                                       | id  |
      | AMFUENGAPID                              | 10  |
      | RANUENGAPID                              | 85  |
      | HandoverType                             | 29  |
      | PDUSessionResourceHandoverList           | 59  |
      | PDUSessionResourceToReleaseListHOCmd     | 78  |
      | TargetToSourceTransparentContainer       | 106 |
    And the PDUSessionResourceHandoverList (id 59) contains only PDU session id 1
    And the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 2 with radioNetwork cause "<cause>"

    Examples:
      | smf_outcome                         | cause                                                |
      | 404 and no n2SmInfo                 | unknown-PDU-session-ID                               |
      | 500 and no n2SmInfo                 | ho-failure-in-target-5GC-ngran-node-or-target-system |
      | no answer within the test timeout   | ho-failure-in-target-5GC-ngran-node-or-target-system |

  @error @n2
  Scenario: SMF HandoverPreparationUnsuccessfulTransfer with HANDOVER_PREP_FAIL is forwarded verbatim in the To Release List HOCmd
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the SMF fake answers PDU session id 2 with 500 n2SmInfoType "HANDOVER_PREP_FAIL" and a valid HandoverPreparationUnsuccessfulTransfer
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids 1 and 2
    When the AMF handles both messages
    Then the PDUSessionResourceToReleaseListHOCmd (id 78) item for PDU session id 2 carries exactly the bytes returned by the SMF for PDU session id 2

  # doc §5.1 E18
  @error @n2
  Scenario: Admitted PDU session unknown to the AMF is listed in the To Release List HOCmd without an SMF call
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids 1 and 11
    When the AMF handles both messages
    Then the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 11 with radioNetwork cause "unknown-PDU-session-ID"
    And the SMF fake received no UpdateSMContext for PDU session id 11

  # doc §5.1 E19
  @reject @n2
  Scenario: Every admitted PDU session fails at the SMF so the AMF sends HANDOVER PREPARATION FAILURE to the source gNB
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session ids 1 and 2 with 500 and no n2SmInfo
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids 1 and 2
    When the AMF handles both messages
    Then the AMF sends a HANDOVER PREPARATION FAILURE to the source gNB
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the HANDOVER PREPARATION FAILURE carries radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system"
    And no HANDOVER COMMAND is sent
    And the pending N2 handover state of AMF UE NGAP ID 1 is dropped
    And the UE is not registered on the target gNB
    And the failure is logged with result "REJECT"

  @reject @n2 @timeout
  Scenario: SMF does not answer any admitted PDU session within the timeout so the AMF sends HANDOVER PREPARATION FAILURE
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake never answers PDU session ids 1 and 2
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids 1 and 2
    When the AMF handles both messages
    Then the AMF sends a HANDOVER PREPARATION FAILURE to the source gNB within the test deadline
    And the pending N2 handover state of AMF UE NGAP ID 1 is dropped

  @happy @n2 @non-blocking
  Scenario: A pending SMF call of the N2 handover does not block NGAP processing of another UE on the same association
    Given a second UE with SUPI "imsi-001010000000002" has AMF UE NGAP ID 2 and RAN UE NGAP ID 2 on source gNB "gnb-source"
    And the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake blocks the answer for PDU session id 1 until released by the test
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1
    And the AMF handles both messages
    When the target gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID 2 on the same SCTP association
    Then the AMF has dispatched that NGAP message for UE "imsi-001010000000002" while the SMF call of UE "imsi-001010000000001" is still pending

  # ===== N2: PREPARING leg at HANDOVER REQUIRED (TS 23.502 §4.9.1.3.2 steps 3-8; TS 29.502 §5.2.2.3.4) =====

  @happy @n2 @preparing
  Scenario: HANDOVER REQUIRED with two PDU sessions triggers one UpdateSMContext per PDU session with hoState PREPARING and HANDOVER_REQUIRED
    Given the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session ids 1 and 2 each with a distinct valid HandoverRequiredTransfer
    And the SMF fake answers the PREPARING request of PDU session ids 1 and 2 with 200 hoState "PREPARING" n2SmInfoType "PDU_RES_SETUP_REQ" and a distinct valid PDUSessionResourceSetupRequestTransfer each
    When the AMF handles the HANDOVER REQUIRED
    Then the SMF fake received exactly one UpdateSMContext per listed PDU session with hoState "PREPARING" and n2SmInfoType "HANDOVER_REQUIRED"
    And each PREPARING n2SmInfo equals the HandoverRequiredTransfer of that PDU session in the HANDOVER REQUIRED
    And each PREPARING request carries a targetId whose ranNodeId.gNbId and tai.tac equal the Target ID of the HANDOVER REQUIRED
    And the SMF fake received no UpdateSMContext for PDU session id 3
    And the Nsmf request log lines carry interface "Nsmf", direction "OUT", message_type "UpdateSMContext" and spec_ref "TS 23.502 §4.9.1.3.2 step 3"
    And the Nsmf response log lines carry interface "Nsmf", direction "IN", message_type "UpdateSMContextResponse" and spec_ref "TS 23.502 §4.9.1.3.2 step 6"

  @happy @n2 @preparing
  Scenario: HANDOVER REQUEST items carry the PDUSessionResourceSetupRequestTransfer bytes returned by the SMF
    Given the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session ids 1 and 2 each with a distinct valid HandoverRequiredTransfer
    And the SMF fake answers the PREPARING request of PDU session ids 1 and 2 with 200 hoState "PREPARING" n2SmInfoType "PDU_RES_SETUP_REQ" and a distinct valid PDUSessionResourceSetupRequestTransfer each
    When the AMF handles the HANDOVER REQUIRED
    Then the AMF sends a HANDOVER REQUEST to the target gNB
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the PDUSessionResourceSetupListHOReq item for PDU session id 1 carries exactly the bytes returned by the SMF for PDU session id 1
    And the PDUSessionResourceSetupListHOReq item for PDU session id 2 carries exactly the bytes returned by the SMF for PDU session id 2
    And the Handover Preparation is logged with result "OK" for PDU session ids 1 and 2
    And the metric fivegc_procedure_total{nf="AMF",procedure="N2HandoverSMFPreparing",result="OK"} increased by 2

  @happy @n2 @preparing @sync
  Scenario: HANDOVER REQUEST is written only after both PREPARING answers have returned
    Given the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session ids 1 and 2 each with a distinct valid HandoverRequiredTransfer
    And the SMF fake blocks the PREPARING answer for PDU session id 2 until released by the test
    And the SMF fake answers the PREPARING request of PDU session id 1 with 200 hoState "PREPARING" n2SmInfoType "PDU_RES_SETUP_REQ" and a valid PDUSessionResourceSetupRequestTransfer
    When the AMF handles the HANDOVER REQUIRED
    And the SMF fake has received the PREPARING requests for PDU session ids 1 and 2
    Then no NGAP message is written to the target gNB connection yet
    When the test releases the PREPARING answer for PDU session id 2 with 200 hoState "PREPARING" n2SmInfoType "PDU_RES_SETUP_REQ" and a valid PDUSessionResourceSetupRequestTransfer
    Then the AMF sends a HANDOVER REQUEST to the target gNB
    And the HANDOVER REQUEST was written after the last PREPARING response was returned

  # doc fallback: compatibility with an SMF that does not return the transfer
  @fallback @n2 @preparing
  Scenario Outline: SMF 2xx on PREPARING without a usable n2SmInfo falls back to the cached N2SmTransfer
    Given the UE PDU session id 1 has a cached N2SmTransfer of known bytes
    And the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session id 1 with a valid HandoverRequiredTransfer
    And the SMF fake answers the PREPARING request of PDU session id 1 with <smf_answer>
    When the AMF handles the HANDOVER REQUIRED
    Then the AMF sends a HANDOVER REQUEST to the target gNB
    And the PDUSessionResourceSetupListHOReq item for PDU session id 1 carries exactly the cached N2SmTransfer bytes
    And no item of the HANDOVER REQUEST contains the bytes "ffffffff"
    And the fallback is logged with level <level>

    Examples:
      | smf_answer                                                                  | level |
      | 200 hoState "PREPARING" without n2SmInfo                                    | WARN  |
      | 200 n2SmInfoType "PDU_RES_SETUP_REQ" and undecodable n2SmInfo bytes "ffffffff" | ERROR |
      | 200 n2SmInfoType "HANDOVER_CMD" and a valid n2SmInfo                        | ERROR |

  # PSI rejected by the SMF on PREPARING: absent from HANDOVER REQUEST, later in IE 78
  @error @n2 @preparing
  Scenario Outline: SMF rejects one PDU session at PREPARING so it is absent from the HANDOVER REQUEST and listed in the HANDOVER COMMAND To Release List HOCmd
    Given the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session ids 1 and 2 each with a distinct valid HandoverRequiredTransfer
    And the SMF fake answers the PREPARING request of PDU session id 1 with 200 hoState "PREPARING" n2SmInfoType "PDU_RES_SETUP_REQ" and a valid PDUSessionResourceSetupRequestTransfer
    And the SMF fake answers the PREPARING request of PDU session id 2 with <smf_outcome>
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    When the AMF handles the HANDOVER REQUIRED and the HANDOVER REQUEST ACKNOWLEDGE
    Then the HANDOVER REQUEST PDUSessionResourceSetupListHOReq contains only PDU session id 1
    And the SMF fake received no UpdateSMContext with hoState "PREPARED" for PDU session id 2
    And the AMF sends a HANDOVER COMMAND to the source gNB
    And the PDUSessionResourceHandoverList (id 59) contains only PDU session id 1
    And <ie78_check>
    And the metric fivegc_procedure_total{nf="AMF",procedure="N2HandoverSMFPreparing",result="<metric_result>"} increased by 1

    Examples:
      | smf_outcome                                                                                  | ie78_check                                                                                                                                  | metric_result |
      | 404 and no n2SmInfo                                                                          | the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 2 with radioNetwork cause "unknown-PDU-session-ID" (26)            | REJECT        |
      | 500 and no n2SmInfo                                                                          | the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 2 with radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system" (7) | REJECT |
      | 500 n2SmInfoType "HANDOVER_PREP_FAIL" and a valid HandoverPreparationUnsuccessfulTransfer    | the PDUSessionResourceToReleaseListHOCmd (id 78) item for PDU session id 2 carries exactly the bytes returned by the SMF for PDU session id 2 | REJECT        |
      | 200 hoState "CANCELLED" without n2SmInfo                                                     | the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 2 with radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system" (7) | REJECT |
      | no answer within the test timeout                                                            | the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 2 with radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system" (7) | FAILURE |

  @error @n2 @preparing
  Scenario: PDU session listed by the source but unknown to the AMF is skipped at PREPARING and listed in the HANDOVER COMMAND with cause unknown-PDU-session-ID
    Given the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session ids 1 and 11 each with a valid HandoverRequiredTransfer
    And the SMF fake answers the PREPARING request of PDU session id 1 with 200 hoState "PREPARING" n2SmInfoType "PDU_RES_SETUP_REQ" and a valid PDUSessionResourceSetupRequestTransfer
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    When the AMF handles the HANDOVER REQUIRED and the HANDOVER REQUEST ACKNOWLEDGE
    Then the SMF fake received no UpdateSMContext for PDU session id 11
    And a WARN is logged with pdu_session_id 11
    And the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 11 with radioNetwork cause "unknown-PDU-session-ID"

  @reject @n2 @preparing @nh-ncc
  Scenario Outline: SMF rejects every PDU session at PREPARING so the AMF sends HANDOVER PREPARATION FAILURE and does not consume an NCC
    Given the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session ids 1 and 2 each with a distinct valid HandoverRequiredTransfer
    And the SMF fake answers the PREPARING request of PDU session ids 1 and 2 with <smf_outcome>
    When the AMF handles the HANDOVER REQUIRED
    Then the AMF sends a HANDOVER PREPARATION FAILURE to the source gNB within the test deadline
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the HANDOVER PREPARATION FAILURE carries radioNetwork cause "ho-failure-in-target-5GC-ngran-node-or-target-system" (7)
    And no HANDOVER REQUEST is written to the target gNB
    And no pending N2 handover state exists for AMF UE NGAP ID 1
    And the Next Hop Chaining Count of the UE is unchanged
    And the failure is logged with result "REJECT" and cause "smf-rejected-all"

    Examples:
      | smf_outcome                                                                                |
      | 404 and no n2SmInfo                                                                        |
      | 500 and no n2SmInfo                                                                        |
      | 500 n2SmInfoType "HANDOVER_PREP_FAIL" and a valid HandoverPreparationUnsuccessfulTransfer  |
      | no answer within the test timeout                                                          |
      | a transport error                                                                          |

  @reject @n2 @preparing @nh-ncc
  Scenario: A failed PREPARING leg does not consume the NCC so the next successful handover still gets NCC 2
    Given the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session id 1 with a valid HandoverRequiredTransfer
    And the SMF fake answers the PREPARING request of PDU session id 1 with 500 and no n2SmInfo
    And the AMF handles the HANDOVER REQUIRED
    And the AMF sent a HANDOVER PREPARATION FAILURE to the source gNB
    And the SMF fake now answers the PREPARING request of PDU session id 1 with 200 hoState "PREPARING" n2SmInfoType "PDU_RES_SETUP_REQ" and a valid PDUSessionResourceSetupRequestTransfer
    When the source gNB sends a second HANDOVER REQUIRED towards "gnb-target" listing PDU session id 1 with a valid HandoverRequiredTransfer
    Then the AMF sends a HANDOVER REQUEST to the target gNB
    And the Security Context Next Hop Chaining Count of the HANDOVER REQUEST is 2
    And the Security Context NH of the HANDOVER REQUEST equals KNH(KAMF, KNH(KAMF, KgNB))

  @reject @n2 @preparing
  Scenario: HANDOVER REQUIRED without any PDU session candidate is still rejected with HandoverRequestMissingIE
    Given the UE has no PDU sessions in the AMF
    And the source gNB sends a HANDOVER REQUIRED towards "gnb-target" without a PDU Session Resource List HORqd
    When the AMF handles the HANDOVER REQUIRED
    Then the AMF sends a HANDOVER PREPARATION FAILURE to the source gNB
    And the SMF fake received no UpdateSMContext request
    And the failure is logged with cause "HandoverRequestMissingIE"

  @fallback @n2 @preparing
  Scenario: No SMF hook configured keeps today's behaviour and uses the cached N2SmTransfer at HANDOVER REQUIRED
    Given no SMF hook is configured in the AMF
    And the UE PDU session id 1 has a cached N2SmTransfer of known bytes
    And the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session id 1 with a valid HandoverRequiredTransfer
    When the AMF handles the HANDOVER REQUIRED
    Then the AMF sends a HANDOVER REQUEST to the target gNB
    And the PDUSessionResourceSetupListHOReq item for PDU session id 1 carries exactly the cached N2SmTransfer bytes
    And the SMF fake received no UpdateSMContext request
    And a WARN is logged that no SMF is configured with interface "Nsmf" and direction "OUT"

  @happy @n2 @preparing @non-blocking
  Scenario: A pending PREPARING call of one UE does not block NGAP processing of another UE on the same association
    Given a second UE with SUPI "imsi-001010000000002" has AMF UE NGAP ID 2 and RAN UE NGAP ID 2 on source gNB "gnb-source"
    And the source gNB sends a HANDOVER REQUIRED towards "gnb-target" listing PDU session id 1 with a valid HandoverRequiredTransfer
    And the SMF fake blocks the PREPARING answer for PDU session id 1 until released by the test
    And the AMF handles the HANDOVER REQUIRED
    And the SMF fake has received the PREPARING request for PDU session id 1 of UE "imsi-001010000000001"
    When the source gNB sends an UPLINK NAS TRANSPORT for AMF UE NGAP ID 2 on the same SCTP association
    Then the AMF has dispatched that NGAP message for UE "imsi-001010000000002" while the SMF call of UE "imsi-001010000000001" is still pending

  # ===== N2: target-failed PSIs of HANDOVER REQUEST ACKNOWLEDGE (TS 23.502 §4.9.1.3.2 step 10; TS 29.502 §5.2.2.3.4) =====

  @happy @n2 @res-alloc-fail
  Scenario: Failed-to-Setup PDU session of the HANDOVER REQUEST ACKNOWLEDGE is forwarded to the SMF as HANDOVER_RES_ALLOC_FAIL with the target's transfer
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the SMF fake answers the HANDOVER_RES_ALLOC_FAIL of PDU session id 2 with 200 hoState "CANCELLED"
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1 and a PDU Session Resource Failed to Setup List HOAck with PDU session id 2 and cause "radioNetwork" 0
    When the AMF handles both messages
    Then the SMF fake received exactly one UpdateSMContext for PDU session id 2 with hoState "PREPARED" and n2SmInfoType "HANDOVER_RES_ALLOC_FAIL"
    And that n2SmInfo equals the HandoverResourceAllocationUnsuccessfulTransfer of PDU session id 2 in the HANDOVER REQUEST ACKNOWLEDGE
    And the AMF sends a HANDOVER COMMAND to the source gNB
    And the PDUSessionResourceHandoverList (id 59) contains only PDU session id 1
    And the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 2 with radioNetwork cause "unspecified" (0)
    And the metric fivegc_procedure_total{nf="AMF",procedure="N2HandoverSMFResAllocFail",result="OK"} increased by 1
    And the Nsmf log line carries interface "Nsmf", direction "OUT" and spec_ref "TS 23.502 §4.9.1.3.2 step 10"

  @error @n2 @res-alloc-fail
  Scenario: Failed PDU session unknown to the AMF is listed in IE 78 without an SMF call
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1 and a PDU Session Resource Failed to Setup List HOAck with PDU session id 11 and cause "radioNetwork" 0
    When the AMF handles both messages
    Then the SMF fake received no UpdateSMContext for PDU session id 11
    And a WARN is logged with pdu_session_id 11
    And the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 11 with radioNetwork cause "unspecified" (0)

  @error @n2 @res-alloc-fail
  Scenario Outline: SMF failure on HANDOVER_RES_ALLOC_FAIL does not change the HANDOVER COMMAND
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the SMF fake answers the HANDOVER_RES_ALLOC_FAIL of PDU session id 2 with <smf_outcome>
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1 and a PDU Session Resource Failed to Setup List HOAck with PDU session id 2 and cause "radioNetwork" 0
    When the AMF handles both messages
    Then the AMF sends a HANDOVER COMMAND to the source gNB
    And the HANDOVER COMMAND IEs appear in this order:
      | IE                                       | id  |
      | AMFUENGAPID                              | 10  |
      | RANUENGAPID                              | 85  |
      | HandoverType                             | 29  |
      | PDUSessionResourceHandoverList           | 59  |
      | PDUSessionResourceToReleaseListHOCmd     | 78  |
      | TargetToSourceTransparentContainer       | 106 |
    And the PDUSessionResourceHandoverList (id 59) contains only PDU session id 1
    And the PDUSessionResourceToReleaseListHOCmd (id 78) contains PDU session id 2 with radioNetwork cause "unspecified" (0)
    And the outcome of the HANDOVER_RES_ALLOC_FAIL call is logged with level WARN

    Examples:
      | smf_outcome                         |
      | 404 and no n2SmInfo                 |
      | 500 and no n2SmInfo                 |
      | no answer within the test timeout   |

  # IE 78 cause = Cause decoded from the target's transfer; SMF HANDOVER_PREP_FAIL bytes win when returned
  @error @n2 @res-alloc-fail
  Scenario: SMF HandoverPreparationUnsuccessfulTransfer returned for a target-failed PDU session is forwarded verbatim in IE 78
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the SMF fake answers the HANDOVER_RES_ALLOC_FAIL of PDU session id 2 with 200 n2SmInfoType "HANDOVER_PREP_FAIL" and a valid HandoverPreparationUnsuccessfulTransfer
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1 and a PDU Session Resource Failed to Setup List HOAck with PDU session id 2 and cause "radioNetwork" 0
    When the AMF handles both messages
    Then the PDUSessionResourceToReleaseListHOCmd (id 78) item for PDU session id 2 carries exactly the bytes returned by the SMF for PDU session id 2

  @error @n2 @res-alloc-fail
  Scenario: PDU session in the Failed to Setup List HOAck is listed in IE 78 exactly once
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1 and a PDU Session Resource Failed to Setup List HOAck with PDU session id 2 and cause "radioNetwork" 0
    When the AMF handles both messages
    Then the PDUSessionResourceToReleaseListHOCmd (id 78) contains exactly 1 item for PDU session id 2

  # doc §5.1 E19 unchanged: no PSI in IE 59
  @reject @n2 @res-alloc-fail
  Scenario: Every PDU session of the HANDOVER REQUEST ACKNOWLEDGE is in the Failed to Setup List HOAck so the AMF sends HANDOVER PREPARATION FAILURE
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers the HANDOVER_RES_ALLOC_FAIL of PDU session ids 1 and 2 with 200 hoState "CANCELLED"
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting no PDU session and a PDU Session Resource Failed to Setup List HOAck with PDU session ids 1 and 2 and cause "radioNetwork" 0
    When the AMF handles both messages
    Then the AMF sends a HANDOVER PREPARATION FAILURE to the source gNB
    And no HANDOVER COMMAND is sent
    And the pending N2 handover state of AMF UE NGAP ID 1 is dropped

  # ===== N2: COMPLETED leg after HANDOVER NOTIFY (TS 23.502 §4.9.1.3.3; TS 29.502 §5.2.2.3.4) =====

  @happy @n2 @completed
  Scenario: HANDOVER NOTIFY triggers one UpdateSMContext hoState COMPLETED without n2SmInfo per SMF-accepted PDU session and none for PSIs in IE 78
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the SMF fake answers PDU session id 2 with 500 and no n2SmInfo
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session ids 1 and 2
    And the AMF handles both messages
    And the SMF fake answers the COMPLETED request of PDU session id 1 with 200 hoState "COMPLETED"
    When the target gNB sends a HANDOVER NOTIFY for the UE
    Then the SMF fake eventually received exactly one UpdateSMContext with hoState "COMPLETED" for PDU session id 1
    And that COMPLETED request carries no n2SmInfo and no n2SmInfoType
    And the SMF fake received no UpdateSMContext with hoState "COMPLETED" for PDU session id 2
    And the SMF fake received no UpdateSMContext with hoState "COMPLETED" for PDU session id 3
    And the metric fivegc_procedure_total{nf="AMF",procedure="N2HandoverSMFComplete",result="OK"} increased by 1
    And the Nsmf log line carries interface "Nsmf", direction "OUT" and spec_ref "TS 23.502 §4.9.1.3.3 (Handover Complete indication)"
    And the Nsmf log lines carry the correlation_id of the HANDOVER REQUIRED procedure

  @error @n2 @completed
  Scenario Outline: SMF failure on the COMPLETED call is only logged and the UE Context Release Command is still sent to the source gNB
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1
    And the AMF handles both messages
    And the SMF fake answers the COMPLETED request of PDU session id 1 with <smf_outcome>
    When the target gNB sends a HANDOVER NOTIFY for the UE
    Then the AMF sends a UE CONTEXT RELEASE COMMAND with radioNetwork cause "successful-handover" (2) to the source gNB
    And the UE RAN UE NGAP ID is 7 and its serving gNB is "gnb-target"
    And the COMPLETED failure is logged with level WARN and result "<result>"
    And the metric fivegc_procedure_total{nf="AMF",procedure="N2HandoverSMFComplete",result="<result>"} increased by 1

    Examples:
      | smf_outcome                         | result  |
      | 404 and no n2SmInfo                 | REJECT  |
      | 500 and no n2SmInfo                 | REJECT  |
      | no answer within the test timeout   | FAILURE |

  @happy @n2 @completed
  Scenario: UE Context Release Command is not delayed by a pending COMPLETED call
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the SMF fake answers PDU session id 1 with 200 hoState "PREPARED" n2SmInfoType "HANDOVER_CMD" and a valid HandoverCommandTransfer
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1
    And the AMF handles both messages
    And the SMF fake blocks the COMPLETED answer for PDU session id 1 until released by the test
    When the target gNB sends a HANDOVER NOTIFY for the UE
    Then the AMF sends a UE CONTEXT RELEASE COMMAND with radioNetwork cause "successful-handover" (2) to the source gNB while the COMPLETED call is still pending

  @fallback @n2 @completed
  Scenario: No SMF hook configured sends no COMPLETED call and still releases the source gNB
    Given no SMF hook is configured in the AMF
    And the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE admitting PDU session id 1
    And the AMF handles both messages
    When the target gNB sends a HANDOVER NOTIFY for the UE
    Then the AMF sends a UE CONTEXT RELEASE COMMAND with radioNetwork cause "successful-handover" (2) to the source gNB
    And the SMF fake received no UpdateSMContext request

  # ===== Live stack =================================================================================

  # doc §7.8 item 11; skipped in-process, runs only with E2E_TEST=1
  @e2e @happy @xn
  Scenario: PacketRusher Xn handover shows the SMF leg before the Path Switch Request Acknowledge
    Given the live stack is up with RAN "packetrusher" and PR_SCENARIO "xn"
    When "make handover-test" is run
    Then the PacketRusher Xn scenario completes the Path Switch
    And the SMF logs the Nsmf_PDUSession_UpdateSMContext PATH_SWITCH_REQ before the AMF sends the PATH SWITCH REQUEST ACKNOWLEDGE
    And the Ack Switched List transfers decode in Wireshark
    And the "XnHandover" procedure summary reports zero failures

  @e2e @happy @n2
  Scenario: PacketRusher N2 handover shows the SMF HANDOVER_CMD in the HANDOVER COMMAND
    Given the live stack is up with RAN "packetrusher" and PR_SCENARIO "n2"
    When "make handover-n2-test" is run
    Then the PacketRusher N2 scenario completes the handover
    And the SMF logs the Nsmf_PDUSession_UpdateSMContext HANDOVER_REQ_ACK before the AMF sends the HANDOVER COMMAND
    And the HANDOVER COMMAND transfers decode in Wireshark
    And the "N2Handover" procedure summary reports zero failures
