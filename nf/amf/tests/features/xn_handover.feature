Feature: Xn Handover — Path Switch Request Acknowledge, NH/NCC chain, no source release (TS 23.502 §4.9.1.2.2, TS 38.413 §8.4.4, §9.2.3.9, §9.3.1.18, TS 33.501 §6.9.2.3.2)
  As an AMF serving a strict NG-RAN node (free5gc/ngap v1.2.0, PacketRusher acf96b5)
  I want to answer a PATH SWITCH REQUEST with a complete PATH SWITCH REQUEST ACKNOWLEDGE
  and to leave the release of the source gNB to the target gNB over XnAP
  So that the Xn handover completes without an Abstract Syntax Error and the NH/NCC key chain stays in sync with the UE
  (AMF-011; design: docs/procedures/XnHandover.md)

  Background:
    Given the AMF NGAP builders are available
    And UE with SUPI "imsi-001010000000001" has AMF UE NGAP ID 1 and RAN UE NGAP ID 1 on source gNB "gnb-source"
    And target gNB "gnb-target" completed NG Setup with the AMF
    And the UE has a KAMF and an Allowed NSSAI of SST 1 SD "000001"
    And the UE has PDU session id 5 on S-NSSAI SST 1 SD "000001"
    And the UE has Security Capabilities stored in the AMF
    And an Initial Context Setup established a KgNB of 256 bits so the NH chain holds NH1 = KNH(KAMF, KgNB) with NCC 1

  # --- Path Switch Request Acknowledge content (TS 38.413 Table 9.2.3.9-1) ---------------------

  # AMF-011 AC1: all mandatory IEs, spec order, strict decoder
  @happy @ie-order @strict-decoder
  Scenario: Path Switch Request Acknowledge carries every mandatory IE in Table 9.2.3.9-1 order
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the message is a successfulOutcome of procedure code 25
    And the IEs appear in this order:
      | IE                                 | id |
      | AMFUENGAPID                        | 10 |
      | RANUENGAPID                        | 85 |
      | SecurityContext                    | 93 |
      | PDUSessionResourceSwitchedList     | 77 |
      | AllowedNSSAI                       | 0  |
    And the AMF UE NGAP ID is 1 and the RAN UE NGAP ID is 7
    And the PDUSessionResourceSwitchedList contains 1 item for PDU session id 5
    And the AllowedNSSAI contains SST 1 SD "000001"
    And the Security Context NH is 256 bits long

  # TS 38.413 §9.3.1.18 + TS 33.501 §6.9.2.1.1: first Ack after ICS carries NCC=2
  @happy @nh-ncc
  Scenario: First Path Switch after Initial Context Setup carries NCC 2 and NH2 = KNH(KAMF, NH1)
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the Security Context Next Hop Chaining Count is 2
    And the Security Context NH equals KNH(KAMF, KNH(KAMF, KgNB))
    And the AMF logs the new "ncc" but never the NH value

  @happy @nh-ncc
  Scenario: Second consecutive Path Switch chains NCC 3 and NH3 = KNH(KAMF, NH2)
    Given the UE already completed one Xn path switch with the AMF
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 9 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the Security Context Next Hop Chaining Count is 3
    And the Security Context NH equals KNH(KAMF, KNH(KAMF, KNH(KAMF, KgNB)))

  # TS 33.501 §6.9.2.3.2: NCC is a 3-bit counter, wrap is on the counter only
  @happy @nh-ncc @ncc-wrap
  Scenario Outline: NCC wraps modulo 8 while the NH keeps deriving from the previous NH
    Given the NH chain of the UE holds NCC <before>
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the Security Context Next Hop Chaining Count is <after>
    And the Security Context NH equals KNH(KAMF, previous NH)

    Examples:
      | before | after |
      | 1      | 2     |
      | 6      | 7     |
      | 7      | 0     |
      | 0      | 1     |

  @happy @nh-ncc
  Scenario: A newly established KgNB resets the NH chain to NH1 with NCC 1
    Given the UE already completed 3 Xn path switches with the AMF
    When a new KgNB is established by an Initial Context Setup
    Then the stored NCC is 1
    And the stored NH equals KNH(KAMF, new KgNB)

  # TS 33.501 §6.9.2.3.2: both leg sides use one chain — N2 HO continues where Xn HO stopped
  @happy @nh-ncc @n2-handover
  Scenario: HANDOVER REQUEST continues the NH/NCC chain after an Xn path switch
    Given the UE already completed one Xn path switch with the AMF
    When the AMF builds a HANDOVER REQUEST for the UE towards the target gNB
    Then the encoded PDU decodes cleanly with free5gc/ngap
    And the Security Context Next Hop Chaining Count is 3
    And the Security Context NH equals KNH(KAMF, KNH(KAMF, KNH(KAMF, KgNB)))

  @happy @nh-ncc @n2-handover
  Scenario: First HANDOVER REQUEST after Initial Context Setup carries NCC 2 not NCC 1
    When the AMF builds a HANDOVER REQUEST for the UE towards the target gNB
    Then the Security Context Next Hop Chaining Count is 2
    And the Security Context NH equals KNH(KAMF, KNH(KAMF, KgNB))

  # --- No source gNB signalling (AMF-011 AC2) -------------------------------------------------

  # TS 23.502 §4.9.1.2.2 step 8: target releases the source over XnAP
  @happy @no-source-release
  Scenario: No UE CONTEXT RELEASE COMMAND is sent to the source gNB after a successful Path Switch
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then no NGAP message is written to the source gNB connection
    And no UE CONTEXT RELEASE COMMAND (procedure code 41) is written to any gNB connection
    And the UE is not flagged for removal

  @happy @rebind
  Scenario: UE-associated NG connection is re-bound to the target gNB with the new RAN UE NGAP ID
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the UE RAN UE NGAP ID is 7 and its serving gNB is "gnb-target"
    And the target gNB maps RAN UE NGAP ID 7 to the UE
    And the source gNB no longer maps RAN UE NGAP ID 1
    And the UE stays in CM-CONNECTED
    And the AMF UE NGAP ID is still 1

  # --- Transport (AMF-011 AC4, TS 38.412 §7) --------------------------------------------------

  @happy @ppid
  Scenario: Path Switch Request Acknowledge is sent with SCTP PPID 60
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then every NGAP PDU written by the AMF carries SCTP PPID 60

  @happy @ppid @n2-handover
  Scenario: N2 handover messages HANDOVER REQUEST and HANDOVER COMMAND are sent with SCTP PPID 60
    Given the source gNB sends a HANDOVER REQUIRED for the UE towards "gnb-target"
    And the target gNB answers with a HANDOVER REQUEST ACKNOWLEDGE
    When the AMF handles both messages
    Then the HANDOVER REQUEST written to the target gNB carries SCTP PPID 60
    And the HANDOVER COMMAND written to the source gNB carries SCTP PPID 60

  # --- Allowed NSSAI rule (procedure doc §7.3) ------------------------------------------------

  @happy @allowed-nssai
  Scenario: Empty Allowed NSSAI falls back to the S-NSSAIs of the established PDU sessions
    Given the UE Allowed NSSAI is empty
    And the UE has PDU session id 5 on S-NSSAI SST 1 SD "000001"
    And the UE has PDU session id 6 on S-NSSAI SST 2 SD "000002"
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 5 and 6
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the AllowedNSSAI contains exactly SST 1 SD "000001" and SST 2 SD "000002"
    And the fallback is logged with level WARN and allowed_nssai_fallback "pdu_sessions"

  @happy @allowed-nssai
  Scenario: Duplicate S-NSSAIs in the UE Allowed NSSAI appear once in the Ack
    Given the UE Allowed NSSAI holds SST 1 SD "000001" twice with different DNNs
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the AllowedNSSAI contains exactly SST 1 SD "000001"

  # --- Path Switch Request Failure (TS 38.413 §8.4.4.3, Table 9.2.3.10-1) ---------------------

  # Doc §5: Allowed NSSAI empty and nothing to fall back to
  @rejection @allowed-nssai
  Scenario: Empty Allowed NSSAI and no PDU session S-NSSAI yields PATH SWITCH REQUEST FAILURE with cause unspecified
    Given the UE Allowed NSSAI is empty
    And the S-NSSAI of every PDU session of the UE is absent
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the encoded PDU decodes cleanly with free5gc/ngap
    And the message is an unsuccessfulOutcome of procedure code 25
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 5 with misc cause "unspecified"
    And no PATH SWITCH REQUEST ACKNOWLEDGE is sent
    And the UE is not re-bound to the target gNB
    And the failure is logged with result "REJECT" and spec_ref "TS 38.413 §8.4.4.3"

  # Doc §5: unknown Source AMF UE NGAP ID
  @error @unknown-ue
  Scenario: PATH SWITCH REQUEST with an unknown Source AMF UE NGAP ID yields PATH SWITCH REQUEST FAILURE
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 4242 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the failure echoes AMF UE NGAP ID 4242 and RAN UE NGAP ID 7
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 5 with radioNetwork cause "unknown-local-UE-NGAP-ID"
    And the failure is logged with result "REJECT"
    And no UE CONTEXT RELEASE COMMAND (procedure code 41) is written to any gNB connection

  @rejection @pdu-session
  Scenario: PATH SWITCH REQUEST for PDU sessions the UE does not have yields PATH SWITCH REQUEST FAILURE
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 11
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 11 with radioNetwork cause "unknown-PDU-session-ID"
    And the UE is not re-bound to the target gNB

  @rejection @pdu-session
  Scenario: PATH SWITCH REQUEST with a duplicated PDU session id yields PATH SWITCH REQUEST FAILURE
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 5 and 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 5 with radioNetwork cause "multiple-PDU-session-ID-instances"

  @rejection @security-context
  Scenario: PATH SWITCH REQUEST for a UE without a usable security context yields PATH SWITCH REQUEST FAILURE
    Given the UE has no KgNB so the NH chain was never initialised
    And the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session id 5
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST FAILURE to the target gNB
    And the PDUSessionResourceReleasedListPSFail (id 69) contains PDU session id 5 with misc cause "unspecified"
    And no PATH SWITCH REQUEST ACKNOWLEDGE with a zero NH is sent
    And the failure is logged with level ERROR

  # --- Partial success and UE security capabilities -------------------------------------------

  @happy @partial
  Scenario: Unknown PDU session id is reported in the Released List while known ones are switched
    Given the target gNB sends a PATH SWITCH REQUEST with new RAN UE NGAP ID 7 and Source AMF UE NGAP ID 1 for PDU session ids 5 and 11
    When the AMF handles the PATH SWITCH REQUEST
    Then the AMF sends a PATH SWITCH REQUEST ACKNOWLEDGE to the target gNB
    And the IEs appear in this order:
      | IE                                 | id |
      | AMFUENGAPID                        | 10 |
      | RANUENGAPID                        | 85 |
      | SecurityContext                    | 93 |
      | PDUSessionResourceSwitchedList     | 77 |
      | PDUSessionResourceReleasedListPSAck| 68 |
      | AllowedNSSAI                       | 0  |
    And the PDUSessionResourceSwitchedList contains only PDU session id 5
    And the PDUSessionResourceReleasedListPSAck contains PDU session id 11 with radioNetwork cause "unknown-PDU-session-ID"

  # TS 38.413 §8.4.4.2 / TS 33.501 §6.7.3.1
  @happy @ue-security-capabilities
  Scenario: UE Security Capabilities in the request differ from the stored ones so the Ack returns the stored capabilities
    Given the target gNB sends a PATH SWITCH REQUEST whose UE Security Capabilities differ from those stored in the AMF
    When the AMF handles the PATH SWITCH REQUEST
    Then the IEs appear in this order:
      | IE                                 | id  |
      | AMFUENGAPID                        | 10  |
      | RANUENGAPID                        | 85  |
      | UESecurityCapabilities             | 119 |
      | SecurityContext                    | 93  |
      | PDUSessionResourceSwitchedList     | 77  |
      | AllowedNSSAI                       | 0   |
    And the UESecurityCapabilities equal the capabilities stored in the AMF
    And the mismatch is logged with level WARN

  @happy @ue-security-capabilities
  Scenario: Matching UE Security Capabilities are not echoed in the Ack
    Given the target gNB sends a PATH SWITCH REQUEST whose UE Security Capabilities equal those stored in the AMF
    When the AMF handles the PATH SWITCH REQUEST
    Then the message does not contain the "UESecurityCapabilities" IE (id 119)

  # --- HANDOVER REQUEST UE-AMBR (AMF-011 AC5, TS 38.413 Table 9.2.3.4-1, TS 23.501 §5.7.2.6) ---

  @happy @ue-ambr @n2-handover
  Scenario: HANDOVER REQUEST carries the subscribed UE-AMBR
    Given the subscribed UE-AMBR is 200000 kbit/s uplink and 500000 kbit/s downlink
    When the AMF builds a HANDOVER REQUEST for the UE towards the target gNB
    Then the encoded PDU decodes cleanly with free5gc/ngap
    And the message contains the "UEAggregateMaximumBitRate" IE (id 110) with criticality reject
    And the UE-AMBR uplink is 200000000 bit/s and downlink is 500000000 bit/s

  @error @ue-ambr @default-ambr @n2-handover
  Scenario: Subscription without subscribed UE-AMBR falls back to 1 Gbps in the HANDOVER REQUEST
    Given the subscription has no subscribedUeAmbr
    When the AMF builds a HANDOVER REQUEST for the UE towards the target gNB
    Then the message contains the "UEAggregateMaximumBitRate" IE (id 110) with criticality reject
    And the UE-AMBR uplink is 1000000000 bit/s and downlink is 1000000000 bit/s

  @happy @ue-ambr @n2-handover
  Scenario: HANDOVER REQUEST UE-AMBR is not the hard-coded 1 Gbps when a subscription exists
    Given the subscribed UE-AMBR is 2000000 kbit/s uplink and 4000000 kbit/s downlink
    When the AMF builds a HANDOVER REQUEST for the UE towards the target gNB
    Then the UE-AMBR uplink is 2000000000 bit/s and downlink is 4000000000 bit/s

  # --- Runtime acceptance (AMF-011 AC3) -------------------------------------------------------

  @e2e @happy
  Scenario: PacketRusher completes the Xn handover without an NGAP decode error
    Given the live stack is up with RAN "packetrusher" and PR_SCENARIO "xn"
    When "make handover-test" is run
    Then the PacketRusher Xn scenario completes the Path Switch
    And the target gNB logs no NGAP decode error and no "mandatory IE SecurityContext is missing"
    And the AMF logs no UE CONTEXT RELEASE COMMAND to the source gNB for the UE
    And the "XnHandover" procedure summary reports zero failures
