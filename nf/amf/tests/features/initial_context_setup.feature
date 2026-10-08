Feature: Initial Context Setup — UE-AMBR conditional presence (TS 38.413 §8.3.1, §9.2.2.1, §8.2.1, §9.2.1.1, §9.3.1.58)
  As an AMF talking to a strict NG-RAN node (free5gc/ngap v1.2.0, PacketRusher acf96b5)
  I want UE Aggregate Maximum Bit Rate in the INITIAL CONTEXT SETUP REQUEST only when the
  PDU Session Resource Setup Request List is present, and delivered otherwise in the
  PDU SESSION RESOURCE SETUP REQUEST
  So that the gNB never rejects the message with an Abstract Syntax Error (TS 38.413 §10.3)

  Background:
    Given the AMF NGAP builders are available
    And UE with SUPI "imsi-001010000000001" has AMF UE NGAP ID 1 and RAN UE NGAP ID 1
    And the UE has Security Capabilities, a KgNB of 256 bits and GUAMI "001/01/cafe00"

  # --- ICS Request without PDU sessions (Initial Registration) -------------------------------

  # TS 38.413 Table 9.2.2.1-1: UE-AMBR is C-ifPDUsessionResourceSetup
  @happy @initial-registration
  Scenario: Initial Registration ICS Request carries no UE-AMBR
    Given the subscribed UE-AMBR is 2000000 kbit/s uplink and 4000000 kbit/s downlink
    And no PDU sessions are to be activated
    When the AMF builds the INITIAL CONTEXT SETUP REQUEST with the Registration Accept NAS-PDU
    Then the encoded PDU decodes cleanly with free5gc/ngap
    And the message is an initiatingMessage of procedure code 14 with criticality reject
    And the message does not contain the "UEAggregateMaximumBitRate" IE (id 110)
    And the message does not contain the "PDUSessionResourceSetupListCxtReq" IE (id 71)
    And the message contains the mandatory IEs "AMFUENGAPID", "RANUENGAPID", "GUAMI", "UESecurityCapabilities", "SecurityKey" and "NASPDU"

  # TS 38.413 §10.3: a conditional IE whose condition is unmet is "erroneously present"
  @rejection @strict-decoder
  Scenario Outline: The encoded ICS Request never contains a conditional IE whose condition is unmet
    Given the subscribed UE-AMBR is <ul> kbit/s uplink and <dl> kbit/s downlink
    And no PDU sessions are to be activated
    And the registration case is "<case>"
    When the AMF builds the INITIAL CONTEXT SETUP REQUEST with the Registration Accept NAS-PDU
    Then a strict conditional-presence check reports no Abstract Syntax Error
    And the check "UEAggregateMaximumBitRate must not be present if PDUSessionResourceSetupListCxtReq is not present" passes

    Examples:
      | case                  | ul      | dl      |
      | initial registration  | 1000000 | 1000000 |
      | mobility registration | 500000  | 500000  |
      | periodic registration | 2000000 | 4000000 |
      | no subscribed UE-AMBR | 0       | 0       |

  # TS 23.502 §4.2.3.2 step 12: nothing was activated, so IE 71 is absent and UE-AMBR must be too
  @rejection @service-request
  Scenario: Service Request with zero activated PDU sessions yields an ICS Request without UE-AMBR
    Given the subscribed UE-AMBR is 1000000 kbit/s uplink and 1000000 kbit/s downlink
    And the UE sent a Service Request whose Uplink Data Status is empty
    When the AMF builds the INITIAL CONTEXT SETUP REQUEST with the Service Accept NAS-PDU
    Then the encoded PDU decodes cleanly with free5gc/ngap
    And the message does not contain the "UEAggregateMaximumBitRate" IE (id 110)
    And the message does not contain the "PDUSessionResourceSetupListCxtReq" IE (id 71)
    And the message contains the mandatory IEs "AMFUENGAPID", "RANUENGAPID", "GUAMI", "UESecurityCapabilities", "SecurityKey" and "NASPDU"

  @rejection @service-request
  Scenario: Service Request where every PDU session activation failed yields an ICS Request without UE-AMBR
    Given the UE sent a Service Request whose Uplink Data Status flags PDU session ids 5 and 6
    And the SMF fails the activation of PDU session ids 5 and 6
    When the AMF builds the INITIAL CONTEXT SETUP REQUEST with the Service Accept NAS-PDU
    Then the message does not contain the "UEAggregateMaximumBitRate" IE (id 110)
    And the message does not contain the "PDUSessionResourceSetupListCxtReq" IE (id 71)

  # --- ICS Request with PDU sessions (Service Request) ---------------------------------------

  # TS 38.413 Table 9.2.2.1-1: UE-AMBR present iff IE 71 present, in spec order
  @happy @service-request
  Scenario: Service Request ICS Request with an activated PDU session carries UE-AMBR and the session list
    Given the subscribed UE-AMBR is 2000000 kbit/s uplink and 4000000 kbit/s downlink
    And the UE has PDU session id 5 on S-NSSAI SST 1 SD "000001" to be activated with a PDUSessionResourceSetupRequestTransfer
    When the AMF builds the INITIAL CONTEXT SETUP REQUEST with the Service Accept NAS-PDU
    Then the encoded PDU decodes cleanly with free5gc/ngap
    And the message contains the "UEAggregateMaximumBitRate" IE (id 110) with criticality reject
    And the UE-AMBR uplink is 2000000000 bit/s and downlink is 4000000000 bit/s
    And the message contains the "PDUSessionResourceSetupListCxtReq" IE (id 71) with 1 item for PDU session id 5
    And the message contains the mandatory IEs "AMFUENGAPID", "RANUENGAPID", "GUAMI", "UESecurityCapabilities", "SecurityKey" and "NASPDU"

  @happy @ie-order
  Scenario: ICS Request IEs follow Table 9.2.2.1-1 order when PDU sessions are activated
    Given the subscribed UE-AMBR is 1000000 kbit/s uplink and 1000000 kbit/s downlink
    And the UE has PDU session id 5 on S-NSSAI SST 1 SD "000001" to be activated with a PDUSessionResourceSetupRequestTransfer
    And the UE has an Allowed NSSAI and an Index to RFSP of 10
    When the AMF builds the INITIAL CONTEXT SETUP REQUEST with the Service Accept NAS-PDU
    Then the IEs appear in this order:
      | IE                                | id  |
      | AMFUENGAPID                       | 10  |
      | RANUENGAPID                       | 85  |
      | UEAggregateMaximumBitRate         | 110 |
      | GUAMI                             | 28  |
      | PDUSessionResourceSetupListCxtReq | 71  |
      | AllowedNSSAI                      | 0   |
      | UESecurityCapabilities            | 119 |
      | SecurityKey                       | 94  |
      | IndexToRFSP                       | 31  |
      | NASPDU                            | 38  |

  @happy @ie-order
  Scenario: ICS Request IEs follow Table 9.2.2.1-1 order when no PDU session is activated
    Given the UE has an Allowed NSSAI and an Index to RFSP of 10
    And no PDU sessions are to be activated
    When the AMF builds the INITIAL CONTEXT SETUP REQUEST with the Registration Accept NAS-PDU
    Then the IEs appear in this order:
      | IE                     | id  |
      | AMFUENGAPID            | 10  |
      | RANUENGAPID            | 85  |
      | GUAMI                  | 28  |
      | AllowedNSSAI           | 0   |
      | UESecurityCapabilities | 119 |
      | SecurityKey            | 94  |
      | IndexToRFSP            | 31  |
      | NASPDU                 | 38  |

  # TS 23.501 §5.7.2.6 + procedure doc §5: operator default 1 Gbps when subscription lacks UE-AMBR
  @error @default-ambr
  Scenario: Subscription without subscribed UE-AMBR falls back to 1 Gbps in the ICS Request with PDU sessions
    Given the subscription has no subscribedUeAmbr
    And the UE has PDU session id 5 on S-NSSAI SST 1 SD "000001" to be activated with a PDUSessionResourceSetupRequestTransfer
    When the AMF builds the INITIAL CONTEXT SETUP REQUEST with the Service Accept NAS-PDU
    Then the message contains the "UEAggregateMaximumBitRate" IE (id 110) with criticality reject
    And the UE-AMBR uplink is 1000000000 bit/s and downlink is 1000000000 bit/s
    And the message contains the "PDUSessionResourceSetupListCxtReq" IE (id 71) with 1 item for PDU session id 5

  # --- PDU SESSION RESOURCE SETUP REQUEST (TS 38.413 §8.2.1, Table 9.2.1.1-1) -----------------

  @happy @pdu-session-setup
  Scenario: First PDU session after a registration whose ICS omitted UE-AMBR delivers UE-AMBR in the PDU SESSION RESOURCE SETUP REQUEST
    Given the subscribed UE-AMBR is 2000000 kbit/s uplink and 4000000 kbit/s downlink
    And the gNB has not yet received a UE-AMBR for this UE in the current N2 context
    And the SMF returns a PDUSessionResourceSetupRequestTransfer for PDU session id 1 on S-NSSAI SST 1 SD "000001"
    When the AMF builds the PDU SESSION RESOURCE SETUP REQUEST
    Then the encoded PDU decodes cleanly with free5gc/ngap
    And the message is an initiatingMessage of procedure code 29
    And the message contains the "UEAggregateMaximumBitRate" IE (id 110) with criticality ignore
    And the UE-AMBR uplink is 2000000000 bit/s and downlink is 4000000000 bit/s
    And the message contains the "PDUSessionResourceSetupListSUReq" IE (id 74) with 1 item for PDU session id 1

  @happy @pdu-session-setup @ie-order
  Scenario: PDU SESSION RESOURCE SETUP REQUEST places UE-AMBR after the PDU Session Resource Setup Request List
    Given the gNB has not yet received a UE-AMBR for this UE in the current N2 context
    And the SMF returns a PDUSessionResourceSetupRequestTransfer for PDU session id 1 on S-NSSAI SST 1 SD "000001"
    When the AMF builds the PDU SESSION RESOURCE SETUP REQUEST
    Then the IEs appear in this order:
      | IE                                | id  |
      | AMFUENGAPID                       | 10  |
      | RANUENGAPID                       | 85  |
      | PDUSessionResourceSetupListSUReq  | 74  |
      | UEAggregateMaximumBitRate         | 110 |

  @error @default-ambr @pdu-session-setup
  Scenario: Subscription without subscribed UE-AMBR falls back to 1 Gbps in the PDU SESSION RESOURCE SETUP REQUEST
    Given the subscription has no subscribedUeAmbr
    And the gNB has not yet received a UE-AMBR for this UE in the current N2 context
    And the SMF returns a PDUSessionResourceSetupRequestTransfer for PDU session id 1 on S-NSSAI SST 1 SD "000001"
    When the AMF builds the PDU SESSION RESOURCE SETUP REQUEST
    Then the message contains the "UEAggregateMaximumBitRate" IE (id 110) with criticality ignore
    And the UE-AMBR uplink is 1000000000 bit/s and downlink is 1000000000 bit/s

  # Procedure doc §7.2: not re-sent unnecessarily once the gNB holds the UE-AMBR
  @happy @pdu-session-setup @not-resent
  Scenario: UE-AMBR already delivered by an ICS Request with PDU sessions is not re-sent in the PDU SESSION RESOURCE SETUP REQUEST
    Given the gNB already received a UE-AMBR for this UE in an INITIAL CONTEXT SETUP REQUEST with PDU sessions
    And the SMF returns a PDUSessionResourceSetupRequestTransfer for PDU session id 2 on S-NSSAI SST 1 SD "000001"
    When the AMF builds the PDU SESSION RESOURCE SETUP REQUEST
    Then the message does not contain the "UEAggregateMaximumBitRate" IE (id 110)
    And the message contains the "PDUSessionResourceSetupListSUReq" IE (id 74) with 1 item for PDU session id 2

  @happy @pdu-session-setup @not-resent
  Scenario: UE-AMBR already delivered by a previous PDU SESSION RESOURCE SETUP REQUEST is not re-sent for a second PDU session
    Given the gNB already received a UE-AMBR for this UE in a PDU SESSION RESOURCE SETUP REQUEST
    And the SMF returns a PDUSessionResourceSetupRequestTransfer for PDU session id 2 on S-NSSAI SST 1 SD "000001"
    When the AMF builds the PDU SESSION RESOURCE SETUP REQUEST
    Then the message does not contain the "UEAggregateMaximumBitRate" IE (id 110)

  @happy @pdu-session-setup @n2-context
  Scenario: UE-AMBR is delivered again after the N2 context was released and re-established by a registration
    Given the gNB already received a UE-AMBR for this UE in a PDU SESSION RESOURCE SETUP REQUEST
    And the UE Context Release Complete was received for the UE
    And a new Initial Registration ICS Request without UE-AMBR was sent
    And the SMF returns a PDUSessionResourceSetupRequestTransfer for PDU session id 1 on S-NSSAI SST 1 SD "000001"
    When the AMF builds the PDU SESSION RESOURCE SETUP REQUEST
    Then the message contains the "UEAggregateMaximumBitRate" IE (id 110) with criticality ignore

  # --- gNB failure outcome (TS 38.413 §8.3.1.3) -----------------------------------------------

  @error @ics-failure
  Scenario: INITIAL CONTEXT SETUP FAILURE releases the UE context and de-registers the UE
    Given UE "imsi-001010000000001" is in 5GMM-REGISTERED state after an ICS Request was sent
    When the gNB answers with INITIAL CONTEXT SETUP FAILURE with protocol cause "abstract-syntax-error-falsely-constructed-message"
    Then the UE transitions to 5GMM-DEREGISTERED and is flagged for removal
    And the AMF sends a UE CONTEXT RELEASE COMMAND with radioNetwork cause "release-due-to-5gc-generated-reason"
    And the failure is logged with result "FAILURE" and spec_ref "TS 38.413 §8.3.1.3"
