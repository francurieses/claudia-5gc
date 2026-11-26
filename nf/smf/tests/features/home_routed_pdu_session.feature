# Home-routed PDU Session Establishment and Release (V-SMF / H-SMF over N16)
# (TS 23.502 §4.3.2.2.2 HR establishment, §4.3.4.3 HR release,
#  TS 29.502 Nsmf_PDUSession Create / Release on /pdu-sessions, TS 23.501 §4.2.4,
#  TS 29.500 §6.1.4.3.3 3gpp-Sbi-Target-apiRoot, TS 24.501 §9.11.4.2 5GSM cause)
#
# Scope (Phase 1, control plane): in-process SMF in both roles (V-SMF and H-SMF are the
# same binary, role chosen by hSmfUri in SmContextCreateData). Peers are httptest mocks
# (local SEPP / H-SMF / hUDM) plus a PFCP stub UPF. The N9 GTP-U user plane is Phase 2
# and UE-initiated release (modify + StatusNotify) is Phase 1b: both out of scope here.
# Design contract: docs/procedures/HomeRoutedPduSession.md (§4 IEs, §5 error cases, §7).

@roaming @home_routed @phase1
Feature: Home-routed PDU Session establishment and release between V-SMF and H-SMF
  As a roaming UE registered in the VPLMN
  I want the V-SMF and the H-SMF to establish a home-routed PDU session over N16
  So that my traffic is anchored at the H-UPF with a UE IP from the HPLMN pool

  Background:
    Given the SMF runs in-process with a PFCP stub V-UPF and a mock local SEPP
    And the VPLMN is "001/01" and the HPLMN is "001/02"

  # --- V-SMF happy path (TS 23.502 §4.3.2.2.2 steps 3-17) ---

  @vsmf
  Scenario: V-SMF establishes a home-routed PDU session and accepts it with the H-SMF UE IP
    Given an SmContextCreateData with hSmfUri "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004/nsmf-pdusession/v1", hplmnSnssai and full DNN "internet.mnc002.mcc001.gprs"
    And the mock H-SMF answers 201 with PduSessionCreatedData carrying ueIpv4Address "10.60.0.2", hcnTunnelInfo and qosRules octets "0x0100" in qosFlowsSetupList
    When the AMF sends the Nsmf_PDUSession CreateSMContext request to the V-SMF
    Then the V-SMF does not send any Nudm_SDM sm-data request to the visited UDM
    And the V-SMF does not send any Npcf_SMPolicyControl request
    And the V-SMF establishes the N4 session on the V-UPF with an N3 F-TEID and an N9 F-TEID
    And the local SEPP receives POST "/nsmf-pdusession/v1/pdu-sessions" with header "3gpp-Sbi-Target-apiRoot" equal to "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004"
    And the PduSessionCreateData carries vcnTunnelInfo, chargingId, n1SmInfoFromUe, vsmfId and vsmfPduSessionUri
    And the V-SMF updates the V-UPF UL FAR with Outer Header Creation towards the hcnTunnelInfo
    And the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT ACCEPT carrying UE IP "10.60.0.2"
    And the qosRules in the PDU SESSION ESTABLISHMENT ACCEPT equal the H-SMF qosRules octets unchanged

  # --- H-SMF happy path (TS 29.502 §5.2.2.7.1) ---

  @hsmf
  Scenario: H-SMF creates the home-routed PDU session and returns PduSessionCreatedData
    Given a PduSessionCreateData with full DNN "internet.mnc002.mcc001.gprs", HPLMN sNssai, vcnTunnelInfo, vsmfId, vsmfPduSessionUri and n1SmInfoFromUe
    And the mock hUDM holds sm-data for the HPLMN S-NSSAI and DNN "internet"
    And the PFCP stub H-UPF accepts the Session Establishment Request
    When the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions" to the H-SMF
    Then the H-SMF fetches sm-data from its own UDM with the HPLMN S-NSSAI
    And the DNN used for the sm-data lookup has the Operator Identifier stripped, "internet"
    And the H-SMF allocates the UE IPv4 address from its own pool
    And the H-UPF UL PDR has Source Interface "Access" and the N9 F-TEID
    And the H-UPF DL FAR has Outer Header Creation towards the vcnTunnelInfo
    And the H-SMF responds 201 with a Location header ending in "/pdu-sessions/{pduSessionRef}"
    And the PduSessionCreatedData carries hcnTunnelInfo, ueIpv4Address, sessionAmbr and qosFlowsSetupList

  # --- H-SMF rejections (docs/procedures/HomeRoutedPduSession.md §5) ---

  @hsmf @rejection
  Scenario Outline: H-SMF rejects the home-routed PDU session and the V-SMF rejects the UE with the 5GSM cause
    Given a PduSessionCreateData whose "<condition>"
    And the V-SMF has established the N4 session on the V-UPF
    When the H-SMF processes POST "/nsmf-pdusession/v1/pdu-sessions"
    Then the H-SMF responds <http_status> with a PduSessionCreateError whose ProblemDetails cause is "<cause>"
    And the PduSessionCreateError carries n1smCause "<n1sm_cause>"
    And the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause <gsm_cause>
    And the V-SMF deletes its V-UPF N4 session

    Examples:
      | condition                               | http_status | cause                | n1sm_cause | gsm_cause |
      | DNN is not subscribed in the hUDM       | 403         | DNN_DENIED           | 1B         | 27        |
      | HPLMN S-NSSAI is not subscribed         | 403         | SNSSAI_DENIED        | 21         | 33        |
      | no sm-data exists for the SUPI          | 403         | SUBSCRIPTION_DENIED  | 21         | 33        |
      | H-UPF N4 establishment fails            | 500         | SYSTEM_FAILURE       | 1A         | 26        |

  @hsmf @rejection
  Scenario Outline: H-SMF rejects a PduSessionCreateData missing a mandatory HR-conditional attribute with 400
    Given a PduSessionCreateData without "<missing_attribute>"
    When the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions" to the H-SMF
    Then the H-SMF responds 400 with a PduSessionCreateError whose ProblemDetails cause is "MANDATORY_IE_MISSING"
    And no N4 session is established on the H-UPF
    And no UE IP address is allocated from the H-SMF pool

    Examples:
      | missing_attribute  |
      | vcnTunnelInfo      |
      | vsmfId             |
      | vsmfPduSessionUri  |
      | dnn                |

  @vsmf @rejection
  Scenario: V-SMF uses the fallback 5GSM cause when the H-SMF error has no n1smCause
    Given the mock H-SMF answers 403 with a PduSessionCreateError cause "N1_SM_ERROR" without n1smCause
    When the AMF sends the Nsmf_PDUSession CreateSMContext request to the V-SMF
    Then the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 111
    And the V-SMF deletes its V-UPF N4 session

  @vsmf @rejection
  Scenario: V-SMF parses a plain ProblemDetails raised by the SEPP
    Given the mock local SEPP answers 504 with a plain ProblemDetails cause "TARGET_NF_NOT_REACHABLE"
    When the AMF sends the Nsmf_PDUSession CreateSMContext request to the V-SMF
    Then the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 38
    And the V-SMF deletes its V-UPF N4 session

  @vsmf @rejection
  Scenario: H-SMF 201 without hcnTunnelInfo is released and rejected
    Given the mock H-SMF answers 201 with PduSessionCreatedData lacking hcnTunnelInfo
    When the AMF sends the Nsmf_PDUSession CreateSMContext request to the V-SMF
    Then the V-SMF sends POST "{hSmfPduSessionRef}/release" to the H-SMF via the local SEPP
    And the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 38
    And the V-SMF deletes its V-UPF N4 session

  @vsmf @rejection
  Scenario: V-UPF N4 establishment failure rejects without any N16 call
    Given the PFCP stub V-UPF rejects the Session Establishment Request
    When the AMF sends the Nsmf_PDUSession CreateSMContext request to the V-SMF
    Then the local SEPP receives no request
    And the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 26

  # --- Error path: peer unreachable (§5 N32 / peer timeout row) ---

  @vsmf @error
  Scenario Outline: V-SMF rejects with 5GSM cause 38 when the H-SMF path is unavailable
    Given the home-routed path fails because "<failure>"
    When the AMF sends the Nsmf_PDUSession CreateSMContext request to the V-SMF
    Then the V-SMF answers the AMF with a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 38
    And the V-SMF deletes its V-UPF N4 session
    And the V-SMF logs result "FAILURE" with interface "N16" and smf_role "V-SMF"

    Examples:
      | failure                                    |
      | the local SEPP is unreachable              |
      | the local SEPP answers 500                 |
      | the H-SMF does not answer within the timeout |

  # --- Release, serving-network initiated (TS 23.502 §4.3.4.3) ---

  @vsmf @hsmf @release
  Scenario: AMF releases the SM context and the V-SMF releases the H-SMF session over N16
    Given an established home-routed PDU session with hSmfPduSessionRef "{hSmfPduSessionRef}"
    When the AMF sends the Nsmf_PDUSession ReleaseSMContext request to the V-SMF
    Then the V-SMF sends POST "{hSmfPduSessionRef}/release" via the local SEPP with header "3gpp-Sbi-Target-apiRoot"
    And the H-SMF deletes the H-UPF N4 session
    And the H-SMF answers 204
    And the V-SMF deletes its V-UPF N4 session
    And the V-SMF answers the AMF with 204

  @vsmf @release @error
  Scenario: V-SMF completes local release even if the N16 release fails
    Given an established home-routed PDU session with hSmfPduSessionRef "{hSmfPduSessionRef}"
    And the N16 release request fails with a 5xx
    When the AMF sends the Nsmf_PDUSession ReleaseSMContext request to the V-SMF
    Then the V-SMF deletes its V-UPF N4 session
    And the V-SMF answers the AMF with 204
    And the V-SMF logs a WARN "hsmf_release_failed"

  @hsmf @release @rejection
  Scenario: H-SMF release on an unknown pduSessionRef answers 404 CONTEXT_NOT_FOUND
    Given the H-SMF has no session for pduSessionRef "unknown-ref"
    When the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions/unknown-ref/release" to the H-SMF
    Then the H-SMF responds 404 with ProblemDetails cause "CONTEXT_NOT_FOUND"

  # --- Legacy / byte identity (Rel-15/16/17 peers unchanged, docs §7.6) ---

  @golden @legacy
  Scenario Outline: Non-roaming CreateSMContext is unchanged under both release profiles
    Given the release profile is "<profile>"
    And an SmContextCreateData without hSmfUri
    When the AMF sends the Nsmf_PDUSession CreateSMContext request to the SMF
    Then the SMF fetches sm-data from the local UDM
    And the SMF sends no request to a SEPP
    And the PFCP Session Establishment Request bytes equal the golden "non_roaming_n4_establishment"
    And the SMF behaves as neither V-SMF nor H-SMF

    Examples:
      | profile |
      | rel17   |
      | rel19   |

  @golden @legacy
  Scenario: SMF NRF profile without sbi.fqdn is unchanged
    Given the SMF config has no sbi.fqdn
    When the SMF builds its NRF NFProfile
    Then the NFProfile bytes equal the golden "smf_nfprofile_no_fqdn"
    And the NFProfile has no fqdn attribute

  @hsmf @legacy
  Scenario: SMF NRF profile with sbi.fqdn carries the fqdn so the hSEPP can discover the H-SMF
    Given the SMF config has sbi.fqdn "smf.5gc.mnc002.mcc001.3gppnetwork.org"
    When the SMF builds its NRF NFProfile
    Then the NFProfile carries fqdn "smf.5gc.mnc002.mcc001.3gppnetwork.org"
    And the NFProfile lists service "nsmf-pdusession"
