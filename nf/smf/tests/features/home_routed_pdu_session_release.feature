# Home-routed PDU Session Release (UE-initiated, serving-network, H-SMF hardening) [ROAM-002]
# (TS 23.502 §4.3.4.3 step 1a and 4a-4b HR release,
#  TS 29.502 §5.2.2.8.2.3 Update (UE_REQ_PDU_SES_REL) and §5.2.2.9 Release on /pdu-sessions,
#  TS 29.500 Table 5.2.7.2-1 application errors, TS 29.500 §5.2.3.2.x 3gpp-Sbi-Originating-Network-Id,
#  TS 24.501 §8.3.12 PDU SESSION RELEASE REQUEST (0xD1), §8.3.14 PDU SESSION RELEASE COMMAND (0xD3),
#  §9.11.4.2 5GSM cause #36 "regular deactivation")
#
# In-process SMF in both roles (V-SMF / H-SMF), httptest mocks for local SEPP and H-SMF,
# PFCP stub UPF. Design contract: docs/procedures/HomeRoutedPduSession.md
# (§8 note 1, findings #12, #13, #17).

@roaming @home_routed @release @ROAM-002
Feature: Home-routed PDU Session release between V-SMF and H-SMF over N16
  As a roaming UE with an established home-routed PDU session
  I want the session released through the V-SMF and the H-SMF
  So that both V-UPF and H-UPF resources and the UE IP address are freed

  Background:
    Given the SMF runs in-process with a PFCP stub V-UPF and a mock local SEPP
    And the VPLMN is "001/01" and the HPLMN is "001/02"

  # --- V-SMF UE-initiated release (TS 23.502 §4.3.4.3 step 1a, 4a-4b) ---

  @vsmf
  Scenario: V-SMF releases a home-routed session on UE-initiated PDU SESSION RELEASE REQUEST
    Given an established home-routed PDU session with PSI 5 and a pduSessionRef at the H-SMF
    And the mock H-SMF answers 204 to POST "{pduSessionRef}/modify"
    When the AMF sends UpdateSMContext with n1SmMsg PDU SESSION RELEASE REQUEST "0xD1" with PTI 7
    Then the V-SMF sends a PFCP Session Modification Request to the V-UPF updating the UL FAR with Apply Action DROP
    And the local SEPP receives POST "/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/modify" with requestIndication "UE_REQ_PDU_SES_REL" and pti 7
    And the V-SMF sends the N4 Update FAR DROP before the N16 modify request
    And the V-SMF deletes the V-UPF N4 session after the H-SMF answers 204
    And the V-SMF answers the AMF 200 with n1SmMsg PDU SESSION RELEASE COMMAND "0xD3" with PSI 5, PTI 7 and 5GSM cause 36

  @vsmf
  Scenario: Deleting the sm-context after UE-initiated release sends no N16 and no N4 message
    Given a home-routed PDU session in which the UE-initiated release has completed with a PDU SESSION RELEASE COMMAND
    When the AMF sends DELETE on the sm-context
    Then the V-SMF frees the SM context
    And the local SEPP receives no further request
    And the V-UPF stub receives no further PFCP message

  # --- V-SMF error path: H-SMF unreachable ---

  @vsmf @error
  Scenario Outline: V-SMF still releases the UE session when the H-SMF is unreachable on UE-initiated release
    Given an established home-routed PDU session with PSI 5 and a pduSessionRef at the H-SMF
    And the mock H-SMF "<h_smf_behaviour>"
    When the AMF sends UpdateSMContext with n1SmMsg PDU SESSION RELEASE REQUEST "0xD1" with PTI 7
    Then the V-SMF answers the AMF 200 with n1SmMsg PDU SESSION RELEASE COMMAND "0xD3" with PSI 5, PTI 7 and 5GSM cause 36
    And the V-SMF deletes the V-UPF N4 session

    Examples:
      | h_smf_behaviour                       |
      | is not reachable (connection refused) |
      | answers 500 SYSTEM_FAILURE            |
      | answers 503 UNSPECIFIED               |

  # --- Non-roaming regression ---

  @vsmf @regression
  Scenario: Non-roaming session receiving PDU SESSION RELEASE REQUEST behaves as before and makes no N16 call
    Given an established non-roaming PDU session with PSI 5
    When the AMF sends UpdateSMContext with n1SmMsg PDU SESSION RELEASE REQUEST "0xD1" with PTI 7
    Then the local SEPP receives no request
    And the SMF follows the existing non-roaming release behaviour

  # --- Serving-network release (TS 23.502 §4.3.4.3, TS 29.502 §5.2.2.9) ---

  @vsmf
  Scenario: Serving-network release on sm-context DELETE sends UL FAR DROP before the N16 Release
    Given an established home-routed PDU session with PSI 5 and a pduSessionRef at the H-SMF
    And the mock H-SMF answers 204 to POST "{pduSessionRef}/release"
    When the AMF sends DELETE on the sm-context, for example on deregistration
    Then the V-SMF sends a PFCP Session Modification Request to the V-UPF updating the UL FAR with Apply Action DROP
    And the V-SMF sends the N4 Update FAR DROP before the N16 Release request
    And the V-SMF deletes the V-UPF N4 session

  # --- H-SMF Update UE_REQ_PDU_SES_REL (TS 29.502 §5.2.2.8.2.3) ---

  @hsmf
  Scenario: H-SMF releases the home-routed session on Update with requestIndication UE_REQ_PDU_SES_REL
    Given a home-routed PDU session at the H-SMF with UE IPv4 address "10.60.0.2" allocated from the HPLMN pool
    When the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/modify" with requestIndication "UE_REQ_PDU_SES_REL", header "3gpp-Sbi-Originating-Network-Id" of the VPLMN
    Then the H-SMF deletes the H-UPF N4 session
    And the H-SMF frees UE IPv4 address "10.60.0.2" back to the pool
    And the H-SMF responds 204

  @hsmf @rejection
  Scenario Outline: H-SMF rejects the Update release request with the application error
    Given a home-routed PDU session at the H-SMF
    When the V-SMF sends an Update release request where "<condition>"
    Then the H-SMF responds <http_status> with ProblemDetails cause "<cause>"
    And the H-SMF session and H-UPF N4 session are unchanged

    Examples:
      | condition                                                   | http_status | cause                    |
      | the pduSessionRef is unknown                                | 404         | CONTEXT_NOT_FOUND        |
      | requestIndication is missing                                | 400         | MANDATORY_IE_MISSING     |
      | header 3gpp-Sbi-Originating-Network-Id is missing           | 403         | SUBSCRIPTION_DENIED      |
      | the originating network is a foreign PLMN not owning the ref | 404         | CONTEXT_NOT_FOUND        |

  # --- H-SMF ReleasePduSession refusal (TS 29.502 §5.2.2.9) ---

  @hsmf @rejection
  Scenario Outline: H-SMF refuses the Release request with the application error
    Given a home-routed PDU session at the H-SMF
    When the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions/{pduSessionRef}/release" where "<condition>"
    Then the H-SMF responds <http_status> with ProblemDetails cause "<cause>"
    And the H-SMF session and H-UPF N4 session are unchanged

    Examples:
      | condition                                                    | http_status | cause             |
      | header 3gpp-Sbi-Originating-Network-Id is missing            | 403         | MISSING_PARAMETER |
      | the originating network is a foreign PLMN                    | 404         | CONTEXT_NOT_FOUND |
      | the originating network is the H-SMF's own PLMN              | 404         | CONTEXT_NOT_FOUND |

  # --- H-SMF vcnTunnelInfo validation (TS 29.502 §5.2.2.7, TS 29.500 Table 5.2.7.2-1) ---

  @hsmf @rejection
  Scenario Outline: H-SMF rejects a PduSessionCreateData whose vcnTunnelInfo ipv4Addr is not a valid unicast N9 address
    Given a valid PduSessionCreateData whose vcnTunnelInfo ipv4Addr is "<address>"
    When the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions" to the H-SMF
    Then the H-SMF responds 400 with ProblemDetails cause "MANDATORY_IE_INCORRECT" and invalidParams param "/vcnTunnelInfo/ipv4Addr"
    And the H-SMF sends no PFCP Session Establishment Request to the H-UPF
    And the H-SMF allocates no UE IP address

    Examples:
      | address         | kind        |
      | 127.0.0.1       | loopback    |
      | 169.254.1.1     | link-local  |
      | 224.0.0.1       | multicast   |
      | 0.0.0.0         | unspecified |
      | 255.255.255.255 | broadcast   |

  @hsmf @rejection
  Scenario: H-SMF rejects a vcnTunnelInfo ipv4Addr outside the configured V-UPF N9 CIDR allow-list
    Given the H-SMF is configured with the allowed V-UPF N9 CIDR list "192.0.2.0/24"
    And a valid PduSessionCreateData whose vcnTunnelInfo ipv4Addr is "198.51.100.10"
    When the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions" to the H-SMF
    Then the H-SMF responds 400 with ProblemDetails cause "MANDATORY_IE_INCORRECT" and invalidParams param "/vcnTunnelInfo/ipv4Addr"
    And the H-SMF sends no PFCP Session Establishment Request to the H-UPF

  @hsmf
  Scenario: H-SMF accepts a vcnTunnelInfo ipv4Addr inside the configured V-UPF N9 CIDR allow-list
    Given the H-SMF is configured with the allowed V-UPF N9 CIDR list "192.0.2.0/24"
    And a valid PduSessionCreateData whose vcnTunnelInfo ipv4Addr is "192.0.2.10"
    And the PFCP stub H-UPF accepts the Session Establishment Request
    When the V-SMF sends POST "/nsmf-pdusession/v1/pdu-sessions" to the H-SMF
    Then the H-SMF responds 201 with a PduSessionCreatedData
    And the H-UPF DL FAR has Outer Header Creation towards "192.0.2.10"
