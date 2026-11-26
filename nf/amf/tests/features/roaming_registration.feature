Feature: Roaming Registration over N32 with home-controlled authentication (TS 23.502 §4.2.2.2.2)
  As a UE whose home PLMN is 001/02 registering on a visited 001/01 gNB
  I want the visited AMF to authenticate me with the home AUSF and register me with the home UDM via the vSEPP
  So that I can roam while non-roaming UEs keep today's local AUSF/UDM behaviour

  # In-process godog: the AMF is driven directly; the vSEPP, local AUSF and local UDM
  # are httptest mocks. Specs: TS 33.501 §6.1.3.2, §6.1.1.4; TS 29.509; TS 29.503;
  # TS 29.500 §6.1.4.3 (3gpp-Sbi-Target-apiRoot); TS 23.501 §6.3.4.
  Background:
    Given the AMF serves PLMN "001/01" with serving network name "5G:mnc001.mcc001.3gppnetwork.org"
    And a vSEPP mock, a local AUSF mock and a local UDM mock are running
    And the AMF is configured with roaming enabled, sepp_address pointing at the vSEPP mock
    And the AMF knows home PLMN "001/02" with ausf_api_root "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002" and udm_api_root "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003"
    And a gNB of PLMN "001/01" is connected to the AMF

  # TS 23.502 §4.2.2.2.2 steps 4-14; TS 29.500 §6.1.4.3: the vSEPP is the apiRoot and
  # the home NF apiRoot travels in 3gpp-Sbi-Target-apiRoot.
  Scenario: Roaming UE of PLMN 001/02 registers via the vSEPP with home-controlled authentication
    Given a UE with a SUCI of home PLMN "001/02" and the home network authorizes the serving network
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the vSEPP mock receives the Nausf_UEAuthentication POST ue-authentications
    And that request carries header "3gpp-Sbi-Target-apiRoot" equal to "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002"
    And that request body has servingNetworkName "5G:mnc001.mcc001.3gppnetwork.org"
    When the UE answers the Authentication Request with a valid RES*
    Then the vSEPP mock receives the PUT 5g-aka-confirmation
    And that request carries header "3gpp-Sbi-Target-apiRoot" equal to "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002"
    And the UDM UECM registration and the SDM get and subscribe requests reach the vSEPP mock
    And those requests carry header "3gpp-Sbi-Target-apiRoot" equal to "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003"
    And the AMF sends a Registration Accept
    And the local AUSF mock and the local UDM mock received zero requests

  # The route chosen at Phase 1 is stored on the UE context (procedure doc §7).
  Scenario: Home route is remembered on the UE context for the 5g-aka-confirmation
    Given a UE with a SUCI of home PLMN "001/02" and the home network authorizes the serving network
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the UE context in the AMF holds a home route with ViaSEPP set and the home AUSF and UDM apiRoots of PLMN "001/02"
    And the 5g-aka-confirmation is sent to the vSEPP mock with header "3gpp-Sbi-Target-apiRoot" equal to the home AUSF apiRoot

  # Legacy guard: non-roaming UEs never take the roaming path.
  Scenario: Non-roaming UE of PLMN 001/01 with roaming enabled uses the local AUSF and UDM only
    Given a UE with a SUCI of home PLMN "001/01"
    When the UE registers with initial Registration Request via the 001/01 gNB
    Then the local AUSF mock and the local UDM mock receive the registration requests
    And the vSEPP mock received zero requests
    And the Nausf and Nudm request bytes are identical to those sent with roaming disabled
    And the AMF sends a Registration Accept

  # Regression: no roaming block means today's behaviour even for a 001/02 SUCI.
  Scenario: Roaming disabled sends a 001/02 SUCI to the local AUSF as before
    Given the AMF configuration has no roaming block
    And a UE with a SUCI of home PLMN "001/02"
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the local AUSF mock receives the Nausf_UEAuthentication POST
    And the vSEPP mock received zero requests
    And no request carries header "3gpp-Sbi-Target-apiRoot"

  # Procedure doc §5 last-but-two row. [VERIFY] operator choice #11 vs #73; doc proposes #11.
  @verify
  Scenario: Roaming UE whose home PLMN 001/03 is not configured is rejected with 5GMM cause 11
    Given a UE with a SUCI of home PLMN "001/03"
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the AMF sends a Registration Reject with 5GMM cause 11
    And no SBI request leaves the AMF
    And the AMF logs result "REJECT" with cause 11, home_plmn and spec_ref

  # Procedure doc §5 row 1. [VERIFY] TS 29.524 mapping; doc chooses #73.
  @verify
  Scenario: Home AUSF returns 403 SERVING_NETWORK_NOT_AUTHORIZED and the AMF rejects with 5GMM cause 73
    Given a UE with a SUCI of home PLMN "001/02"
    And the vSEPP mock relays the home AUSF answer 403 with ProblemDetails cause "SERVING_NETWORK_NOT_AUTHORIZED"
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the AMF sends a Registration Reject with 5GMM cause 73
    And the AMF logs result "REJECT" with via_sepp true

  # Procedure doc §5: 504 from the SEPP maps to #22 (NFUnavailableRejectCause).
  Scenario: vSEPP answers 504 TARGET_NF_NOT_REACHABLE and the AMF rejects with 5GMM cause 22
    Given a UE with a SUCI of home PLMN "001/02"
    And the vSEPP mock answers 504 with ProblemDetails cause "TARGET_NF_NOT_REACHABLE"
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the AMF sends a Registration Reject with 5GMM cause 22
    And the AMF logs result "REJECT" with spec_ref

  Scenario: vSEPP unreachable at transport level and the AMF rejects with 5GMM cause 22
    Given a UE with a SUCI of home PLMN "001/02"
    And the vSEPP mock is closed
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the AMF sends a Registration Reject with 5GMM cause 22
    And the AMF logs result "FAILURE" with via_sepp true

  # Procedure doc §5: TS 29.503 ROAMING_NOT_ALLOWED -> #11 (udm_error.go).
  Scenario: Home UDM UECM returns 403 ROAMING_NOT_ALLOWED and the AMF rejects with 5GMM cause 11
    Given a UE with a SUCI of home PLMN "001/02" and the home network authorizes the serving network
    And the vSEPP mock relays the home UDM UECM answer 403 with ProblemDetails cause "ROAMING_NOT_ALLOWED"
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    And the UE answers the Authentication Request with a valid RES*
    Then the AMF sends a Registration Reject with 5GMM cause 11
    And the AMF logs result "REJECT" with cause 11 and home_plmn
