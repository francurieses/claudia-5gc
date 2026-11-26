@amf @roaming @SEPP-005
Feature: AMF roaming partners from the partners file (TS 23.502 §4.2.2.2.2; TS 29.500 §6.1.4.3; TS 24.501 §5.5.1.2.5)
  As an operator of the local core
  I want the AMF to route UEs of a roaming partner PLMN only when the partners file defines home NFs for it
  So that the default core is partner-free and adding a partner needs configuration only

  # SPEC mode (SEPP-005): scenarios only. Design: docs/procedures/N32InteropReadiness.md §3.4, §4.1, E12, E13.
  # In-process godog like roaming_registration.feature: the SEPP (sepp:8014), the local AUSF and the local UDM are httptest mocks.
  # Step phrasing reuses roaming_registration.feature where it matches.

  Background:
    Given the AMF serves PLMN "001/01" with serving network name "5G:mnc001.mcc001.3gppnetwork.org"
    And a SEPP mock, a local AUSF mock and a local UDM mock are running
    And the AMF is configured with roaming enabled, sepp_address pointing at the SEPP mock
    And a gNB of PLMN "001/01" is connected to the AMF

  @rejection @default
  Scenario: Default configuration with empty home_plmns rejects a UE of another PLMN with 5GMM cause 11 (E13)
    Given the AMF configuration has an empty home_plmns list and no partners file
    And a UE with a SUCI of home PLMN "001/02"
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the AMF sends a Registration Reject with 5GMM cause 11
    And the SEPP mock, the local AUSF mock and the local UDM mock received zero requests

  @happy @partners
  Scenario: Partners file entry with home_nfs routes the UE of that PLMN via the SEPP
    Given a roaming partners file with partner PLMN "001/02" and home_nfs ausf_api_root "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002" and udm_api_root "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003"
    And the AMF is started with ROAMING_PARTNERS_FILE pointing at that file
    And a UE with a SUCI of home PLMN "001/02" and the home network authorizes the serving network
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the SEPP mock receives the Nausf_UEAuthentication POST ue-authentications
    And that request carries header "3gpp-Sbi-Target-apiRoot" equal to "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002"
    And the local AUSF mock received zero requests

  @rejection @partners
  Scenario: Partner without home_nfs is not routed and the UE gets 5GMM cause 11
    Given a roaming partners file with partner PLMN "001/02" that has an n32 section but no home_nfs
    And the AMF is started with ROAMING_PARTNERS_FILE pointing at that file
    And a UE with a SUCI of home PLMN "001/02"
    When the UE sends a Registration Request of type "initial" via the 001/01 gNB
    Then the AMF sends a Registration Reject with 5GMM cause 11
    And the SEPP mock and the local AUSF mock received zero requests

  @regression @partners
  Scenario: UE of the serving PLMN is unchanged when a partners file is loaded
    Given a roaming partners file with partner PLMN "001/02" and home_nfs ausf_api_root "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002" and udm_api_root "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003"
    And the AMF is started with ROAMING_PARTNERS_FILE pointing at that file
    And a UE with a SUCI of home PLMN "001/01"
    When the UE registers with initial Registration Request via the 001/01 gNB
    Then the local AUSF mock and the local UDM mock receive the registration requests
    And the SEPP mock received zero requests

  @error @config
  Scenario Outline: AMF refuses to start on an invalid partners file (E12)
    Given <file>
    When the AMF starts with ROAMING_PARTNERS_FILE pointing at that file
    Then the AMF exits with status 1
    And the AMF log has an ERROR line with cause "config_invalid"

    Examples:
      | file                                                                    |
      | a partners file that is not valid YAML                                  |
      | a partners file with a partner whose plmn has a non-numeric mcc         |
      | a partners file with two entries for PLMN "001/02"                      |

  @partners
  Scenario: A missing partners file is treated as no partners
    Given ROAMING_PARTNERS_FILE points to a file that does not exist
    When the AMF starts
    Then the AMF starts successfully
    And the AMF holds zero home PLMNs
