Feature: Service Request with user-plane re-activation (TS 23.502 §4.2.3)
  As a CM-IDLE UE with pending uplink data
  I want the AMF to re-activate my PDU session resources during Service Request
  So that the user plane resumes without a UE-requested re-establishment

  Background:
    Given a running 5GC with AMF, SMF, UPF, and NRF
    And a UERANSIM gNB is connected to the AMF
    And UE "imsi-001010000000001" is MM-REGISTERED with an established PDU session 1

  # Regression: without the TAI list IE (0x54) UERANSIM cancels the Service
  # Request from CM-IDLE with "current TAI is not in the TAI list".
  # Ref: TS 24.501 §9.11.3.9, §5.5.1.2.4
  Scenario: Registration Accept carries the registration area TAI list
    Then the Registration Accept sent to the UE includes a TAI list covering the serving TAC

  # TS 23.502 §4.2.3 step 6: N2 Request (InitialContextSetupRequest) carries
  # the N2SM information from the SMF so the gNB re-establishes the user plane
  # directly — no UE-side re-establishment workaround.
  Scenario: Service Request from CM-IDLE re-activates the user plane via N2SM info
    Given the UE is forced to CM-IDLE by an AN Release
    When the UE sends uplink data on PDU session 1
    Then the UE sends a Service Request with PDU session 1 in the Uplink Data Status
    And the AMF fetches the N2SM Setup Request Transfer from the SMF with upCnxState ACTIVATING
    And the InitialContextSetupRequest carries PDU session 1 in the PDUSessionResourceSetupListCxtReq
    And the gNB returns the DL tunnel info in the InitialContextSetupResponse CxtRes list
    And the AMF forwards the DL tunnel info to the SMF to re-activate DL forwarding
    And pinging the N6 gateway via the UE tunnel interface succeeds

  # A signalling-only Service Request (no Uplink Data Status) must not carry
  # any PDU session list in the InitialContextSetupRequest.
  Scenario: Signalling-only Service Request carries no PDU session list
    Given the UE is forced to CM-IDLE by an AN Release
    When the UE sends a Service Request without an Uplink Data Status
    Then the InitialContextSetupRequest carries no PDUSessionResourceSetupListCxtReq
