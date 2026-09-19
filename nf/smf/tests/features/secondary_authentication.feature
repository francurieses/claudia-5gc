# Secondary Authentication / Authorization by a DN-AAA Server
# (TS 23.501 §5.6.6, TS 23.502 §4.3.2.3, TS 24.501 §8.3.5-§8.3.7 EAP-in-5GSM,
#  TS 24.501 §9.11.4.2 5GSM cause values, RFC 3748 EAP framing)
#
# Scope: these scenarios exercise the SMF-side gate in handleCreateSMContext
# (Nudm_SDM sm-data "secondary auth required" flag), the EAP relay state
# machine (PENDING_AUTH -> AWAITING_AAA -> AUTHORIZED|REJECTED) that pushes
# PDU SESSION AUTHENTICATION COMMAND [0xC5] / COMPLETE [0xC6] over N1 via the
# AMF, and the terminal PDU SESSION ESTABLISHMENT ACCEPT [0xC2] / REJECT
# [0xC3] carrying the EAP message IE (IEI 0x78). The DN-AAA itself is the
# SMF-internal simulated EAP server described in
# docs/procedures/SecondaryAuthentication.md (same posture as the AUSF NSSAA
# simulated AAA-S) — no live N1 UE peer is exercised here (UERANSIM v3.2.8
# has no secondary-auth capability).

Feature: Secondary Authentication / DN-AAA during PDU Session Establishment
  As the SMF acting as EAP pass-through authenticator
  I want to gate PDU Session Establishment on a DN-AAA EAP exchange when the DNN requires it
  So that DN-specific authorization is enforced per TS 23.501 §5.6.6 / TS 23.502 §4.3.2.3

  Background:
    Given the SMF has fetched Nudm_SDM sm-data for the DNN/S-NSSAI subscription

  # --- Happy path (TS 23.502 §4.3.2.3, EAP-Success branch) ---

  Scenario: DNN requiring secondary auth succeeds with DN-AAA EAP-Success
    Given a DNN "secure-corp" whose subscription requires secondary DN-AAA authentication
    When a UE sends a PDU SESSION ESTABLISHMENT REQUEST for DNN "secure-corp"
    Then the SMF sends a PDU SESSION AUTHENTICATION COMMAND with an EAP-Request/Identity
    And the UE responds with a PDU SESSION AUTHENTICATION COMPLETE carrying EAP-Response/Identity
    And the SMF relays the EAP-Response to the DN-AAA over N6
    And the DN-AAA returns EAP-Success
    And the SMF creates the N4 PFCP session with the UPF
    And the SMF returns a PDU SESSION ESTABLISHMENT ACCEPT carrying EAP-Success in IEI "0x78"

  # --- No-regression path (DNN not requiring secondary auth) ---

  Scenario: DNN not requiring secondary auth establishes normally with no EAP exchange (no regression)
    Given a DNN "internet" whose subscription does not require secondary DN-AAA authentication
    When a UE sends a PDU SESSION ESTABLISHMENT REQUEST for DNN "internet"
    Then the SMF does not send any PDU SESSION AUTHENTICATION COMMAND
    And the SMF creates the N4 PFCP session with the UPF
    And the SMF returns a PDU SESSION ESTABLISHMENT ACCEPT with no EAP message IE present

  # --- Error path (DN-AAA unreachable / timeout, TS 24.501 §9.11.4.2) ---

  Scenario: DN-AAA unreachable during secondary authentication rejects the establishment
    Given a DNN "secure-corp" whose subscription requires secondary DN-AAA authentication
    And the DN-AAA is unreachable
    When a UE sends a PDU SESSION ESTABLISHMENT REQUEST for DNN "secure-corp"
    Then the SMF sends a PDU SESSION AUTHENTICATION COMMAND with an EAP-Request/Identity
    And the UE responds with a PDU SESSION AUTHENTICATION COMPLETE carrying EAP-Response/Identity
    And the SMF relay to the DN-AAA over N6 times out
    And the SMF does not create an N4 PFCP session
    And the SMF returns a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 29
    And the allocated UE IP address is released

  # --- Spec-deviation rejection (DN-AAA EAP-Failure, TS 24.501 §9.11.4.2) ---

  Scenario: DN-AAA EAP-Failure rejects the establishment with 5GSM cause 29
    Given a DNN "secure-corp" whose subscription requires secondary DN-AAA authentication
    When a UE sends a PDU SESSION ESTABLISHMENT REQUEST for DNN "secure-corp"
    Then the SMF sends a PDU SESSION AUTHENTICATION COMMAND with an EAP-Request/Identity
    And the UE responds with a PDU SESSION AUTHENTICATION COMPLETE carrying EAP-Response/Identity
    And the SMF relays the EAP-Response to the DN-AAA over N6
    And the DN-AAA returns EAP-Failure
    And the SMF does not create an N4 PFCP session
    And the SMF returns a PDU SESSION ESTABLISHMENT REJECT with 5GSM cause 29 and EAP-Failure in IEI "0x78"
    And the allocated UE IP address is released
