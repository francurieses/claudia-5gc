Feature: Public Warning System — Write-Replace Warning / PWS Cancel (TS 38.413 §8.9)
  As the management portal playing the Cell Broadcast Centre (CBC) role
  I want the AMF to fan out NGAP Write-Replace Warning and PWS Cancel Requests to every connected gNB
  So that ETWS/CMAS-style emergency broadcasts reach every cell in the Warning Area, independent of any UE registration

  Background:
    Given the AMF NGAP server is running
    And one or more gNBs are connected to the AMF over N2

  # TS 38.413 §8.9.1 — Write-Replace Warning is Class 1, non-UE-associated, correlated only by (MessageIdentifier, SerialNumber)
  Scenario: CBC broadcasts a warning and every connected gNB reports completion
    When the CBC POSTs a Write-Replace Warning broadcast with messageId "4370" and serialNumber "1"
    Then the response status is 202
    And the AMF sends an NGAP Write-Replace Warning Request to every connected gNB
    And each gNB's Write-Replace Warning Response updates the per-gNB completion status with a BroadcastCompletedAreaList

  # TS 38.413 §8.9.2 — PWS Cancel is Class 1, non-UE-associated, keyed by the same (MessageIdentifier, SerialNumber)
  Scenario: CBC cancels an active broadcast and every connected gNB confirms cancellation
    Given an active broadcast identified by messageId "4370" and serialNumber "1"
    When the CBC POSTs a PWS cancel for messageId "4370" and serialNumber "1"
    Then the response status is 202
    And the AMF sends an NGAP PWS Cancel Request to every connected gNB
    And each gNB's PWS Cancel Response reports a BroadcastCancelledAreaList

  # Error path — TS 23.041 §9.3.2 correlation fails when no broadcast status entry matches
  Scenario: PWS cancel for an unknown messageId and serialNumber is rejected
    When the CBC POSTs a PWS cancel for messageId "9999" and serialNumber "42" that was never broadcast
    Then the response status is 404

  # Edge case — TS 38.413 §8.9.1 note: Class 1 needs a peer, but the broadcast is still accepted and recorded
  Scenario: Broadcast submitted with no gNB connected is accepted with zero fan-out targets
    Given no gNB is currently connected to the AMF
    When the CBC POSTs a Write-Replace Warning broadcast with messageId "4371" and serialNumber "1"
    Then the response status is 202
    And the AMF reports that 0 gNBs were targeted
    And no NGAP Write-Replace Warning Request is sent

  # TS 23.041 §9.4 — the CBC role omits optional IEs and the AMF fills 3GPP-legal defaults
  Scenario: Broadcast with only message text is accepted using 3GPP-legal defaults for omitted IEs
    When the CBC POSTs a Write-Replace Warning broadcast with only the message text "Tsunami warning: move to higher ground"
    Then the response status is 202
    And the AMF fills MessageIdentifier, SerialNumber, WarningAreaList, RepetitionPeriod, NumberOfBroadcastsRequested, WarningType, WarningSecurityInfo and DataCodingScheme with 3GPP-legal defaults
    And the AMF sends an NGAP Write-Replace Warning Request to every connected gNB
