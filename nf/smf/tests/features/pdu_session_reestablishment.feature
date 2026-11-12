Feature: PDU session re-establishment with the same PDU Session ID
  As the SMF
  I want a repeated establishment for an existing PDU Session ID to replace the old SM context
  So that exactly one session per SUPI and PSI remains (TS 23.502 §4.3.2.2.1 step 1, TS 24.501 §6.4.1.2)

  Scenario: UE restarts and re-establishes PSI 1
    Given an SMF with an active session for "imsi-001010000000001" PSI 1
    When the AMF creates an SM context for "imsi-001010000000001" PSI 1 again
    Then exactly 1 session exists for "imsi-001010000000001" PSI 1
    And the old SM context no longer exists
