Feature: Network Slice-Specific Authentication and Authorization (TS 23.502 §4.2.9)
  As a network operator
  I want the AMF to run EAP-based slice authentication with the AAA-S via AUSF
  So that S-NSSAIs subject to NSSAA are only granted after a successful slice auth

  Scenario: A slice subject to NSSAA is authenticated and added to Allowed NSSAI
    Given the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    And the AAA-S will return EAP-Success for the slice
    When the AMF starts NSSAA after registration
    Then the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for "1-000003"
    And on the UE's COMPLETE the AMF relays the EAP payload to AUSF
    And the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT carrying EAP-Success
    And S-NSSAI "1-000003" is in the Allowed NSSAI

  Scenario: A slice that fails NSSAA is moved to Rejected NSSAI with cause 3
    Given the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    And the AAA-S will return EAP-Failure for the slice
    When the AMF starts NSSAA after registration
    Then the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT carrying EAP-Failure
    And S-NSSAI "1-000003" is in the Rejected NSSAI with cause 3
    And S-NSSAI "1-000003" is not in the Allowed NSSAI

  Scenario: A UE with no slice subject to NSSAA skips the procedure
    Given the subscription marks no S-NSSAI as subject to NSSAA
    When the AMF starts NSSAA after registration
    Then the AMF sends no NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND
    And the Allowed NSSAI is unchanged

  Scenario: AAA-initiated revocation removes a previously authorized slice
    Given S-NSSAI "1-000003" was previously authorized by NSSAA
    When the AAA-S revokes authorization for S-NSSAI "1-000003"
    Then S-NSSAI "1-000003" is removed from the Allowed NSSAI
    And S-NSSAI "1-000003" is in the Rejected NSSAI with cause 3
    And the AMF sends a Configuration Update Command with the new Allowed NSSAI

  Scenario: The NSSAA NAS messages round-trip byte-exactly
    Given a NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for S-NSSAI "1-000003" with an EAP-Request
    When the message is encoded and decoded
    Then the decoded S-NSSAI and EAP payload match the originals
