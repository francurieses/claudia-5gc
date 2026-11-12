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

  Scenario: A slice that fails NSSAA is moved to Rejected NSSAI with cause 2 (failed or revoked NSSAA)
    Given the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    And the AAA-S will return EAP-Failure for the slice
    When the AMF starts NSSAA after registration
    Then the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT carrying EAP-Failure
    And S-NSSAI "1-000003" is in the Rejected NSSAI with cause 2
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
    And S-NSSAI "1-000003" is in the Rejected NSSAI with cause 2
    And the AMF sends a Configuration Update Command with the new Allowed NSSAI

  Scenario: The NSSAA NAS messages round-trip byte-exactly
    Given a NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND for S-NSSAI "1-000003" with an EAP-Request
    When the message is encoded and decoded
    Then the decoded S-NSSAI and EAP payload match the originals

  Scenario: A multi-round exchange relays every EAP-Request and keeps the authCtxId (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    And the AAA-S will challenge the UE 2 times before returning EAP-Success
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF relays 2 EAP-Requests in COMMANDs for "1-000003" and PUTs each answer to the open context
    And the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT carrying EAP-Success
    And S-NSSAI "1-000003" is in the Allowed NSSAI

  Scenario: A slice left PENDING is re-initiated on the next registration (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    And the AAA-S is unreachable
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then S-NSSAI "1-000003" is PENDING
    And the AMF sends no NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT
    When the AAA-S is reachable again and will return EAP-Success for the slice
    And the UE registers again
    Then the AMF sends a NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT carrying EAP-Success
    And S-NSSAI "1-000003" is in the Allowed NSSAI

  Scenario: A slice that failed with an EAP-Failure is never retried (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    And the AAA-S will return EAP-Failure for the slice
    When the UE answers every COMMAND until the NSSAA procedure ends
    And the UE registers again
    Then the AMF sends no COMMAND for the new registration
    And S-NSSAI "1-000003" is in the Rejected NSSAI with cause 2
    And S-NSSAI "1-000003" is not in the Allowed NSSAI

  # TS 24.501 V19.8.0 §5.4.7.2.3 a): the fifth T3575 expiry completes the procedure
  # as a failure for the S-NSSAI. No RESULT; the slice is rejected and never retried.
  Scenario: The fifth T3575 expiry fails the slice, which is rejected and never retried (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    When the UE never answers the COMMAND until T3575 expires for the fifth time
    Then the AMF sends no NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT
    And S-NSSAI "1-000003" is in the Rejected NSSAI with cause 2
    And S-NSSAI "1-000003" is not in the Allowed NSSAI
    And S-NSSAI "1-000003" is not PENDING
    When the UE registers again
    Then the AMF sends no COMMAND for the new registration
    And S-NSSAI "1-000003" is in the Rejected NSSAI with cause 2

  # TS 23.502 §4.2.9.2 step 19a: one CONFIGURATION UPDATE COMMAND for the whole queue.
  Scenario: A drained queue sends one Configuration Update Command with the Allowed and the Rejected NSSAI (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the subscription marks S-NSSAI "1-000003" and S-NSSAI "1-000004" as subject to NSSAA
    And the AAA-S will return EAP-Success for S-NSSAI "1-000003" and EAP-Failure for S-NSSAI "1-000004"
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF sends exactly 1 Configuration Update Command
    And the Configuration Update Command carries S-NSSAI "1-000003" in the Allowed NSSAI
    And the Configuration Update Command carries S-NSSAI "1-000004" in the Rejected NSSAI with cause 2

  Scenario: Under rel17 a failed last slice sends no Configuration Update Command
    Given the subscription marks S-NSSAI "1-000003" and S-NSSAI "1-000004" as subject to NSSAA
    And the AAA-S will return EAP-Success for S-NSSAI "1-000003" and EAP-Failure for S-NSSAI "1-000004"
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF sends exactly 0 Configuration Update Command

  # TS 24.501 §4.6.2.4: the Registration Accept lists the S-NSSAIs withheld for NSSAA.
  Scenario: The Registration Accept carries the Pending NSSAI (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    When the AMF builds the Registration Accept
    Then the Registration Accept carries S-NSSAI "1-000003" in the Pending NSSAI

  Scenario: The rel17 Registration Accept carries no Pending NSSAI
    Given the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    When the AMF builds the Registration Accept
    Then the Registration Accept carries no Pending NSSAI

  # AMF-022: TS 23.502 §4.2.9.2 step 19b, TS 24.501 §4.6.2.4 c), §5.5.2.3.1.
  Scenario: NSSAA fails for every S-NSSAI and no default can be allowed - network-initiated de-registration (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    And the AAA-S will return EAP-Failure for the slice
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF performs a network-initiated de-registration instead of a Configuration Update Command
    And the DEREGISTRATION REQUEST has 5GMM cause 62, re-registration not required and S-NSSAI "1-000003" in the Rejected NSSAI with cause 2

  Scenario: The fifth T3575 expiry of the only slice ends in a network-initiated de-registration (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    When the UE never answers the COMMAND until T3575 expires for the fifth time
    Then the AMF performs a network-initiated de-registration instead of a Configuration Update Command
    And the DEREGISTRATION REQUEST has 5GMM cause 62, re-registration not required and S-NSSAI "1-000003" in the Rejected NSSAI with cause 2

  Scenario: Revoking the last allowed S-NSSAI ends in a network-initiated de-registration (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    When the AAA-S revokes authorization for the last allowed S-NSSAI "1-000003"
    Then the AMF performs a network-initiated de-registration instead of a Configuration Update Command
    And the DEREGISTRATION REQUEST has 5GMM cause 62, re-registration not required and S-NSSAI "1-000003" in the Rejected NSSAI with cause 2

  Scenario: A UE with an emergency PDU session gets the Configuration Update Command instead (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    And the UE has an emergency PDU session
    And the AAA-S will return EAP-Failure for the slice
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF performs no network-initiated de-registration
    And the AMF sends exactly 1 Configuration Update Command
    And the Configuration Update Command carries S-NSSAI "1-000003" in the Rejected NSSAI with cause 2

  Scenario: A failed slice with another S-NSSAI still allowed keeps the registration (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the subscription marks S-NSSAI "1-000003" as subject to NSSAA
    And the AAA-S will return EAP-Failure for the slice
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF performs no network-initiated de-registration
    And the AMF sends exactly 1 Configuration Update Command

  Scenario: rel17 behaviour is unchanged: no de-registration, no Configuration Update Command
    Given the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    And the AAA-S will return EAP-Failure for the slice
    When the AMF starts NSSAA after registration
    Then the AMF performs no network-initiated de-registration
    And the AMF sends no Configuration Update Command

  # TS 24.501 §5.5.2.3.1 / §5.4.4.2: a UE that set the ER-NSSAI bit gets the Extended
  # rejected NSSAI IE (0x68) INSTEAD of the Rejected NSSAI IE (0x6D / 0x11).
  Scenario: A UE that supports extended rejected NSSAI gets the Extended rejected NSSAI IE in the DEREGISTRATION REQUEST (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    And the UE supports extended rejected NSSAI
    And the AAA-S will return EAP-Failure for the slice
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF performs a network-initiated de-registration instead of a Configuration Update Command
    And the DEREGISTRATION REQUEST carries S-NSSAI "1-000003" with cause 2 in the Extended rejected NSSAI instead of the Rejected NSSAI

  # TS 24.501 §4.6.2.4 b), TS 23.502 §4.2.9.2 step 19a: every requested slice failed but a
  # default S-NSSAI can be allowed -> it is the Allowed NSSAI of the CUC.
  Scenario: A default S-NSSAI is allowed in the Configuration Update Command when the only requested slice failed (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    And S-NSSAI "1-000009" is also subscribed as a default S-NSSAI not subject to NSSAA
    And the AAA-S will return EAP-Failure for the slice
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF performs no network-initiated de-registration
    And the AMF sends exactly 1 Configuration Update Command
    And the Configuration Update Command carries S-NSSAI "1-000009" in the Allowed NSSAI
    And the Configuration Update Command carries S-NSSAI "1-000003" in the Rejected NSSAI with cause 2

  Scenario: The Configuration Update Command of an extended-rejected-NSSAI UE carries the Extended rejected NSSAI IE (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    And S-NSSAI "1-000009" is also subscribed as a default S-NSSAI not subject to NSSAA
    And the UE supports extended rejected NSSAI
    And the AAA-S will return EAP-Failure for the slice
    When the UE answers every COMMAND until the NSSAA procedure ends
    Then the AMF sends exactly 1 Configuration Update Command
    And the Configuration Update Command carries S-NSSAI "1-000003" with cause 2 in the Extended rejected NSSAI instead of the Rejected NSSAI

  Scenario: Revoking the last allowed S-NSSAI allows the default S-NSSAI in the Configuration Update Command (rel19)
    Given the AMF runs the rel19 NSSAA profile
    And the only subscribed S-NSSAI is "1-000003", subject to NSSAA
    And S-NSSAI "1-000009" is also subscribed as a default S-NSSAI not subject to NSSAA
    When the AAA-S revokes authorization for the last allowed S-NSSAI "1-000003"
    Then the AMF performs no network-initiated de-registration
    And the Configuration Update Command carries S-NSSAI "1-000009" in the Allowed NSSAI
