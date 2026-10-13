@MCP-010
Feature: AMF-initiated AN Release triggered by O&M (TS 23.502 §4.2.6; TS 38.413 §8.3.3)
  As an O&M actor using the AMF management API on :9002 (not an SBI path)
  I want to release the AN connection of a CM-CONNECTED UE with NGAP Cause misc/om-intervention
  So that the UE becomes CM-IDLE, its user plane is deactivated at the SMF, and it stays RM-REGISTERED

  # Design: docs/procedures/an-release-nw.md. The mgmt endpoint is
  # POST /amf/v1/ue-contexts/{supi}/an-release. No 5GMM or 5GSM cause applies: no NAS message
  # is sent to the UE in this procedure. Error responses are HTTP statuses of the mgmt API.

  Background:
    Given the AMF inbound namf-comm SBI server is running
    And a UE "imsi-001010000000001" is registered with an active NAS security context
    And the UE has an established PDU session 1 on DNN "internet"
    And the AMF management API is running
    And an SMF mock records Nsmf UpdateSMContext requests

  # TS 23.502 §4.2.6 step 2; TS 38.413 §8.3.3.2 / §9.2.2.5 / §9.3.1.2; TS 38.412 §7
  Scenario: O&M AN release of a CM-CONNECTED UE returns 202 and sends UE CONTEXT RELEASE COMMAND with cause misc om-intervention
    Given the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    When O&M POSTs an AN release for SUPI "imsi-001010000000001"
    Then the response status is 202
    And the AN release response has accepted true and previous_cm_state "CM-CONNECTED"
    And the AN release response lists affected_pdu_sessions as the JSON numbers 1
    And the AN release response carries a non-empty spec_ref
    And the AMF sends a UE CONTEXT RELEASE COMMAND to the serving gNB with procedure code 41
    And the UE CONTEXT RELEASE COMMAND carries the UE NGAP ID pair of the UE followed by Cause misc "om-intervention" (3)
    And the UE CONTEXT RELEASE COMMAND is sent with SCTP PPID 60
    And the UE is not marked for removal

  # TS 23.502 §4.2.6 steps 4-5; TS 29.502 §5.2.2.3.2; TS 23.501 §5.3.3.2 (CM state transitions)
  Scenario: UE CONTEXT RELEASE COMPLETE after O&M AN release moves the UE to CM-IDLE and notifies the SMF DEACTIVATED per PDU session
    Given the UE has an established PDU session 2 on DNN "internet"
    And the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    And O&M POSTs an AN release for SUPI "imsi-001010000000001"
    When the gNB answers with a UE CONTEXT RELEASE COMPLETE for the UE
    Then the UE becomes CM-IDLE within the test deadline
    And the AMF requests upCnxState "DEACTIVATED" from the SMF for PDU session 1 exactly once
    And the AMF requests upCnxState "DEACTIVATED" from the SMF for PDU session 2 exactly once
    And the UE context is still present and RM-REGISTERED
    And the UE is not marked for removal

  # Project mgmt API: the 202 is returned once the Command is written, not after the Complete
  Scenario: No SMF notification and no CM state change before the gNB answers with UE CONTEXT RELEASE COMPLETE
    Given the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    When O&M POSTs an AN release for SUPI "imsi-001010000000001"
    Then the response status is 202
    And the UE is still CM-CONNECTED
    And the AMF sends no upCnxState "DEACTIVATED" request to the SMF

  # docs/procedures/an-release-nw.md §5: CMState decides, not the gNB lookup (GNBAddr is kept after Release Complete)
  Scenario: O&M AN release of a CM-IDLE UE is rejected with 409 and no NGAP message is sent
    Given the UE is CM-IDLE
    And the UE is served by a connected gNB
    When O&M POSTs an AN release for SUPI "imsi-001010000000001"
    Then the response status is 409
    And the AMF sends no UE CONTEXT RELEASE COMMAND
    And the UE is still CM-IDLE

  Scenario: O&M AN release of an unknown SUPI is rejected with 404 and no NGAP message is sent
    When O&M POSTs an AN release for SUPI "imsi-001019999999999"
    Then the response status is 404
    And the AMF sends no UE CONTEXT RELEASE COMMAND

  # docs/procedures/an-release-nw.md §5: CM-CONNECTED UE without serving gNB / N2 association
  Scenario: O&M AN release of a CM-CONNECTED UE without an N2 association is rejected with 503 and no NGAP message is sent
    Given the UE is CM-CONNECTED
    And no gNB association exists for the UE
    When O&M POSTs an AN release for SUPI "imsi-001010000000001"
    Then the response status is 503
    And the AMF sends no UE CONTEXT RELEASE COMMAND
    And the UE is still CM-CONNECTED

  # docs/procedures/an-release-nw.md §5 / §7 routing pitfall: the method-less catch-all must not take over
  Scenario Outline: Method other than POST on the AN release path is rejected with 405
    Given the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    When O&M sends an HTTP <method> to the AN release path of SUPI "imsi-001010000000001"
    Then the response status is 405
    And the response Allow header is "POST"
    And the AMF sends no UE CONTEXT RELEASE COMMAND
    And the UE context is still present and RM-REGISTERED

    Examples:
      | method |
      | GET    |
      | DELETE |

  # docs/procedures/an-release-nw.md §5: a release with PendingRemoval set would remove the context on Complete
  Scenario: O&M AN release while a deregistration is pending is rejected with 409 and no second release is sent
    Given the UE is CM-CONNECTED
    And the UE is served by a connected gNB
    And a deregistration is pending for the UE
    When O&M POSTs an AN release for SUPI "imsi-001010000000001"
    Then the response status is 409
    And the AMF sends no UE CONTEXT RELEASE COMMAND

  # docs/procedures/an-release-nw.md §7 snapshot fixes
  Scenario: UE snapshot after Registration Complete has a non-zero registration_time and numeric pdu_session_ids
    Given the UE completed registration with a Registration Complete
    When O&M requests the UE snapshot for SUPI "imsi-001010000000001"
    Then the response status is 200
    And the UE snapshot registration_time is not the zero time
    And the UE snapshot pdu_session_ids is a JSON array of numbers equal to 1
