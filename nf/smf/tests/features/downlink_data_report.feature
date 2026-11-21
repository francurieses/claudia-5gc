# Downlink Data Report at the SMF: PFCP DLDR -> N1N2MessageTransfer (SMF-011)
# (TS 23.502 §4.2.3.3 steps 2a-3c; TS 29.244 §5.2.3, §7.5.2.6 Create BAR,
#  §7.5.8 / §7.5.8.2 Session Report Request DLDR, §7.5.9 Session Report Response,
#  §8.2.21 Report Type; TS 29.518 §5.2.2.3 N1N2MessageTransfer)
#
# Design contract: docs/procedures/network-triggered-service-request.md
# ("N4 trigger (SMF-011)", "Error and edge scenarios", "[VERIFY] resolutions - SMF-011").
# Harness: in-process SMF, fake UPF PFCP peer on loopback UDP that injects Session Report
# Requests, httptest AMF recording POST /namf-comm/v1/ue-contexts/{supi}/n1-n2-messages.
# Out of scope (UPF side): buffering itself, see nf/upf/tests/features/dl_buffering.feature.

Feature: Downlink Data Report handling at the SMF
  As the SMF
  I want to turn a PFCP Downlink Data Report into one N1N2MessageTransfer towards the AMF
  So that an idle UE is paged and the buffered downlink data is delivered (TS 23.502 §4.2.3.3)

  Background:
    Given a fake UPF PFCP peer listening on a loopback UDP socket
    And an httptest AMF recording N1N2MessageTransfer requests
    And the SMF is running in-process with the fake UPF as N4 peer and the httptest AMF as Namf-comm
    And the SMF holds an IDLE PDU session "imsi-001010000000001" PSI 1 whose DL FAR 1 is BUFF+NOCP

  @SMF-011
  Scenario: PDU session establishment installs Create BAR, DL PDR 2 to FAR 1 with BAR ID 1, and UL PDR 1 to FAR 2
    When a new PDU session "imsi-001010000000002" PSI 2 is established through the SMF
    Then the fake UPF receives a PFCP Session Establishment Request containing exactly one Create BAR with BAR ID 1
    And the Create BAR contains no Suggested Buffering Packets Count
    And the Create PDR with PDR ID 2 has Source Interface "Core" and references FAR ID 1
    And the Create FAR with FAR ID 1 carries BAR ID 1
    And the Create PDR with PDR ID 1 has Source Interface "Access" and references FAR ID 2
    And the Create FAR with FAR ID 2 has Apply Action FORW with Destination Interface "Core"

  @SMF-011
  Scenario: DLDR for PDR 2 with QFI is answered Cause 1 and triggers exactly one N1N2MessageTransfer with pduSessionId
    When the fake UPF sends a Session Report Request with Report Type DLDR and Downlink Data Report PDR ID 2 with QFI 1 for the session
    Then the fake UPF receives a Session Report Response with Cause 1 "Request accepted"
    And the httptest AMF receives exactly one N1N2MessageTransfer for "imsi-001010000000001" with pduSessionId 1
    And the SMF logs procedure "NetworkTriggeredServiceRequest" interface "N4" direction "IN" with spec_ref "TS 23.502 §4.2.3.3 step 2a"
    And the SMF logs procedure "NetworkTriggeredServiceRequest" interface "Namf" direction "OUT" with spec_ref "TS 23.502 §4.2.3.3 step 3a"

  @SMF-011
  Scenario: Duplicate DLDR while paging is pending is acknowledged without a second N1N2MessageTransfer
    Given the SMF has already sent one N1N2MessageTransfer for the session and paging is pending
    When the fake UPF sends a Session Report Request with Report Type DLDR and Downlink Data Report PDR ID 2 with QFI 1 for the session
    Then the fake UPF receives a Session Report Response with Cause 1 "Request accepted"
    And the httptest AMF has received exactly one N1N2MessageTransfer in total

  @SMF-011
  Scenario: Service Request re-activation with Update FAR 1 FORW+OHC clears the pending-paging flag
    Given the SMF has already sent one N1N2MessageTransfer for the session and paging is pending
    When the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "ACTIVATING" and the gNB N3 tunnel for the session
    Then the fake UPF receives a PFCP Session Modification Request with Update FAR 1 Apply Action FORW and an Outer Header Creation
    And the SMF PDU session state is "ACTIVE"
    And the SMF no longer holds a pending-paging flag for the session

  @SMF-011
  Scenario: DLDR for an unknown SEID is rejected with PFCP Cause 65 and no N1N2MessageTransfer
    When the fake UPF sends a Session Report Request with Report Type DLDR for SEID 0xDEAD that matches no session
    Then the fake UPF receives a Session Report Response with Cause 65 "Session context not found" and header SEID 0
    And the httptest AMF has received no N1N2MessageTransfer

  @SMF-011
  Scenario: DLDR without the Downlink Data Report IE is rejected with PFCP Cause 67 and no N1N2MessageTransfer
    When the fake UPF sends a Session Report Request with Report Type DLDR and no Downlink Data Report IE for the session
    Then the fake UPF receives a Session Report Response with Cause 67 "Conditional IE missing" and Offending IE 83
    And the httptest AMF has received no N1N2MessageTransfer

  @SMF-011
  Scenario: AMF answers 404 CONTEXT_NOT_FOUND, SMF logs FAILURE, clears pending and sends Update FAR 1 DROP
    Given the httptest AMF answers N1N2MessageTransfer with HTTP 404 and ProblemDetails cause "CONTEXT_NOT_FOUND"
    When the fake UPF sends a Session Report Request with Report Type DLDR and Downlink Data Report PDR ID 2 with QFI 1 for the session
    Then the fake UPF receives a Session Report Response with Cause 1 "Request accepted"
    And the SMF logs procedure "NetworkTriggeredServiceRequest" interface "Namf" with result "FAILURE" and cause "CONTEXT_NOT_FOUND"
    And the fake UPF receives a PFCP Session Modification Request with Update FAR 1 Apply Action DROP
    And the SMF no longer holds a pending-paging flag for the session
    And the httptest AMF has received exactly one N1N2MessageTransfer in total
