# AN Release — SMF/UPF N4 leg: UP deactivation with DL buffering (SMF-008)
# (TS 23.502 §4.2.6 step 5 trigger, step 6a PFCP Session Modification Request,
#  step 6b response, step 7 UpdateSMContext response; TS 29.244 §5.2.3,
#  §7.5.4.3 Update FAR, §7.5.5, §8.2.26 Apply Action; TS 23.501 §5.8.2.19;
#  TS 29.502 §5.2.2.3.2 Nsmf_PDUSession_UpdateSMContext)
#
# Scope: in-process SMF against a fake UPF on a loopback UDP socket, driving
# POST /nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify with
# upCnxState=DEACTIVATED. The Update FAR must carry FAR ID 1 and Apply Action
# BUFF+NOCP (0x0C: BUFF bit 3 = 0x04, NOCP bit 4 = 0x08), no FORW, no DROP,
# no Update Forwarding Parameters, no BAR.
# Out of scope (SMF-011): UPF buffering, Downlink Data Report (DLDR) and paging.
# The other DROP paths (N2 handover target-failed, PDU Resource Setup failure,
# via pfcpDeactivateDL) stay DROP (0x01).

Feature: AN Release N4 leg at the SMF
  As the SMF
  I want to switch the downlink FAR to buffering when the AN is released
  So that downlink data for a CM-IDLE UE is buffered and reported, not dropped (TS 23.502 §4.2.6 step 6a)

  Background:
    Given a fake UPF PFCP peer listening on a loopback UDP socket that answers PFCP Session Modification Requests with Cause "Request accepted"
    And the SMF is running in-process with the fake UPF as N4 peer
    And the SMF holds an ACTIVE PDU session "imsi-001010000000001" PSI 1 with DL FAR 1 forwarding to the AN tunnel

  Scenario: UP deactivation sends Update FAR 1 with Apply Action BUFF+NOCP and sets the session IDLE
    When the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "DEACTIVATED" for the session
    Then the SMF answers the UpdateSMContext with HTTP 200
    And the fake UPF receives a PFCP Session Modification Request with the UP SEID of the session in the header
    And the PFCP Session Modification Request contains exactly one Update FAR with FAR ID 1
    And the Update FAR Apply Action is exactly 0x0C with BUFF set, NOCP set, FORW not set and DROP not set
    And the Update FAR contains no Update Forwarding Parameters and no BAR ID
    And the PFCP Session Modification Request contains no Create BAR and no Update BAR
    And the SMF PDU session state is "IDLE"
    And the SMF logs procedure "AnRelease" interface "N4" direction "OUT" with apply_action "BUFF+NOCP" and spec_ref "TS 23.502 §4.2.6 step 6a"
    And the SMF logs procedure "AnRelease" interface "N4" direction "IN" with result "OK" and spec_ref "TS 23.502 §4.2.6 step 6b"

  Scenario: UPF rejects the AN Release Session Modification with PFCP Cause 64 and the session stays IDLE
    Given the fake UPF answers PFCP Session Modification Requests with Cause 64 "Request rejected"
    When the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "DEACTIVATED" for the session
    Then the SMF answers the UpdateSMContext with HTTP 200
    And the fake UPF receives a PFCP Session Modification Request with Update FAR 1 and Apply Action 0x0C
    And the SMF logs a warning with procedure "AnRelease" direction "IN" result "REJECT" and cause 64
    And the SMF sends no PFCP Session Modification Request with Apply Action DROP as fallback
    And the SMF PDU session state is "IDLE"

  Scenario: UPF does not answer the AN Release Session Modification and the session stays IDLE
    Given the fake UPF receives PFCP Session Modification Requests without answering
    When the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "DEACTIVATED" for the session
    Then the SMF answers the UpdateSMContext with HTTP 200 without waiting for the N4 transaction
    And the SMF logs a warning with procedure "AnRelease" direction "IN" result "FAILURE" and cause "pfcp-timeout" within the deadline
    And the SMF PDU session state is "IDLE"

  Scenario: Session in RELEASING gets no N4 message on UP deactivation
    Given the SMF PDU session is in state "RELEASING"
    When the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "DEACTIVATED" for the session
    Then the SMF answers the UpdateSMContext with HTTP 200
    And the fake UPF receives no PFCP message within the observation window
    And the SMF PDU session state is "RELEASING"

  Scenario: Unknown smContextRef gets 404 CONTEXT_NOT_FOUND and no N4 message
    When the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "DEACTIVATED" for an unknown smContextRef
    Then the SMF answers the UpdateSMContext with HTTP 404 and ProblemDetails cause "CONTEXT_NOT_FOUND"
    And the fake UPF receives no PFCP message within the observation window

  Scenario: N2 handover target-failed deactivation still sends Apply Action DROP
    Given the SMF PDU session is a handover target-failed session after "HANDOVER_RES_ALLOC_FAIL"
    When the AMF sends Nsmf_PDUSession_UpdateSMContext with upCnxState "DEACTIVATED" for the session
    Then the fake UPF receives a PFCP Session Modification Request with Update FAR 1
    And the Update FAR Apply Action is exactly 0x01 with DROP set, BUFF not set, NOCP not set and FORW not set
    And the SMF logs no procedure "AnRelease" with apply_action "BUFF+NOCP" for the session

  Scenario: PDU Resource Setup failure deactivation still sends Apply Action DROP
    When the AMF reports "PDU_RES_SETUP_FAIL" for the session
    Then the fake UPF receives a PFCP Session Modification Request with Update FAR 1
    And the Update FAR Apply Action is exactly 0x01 with DROP set, BUFF not set, NOCP not set and FORW not set
