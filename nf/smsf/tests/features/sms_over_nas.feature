Feature: SMS over NAS — Nsmsf_SMService (TS 29.540 §5.2 / TS 23.502 §4.13)
  As an AMF relaying NAS Transport messages with Payload Container Type = SMS (0x02)
  I want the SMSF to manage per-UE SMS contexts and handle MO/MT SMS flows
  So that subscribers can exchange short messages over the NAS interface per TS 23.502 §4.13

  Background:
    Given a clean SMSF instance is running
    And the NRF is available and accepts NF registrations
    And the UDM is available and accepts UECM registrations
    And a mock AMF namf-comm endpoint is listening for N1N2MessageTransfer callbacks

  # ---------------------------------------------------------------------------
  # Scenario 1 — NRF registration + SMS Management Activation (AC 1)
  # TS 29.510 §5.2 (NRF) + TS 29.540 §5.2.2 (Activate)
  # ---------------------------------------------------------------------------
  Scenario: SMSF registers in NRF and activates an SMS context returning 201 Created
    Given the SMSF has registered with nfType "SMSF" in the NRF
    When the AMF sends an Nsmsf_SMService Activate request for SUPI "imsi-001010000000001" with accessType "3GPP_ACCESS" and amfId "amf-instance-001" and amfCallbackUri "http://mock-amf/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    Then the SMSF responds with status 201 Created
    And the response body contains a UeSmsContextData with supi "imsi-001010000000001"
    And the UDM received a UECM registration for SUPI "imsi-001010000000001" at resource "smsf-3gpp-access"
    And the SMSF instance is discoverable in the NRF for nfType "SMSF"

  # ---------------------------------------------------------------------------
  # Scenario 2 — MO SMS round-trip via loopback DTE (AC 2)
  # TS 29.540 §5.2.4 (UplinkSMS) + TS 29.518 §5.2.2.3 (N1N2MessageTransfer)
  # ---------------------------------------------------------------------------
  Scenario: MO SMS submitted via UplinkSMS is echoed back as MT SMS to the UE
    Given an active SMS context exists for SUPI "imsi-001010000000001" with amfCallbackUri pointing to the mock AMF
    When the AMF sends an Nsmsf_SMService UplinkSMS request for SUPI "imsi-001010000000001" with smsRecordId "rec-mo-001" and smsPayload "AQIDBA==" and Payload Container Type 0x02
    Then the SMSF responds with status 200 OK
    And the mock AMF receives a Namf_Communication_N1N2MessageTransfer request within 2 seconds
    And the N1N2MessageTransfer request carries n1MessageClass "SMS"
    And the N1N2MessageTransfer request carries Payload Container Type 0x02
    And the echoed smsPayload in the N1N2MessageTransfer matches "AQIDBA=="

  # ---------------------------------------------------------------------------
  # Scenario 3 — MT SMS delivery path via namf-comm (AC 3)
  # TS 23.502 §4.13.4 + TS 29.518 §5.2.2.3
  # ---------------------------------------------------------------------------
  Scenario: SMSF-originated MT SMS is delivered to the UE via AMF N1N2MessageTransfer
    Given an active SMS context exists for SUPI "imsi-001010000000002" with amfCallbackUri pointing to the mock AMF
    When the SMSF originates an MT SMS for SUPI "imsi-001010000000002" with smsPayload "dGVzdA==" and Payload Container Type 0x02
    Then the mock AMF receives a Namf_Communication_N1N2MessageTransfer request within 2 seconds
    And the N1N2MessageTransfer request carries n1MessageClass "SMS"
    And the N1N2MessageTransfer request carries Payload Container Type 0x02
    And the N1N2MessageTransfer n1MessageContainer smsPayload is "dGVzdA=="

  # ---------------------------------------------------------------------------
  # Scenario 4 — UplinkSMS for unknown context returns 404 CONTEXT_NOT_FOUND (AC 4)
  # TS 29.540 §5.2.4 error case
  # ---------------------------------------------------------------------------
  Scenario: UplinkSMS for a SUPI with no active SMS context returns 404 CONTEXT_NOT_FOUND
    Given no SMS context exists for SUPI "imsi-001010000000099"
    When the AMF sends an Nsmsf_SMService UplinkSMS request for SUPI "imsi-001010000000099" with smsRecordId "rec-err-001" and smsPayload "AQIDBA==" and Payload Container Type 0x02
    Then the SMSF responds with status 404
    And the cause is "CONTEXT_NOT_FOUND"

  # ---------------------------------------------------------------------------
  # Scenario 5 — Activate with missing mandatory IE returns 400 (AC 5)
  # TS 29.540 §6.1.6.2.2 — supi and accessType are mandatory
  # ---------------------------------------------------------------------------
  Scenario: SMS Management Activation with missing accessType is rejected with 400
    Given the SMSF has registered with nfType "SMSF" in the NRF
    When the AMF sends an Nsmsf_SMService Activate request for SUPI "imsi-001010000000001" with no accessType and amfId "amf-instance-001" and amfCallbackUri "http://mock-amf/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
    Then the SMSF responds with status 400
    And the cause is "MANDATORY_IE_MISSING"

  Scenario: SMS Management Activation with missing supi in request body is rejected with 400
    Given the SMSF has registered with nfType "SMSF" in the NRF
    When the AMF sends an Nsmsf_SMService Activate request with no supi in the body and accessType "3GPP_ACCESS" and amfId "amf-instance-001"
    Then the SMSF responds with status 400
    And the cause is "MANDATORY_IE_MISSING"

  # ---------------------------------------------------------------------------
  # Scenario 6 — Deactivate then UplinkSMS returns 404 (AC 6)
  # TS 29.540 §5.2.3 (Deactivate) + §5.2.4 (UplinkSMS after deactivation)
  # ---------------------------------------------------------------------------
  Scenario: SMS context Deactivation returns 204 and subsequent UplinkSMS returns 404
    Given an active SMS context exists for SUPI "imsi-001010000000003" with amfCallbackUri pointing to the mock AMF
    When the AMF sends an Nsmsf_SMService Deactivate request for SUPI "imsi-001010000000003"
    Then the SMSF responds with status 204 No Content
    When the AMF sends an Nsmsf_SMService UplinkSMS request for SUPI "imsi-001010000000003" with smsRecordId "rec-post-deact-001" and smsPayload "AQIDBA==" and Payload Container Type 0x02
    Then the SMSF responds with status 404
    And the cause is "CONTEXT_NOT_FOUND"
