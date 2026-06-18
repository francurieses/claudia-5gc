Feature: PDU Session Modification UE-requested (TS 23.502 §4.3.3.1)
  As a UE with an established PDU session
  I want to request modification of my session parameters
  So that the network acknowledges the modification and the session remains active

  Background:
    Given a running 5GC with AMF, SMF, UPF, and NRF
    And a UERANSIM gNB is connected to the AMF
    And UE "imsi-001010000000001" is MM-REGISTERED with an established PDU session 1

  # TS 23.502 §4.3.3.1 — UE-requested modification, happy path
  Scenario: UE-requested PDU Session Modification is acknowledged
    When UE "imsi-001010000000001" sends a PDU Session Modification Request for session 1
    Then the AMF forwards a 5GSM Modification Request (0xC9) to the SMF via Nsmf_PDUSession_UpdateSMContext
    And the SMF responds with a 5GSM Modification Command (0xCB) in the n1SmMsg field
    And the SMF response includes an N2SM PDU Session Resource Modify Request Transfer
    And the AMF wraps the 0xCB command in a secured DL NAS Transport (SHT=0x02)
    And the AMF sends an NGAP PDU Session Resource Modify Request (ProcCode=26) to the gNB
    And the gNB responds with a PDU Session Resource Modify Response
    And the UE receives the Modification Command and sends a Modification Complete (0xCC)
    And the PDU session remains active with the same IP address

  # Error path: SMF context not found (e.g. SMF restarted)
  Scenario: PDU Session Modification for unknown session is rejected
    Given UE "imsi-001010000000001" has no active PDU session
    When UE "imsi-001010000000001" sends a PDU Session Modification Request for session 9
    Then the AMF responds with a NAS 5GMM error or ignores the request
    And no Nsmf_PDUSession_UpdateSMContext call is made

  # Verify data plane is unaffected
  Scenario: Data plane connectivity is maintained after Modification
    When UE "imsi-001010000000001" sends a PDU Session Modification Request for session 1
    And the modification procedure completes successfully
    Then pinging 8.8.8.8 via the UE tunnel interface still succeeds with zero packet loss
