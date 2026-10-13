@mcp010
Feature: MCP control tools for AN release, location, AF QoS sessions, PWS resend and MT-SMS
  As an operator driving the 5G core through an LLM client
  I want DISRUPTIVE control tools to dry-run first and act only on confirm true
  So that no signalling reaches the AMF, NEF, SMSF or portal by accident
  # Refs: TS 23.502 §4.2.6 and TS 38.413 §8.3.3 (AN release, UE Context Release Request/Command);
  # TS 23.502 §4.15.6.6 and TS 29.522 §4.4.13 (AF session with required QoS, NEF);
  # TS 38.413 §8.9.1 (Write-Replace Warning, PWS); TS 23.502 §4.13.3 (MT SMS over NAS).

  Background:
    Given the MCP control tools run against mocked AMF, SMF, NRF, NEF, SMSF and portal upstreams
    And the MCP guard runs with access_mode "operator"
    And the AMF mock knows UE "imsi-001010000000001" in 5GMM state "5GMM-REGISTERED"

  # ---- ue_an_release_nw ----------------------------------------------------------

  Scenario: ue_an_release_nw dry-run lists the affected PDU sessions and previous_cm_state and sends no POST
    Given the AMF mock reports cm_state "CM-CONNECTED" for the UE
    And the AMF mock holds UE "imsi-001010000000001" with pdu_session_ids [1,2]
    When I call "ue_an_release_nw" with arguments {"supi":"imsi-001010000000001"}
    Then the result is a dry run
    And the dry-run plan lists previous_cm_state "CM-CONNECTED" and affected PDU session ids 1 and 2
    And the AMF mock received 0 POST requests
    And the audit log has an entry for "ue_an_release_nw" with outcome "dry_run"

  Scenario: ue_an_release_nw with confirm true sends exactly one an-release POST and is accepted
    Given the AMF mock reports cm_state "CM-CONNECTED" for the UE
    And the AMF mock holds UE "imsi-001010000000001" with pdu_session_ids [1]
    And the AMF mock accepts POST "/amf/v1/ue-contexts/imsi-001010000000001/an-release"
    When I call "ue_an_release_nw" with arguments {"supi":"imsi-001010000000001","confirm":true}
    Then the call succeeds
    And the AMF mock received exactly 1 POST to "/amf/v1/ue-contexts/imsi-001010000000001/an-release"
    And the result field "accepted" is true
    And the result field "previous_cm_state" is "CM-CONNECTED"
    And the result affected_pdu_sessions are 1
    And the result field "spec_ref" contains "TS 23.502 §4.2.6"

  Scenario: ue_an_release_nw refuses a CM-IDLE UE at planning and sends no POST
    Given the AMF mock reports cm_state "CM-IDLE" for the UE
    When I call "ue_an_release_nw" with arguments {"supi":"imsi-001010000000001","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "CM-IDLE"
    And the AMF mock received 0 POST requests

  Scenario: ue_an_release_nw for a UE unknown to the AMF is refused with UE not found
    Given the AMF mock answers 404 for UE "imsi-001010000000099"
    When I call "ue_an_release_nw" with arguments {"supi":"imsi-001010000000099","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "UE not found"
    And the AMF mock received 0 POST requests

  Scenario: ue_an_release_nw maps an AMF 409 on the an-release POST to -32000 carrying the upstream status
    Given the AMF mock reports cm_state "CM-CONNECTED" for the UE
    And the AMF mock answers 409 for POST "/amf/v1/ue-contexts/imsi-001010000000001/an-release"
    When I call "ue_an_release_nw" with arguments {"supi":"imsi-001010000000001","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "409"

  Scenario: ue_an_release_nw rejects a malformed SUPI
    When I call "ue_an_release_nw" with arguments {"supi":"not-a-supi","confirm":true}
    Then the call is refused with code -32602
    And the AMF mock received 0 POST requests

  # ---- ue_location_get -----------------------------------------------------------

  Scenario: ue_location_get dry-run for a UE unknown to the AMF is refused and the portal is not called
    Given the AMF mock answers 404 for UE "imsi-001010000000099"
    When I call "ue_location_get" with arguments {"supi":"imsi-001010000000099"}
    Then the call is refused with code -32000
    And the portal mock received 0 location requests

  Scenario: ue_location_get dry-run for a registered UE does not trigger Location Reporting
    When I call "ue_location_get" with arguments {"supi":"imsi-001010000000001"}
    Then the result is a dry run
    And the portal mock received 0 location requests

  Scenario: ue_location_get with confirm true reads the location through the portal
    Given the portal mock answers GET "/api/v1/location/ue/imsi-001010000000001" with reachable true, latitude 40.4168, longitude -3.7038, accuracy_m 50, nr_cell_id "000000010", tac "000001"
    When I call "ue_location_get" with arguments {"supi":"imsi-001010000000001","confirm":true}
    Then the call succeeds
    And the portal mock received exactly 1 GET to "/api/v1/location/ue/imsi-001010000000001"
    And the result contains the keys "reachable", "latitude", "longitude", "accuracy_m", "nr_cell_id", "tac"
    And the result field "reachable" is true

  # ---- af_qos_session_create / get / delete (NEF, TS 29.522 §4.4.13) --------------

  Scenario: af_qos_session_create dry-run with an IP in no SMF session is refused and the NEF is not called
    Given the SMF mock holds sessions with ueIp "10.60.0.1" and "10.60.0.2"
    When I call "af_qos_session_create" with arguments {"scs_as_id":"as-1","ue_ipv4":"10.60.0.99","qos_reference":"qos-gbr-1"}
    Then the call is refused with code -32000
    And the NEF mock received 0 requests
    And the NRF mock received 0 token requests

  Scenario: af_qos_session_create dry-run with a valid IP describes the subscription and sends nothing
    Given the SMF mock holds sessions with ueIp "10.60.0.1" and "10.60.0.2"
    When I call "af_qos_session_create" with arguments {"scs_as_id":"as-1","ue_ipv4":"10.60.0.1","qos_reference":"qos-gbr-1"}
    Then the result is a dry run
    And the NEF mock received 0 requests
    And the NRF mock received 0 token requests

  Scenario: af_qos_session_create with confirm true obtains a bearer token then POSTs the subscription to the NEF
    Given the SMF mock holds sessions with ueIp "10.60.0.1" and "10.60.0.2"
    And the NRF mock issues an access token "tok-abc" for scope "nnef-afsessionwithqos" on POST "/oauth2/v1/token"
    And the NEF mock answers POST "/3gpp-as-session-with-qos/v1/as-1/subscriptions" with 201 and subscription id "sub-1"
    When I call "af_qos_session_create" with arguments {"scs_as_id":"as-1","ue_ipv4":"10.60.0.1","qos_reference":"qos-gbr-1","confirm":true}
    Then the call succeeds
    And the NRF mock received a client_credentials token request for scope "nnef-afsessionwithqos"
    And the NEF mock received exactly 1 POST to "/3gpp-as-session-with-qos/v1/as-1/subscriptions" with header "Authorization" equal to "Bearer tok-abc"
    And the result field "subscription_id" is "sub-1"
    And the result field "accepted" is true
    And the result contains the keys "subscription_id", "self_link", "accepted"

  Scenario: af_qos_session_create rejects an invalid ue_ipv4
    When I call "af_qos_session_create" with arguments {"scs_as_id":"as-1","ue_ipv4":"999.1.1.1","qos_reference":"qos-gbr-1","confirm":true}
    Then the call is refused with code -32602
    And the NEF mock received 0 requests

  Scenario: af_qos_session_delete with confirm true deletes the subscription and a later get returns 404
    Given the NRF mock issues an access token "tok-abc" for scope "nnef-afsessionwithqos" on POST "/oauth2/v1/token"
    And the NEF mock holds subscription "sub-1" for scsAsId "as-1"
    When I call "af_qos_session_delete" with arguments {"scs_as_id":"as-1","subscription_id":"sub-1","confirm":true}
    Then the call succeeds
    And the NEF mock received exactly 1 DELETE to "/3gpp-as-session-with-qos/v1/as-1/subscriptions/sub-1"
    And the result field "deleted" is true
    When I call "af_qos_session_get" with arguments {"scs_as_id":"as-1","subscription_id":"sub-1"}
    Then the call is refused with code -32000
    And the refusal message mentions "404"

  Scenario: af_qos_session_delete dry-run sends no DELETE to the NEF
    Given the NEF mock holds subscription "sub-1" for scsAsId "as-1"
    When I call "af_qos_session_delete" with arguments {"scs_as_id":"as-1","subscription_id":"sub-1"}
    Then the result is a dry run
    And the NEF mock received 0 DELETE requests

  Scenario: af_qos_session_get returns the NEF resource and is allowed under the read-only access mode
    Given the MCP guard runs with access_mode "read-only"
    And the NEF mock holds subscription "sub-1" for scsAsId "as-1"
    When I call "af_qos_session_get" with arguments {"scs_as_id":"as-1","subscription_id":"sub-1"}
    Then the call succeeds
    And "af_qos_session_get" is listed in tools/list

  # ---- sms_send_mt (SMSF, TS 23.502 §4.13.3) ---------------------------------------

  Scenario: sms_send_mt rejects invalid base64 with -32602 and the SMSF is not called
    When I call "sms_send_mt" with arguments {"supi":"imsi-001010000000001","payload_b64":"%%%not-base64%%%","confirm":true}
    Then the call is refused with code -32602
    And the SMSF mock received 0 requests

  Scenario: sms_send_mt rejects a payload above 255 decoded bytes with -32602
    When I call "sms_send_mt" with arguments carrying a payload_b64 of 256 decoded bytes for "imsi-001010000000001" and confirm true
    Then the call is refused with code -32602
    And the SMSF mock received 0 requests

  Scenario: sms_send_mt accepts a payload of exactly 255 decoded bytes on dry-run without calling the SMSF
    When I call "sms_send_mt" with arguments carrying a payload_b64 of 255 decoded bytes for "imsi-001010000000001" and confirm false
    Then the result is a dry run
    And the SMSF mock received 0 requests

  Scenario: sms_send_mt with confirm true POSTs the base64 smsPayload to the SMSF
    Given the SMSF mock answers POST "/nsmsf-sms-internal/v1/ue-contexts/imsi-001010000000001/mt-sms" with 200 and status "DELIVERED"
    When I call "sms_send_mt" with arguments {"supi":"imsi-001010000000001","payload_b64":"AQIDBA==","confirm":true}
    Then the call succeeds
    And the SMSF mock received exactly 1 POST to "/nsmsf-sms-internal/v1/ue-contexts/imsi-001010000000001/mt-sms" with smsPayload "AQIDBA=="
    And the result contains the keys "status"

  Scenario: sms_send_mt maps an SMSF 404 CONTEXT_NOT_FOUND to a structured -32000 error
    Given the SMSF mock answers 404 with cause "CONTEXT_NOT_FOUND" for POST "/nsmsf-sms-internal/v1/ue-contexts/imsi-001010000000001/mt-sms"
    When I call "sms_send_mt" with arguments {"supi":"imsi-001010000000001","payload_b64":"AQIDBA==","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "CONTEXT_NOT_FOUND"

  # ---- pws_resend (TS 38.413 §8.9.1) -----------------------------------------------

  Scenario: pws_resend dry-run sends nothing to the portal
    When I call "pws_resend" with arguments {"message_identifier":4370,"serial_number":16384}
    Then the result is a dry run
    And the portal mock received 0 POST requests to "/api/v1/pws/resend"

  Scenario: pws_resend with confirm true POSTs to the portal pws resend endpoint
    Given the portal mock accepts POST "/api/v1/pws/resend"
    When I call "pws_resend" with arguments {"message_identifier":4370,"serial_number":16384,"confirm":true}
    Then the call succeeds
    And the portal mock received exactly 1 POST to "/api/v1/pws/resend"

  # ---- Tool registry ----------------------------------------------------------------

  Scenario: Disruptive control tools are hidden from tools/list in read-only mode
    Given the MCP guard runs with access_mode "read-only"
    When I list the tools
    Then the tool list does not contain "ue_an_release_nw"
    And the tool list does not contain "af_qos_session_create"
    And the tool list does not contain "sms_send_mt"
    And the tool list does not contain "pws_resend"
    And the tool list contains "af_qos_session_get"

  Scenario: tools/list contains the control tools and never a ueransim or packetrusher tool
    When I list the tools
    Then the tool list contains "ue_an_release_nw"
    And the tool list contains "ue_location_get"
    And the tool list contains "af_qos_session_create"
    And the tool list contains "af_qos_session_get"
    And the tool list contains "af_qos_session_delete"
    And the tool list contains "pws_resend"
    And the tool list contains "sms_send_mt"
    And the tool list contains no name starting with "ueransim_" or "packetrusher_"
