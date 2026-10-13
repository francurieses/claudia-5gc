@mcp011
Feature: MCP runtime parameter tools for AMF timers, QoS overrides and subscriber provisioning
  As an operator driving the 5G core through an LLM client
  I want to read and change AMF NAS timers, list PCF QoS overrides and manage subscribers behind the guard
  So that runtime changes are validated, confirmed, audited and never leak subscriber keys
  # Refs: TS 24.501 §5.3.7 and §10.2 Table 10.2.1 (T3512, GPRS Timer 3, mobile reachable, implicit detach);
  # TS 23.501 §5.3.2 (registration management, periodic registration update);
  # TS 29.512 §5.2.2.2 (SM Policy Association creation, QoS decisions).

  Background:
    Given the MCP runtime tools run against mocked AMF, PCF and portal upstreams
    And the MCP guard runs with access_mode "operator"
    And the caller role is "admin"
    And the AMF mock holds timer config t3512_secs 3240, mobile_reachable_guard_secs 240, implicit_detach_secs 3840 with base t3512_secs 3240

  # ---- amf_timer_config (read: READ_ONLY, set: MUTATING) -----------------------------

  Scenario: amf_timer_config with no values reads the effective timers with a GET and sends no PUT
    When I call "amf_timer_config" with arguments {}
    Then the call succeeds
    And the AMF mock received exactly 1 GET to "/amf/v1/config/timers"
    And the AMF mock received 0 PUT requests
    And the result contains the keys "effective", "base", "applies_to", "persisted"
    And the result field "persisted" is false
    And the result field "applies_to" is "Registration Accepts sent after the change; running timers keep their value"
    And the effective timer "mobile_reachable_secs" equals 3480

  Scenario: amf_timer_config with t3512_secs sets the timer with one PUT and runs without confirm
    Given the AMF mock accepts PUT "/amf/v1/config/timers" returning t3512_secs 1800, mobile_reachable_guard_secs 240, implicit_detach_secs 3840
    When I call "amf_timer_config" with arguments {"t3512_secs":1800}
    Then the call succeeds
    And the AMF mock received exactly 1 PUT to "/amf/v1/config/timers" with t3512_secs 1800
    And the effective timer "t3512_secs" equals 1800
    And the result field "persisted" is false
    And the audit log has an entry for "amf_timer_config" with outcome "executed"

  Scenario: amf_timer_config with all three values sends them in one PUT
    Given the AMF mock accepts PUT "/amf/v1/config/timers" returning t3512_secs 3600, mobile_reachable_guard_secs 300, implicit_detach_secs 4000
    When I call "amf_timer_config" with arguments {"t3512_secs":3600,"mobile_reachable_guard_secs":300,"implicit_detach_secs":4000}
    Then the call succeeds
    And the AMF mock received exactly 1 PUT to "/amf/v1/config/timers" with t3512_secs 3600
    And the effective timer "mobile_reachable_guard_secs" equals 300
    And the effective timer "implicit_detach_secs" equals 4000

  Scenario: amf_timer_config reset true restores the base values with one PUT
    Given the AMF mock accepts PUT "/amf/v1/config/timers" returning t3512_secs 3240, mobile_reachable_guard_secs 240, implicit_detach_secs 3840
    When I call "amf_timer_config" with arguments {"reset":true}
    Then the call succeeds
    And the AMF mock received exactly 1 PUT to "/amf/v1/config/timers"
    And the effective timer "t3512_secs" equals 3240

  Scenario: amf_timer_config set is refused in read-only access mode and the AMF is not called
    Given the MCP guard runs with access_mode "read-only"
    When I call "amf_timer_config" with arguments {"t3512_secs":1800}
    Then the call is refused with code -32000
    And the AMF mock received 0 PUT requests

  Scenario: amf_timer_config read still works in read-only access mode
    Given the MCP guard runs with access_mode "read-only"
    When I call "amf_timer_config" with arguments {}
    Then the call succeeds
    And the AMF mock received exactly 1 GET to "/amf/v1/config/timers"
    # Discovery filters on the static risk (MUTATING), like nf_log_level: the read form is
    # callable in read-only mode (RiskFor = READ_ONLY) but the tool is not advertised there.
    When I list the tools
    Then the tool list does not contain "amf_timer_config"

  Scenario: amf_timer_config rejects a T3512 that is not representable in GPRS Timer 3
    When I call "amf_timer_config" with arguments {"t3512_secs":61}
    Then the call is refused with code -32602
    And the AMF mock received 0 PUT requests

  Scenario: amf_timer_config rejects a T3512 below 60 seconds
    When I call "amf_timer_config" with arguments {"t3512_secs":30}
    Then the call is refused with code -32602
    And the AMF mock received 0 PUT requests

  Scenario: amf_timer_config rejects a T3512 above 86400 seconds
    When I call "amf_timer_config" with arguments {"t3512_secs":86460}
    Then the call is refused with code -32602
    And the AMF mock received 0 PUT requests

  Scenario: amf_timer_config rejects a mobile reachable guard above 3600 seconds
    When I call "amf_timer_config" with arguments {"mobile_reachable_guard_secs":3601}
    Then the call is refused with code -32602
    And the AMF mock received 0 PUT requests

  Scenario: amf_timer_config rejects an implicit detach timer below 60 seconds
    When I call "amf_timer_config" with arguments {"implicit_detach_secs":59}
    Then the call is refused with code -32602
    And the AMF mock received 0 PUT requests

  Scenario: amf_timer_config rejects reset combined with values
    When I call "amf_timer_config" with arguments {"reset":true,"t3512_secs":1800}
    Then the call is refused with code -32602
    And the AMF mock received 0 PUT requests

  Scenario: amf_timer_config maps an AMF 400 on the PUT to -32000 carrying the upstream status
    Given the AMF mock answers 400 for PUT "/amf/v1/config/timers"
    When I call "amf_timer_config" with arguments {"t3512_secs":1800}
    Then the call is refused with code -32000
    And the refusal message mentions "400"

  Scenario: amf_timer_config read reports an unreachable AMF as -32000
    Given the mocked AMF upstream is shut down
    When I call "amf_timer_config" with arguments {}
    Then the call is refused with code -32000

  # ---- qos_policy_list (READ_ONLY, PCF sm-policy-overrides) ----------------------------

  Scenario: qos_policy_list returns the overrides held by the PCF
    Given the PCF mock holds an sm-policy override for supi "imsi-001010000000001" dnn "internet" 5qi 7 arp 8 ambr_ul "50 Mbps" ambr_dl "100 Mbps"
    When I call "qos_policy_list" with arguments {}
    Then the call succeeds
    And the PCF mock received exactly 1 GET to "/pcf-internal/v1/sm-policy-overrides"
    And the qos_policy_list has exactly 1 entry for supi "imsi-001010000000001"
    And each qos_policy_list entry has the keys "supi", "5qi", "arp", "ambr_ul", "ambr_dl"

  Scenario: qos_policy_list returns an empty list when the PCF holds no override
    Given the PCF mock holds no sm-policy overrides
    When I call "qos_policy_list" with arguments {}
    Then the call succeeds
    And the qos_policy_list is an empty list

  Scenario: qos_policy_list shows an entry created by qos_policy_set
    Given the PCF mock accepts qos_policy_set for supi "imsi-001010000000001" and then lists it
    When I call "qos_policy_set" with arguments {"supi":"imsi-001010000000001","dnn":"internet","5qi":7,"confirm":true}
    And I call "qos_policy_list" with arguments {}
    Then the call succeeds
    And the qos_policy_list has exactly 1 entry for supi "imsi-001010000000001"

  Scenario: qos_policy_list is allowed under the read-only access mode
    Given the MCP guard runs with access_mode "read-only"
    And the PCF mock holds no sm-policy overrides
    When I call "qos_policy_list" with arguments {}
    Then the call succeeds
    And "qos_policy_list" is listed in tools/list

  Scenario: qos_policy_list maps a PCF 500 to -32000 carrying the upstream status
    Given the PCF mock answers 500 for GET "/pcf-internal/v1/sm-policy-overrides"
    When I call "qos_policy_list" with arguments {}
    Then the call is refused with code -32000
    And the refusal message mentions "500"

  Scenario: qos_policy_list rejects a malformed supi filter
    When I call "qos_policy_list" with arguments {"supi":"not-a-supi"}
    Then the call is refused with code -32602
    And the PCF mock received 0 requests

  # ---- subscriber_profile_update (DISRUPTIVE, Planner) ---------------------------------

  Scenario: subscriber_profile_update dry-run returns a redacted plan, announces deregistration and sends no PUT
    Given the portal mock holds subscriber "imsi-001010000000001" with k "00112233445566778899aabbccddeeff", opc "ffeeddccbbaa99887766554433221100", ambr_ul "50000" and ambr_dl "100000"
    When I call "subscriber_profile_update" with arguments {"supi":"imsi-001010000000001","fields":{"ambr_dl":"200 Mbps"}}
    Then the result is a dry run
    And the dry-run plan states that the UE will be deregistered
    And the portal mock received exactly 1 GET to "/api/v1/subscribers/imsi-001010000000001"
    And the portal mock received 0 PUT requests
    And the audit log has an entry for "subscriber_profile_update" with outcome "dry_run"
    And the output contains neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"

  Scenario: subscriber_profile_update with confirm true merges the allowlisted fields and carries the keys through the PUT
    Given the portal mock holds subscriber "imsi-001010000000001" with k "00112233445566778899aabbccddeeff", opc "ffeeddccbbaa99887766554433221100", ambr_ul "50000" and ambr_dl "100000"
    And the portal mock accepts PUT "/api/v1/subscribers/imsi-001010000000001" reporting deregistered true
    When I call "subscriber_profile_update" with arguments {"supi":"imsi-001010000000001","fields":{"ambr_dl":"200 Mbps"},"confirm":true}
    Then the call succeeds
    And the portal mock received exactly 1 PUT to "/api/v1/subscribers/imsi-001010000000001" with ambr_dl 200000 kbps and the stored k and opc unchanged
    And the result field "updated" is true
    And the result field "deregistered" is true
    And the result field "previous" contains "100000"
    And the audit log has an entry for "subscriber_profile_update" with outcome "executed"

  Scenario: subscriber_profile_update rejects an ambr_dl that is not a TS 29.571 BitRate with -32602 and sends no PUT
    Given the portal mock holds subscriber "imsi-001010000000001" with k "00112233445566778899aabbccddeeff", opc "ffeeddccbbaa99887766554433221100", ambr_ul "50000" and ambr_dl "100000"
    When I call "subscriber_profile_update" with arguments {"supi":"imsi-001010000000001","fields":{"ambr_dl":"500 bps"},"confirm":true}
    Then the call is refused with code -32602
    And the portal mock received 0 PUT requests

  Scenario: subscriber_profile_update never leaks key hex in the result, the audit log or slog
    Given the portal mock holds subscriber "imsi-001010000000001" with k "00112233445566778899aabbccddeeff", opc "ffeeddccbbaa99887766554433221100", ambr_ul "50000" and ambr_dl "100000"
    And the portal mock accepts PUT "/api/v1/subscribers/imsi-001010000000001" reporting deregistered true
    When I call "subscriber_profile_update" with arguments {"supi":"imsi-001010000000001","fields":{"ambr_ul":"60 Mbps"},"confirm":true}
    Then the call succeeds
    And the output contains neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"
    And the audit log and slog contain neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"

  Scenario Outline: subscriber_profile_update rejects key and unknown fields with -32602 and makes no upstream call
    When I call "subscriber_profile_update" with arguments {"supi":"imsi-001010000000001","fields":{"<field>":"<value>"},"confirm":true}
    Then the call is refused with code -32602
    And the portal mock received 0 requests
    And the output contains neither "<value>" nor "00112233445566778899aabbccddeeff"

    Examples:
      | field    | value                            |
      | k        | 00112233445566778899aabbccddeeff |
      | opc      | ffeeddccbbaa99887766554433221100 |
      | op       | 0123456789abcdef0123456789abcdef |
      | sqn      | 000000000001                     |
      | amf      | 8000                             |
      | whatever | x                                |

  Scenario: subscriber_profile_update for an unknown SUPI is refused with -32000 and no PUT is sent
    Given the portal mock answers 404 for GET "/api/v1/subscribers/imsi-001010000000099"
    When I call "subscriber_profile_update" with arguments {"supi":"imsi-001010000000099","fields":{"ambr_dl":"200 Mbps"},"confirm":true}
    Then the call is refused with code -32000
    And the portal mock received 0 PUT requests

  Scenario: subscriber_profile_update is hidden from tools/list in read-only mode
    Given the MCP guard runs with access_mode "read-only"
    When I list the tools
    Then the tool list does not contain "subscriber_profile_update"

  Scenario: subscriber_profile_update rejects a malformed SUPI
    When I call "subscriber_profile_update" with arguments {"supi":"not-a-supi","fields":{"ambr_dl":"200 Mbps"},"confirm":true}
    Then the call is refused with code -32602
    And the portal mock received 0 requests

  # ---- subscriber_provision (ADMIN) ----------------------------------------------------

  Scenario: subscriber_provision dry-run does not echo k or opc and sends no POST
    Given the MCP guard runs with access_mode "lab"
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"00112233445566778899aabbccddeeff","opc":"ffeeddccbbaa99887766554433221100"}
    Then the result is a dry run
    And the portal mock received 0 POST requests to "/api/v1/subscribers"
    And the output contains neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"
    And the audit log has an entry for "subscriber_provision" with outcome "dry_run"

  Scenario: subscriber_provision with confirm true POSTs once and leaks neither key
    Given the MCP guard runs with access_mode "lab"
    And the portal mock accepts POST "/api/v1/subscribers"
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"00112233445566778899aabbccddeeff","opc":"ffeeddccbbaa99887766554433221100","sqn":"000000000020","amf":"8000","profile":{"ambr_ul":"50 Mbps","ambr_dl":"100 Mbps"},"confirm":true}
    Then the call succeeds
    And the portal mock received exactly 1 POST to "/api/v1/subscribers"
    And the result field "created" is true
    And the result field "supi" is "imsi-001010000000077"
    And the output contains neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"
    And the audit log has an entry for "subscriber_provision" with outcome "executed"
    And the audit log and slog contain neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"

  Scenario: subscriber_provision then subscriber_get shows the subscriber with keys redacted
    Given the MCP guard runs with access_mode "lab"
    And the portal mock stores subscribers POSTed to "/api/v1/subscribers"
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"00112233445566778899aabbccddeeff","opc":"ffeeddccbbaa99887766554433221100","confirm":true}
    And I call "subscriber_get" with arguments {"supi":"imsi-001010000000077"}
    Then the call succeeds
    And the subscriber list contains no key material
    And the output contains neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"

  Scenario Outline: subscriber_provision rejects bad hex or wrong length with -32602 and no POST
    Given the MCP guard runs with access_mode "lab"
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"<k>","opc":"<opc>","confirm":true}
    Then the call is refused with code -32602
    And the portal mock received 0 POST requests to "/api/v1/subscribers"
    And the output contains neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"

    Examples:
      | k                                | opc                              |
      | 00112233445566778899aabbccddee   | ffeeddccbbaa99887766554433221100 |
      | 00112233445566778899aabbccddeegg | ffeeddccbbaa99887766554433221100 |
      | 00112233445566778899aabbccddeeff | ffeeddccbbaa998877665544332211   |

  Scenario: subscriber_provision rejects a malformed sqn and amf with -32602
    Given the MCP guard runs with access_mode "lab"
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"00112233445566778899aabbccddeeff","opc":"ffeeddccbbaa99887766554433221100","sqn":"12","amf":"zz","confirm":true}
    Then the call is refused with code -32602
    And the portal mock received 0 POST requests to "/api/v1/subscribers"

  Scenario: subscriber_provision is refused in operator access mode and the portal is not called
    Given the MCP guard runs with access_mode "operator"
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"00112233445566778899aabbccddeeff","opc":"ffeeddccbbaa99887766554433221100","confirm":true}
    Then the call is refused with code -32000 and message "access_mode operator does not allow it"
    And the portal mock received 0 POST requests to "/api/v1/subscribers"
    When I list the tools
    Then the tool list does not contain "subscriber_provision"

  Scenario: subscriber_provision is refused for the operator role even in lab mode
    Given the MCP server runs with access mode "lab" and bearer authentication
    And I send the operator token
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"00112233445566778899aabbccddeeff","opc":"ffeeddccbbaa99887766554433221100","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "role operator"
    And the portal mock received 0 POST requests to "/api/v1/subscribers"

  Scenario: subscriber_provision is refused for the viewer role in lab mode
    Given the MCP server runs with access mode "lab" and bearer authentication
    And I send the viewer token
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"00112233445566778899aabbccddeeff","opc":"ffeeddccbbaa99887766554433221100","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "role viewer"
    And the portal mock received 0 POST requests to "/api/v1/subscribers"

  Scenario: subscriber_provision maps a portal 409 duplicate to -32000 without echoing the keys
    Given the MCP guard runs with access_mode "lab"
    And the portal mock answers 409 for POST "/api/v1/subscribers"
    When I call "subscriber_provision" with arguments {"supi":"imsi-001010000000077","k":"00112233445566778899aabbccddeeff","opc":"ffeeddccbbaa99887766554433221100","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "409"
    And the output contains neither "00112233445566778899aabbccddeeff" nor "ffeeddccbbaa99887766554433221100"

  # ---- subscriber_delete (ADMIN) -------------------------------------------------------

  Scenario: subscriber_delete dry-run sends no DELETE
    Given the MCP guard runs with access_mode "lab"
    And the portal mock holds subscribers "imsi-001010000000077" and "imsi-001010000000078"
    When I call "subscriber_delete" with arguments {"supi":"imsi-001010000000077"}
    Then the result is a dry run
    And the portal mock received 0 DELETE requests
    And the audit log has an entry for "subscriber_delete" with outcome "dry_run"

  Scenario: subscriber_delete with confirm true deletes once and a later subscriber_get returns 404
    Given the MCP guard runs with access_mode "lab"
    And the portal mock stores subscribers POSTed to "/api/v1/subscribers"
    And the portal mock holds subscribers "imsi-001010000000077" and "imsi-001010000000078"
    When I call "subscriber_delete" with arguments {"supi":"imsi-001010000000077","confirm":true}
    Then the call succeeds
    And the portal mock received exactly 1 DELETE to "/api/v1/subscribers/imsi-001010000000077"
    And the result field "deleted" is true
    And the audit log has an entry for "subscriber_delete" with outcome "executed"
    When I call "subscriber_get" with arguments {"supi":"imsi-001010000000077"}
    Then the call is refused with code -32000
    And the refusal message mentions "404"

  # The portal DELETE answers 204 even when no row matches, so the tool GETs first and
  # refuses an unknown SUPI before any DELETE is sent.
  Scenario: subscriber_delete refuses an unknown SUPI with -32000 and sends no DELETE
    Given the MCP guard runs with access_mode "lab"
    And the portal mock answers 404 for DELETE "/api/v1/subscribers/imsi-001010000000099"
    When I call "subscriber_delete" with arguments {"supi":"imsi-001010000000099","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "subscriber not found"
    And the portal mock received 0 DELETE requests

  Scenario: subscriber_delete rejects a malformed SUPI
    Given the MCP guard runs with access_mode "lab"
    When I call "subscriber_delete" with arguments {"supi":"not-a-supi","confirm":true}
    Then the call is refused with code -32602
    And the portal mock received 0 DELETE requests

  Scenario: subscriber_delete is refused in operator access mode
    Given the MCP guard runs with access_mode "operator"
    When I call "subscriber_delete" with arguments {"supi":"imsi-001010000000077","confirm":true}
    Then the call is refused with code -32000 and message "access_mode operator does not allow it"
    And the portal mock received 0 DELETE requests
    When I list the tools
    Then the tool list does not contain "subscriber_delete"

  Scenario: subscriber_delete is refused for the operator role in lab mode
    Given the MCP server runs with access mode "lab" and bearer authentication
    And I send the operator token
    When I call "subscriber_delete" with arguments {"supi":"imsi-001010000000077","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "role operator"
    And the portal mock received 0 DELETE requests

  Scenario: subscriber_delete is refused for the viewer role in lab mode
    Given the MCP server runs with access mode "lab" and bearer authentication
    And I send the viewer token
    When I call "subscriber_delete" with arguments {"supi":"imsi-001010000000077","confirm":true}
    Then the call is refused with code -32000
    And the refusal message mentions "role viewer"
    And the portal mock received 0 DELETE requests

  # ---- Tool registry ---------------------------------------------------------------------

  Scenario: Runtime tools are visible in lab mode and admin tools are hidden in operator mode
    Given the MCP guard runs with access_mode "lab"
    When I list the tools
    Then the tool list contains "amf_timer_config"
    And the tool list contains "qos_policy_list"
    And the tool list contains "subscriber_profile_update"
    And the tool list contains "subscriber_provision"
    And the tool list contains "subscriber_delete"
