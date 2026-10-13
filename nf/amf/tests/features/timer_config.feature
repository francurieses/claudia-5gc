@mcp011
Feature: AMF runtime timer configuration via O&M (TS 24.501 §5.3.7, §10.2 Table 10.2.1; TS 23.501 §5.4.1.1)
  As an O&M actor using the AMF management API on :9002 (not an SBI path)
  I want to read and change T3512, the mobile reachable guard and the implicit de-registration timer at runtime
  So that the next REGISTRATION ACCEPT carries the new T3512 value (IEI 0x5E) without an AMF restart

  # Design: docs/procedures/amf-timer-config.md. Endpoint: GET/PUT /amf/v1/config/timers.
  # No 5GMM or 5GSM cause applies: the O&M change sends no NAS message. Errors are HTTP statuses
  # of the mgmt API with a ProblemDetails-like body {status, title, detail, cause}.
  # Test base (YAML) values: T3512 60 s, mobile_reachable_guard 120 s, implicit_detach 60 s.
  # GPRS timer 3 (TS 24.008 §10.5.7.4a): 120 s = unit 1 min value 2 = 0xA2; 60 s = 0xA1; 600 s = 0x01.

  Background:
    Given the AMF inbound namf-comm SBI server is running
    And a UE "imsi-001010000000001" is registered with an active NAS security context
    And the AMF management API is running
    And the AMF timer configuration has base T3512 60, guard 120 and implicit detach 60 seconds

  # ---- Happy path -------------------------------------------------------------------------

  Scenario: GET returns effective equal to base, a derived mobile_reachable_secs and persisted false at startup
    When O&M reads the timer configuration
    Then the response status is 200
    And the timer effective values are T3512 60, guard 120, mobile reachable 180 and implicit detach 60
    And the timer base values are T3512 60, guard 120, mobile reachable 180 and implicit detach 60
    And the timer response has persisted false

  Scenario: PUT t3512_secs 120 changes effective T3512 and derived mobile reachable, leaves base unchanged and is not persisted
    When O&M changes the timer configuration with body '{"t3512_secs":120}'
    Then the response status is 200
    And the timer effective values are T3512 120, guard 120, mobile reachable 240 and implicit detach 60
    And the timer base values are T3512 60, guard 120, mobile reachable 180 and implicit detach 60
    And the timer response has persisted false

  Scenario: PUT is a partial update that keeps omitted fields
    Given O&M changes the timer configuration with body '{"t3512_secs":120}'
    When O&M changes the timer configuration with body '{"mobile_reachable_guard_secs":30}'
    Then the response status is 200
    And the timer effective values are T3512 120, guard 30, mobile reachable 150 and implicit detach 60

  # TS 24.501 §8.2.7 Table 8.2.7.1.1 IEI 0x5E; §9.11.2.5
  Scenario: Registration Accept built after PUT t3512_secs 120 carries T3512 value IEI 0x5E with GPRS timer 3 value 0xA2
    Given O&M changes the timer configuration with body '{"t3512_secs":120}'
    When the AMF builds a Registration Accept
    Then the Registration Accept carries the T3512 value IE 0x5E with GPRS timer 3 octet 0xA2

  Scenario: Mobility Registration Update Accept built after PUT t3512_secs 120 carries T3512 value 0xA2
    Given O&M changes the timer configuration with body '{"t3512_secs":120}'
    When the AMF builds a Registration Update Accept
    Then the Registration Accept carries the T3512 value IE 0x5E with GPRS timer 3 octet 0xA2

  Scenario: Reset restores the YAML base values and the next Registration Accept carries the base encoding 0xA1
    Given O&M changes the timer configuration with body '{"t3512_secs":120,"mobile_reachable_guard_secs":30,"implicit_detach_secs":300}'
    When O&M changes the timer configuration with body '{"reset":true}'
    Then the response status is 200
    And the timer effective values equal the timer base values
    And the timer response has persisted false
    When the AMF builds a Registration Accept
    Then the Registration Accept carries the T3512 value IE 0x5E with GPRS timer 3 octet 0xA1

  # TS 24.501 §5.3.7; TS 23.501 §5.4.1.1: timers armed after the change use the new values
  Scenario: Implicit Detach timer armed after PUT implicit_detach_secs 300 uses the new duration
    Given O&M changes the timer configuration with body '{"implicit_detach_secs":300}'
    When the UE Mobile Reachable timer expires and the Implicit Detach timer is armed
    Then the armed Implicit Detach duration is 300 seconds

  Scenario: Mobile Reachable timer armed after PUT t3512_secs 120 uses T3512 plus guard
    Given O&M changes the timer configuration with body '{"t3512_secs":120}'
    And the UE is CM-CONNECTED
    When the UE becomes CM-IDLE after an AN release
    Then the armed Mobile Reachable duration is 240 seconds

  # docs/procedures/amf-timer-config.md §1 semantics 3: already-armed per-UE timers are untouched
  Scenario: A Mobile Reachable timer already armed keeps its old duration when T3512 is changed later
    Given the UE is CM-CONNECTED
    And the UE becomes CM-IDLE after an AN release
    And the armed Mobile Reachable duration is 180 seconds
    When O&M changes the timer configuration with body '{"t3512_secs":600}'
    Then the response status is 200
    And the armed Mobile Reachable duration of the UE is still 180 seconds

  # docs/procedures/amf-timer-config.md §7.3: lowered-T3512 mitigation (TS 24.501 §5.3.7: mobile reachable longer than the T3512 the UE holds)
  Scenario: Mobile Reachable timer after T3512 is lowered below the value sent to the UE uses the sent T3512 plus guard
    Given O&M changes the timer configuration with body '{"t3512_secs":600}'
    And the AMF sent the UE a Registration Accept with T3512 600 seconds
    And the UE is CM-CONNECTED
    And O&M changes the timer configuration with body '{"t3512_secs":60}'
    When the UE becomes CM-IDLE after an AN release
    Then the armed Mobile Reachable duration is 720 seconds
    And the armed Mobile Reachable duration is not 180 seconds

  # ---- Canonical logging ------------------------------------------------------------------

  Scenario: Accepted PUT is logged with procedure TimerConfigChange, interface OAM, direction IN and result OK
    When O&M changes the timer configuration with body '{"t3512_secs":120}'
    Then the AMF logs a line with procedure "TimerConfigChange", interface "OAM", direction "IN" and result "OK"

  Scenario: Rejected PUT is logged with procedure TimerConfigChange, interface OAM, direction IN, result REJECT and the cause
    When O&M changes the timer configuration with body '{"t3512_secs":59}'
    Then the AMF logs a line with procedure "TimerConfigChange", interface "OAM", direction "IN" and result "REJECT"
    And the logged cause is "T3512_OUT_OF_RANGE"

  # ---- Rejections: bounds -----------------------------------------------------------------

  Scenario Outline: PUT with T3512 outside 60..86400 s is rejected with 400 and nothing changes
    When O&M changes the timer configuration with body '{"t3512_secs":<value>}'
    Then the response status is 400
    And the timer problem cause is "T3512_OUT_OF_RANGE"
    And the timer effective values equal the timer base values

    Examples:
      | value |
      | 59    |
      | 86401 |

  # Design decision: T3512 must round-trip exactly through nas.EncodeGPRSTimer3
  Scenario Outline: PUT with a T3512 not exactly representable in GPRS timer 3 is rejected with 400 T3512_NOT_REPRESENTABLE and nothing changes
    When O&M changes the timer configuration with body '{"t3512_secs":<value>}'
    Then the response status is 400
    And the timer problem cause is "T3512_NOT_REPRESENTABLE"
    And the timer effective values equal the timer base values

    Examples:
      | value |
      | 61    |
      | 2000  |
      | 3240  |

  Scenario Outline: PUT with a T3512 exactly representable in GPRS timer 3 is accepted
    When O&M changes the timer configuration with body '{"t3512_secs":<value>}'
    Then the response status is 200
    And the timer effective T3512 is <value>

    Examples:
      | value |
      | 60    |
      | 120   |
      | 600   |
      | 3600  |
      | 86400 |

  Scenario: PUT with mobile_reachable_guard_secs 3601 is rejected with 400 and nothing changes
    When O&M changes the timer configuration with body '{"mobile_reachable_guard_secs":3601}'
    Then the response status is 400
    And the timer problem cause is "GUARD_OUT_OF_RANGE"
    And the timer effective values equal the timer base values

  Scenario: PUT with a negative mobile_reachable_guard_secs is rejected with 400 and nothing changes
    When O&M changes the timer configuration with body '{"mobile_reachable_guard_secs":-1}'
    Then the response status is 400
    And the timer effective values equal the timer base values

  Scenario: PUT with mobile_reachable_guard_secs 0 is accepted and mobile reachable equals T3512
    When O&M changes the timer configuration with body '{"mobile_reachable_guard_secs":0}'
    Then the response status is 200
    And the timer effective values are T3512 60, guard 0, mobile reachable 60 and implicit detach 60

  Scenario: PUT with implicit_detach_secs 59 is rejected with 400 and nothing changes
    When O&M changes the timer configuration with body '{"implicit_detach_secs":59}'
    Then the response status is 400
    And the timer problem cause is "IMPLICIT_DETACH_OUT_OF_RANGE"
    And the timer effective values equal the timer base values

  Scenario: PUT with implicit_detach_secs 86401 is rejected with 400 and nothing changes
    When O&M changes the timer configuration with body '{"implicit_detach_secs":86401}'
    Then the response status is 400
    And the timer problem cause is "IMPLICIT_DETACH_OUT_OF_RANGE"
    And the timer effective values equal the timer base values

  Scenario: PUT is all-or-nothing when one field is valid and another is out of range
    When O&M changes the timer configuration with body '{"t3512_secs":120,"implicit_detach_secs":59}'
    Then the response status is 400
    And the timer problem cause is "IMPLICIT_DETACH_OUT_OF_RANGE"
    And the timer effective values equal the timer base values

  # ---- Rejections: request shape ----------------------------------------------------------

  Scenario: PUT reset true combined with a value field is rejected with 400 RESET_EXCLUSIVE and nothing changes
    Given O&M changes the timer configuration with body '{"t3512_secs":120}'
    When O&M changes the timer configuration with body '{"reset":true,"t3512_secs":300}'
    Then the response status is 400
    And the timer problem cause is "RESET_EXCLUSIVE"
    And the timer effective T3512 is 120

  Scenario: PUT with an unknown JSON field is rejected with 400 UNKNOWN_FIELD and nothing changes
    When O&M changes the timer configuration with body '{"t3512":120}'
    Then the response status is 400
    And the timer problem cause is "UNKNOWN_FIELD"
    And the timer effective values equal the timer base values

  Scenario: PUT carrying the derived field mobile_reachable_secs is rejected with 400 and nothing changes
    When O&M changes the timer configuration with body '{"mobile_reachable_secs":500}'
    Then the response status is 400
    And the timer effective values equal the timer base values

  Scenario: PUT with malformed JSON is rejected with 400 MALFORMED_REQUEST and nothing changes
    When O&M changes the timer configuration with body '{"t3512_secs":'
    Then the response status is 400
    And the timer problem cause is "MALFORMED_REQUEST"
    And the timer effective values equal the timer base values

  Scenario Outline: PUT with an empty or no-op body is rejected with 400 because there is nothing to change
    When O&M changes the timer configuration with body '<body>'
    Then the response status is 400
    And the timer effective values equal the timer base values

    Examples:
      | body             |
      |                  |
      | {}               |
      | {"reset":false}  |

  Scenario Outline: Method other than GET or PUT on the timer configuration path is rejected with 405
    When O&M sends an HTTP <method> to the timer configuration path
    Then the response status is 405
    And the response Allow header is "GET, PUT"
    And the timer effective values equal the timer base values

    Examples:
      | method |
      | DELETE |
      | POST   |

  # ---- Concurrency ------------------------------------------------------------------------

  Scenario: Concurrent PUTs and GETs leave a consistent effective state where mobile reachable equals T3512 plus guard
    When O&M issues concurrent timer configuration PUTs and GETs
    Then every timer response satisfies mobile reachable equals T3512 plus guard
