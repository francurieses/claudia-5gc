Feature: Nlmf_Location deferred location - periodic and area events via DetermineLocation (TS 29.572 §5.2.2.2 / §5.2.2.4.2)
  As a GMLC acting as the LCS client
  I want to activate periodic or triggered (area event) location in the LMF with DetermineLocation
  So that the LMF reports each event to my hgmlcCallBackURI with the EventNotify callback
  and I can release the session with CancelLocation

  # spec_ref: TS 29.572 §5.2.2.2.2  (DetermineLocation deferred: 200 LocationDataExt = successful activation)
  # spec_ref: TS 29.572 §5.2.2.4.2  (CancelLocation with hgmlcCallBackURI + ldrReference -> 204)
  # spec_ref: TS 29.572 Table 6.1.4.2.2-2 (501 UNSUPPORTED_EVENT_TYPE, 403 LOCATION_SESSION_UNKNOWN)
  # spec_ref: TS 29.572 Table 6.1.6.3.14-1 (LdrType), TS29572_Nlmf_Location.yaml (EventNotifyData callback)
  # spec_ref: TS 23.273 §6.3.3 step 5 (GMLC-initiated cancel releases the session without a notification)
  # endpoint: POST /nlmf-loc/v1/determine-location -> 200 LocationDataExt | 400 | 501
  # endpoint: POST /nlmf-loc/v1/cancel-location -> 204 | 400 | 403
  # callback: POST {hgmlcCallBackURI} EventNotifyData
  # The deferred behaviour is Rel-19 only: rel17 / no profile ignores the deferred attributes.

  Background:
    Given the 5GC is running with an LMF and a mock AMF for Namf_Location ProvideLocationInfo
    And a GMLC callback receiver is listening on an https hgmlcCallBackURI

  # ---------------------------------------------------------------------------
  # Happy path - periodic activation, EventNotify reports, final NORMAL_TERMINATION
  # ---------------------------------------------------------------------------
  Scenario: Rel-19 periodic location is activated with 200 LocationDataExt and reported by EventNotify until reportingAmount is reached
    Given the LMF runs the "rel19" release profile
    And the UE is reported in NR cell "000000010"
    When the GMLC sends a DetermineLocation for "imsi-001010000000001" with ldrType "PERIODIC", ldrReference "0a1b2c", reportingAmount 3 and reportingIntervalMs 100
    Then the LMF responds with HTTP status 200
    And the LocationDataExt carries a locationEstimate and a timestampOfLocationEstimate
    And the LocationDataExt acceptedPeriodicEventInfo has reportingIntervalMs 100
    And the callback receiver gets 3 EventNotify callbacks within 8 seconds
    And every EventNotify has ldrReference "0a1b2c" and reportedEventType "PERIODIC_EVENT"
    And only the last EventNotify carries terminationCause "NORMAL_TERMINATION"

  # ---------------------------------------------------------------------------
  # Happy path - area events per ldrType
  # ---------------------------------------------------------------------------
  Scenario Outline: Rel-19 area event activation reports <reportedEventType> for ldrType <ldrType>
    Given the LMF runs the "rel19" release profile
    And the UE is reported in NR cell "<firstCell>" and then in NR cell "<nextCell>"
    When the GMLC sends a DetermineLocation for "imsi-001010000000001" with ldrType "<ldrType>", ldrReference "0a1b2c" and an area of NR cell "000000010" sampled every 1 second
    Then the LMF responds with HTTP status 200
    And the LocationDataExt carries a locationEstimate and a timestampOfLocationEstimate
    And the callback receiver gets at least 1 EventNotify callbacks within 8 seconds
    And the first EventNotify has reportedEventType "<reportedEventType>" and ldrReference "0a1b2c"

    Examples:
      | ldrType             | firstCell   | nextCell    | reportedEventType        |
      | ENTERING_INTO_AREA  | 000000011   | 000000010   | ENTERING_AREA_EVENT      |
      | LEAVING_FROM_AREA   | 000000010   | 000000011   | LEAVING_AREA_EVENT       |
      | BEING_INSIDE_AREA   | 000000010   | 000000010   | BEING_INSIDE_AREA_EVENT  |

  # ---------------------------------------------------------------------------
  # Session end by the LMF
  # ---------------------------------------------------------------------------
  Scenario: Area event session ends at reportingDuration with a final LOCATION_CANCELLATION_EVENT NORMAL_TERMINATION
    Given the LMF runs the "rel19" release profile
    And the UE is reported in NR cell "000000011"
    When the GMLC sends a DetermineLocation for "imsi-001010000000001" with ldrType "ENTERING_INTO_AREA", ldrReference "0a1b2c", an area of NR cell "000000010" sampled every 1 second and reportingDuration 1 second
    Then the LMF responds with HTTP status 200
    And the callback receiver gets at least 1 EventNotify callbacks within 8 seconds
    And the last EventNotify has reportedEventType "LOCATION_CANCELLATION_EVENT" and terminationCause "NORMAL_TERMINATION"

  Scenario: LMF duration cap ends an infinite periodic session with TERMINATION_BY_NETWORK
    Given the LMF runs the "rel19" release profile
    And the LMF caps deferred location sessions at 1 second
    And the UE is reported in NR cell "000000010"
    When the GMLC sends a DetermineLocation for "imsi-001010000000001" with ldrType "PERIODIC", ldrReference "0a1b2c", infinite reporting and reportingIntervalMs 100
    Then the LMF responds with HTTP status 200
    And the LocationDataExt acceptedPeriodicEventInfo has reportingInfiniteInd true
    And the callback receiver gets an EventNotify with reportedEventType "LOCATION_CANCELLATION_EVENT" within 8 seconds
    And the last EventNotify has reportedEventType "LOCATION_CANCELLATION_EVENT" and terminationCause "TERMINATION_BY_NETWORK"

  # ---------------------------------------------------------------------------
  # CancelLocation (TS 29.572 §5.2.2.4.2)
  # ---------------------------------------------------------------------------
  Scenario: GMLC CancelLocation releases the deferred session silently and a second cancel is rejected with 403 LOCATION_SESSION_UNKNOWN
    Given the LMF runs the "rel19" release profile
    And the UE is reported in NR cell "000000010"
    And the GMLC has activated an infinite periodic location with ldrReference "0a1b2c" and reportingIntervalMs 150
    And the callback receiver has received at least 1 EventNotify
    When the GMLC sends a CancelLocation with the hgmlcCallBackURI and ldrReference "0a1b2c"
    Then the LMF responds with HTTP status 204
    And the callback receiver gets no EventNotify after the cancel
    When the GMLC sends a CancelLocation with the hgmlcCallBackURI and ldrReference "0a1b2c"
    Then the LMF responds with HTTP status 403
    And the response ProblemDetails cause is "LOCATION_SESSION_UNKNOWN"

  # ---------------------------------------------------------------------------
  # Spec-deviation rejections
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation with a non-https hgmlcCallBackURI is rejected with 400 MANDATORY_IE_INCORRECT
    Given the LMF runs the "rel19" release profile
    And the UE is reported in NR cell "000000010"
    When the GMLC sends a DetermineLocation for "imsi-001010000000001" with ldrType "PERIODIC", ldrReference "0a1b2c", reportingAmount 2, reportingIntervalMs 100 and hgmlcCallBackURI "http://gmlc.example.test/notify"
    Then the LMF responds with HTTP status 400
    And the response ProblemDetails cause is "MANDATORY_IE_INCORRECT"
    And the problem invalidParams names "/hgmlcCallBackURI"
    And the callback receiver gets no EventNotify within the observation window

  Scenario: Rel-19 MOTION ldrType is rejected with 501 UNSUPPORTED_EVENT_TYPE
    Given the LMF runs the "rel19" release profile
    And the UE is reported in NR cell "000000010"
    When the GMLC sends a DetermineLocation for "imsi-001010000000001" with ldrType "MOTION", ldrReference "0a1b2c", reportingAmount 2 and reportingIntervalMs 100
    Then the LMF responds with HTTP status 501
    And the response ProblemDetails cause is "UNSUPPORTED_EVENT_TYPE"

  Scenario Outline: Rel-19 inconsistent ldrType and event information is rejected with 400 MANDATORY_IE_INCORRECT (<case>)
    Given the LMF runs the "rel19" release profile
    And the UE is reported in NR cell "000000010"
    When the GMLC sends a DetermineLocation for "imsi-001010000000001" with ldrType "<ldrType>", ldrReference "0a1b2c" and <info>
    Then the LMF responds with HTTP status 400
    And the response ProblemDetails cause is "MANDATORY_IE_INCORRECT"
    And the problem invalidParams names "<param>"

    Examples:
      | case                                  | ldrType            | info                                                              | param                |
      | PERIODIC with areaEventInfo only      | PERIODIC           | an area of NR cell "000000010" sampled every 1 second             | /periodicEventInfo   |
      | ENTERING_INTO_AREA with periodic only | ENTERING_INTO_AREA | reportingAmount 2 and reportingIntervalMs 100                     | /areaEventInfo       |

  Scenario: Release profile rel17 ignores the deferred attributes and answers an immediate LocationData
    Given the LMF runs the "rel17" release profile
    And the UE is reported in NR cell "000000010"
    When the GMLC sends a DetermineLocation for "imsi-001010000000001" with ldrType "PERIODIC", ldrReference "0a1b2c", reportingAmount 3 and reportingIntervalMs 100
    Then the LMF responds with HTTP status 200
    And the LocationDataExt carries a locationEstimate and no timestampOfLocationEstimate
    And the callback receiver gets no EventNotify within the observation window
