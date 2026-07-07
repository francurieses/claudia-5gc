Feature: Nlmf_Location DetermineLocation — Cell-ID positioning (TS 29.572 §5.2.2.2, TS 23.273 §7.2)
  As an LCS consumer (internal NF or AF)
  I want to POST a DetermineLocation request to the LMF for a registered UE
  So that I receive a LocationData response containing the serving NRCGI and TAI

  # spec_ref: TS 29.572 §5.2.2.2  (Nlmf_Location DetermineLocation — producer)
  # spec_ref: TS 23.273 §7.2       (UE positioning procedure — Cell-ID method)
  # spec_ref: TS 29.518 §5.2.2.6   (Namf_Location ProvideLocationInfo — consumer)
  # spec_ref: TS 38.413 §8.17.1    (NGAP LocationReportingControl / LocationReport)
  # spec_ref: TS 29.571            (ProblemDetails common types)
  # endpoint: POST /nlmf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info → 200 LocationData

  Background:
    Given a clean LMF instance is running on SBI port 8012
    And the LMF has registered with nfType "LMF" and service "nlmf-loc" in the NRF
    And a mock AMF is available for Namf_Location ProvideLocationInfo

  # ---------------------------------------------------------------------------
  # Scenario 1 — Happy path: Cell-ID positioning returns NRCGI + TAI (AC 1)
  # TS 29.572 §5.2.2.2 — 200 OK + LocationData {locationEstimate(POINT), nrCellId, tai}
  # TS 23.273 §7.2 — serving cell reported by gNB via NGAP LocationReport
  # ---------------------------------------------------------------------------
  Scenario: Successful Cell-ID positioning returns NRCGI and TAI for a known UE
    Given the mock AMF returns a Namf LocationData with nrCellId "000000010" and tai plmnId mcc "001" mnc "01" tac "0001" for ueContextId "imsi-001010000000001"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001"
    Then the LMF responds with HTTP status 200
    And the response LocationData contains nrCellId "000000010"
    And the response LocationData contains tai with tac "0001"
    And the response locationEstimate has shape "POINT"
    And the response ageOfLocationEstimate is 0
    And the metric fivegc_lmf_locate_total with label result "OK" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 2 — UE not found: AMF returns 404 CONTEXT_NOT_FOUND (AC 2)
  # TS 29.572 §5.2.2.2 — LMF propagates Namf 404 → Nlmf 404 CONTEXT_NOT_FOUND
  # Error table: {ueContextId} has no UE context in the AMF → 404 CONTEXT_NOT_FOUND
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation for an unknown UE returns 404 CONTEXT_NOT_FOUND
    Given the mock AMF returns 404 with cause "CONTEXT_NOT_FOUND" for ueContextId "imsi-001010000000099"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000099" with supi "imsi-001010000000099"
    Then the LMF responds with HTTP status 404
    And the response ProblemDetails cause is "CONTEXT_NOT_FOUND"
    And the metric fivegc_lmf_locate_total with label result "FAILURE" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 3 — gNB positioning timeout: AMF returns 504 LOCATION_FAILURE (AC 3)
  # TS 29.572 §5.2.2.2 — no NGAP LocationReport before deadline → 504
  # Error table: no NGAP LocationReport before timeout → LOCATION_FAILURE
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation when gNB does not respond before timeout returns a failure result
    Given the mock AMF returns 504 with cause "LOCATION_FAILURE" for ueContextId "imsi-001010000000001"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001"
    Then the LMF responds with HTTP status 504
    And the response ProblemDetails cause is "LOCATION_FAILURE"
    And the metric fivegc_lmf_locate_total with label result "FAILURE" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 4 — Deferred MT Location timeout: paging-then-locate, UE never responds
  # TS 23.273 §7.2 steps E2–E7 — AMF pages CM-IDLE UE; T-positioning (15 s) expires.
  # AMF returns 504 UE_NOT_REACHABLE after its guard timer fires.
  # Error table: UE paged but not reachable within T-positioning → UE_NOT_REACHABLE
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation for a CM-IDLE UE whose paging times out returns UE_NOT_REACHABLE
    Given the mock AMF returns 504 with cause "UE_NOT_REACHABLE" for ueContextId "imsi-001010000000002"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000002" with supi "imsi-001010000000002"
    Then the LMF responds with HTTP status 504
    And the response ProblemDetails cause is "UE_NOT_REACHABLE"
    And the metric fivegc_lmf_locate_total with label result "FAILURE" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 5 — Spec deviation: both supi and gpsi absent → 400 MANDATORY_IE_MISSING
  # TS 29.572 §5.2.2.2 — at least one of supi / gpsi is required to identify the UE
  # Error table: UE not identifiable (supi/gpsi both absent) → LMF 400 MANDATORY_IE_MISSING
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation without supi or gpsi is rejected with 400 MANDATORY_IE_MISSING
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with neither supi nor gpsi in the request body
    Then the LMF responds with HTTP status 400
    And the response ProblemDetails cause is "MANDATORY_IE_MISSING"
    And the metric fivegc_lmf_locate_total with label result "REJECT" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 6 — Spec deviation: LMF cannot reach AMF → 504 LOCATION_FAILURE
  # TS 29.572 §5.2.2.2 — AMF SBI discovery / connectivity failure propagated to LCS client
  # Error table: LMF cannot reach AMF / AMF discovery fails → 504 LOCATION_FAILURE
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation when AMF is unreachable returns 504 LOCATION_FAILURE
    Given the mock AMF is not reachable
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001"
    Then the LMF responds with HTTP status 504
    And the response ProblemDetails cause is "LOCATION_FAILURE"
    And the metric fivegc_lmf_locate_total with label result "FAILURE" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 7 — Location privacy: UDM returns ALLOW_ALL → location proceeds normally
  # TS 23.273 §9.1; TS 29.503 §5.2.2 — lcsData.locationPrivacy != BLOCK_ALL → allow
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation proceeds when UDM location privacy is ALLOW_ALL
    Given the mock AMF returns a Namf LocationData with nrCellId "000000010" and tai plmnId mcc "001" mnc "01" tac "0001" for ueContextId "imsi-001010000000001"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001"
    Then the LMF responds with HTTP status 200
    And the response LocationData contains nrCellId "000000010"
    And the metric fivegc_lmf_locate_total with label result "OK" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 8 — Location privacy: UDM returns BLOCK_ALL → 403 PRIVACY_EXCEPTION_DENIED
  # TS 23.273 §9.1 — subscriber blocked location disclosure; LMF must not forward
  # to AMF; respond 403 PRIVACY_EXCEPTION_DENIED to LCS client
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation is blocked when UDM location privacy is BLOCK_ALL
    Given the subscriber location privacy for "imsi-001010000000003" is "BLOCK_ALL"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000003" with supi "imsi-001010000000003"
    Then the LMF responds with HTTP status 403
    And the response ProblemDetails cause is "PRIVACY_EXCEPTION_DENIED"
    And the metric fivegc_lmf_locate_total with label result "REJECT" is incremented
