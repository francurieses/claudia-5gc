Feature: Nlmf_Location DetermineLocation — NRPPa Relay and E-CID Positioning (TS 38.455 / TS 38.413 §8.17.3 / TS 23.273 §6.2.9)
  As an LCS consumer (internal NF or AF)
  I want to POST a DetermineLocation request with locationQoS.hAccuracy in the 50–200 m band
  So that the LMF triggers a quality-driven NRPPa E-CID positioning exchange with the gNB via AMF relay
  and returns a LocationData estimate with uncertainty ≤ 150 m,
  falling back transparently to Cell-ID when the gNB cannot provide E-CID measurements

  # spec_ref: TS 38.455 §8          (NRPPa E-CID subset — PositioningInformationRequest/Response,
  #                                   E-CIDMeasurementInitiationRequest/Response/Failure, E-CIDMeasurementReport)
  # spec_ref: TS 38.413 §8.17.3     (NGAP UE-Associated NRPPa Transport, ProcCode 68 UL / 69 DL)
  # spec_ref: TS 38.413 §8.17.4     (NGAP Non-UE-Associated NRPPa Transport, ProcCode 66 UL / 67 DL)
  # spec_ref: TS 23.273 §6.2.9      (E-CID positioning method — quality-driven method selection, gNB-reported AP position)
  # spec_ref: TS 23.273 §7.2 step C (NRPPa over N2 relay path — AMF is a transparent relay, does not decode NRPPa)
  # spec_ref: TS 29.572 §5.2.2.2    (DetermineLocation — method selection trigger + LocationData response)
  # spec_ref: TS 29.572 §6.1.6.2.2  (LocationData schema: locationEstimate, accuracy, nrCellId, tai, positioningDataList)
  # spec_ref: TS 29.518 §5.2.2.6    (Namf_Location producer — dl-nrppa-info dispatch + ul-nrppa-info relay)
  # spec_ref: TS 29.571 §5.2.7      (ProblemDetails / cause strings)
  # endpoint: POST /nlmf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info → 200 LocationData (reused — Cell-ID fallback path)
  # endpoint: POST /nlmf-loc/v1/ue-contexts/{ueContextId}/ul-nrppa-info   → 202 Accepted (new — AMF→LMF UL NRPPa relay receive)
  # endpoint: POST /namf-loc/v1/ue-contexts/{ueContextId}/dl-nrppa-info   → 202 Accepted (new — LMF→AMF DL NRPPa dispatch)

  Background:
    Given a clean LMF instance is running on SBI port 8012
    And the LMF has registered with nfType "LMF" and service "nlmf-loc" in the NRF
    And a mock AMF is available for Namf_Location ProvideLocationInfo and Namf_Location dl-nrppa-info

  # ---------------------------------------------------------------------------
  # Scenario 1 — Happy path: E-CID success (AC: hAccuracy=100 → NRPPa exchange → eCID result)
  # TS 29.572 §5.2.2.2 — method selection: hAccuracy=100 ∈ [50, 200] m → E-CID / NRPPa path
  # TS 38.455 §8 — capability round: PositioningInformationRequest → Response{E-CID_SUPPORTED}
  #                measurement round: E-CIDMeasurementInitiationRequest → E-CIDMeasurementReport
  # TS 23.273 §6.2.9 / TS 38.455 §9 — the gNB reports its own WGS84 estimate via the real, optional
  #                     NG-RANAccessPointPosition IE (TS 23.032 Ellipsoid Point with Uncertainty
  #                     Ellipse shape) inside E-CID-MeasurementResult; uncertainty ≤ 150 m (vs Cell-ID ≥ 500 m)
  # TS 29.572 §6.1.6.2.2 — LocationData: shape POINT, nrCellId (serving), tai, positioningDataList:[eCID]
  # AC (backlog): DetermineLocation with hAccuracy=100 → E-CID position returned with uncertainty ≤ 150 m
  # AC (backlog): AMF must log "UplinkNRPPa received", LMF must log "E-CID position calculated"
  # ---------------------------------------------------------------------------
  Scenario: Successful E-CID positioning via NRPPa returns a POINT estimate with uncertainty at most 150 m and positioningDataList containing eCID
    Given the mock AMF relays NRPPa for ueContextId "imsi-001010000000001" with gNB capability "E-CID_SUPPORTED" and E-CIDMeasurementReport serving nrCellId "000000010" plmn mcc "001" mnc "01" tac "0001" and AP position lat "40.416775" lon "-3.703790" uncertainty "90"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001" and locationQoS hAccuracy 100
    Then the LMF responds with HTTP status 200
    And the response locationEstimate has shape "POINT"
    And the response LocationData locationEstimate point has a non-null latitude and longitude
    And the response LocationData contains nrCellId "000000010"
    And the response LocationData contains tai with tac "0001"
    And the response LocationData positioningDataList includes method "eCID"
    And the response LocationData accuracy is at most 150
    And the metric fivegc_lmf_ecid_total with label result "OK" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 2 — NRPPa guard timer expiry → transparent fallback to Cell-ID (no 5xx surfaced)
  # Error table: no UL NRPPa (capability response or measurement report) before guard timer expires
  # TS 23.273 §6.2.9 — graceful downgrade: guard timer fires → LMF falls back to Cell-ID silently
  # LMF MUST return 200 OK with a Cell-ID LocationData — the LCS client must not receive a 5xx
  # positioningDataList must NOT contain "eCID" (Cell-ID method was applied, not E-CID)
  # ---------------------------------------------------------------------------
  Scenario: NRPPa guard timer expiry causes transparent fallback to Cell-ID with no error surfaced to the LCS consumer
    Given the mock AMF accepts dl-nrppa-info for ueContextId "imsi-001010000000001" but never relays a UL NRPPa response
    And the mock AMF returns a Namf LocationData with nrCellId "000000010" and tai plmnId mcc "001" mnc "01" tac "0001" for ueContextId "imsi-001010000000001"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001" and locationQoS hAccuracy 100
    Then the LMF responds with HTTP status 200
    And the response locationEstimate has shape "POINT"
    And the response LocationData contains nrCellId "000000010"
    And the response LocationData contains tai with tac "0001"
    And the response LocationData positioningDataList does not include method "eCID"
    And the metric fivegc_lmf_ecid_total with label result "FALLBACK_CELLID" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 3 — gNB capability = NONE → immediate transparent fallback to Cell-ID
  # TS 38.455 §8 — capability round: PositioningInformationResponse{E-CID: NONE}
  #                (or PositioningInformationFailure) received from gNB via AMF relay
  # Error table: gNB capability = NONE / PositioningInformationFailure → fallback to Cell-ID, result=FALLBACK_CELLID
  # LMF MUST NOT attempt E-CIDMeasurementInitiationRequest after receiving a NONE capability reply
  # TS 23.273 §6.2.9 — graceful downgrade path on capability mismatch
  # ---------------------------------------------------------------------------
  Scenario: gNB returning E-CID capability NONE triggers immediate transparent fallback to Cell-ID without attempting measurement
    Given the mock AMF relays NRPPa for ueContextId "imsi-001010000000001" with gNB capability "E-CID_NONE" and no E-CID measurement report
    And the mock AMF returns a Namf LocationData with nrCellId "000000010" and tai plmnId mcc "001" mnc "01" tac "0001" for ueContextId "imsi-001010000000001"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001" and locationQoS hAccuracy 100
    Then the LMF responds with HTTP status 200
    And the response locationEstimate has shape "POINT"
    And the response LocationData contains nrCellId "000000010"
    And the response LocationData contains tai with tac "0001"
    And the response LocationData positioningDataList does not include method "eCID"
    And the metric fivegc_lmf_ecid_total with label result "FALLBACK_CELLID" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 4 — Method selection: hAccuracy > 200 m → Cell-ID only, no NRPPa exchange
  # TS 23.273 §6.2.9 — quality-driven selection threshold: hAccuracy=300 > 200 m → Cell-ID
  # The LMF MUST NOT dispatch any dl-nrppa-info call to the AMF when hAccuracy > 200 m
  # TS 29.572 §6.1.6.2.2 — LocationData: Cell-ID result with shape POINT; no eCID in positioningDataList
  # AC (backlog): hAccuracy > 200 m goes straight to Cell-ID without any NRPPa exchange
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation with hAccuracy above 200 m selects Cell-ID method directly and dispatches no NRPPa messages to the AMF
    Given the mock AMF returns a Namf LocationData with nrCellId "000000010" and tai plmnId mcc "001" mnc "01" tac "0001" for ueContextId "imsi-001010000000001"
    And the mock AMF records any dl-nrppa-info calls it receives
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001" and locationQoS hAccuracy 300
    Then the LMF responds with HTTP status 200
    And the response locationEstimate has shape "POINT"
    And the response LocationData contains nrCellId "000000010"
    And the response LocationData positioningDataList does not include method "eCID"
    And the mock AMF received no dl-nrppa-info calls

  # ---------------------------------------------------------------------------
  # Scenario 5 — Spec deviation: UDM BLOCK_ALL privacy blocks DetermineLocation before any NRPPa
  # TS 23.273 §9.1 — subscriber lcsData.locationPrivacy = BLOCK_ALL: LMF must gate before NRPPa
  # Error table: BLOCK_ALL → 403 PRIVACY_EXCEPTION_DENIED; no dl-nrppa-info must be dispatched
  # Privacy gate fires before method selection and before any AMF interaction — regardless of hAccuracy
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation with E-CID hAccuracy blocked by UDM BLOCK_ALL privacy policy before any NRPPa exchange is attempted
    Given the subscriber location privacy for "imsi-001010000000003" is "BLOCK_ALL"
    And the mock AMF records any dl-nrppa-info calls it receives
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000003" with supi "imsi-001010000000003" and locationQoS hAccuracy 100
    Then the LMF responds with HTTP status 403
    And the response ProblemDetails cause is "PRIVACY_EXCEPTION_DENIED"
    And the mock AMF received no dl-nrppa-info calls
    And the metric fivegc_lmf_ecid_total with label result "OK" is not incremented
