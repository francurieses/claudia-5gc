Feature: Nlmf_Location DetermineLocation — LPP Relay and GNSS Positioning (TS 37.355 / TS 24.501 §8.7.4 / TS 23.273 §6.2.10)
  As an LCS consumer (internal NF or AF)
  I want to POST a DetermineLocation request with locationQoS.hAccuracy below 50 m
  So that the LMF triggers a quality-driven LPP capability/assistance/measurement exchange with the
  UE via a transparent AMF NAS N1 relay and returns a LocationData estimate with uncertainty <= 50 m,
  falling back transparently to E-CID then Cell-ID when the UE cannot provide a GNSS fix

  # spec_ref: TS 37.355 §6           (LPP A-GNSS subset — RequestCapabilities/ProvideCapabilities,
  #                                   ProvideAssistanceData, RequestLocationInformation/ProvideLocationInformation)
  # spec_ref: TS 24.501 §8.7.4       (DL/UL NAS Transport carrying LPP)
  # spec_ref: TS 24.501 §9.11.3.40   (Payload container type IE — value 0x03 = LPP message container.
  #                                   NOT 0x01 — 0x01 is N1 SM information / 5GSM. See procedure doc
  #                                   Conformance Notes: the backlog descriptor's "0x01" is a documentation error.)
  # spec_ref: TS 38.413 §8.6.2       (NGAP DownlinkNASTransport, ProcCode 4 — opaque NAS relay)
  # spec_ref: TS 38.413 §8.6.3       (NGAP UplinkNASTransport, ProcCode 46 — opaque NAS relay)
  # spec_ref: TS 23.273 §6.2.10      (GNSS positioning method — quality-driven method selection, A-GNSS via LPP)
  # spec_ref: TS 23.273 §7.2         (LPP over N1 relay path — AMF is a transparent relay, does not decode LPP)
  # spec_ref: TS 29.572 §5.2.2.2     (DetermineLocation — method selection trigger + LocationData response)
  # spec_ref: TS 29.572 §6.1.6.2.2   (LocationData schema: locationEstimate, accuracy, positioningDataList)
  # spec_ref: TS 29.571 §5.2.7       (ProblemDetails / cause strings)
  # endpoint: POST /nlmf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info → 200 LocationData (reused — DetermineLocation entry)
  # endpoint: POST /nlmf-loc/v1/ue-contexts/{ueContextId}/ul-lpp-info      → 202 Accepted (new — AMF→LMF UL LPP relay receive)
  # endpoint: POST /namf-loc/v1/ue-contexts/{ueContextId}/dl-lpp-info      → 202 Accepted (new — LMF→AMF DL LPP dispatch)

  Background:
    Given a clean LMF instance is running on SBI port 8012
    And the LMF has registered with nfType "LMF" and service "nlmf-loc" in the NRF
    And a mock AMF is available for Namf_Location ProvideLocationInfo, Namf_Location dl-nrppa-info and Namf_Location dl-lpp-info

  # ---------------------------------------------------------------------------
  # Scenario 1 — Happy path: GNSS success via LPP (AC: hAccuracy=30 → full LPP sequence → gnss result)
  # TS 29.572 §5.2.2.2 — method selection: hAccuracy=30 < 50 m → GNSS / LPP path
  # TS 37.355 §6 — capability round: RequestCapabilities → ProvideCapabilities{GNSS=SUPPORTED}
  #                assistance round: ProvideAssistanceData + RequestLocationInformation → UE
  #                measurement round: ProvideLocationInformation (per-SV pseudoranges) → LMF
  # TS 24.501 §8.7.4 / §9.11.3.40 — every LPP leg rides DL/UL NAS Transport with payload
  #                container type 0x03 (NOT 0x01); the AMF relays opaquely and never decodes it
  # TS 23.273 §6.2.10 — simplified WLS GNSS fix; uncertainty clamped <= 50 m CEP50
  # TS 29.572 §6.1.6.2.2 — LocationData: shape POINT, non-null lat/lon, positioningDataList:[gnss]
  # AC (backlog): DetermineLocation with hAccuracy=30 → GNSS position returned with accuracy <= 50 m
  # AC (backlog): AMF must log "UplinkLPP received", LMF must log "GNSS position calculated"
  # ---------------------------------------------------------------------------
  Scenario: Successful GNSS positioning via LPP returns a POINT estimate with accuracy at most 50 m and positioningDataList containing gnss
    Given the mock AMF relays LPP for ueContextId "imsi-001010000000001" with UE capability "GNSS_SUPPORTED" and ProvideLocationInformation reporting 4 satellite pseudoranges near lat "40.416775" lon "-3.703790"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001" and locationQoS hAccuracy 30
    Then the LMF responds with HTTP status 200
    And the response locationEstimate has shape "POINT"
    And the response LocationData locationEstimate point has a non-null latitude and longitude
    And the response LocationData positioningDataList includes method "gnss"
    And the response LocationData accuracy is at most 50
    And every dl-lpp-info and ul-lpp-info exchange used NAS payload container type 3
    And the metric fivegc_lmf_gnss_total with label result "OK" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 2 — GNSS unsupported → transparent fallback to E-CID (no error surfaced to the LCS consumer)
  # TS 37.355 §6 — capability round: ProvideCapabilities with an empty/absent GNSS support list
  # TS 23.273 §6.2.10 — graceful downgrade: GNSS=NONE → LMF falls back to E-CID (LMF-004), not Cell-ID directly
  # LMF MUST return 200 OK with an E-CID LocationData — the LCS client must not receive a 5xx
  # positioningDataList must reflect the E-CID method (not gnss); accuracy lands in the E-CID band (<= 150 m)
  # LMF MUST NOT attempt ProvideAssistanceData / RequestLocationInformation after a GNSS=NONE reply
  # ---------------------------------------------------------------------------
  Scenario: UE reporting GNSS capability NONE triggers transparent fallback to E-CID positioning without attempting assistance data or measurement
    Given the mock AMF relays LPP for ueContextId "imsi-001010000000002" with UE capability "GNSS_NONE" and no ProvideLocationInformation report
    And the mock AMF relays NRPPa for ueContextId "imsi-001010000000002" with gNB capability "E-CID_SUPPORTED" and E-CIDMeasurementReport serving nrCellId "000000010" plmn mcc "001" mnc "01" tac "0001" and AP position lat "40.416775" lon "-3.703790" uncertainty "90"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000002" with supi "imsi-001010000000002" and locationQoS hAccuracy 30
    Then the LMF responds with HTTP status 200
    And the response locationEstimate has shape "POINT"
    And the response LocationData positioningDataList includes method "eCID"
    And the response LocationData positioningDataList does not include method "gnss"
    And the response LocationData accuracy is at most 150
    And the mock AMF received no ProvideAssistanceData or RequestLocationInformation LPP messages for ueContextId "imsi-001010000000002"
    And the metric fivegc_lmf_gnss_total with label result "FALLBACK_ECID" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 3 — Capability exchange drives the LPP state machine IDLE -> CAPS_REQUESTED
  # TS 37.355 §6 — RequestCapabilities (LMF→UE) / ProvideCapabilities (UE→LMF) round-trip
  # TS 24.501 §8.7.4 — DL NAS Transport with payload container type 0x03 carries RequestCapabilities;
  #                     UL NAS Transport with payload container type 0x03 carries ProvideCapabilities
  # TS 38.413 §8.6.2 / §8.6.3 — the opaque LPP container rides the existing NGAP DownlinkNASTransport
  #                              (ProcCode 4) / UplinkNASTransport (ProcCode 46) relay
  # AC (backlog): the DetermineLocation trigger relays LPP RequestCapabilities via DL NAS Transport
  #               payload container type 0x03 and the LMF processes ProvideCapabilities, advancing
  #               its per-SUPI state machine from IDLE to CAPS_REQUESTED
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation triggers an LPP capability exchange over payload container type 3 and advances the LMF state machine to CAPS_REQUESTED
    Given the mock AMF relays LPP for ueContextId "imsi-001010000000001" with UE capability "GNSS_SUPPORTED" and ProvideLocationInformation reporting 4 satellite pseudoranges near lat "40.416775" lon "-3.703790"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000001" with supi "imsi-001010000000001" and locationQoS hAccuracy 30
    Then the LMF responds with HTTP status 200
    And the mock AMF received a dl-lpp-info dispatch for ueContextId "imsi-001010000000001" carrying an LPP RequestCapabilities message over NAS payload container type 3
    And the LMF logged an "UplinkLPP received" event with lpp_msg "ProvideCapabilities"
    And the LMF per-SUPI LPP state for ueContextId "imsi-001010000000001" advanced through state "CAPS_REQUESTED"

  # ---------------------------------------------------------------------------
  # Scenario 4 — GNSS measurement timeout → fallback chain GNSS -> E-CID -> Cell-ID
  # TS 23.273 §6.2.10 — LPP guard timer expiry at the measurement step is a graceful degradation
  #                     trigger, not a hard error; the LMF downgrades one tier at a time
  # Error table: no UL LPP ProvideLocationInformation before the guard timer expires → FALLBACK
  # This scenario additionally forces the E-CID leg to fail (no gNB measurement) so the chain
  # bottoms out at Cell-ID, still returning 200 (never a 5xx) to the LCS consumer
  # ---------------------------------------------------------------------------
  Scenario: GNSS measurement timeout with an unavailable E-CID leg falls back all the way to Cell-ID and still returns 200
    Given the mock AMF relays LPP for ueContextId "imsi-001010000000004" with UE capability "GNSS_SUPPORTED" but never relays a UL ProvideLocationInformation report
    And the mock AMF relays NRPPa for ueContextId "imsi-001010000000004" with gNB capability "E-CID_NONE" and no E-CID measurement report
    And the mock AMF returns a Namf LocationData with nrCellId "000000010" and tai plmnId mcc "001" mnc "01" tac "0001" for ueContextId "imsi-001010000000004"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000004" with supi "imsi-001010000000004" and locationQoS hAccuracy 30
    Then the LMF responds with HTTP status 200
    And the response locationEstimate has shape "POINT"
    And the response LocationData contains nrCellId "000000010"
    And the response LocationData positioningDataList does not include method "gnss"
    And the response LocationData positioningDataList does not include method "eCID"
    And the metric fivegc_lmf_gnss_total with label result "FALLBACK_CELLID" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 5 — Error path: AMF cannot relay because the UE is not reachable on N1 (dl-lpp-info rejected)
  # TS 23.273 §6.2.10 — dl-lpp-info rejection is treated as a hard relay failure at the GNSS tier;
  #                     the LMF MUST downgrade gracefully, never surfacing the AMF-side error upward
  # Error table: UE is CM-IDLE (no N1/N2 connection) on dl-lpp-info → AMF rejects (409/504
  #              UE_NOT_REACHABLE) → LMF falls back to E-CID
  # ---------------------------------------------------------------------------
  Scenario: AMF unreachable UE on dl-lpp-info causes transparent fallback to E-CID positioning
    Given the mock AMF rejects dl-lpp-info for ueContextId "imsi-001010000000005" with cause "UE_NOT_REACHABLE"
    And the mock AMF relays NRPPa for ueContextId "imsi-001010000000005" with gNB capability "E-CID_SUPPORTED" and E-CIDMeasurementReport serving nrCellId "000000010" plmn mcc "001" mnc "01" tac "0001" and AP position lat "40.416775" lon "-3.703790" uncertainty "90"
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000005" with supi "imsi-001010000000005" and locationQoS hAccuracy 30
    Then the LMF responds with HTTP status 200
    And the response LocationData positioningDataList includes method "eCID"
    And the response LocationData positioningDataList does not include method "gnss"
    And the metric fivegc_lmf_gnss_total with label result "FALLBACK_ECID" is incremented

  # ---------------------------------------------------------------------------
  # Scenario 6 — Spec deviation: UDM BLOCK_ALL privacy blocks DetermineLocation before any LPP dispatch
  # TS 23.273 §9.1 — subscriber lcsData.locationPrivacy = BLOCK_ALL: LMF must gate before LPP
  # Error table: BLOCK_ALL → 403 PRIVACY_EXCEPTION_DENIED; no dl-lpp-info must be dispatched
  # Privacy gate fires before method selection and before any AMF interaction — regardless of hAccuracy
  # ---------------------------------------------------------------------------
  Scenario: DetermineLocation with GNSS hAccuracy blocked by UDM BLOCK_ALL privacy policy before any LPP exchange is attempted
    Given the subscriber location privacy for "imsi-001010000000006" is "BLOCK_ALL"
    And the mock AMF records any dl-lpp-info calls it receives
    When an LCS consumer POSTs a DetermineLocation request for ueContextId "imsi-001010000000006" with supi "imsi-001010000000006" and locationQoS hAccuracy 30
    Then the LMF responds with HTTP status 403
    And the response ProblemDetails cause is "PRIVACY_EXCEPTION_DENIED"
    And the mock AMF received no dl-lpp-info calls
    And the metric fivegc_lmf_gnss_total with label result "OK" is not incremented
