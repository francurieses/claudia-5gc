// Package server — GNSS positioning via LPP relay (LMF-005, rewired for the
// LMF-009 spec-faithful UPER codec and three-leg flow).
//
// Quality-driven method selection (TS 23.273 §6.2.10 / TS 29.572 §5.2.2.2),
// extending the LMF-004 selector in ecid.go:
//
//	hAccuracy > 200 m (or absent/≤0) → Cell-ID   (LMF-001 path)
//	50 m ≤ hAccuracy ≤ 200 m         → E-CID     (LMF-004 path, ecid.go)
//	hAccuracy < 50 m                  → GNSS/LPP  (this file)
//
// The A-GNSS LPP exchange rides the AMF's synchronous NAS relay
// (POST /namf-loc/.../dl-lpp-info → DL NAS Transport PCT=0x03 → UL NAS
// Transport PCT=0x03 → HTTP 200 body) in THREE DL legs (TS 37.355 §5.2):
//
//	Leg 1: RequestCapabilities (txn N1, endTransaction=FALSE)
//	       → ProvideCapabilities (echo N1, endTransaction=TRUE)
//	Leg 2: ProvideAssistanceData (txn N2, endTransaction=TRUE) — unsolicited,
//	       DL-only (TS 37.355 assistance delivery has no response message):
//	       sent with expectUlResponse=false, the AMF answers 204 No Content.
//	Leg 3: RequestLocationInformation (txn N3, endTransaction=FALSE)
//	       → ProvideLocationInformation (echo N3, endTransaction=TRUE) with
//	       per-SV codePhase pseudoranges.
//
// Quantized-anchor rule: the WLS seed and the synthetic ephemeris derive from
// the leg-2 gnss-ReferenceLocation AS ENCODED ON THE WIRE (decode-of-encode),
// never from the raw config float — both ends compute byte-identical geometry.
//
// On any failure in any leg, a decoded gnss-Error, an echoed-transaction
// decode error, or a WLS solve that cannot converge (< 4 usable satellites),
// the LMF falls back to E-CID (ecid.go's performECIDOrFallback), which itself
// falls back to Cell-ID — the graceful, no-5xx degradation LMF-004
// established. An echoed transactionID mismatch is log-warn only
// (lpp_txn_mismatch) — correlation remains by AMF-UE-NGAP-ID.
//
// Ref: TS 37.355 §5.2/§6 (LPP A-GNSS procedures), TS 23.273 §6.2.10 (GNSS
// method) / §7.2 (transparent AMF relay), TS 29.572 §5.2.2.2
// (DetermineLocation), TS 29.518 §5.2.2.6 (Namf_Location dl-lpp-info),
// TS 24.501 §8.7.4 (DL/UL NAS Transport carrying LPP).
package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/lpp"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- LPP per-SUPI state machine states (docs/procedures/LPPRelay.md) --------

const (
	lppStateIdle            = "IDLE"
	lppStateCapsRequested   = "CAPS_REQUESTED"
	lppStateAssistSent      = "ASSIST_SENT"
	lppStateMeasureReceived = "MEASURE_RECEIVED"
	lppStateFixed           = "FIXED"
	lppStateFallback        = "FALLBACK"
)

// lppGuardTimerNote documents that the guard timer for each LPP leg is
// enforced by the LPPSender implementation (HTTPAMFLocationClient's HTTP
// client / the AMF's lppTimeout deadline), mirroring the E-CID NRPPa relay —
// no separate timer is started here. Ref: TS 23.273 §6.2.10.
const lppGuardTimerNote = "enforced by LPPSender (AMF dl-lpp-info guard timer)"

// ---- LPPSender interface ------------------------------------------------------

// LPPSender is the interface for sending opaque LPP PDUs to the UE via the
// AMF NAS N1 relay. Implemented by HTTPAMFLocationClient in production; test
// doubles in tests.
//
// expectUlResponse=true (legs 1/3): the AMF blocks until the matching UL NAS
// Transport (PCT=0x03) arrives and returns its LPP PDU (HTTP 200).
// expectUlResponse=false (leg 2, ProvideAssistanceData — unsolicited, no LPP
// response message exists): the AMF sends the DL NAS Transport and returns
// 204 No Content immediately; the returned PDU slice is nil.
//
// Ref: TS 29.518 §5.2.2.6 (Namf_Location dl-lpp-info); TS 24.501 §8.7.4;
// docs/procedures/LPPRelay.md §Endpoints.
type LPPSender interface {
	// SendDLLPP sends lppPDU to the UE via the AMF relay for the given UE context.
	// Returns (ulLPPPDU, "", nil) on 200; (nil, "", nil) on 204 (expectUlResponse=false).
	// Returns (nil, "CONTEXT_NOT_FOUND", ErrUEContextNotFound) on AMF 404.
	// Returns (nil, cause, ErrLocationFailure) on timeout or other relay failure.
	SendDLLPP(ctx context.Context, ueContextID string, lppPDU []byte, expectUlResponse bool) ([]byte, string, error)
}

// ---- per-SUPI LPP state tracker -----------------------------------------------

// lppStateTracker records the current LPP state machine state per ueContextId,
// for introspection/logging and forward-compatibility with an async relay
// model. Always cleaned up (defer Delete) so a timeout or fallback cannot
// leak an entry. Ref: docs/procedures/LPPRelay.md §LMF per-SUPI LPP state machine.
type lppStateTracker struct {
	states sync.Map // map[string]string ueContextId -> state
}

func (t *lppStateTracker) set(ueContextID, state string) { t.states.Store(ueContextID, state) }
func (t *lppStateTracker) get(ueContextID string) string {
	v, ok := t.states.Load(ueContextID)
	if !ok {
		return lppStateIdle
	}
	return v.(string)
}
func (t *lppStateTracker) delete(ueContextID string) { t.states.Delete(ueContextID) }

// ---- GNSS LPP exchange (main entry point) ------------------------------------

// performLPPOrFallback attempts UE-assisted A-GNSS positioning via the
// three-leg LPP flow over the AMF NAS relay (see the package doc comment).
//
// On success: returns LocationData with a POINT fix (uncertainty ≤ 50 m) and
// positioningDataList=["gnss"].
// On any fallback: calls s.performECIDOrFallback (which itself may further
// fall back to Cell-ID) and returns its result — no 5xx surfaced.
//
// The privacy gate MUST have been checked by the caller before invoking this
// method (same invariant as performECIDOrFallback).
//
// Ref: TS 37.355 §5.2/§6; TS 23.273 §6.2.10; TS 29.572 §5.2.2.2.
func (s *Server) performLPPOrFallback(ctx context.Context, ueContextID, supi string) (*LocationData, string, error) {
	start := time.Now()
	corrID := logging.CorrelationID(ctx)

	log := logging.NewProcedureLogger(ctx, s.logger, "LPPRelay").With(
		"nf", "LMF",
		"procedure", "LPPRelay",
		"interface", "Namf",
		"direction", "OUT",
		"correlation_id", corrID,
		"ue_context_id", ueContextID,
		"supi", supi,
		"spec_ref", "TS 37.355 §6 / TS 23.273 §6.2.10",
	)

	s.lppState.set(ueContextID, lppStateIdle)
	defer s.lppState.delete(ueContextID)

	fallback := func(reason string) (*LocationData, string, error) {
		s.lppState.set(ueContextID, lppStateFallback)
		locResp, cause, err := s.performECIDOrFallback(ctx, ueContextID, supi)
		result := "FALLBACK_CELLID"
		if err == nil && locResp != nil {
			for _, m := range locResp.PositioningDataList {
				if m == "eCID" {
					result = "FALLBACK_ECID"
					break
				}
			}
		}
		log.Info("GNSS/LPP falling back",
			"reason", reason,
			"result", result,
			"lpp_state", lppStateFallback,
			"duration_ms", time.Since(start).Milliseconds(),
			"spec_ref", "TS 23.273 §6.2.10",
		)
		metrics.LMFGNSSTotal.WithLabelValues(result).Inc()
		return locResp, cause, err
	}

	// verifyEcho log-warns on an echoed transactionID mismatch WITHOUT
	// aborting — TS 37.355 §5.2; correlation is by AMF-UE-NGAP-ID.
	verifyEcho := func(sent lpp.TransactionID, pdu *lpp.PDU, leg string) {
		if !pdu.HasTransactionID || pdu.TransactionID != sent {
			log.Warn("echoed LPP transactionID mismatch",
				"result", "lpp_txn_mismatch",
				"leg", leg,
				"lpp_txn", sent.Number,
				"echoed_initiator", pdu.TransactionID.Initiator,
				"echoed_txn", pdu.TransactionID.Number,
				"spec_ref", "TS 37.355 §5.2",
			)
		}
	}

	if s.lppClient == nil {
		return fallback("LPP client not wired")
	}

	// ---- Leg 1: Capability Transfer — RequestCapabilities → ProvideCapabilities.
	// Ref: TS 37.355 §5.2/§6.2 (txn N1, endTransaction=FALSE on the request).
	txn1 := lpp.NextTransactionID()
	reqCapsPDU, err := lpp.BuildRequestCapabilities(txn1)
	if err != nil {
		return fallback("build RequestCapabilities: " + err.Error())
	}
	s.lppState.set(ueContextID, lppStateCapsRequested)
	log.Info("GNSS capability request dispatched to AMF",
		"lpp_msg", "RequestCapabilities",
		"lpp_state", lppStateCapsRequested,
		"lpp_txn", txn1.Number,
		"spec_ref", "TS 37.355 §6 / TS 24.501 §8.7.4",
	)

	capRspPDU, cause, err := s.lppClient.SendDLLPP(ctx, ueContextID, reqCapsPDU, true)
	if err != nil {
		log.Warn("GNSS capability leg failed",
			"lpp_msg", "RequestCapabilities",
			"error", err, "cause", cause,
			"spec_ref", lppGuardTimerNote,
		)
		return fallback("LPP capability leg failed: " + cause)
	}

	capPDU, err := lpp.Decode(capRspPDU)
	if err != nil {
		log.Warn("GNSS capability response decode error", "error", err)
		return fallback("LPP capability response decode error")
	}
	if capPDU.Type != lpp.MsgProvideCapabilities || capPDU.ProvideCapabilities == nil {
		log.Warn("GNSS capability response: unexpected LPP message type",
			"lpp_msg_type", capPDU.Type,
		)
		return fallback("unexpected LPP message type in capability response")
	}
	verifyEcho(txn1, capPDU, "capability")

	caps := capPDU.ProvideCapabilities
	log.Info("UplinkLPP received",
		"lpp_msg", "ProvideCapabilities",
		"lpp_txn", capPDU.TransactionID.Number,
		"gnss_supported", caps.AGNSSSupported,
		"gps_ue_assisted", caps.GPSUEAssisted,
		"spec_ref", "TS 24.501 §8.7.4",
	)

	// GNSS=NONE (a-gnss-ProvideCapabilities absent or no usable gps
	// ue-assisted entry) → graceful downgrade. Ref: TS 23.273 §6.2.10.
	if !caps.AGNSSSupported || !caps.GPSUEAssisted {
		log.Info("GNSS capability=NONE from UE",
			"lpp_msg", "ProvideCapabilities",
			"spec_ref", "TS 23.273 §6.2.10",
		)
		return fallback("UE reported GNSS capability = NONE")
	}

	// ---- Leg 2: Assistance Data — ProvideAssistanceData (DL-only, no UL reply).
	// Ref: TS 37.355 §6.5.2 (txn N2, endTransaction=TRUE, unsolicited).
	sign, rawLat := lpp.EncodeLatitude(s.cfg.DefaultCoord.Lat)
	rawLon := lpp.EncodeLongitude(s.cfg.DefaultCoord.Lon)
	assistData := lpp.AssistanceData{
		DayNumber:        0,
		TimeOfDay:        0,
		ReferenceTimeUnc: lpp.ReferenceTimeUncDefault,
		ReferenceLocation: lpp.ReferenceLocation{
			LatitudeSign:         sign,
			DegreesLatitude:      rawLat,
			DegreesLongitude:     rawLon,
			AltitudeDirection:    0,
			Altitude:             0,
			UncertaintySemiMajor: 42, // ≈538 m — Cell-ID anchor band (TS 23.032 §6)
			UncertaintySemiMinor: 42,
			OrientationMajorAxis: 0,   // circle
			UncertaintyAltitude:  127, // altitude not modelled
			Confidence:           68,  // 1-σ convention, matches E-CID
		},
	}
	assistData.DayNumber, assistData.TimeOfDay = lpp.UnixToGPSDayTime(time.Now().Unix())

	txn2 := lpp.NextTransactionID()
	assistPDU, err := lpp.BuildProvideAssistanceData(txn2, assistData)
	if err != nil {
		return fallback("build ProvideAssistanceData: " + err.Error())
	}
	s.lppState.set(ueContextID, lppStateAssistSent)
	log.Info("GNSS assistance data dispatched (DL-only, no UL reply)",
		"lpp_msg", "ProvideAssistanceData",
		"lpp_state", lppStateAssistSent,
		"lpp_txn", txn2.Number,
		"spec_ref", "TS 37.355 §6.5.2 / TS 24.501 §8.7.4",
	)

	if _, cause2, err2 := s.lppClient.SendDLLPP(ctx, ueContextID, assistPDU, false); err2 != nil {
		log.Warn("GNSS assistance leg send failed",
			"lpp_msg", "ProvideAssistanceData",
			"error", err2, "cause", cause2,
			"spec_ref", lppGuardTimerNote,
		)
		return fallback("LPP assistance leg send failed: " + cause2)
	}

	// Quantized-anchor rule: seed the ephemeris and the WLS initial guess
	// from the wire-quantized reference location (decode-of-encode), never
	// the raw config float — byte-identical geometry on both ends.
	// Ref: docs/procedures/LPPRelay.md §Synthetic satellite geometry.
	qLat := lpp.DecodeLatitude(sign, rawLat)
	qLon := lpp.DecodeLongitude(rawLon)
	ephemeris := lpp.GenerateSyntheticEphemeris(qLat, qLon)

	// ---- Leg 3: Location Information Transfer — RequestLocationInformation
	// → ProvideLocationInformation. Ref: TS 37.355 §6.2 (txn N3).
	txn3 := lpp.NextTransactionID()
	reqLocPDU, err := lpp.BuildRequestLocationInformation(txn3)
	if err != nil {
		return fallback("build RequestLocationInformation: " + err.Error())
	}
	log.Info("GNSS location information request dispatched",
		"lpp_msg", "RequestLocationInformation",
		"lpp_state", lppStateAssistSent,
		"lpp_txn", txn3.Number,
		"satellite_count", len(ephemeris),
		"spec_ref", "TS 37.355 §6 / TS 24.501 §8.7.4",
	)

	measRspPDU, cause3, err3 := s.lppClient.SendDLLPP(ctx, ueContextID, reqLocPDU, true)
	if err3 != nil {
		log.Warn("GNSS measurement leg failed",
			"lpp_msg", "RequestLocationInformation",
			"error", err3, "cause", cause3,
			"spec_ref", lppGuardTimerNote,
		)
		return fallback("LPP measurement leg failed: " + cause3)
	}

	measPDU, err := lpp.Decode(measRspPDU)
	if err != nil {
		log.Warn("GNSS measurement response decode error", "error", err)
		return fallback("LPP measurement response decode error")
	}
	if measPDU.Type != lpp.MsgProvideLocationInformation {
		log.Warn("GNSS measurement response: unexpected LPP message type",
			"lpp_msg_type", measPDU.Type,
		)
		return fallback("unexpected LPP message type in measurement response")
	}
	verifyEcho(txn3, measPDU, "measurement")

	if measPDU.TargetDeviceErrorCause != nil {
		log.Warn("GNSS measurement response carries gnss-Error",
			"lpp_msg", "ProvideLocationInformation",
			"gnss_error_cause", *measPDU.TargetDeviceErrorCause,
			"spec_ref", "TS 37.355 §6.5.2 (GNSS-TargetDeviceErrorCauses)",
		)
		return fallback("UE reported gnss-Error in ProvideLocationInformation")
	}
	if measPDU.LocationMeasurements == nil {
		return fallback("ProvideLocationInformation without measurements")
	}

	s.lppState.set(ueContextID, lppStateMeasureReceived)
	sats := measPDU.LocationMeasurements.Sats
	log.Info("UplinkLPP received",
		"lpp_msg", "ProvideLocationInformation",
		"lpp_state", lppStateMeasureReceived,
		"lpp_txn", measPDU.TransactionID.Number,
		"measurement_count", len(sats),
		"spec_ref", "TS 24.501 §8.7.4",
	)

	if len(sats) < lpp.WLSMinSatellites {
		log.Warn("GNSS measurement report has too few usable satellites",
			"measurement_count", len(sats),
			"min_required", lpp.WLSMinSatellites,
			"spec_ref", "TS 23.273 §6.2.10",
		)
		return fallback("fewer than WLSMinSatellites usable satellites")
	}

	// Decode codePhase fields → pseudoranges in metres. Constellation index
	// i ∈ 1..4 rides the wire as satellite-id = i − 1 (TS 37.355 §6.4 SV-ID).
	measurements := make([]lpp.Measurement, 0, len(sats))
	for _, sv := range sats {
		measurements = append(measurements, lpp.Measurement{
			SVID:              sv.SVID + 1,
			PseudorangeMeters: lpp.CodePhaseToPseudorange(sv.IntegerCodePhase, sv.CodePhase),
		})
	}

	// ---- Position calculation (simplified WLS around the quantized anchor).
	// Ref: TS 23.273 §6.2.10; docs/procedures/LPPRelay.md §Simplified WLS.
	result, ok := lpp.SolveWLS(qLat, qLon, ephemeris, measurements)
	if !ok {
		log.Warn("GNSS WLS solve did not converge", "spec_ref", "TS 23.273 §6.2.10")
		return fallback("WLS solve did not converge")
	}

	s.lppState.set(ueContextID, lppStateFixed)

	// Best-effort TAI/NRCellId metadata from AMF ProvideLocationInfo (same
	// pattern as performECIDOrFallback — the position itself is already
	// known from the WLS fix).
	amfLoc, _, amfErr := s.amfClient.ProvideLocationInfo(ctx, ueContextID)
	var tai *TaiLoc
	var nrCellID string
	if amfErr == nil && amfLoc != nil {
		tai = amfLoc.Tai
		nrCellID = amfLoc.NRCellId
	} else {
		log.Warn("GNSS: ProvideLocationInfo for TAI failed (continuing without TAI)",
			"error", amfErr,
			"spec_ref", "TS 29.518 §5.2.2.6",
		)
	}

	log.Info("GNSS position calculated",
		"lat", result.Lat,
		"lon", result.Lon,
		"uncertainty_m", result.UncertaintyM,
		"satellite_count", result.SatelliteCount,
		"method", "GNSS",
		"result", "OK",
		"lpp_state", lppStateFixed,
		"duration_ms", time.Since(start).Milliseconds(),
		"spec_ref", "TS 23.273 §6.2.10",
	)
	metrics.LMFGNSSTotal.WithLabelValues("OK").Inc()

	return &LocationData{
		LocationEstimate: &GeographicArea{
			Shape:       "POINT",
			Point:       &LatLon{Lat: result.Lat, Lon: result.Lon},
			Uncertainty: result.UncertaintyM,
		},
		NRCellId:            nrCellID,
		Tai:                 tai,
		PositioningDataList: []string{"gnss"},
	}, "", nil
}

// ---- UL LPP receive stub (forward-compatibility) ------------------------------

// handleULLPP is a stub handler for the LMF's ul-lpp-info receive endpoint.
//
// In the synchronous AMF relay model (LMF-005/009, mirroring LMF-004) the LMF
// receives UL LPP PDUs as the HTTP 200 response body from dl-lpp-info — not
// via this endpoint. This stub is registered for forward-compatibility with
// an async relay model and to satisfy the endpoint contract declared in
// docs/procedures/LPPRelay.md §Endpoints.
//
// Ref: docs/procedures/LPPRelay.md §Endpoints; TS 29.518 §5.2.2.6.
func (s *Server) handleULLPP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusAccepted)
}
