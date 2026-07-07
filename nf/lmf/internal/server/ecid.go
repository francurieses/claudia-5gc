// Package server — E-CID positioning via NRPPa relay (LMF-004).
//
// Quality-driven method selection (TS 23.273 §6.2.9 / TS 29.572 §5.2.2.2):
//
//	hAccuracy > 200 m (or absent/≤0) → Cell-ID   (LMF-001 path, no NRPPa)
//	50 m ≤ hAccuracy ≤ 200 m         → E-CID     (this file — NRPPa capability + measurement)
//	hAccuracy < 50 m                  → LPP/GNSS desired (LMF-005, deferred); MVP downgrades to E-CID
//
// The E-CID NRPPa exchange uses the synchronous AMF relay model (LMF-004 PASS 1):
//   - LMF → AMF POST /namf-loc/.../dl-nrppa-info   (sends DL NRPPa)
//   - AMF → gNB NGAP DownlinkUEAssociatedNRPPaTransport (ProcCode=8)
//   - gNB → AMF NGAP UplinkUEAssociatedNRPPaTransport  (ProcCode=50) — synchronous response
//   - AMF returns the UL NRPPa PDU in the HTTP 200 body
//
// Two rounds:
//
//	Round 1: PositioningInformationRequest → PositioningInformationResponse{E-CID capability}
//	Round 2: E-CIDMeasurementInitiationRequest → E-CIDMeasurementReport{ServingNRCGI + optional AP position}
//
// On any failure in either round the LMF falls back to Cell-ID transparently (no 5xx surfaced).
//
// Ref: TS 38.455 §8 (NRPPa procedures), TS 23.273 §6.2.9 (E-CID method),
// TS 29.572 §5.2.2.2 (DetermineLocation), TS 29.518 §5.2.2.6 (Namf_Location NRPPa relay),
// TS 38.413 §8.17.3 (NGAP UE-Associated NRPPa Transport).
package server

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nrppa"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// ---- Method-selection thresholds (TS 23.273 §6.2.9) -------------------------

const (
	// hAccuracyCellIDFloorM is the hAccuracy threshold above which Cell-ID positioning
	// is selected. hAccuracy > 200 m (or absent) → Cell-ID (LMF-001 path, no NRPPa).
	// Ref: TS 23.273 §6.2.9; TS 29.572 §5.2.2.2.
	hAccuracyCellIDFloorM = 200.0

	// hAccuracyEcidFloorM is the lower E-CID band boundary and, equivalently,
	// the GNSS/LPP band ceiling (hAccuracyGnssFloorM below is the same value,
	// named per docs/procedures/LPPRelay.md for readability at the call site).
	// hAccuracy < 50 m → GNSS/LPP (LMF-005, this file's selectMethod); when
	// the LPP client is not wired, DetermineLocation downgrades to E-CID.
	// Ref: TS 23.273 §6.2.9 / §6.2.10.
	hAccuracyEcidFloorM = 50.0

	// hAccuracyGnssFloorM is the GNSS/LPP band ceiling (alias of
	// hAccuracyEcidFloorM) — hAccuracy < hAccuracyGnssFloorM selects GNSS/LPP.
	// Ref: TS 23.273 §6.2.10; docs/procedures/LPPRelay.md §Quality/method selection.
	hAccuracyGnssFloorM = hAccuracyEcidFloorM

	// ecidUncertaintyMinM is the minimum horizontal uncertainty returned for a multi-cell
	// E-CID fix. Clamps the weighted-RMS to the E-CID band floor.
	// Ref: TS 23.273 §6.2.9 (E-CID accuracy ≈ 50–150 m).
	ecidUncertaintyMinM = 50.0

	// ecidUncertaintyMaxM is the maximum horizontal uncertainty for a multi-cell E-CID fix.
	// Feature acceptance criterion: uncertainty ≤ 150 m (vs Cell-ID ≥ 500 m).
	// Ref: TS 23.273 §6.2.9; NRPPaRelay.md §E-CID weighted-centroid position calculation.
	ecidUncertaintyMaxM = 150.0

	// ecidSingleCellUncertaintyM is returned when the gNB reports no
	// nG-RANAccessPointPosition and the LMF falls back to the serving cell's
	// configured/default anchor. Better than Cell-ID (~500 m) since the value is
	// still confirmed via the dedicated NRPPa exchange, but worse than a gNB-
	// supplied AP position estimate (~100 m).
	ecidSingleCellUncertaintyM = 300.0
)

// positioningMethod selects the UE-positioning algorithm for a DetermineLocation request.
type positioningMethod int

const (
	// methodCellID uses the serving cell NRCGI/TAI as the position estimate (~500 m).
	// Ref: TS 23.273 §6.2.8 (Cell-ID method).
	methodCellID positioningMethod = iota

	// methodECID uses NRPPa E-CID RSRP measurements for an improved estimate (~100 m).
	// Ref: TS 23.273 §6.2.9 (E-CID method).
	methodECID

	// methodLPP uses A-GNSS via LPP over N1 for the highest-accuracy estimate
	// (< 50 m CEP50, target). Ref: TS 23.273 §6.2.10 (GNSS/A-GNSS method); LMF-005.
	methodLPP
)

// String implements fmt.Stringer for logging.
func (m positioningMethod) String() string {
	switch m {
	case methodCellID:
		return "CELL_ID"
	case methodECID:
		return "ECID"
	case methodLPP:
		return "GNSS"
	default:
		return "UNKNOWN"
	}
}

// selectMethod implements quality-driven positioning method selection.
//
// Rules (TS 23.273 §6.2.9 / §6.2.10):
//   - hAccuracy ≤ 0 (absent)  → Cell-ID  (operator/subscriber default)
//   - hAccuracy > 200 m        → Cell-ID  (low-accuracy requirement, Cell-ID suffices)
//   - 50 m ≤ hAccuracy ≤ 200 m → E-CID   (LMF-004)
//   - 0 < hAccuracy < 50 m     → GNSS/LPP (LMF-005)
//
// This is a pure function — it does not know whether the LPP or NRPPa client
// is actually wired. The caller (handleDetermineLocation) downgrades one tier
// at a time (GNSS → E-CID → Cell-ID) when the corresponding client is nil.
// Ref: docs/procedures/LPPRelay.md §Quality/method selection.
func selectMethod(hAccuracy float64) positioningMethod {
	if hAccuracy <= 0 || hAccuracy > hAccuracyCellIDFloorM {
		return methodCellID
	}
	if hAccuracy < hAccuracyGnssFloorM {
		return methodLPP
	}
	return methodECID
}

// ---- DLNRPPASender interface --------------------------------------------------

// DLNRPPASender is the interface for sending opaque NRPPa PDUs to the gNB via the
// AMF relay. Implemented by HTTPAMFLocationClient in production; test doubles in tests.
//
// The caller is the LMF E-CID positioning layer; the AMF handles the synchronous
// NGAP exchange (ProcCode 8 DL → ProcCode 50 UL) and returns the UL NRPPa PDU.
//
// Ref: TS 29.518 §5.2.2.6 (Namf_Location dl-nrppa-info); TS 38.413 §8.17.3.
type DLNRPPASender interface {
	// SendDLNRPPa sends nrppaPDU to the gNB via the AMF relay for the given UE context.
	// Returns (ulNRPPaPDU, "", nil) on success.
	// Returns (nil, "CONTEXT_NOT_FOUND", ErrUEContextNotFound) on AMF 404.
	// Returns (nil, cause, ErrLocationFailure) on timeout or other relay failure.
	SendDLNRPPa(ctx context.Context, ueContextID string, nrppaPDU []byte) ([]byte, string, error)
}

// ---- LMF Measurement ID counter ----------------------------------------------

// lmfMeasIDCounter is an atomic counter generating unique LMF-Measurement-IDs per request.
// Ref: TS 38.455 §9 (LMF-Measurement-ID IE).
var lmfMeasIDCounter uint64

// nextLMFMeasID returns the next LMF Measurement ID (wraps at uint16 max).
func nextLMFMeasID() uint16 {
	return uint16(atomic.AddUint64(&lmfMeasIDCounter, 1) & 0xFFFF)
}

// ---- E-CID NRPPa exchange (main entry point) ---------------------------------

// performECIDOrFallback attempts E-CID positioning via two synchronous NRPPa rounds:
//
//  1. Capability round: PositioningInformationRequest → PositioningInformationResponse.
//     If gNB reports E-CID unsupported or the round fails → fallback to Cell-ID.
//  2. Measurement round: E-CIDMeasurementInitiationRequest → E-CIDMeasurementReport.
//     If gNB rejects, times out, or the report has no mapped cells → fallback to Cell-ID.
//
// On success: returns LocationData with POINT centroid (uncertainty ≤ 150 m) and
// positioningDataList=["eCID"].
// On any fallback: calls s.locate() (Cell-ID) and returns its result (no 5xx).
//
// The privacy gate MUST have been checked by the caller before invoking this method.
//
// Ref: TS 38.455 §8 (NRPPa procedures), TS 23.273 §6.2.9, TS 29.572 §5.2.2.2.
func (s *Server) performECIDOrFallback(ctx context.Context, ueContextID, supi string) (*LocationData, string, error) {
	start := time.Now()
	corrID := logging.CorrelationID(ctx)

	log := logging.NewProcedureLogger(ctx, s.logger, "NRPPaPositioning").With(
		"nf", "LMF",
		"procedure", "NRPPaPositioning",
		"interface", "Namf",
		"direction", "OUT",
		"correlation_id", corrID,
		"ue_context_id", ueContextID,
		"supi", supi,
		"spec_ref", "TS 38.455 §8 / TS 23.273 §6.2.9",
	)

	// ---- Round 1: Capability — PositioningInformationRequest -------------------
	// Ref: TS 38.455 §8.2 (Positioning Information Exchange procedure).
	posInfoReqPDU := nrppa.EncodePosInfoReq(nrppa.PositioningInformationRequest{})
	log.Info("E-CID capability request dispatched to AMF",
		"nrppa_msg", "PositioningInformationRequest",
		"spec_ref", "TS 38.455 §8.2 / TS 38.413 §8.17.3 (ProcCode=8 DL)",
	)

	capRspPDU, cause, err := s.nrppaClient.SendDLNRPPa(ctx, ueContextID, posInfoReqPDU)
	if err != nil {
		log.Warn("E-CID capability round failed — falling back to Cell-ID",
			"nrppa_msg", "PositioningInformationRequest",
			"error", err, "cause", cause,
			"result", "FALLBACK_CELLID",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		metrics.LMFECIDTotal.WithLabelValues("FALLBACK_CELLID").Inc()
		return s.locate(ctx, ueContextID, supi)
	}

	capPDU, err := nrppa.Decode(capRspPDU)
	if err != nil {
		log.Warn("E-CID capability response decode error — falling back to Cell-ID",
			"error", err, "result", "FALLBACK_CELLID",
		)
		metrics.LMFECIDTotal.WithLabelValues("FALLBACK_CELLID").Inc()
		return s.locate(ctx, ueContextID, supi)
	}

	// A PositioningInformationFailure or PositioningInformationResponse{ECIDSupported=false}
	// means the gNB cannot provide E-CID measurements → graceful downgrade to Cell-ID.
	// Ref: TS 38.455 §8.2; TS 23.273 §6.2.9 (capability mismatch fallback).
	ecidSupported := capPDU.MsgPosInfoRsp != nil && capPDU.MsgPosInfoRsp.ECIDSupported
	if capPDU.Type == nrppa.MsgPositioningInformationFailure || !ecidSupported {
		capability := "E-CID_NONE"
		log.Info("E-CID capability=NONE from gNB — falling back to Cell-ID",
			"nrppa_msg", "PositioningInformationResponse",
			"capability", capability,
			"result", "FALLBACK_CELLID",
			"spec_ref", "TS 23.273 §6.2.9",
		)
		metrics.LMFECIDTotal.WithLabelValues("FALLBACK_CELLID").Inc()
		return s.locate(ctx, ueContextID, supi)
	}

	log.Info("E-CID capability=SUPPORTED — proceeding to measurement round",
		"nrppa_msg", "PositioningInformationResponse",
		"spec_ref", "TS 38.455 §8.2",
	)

	// ---- Round 2: Measurement — E-CIDMeasurementInitiationRequest --------------
	// Ref: TS 38.455 §8.x (E-CID Measurement Initiation); TS 23.273 §6.2.9.
	measID := nextLMFMeasID()
	ecidInitReqPDU := nrppa.EncodeECIDInitReq(nrppa.ECIDMeasurementInitiationRequestMsg{
		LMFMeasurementID: measID,
		Quantities:       nrppa.QuantityRSRP,
	})
	log.Info("E-CID measurement initiation request dispatched",
		"nrppa_msg", "E-CIDMeasurementInitiationRequest",
		"lmf_measurement_id", measID,
		"spec_ref", "TS 38.455 §8.x / TS 38.413 §8.17.3 (ProcCode=8 DL)",
	)

	measRspPDU, cause2, err2 := s.nrppaClient.SendDLNRPPa(ctx, ueContextID, ecidInitReqPDU)
	if err2 != nil {
		log.Warn("E-CID measurement round failed — falling back to Cell-ID",
			"nrppa_msg", "E-CIDMeasurementInitiationRequest",
			"error", err2, "cause", cause2,
			"result", "FALLBACK_CELLID",
			"spec_ref", "TS 23.273 §6.2.9",
		)
		metrics.LMFECIDTotal.WithLabelValues("FALLBACK_CELLID").Inc()
		return s.locate(ctx, ueContextID, supi)
	}

	measPDU, err := nrppa.Decode(measRspPDU)
	if err != nil {
		log.Warn("E-CID measurement response decode error — falling back to Cell-ID",
			"error", err, "result", "FALLBACK_CELLID",
		)
		metrics.LMFECIDTotal.WithLabelValues("FALLBACK_CELLID").Inc()
		return s.locate(ctx, ueContextID, supi)
	}

	// Expect an E-CIDMeasurementReport. In the simplified synchronous model (LMF-004 MVP)
	// the gNB patch (0041) replies to E-CIDMeasurementInitiationRequest with the report
	// directly. An InitiationFailure or unexpected type triggers fallback.
	// Ref: NRPPaRelay.md §Implementation notes (synchronous relay model).
	if measPDU.MsgECIDReport == nil {
		fallCause := "unexpected NRPPa message type"
		if measPDU.MsgECIDInitFail != nil {
			fallCause = fmt.Sprintf("E-CIDMeasurementInitiationFailure cause=%d", measPDU.MsgECIDInitFail.Cause)
		}
		log.Warn("E-CID measurement report not received — falling back to Cell-ID",
			"nrppa_msg_type", fmt.Sprintf("0x%02x", measPDU.Type),
			"cause", fallCause,
			"result", "FALLBACK_CELLID",
		)
		metrics.LMFECIDTotal.WithLabelValues("FALLBACK_CELLID").Inc()
		return s.locate(ctx, ueContextID, supi)
	}

	report := measPDU.MsgECIDReport
	log.Info("E-CID measurement report received from gNB",
		"nrppa_msg", "E-CIDMeasurementReport",
		"lmf_measurement_id", report.LMFMeasurementID,
		"ran_measurement_id", report.RANMeasurementID,
		"ap_position_present", report.APPosition != nil,
		"spec_ref", "TS 38.455 §8.x / TS 38.413 §8.17.3 (ProcCode=50 UL)",
	)

	// ---- Position calculation ---------------------------------------------------
	// Ref: TS 23.273 §6.2.9; NRPPaRelay.md §E-CID position calculation.
	centLat, centLon, uncertainty, ok := s.computeECIDPosition(report)
	if !ok {
		log.Warn("E-CID: serving cell not resolvable — falling back to Cell-ID",
			"result", "FALLBACK_CELLID",
			"spec_ref", "TS 23.273 §6.2.9",
		)
		metrics.LMFECIDTotal.WithLabelValues("FALLBACK_CELLID").Inc()
		return s.locate(ctx, ueContextID, supi)
	}

	// Fetch TAI from AMF ProvideLocationInfo (the NRPPa report carries no TAC field
	// in the shared/nrppa codec). The E-CID centroid provides the position; the AMF
	// provides metadata (TAI, serving nrCellId from the NGAP perspective).
	// Ref: TS 29.572 §6.1.6.2.2 (tai field); NRPPaRelay.md §Information Elements.
	amfLoc, _, amfErr := s.amfClient.ProvideLocationInfo(ctx, ueContextID)
	servingCellStr := nrcgiToHex(report.ServingNRCGI)
	var tai *TaiLoc
	if amfErr == nil && amfLoc != nil {
		tai = amfLoc.Tai
		if servingCellStr == "" && amfLoc.NRCellId != "" {
			servingCellStr = amfLoc.NRCellId
		}
	} else {
		log.Warn("E-CID: ProvideLocationInfo for TAI failed (continuing without TAI)",
			"error", amfErr,
			"spec_ref", "TS 29.518 §5.2.2.6",
		)
	}

	log.Info("E-CID position calculated",
		"lat", centLat,
		"lon", centLon,
		"uncertainty_m", uncertainty,
		"nr_cell_id", servingCellStr,
		"ap_position_present", report.APPosition != nil,
		"method", "ECID",
		"result", "OK",
		"duration_ms", time.Since(start).Milliseconds(),
		"spec_ref", "TS 23.273 §6.2.9",
	)
	metrics.LMFECIDTotal.WithLabelValues("OK").Inc()

	return &LocationData{
		LocationEstimate: &GeographicArea{
			Shape:       "POINT",
			Point:       &LatLon{Lat: centLat, Lon: centLon},
			Uncertainty: uncertainty,
		},
		NRCellId:            servingCellStr,
		Tai:                 tai,
		PositioningDataList: []string{"eCID"},
	}, "", nil
}

// ---- Position calculation ------------------------------------------------------

// computeECIDPosition derives the WGS84 position estimate from an E-CID
// measurement report, returning (lat, lon, uncertainty_m, true) whenever the
// serving cell is resolvable.
//
// Returns (0, 0, 0, false) only when the serving cell has no mapped or default
// coordinate at all — the caller should fall back to Cell-ID positioning.
//
// Algorithm (TS 23.273 §6.2.9; TS 38.455 §9 NG-RANAccessPointPosition):
//
//  1. If the gNB reported nG-RANAccessPointPosition (a real, spec-defined WGS84
//     estimate — TS 23.032 Ellipsoid Point with Uncertainty Ellipse shape), use it
//     directly: lat/lon from the IE, uncertainty = max(semi-major, semi-minor)
//     clamped to the E-CID accuracy band [50, 150] m.
//  2. Otherwise, fall back to the serving NRCGI's configured/default anchor with
//     ecidSingleCellUncertaintyM (300 m) — better than nothing, but the gNB
//     supplied no accuracy-improving data beyond Cell-ID.
//
// TS 38.455's E-CID-MeasurementResult has no NR-neighbour-cell RSRP list (its
// optional measuredResults field is E-UTRA-only, a legacy LPPa/inter-RAT
// assistance IE) — so, unlike an earlier revision of this file, there is no
// multi-cell RSRP-weighted centroid; NG-RANAccessPointPosition is the spec-legal
// mechanism for a gNB to report a tighter-than-Cell-ID estimate.
func (s *Server) computeECIDPosition(report *nrppa.ECIDMeasurementReportMsg) (lat, lon, uncertainty float64, ok bool) {
	if report.APPosition != nil {
		u := report.APPosition.UncertaintySemiMajorM
		if report.APPosition.UncertaintySemiMinorM > u {
			u = report.APPosition.UncertaintySemiMinorM
		}
		if u < ecidUncertaintyMinM {
			u = ecidUncertaintyMinM
		}
		if u > ecidUncertaintyMaxM {
			u = ecidUncertaintyMaxM
		}
		return report.APPosition.Lat, report.APPosition.Lon, u, true
	}

	servingHex := nrcgiToHex(report.ServingNRCGI)
	coord, found := s.cfg.CellCoordinates[servingHex]
	if !found {
		coord = s.cfg.DefaultCoord
	}
	return coord.Lat, coord.Lon, ecidSingleCellUncertaintyM, true
}

// nrcgiToHex converts an NRCGI's 5-byte CellID to the canonical 9-character
// lowercase hex string used as the nrCellId throughout this NF and in the
// cell_coordinates config map.
//
// The 36-bit NR Cell Identity is packed in the most significant 36 bits of the
// 5-byte field; the low 4 bits of byte 4 are always zero (TS 38.413 §9.3.1.x).
// Decoding: shift the 40-bit value right by 4 → 36-bit identity → 9 hex chars.
//
// Example: CellID [0x00,0x00,0x00,0x01,0x00] → val=256 >> 4 = 16 → "000000010".
// Ref: TS 38.413 §9.3.1.x; shared/nrppa NRCGI wire format.
func nrcgiToHex(n nrppa.NRCGI) string {
	val := uint64(n.CellID[0])<<32 |
		uint64(n.CellID[1])<<24 |
		uint64(n.CellID[2])<<16 |
		uint64(n.CellID[3])<<8 |
		uint64(n.CellID[4])
	val >>= 4 // remove 4 zero-padding bits → 36-bit cell identity
	return fmt.Sprintf("%09x", val)
}

// ---- UL NRPPa receive stub (forward-compatibility) ---------------------------

// handleULNRPPa is a stub handler for the LMF's ul-nrppa-info receive endpoint.
//
// In the synchronous AMF relay model (LMF-004 PASS 1) the LMF receives UL NRPPa
// PDUs as the HTTP 200 response body from dl-nrppa-info — not via this endpoint.
// This stub is registered for forward-compatibility with the async model (LMF-005+)
// and to satisfy the endpoint contract declared in NRPPaRelay.md §Endpoints.
//
// Ref: NRPPaRelay.md §Endpoints; TS 29.518 §5.2.2.6.
func (s *Server) handleULNRPPa(w http.ResponseWriter, r *http.Request) {
	// In the synchronous relay model, this endpoint is not exercised by DetermineLocation.
	// Future: async relay (LMF-005+) would decode the body and dispatch to a pending
	// transaction channel keyed by Routing-ID / LMF-Measurement-ID.
	w.WriteHeader(http.StatusAccepted)
}
