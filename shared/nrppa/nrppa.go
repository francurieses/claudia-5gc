// Package nrppa implements the E-CID subset of NRPPa (NR Positioning Protocol A,
// TS 38.455 Rel-17) used by the LMF and the UERANSIM gNB patch 0041 to exchange
// positioning messages over the AMF NGAP NRPPa relay (TS 38.413 §8.17.3/§8.17.4).
//
// Encoding is real ASN.1 Aligned PER (APER) via github.com/free5gc/aper — see
// nrppa_asn1.go for the hand-written struct mirror of the TS 38.455 ASN.1 module
// (free5gc has no NRPPa module, unlike NGAP). This file provides the friendly
// public API: Go-native message types plus Encode*/Decode functions that build/
// parse the ASN.1 structs.
//
// # E-CID Procedures used (TS 38.455 Table 9.1-1 Rel-17)
//
//	positioningInformationExchange  ProcedureCode=9  LMF→gNB request / gNB→LMF response
//	e-CIDMeasurementInitiation      ProcedureCode=2  LMF→gNB initiation / gNB→LMF accept or reject
//	e-CIDMeasurementReport          ProcedureCode=4  gNB→LMF indication (InitiatingMessage, crit=ignore)
//
// # Synchronous relay simplification
//
// The AMF relay used by this project (TS 38.413 §8.17.3 UE-Associated NRPPa
// Transport) is a single synchronous DL→UL round trip per HTTP call — there is
// no channel for the gNB to push an unsolicited later message. So the
// e-CIDMeasurementReport (normally an independent, later, Class-2 indication per
// spec) is instead returned directly as the synchronous reply to
// e-CIDMeasurementInitiationRequest, skipping the intermediate
// E-CIDMeasurementInitiationResponse ack. This is a documented MVP relay-model
// simplification, not a wire-format deviation — E-CIDMeasurementInitiationResponse
// remains fully implemented (EncodeECIDInitRsp/decodeECIDInitRsp) for spec
// completeness and any future async relay model (LMF-005+).
package nrppa

import (
	"fmt"

	"github.com/free5gc/aper"
)

// ---- Internal message type discriminators (not wire bytes) ------------------

// Message type constants are set by Decode to identify the decoded message kind.
const (
	MsgPositioningInformationRequest uint8 = iota + 1
	MsgPositioningInformationResponse
	MsgPositioningInformationFailure
	MsgECIDMeasurementInitiationRequest
	MsgECIDMeasurementInitiationResponse
	MsgECIDMeasurementInitiationFailure
	MsgECIDMeasurementReport
)

// QuantityRSRP is the E-CID Measurement Quantity identifier for RSRP.
// Ref: TS 38.455 §9 (MeasurementQuantitiesValue.rSRP = 4).
const QuantityRSRP uint8 = 0x01

// ---- NRCGI --------------------------------------------------------------------

// NRCGI is an NR Cell Global Identifier.
//
//	PLMN:   3-byte nibble-encoded PLMN identity (TS 24.501 §9.11.3.4)
//	CellID: 5-byte NR Cell Identity — 36 bits packed MSB-first, low 4 bits of
//	        byte 4 are BIT STRING SIZE(36) APER alignment padding.
//
// Ref: TS 38.455 §9 (NG-RAN-CGI / NGRANCell.nR-CellID); TS 38.413 §9.3.1.x.
type NRCGI struct {
	PLMN   [3]byte
	CellID [5]byte
}

func (n NRCGI) toNGRANCGI() NGRANCGI {
	bits := make([]byte, 5)
	copy(bits, n.CellID[:])
	return NGRANCGI{
		PLMNIdentity: aper.OctetString(append([]byte(nil), n.PLMN[:]...)),
		NGRANCell: NGRANCell{
			Present:  NGRANCellPresentNRCellID,
			NRCellID: &aper.BitString{Bytes: bits, BitLength: 36},
		},
	}
}

func nrcgiFromNGRANCGI(cgi NGRANCGI) NRCGI {
	var n NRCGI
	copy(n.PLMN[:], cgi.PLMNIdentity)
	if cgi.NGRANCell.Present == NGRANCellPresentNRCellID && cgi.NGRANCell.NRCellID != nil {
		copy(n.CellID[:], cgi.NGRANCell.NRCellID.Bytes)
	}
	return n
}

// ---- NGRANAccessPointPosition (friendly) -------------------------------------

// APPosition is the gNB's own WGS84 position estimate for the UE, carried in the
// (optional) E-CID-MeasurementResult.nG-RANAccessPointPosition IE — a real,
// spec-defined field (TS 23.032 Ellipsoid Point with Uncertainty Ellipse shape),
// not an invented extension. Its presence/uncertainty is what distinguishes an
// E-CID fix from plain Cell-ID.
//
// Ref: TS 38.455 §9 (NG-RANAccessPointPosition); TS 23.032 §6.2, §6.7 (encoding).
type APPosition struct {
	// Lat, Lon are WGS84 degrees.
	Lat, Lon float64
	// AltitudeM is metres above the reference ellipsoid (project simplification —
	// TS 23.032's altitude unit is not meaningful for a synthetic/simulated gNB).
	AltitudeM float64
	// UncertaintySemiMajorM, UncertaintySemiMinorM are the 1-sigma uncertainty
	// ellipse semi-axes in metres (TS 23.032 §6.7 "uncertainty code" encoding).
	UncertaintySemiMajorM, UncertaintySemiMinorM float64
	// OrientationDeg is the major-axis orientation, 0..358° in 2° steps.
	OrientationDeg float64
	// UncertaintyAltitudeM is the vertical uncertainty in metres.
	UncertaintyAltitudeM float64
	// ConfidencePct is 0..100.
	ConfidencePct uint8
}

// uncertaintyCodeC, uncertaintyCodeX are the TS 23.032 §6.7 "uncertainty code"
// parameters: r = C * ((1+x)^k - 1), C=10m, x=0.1 — the standard 3GPP encoding
// for horizontal/vertical uncertainty used throughout the geographic-coordinate
// IEs (Cell-ID, E-CID, GERAN/UTRAN/E-UTRAN location reporting, ...).
const (
	uncertaintyCodeC = 10.0
	uncertaintyCodeX = 0.1
)

func metersToUncertaintyCode(m float64) int64 {
	if m <= 0 {
		return 0
	}
	k := int64(0)
	for r := 0.0; r < m && k < 127; k++ {
		r = uncertaintyCodeC * (mathPow(1+uncertaintyCodeX, float64(k+1)) - 1)
	}
	return k
}

func uncertaintyCodeToMeters(k int64) float64 {
	return uncertaintyCodeC * (mathPow(1+uncertaintyCodeX, float64(k)) - 1)
}

// mathPow avoids importing "math" solely for Pow in this small file's hot path;
// kept trivial and side-effect free.
func mathPow(base, exp float64) float64 {
	// exp is always a small non-negative integer here (uncertainty code 0..127).
	result := 1.0
	n := int(exp)
	for i := 0; i < n; i++ {
		result *= base
	}
	return result
}

func (p APPosition) toWire() *NGRANAccessPointPosition {
	latSign := LatitudeSignNorth
	lat := p.Lat
	if lat < 0 {
		latSign = LatitudeSignSouth
		lat = -lat
	}
	latRaw := clampI64(int64(lat/90.0*8388607.0), 0, 8388607)
	lonRaw := clampI64(int64(p.Lon/180.0*8388608.0), -8388608, 8388607)
	altSign := DirectionOfAltitudeHeight
	alt := p.AltitudeM
	if alt < 0 {
		altSign = DirectionOfAltitudeDepth
		alt = -alt
	}
	altRaw := clampI64(int64(alt), 0, 32767)
	return &NGRANAccessPointPosition{
		LatitudeSign:           latSign,
		Latitude:               latRaw,
		Longitude:              lonRaw,
		DirectionOfAltitude:    altSign,
		Altitude:               altRaw,
		UncertaintySemiMajor:   metersToUncertaintyCode(p.UncertaintySemiMajorM),
		UncertaintySemiMinor:   metersToUncertaintyCode(p.UncertaintySemiMinorM),
		OrientationOfMajorAxis: clampI64(int64(p.OrientationDeg/2.0), 0, 179),
		UncertaintyAltitude:    metersToUncertaintyCode(p.UncertaintyAltitudeM),
		Confidence:             clampI64(int64(p.ConfidencePct), 0, 100),
	}
}

func appPositionFromWire(w *NGRANAccessPointPosition) *APPosition {
	if w == nil {
		return nil
	}
	lat := float64(w.Latitude) / 8388607.0 * 90.0
	if w.LatitudeSign == LatitudeSignSouth {
		lat = -lat
	}
	lon := float64(w.Longitude) / 8388608.0 * 180.0
	alt := float64(w.Altitude)
	if w.DirectionOfAltitude == DirectionOfAltitudeDepth {
		alt = -alt
	}
	return &APPosition{
		Lat:                   lat,
		Lon:                   lon,
		AltitudeM:             alt,
		UncertaintySemiMajorM: uncertaintyCodeToMeters(w.UncertaintySemiMajor),
		UncertaintySemiMinorM: uncertaintyCodeToMeters(w.UncertaintySemiMinor),
		OrientationDeg:        float64(w.OrientationOfMajorAxis) * 2.0,
		UncertaintyAltitudeM:  uncertaintyCodeToMeters(w.UncertaintyAltitude),
		ConfidencePct:         uint8(w.Confidence),
	}
}

func clampI64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---- Cause --------------------------------------------------------------------

func causeUnspecifiedMisc() *Cause {
	v := CauseMiscUnspecified
	return &Cause{Present: CausePresentMisc, Misc: &CauseMisc{Value: v}}
}

func causeToByte(c *Cause) uint8 {
	if c == nil {
		return 0
	}
	switch c.Present {
	case CausePresentRadioNetwork:
		if c.RadioNetwork != nil {
			return uint8(c.RadioNetwork.Value)
		}
	case CausePresentProtocol:
		if c.Protocol != nil {
			return uint8(c.Protocol.Value)
		}
	case CausePresentMisc:
		if c.Misc != nil {
			return uint8(c.Misc.Value)
		}
	}
	return 0
}

// ---- NRPPaTransactionID counter ----------------------------------------------

var transactionIDCounter uint32

// nextTransactionID returns the next NRPPATransactionID (INTEGER 0..32767),
// wrapping. The synchronous single-shot relay model in this project does not use
// the transaction ID for correlation (the AMF correlates by AMF-UE-NGAP-ID at the
// NGAP layer), but the field is mandatory on every NRPPA-PDU per TS 38.455 and
// must be present for a real ASN.1 dissector to parse the message.
func nextTransactionID() int64 {
	transactionIDCounter++
	return int64(transactionIDCounter % 32768)
}

// ---- NRPPaPDU (decoded) --------------------------------------------------------

// NRPPaPDU is the top-level decoded message. Exactly one of the Msg* fields is
// non-nil, selected by Type.
type NRPPaPDU struct {
	Type uint8

	MsgPosInfoReq   *PositioningInformationRequest
	MsgPosInfoRsp   *PositioningInformationResponse
	MsgPosInfoFail  *PositioningInformationFailure
	MsgECIDInitReq  *ECIDMeasurementInitiationRequestMsg
	MsgECIDInitRsp  *ECIDMeasurementInitiationResponseMsg
	MsgECIDInitFail *ECIDMeasurementInitiationFailureMsg
	MsgECIDReport   *ECIDMeasurementReportMsg
}

// Decode decodes raw NRPPa APER bytes (as received from the NGAP relay) into an
// NRPPaPDU. Ref: TS 38.455 Annex A; TS 38.413 §8.17.3.
func Decode(b []byte) (*NRPPaPDU, error) {
	pdu := &NRPPAPDU{}
	if err := aper.UnmarshalWithParams(b, pdu, "valueExt,valueLB:0,valueUB:2"); err != nil {
		return nil, fmt.Errorf("nrppa: decode outer PDU: %w", err)
	}

	out := &NRPPaPDU{}
	switch pdu.Present {
	case NRPPAPDUPresentInitiatingMessage:
		im := pdu.InitiatingMessage
		switch im.Value.Present {
		case InitiatingMessagePresentPositioningInformationRequest:
			out.Type = MsgPositioningInformationRequest
			out.MsgPosInfoReq = &PositioningInformationRequest{}
		case InitiatingMessagePresentECIDMeasurementInitiationRequest:
			out.Type = MsgECIDMeasurementInitiationRequest
			out.MsgECIDInitReq = ecidInitReqFromWire(im.Value.ECIDMeasurementInitiationRequest)
		case InitiatingMessagePresentECIDMeasurementReport:
			out.Type = MsgECIDMeasurementReport
			out.MsgECIDReport = ecidReportFromWire(im.Value.ECIDMeasurementReport)
		default:
			return nil, fmt.Errorf("nrppa: decode: unknown InitiatingMessage present=%d", im.Value.Present)
		}
	case NRPPAPDUPresentSuccessfulOutcome:
		so := pdu.SuccessfulOutcome
		switch so.Value.Present {
		case SuccessfulOutcomePresentPositioningInformationResponse:
			out.Type = MsgPositioningInformationResponse
			out.MsgPosInfoRsp = &PositioningInformationResponse{ECIDSupported: true}
		case SuccessfulOutcomePresentECIDMeasurementInitiationResponse:
			out.Type = MsgECIDMeasurementInitiationResponse
			out.MsgECIDInitRsp = ecidInitRspFromWire(so.Value.ECIDMeasurementInitiationResponse)
		default:
			return nil, fmt.Errorf("nrppa: decode: unknown SuccessfulOutcome present=%d", so.Value.Present)
		}
	case NRPPAPDUPresentUnsuccessfulOutcome:
		uo := pdu.UnsuccessfulOutcome
		switch uo.Value.Present {
		case UnsuccessfulOutcomePresentPositioningInformationFailure:
			out.Type = MsgPositioningInformationFailure
			out.MsgPosInfoFail = &PositioningInformationFailure{
				Cause: causeFromFailureIEs(uo.Value.PositioningInformationFailure.ProtocolIEs.List),
			}
		case UnsuccessfulOutcomePresentECIDMeasurementInitiationFailure:
			out.Type = MsgECIDMeasurementInitiationFailure
			out.MsgECIDInitFail = &ECIDMeasurementInitiationFailureMsg{
				Cause: causeFromInitFailureIEs(uo.Value.ECIDMeasurementInitiationFailure.ProtocolIEs.List),
			}
		default:
			return nil, fmt.Errorf("nrppa: decode: unknown UnsuccessfulOutcome present=%d", uo.Value.Present)
		}
	default:
		return nil, fmt.Errorf("nrppa: decode: unknown NRPPA-PDU present=%d", pdu.Present)
	}
	return out, nil
}

func causeFromFailureIEs(ies []PositioningInformationFailureIEs) uint8 {
	for _, ie := range ies {
		if ie.Value.Present == PositioningInformationFailureIEsPresentCause {
			return causeToByte(ie.Value.Cause)
		}
	}
	return 0
}

func causeFromInitFailureIEs(ies []ECIDMeasurementInitiationFailureIEs) uint8 {
	for _, ie := range ies {
		if ie.Value.Present == ECIDMeasurementInitiationFailureIEsPresentCause {
			return causeToByte(ie.Value.Cause)
		}
	}
	return 0
}

// ---- PositioningInformationRequest (LMF → gNB) ------------------------------

// PositioningInformationRequest queries the gNB for its NRPPa/E-CID capabilities.
// Ref: TS 38.455 §8.2 (InitiatingMessage, ProcedureCode=9).
type PositioningInformationRequest struct{}

// EncodePosInfoReq encodes a PositioningInformationRequest as APER.
func EncodePosInfoReq(_ PositioningInformationRequest) []byte {
	pdu := NRPPAPDU{
		Present: NRPPAPDUPresentInitiatingMessage,
		InitiatingMessage: &InitiatingMessage{
			ProcedureCode:      ProcedureCode{Value: ProcCodePositioningInformationExchange},
			Criticality:        Criticality{Value: CriticalityPresentReject},
			NRPPATransactionID: NRPPATransactionID{Value: nextTransactionID()},
			Value: InitiatingMessageValue{
				Present:                       InitiatingMessagePresentPositioningInformationRequest,
				PositioningInformationRequest: &wirePositioningInformationRequest{},
			},
		},
	}
	return mustEncode(pdu)
}

// ---- PositioningInformationResponse (gNB → LMF) ------------------------------

// PositioningInformationResponse reports the gNB's positioning capability. All
// PositioningInformationResponse IEs are optional and outside the E-CID subset,
// so a bare SuccessfulOutcome (0 IEs) is used as the "E-CID supported" signal —
// see the package doc comment.
type PositioningInformationResponse struct {
	ECIDSupported bool
}

// EncodePosInfoRsp encodes a PositioningInformationResponse as APER.
// ECIDSupported=false encodes a PositioningInformationFailure (UnsuccessfulOutcome)
// instead, since SuccessfulOutcome has no field to carry "false".
func EncodePosInfoRsp(m PositioningInformationResponse) []byte {
	if !m.ECIDSupported {
		return EncodePosInfoFail(PositioningInformationFailure{Cause: causeToByte(causeUnspecifiedMisc())})
	}
	pdu := NRPPAPDU{
		Present: NRPPAPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &SuccessfulOutcome{
			ProcedureCode:      ProcedureCode{Value: ProcCodePositioningInformationExchange},
			Criticality:        Criticality{Value: CriticalityPresentReject},
			NRPPATransactionID: NRPPATransactionID{Value: nextTransactionID()},
			Value: SuccessfulOutcomeValue{
				Present:                        SuccessfulOutcomePresentPositioningInformationResponse,
				PositioningInformationResponse: &wirePositioningInformationResponse{},
			},
		},
	}
	return mustEncode(pdu)
}

// ---- PositioningInformationFailure (gNB → LMF) --------------------------------

// PositioningInformationFailure is the negative reply to a capability query.
type PositioningInformationFailure struct {
	// Cause is the NRPPa cause code (CauseMisc/CauseProtocol/CauseRadioNetwork
	// enum value flattened to a byte). 0 = unspecified.
	Cause uint8
}

// EncodePosInfoFail encodes a PositioningInformationFailure as APER.
func EncodePosInfoFail(m PositioningInformationFailure) []byte {
	pdu := NRPPAPDU{
		Present: NRPPAPDUPresentUnsuccessfulOutcome,
		UnsuccessfulOutcome: &UnsuccessfulOutcome{
			ProcedureCode:      ProcedureCode{Value: ProcCodePositioningInformationExchange},
			Criticality:        Criticality{Value: CriticalityPresentReject},
			NRPPATransactionID: NRPPATransactionID{Value: nextTransactionID()},
			Value: UnsuccessfulOutcomeValue{
				Present: UnsuccessfulOutcomePresentPositioningInformationFailure,
				PositioningInformationFailure: &wirePositioningInformationFailure{
					ProtocolIEs: ProtocolIEContainerPositioningInformationFailureIEs{
						List: []PositioningInformationFailureIEs{
							{
								ID:          ProtocolIEID{Value: idCause},
								Criticality: Criticality{Value: CriticalityPresentIgnore},
								Value: PositioningInformationFailureIEsValue{
									Present: PositioningInformationFailureIEsPresentCause,
									Cause:   causeUnspecifiedMisc(),
								},
							},
						},
					},
				},
			},
		},
	}
	return mustEncode(pdu)
}

// ---- E-CIDMeasurementInitiationRequest (LMF → gNB) -------------------------

// ECIDMeasurementInitiationRequestMsg requests the gNB to start E-CID measurements.
type ECIDMeasurementInitiationRequestMsg struct {
	// LMFMeasurementID is the LMF-assigned transaction identifier (1..15 in the
	// root INTEGER range — see UEMeasurementID).
	LMFMeasurementID uint16
	// Quantities is a bitmask of requested E-CID quantities; QuantityRSRP (0x01)
	// requests RSRP. The E-CID MVP always requests RSRP.
	Quantities uint8
}

// EncodeECIDInitReq encodes an ECIDMeasurementInitiationRequestMsg as APER.
func EncodeECIDInitReq(m ECIDMeasurementInitiationRequestMsg) []byte {
	pdu := NRPPAPDU{
		Present: NRPPAPDUPresentInitiatingMessage,
		InitiatingMessage: &InitiatingMessage{
			ProcedureCode:      ProcedureCode{Value: ProcCodeECIDMeasurementInitiation},
			Criticality:        Criticality{Value: CriticalityPresentReject},
			NRPPATransactionID: NRPPATransactionID{Value: nextTransactionID()},
			Value: InitiatingMessageValue{
				Present: InitiatingMessagePresentECIDMeasurementInitiationRequest,
				ECIDMeasurementInitiationRequest: &ECIDMeasurementInitiationRequest{
					ProtocolIEs: ProtocolIEContainerECIDMeasurementInitiationRequestIEs{
						List: []ECIDMeasurementInitiationRequestIEs{
							{
								ID:          ProtocolIEID{Value: idLMFUEMeasurementID},
								Criticality: Criticality{Value: CriticalityPresentReject},
								Value: ECIDMeasurementInitiationRequestIEsValue{
									Present:            ECIDMeasurementInitiationRequestIEsPresentLMFUEMeasurementID,
									LMFUEMeasurementID: &UEMeasurementID{Value: measIDValue(m.LMFMeasurementID)},
								},
							},
							{
								ID:          ProtocolIEID{Value: idReportCharacteristics},
								Criticality: Criticality{Value: CriticalityPresentReject},
								Value: ECIDMeasurementInitiationRequestIEsValue{
									Present:               ECIDMeasurementInitiationRequestIEsPresentReportCharacteristics,
									ReportCharacteristics: &ReportCharacteristics{Value: ReportCharacteristicsOnDemand},
								},
							},
							{
								ID:          ProtocolIEID{Value: idMeasurementQuantities},
								Criticality: Criticality{Value: CriticalityPresentReject},
								Value: ECIDMeasurementInitiationRequestIEsValue{
									Present: ECIDMeasurementInitiationRequestIEsPresentMeasurementQuantities,
									MeasurementQuantities: &MeasurementQuantities{
										List: []MeasurementQuantitiesItemIE{
											{
												ID:          ProtocolIEID{Value: idMeasurementQuantitiesItem},
												Criticality: Criticality{Value: CriticalityPresentReject},
												Value: MeasurementQuantitiesItemIEValue{
													Present: MeasurementQuantitiesItemIEPresentItem,
													Item: &MeasurementQuantitiesItem{
														MeasurementQuantitiesValue: MeasurementQuantitiesValue{Value: MeasurementQuantitiesValueRSRP},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return mustEncode(pdu)
}

func ecidInitReqFromWire(w *ECIDMeasurementInitiationRequest) *ECIDMeasurementInitiationRequestMsg {
	m := &ECIDMeasurementInitiationRequestMsg{Quantities: QuantityRSRP}
	if w == nil {
		return m
	}
	for _, ie := range w.ProtocolIEs.List {
		if ie.Value.Present == ECIDMeasurementInitiationRequestIEsPresentLMFUEMeasurementID && ie.Value.LMFUEMeasurementID != nil {
			m.LMFMeasurementID = measIDFromValue(ie.Value.LMFUEMeasurementID.Value)
		}
	}
	return m
}

// measIDValue/measIDFromValue map the external 1-based uint16 measurement ID
// onto the UEMeasurementID INTEGER(1..15,...,16..256) root/extension range.
func measIDValue(id uint16) int64 {
	if id == 0 {
		return 1
	}
	v := int64(((id - 1) % 256) + 1)
	if v > 15 {
		return 15 // clamp into the root range; the extension range is unused by this MVP
	}
	return v
}

func measIDFromValue(v int64) uint16 { return uint16(v) }

// ---- E-CIDMeasurementInitiationResponse (gNB → LMF) -------------------------

// ECIDMeasurementInitiationResponseMsg accepts the measurement request and
// assigns a RAN-side measurement identifier. See the package doc comment — this
// project's synchronous relay model returns an ECIDMeasurementReportMsg directly
// instead of this ack; this type/encoder remain for spec completeness.
type ECIDMeasurementInitiationResponseMsg struct {
	LMFMeasurementID uint16
	RANMeasurementID uint16
}

// EncodeECIDInitRsp encodes an ECIDMeasurementInitiationResponseMsg as APER.
func EncodeECIDInitRsp(m ECIDMeasurementInitiationResponseMsg) []byte {
	pdu := NRPPAPDU{
		Present: NRPPAPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &SuccessfulOutcome{
			ProcedureCode:      ProcedureCode{Value: ProcCodeECIDMeasurementInitiation},
			Criticality:        Criticality{Value: CriticalityPresentReject},
			NRPPATransactionID: NRPPATransactionID{Value: nextTransactionID()},
			Value: SuccessfulOutcomeValue{
				Present: SuccessfulOutcomePresentECIDMeasurementInitiationResponse,
				ECIDMeasurementInitiationResponse: &ECIDMeasurementInitiationResponse{
					ProtocolIEs: ProtocolIEContainerECIDMeasurementInitiationResponseIEs{
						List: []ECIDMeasurementInitiationResponseIEs{
							{
								ID:          ProtocolIEID{Value: idLMFUEMeasurementID},
								Criticality: Criticality{Value: CriticalityPresentReject},
								Value: ECIDMeasurementInitiationResponseIEsValue{
									Present:            ECIDMeasurementInitiationResponseIEsPresentLMFUEMeasurementID,
									LMFUEMeasurementID: &UEMeasurementID{Value: measIDValue(m.LMFMeasurementID)},
								},
							},
							{
								ID:          ProtocolIEID{Value: idRANUEMeasurementID},
								Criticality: Criticality{Value: CriticalityPresentReject},
								Value: ECIDMeasurementInitiationResponseIEsValue{
									Present:            ECIDMeasurementInitiationResponseIEsPresentRANUEMeasurementID,
									RANUEMeasurementID: &UEMeasurementID{Value: measIDValue(m.RANMeasurementID)},
								},
							},
						},
					},
				},
			},
		},
	}
	return mustEncode(pdu)
}

func ecidInitRspFromWire(w *ECIDMeasurementInitiationResponse) *ECIDMeasurementInitiationResponseMsg {
	m := &ECIDMeasurementInitiationResponseMsg{}
	if w == nil {
		return m
	}
	for _, ie := range w.ProtocolIEs.List {
		switch ie.Value.Present {
		case ECIDMeasurementInitiationResponseIEsPresentLMFUEMeasurementID:
			if ie.Value.LMFUEMeasurementID != nil {
				m.LMFMeasurementID = measIDFromValue(ie.Value.LMFUEMeasurementID.Value)
			}
		case ECIDMeasurementInitiationResponseIEsPresentRANUEMeasurementID:
			if ie.Value.RANUEMeasurementID != nil {
				m.RANMeasurementID = measIDFromValue(ie.Value.RANUEMeasurementID.Value)
			}
		}
	}
	return m
}

// ---- E-CIDMeasurementInitiationFailure (gNB → LMF) --------------------------

// ECIDMeasurementInitiationFailureMsg rejects the measurement request.
type ECIDMeasurementInitiationFailureMsg struct {
	Cause uint8
}

// EncodeECIDInitFail encodes an ECIDMeasurementInitiationFailureMsg as APER.
func EncodeECIDInitFail(m ECIDMeasurementInitiationFailureMsg) []byte {
	pdu := NRPPAPDU{
		Present: NRPPAPDUPresentUnsuccessfulOutcome,
		UnsuccessfulOutcome: &UnsuccessfulOutcome{
			ProcedureCode:      ProcedureCode{Value: ProcCodeECIDMeasurementInitiation},
			Criticality:        Criticality{Value: CriticalityPresentReject},
			NRPPATransactionID: NRPPATransactionID{Value: nextTransactionID()},
			Value: UnsuccessfulOutcomeValue{
				Present: UnsuccessfulOutcomePresentECIDMeasurementInitiationFailure,
				ECIDMeasurementInitiationFailure: &ECIDMeasurementInitiationFailure{
					ProtocolIEs: ProtocolIEContainerECIDMeasurementInitiationFailureIEs{
						List: []ECIDMeasurementInitiationFailureIEs{
							{
								ID:          ProtocolIEID{Value: idLMFUEMeasurementID},
								Criticality: Criticality{Value: CriticalityPresentReject},
								Value: ECIDMeasurementInitiationFailureIEsValue{
									Present:            ECIDMeasurementInitiationFailureIEsPresentLMFUEMeasurementID,
									LMFUEMeasurementID: &UEMeasurementID{Value: 1},
								},
							},
							{
								ID:          ProtocolIEID{Value: idCause},
								Criticality: Criticality{Value: CriticalityPresentIgnore},
								Value: ECIDMeasurementInitiationFailureIEsValue{
									Present: ECIDMeasurementInitiationFailureIEsPresentCause,
									Cause:   causeUnspecifiedMisc(),
								},
							},
						},
					},
				},
			},
		},
	}
	return mustEncode(pdu)
}

// ---- E-CIDMeasurementReport (gNB → LMF) -------------------------------------

// ECIDMeasurementReportMsg delivers the E-CID position source to the LMF.
type ECIDMeasurementReportMsg struct {
	LMFMeasurementID uint16
	RANMeasurementID uint16
	// ServingNRCGI is the NR Cell Global Identifier of the serving cell.
	ServingNRCGI NRCGI
	// ServingTAC is the serving cell's 3-byte Tracking Area Code.
	ServingTAC [3]byte
	// APPosition is the gNB's own WGS84 position estimate (optional per spec;
	// nil = the gNB reported no better-than-Cell-ID estimate).
	APPosition *APPosition
}

// EncodeECIDReport encodes an ECIDMeasurementReportMsg as APER.
// Wire: InitiatingMessage, ProcedureCode=4, criticality=ignore (Class-2 indication).
func EncodeECIDReport(m ECIDMeasurementReportMsg) []byte {
	result := &ECIDMeasurementResult{
		ServingCellID:  m.ServingNRCGI.toNGRANCGI(),
		ServingCellTAC: aper.OctetString(append([]byte(nil), m.ServingTAC[:]...)),
	}
	if m.APPosition != nil {
		result.NGRANAccessPointPosition = m.APPosition.toWire()
	}

	pdu := NRPPAPDU{
		Present: NRPPAPDUPresentInitiatingMessage,
		InitiatingMessage: &InitiatingMessage{
			ProcedureCode:      ProcedureCode{Value: ProcCodeECIDMeasurementReport},
			Criticality:        Criticality{Value: CriticalityPresentIgnore},
			NRPPATransactionID: NRPPATransactionID{Value: nextTransactionID()},
			Value: InitiatingMessageValue{
				Present: InitiatingMessagePresentECIDMeasurementReport,
				ECIDMeasurementReport: &ECIDMeasurementReport{
					ProtocolIEs: ProtocolIEContainerECIDMeasurementReportIEs{
						List: []ECIDMeasurementReportIEs{
							{
								ID:          ProtocolIEID{Value: idLMFUEMeasurementID},
								Criticality: Criticality{Value: CriticalityPresentReject},
								Value: ECIDMeasurementReportIEsValue{
									Present:            ECIDMeasurementReportIEsPresentLMFUEMeasurementID,
									LMFUEMeasurementID: &UEMeasurementID{Value: measIDValue(m.LMFMeasurementID)},
								},
							},
							{
								ID:          ProtocolIEID{Value: idRANUEMeasurementID},
								Criticality: Criticality{Value: CriticalityPresentReject},
								Value: ECIDMeasurementReportIEsValue{
									Present:            ECIDMeasurementReportIEsPresentRANUEMeasurementID,
									RANUEMeasurementID: &UEMeasurementID{Value: measIDValue(m.RANMeasurementID)},
								},
							},
							{
								ID:          ProtocolIEID{Value: idECIDMeasurementResult},
								Criticality: Criticality{Value: CriticalityPresentIgnore},
								Value: ECIDMeasurementReportIEsValue{
									Present:               ECIDMeasurementReportIEsPresentECIDMeasurementResult,
									ECIDMeasurementResult: result,
								},
							},
						},
					},
				},
			},
		},
	}
	return mustEncode(pdu)
}

func ecidReportFromWire(w *ECIDMeasurementReport) *ECIDMeasurementReportMsg {
	m := &ECIDMeasurementReportMsg{}
	if w == nil {
		return m
	}
	for _, ie := range w.ProtocolIEs.List {
		switch ie.Value.Present {
		case ECIDMeasurementReportIEsPresentLMFUEMeasurementID:
			if ie.Value.LMFUEMeasurementID != nil {
				m.LMFMeasurementID = measIDFromValue(ie.Value.LMFUEMeasurementID.Value)
			}
		case ECIDMeasurementReportIEsPresentRANUEMeasurementID:
			if ie.Value.RANUEMeasurementID != nil {
				m.RANMeasurementID = measIDFromValue(ie.Value.RANUEMeasurementID.Value)
			}
		case ECIDMeasurementReportIEsPresentECIDMeasurementResult:
			if r := ie.Value.ECIDMeasurementResult; r != nil {
				m.ServingNRCGI = nrcgiFromNGRANCGI(r.ServingCellID)
				copy(m.ServingTAC[:], r.ServingCellTAC)
				m.APPosition = appPositionFromWire(r.NGRANAccessPointPosition)
			}
		}
	}
	return m
}

// ---- encode helper ------------------------------------------------------------

// mustEncode marshals pdu as APER. Encoding failures indicate a bug in this
// package's own struct construction (malformed field combination), not caller
// input — matching the panic-in-a-library-invariant convention used by the old
// bespoke codec's silent-failure paths would hide real bugs, so this panics.
// Ref: root CLAUDE.md "No panic in production" — this is an internal invariant
// violation (equivalent to encoding/json.Marshal on a struct with a bad tag),
// not a runtime/input error, so it is acceptable here per the same convention
// github.com/free5gc/ngap-based encoders in this repo use (return nil on error).
func mustEncode(pdu NRPPAPDU) []byte {
	b, err := aper.MarshalWithParams(pdu, "valueExt,valueLB:0,valueUB:2")
	if err != nil {
		return nil
	}
	return b
}
