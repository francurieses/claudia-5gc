// Package lpp implements a spec-faithful subset of TS 37.355 (LTE
// Positioning Protocol — LPP, Rel-17) for UE-assisted A-GNSS positioning,
// encoded in ASN.1 BASIC-PER UNALIGNED as TS 37.355 §4 mandates.
//
// The wire structures mirror the vendored ASN.1 module
// specs/3gpp-asn1/LPP-PDU-Definitions.asn (TS 37.355 V19.3.0 — the A-GNSS
// subset is Rel-9 baseline, unchanged through Rel-17) type-for-type, with the
// exact field order and OPTIONAL markers the UPER presence bitmaps derive
// from. The unaligned-PER primitives live in uper.go (hand-rolled;
// free5gc/aper implements ALIGNED PER only and cannot produce UPER).
// Conformance oracle: the Wireshark/tshark LPP dissector must dissect every
// PDU this package emits with zero malformed fields (lpp_tshark_test.go).
//
// # Message set (docs/procedures/LPPRelay.md — the LMF-009 wire contract)
//
//	Leg 1  RequestCapabilities          LMF → UE   endTransaction=FALSE
//	Leg 1  ProvideCapabilities           UE → LMF  endTransaction=TRUE (echo txn)
//	Leg 2  ProvideAssistanceData        LMF → UE   endTransaction=TRUE, no UL reply
//	Leg 3  RequestLocationInformation   LMF → UE   endTransaction=FALSE
//	Leg 3  ProvideLocationInformation    UE → LMF  endTransaction=TRUE (echo txn)
//
// # Decode tolerance
//
// The decoder skips (read-and-discard) any extension additions a future peer
// sets on an extensible SEQUENCE (well-defined via the UPER open-type length,
// see uper.go skipSequenceExtensions). Root OPTIONAL fields outside the
// pinned A-GNSS subset (e.g. otdoa-*, epdu-*) are NOT skippable — PER carries
// no per-field length for root fields — so their presence is a decode error;
// the LMF treats any decode error as a graceful fallback trigger
// (TS 23.273 §6.2.10), never a 5xx.
//
// Ref: TS 37.355 §4 (encoding), §5.2 (transactions), §6.2 (LPP-Message),
// §6.4 (common IEs), §6.5.2 (A-GNSS IEs); TS 23.032 §6 (geodetic shapes);
// TS 24.501 §8.7.4 (DL/UL NAS Transport carrying LPP, PCT=0x03);
// TS 23.273 §6.2.10 / §7.2.
package lpp

import (
	"fmt"
	"sync/atomic"
)

// ---- Message type discriminators (Go-side, not wire bytes) --------------------

// Message type constants set by Decode to identify the decoded message kind.
const (
	MsgRequestCapabilities uint8 = iota + 1
	MsgProvideCapabilities
	MsgProvideAssistanceData
	MsgRequestLocationInformation
	MsgProvideLocationInformation
)

// LPP-MessageBody.c1 alternative indices (module: 16-way inner CHOICE, 4-bit
// index — requestCapabilities(0) … error(7) + 8 spares).
const (
	c1RequestCapabilities        = 0
	c1ProvideCapabilities        = 1
	c1RequestAssistanceData      = 2
	c1ProvideAssistanceData      = 3
	c1RequestLocationInformation = 4
	c1ProvideLocationInformation = 5
	c1Abort                      = 6
	c1Error                      = 7
	c1Alternatives               = 16 // 4-bit index width
)

// ---- Transaction handling (TS 37.355 §5.2) ------------------------------------

// Initiator values of LPP-TransactionID.initiator (extensible ENUMERATED
// {locationServer(0), targetDevice(1), ...}, module L48).
const (
	InitiatorLocationServer uint8 = 0
	InitiatorTargetDevice   uint8 = 1
)

// TransactionID mirrors LPP-TransactionID (module L42): initiator +
// transactionNumber INTEGER (0..255) (module L54). Every transaction in this
// project is LMF-initiated (initiator=locationServer); the UE's response
// ECHOES the same TransactionID (TS 37.355 §5.2 — it does NOT switch to
// targetDevice, which marks UE-initiated transactions only).
type TransactionID struct {
	Initiator uint8
	Number    uint8
}

var transactionCounter uint32

// NextTransactionID returns the next LMF-assigned transaction identity:
// initiator=locationServer, number = monotonic counter mod 256
// (TransactionNumber ::= INTEGER (0..255), TS 37.355 §5.2 / module L54).
func NextTransactionID() TransactionID {
	return TransactionID{
		Initiator: InitiatorLocationServer,
		Number:    uint8(atomic.AddUint32(&transactionCounter, 1) % 256),
	}
}

// ---- GNSS constants (TS 37.355 §6.4) -------------------------------------------

// GNSS-ID.gnss-id root enumeration values (extensible ENUMERATED
// {gps, sbas, qzss, galileo, glonass, ..., bds, navic-v1610}, module L6398).
const (
	GNSSIDGPS     uint8 = 0
	GNSSIDSBAS    uint8 = 1
	GNSSIDQZSS    uint8 = 2
	GNSSIDGalileo uint8 = 3
	GNSSIDGLONASS uint8 = 4
)

// gnssIDRootCount is the number of root values of the GNSS-ID enumeration.
const gnssIDRootCount = 5

// Pinned BIT STRING payloads (docs/procedures/LPPRelay.md wire contract —
// variable-size constraints are pinned to 8 bits so Go and the C++ UE patch
// emit byte-identical PDUs; any size in range is spec-legal).
const (
	// posModesUEAssisted is PositioningModes.posModes with only
	// ue-assisted(2) set, as 8 bits: '00100000'B (module L669).
	posModesUEAssisted uint64 = 0x20
	// gnssSignalIDsGPSL1CA is GNSS-SignalIDs.gnss-SignalIDs (fixed SIZE(8))
	// with bit 0 = GPS L1 C/A set: '10000000'B (module L6463; TS 37.355 §6.4).
	gnssSignalIDsGPSL1CA uint64 = 0x80
	// gnssIDBitmapGPS is GNSS-ID-Bitmap.gnss-ids with bit 0 = gps set, as
	// 8 bits: '10000000'B (module L6404).
	gnssIDBitmapGPS uint64 = 0x80
	// bitStringPinnedLen is the pinned length (8) for the two variable-size
	// bit strings above.
	bitStringPinnedLen = 8
)

// mpathDet values (GNSS-SatMeasElement.mpathDet, extensible ENUMERATED
// {notMeasured(0), low(1), medium(2), high(3), ...}, module L5812).
const (
	MpathDetNotMeasured uint8 = 0
	MpathDetLow         uint8 = 1
	MpathDetMedium      uint8 = 2
	MpathDetHigh        uint8 = 3
)

// mpathDetRootCount is the number of root values of the mpathDet enumeration.
const mpathDetRootCount = 4

// GNSS-TargetDeviceErrorCauses.cause root enumeration values (module L6375).
const (
	GNSSErrorUndefined                  uint8 = 0
	GNSSErrorNotEnoughSatellites        uint8 = 1
	GNSSErrorAssistanceDataMissing      uint8 = 2
	GNSSErrorNotAllMeasurementsPossible uint8 = 3
)

// gnssTargetErrorRootCount is the number of root cause values.
const gnssTargetErrorRootCount = 4

// LocationInformationType values (extensible ENUMERATED, module L795). Only
// locationMeasurementsRequired(1) is sent (UE-assisted: the UE reports
// measurements, the LMF computes the fix).
const (
	locationEstimateRequired     = 0
	locationMeasurementsRequired = 1
	locationInfoTypeRootCount    = 4
)

// ---- Wire-contract pinned field values (docs/procedures/LPPRelay.md) -----------

const (
	// ReferenceTimeUncDefault is the gnss-ReferenceTime.referenceTimeUnc
	// value sent in ProvideAssistanceData (conservative — no fine time
	// assistance in this flow). Scale r = 0.5·(1.14^K − 1) µs
	// (TS 37.355 §6.5.2 field description; confirmed against the tshark
	// LPP dissector, see lpp_tshark_test.go).
	ReferenceTimeUncDefault uint8 = 32

	// CNoDefault is the per-SV carrier-to-noise value (dB-Hz) the synthetic
	// UE reports (plausible fixed value, wire contract pin).
	CNoDefault uint8 = 44

	// CodePhaseRMSErrorDefault is the pinned per-SV codePhaseRMSError
	// encoded integer k = 8·y + x with exponent y in the 3 MSBs (k=20 ⇒
	// x=4, y=2 ⇒ RMS = 0.5·(1 + 4/8)·2² = exactly 3.0 m). Packing order
	// confirmed against the tshark LPP dissector (lpp_tshark_test.go).
	CodePhaseRMSErrorDefault uint8 = 20
)

// ---- Decoded / builder value types ---------------------------------------------

// ProvideCapabilitiesInfo is the decoded (UE → LMF) capability view.
type ProvideCapabilitiesInfo struct {
	// AGNSSSupported is true when a-gnss-ProvideCapabilities is present with
	// a non-empty gnss-SupportList (GNSS=NONE ⇔ false — TS 23.273 §6.2.10
	// fallback trigger).
	AGNSSSupported bool
	// GPSUEAssisted is true when the support list carries a gps entry whose
	// agnss-Modes has the ue-assisted bit set — the LMF proceeds to legs 2/3
	// only in this case.
	GPSUEAssisted bool
	// SupportedGNSS lists the decoded gnss-id values (root or extended).
	SupportedGNSS []uint8
}

// ReferenceLocation mirrors EllipsoidPointWithAltitudeAndUncertaintyEllipsoid
// (module L433 — not extensible, all 10 fields mandatory), carrying the raw
// TS 23.032 §6 quantized values exactly as encoded on the wire. Use
// EncodeLatitude/EncodeLongitude (gnss.go) to fill the coordinate fields and
// DecodeLatitude/DecodeLongitude to recover degrees (the quantized-anchor
// rule: both ends derive geometry from these wire-quantized values).
type ReferenceLocation struct {
	LatitudeSign         uint8  // 0 = north, 1 = south
	DegreesLatitude      uint32 // 0..8388607 (23-bit)
	DegreesLongitude     int32  // −8388608..8388607 (24-bit)
	AltitudeDirection    uint8  // 0 = height, 1 = depth
	Altitude             uint16 // 0..32767 metres
	UncertaintySemiMajor uint8  // 0..127, r = 10·(1.1^K − 1) m
	UncertaintySemiMinor uint8  // 0..127
	OrientationMajorAxis uint8  // 0..179, 2° units
	UncertaintyAltitude  uint8  // 0..127, r = 45·(1.025^K − 1) m
	Confidence           uint8  // 0..100 percent
}

// AssistanceData is the (LMF → UE) leg-2 payload: gnss-ReferenceTime
// (GPS day number + time of day, see UnixToGPSDayTime in gnss.go) +
// gnss-ReferenceLocation (serving-cell anchor). gnss-GenericAssistData is
// legally absent — no navigation model is sent; both ends derive the
// deterministic constellation from the wire-quantized anchor
// (GenerateSyntheticEphemeris, gnss.go).
type AssistanceData struct {
	DayNumber         uint16 // gnss-DayNumber INTEGER (0..32767)
	TimeOfDay         uint32 // gnss-TimeOfDay INTEGER (0..86399)
	ReferenceTimeUnc  uint8  // referenceTimeUnc INTEGER (0..127)
	ReferenceLocation ReferenceLocation
}

// SatMeas mirrors GNSS-SatMeasElement (module L5812) for the fields this
// subset carries. The pseudorange rides in CodePhase/IntegerCodePhase — see
// PseudorangeToCodePhase / CodePhaseToPseudorange (gnss.go).
type SatMeas struct {
	SVID              uint8  // SV-ID.satellite-id 0..63 (GPS: PRN − 1)
	CNo               uint8  // 0..63 dB-Hz
	MpathDet          uint8  // MpathDet* enum value
	CodePhase         uint32 // 0..2097151, 2⁻²¹ ms units
	IntegerCodePhase  uint8  // 0..127 whole ms (always included by our UE)
	CodePhaseRMSError uint8  // 0..63, k = 8·y + x floating format
}

// LocationMeasurements is the (UE → LMF) leg-3 measurement payload
// (gnss-SignalMeasurementInformation, module L5726).
type LocationMeasurements struct {
	// GNSSTODMsec is measurementReferenceTime.gnss-TOD-msec (0..3599999) —
	// see GPSTODMsec in gnss.go.
	GNSSTODMsec uint32
	// Sats is the gnss-SatMeasList (1..64 entries; this project sends 4).
	Sats []SatMeas
}

// PDU is the top-level decoded LPP-Message. Type selects which payload
// pointer is non-nil (RequestCapabilities and RequestLocationInformation
// carry no payload beyond their pinned flags and set none).
type PDU struct {
	Type uint8

	// HasTransactionID reflects the transactionID presence bit; both ends of
	// this project always send it.
	HasTransactionID bool
	TransactionID    TransactionID
	EndTransaction   bool

	ProvideCapabilities  *ProvideCapabilitiesInfo
	AssistanceData       *AssistanceData
	LocationMeasurements *LocationMeasurements
	// TargetDeviceErrorCause is non-nil when a ProvideLocationInformation
	// carried gnss-Error.targetDeviceErrorCauses instead of measurements
	// (GNSSError* values; extended values decode to >= 4).
	TargetDeviceErrorCause *uint8
}

// ---- Envelope encode -------------------------------------------------------------

// writeEnvelope writes the LPP-Message preamble through the per-message
// criticalExtensions.c1 wrapper (module L9–L15). LPP-Message is NOT
// extensible: 4 presence bits (transactionID, sequenceNumber,
// acknowledgement, lpp-MessageBody); sequenceNumber and acknowledgement are
// never sent (TS 37.355 §5.2 reliable-transport aids, out of scope).
func writeEnvelope(w *bitWriter, txn TransactionID, endTransaction bool, c1Index uint64) {
	// Presence bits: transactionID=1, sequenceNumber=0, acknowledgement=0,
	// lpp-MessageBody=1.
	w.writeBits(0b1001, 4)

	// LPP-TransactionID ::= SEQUENCE { initiator, transactionNumber, ... } —
	// extensible, no OPTIONALs: ext bit + extensible ENUM(2 roots) + INTEGER(0..255).
	w.writeBit(0)
	w.writeEnumExt(uint64(txn.Initiator), 2)
	w.writeBits(uint64(txn.Number), 8)

	w.writeBool(endTransaction)

	// LPP-MessageBody ::= CHOICE { c1, messageClassExtension } — 2 root
	// alternatives, not extensible: 1-bit index, then the 16-way c1 CHOICE
	// (4-bit index).
	w.writeBit(0)
	w.writeBits(c1Index, bitWidth(c1Alternatives))

	// Per-message wrapper: criticalExtensions CHOICE { c1, criticalExtensionsFuture }
	// (1 bit) then the 4-way c1 CHOICE { <message>-r9, spare3..1 } (2 bits).
	w.writeBit(0)
	w.writeBits(0, 2)
}

// ---- Builders ---------------------------------------------------------------------

// BuildRequestCapabilities encodes leg 1's RequestCapabilities (LMF → UE):
// only a-gnss-RequestCapabilities present, with gnss-SupportListReq=TRUE and
// the other two flags FALSE; endTransaction=FALSE (the UE's
// ProvideCapabilities closes the transaction).
// Ref: TS 37.355 §5.2/§6.2; module L57/L67/L6345.
func BuildRequestCapabilities(txn TransactionID) ([]byte, error) {
	w := &bitWriter{}
	writeEnvelope(w, txn, false, c1RequestCapabilities)

	// RequestCapabilities-r9-IEs (extensible, 5 root OPTIONALs): only
	// a-gnss-RequestCapabilities present.
	w.writeBit(0)           // extension bit
	w.writeBits(0b01000, 5) // presence: common, A-GNSS, otdoa, ecid, epdu
	w.writeBit(0)           // A-GNSS-RequestCapabilities extension bit
	w.writeBool(true)       // gnss-SupportListReq
	w.writeBool(false)      // assistanceDataSupportListReq
	w.writeBool(false)      // locationVelocityTypesReq
	return w.bytes(), nil
}

// BuildProvideCapabilities encodes leg 1's ProvideCapabilities (UE → LMF),
// echoing txn with endTransaction=TRUE.
//
// gnssSupported=true: a-gnss-ProvideCapabilities with one GNSS-SupportElement
// {gps, agnss-Modes='00100000'B (ue-assisted), gnss-Signals='10000000'B
// (GPS L1 C/A), adr=FALSE, velocity=FALSE}.
// gnssSupported=false (GNSS=NONE): a-gnss-ProvideCapabilities entirely absent
// (legal — every ProvideCapabilities-r9-IEs field is OPTIONAL).
// Ref: TS 37.355 §6.2; module L97/L107/L5875/L5900.
func BuildProvideCapabilities(txn TransactionID, gnssSupported bool) ([]byte, error) {
	w := &bitWriter{}
	writeEnvelope(w, txn, true, c1ProvideCapabilities)

	w.writeBit(0) // ProvideCapabilities-r9-IEs extension bit
	if !gnssSupported {
		w.writeBits(0b00000, 5) // all five root OPTIONALs absent
		return w.bytes(), nil
	}
	w.writeBits(0b01000, 5) // only a-gnss-ProvideCapabilities present

	// A-GNSS-ProvideCapabilities (extensible, 4 root OPTIONALs): only
	// gnss-SupportList present.
	w.writeBit(0)
	w.writeBits(0b1000, 4)

	// GNSS-SupportList ::= SEQUENCE (SIZE(1..16)) OF — one element.
	if err := w.writeConstrained(1, 1, 16); err != nil {
		return nil, fmt.Errorf("lpp: build provide capabilities: %w", err)
	}

	// GNSS-SupportElement (extensible; root OPTIONALs sbas-IDs, fta-MeasSupport).
	w.writeBit(0)        // extension bit
	w.writeBits(0b00, 2) // sbas-IDs absent, fta-MeasSupport absent
	writeGNSSID(w, GNSSIDGPS)
	// agnss-Modes: PositioningModes (extensible SEQUENCE) wrapping
	// posModes BIT STRING (SIZE(1..8)) — pinned to 8 bits.
	w.writeBit(0)
	if err := w.writeConstrained(bitStringPinnedLen, 1, 8); err != nil {
		return nil, fmt.Errorf("lpp: build provide capabilities: %w", err)
	}
	w.writeBits(posModesUEAssisted, bitStringPinnedLen)
	// gnss-Signals: GNSS-SignalIDs (extensible SEQUENCE, 0 root OPTIONALs)
	// wrapping gnss-SignalIDs BIT STRING (SIZE(8)) — fixed size, no determinant.
	w.writeBit(0)
	w.writeBits(gnssSignalIDsGPSL1CA, 8)
	w.writeBool(false) // adr-Support
	w.writeBool(false) // velocityMeasurementSupport
	return w.bytes(), nil
}

// BuildProvideAssistanceData encodes leg 2's ProvideAssistanceData
// (LMF → UE): only a-gnss-ProvideAssistanceData.gnss-CommonAssistData with
// gnss-ReferenceTime + gnss-ReferenceLocation (gnss-GenericAssistData legally
// absent). Single-message transaction: endTransaction=TRUE, no UL reply
// (TS 37.355 assistance-data delivery is unsolicited).
// Ref: TS 37.355 §6.2/§6.5.2; module L172/L182/L3303/L3314/L3442/L3458/L3533/L433.
func BuildProvideAssistanceData(txn TransactionID, ad AssistanceData) ([]byte, error) {
	w := &bitWriter{}
	writeEnvelope(w, txn, true, c1ProvideAssistanceData)

	// ProvideAssistanceData-r9-IEs (extensible, 4 root OPTIONALs:
	// commonIEs, a-gnss, otdoa, epdu): only a-gnss present.
	w.writeBit(0)
	w.writeBits(0b0100, 4)

	// A-GNSS-ProvideAssistanceData (extensible, 3 root OPTIONALs:
	// gnss-CommonAssistData, gnss-GenericAssistData, gnss-Error): only common.
	w.writeBit(0)
	w.writeBits(0b100, 3)

	// GNSS-CommonAssistData (extensible, 4 root OPTIONALs: referenceTime,
	// referenceLocation, ionosphericModel, earthOrientationParameters).
	w.writeBit(0)
	w.writeBits(0b1100, 4)

	// GNSS-ReferenceTime (extensible; root OPTIONALs referenceTimeUnc,
	// gnss-ReferenceTimeForCells): referenceTimeUnc included (Cond noFTA).
	w.writeBit(0)
	w.writeBits(0b10, 2)
	// GNSS-SystemTime (extensible; root OPTIONALs gnss-TimeOfDayFrac-msec,
	// notificationOfLeapSecond, gps-TOW-Assist): all absent.
	w.writeBit(0)
	w.writeBits(0b000, 3)
	writeGNSSID(w, GNSSIDGPS) // gnss-TimeID
	if err := w.writeConstrained(int64(ad.DayNumber), 0, 32767); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: gnss-DayNumber: %w", err)
	}
	if err := w.writeConstrained(int64(ad.TimeOfDay), 0, 86399); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: gnss-TimeOfDay: %w", err)
	}
	if err := w.writeConstrained(int64(ad.ReferenceTimeUnc), 0, 127); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: referenceTimeUnc: %w", err)
	}

	// GNSS-ReferenceLocation (extensible SEQUENCE, no OPTIONALs) wrapping
	// threeDlocation = EllipsoidPointWithAltitudeAndUncertaintyEllipsoid
	// (NOT extensible, all 10 fields mandatory — no preamble at all).
	w.writeBit(0)
	loc := ad.ReferenceLocation
	w.writeBits(uint64(loc.LatitudeSign), 1)
	if err := w.writeConstrained(int64(loc.DegreesLatitude), 0, 8388607); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: degreesLatitude: %w", err)
	}
	if err := w.writeConstrained(int64(loc.DegreesLongitude), -8388608, 8388607); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: degreesLongitude: %w", err)
	}
	w.writeBits(uint64(loc.AltitudeDirection), 1)
	if err := w.writeConstrained(int64(loc.Altitude), 0, 32767); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: altitude: %w", err)
	}
	if err := w.writeConstrained(int64(loc.UncertaintySemiMajor), 0, 127); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: uncertaintySemiMajor: %w", err)
	}
	if err := w.writeConstrained(int64(loc.UncertaintySemiMinor), 0, 127); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: uncertaintySemiMinor: %w", err)
	}
	if err := w.writeConstrained(int64(loc.OrientationMajorAxis), 0, 179); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: orientationMajorAxis: %w", err)
	}
	if err := w.writeConstrained(int64(loc.UncertaintyAltitude), 0, 127); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: uncertaintyAltitude: %w", err)
	}
	if err := w.writeConstrained(int64(loc.Confidence), 0, 100); err != nil {
		return nil, fmt.Errorf("lpp: build provide assistance data: confidence: %w", err)
	}
	return w.bytes(), nil
}

// BuildRequestLocationInformation encodes leg 3's RequestLocationInformation
// (LMF → UE): commonIEs with locationInformationType =
// locationMeasurementsRequired (UE-assisted) + gnss-PositioningInstructions
// {gnss-Methods='10000000'B (gps), all four flags FALSE}; endTransaction=FALSE.
// Ref: TS 37.355 §6.2; module L213/L223/L766/L795/L5853/L5859.
func BuildRequestLocationInformation(txn TransactionID) ([]byte, error) {
	w := &bitWriter{}
	writeEnvelope(w, txn, false, c1RequestLocationInformation)

	// RequestLocationInformation-r9-IEs (extensible, 5 root OPTIONALs:
	// commonIEs, a-gnss, otdoa, ecid, epdu): commonIEs + a-gnss present.
	w.writeBit(0)
	w.writeBits(0b11000, 5)

	// CommonIEsRequestLocationInformation (extensible, 7 root OPTIONALs —
	// triggeredReporting, periodicalReporting, additionalInformation, qos,
	// environment, locationCoordinateTypes, velocityTypes: all absent).
	w.writeBit(0)
	w.writeBits(0, 7)
	w.writeEnumExt(locationMeasurementsRequired, locationInfoTypeRootCount)

	// A-GNSS-RequestLocationInformation (extensible, no root OPTIONALs).
	w.writeBit(0)
	// GNSS-PositioningInstructions (extensible, no root OPTIONALs).
	w.writeBit(0)
	// gnss-Methods: GNSS-ID-Bitmap (extensible SEQUENCE) wrapping gnss-ids
	// BIT STRING (SIZE(1..16)) — pinned to 8 bits, bit 0 = gps.
	w.writeBit(0)
	if err := w.writeConstrained(bitStringPinnedLen, 1, 16); err != nil {
		return nil, fmt.Errorf("lpp: build request location information: %w", err)
	}
	w.writeBits(gnssIDBitmapGPS, bitStringPinnedLen)
	w.writeBool(false) // fineTimeAssistanceMeasReq
	w.writeBool(false) // adrMeasReq
	w.writeBool(false) // multiFreqMeasReq
	w.writeBool(false) // assistanceAvailability
	return w.bytes(), nil
}

// BuildProvideLocationInformation encodes leg 3's ProvideLocationInformation
// (UE → LMF), echoing txn with endTransaction=TRUE: one gps
// GNSS-MeasurementForOneGNSS with one GNSS-SgnMeasElement (GPS L1 C/A) whose
// gnss-SatMeasList carries meas.Sats (1..64 per-SV entries; this project
// sends 4). gnss-LocationInformation is never sent (UE-assisted: the UE never
// reports its own fix).
// Ref: TS 37.355 §6.2/§6.5.2; module L260/L270/L5718/L5726/L5733/L5793–L5812.
func BuildProvideLocationInformation(txn TransactionID, meas LocationMeasurements) ([]byte, error) {
	if len(meas.Sats) == 0 || len(meas.Sats) > 64 {
		return nil, fmt.Errorf("lpp: build provide location information: %d satellites (want 1..64)", len(meas.Sats))
	}
	w := &bitWriter{}
	writeEnvelope(w, txn, true, c1ProvideLocationInformation)

	// ProvideLocationInformation-r9-IEs (extensible, 5 root OPTIONALs):
	// only a-gnss-ProvideLocationInformation present.
	w.writeBit(0)
	w.writeBits(0b01000, 5)

	// A-GNSS-ProvideLocationInformation (extensible, 3 root OPTIONALs:
	// gnss-SignalMeasurementInformation, gnss-LocationInformation, gnss-Error).
	w.writeBit(0)
	w.writeBits(0b100, 3)

	// GNSS-SignalMeasurementInformation (extensible, no root OPTIONALs).
	w.writeBit(0)

	// MeasurementReferenceTime (extensible; root OPTIONALs gnss-TOD-frac,
	// gnss-TOD-unc, networkTime — all absent).
	w.writeBit(0)
	w.writeBits(0b000, 3)
	if err := w.writeConstrained(int64(meas.GNSSTODMsec), 0, 3599999); err != nil {
		return nil, fmt.Errorf("lpp: build provide location information: gnss-TOD-msec: %w", err)
	}
	writeGNSSID(w, GNSSIDGPS) // gnss-TimeID

	// GNSS-MeasurementList ::= SEQUENCE (SIZE(1..16)) OF — one entry.
	if err := w.writeConstrained(1, 1, 16); err != nil {
		return nil, fmt.Errorf("lpp: build provide location information: %w", err)
	}
	// GNSS-MeasurementForOneGNSS (extensible, no root OPTIONALs).
	w.writeBit(0)
	writeGNSSID(w, GNSSIDGPS)
	// GNSS-SgnMeasList ::= SEQUENCE (SIZE(1..8)) OF — one entry.
	if err := w.writeConstrained(1, 1, 8); err != nil {
		return nil, fmt.Errorf("lpp: build provide location information: %w", err)
	}
	// GNSS-SgnMeasElement (extensible; root OPTIONAL gnss-CodePhaseAmbiguity absent).
	w.writeBit(0)
	w.writeBits(0b0, 1)
	// gnss-SignalID: GNSS-SignalID (extensible SEQUENCE) wrapping
	// gnss-SignalID INTEGER (0..7) = 0 (GPS L1 C/A, module L6454).
	w.writeBit(0)
	w.writeBits(0, 3)
	// GNSS-SatMeasList ::= SEQUENCE (SIZE(1..64)) OF.
	if err := w.writeConstrained(int64(len(meas.Sats)), 1, 64); err != nil {
		return nil, fmt.Errorf("lpp: build provide location information: %w", err)
	}
	for i, sv := range meas.Sats {
		// GNSS-SatMeasElement (extensible; root OPTIONALs carrierQualityInd,
		// integerCodePhase, doppler, adr — integerCodePhase always included).
		w.writeBit(0)
		w.writeBits(0b0100, 4)
		// svID: SV-ID (extensible SEQUENCE) wrapping satellite-id INTEGER (0..63).
		w.writeBit(0)
		if err := w.writeConstrained(int64(sv.SVID), 0, 63); err != nil {
			return nil, fmt.Errorf("lpp: build provide location information: sat %d svID: %w", i, err)
		}
		if err := w.writeConstrained(int64(sv.CNo), 0, 63); err != nil {
			return nil, fmt.Errorf("lpp: build provide location information: sat %d cNo: %w", i, err)
		}
		if sv.MpathDet >= mpathDetRootCount {
			return nil, fmt.Errorf("lpp: build provide location information: sat %d mpathDet %d out of root range", i, sv.MpathDet)
		}
		w.writeEnumExt(uint64(sv.MpathDet), mpathDetRootCount)
		if err := w.writeConstrained(int64(sv.CodePhase), 0, 2097151); err != nil {
			return nil, fmt.Errorf("lpp: build provide location information: sat %d codePhase: %w", i, err)
		}
		if err := w.writeConstrained(int64(sv.IntegerCodePhase), 0, 127); err != nil {
			return nil, fmt.Errorf("lpp: build provide location information: sat %d integerCodePhase: %w", i, err)
		}
		if err := w.writeConstrained(int64(sv.CodePhaseRMSError), 0, 63); err != nil {
			return nil, fmt.Errorf("lpp: build provide location information: sat %d codePhaseRMSError: %w", i, err)
		}
	}
	return w.bytes(), nil
}

// BuildProvideLocationInformationError encodes a ProvideLocationInformation
// carrying gnss-Error.targetDeviceErrorCauses{cause} instead of measurements
// (the UE's A-GNSS failure reply, e.g. GNSSErrorAssistanceDataMissing when no
// anchor is stored). Echoes txn with endTransaction=TRUE.
// Ref: TS 37.355 §6.2; module L6353/L6375; docs/procedures/LPPRelay.md error table.
func BuildProvideLocationInformationError(txn TransactionID, cause uint8) ([]byte, error) {
	if cause >= gnssTargetErrorRootCount {
		return nil, fmt.Errorf("lpp: build provide location information error: cause %d out of root range", cause)
	}
	w := &bitWriter{}
	writeEnvelope(w, txn, true, c1ProvideLocationInformation)

	w.writeBit(0)           // r9-IEs extension bit
	w.writeBits(0b01000, 5) // only a-gnss-ProvideLocationInformation

	// A-GNSS-ProvideLocationInformation: only gnss-Error present.
	w.writeBit(0)
	w.writeBits(0b001, 3)

	// A-GNSS-Error ::= CHOICE { locationServerErrorCauses,
	// targetDeviceErrorCauses, ... } — extensible: ext bit + 1-bit index.
	w.writeBit(0)
	w.writeBits(1, 1) // targetDeviceErrorCauses

	// GNSS-TargetDeviceErrorCauses (extensible; 3 root OPTIONAL NULLs absent).
	w.writeBit(0)
	w.writeBits(0b000, 3)
	w.writeEnumExt(uint64(cause), gnssTargetErrorRootCount)
	return w.bytes(), nil
}

// writeGNSSID writes a GNSS-ID (extensible SEQUENCE, no OPTIONALs, wrapping
// the extensible gnss-id ENUMERATED — module L6398).
func writeGNSSID(w *bitWriter, id uint8) {
	w.writeBit(0)
	w.writeEnumExt(uint64(id), gnssIDRootCount)
}

// ---- Decode -----------------------------------------------------------------------

// Decode decodes raw UPER LPP-Message bytes (as received via the NAS payload
// container, payload container type 0x03) into a PDU, returning the echoed
// TransactionID for the TS 37.355 §5.2 verification. Extension additions set
// by a future peer on any extensible SEQUENCE in the subset are skipped;
// root OPTIONAL fields outside the subset are a decode error (see package doc).
func Decode(b []byte) (pdu *PDU, err error) {
	r := &bitReader{buf: b}
	out := &PDU{}

	presence, err := r.readPresence(4)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode: envelope preamble: %w", err)
	}
	hasTxn, hasSeq, hasAck, hasBody := presence[0], presence[1], presence[2], presence[3]

	if hasTxn {
		out.HasTransactionID = true
		if err := decodeTransactionID(r, &out.TransactionID); err != nil {
			return nil, err
		}
	}
	endTx, err := r.readBool()
	if err != nil {
		return nil, fmt.Errorf("lpp: decode: endTransaction: %w", err)
	}
	out.EndTransaction = endTx

	if hasSeq {
		// SequenceNumber ::= INTEGER (0..255) — never sent by this project;
		// consume and ignore.
		if _, err := r.readConstrained(0, 255); err != nil {
			return nil, fmt.Errorf("lpp: decode: sequenceNumber: %w", err)
		}
	}
	if hasAck {
		// Acknowledgement ::= SEQUENCE { ackRequested BOOLEAN,
		// ackIndicator SequenceNumber OPTIONAL } — consume and ignore.
		ackPresence, err := r.readPresence(1)
		if err != nil {
			return nil, fmt.Errorf("lpp: decode: acknowledgement: %w", err)
		}
		if _, err := r.readBool(); err != nil {
			return nil, fmt.Errorf("lpp: decode: acknowledgement: %w", err)
		}
		if ackPresence[0] {
			if _, err := r.readConstrained(0, 255); err != nil {
				return nil, fmt.Errorf("lpp: decode: acknowledgement: %w", err)
			}
		}
	}
	if !hasBody {
		return nil, fmt.Errorf("lpp: decode: lpp-MessageBody absent")
	}

	// LPP-MessageBody CHOICE (1 bit) + c1 CHOICE (4 bits).
	bodyChoice, err := r.readBit()
	if err != nil {
		return nil, fmt.Errorf("lpp: decode: message body choice: %w", err)
	}
	if bodyChoice != 0 {
		return nil, fmt.Errorf("lpp: decode: messageClassExtension body not supported")
	}
	c1, err := r.readBits(bitWidth(c1Alternatives))
	if err != nil {
		return nil, fmt.Errorf("lpp: decode: c1 index: %w", err)
	}

	// Per-message criticalExtensions wrapper.
	if err := decodeCriticalExtensions(r); err != nil {
		return nil, err
	}

	switch c1 {
	case c1RequestCapabilities:
		out.Type = MsgRequestCapabilities
		err = decodeRequestCapabilities(r)
	case c1ProvideCapabilities:
		out.Type = MsgProvideCapabilities
		out.ProvideCapabilities, err = decodeProvideCapabilities(r)
	case c1ProvideAssistanceData:
		out.Type = MsgProvideAssistanceData
		out.AssistanceData, err = decodeProvideAssistanceData(r)
	case c1RequestLocationInformation:
		out.Type = MsgRequestLocationInformation
		err = decodeRequestLocationInformation(r)
	case c1ProvideLocationInformation:
		out.Type = MsgProvideLocationInformation
		out.LocationMeasurements, out.TargetDeviceErrorCause, err = decodeProvideLocationInformation(r)
	default:
		return nil, fmt.Errorf("lpp: decode: unsupported LPP-MessageBody c1 index %d", c1)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decodeTransactionID reads LPP-TransactionID (extensible SEQUENCE, no
// OPTIONALs: initiator + transactionNumber).
func decodeTransactionID(r *bitReader, txn *TransactionID) error {
	ext, err := r.readBit()
	if err != nil {
		return fmt.Errorf("lpp: decode: transactionID: %w", err)
	}
	init, err := r.readEnumExt(2)
	if err != nil {
		return fmt.Errorf("lpp: decode: transactionID initiator: %w", err)
	}
	num, err := r.readBits(8)
	if err != nil {
		return fmt.Errorf("lpp: decode: transactionNumber: %w", err)
	}
	txn.Initiator = uint8(init)
	txn.Number = uint8(num)
	if ext == 1 {
		if err := r.skipSequenceExtensions(); err != nil {
			return fmt.Errorf("lpp: decode: transactionID extensions: %w", err)
		}
	}
	return nil
}

// decodeCriticalExtensions reads the per-message
// criticalExtensions.c1.<message>-r9 wrapper (1-bit CHOICE + 2-bit c1 CHOICE).
func decodeCriticalExtensions(r *bitReader) error {
	choice, err := r.readBit()
	if err != nil {
		return fmt.Errorf("lpp: decode: criticalExtensions: %w", err)
	}
	if choice != 0 {
		return fmt.Errorf("lpp: decode: criticalExtensionsFuture not supported")
	}
	c1, err := r.readBits(2)
	if err != nil {
		return fmt.Errorf("lpp: decode: criticalExtensions c1: %w", err)
	}
	if c1 != 0 {
		return fmt.Errorf("lpp: decode: criticalExtensions spare alternative %d", c1)
	}
	return nil
}

// readSeqExt reads an extensible SEQUENCE's extension bit; the returned
// closure must be invoked after all root fields to skip any additions.
func readSeqExt(r *bitReader) (func() error, error) {
	ext, err := r.readBit()
	if err != nil {
		return nil, err
	}
	if ext == 0 {
		return func() error { return nil }, nil
	}
	return r.skipSequenceExtensions, nil
}

// decodeGNSSID reads a GNSS-ID and returns the (root or extended) gnss-id value.
func decodeGNSSID(r *bitReader) (uint8, error) {
	skip, err := readSeqExt(r)
	if err != nil {
		return 0, err
	}
	v, err := r.readEnumExt(gnssIDRootCount)
	if err != nil {
		return 0, err
	}
	if err := skip(); err != nil {
		return 0, err
	}
	return uint8(v), nil
}

// decodeRequestCapabilities parses RequestCapabilities-r9-IEs (validating the
// a-gnss flags; no payload is surfaced).
func decodeRequestCapabilities(r *bitReader) error {
	skip, err := readSeqExt(r)
	if err != nil {
		return fmt.Errorf("lpp: decode request capabilities: %w", err)
	}
	presence, err := r.readPresence(5)
	if err != nil {
		return fmt.Errorf("lpp: decode request capabilities: %w", err)
	}
	if presence[0] || presence[2] || presence[3] || presence[4] {
		return fmt.Errorf("lpp: decode request capabilities: non-A-GNSS root OPTIONAL present (outside subset)")
	}
	if presence[1] {
		aSkip, err := readSeqExt(r)
		if err != nil {
			return fmt.Errorf("lpp: decode request capabilities: a-gnss: %w", err)
		}
		for i := 0; i < 3; i++ { // gnss-SupportListReq, assistanceDataSupportListReq, locationVelocityTypesReq
			if _, err := r.readBool(); err != nil {
				return fmt.Errorf("lpp: decode request capabilities: a-gnss flags: %w", err)
			}
		}
		if err := aSkip(); err != nil {
			return fmt.Errorf("lpp: decode request capabilities: a-gnss extensions: %w", err)
		}
	}
	return skip()
}

// decodeProvideCapabilities parses ProvideCapabilities-r9-IEs into the
// friendly capability view.
func decodeProvideCapabilities(r *bitReader) (*ProvideCapabilitiesInfo, error) {
	info := &ProvideCapabilitiesInfo{}
	skip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide capabilities: %w", err)
	}
	presence, err := r.readPresence(5)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide capabilities: %w", err)
	}
	if presence[0] || presence[2] || presence[3] || presence[4] {
		return nil, fmt.Errorf("lpp: decode provide capabilities: non-A-GNSS root OPTIONAL present (outside subset)")
	}
	if !presence[1] {
		// a-gnss-ProvideCapabilities absent — GNSS=NONE (legal; fallback trigger).
		return info, skip()
	}

	aSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide capabilities: a-gnss: %w", err)
	}
	aPresence, err := r.readPresence(4)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide capabilities: a-gnss: %w", err)
	}
	if aPresence[1] || aPresence[2] || aPresence[3] {
		return nil, fmt.Errorf("lpp: decode provide capabilities: a-gnss root OPTIONAL outside subset present")
	}
	if aPresence[0] {
		count, err := r.readConstrained(1, 16)
		if err != nil {
			return nil, fmt.Errorf("lpp: decode provide capabilities: gnss-SupportList: %w", err)
		}
		for i := int64(0); i < count; i++ {
			gnssID, ueAssisted, err := decodeGNSSSupportElement(r)
			if err != nil {
				return nil, fmt.Errorf("lpp: decode provide capabilities: element %d: %w", i, err)
			}
			info.SupportedGNSS = append(info.SupportedGNSS, gnssID)
			if gnssID == GNSSIDGPS && ueAssisted {
				info.GPSUEAssisted = true
			}
		}
		info.AGNSSSupported = len(info.SupportedGNSS) > 0
	}
	if err := aSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode provide capabilities: a-gnss extensions: %w", err)
	}
	return info, skip()
}

// decodeGNSSSupportElement parses one GNSS-SupportElement (module L5900),
// returning its gnss-id and whether agnss-Modes has the ue-assisted bit set.
func decodeGNSSSupportElement(r *bitReader) (gnssID uint8, ueAssisted bool, err error) {
	skip, err := readSeqExt(r)
	if err != nil {
		return 0, false, err
	}
	presence, err := r.readPresence(2) // sbas-IDs, fta-MeasSupport
	if err != nil {
		return 0, false, err
	}
	gnssID, err = decodeGNSSID(r)
	if err != nil {
		return 0, false, fmt.Errorf("gnss-ID: %w", err)
	}
	if presence[0] {
		// SBAS-IDs ::= SEQUENCE { sbas-IDs BIT STRING (SIZE(1..8)), ... }.
		sbasSkip, err := readSeqExt(r)
		if err != nil {
			return 0, false, fmt.Errorf("sbas-IDs: %w", err)
		}
		n, err := r.readConstrained(1, 8)
		if err != nil {
			return 0, false, fmt.Errorf("sbas-IDs: %w", err)
		}
		if _, err := r.readBits(int(n)); err != nil {
			return 0, false, fmt.Errorf("sbas-IDs: %w", err)
		}
		if err := sbasSkip(); err != nil {
			return 0, false, fmt.Errorf("sbas-IDs extensions: %w", err)
		}
	}
	// agnss-Modes: PositioningModes { posModes BIT STRING (SIZE(1..8)), ... }.
	pmSkip, err := readSeqExt(r)
	if err != nil {
		return 0, false, fmt.Errorf("agnss-Modes: %w", err)
	}
	pmLen, err := r.readConstrained(1, 8)
	if err != nil {
		return 0, false, fmt.Errorf("agnss-Modes: %w", err)
	}
	pmBits, err := r.readBits(int(pmLen))
	if err != nil {
		return 0, false, fmt.Errorf("agnss-Modes: %w", err)
	}
	// Named bit ue-assisted(2), counted from the MSB of the bit string.
	if pmLen >= 3 && pmBits&(1<<uint(pmLen-3)) != 0 {
		ueAssisted = true
	}
	if err := pmSkip(); err != nil {
		return 0, false, fmt.Errorf("agnss-Modes extensions: %w", err)
	}
	// gnss-Signals: GNSS-SignalIDs { gnss-SignalIDs BIT STRING (SIZE(8)), ..., ext }.
	sigSkip, err := readSeqExt(r)
	if err != nil {
		return 0, false, fmt.Errorf("gnss-Signals: %w", err)
	}
	if _, err := r.readBits(8); err != nil {
		return 0, false, fmt.Errorf("gnss-Signals: %w", err)
	}
	if err := sigSkip(); err != nil {
		return 0, false, fmt.Errorf("gnss-Signals extensions: %w", err)
	}
	if presence[1] {
		return 0, false, fmt.Errorf("fta-MeasSupport present (outside subset)")
	}
	if _, err := r.readBool(); err != nil { // adr-Support
		return 0, false, err
	}
	if _, err := r.readBool(); err != nil { // velocityMeasurementSupport
		return 0, false, err
	}
	return gnssID, ueAssisted, skip()
}

// decodeProvideAssistanceData parses ProvideAssistanceData-r9-IEs into the
// reference-time + reference-location assistance view.
func decodeProvideAssistanceData(r *bitReader) (*AssistanceData, error) {
	skip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: %w", err)
	}
	presence, err := r.readPresence(4) // commonIEs, a-gnss, otdoa, epdu
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: %w", err)
	}
	if presence[0] || presence[2] || presence[3] {
		return nil, fmt.Errorf("lpp: decode provide assistance data: non-A-GNSS root OPTIONAL present (outside subset)")
	}
	if !presence[1] {
		return nil, fmt.Errorf("lpp: decode provide assistance data: a-gnss-ProvideAssistanceData absent")
	}

	aSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: a-gnss: %w", err)
	}
	aPresence, err := r.readPresence(3) // commonAssistData, genericAssistData, gnss-Error
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: a-gnss: %w", err)
	}
	if aPresence[1] || aPresence[2] {
		return nil, fmt.Errorf("lpp: decode provide assistance data: gnss-GenericAssistData/gnss-Error present (outside subset)")
	}
	if !aPresence[0] {
		return nil, fmt.Errorf("lpp: decode provide assistance data: gnss-CommonAssistData absent")
	}

	cSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: common: %w", err)
	}
	cPresence, err := r.readPresence(4) // refTime, refLocation, iono, eop
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: common: %w", err)
	}
	if cPresence[2] || cPresence[3] {
		return nil, fmt.Errorf("lpp: decode provide assistance data: ionospheric/earth-orientation present (outside subset)")
	}
	if !cPresence[0] || !cPresence[1] {
		return nil, fmt.Errorf("lpp: decode provide assistance data: gnss-ReferenceTime and gnss-ReferenceLocation both required by this subset")
	}

	ad := &AssistanceData{}

	// GNSS-ReferenceTime.
	rtSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: referenceTime: %w", err)
	}
	rtPresence, err := r.readPresence(2) // referenceTimeUnc, gnss-ReferenceTimeForCells
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: referenceTime: %w", err)
	}
	if rtPresence[1] {
		return nil, fmt.Errorf("lpp: decode provide assistance data: gnss-ReferenceTimeForCells present (outside subset)")
	}
	// GNSS-SystemTime.
	stSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: systemTime: %w", err)
	}
	stPresence, err := r.readPresence(3) // frac-msec, leap, gps-TOW-Assist
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: systemTime: %w", err)
	}
	if stPresence[2] {
		return nil, fmt.Errorf("lpp: decode provide assistance data: gps-TOW-Assist present (outside subset)")
	}
	if _, err := decodeGNSSID(r); err != nil { // gnss-TimeID
		return nil, fmt.Errorf("lpp: decode provide assistance data: gnss-TimeID: %w", err)
	}
	day, err := r.readConstrained(0, 32767)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: gnss-DayNumber: %w", err)
	}
	tod, err := r.readConstrained(0, 86399)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: gnss-TimeOfDay: %w", err)
	}
	ad.DayNumber = uint16(day)
	ad.TimeOfDay = uint32(tod)
	if stPresence[0] { // gnss-TimeOfDayFrac-msec INTEGER (0..999) — consume.
		if _, err := r.readConstrained(0, 999); err != nil {
			return nil, fmt.Errorf("lpp: decode provide assistance data: frac-msec: %w", err)
		}
	}
	if stPresence[1] { // notificationOfLeapSecond BIT STRING (SIZE(2)) — consume.
		if _, err := r.readBits(2); err != nil {
			return nil, fmt.Errorf("lpp: decode provide assistance data: leap: %w", err)
		}
	}
	if err := stSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: systemTime extensions: %w", err)
	}
	if rtPresence[0] {
		unc, err := r.readConstrained(0, 127)
		if err != nil {
			return nil, fmt.Errorf("lpp: decode provide assistance data: referenceTimeUnc: %w", err)
		}
		ad.ReferenceTimeUnc = uint8(unc)
	}
	if err := rtSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: referenceTime extensions: %w", err)
	}

	// GNSS-ReferenceLocation (extensible wrapper, no OPTIONALs) →
	// EllipsoidPointWithAltitudeAndUncertaintyEllipsoid (not extensible).
	rlSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: referenceLocation: %w", err)
	}
	loc := &ad.ReferenceLocation
	fields := []struct {
		name string
		lb   int64
		ub   int64
		set  func(int64)
	}{
		{"latitudeSign", 0, 1, func(v int64) { loc.LatitudeSign = uint8(v) }},
		{"degreesLatitude", 0, 8388607, func(v int64) { loc.DegreesLatitude = uint32(v) }},
		{"degreesLongitude", -8388608, 8388607, func(v int64) { loc.DegreesLongitude = int32(v) }},
		{"altitudeDirection", 0, 1, func(v int64) { loc.AltitudeDirection = uint8(v) }},
		{"altitude", 0, 32767, func(v int64) { loc.Altitude = uint16(v) }},
		{"uncertaintySemiMajor", 0, 127, func(v int64) { loc.UncertaintySemiMajor = uint8(v) }},
		{"uncertaintySemiMinor", 0, 127, func(v int64) { loc.UncertaintySemiMinor = uint8(v) }},
		{"orientationMajorAxis", 0, 179, func(v int64) { loc.OrientationMajorAxis = uint8(v) }},
		{"uncertaintyAltitude", 0, 127, func(v int64) { loc.UncertaintyAltitude = uint8(v) }},
		{"confidence", 0, 100, func(v int64) { loc.Confidence = uint8(v) }},
	}
	for _, f := range fields {
		v, err := r.readConstrained(f.lb, f.ub)
		if err != nil {
			return nil, fmt.Errorf("lpp: decode provide assistance data: %s: %w", f.name, err)
		}
		f.set(v)
	}
	if err := rlSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: referenceLocation extensions: %w", err)
	}
	if err := cSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: common extensions: %w", err)
	}
	if err := aSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode provide assistance data: a-gnss extensions: %w", err)
	}
	return ad, skip()
}

// decodeRequestLocationInformation validates RequestLocationInformation-r9-IEs
// (used by tests and by the Go mirror of the UE-side decode; no payload is
// surfaced beyond structural validation).
func decodeRequestLocationInformation(r *bitReader) error {
	skip, err := readSeqExt(r)
	if err != nil {
		return fmt.Errorf("lpp: decode request location information: %w", err)
	}
	presence, err := r.readPresence(5) // commonIEs, a-gnss, otdoa, ecid, epdu
	if err != nil {
		return fmt.Errorf("lpp: decode request location information: %w", err)
	}
	if presence[2] || presence[3] || presence[4] {
		return fmt.Errorf("lpp: decode request location information: non-A-GNSS root OPTIONAL present (outside subset)")
	}
	if presence[0] {
		cSkip, err := readSeqExt(r)
		if err != nil {
			return fmt.Errorf("lpp: decode request location information: commonIEs: %w", err)
		}
		cPresence, err := r.readPresence(7)
		if err != nil {
			return fmt.Errorf("lpp: decode request location information: commonIEs: %w", err)
		}
		for i, p := range cPresence {
			if p {
				return fmt.Errorf("lpp: decode request location information: commonIEs root OPTIONAL %d present (outside subset)", i)
			}
		}
		if _, err := r.readEnumExt(locationInfoTypeRootCount); err != nil {
			return fmt.Errorf("lpp: decode request location information: locationInformationType: %w", err)
		}
		if err := cSkip(); err != nil {
			return fmt.Errorf("lpp: decode request location information: commonIEs extensions: %w", err)
		}
	}
	if presence[1] {
		aSkip, err := readSeqExt(r)
		if err != nil {
			return fmt.Errorf("lpp: decode request location information: a-gnss: %w", err)
		}
		piSkip, err := readSeqExt(r)
		if err != nil {
			return fmt.Errorf("lpp: decode request location information: positioningInstructions: %w", err)
		}
		// gnss-Methods: GNSS-ID-Bitmap.
		bmSkip, err := readSeqExt(r)
		if err != nil {
			return fmt.Errorf("lpp: decode request location information: gnss-Methods: %w", err)
		}
		n, err := r.readConstrained(1, 16)
		if err != nil {
			return fmt.Errorf("lpp: decode request location information: gnss-Methods: %w", err)
		}
		if _, err := r.readBits(int(n)); err != nil {
			return fmt.Errorf("lpp: decode request location information: gnss-Methods: %w", err)
		}
		if err := bmSkip(); err != nil {
			return fmt.Errorf("lpp: decode request location information: gnss-Methods extensions: %w", err)
		}
		for i := 0; i < 4; i++ { // fineTimeAssistanceMeasReq, adrMeasReq, multiFreqMeasReq, assistanceAvailability
			if _, err := r.readBool(); err != nil {
				return fmt.Errorf("lpp: decode request location information: instruction flags: %w", err)
			}
		}
		if err := piSkip(); err != nil {
			return fmt.Errorf("lpp: decode request location information: positioningInstructions extensions: %w", err)
		}
		if err := aSkip(); err != nil {
			return fmt.Errorf("lpp: decode request location information: a-gnss extensions: %w", err)
		}
	}
	return skip()
}

// decodeProvideLocationInformation parses ProvideLocationInformation-r9-IEs
// into either the per-SV measurement view or a target-device error cause.
func decodeProvideLocationInformation(r *bitReader) (*LocationMeasurements, *uint8, error) {
	skip, err := readSeqExt(r)
	if err != nil {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: %w", err)
	}
	presence, err := r.readPresence(5) // commonIEs, a-gnss, otdoa, ecid, epdu
	if err != nil {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: %w", err)
	}
	if presence[0] || presence[2] || presence[3] || presence[4] {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: non-A-GNSS root OPTIONAL present (outside subset)")
	}
	if !presence[1] {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: a-gnss-ProvideLocationInformation absent")
	}

	aSkip, err := readSeqExt(r)
	if err != nil {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: a-gnss: %w", err)
	}
	aPresence, err := r.readPresence(3) // signalMeasurementInformation, locationInformation, gnss-Error
	if err != nil {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: a-gnss: %w", err)
	}
	if aPresence[1] {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: gnss-LocationInformation present (UE-based, outside subset)")
	}

	var meas *LocationMeasurements
	if aPresence[0] {
		meas, err = decodeSignalMeasurementInformation(r)
		if err != nil {
			return nil, nil, err
		}
	}
	var errCause *uint8
	if aPresence[2] {
		errCause, err = decodeAGNSSError(r)
		if err != nil {
			return nil, nil, err
		}
	}
	if err := aSkip(); err != nil {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: a-gnss extensions: %w", err)
	}
	if err := skip(); err != nil {
		return nil, nil, err
	}
	if meas == nil && errCause == nil {
		return nil, nil, fmt.Errorf("lpp: decode provide location information: neither measurements nor gnss-Error present")
	}
	return meas, errCause, nil
}

// decodeSignalMeasurementInformation parses GNSS-SignalMeasurementInformation
// (module L5726). Only the first gps measurement branch's first signal's
// satellite list is surfaced (this subset never carries more than one
// constellation/signal).
func decodeSignalMeasurementInformation(r *bitReader) (*LocationMeasurements, error) {
	out := &LocationMeasurements{}
	sSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: %w", err)
	}

	// MeasurementReferenceTime.
	mtSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: referenceTime: %w", err)
	}
	mtPresence, err := r.readPresence(3) // gnss-TOD-frac, gnss-TOD-unc, networkTime
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: referenceTime: %w", err)
	}
	if mtPresence[2] {
		return nil, fmt.Errorf("lpp: decode measurements: networkTime present (outside subset)")
	}
	tod, err := r.readConstrained(0, 3599999)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: gnss-TOD-msec: %w", err)
	}
	out.GNSSTODMsec = uint32(tod)
	if mtPresence[0] { // gnss-TOD-frac INTEGER (0..3999) — consume.
		if _, err := r.readConstrained(0, 3999); err != nil {
			return nil, fmt.Errorf("lpp: decode measurements: gnss-TOD-frac: %w", err)
		}
	}
	if mtPresence[1] { // gnss-TOD-unc INTEGER (0..127) — consume.
		if _, err := r.readConstrained(0, 127); err != nil {
			return nil, fmt.Errorf("lpp: decode measurements: gnss-TOD-unc: %w", err)
		}
	}
	if _, err := decodeGNSSID(r); err != nil { // gnss-TimeID
		return nil, fmt.Errorf("lpp: decode measurements: gnss-TimeID: %w", err)
	}
	if err := mtSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: referenceTime extensions: %w", err)
	}

	// GNSS-MeasurementList (SIZE(1..16)).
	listCount, err := r.readConstrained(1, 16)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: measurementList: %w", err)
	}
	if listCount != 1 {
		return nil, fmt.Errorf("lpp: decode measurements: %d GNSS-MeasurementForOneGNSS entries (subset carries exactly 1)", listCount)
	}
	mSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: forOneGNSS: %w", err)
	}
	if _, err := decodeGNSSID(r); err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: gnss-ID: %w", err)
	}
	sgnCount, err := r.readConstrained(1, 8)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: sgnMeasList: %w", err)
	}
	if sgnCount != 1 {
		return nil, fmt.Errorf("lpp: decode measurements: %d GNSS-SgnMeasElement entries (subset carries exactly 1)", sgnCount)
	}

	// GNSS-SgnMeasElement.
	eSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: sgnMeasElement: %w", err)
	}
	ePresence, err := r.readPresence(1) // gnss-CodePhaseAmbiguity
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: sgnMeasElement: %w", err)
	}
	// gnss-SignalID: GNSS-SignalID { gnss-SignalID INTEGER (0..7), ..., ext }.
	sigSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: gnss-SignalID: %w", err)
	}
	if _, err := r.readConstrained(0, 7); err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: gnss-SignalID: %w", err)
	}
	if err := sigSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: gnss-SignalID extensions: %w", err)
	}
	if ePresence[0] { // gnss-CodePhaseAmbiguity INTEGER (0..127) — consume.
		if _, err := r.readConstrained(0, 127); err != nil {
			return nil, fmt.Errorf("lpp: decode measurements: codePhaseAmbiguity: %w", err)
		}
	}

	satCount, err := r.readConstrained(1, 64)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: satMeasList: %w", err)
	}
	for i := int64(0); i < satCount; i++ {
		sv, err := decodeSatMeasElement(r)
		if err != nil {
			return nil, fmt.Errorf("lpp: decode measurements: sat %d: %w", i, err)
		}
		out.Sats = append(out.Sats, sv)
	}
	if err := eSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: sgnMeasElement extensions: %w", err)
	}
	if err := mSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode measurements: forOneGNSS extensions: %w", err)
	}
	return out, sSkip()
}

// decodeSatMeasElement parses one GNSS-SatMeasElement (module L5812).
func decodeSatMeasElement(r *bitReader) (SatMeas, error) {
	var sv SatMeas
	skip, err := readSeqExt(r)
	if err != nil {
		return sv, err
	}
	presence, err := r.readPresence(4) // carrierQualityInd, integerCodePhase, doppler, adr
	if err != nil {
		return sv, err
	}
	// svID: SV-ID { satellite-id INTEGER (0..63), ... }.
	svSkip, err := readSeqExt(r)
	if err != nil {
		return sv, fmt.Errorf("svID: %w", err)
	}
	svid, err := r.readConstrained(0, 63)
	if err != nil {
		return sv, fmt.Errorf("svID: %w", err)
	}
	if err := svSkip(); err != nil {
		return sv, fmt.Errorf("svID extensions: %w", err)
	}
	sv.SVID = uint8(svid)

	cno, err := r.readConstrained(0, 63)
	if err != nil {
		return sv, fmt.Errorf("cNo: %w", err)
	}
	sv.CNo = uint8(cno)

	mpath, err := r.readEnumExt(mpathDetRootCount)
	if err != nil {
		return sv, fmt.Errorf("mpathDet: %w", err)
	}
	sv.MpathDet = uint8(mpath)

	if presence[0] { // carrierQualityInd INTEGER (0..3) — consume.
		if _, err := r.readConstrained(0, 3); err != nil {
			return sv, fmt.Errorf("carrierQualityInd: %w", err)
		}
	}
	cp, err := r.readConstrained(0, 2097151)
	if err != nil {
		return sv, fmt.Errorf("codePhase: %w", err)
	}
	sv.CodePhase = uint32(cp)
	if presence[1] {
		icp, err := r.readConstrained(0, 127)
		if err != nil {
			return sv, fmt.Errorf("integerCodePhase: %w", err)
		}
		sv.IntegerCodePhase = uint8(icp)
	}
	rms, err := r.readConstrained(0, 63)
	if err != nil {
		return sv, fmt.Errorf("codePhaseRMSError: %w", err)
	}
	sv.CodePhaseRMSError = uint8(rms)
	if presence[2] { // doppler INTEGER (-32768..32767) — consume.
		if _, err := r.readConstrained(-32768, 32767); err != nil {
			return sv, fmt.Errorf("doppler: %w", err)
		}
	}
	if presence[3] { // adr INTEGER (0..33554431) — consume.
		if _, err := r.readConstrained(0, 33554431); err != nil {
			return sv, fmt.Errorf("adr: %w", err)
		}
	}
	return sv, skip()
}

// decodeAGNSSError parses A-GNSS-Error, returning the target-device cause
// value (location-server causes and extended CHOICE alternatives are outside
// this subset).
func decodeAGNSSError(r *bitReader) (*uint8, error) {
	ext, err := r.readBit()
	if err != nil {
		return nil, fmt.Errorf("lpp: decode gnss-Error: %w", err)
	}
	if ext == 1 {
		return nil, fmt.Errorf("lpp: decode gnss-Error: extended CHOICE alternative not supported")
	}
	alt, err := r.readBits(1)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode gnss-Error: %w", err)
	}
	if alt != 1 {
		return nil, fmt.Errorf("lpp: decode gnss-Error: locationServerErrorCauses not expected from a target device")
	}
	tSkip, err := readSeqExt(r)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode gnss-Error: %w", err)
	}
	// GNSS-TargetDeviceErrorCauses: 3 root OPTIONAL NULLs (encode to nothing).
	if _, err := r.readPresence(3); err != nil {
		return nil, fmt.Errorf("lpp: decode gnss-Error: %w", err)
	}
	cause, err := r.readEnumExt(gnssTargetErrorRootCount)
	if err != nil {
		return nil, fmt.Errorf("lpp: decode gnss-Error: cause: %w", err)
	}
	if err := tSkip(); err != nil {
		return nil, fmt.Errorf("lpp: decode gnss-Error: extensions: %w", err)
	}
	c := uint8(cause)
	return &c, nil
}
