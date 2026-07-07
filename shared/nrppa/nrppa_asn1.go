// ASN.1 Aligned PER (APER) struct mirror of the TS 38.455 (NRPPa) E-CID subset,
// using github.com/free5gc/aper reflection-based Marshal/Unmarshal — the same
// mechanism github.com/free5gc/ngap uses for NGAP. free5gc has no NRPPa module,
// so these types are hand-written directly from the 3GPP ASN.1 source
// (NRPPA-PDU-Descriptions.asn, NRPPA-PDU-Contents.asn, NRPPA-IEs.asn,
// NRPPA-Constants.asn, NRPPA-CommonDataTypes.asn — TS 38.455 V19.1.0), following
// the exact struct/tag conventions of github.com/free5gc/ngap/ngapType (CHOICE via
// a leading "Present int" field, openType IE values, "optional"/"valueExt" tags).
//
// Only the E-CID positioning subset is implemented: e-CIDMeasurementInitiation
// (ProcedureCode=2), e-CIDMeasurementReport (ProcedureCode=4), and
// positioningInformationExchange (ProcedureCode=9) — TS 38.455 Table 9.1-1.
// Optional/conditional IEs outside this subset (MeasurementPeriodicity,
// OtherRAT/WLAN measurements, CriticalityDiagnostics, Cell-Portion-ID, SRS-related
// PositioningInformation IEs, ...) are legally omitted — ProtocolIE-Container is a
// variable-length SEQUENCE OF, so absent IEs cost nothing and do not desync the
// APER bitstream. Fixed-field SEQUENCEs (E-CID-MeasurementResult, NG-RAN-CGI,
// NG-RANAccessPointPosition) declare every OPTIONAL field from the spec — even
// ones this package never populates — because those contribute real preamble
// bits; omitting the Go field would desync a real 3GPP dissector (Wireshark).
package nrppa

import "github.com/free5gc/aper"

// ---- NRPPA-CommonDataTypes (TS 38.455 §9.3.6) -------------------------------

// ProcedureCode ::= INTEGER (0..255)
type ProcedureCode struct {
	Value int64 `aper:"valueLB:0,valueUB:255"`
}

// Criticality ::= ENUMERATED { reject, ignore, notify }
type Criticality struct {
	Value aper.Enumerated `aper:"valueLB:0,valueUB:2"`
}

const (
	CriticalityPresentReject aper.Enumerated = 0
	CriticalityPresentIgnore aper.Enumerated = 1
	CriticalityPresentNotify aper.Enumerated = 2
)

// NRPPATransactionID ::= INTEGER (0..32767)
type NRPPATransactionID struct {
	Value int64 `aper:"valueLB:0,valueUB:32767"`
}

// ProtocolIEID ::= INTEGER (0..maxProtocolIEs), maxProtocolIEs = 65535.
type ProtocolIEID struct {
	Value int64 `aper:"valueLB:0,valueUB:65535"`
}

// ---- Procedure codes (TS 38.455 Table 9.1-1, NRPPA-Constants.asn) -----------

const (
	// ProcCodeECIDMeasurementInitiation = id-e-CIDMeasurementInitiation.
	ProcCodeECIDMeasurementInitiation int64 = 2
	// ProcCodeECIDMeasurementReport = id-e-CIDMeasurementReport.
	ProcCodeECIDMeasurementReport int64 = 4
	// ProcCodePositioningInformationExchange = id-positioningInformationExchange.
	ProcCodePositioningInformationExchange int64 = 9
)

// ---- Protocol IE ids (TS 38.455 Table 9.2-x, NRPPA-Constants.asn) -----------

const (
	idCause                     int64 = 0
	idLMFUEMeasurementID        int64 = 2
	idReportCharacteristics     int64 = 3
	idMeasurementQuantities     int64 = 5
	idRANUEMeasurementID        int64 = 6
	idECIDMeasurementResult     int64 = 7
	idMeasurementQuantitiesItem int64 = 11
)

// ---- NRPPA-PDU (NRPPA-PDU-Descriptions.asn) ---------------------------------

const (
	NRPPAPDUPresentNothing int = iota
	NRPPAPDUPresentInitiatingMessage
	NRPPAPDUPresentSuccessfulOutcome
	NRPPAPDUPresentUnsuccessfulOutcome
)

// NRPPAPDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome, ... }
type NRPPAPDU struct {
	Present             int
	InitiatingMessage   *InitiatingMessage
	SuccessfulOutcome   *SuccessfulOutcome
	UnsuccessfulOutcome *UnsuccessfulOutcome
}

// InitiatingMessage ::= SEQUENCE { procedureCode, criticality, nrppatransactionID, value }
type InitiatingMessage struct {
	ProcedureCode      ProcedureCode
	Criticality        Criticality
	NRPPATransactionID NRPPATransactionID
	Value              InitiatingMessageValue `aper:"openType,referenceFieldName:ProcedureCode"`
}

// SuccessfulOutcome ::= SEQUENCE { procedureCode, criticality, nrppatransactionID, value }
type SuccessfulOutcome struct {
	ProcedureCode      ProcedureCode
	Criticality        Criticality
	NRPPATransactionID NRPPATransactionID
	Value              SuccessfulOutcomeValue `aper:"openType,referenceFieldName:ProcedureCode"`
}

// UnsuccessfulOutcome ::= SEQUENCE { procedureCode, criticality, nrppatransactionID, value }
type UnsuccessfulOutcome struct {
	ProcedureCode      ProcedureCode
	Criticality        Criticality
	NRPPATransactionID NRPPATransactionID
	Value              UnsuccessfulOutcomeValue `aper:"openType,referenceFieldName:ProcedureCode"`
}

const (
	InitiatingMessagePresentNothing int = iota
	InitiatingMessagePresentECIDMeasurementInitiationRequest
	InitiatingMessagePresentECIDMeasurementReport
	InitiatingMessagePresentPositioningInformationRequest
)

// InitiatingMessageValue is the OPEN TYPE selected by InitiatingMessage.ProcedureCode.
type InitiatingMessageValue struct {
	Present                          int
	ECIDMeasurementInitiationRequest *ECIDMeasurementInitiationRequest  `aper:"valueExt,referenceFieldValue:2"`
	ECIDMeasurementReport            *ECIDMeasurementReport             `aper:"valueExt,referenceFieldValue:4"`
	PositioningInformationRequest    *wirePositioningInformationRequest `aper:"valueExt,referenceFieldValue:9"`
}

const (
	SuccessfulOutcomePresentNothing int = iota
	SuccessfulOutcomePresentECIDMeasurementInitiationResponse
	SuccessfulOutcomePresentPositioningInformationResponse
)

// SuccessfulOutcomeValue is the OPEN TYPE selected by SuccessfulOutcome.ProcedureCode.
type SuccessfulOutcomeValue struct {
	Present                           int
	ECIDMeasurementInitiationResponse *ECIDMeasurementInitiationResponse  `aper:"valueExt,referenceFieldValue:2"`
	PositioningInformationResponse    *wirePositioningInformationResponse `aper:"valueExt,referenceFieldValue:9"`
}

const (
	UnsuccessfulOutcomePresentNothing int = iota
	UnsuccessfulOutcomePresentECIDMeasurementInitiationFailure
	UnsuccessfulOutcomePresentPositioningInformationFailure
)

// UnsuccessfulOutcomeValue is the OPEN TYPE selected by UnsuccessfulOutcome.ProcedureCode.
type UnsuccessfulOutcomeValue struct {
	Present                          int
	ECIDMeasurementInitiationFailure *ECIDMeasurementInitiationFailure  `aper:"valueExt,referenceFieldValue:2"`
	PositioningInformationFailure    *wirePositioningInformationFailure `aper:"valueExt,referenceFieldValue:9"`
}

// ---- e-CIDMeasurementInitiation (ProcedureCode=2) ---------------------------

// ECIDMeasurementInitiationRequest ::= SEQUENCE { protocolIEs, ... }
type ECIDMeasurementInitiationRequest struct {
	ProtocolIEs ProtocolIEContainerECIDMeasurementInitiationRequestIEs
}

type ProtocolIEContainerECIDMeasurementInitiationRequestIEs struct {
	List []ECIDMeasurementInitiationRequestIEs `aper:"sizeLB:0,sizeUB:65535"`
}

type ECIDMeasurementInitiationRequestIEs struct {
	ID          ProtocolIEID
	Criticality Criticality
	Value       ECIDMeasurementInitiationRequestIEsValue `aper:"openType,referenceFieldName:ID"`
}

const (
	ECIDMeasurementInitiationRequestIEsPresentNothing int = iota
	ECIDMeasurementInitiationRequestIEsPresentLMFUEMeasurementID
	ECIDMeasurementInitiationRequestIEsPresentReportCharacteristics
	ECIDMeasurementInitiationRequestIEsPresentMeasurementQuantities
)

type ECIDMeasurementInitiationRequestIEsValue struct {
	Present               int
	LMFUEMeasurementID    *UEMeasurementID       `aper:"referenceFieldValue:2"`
	ReportCharacteristics *ReportCharacteristics `aper:"referenceFieldValue:3"`
	MeasurementQuantities *MeasurementQuantities `aper:"referenceFieldValue:5"`
}

// ECIDMeasurementInitiationResponse ::= SEQUENCE { protocolIEs, ... }
type ECIDMeasurementInitiationResponse struct {
	ProtocolIEs ProtocolIEContainerECIDMeasurementInitiationResponseIEs
}

type ProtocolIEContainerECIDMeasurementInitiationResponseIEs struct {
	List []ECIDMeasurementInitiationResponseIEs `aper:"sizeLB:0,sizeUB:65535"`
}

type ECIDMeasurementInitiationResponseIEs struct {
	ID          ProtocolIEID
	Criticality Criticality
	Value       ECIDMeasurementInitiationResponseIEsValue `aper:"openType,referenceFieldName:ID"`
}

const (
	ECIDMeasurementInitiationResponseIEsPresentNothing int = iota
	ECIDMeasurementInitiationResponseIEsPresentLMFUEMeasurementID
	ECIDMeasurementInitiationResponseIEsPresentRANUEMeasurementID
	ECIDMeasurementInitiationResponseIEsPresentECIDMeasurementResult
)

type ECIDMeasurementInitiationResponseIEsValue struct {
	Present               int
	LMFUEMeasurementID    *UEMeasurementID       `aper:"referenceFieldValue:2"`
	RANUEMeasurementID    *UEMeasurementID       `aper:"referenceFieldValue:6"`
	ECIDMeasurementResult *ECIDMeasurementResult `aper:"valueExt,referenceFieldValue:7"`
}

// ECIDMeasurementInitiationFailure ::= SEQUENCE { protocolIEs, ... }
type ECIDMeasurementInitiationFailure struct {
	ProtocolIEs ProtocolIEContainerECIDMeasurementInitiationFailureIEs
}

type ProtocolIEContainerECIDMeasurementInitiationFailureIEs struct {
	List []ECIDMeasurementInitiationFailureIEs `aper:"sizeLB:0,sizeUB:65535"`
}

type ECIDMeasurementInitiationFailureIEs struct {
	ID          ProtocolIEID
	Criticality Criticality
	Value       ECIDMeasurementInitiationFailureIEsValue `aper:"openType,referenceFieldName:ID"`
}

const (
	ECIDMeasurementInitiationFailureIEsPresentNothing int = iota
	ECIDMeasurementInitiationFailureIEsPresentLMFUEMeasurementID
	ECIDMeasurementInitiationFailureIEsPresentCause
)

type ECIDMeasurementInitiationFailureIEsValue struct {
	Present            int
	LMFUEMeasurementID *UEMeasurementID `aper:"referenceFieldValue:2"`
	Cause              *Cause           `aper:"referenceFieldValue:0,valueUB:2"`
}

// ---- e-CIDMeasurementReport (ProcedureCode=4) -------------------------------

// ECIDMeasurementReport ::= SEQUENCE { protocolIEs, ... }
type ECIDMeasurementReport struct {
	ProtocolIEs ProtocolIEContainerECIDMeasurementReportIEs
}

type ProtocolIEContainerECIDMeasurementReportIEs struct {
	List []ECIDMeasurementReportIEs `aper:"sizeLB:0,sizeUB:65535"`
}

type ECIDMeasurementReportIEs struct {
	ID          ProtocolIEID
	Criticality Criticality
	Value       ECIDMeasurementReportIEsValue `aper:"openType,referenceFieldName:ID"`
}

const (
	ECIDMeasurementReportIEsPresentNothing int = iota
	ECIDMeasurementReportIEsPresentLMFUEMeasurementID
	ECIDMeasurementReportIEsPresentRANUEMeasurementID
	ECIDMeasurementReportIEsPresentECIDMeasurementResult
)

type ECIDMeasurementReportIEsValue struct {
	Present               int
	LMFUEMeasurementID    *UEMeasurementID       `aper:"referenceFieldValue:2"`
	RANUEMeasurementID    *UEMeasurementID       `aper:"referenceFieldValue:6"`
	ECIDMeasurementResult *ECIDMeasurementResult `aper:"valueExt,referenceFieldValue:7"`
}

// ---- positioningInformationExchange (ProcedureCode=9) -----------------------
//
// All IEs defined for these three messages are OPTIONAL in TS 38.455 and outside
// the E-CID subset (SRS/TEG/beam related) — this package always sends an empty
// ProtocolIE-Container (0 IEs), which is spec-legal. wirePositioningInformationResponse
// SuccessfulOutcome (bare, 0 IEs) is used as the E-CID-capability-supported proxy;
// wirePositioningInformationFailure UnsuccessfulOutcome (with a mandatory Cause) as
// the not-supported proxy — see EncodePosInfoRsp.

// wirePositioningInformationRequest ::= SEQUENCE { protocolIEs, ... }
type wirePositioningInformationRequest struct {
	ProtocolIEs ProtocolIEContainerEmptyIEs
}

// wirePositioningInformationResponse ::= SEQUENCE { protocolIEs, ... }
type wirePositioningInformationResponse struct {
	ProtocolIEs ProtocolIEContainerEmptyIEs
}

// wirePositioningInformationFailure ::= SEQUENCE { protocolIEs, ... }
type wirePositioningInformationFailure struct {
	ProtocolIEs ProtocolIEContainerPositioningInformationFailureIEs
}

// ProtocolIEContainerEmptyIEs backs the always-empty ProtocolIE-Container of
// wirePositioningInformationRequest/Response — every IE those messages define is
// OPTIONAL/outside the E-CID subset, so List is always nil (0 IEs, spec-legal).
type ProtocolIEContainerEmptyIEs struct {
	List []emptyIE `aper:"sizeLB:0,sizeUB:65535"`
}

// emptyIE is never populated; it only gives ProtocolIEContainerEmptyIEs.List an
// element type so the (always zero-length) SEQUENCE OF has somewhere to point.
type emptyIE struct {
	ID          ProtocolIEID
	Criticality Criticality
	Value       emptyIEValue `aper:"openType,referenceFieldName:ID"`
}

type emptyIEValue struct {
	Present int
}

type ProtocolIEContainerPositioningInformationFailureIEs struct {
	List []PositioningInformationFailureIEs `aper:"sizeLB:0,sizeUB:65535"`
}

type PositioningInformationFailureIEs struct {
	ID          ProtocolIEID
	Criticality Criticality
	Value       PositioningInformationFailureIEsValue `aper:"openType,referenceFieldName:ID"`
}

const (
	PositioningInformationFailureIEsPresentNothing int = iota
	PositioningInformationFailureIEsPresentCause
)

type PositioningInformationFailureIEsValue struct {
	Present int
	Cause   *Cause `aper:"referenceFieldValue:0,valueUB:2"`
}

// ---- IE value types (NRPPA-IEs.asn) ------------------------------------------

// UEMeasurementID ::= INTEGER (1..15, ..., 16..256). TS 38.455 §9.3.
type UEMeasurementID struct {
	Value int64 `aper:"valueExt,valueLB:1,valueUB:15"`
}

// ReportCharacteristics ::= ENUMERATED { onDemand, periodic, ... }
type ReportCharacteristics struct {
	Value aper.Enumerated `aper:"valueExt,valueLB:0,valueUB:1"`
}

const (
	ReportCharacteristicsOnDemand aper.Enumerated = 0
	ReportCharacteristicsPeriodic aper.Enumerated = 1
)

// MeasurementQuantities ::= SEQUENCE (SIZE(1..maxNoMeas)) OF
//
//	ProtocolIE-Single-Container {{MeasurementQuantities-ItemIEs}}
//
// maxNoMeas = 64. Each item is itself a full ProtocolIE-Field (id/criticality/
// value), per the ProtocolIE-Single-Container idiom (NRPPA-Containers.asn).
type MeasurementQuantities struct {
	List []MeasurementQuantitiesItemIE `aper:"sizeLB:1,sizeUB:64"`
}

type MeasurementQuantitiesItemIE struct {
	ID          ProtocolIEID
	Criticality Criticality
	Value       MeasurementQuantitiesItemIEValue `aper:"openType,referenceFieldName:ID"`
}

const (
	MeasurementQuantitiesItemIEPresentNothing int = iota
	MeasurementQuantitiesItemIEPresentItem
)

type MeasurementQuantitiesItemIEValue struct {
	Present int
	Item    *MeasurementQuantitiesItem `aper:"valueExt,referenceFieldValue:11"`
}

// MeasurementQuantitiesItem ::= SEQUENCE { measurementQuantitiesValue, iE-Extensions OPTIONAL, ... }
type MeasurementQuantitiesItem struct {
	MeasurementQuantitiesValue MeasurementQuantitiesValue
	IEExtensions               *protocolExtensionContainerPlaceholder `aper:"optional"`
}

// MeasurementQuantitiesValue ::= ENUMERATED { cell-ID, angleOfArrival,
//
//	timingAdvanceType1, timingAdvanceType2, rSRP, rSRQ, ... }
type MeasurementQuantitiesValue struct {
	Value aper.Enumerated `aper:"valueExt,valueLB:0,valueUB:5"`
}

const (
	MeasurementQuantitiesValueCellID             aper.Enumerated = 0
	MeasurementQuantitiesValueAngleOfArrival     aper.Enumerated = 1
	MeasurementQuantitiesValueTimingAdvanceType1 aper.Enumerated = 2
	MeasurementQuantitiesValueTimingAdvanceType2 aper.Enumerated = 3
	MeasurementQuantitiesValueRSRP               aper.Enumerated = 4
	MeasurementQuantitiesValueRSRQ               aper.Enumerated = 5
)

// Cause ::= CHOICE { radioNetwork, protocol, misc, choice-Extension }.
// The choice-Extension escape-hatch branch (TS 38.455's manual-extensibility
// idiom, mirroring how github.com/free5gc/ngap models NGAP's own Cause) is never
// constructed by this package, so it is omitted from the Go type — the 3-branch
// CHOICE below (indices 0..2) is a legal, non-extensible subset encoding.
const (
	CausePresentNothing int = iota
	CausePresentRadioNetwork
	CausePresentProtocol
	CausePresentMisc
)

type Cause struct {
	Present      int
	RadioNetwork *CauseRadioNetwork
	Protocol     *CauseProtocol
	Misc         *CauseMisc
}

// CauseRadioNetwork ::= ENUMERATED { unspecified, requested-item-not-supported,
//
//	requested-item-temporarily-not-available, ... }  (root: 3 values, 0..2)
type CauseRadioNetwork struct {
	Value aper.Enumerated `aper:"valueExt,valueLB:0,valueUB:2"`
}

// CauseProtocol ::= ENUMERATED { transfer-syntax-error, ..., unspecified,
//
//	abstract-syntax-error-falsely-constructed-message, ... }  (root: 7 values, 0..6)
type CauseProtocol struct {
	Value aper.Enumerated `aper:"valueExt,valueLB:0,valueUB:6"`
}

const CauseProtocolUnspecified aper.Enumerated = 5

// CauseMisc ::= ENUMERATED { unspecified, ... }  (root: 1 value, 0)
type CauseMisc struct {
	Value aper.Enumerated `aper:"valueExt,valueLB:0,valueUB:0"`
}

const CauseMiscUnspecified aper.Enumerated = 0

// ---- E-CID-MeasurementResult (id=7) ------------------------------------------

// ECIDMeasurementResult ::= SEQUENCE {
//
//	servingCell-ID              NG-RAN-CGI,
//	servingCellTAC              TAC,
//	nG-RANAccessPointPosition   NG-RANAccessPointPosition OPTIONAL,
//	measuredResults             MeasuredResults OPTIONAL,
//	iE-Extensions               ProtocolExtensionContainer OPTIONAL,
//	...
//	}
//
// measuredResults is a SEQUENCE OF E-UTRA-typed measurement entries (legacy
// LPPa/E-UTRA inter-RAT assistance fields — TS 38.455 has no NR-neighbour-cell
// variant of this list). This package never has E-UTRA data to report, so
// MeasuredResults is always absent; nG-RANAccessPointPosition (a real,
// spec-defined WGS84 estimate — TS 23.032 Ellipsoid Point with Uncertainty
// Ellipse encoding) carries the accuracy-improving payload instead. Both extra
// OPTIONAL fields are still declared (always nil) so the 3-bit preamble matches
// the real spec SEQUENCE — dropping them would desync a real ASN.1 dissector.
type ECIDMeasurementResult struct {
	ServingCellID            NGRANCGI                               `aper:"valueExt"`
	ServingCellTAC           aper.OctetString                       `aper:"sizeLB:3,sizeUB:3"`
	NGRANAccessPointPosition *NGRANAccessPointPosition              `aper:"optional,valueExt"`
	MeasuredResults          *measuredResultsPlaceholder            `aper:"optional"`
	IEExtensions             *protocolExtensionContainerPlaceholder `aper:"optional"`
}

// measuredResultsPlaceholder stands in for the E-UTRA-only MeasuredResults type
// (never populated by this package — see ECIDMeasurementResult doc comment).
type measuredResultsPlaceholder struct {
	List []struct{ Present int } `aper:"sizeLB:1,sizeUB:64"`
}

// protocolExtensionContainerPlaceholder stands in for ProtocolExtensionContainer
// (never populated — no NRPPa Rel-17 extension IEs are implemented).
type protocolExtensionContainerPlaceholder struct {
	List []struct{ Present int } `aper:"sizeLB:1,sizeUB:65535"`
}

// ---- NG-RAN-CGI (NRPPA-IEs.asn) ----------------------------------------------

// NGRANCGI ::= SEQUENCE { pLMN-Identity, nG-RANcell, iE-Extensions OPTIONAL, ... }
type NGRANCGI struct {
	PLMNIdentity aper.OctetString                       `aper:"sizeLB:3,sizeUB:3"`
	NGRANCell    NGRANCell                              `aper:"valueUB:2"`
	IEExtensions *protocolExtensionContainerPlaceholder `aper:"optional"`
}

// NGRANCell ::= CHOICE { eUTRA-CellID, nR-CellID, choice-Extension }.
// The choice-Extension branch (index 2) is never constructed by this package —
// see the Cause type doc comment for the same idiom — but the CHOICE index
// width on the wire is still 2 bits (ceil(log2(3)), the real 3-alternative
// count), NOT 1 bit: a real ASN.1 dissector expects the full 3-alternative
// width regardless of which branches this package happens to construct.
// `valueUB:2` (range=3) on the NGRANCGI.NGRANCell field above gets this right;
// getting it wrong (as an earlier revision of this file did, `valueUB:1`)
// desyncs every bit after the choice index — verified against a live pcap
// (Wireshark decoded the 1-bit version as `choice-Extension`, not `nR-CellID`,
// and the corrupted downstream bits made latitude/altitude nonsensical).
const (
	NGRANCellPresentNothing int = iota
	NGRANCellPresentEUTRACellID
	NGRANCellPresentNRCellID
)

type NGRANCell struct {
	Present     int
	EUTRACellID *aper.BitString `aper:"sizeLB:28,sizeUB:28"`
	NRCellID    *aper.BitString `aper:"sizeLB:36,sizeUB:36"`
}

// ---- NG-RANAccessPointPosition (NRPPA-IEs.asn) -------------------------------
//
// TS 38.455's field-for-field reuse of the TS 23.032 "Ellipsoid Point with
// Uncertainty Ellipse" shape. Real, spec-legal geographic-coordinate carrier —
// the gNB's own accuracy-improving position estimate, not an invented IE.
// Latitude and Longitude have constrained-INTEGER ranges above 65536
// (8388608 / 16777216). Per X.691 §10.5.7.4, once a constrained whole number's
// range exceeds 64K the range itself is ignored for the length calculation: the
// value is encoded as an octet-aligned length-determinant (sized to the range's
// max octet count) followed by the minimal number of octets for *that specific
// value* — free5gc/aper's `appendInteger` implements exactly this (verified
// byte-for-byte against a live pcap capture dissected by Wireshark's real NRPPa
// ASN.1 dissector). A fixed-width, no-length-prefix OctetString (an earlier
// revision of this file used one, assuming appendInteger was buggy for large
// ranges) is NOT what X.691 mandates here and desyncs a real dissector.
type NGRANAccessPointPosition struct {
	LatitudeSign           aper.Enumerated                        `aper:"valueLB:0,valueUB:1"` // 0=north, 1=south
	Latitude               int64                                  `aper:"valueLB:0,valueUB:8388607"`
	Longitude              int64                                  `aper:"valueLB:-8388608,valueUB:8388607"`
	DirectionOfAltitude    aper.Enumerated                        `aper:"valueLB:0,valueUB:1"` // 0=height, 1=depth
	Altitude               int64                                  `aper:"valueLB:0,valueUB:32767"`
	UncertaintySemiMajor   int64                                  `aper:"valueLB:0,valueUB:127"`
	UncertaintySemiMinor   int64                                  `aper:"valueLB:0,valueUB:127"`
	OrientationOfMajorAxis int64                                  `aper:"valueLB:0,valueUB:179"`
	UncertaintyAltitude    int64                                  `aper:"valueLB:0,valueUB:127"`
	Confidence             int64                                  `aper:"valueLB:0,valueUB:100"`
	IEExtensions           *protocolExtensionContainerPlaceholder `aper:"optional"`
}

const (
	LatitudeSignNorth aper.Enumerated = 0
	LatitudeSignSouth aper.Enumerated = 1

	DirectionOfAltitudeHeight aper.Enumerated = 0
	DirectionOfAltitudeDepth  aper.Enumerated = 1
)
