// Package sbi implements the AMF's inbound Service Based Interface server.
//
// This is the inbound SBI server on the AMF. It serves:
//   - Namf_Communication (namf-comm): UEContextTransfer, N1N2MessageTransfer
//   - Namf_Location (namf-loc): ProvideLocationInfo (Cell-ID positioning relay)
//
// Ref: TS 29.518 §5.3.2 (Namf_Communication_UEContextTransfer),
//
//	TS 29.518 §5.2.2.6 (Namf_Location_ProvideLocationInfo),
//	TS 23.502 §4.2.2.2.3 (Registration with AMF change),
//	TS 23.273 §7.2 (Cell-ID positioning).
package sbi

// TransferReason enumerates why the new AMF is requesting the UE context.
// Ref: TS 29.518 §6.1.6.3.x (TransferReason).
const (
	ReasonInitReg            = "INIT_REG"
	ReasonMobiReg            = "MOBI_REG"
	ReasonMobiRegUEValidated = "MOBI_REG_UE_VALIDATED"
)

// UeContextTransferReqData is the request body of UEContextTransfer.
// Ref: TS 29.518 §6.1.6.2.2.
type UeContextTransferReqData struct {
	Reason            string              `json:"reason"`
	AccessType        string              `json:"accessType,omitempty"`
	PlmnID            *PlmnID             `json:"plmnId,omitempty"`
	RegRequest        *N1MessageContainer `json:"regRequest,omitempty"`
	SupportedFeatures string              `json:"supportedFeatures,omitempty"`
}

// UeContextTransferRspData is the response body of UEContextTransfer.
// Ref: TS 29.518 §6.1.6.2.3.
type UeContextTransferRspData struct {
	UeContext         UeContext `json:"ueContext"`
	SupportedFeatures string    `json:"supportedFeatures,omitempty"`
}

// N1MessageContainer wraps a NAS message carried over SBI.
// Ref: TS 29.518 §6.1.6.2.10.
type N1MessageContainer struct {
	N1MessageClass   string          `json:"n1MessageClass"`
	N1MessageContent RefToBinaryData `json:"n1MessageContent"`
}

// RefToBinaryData references a binary part of a multipart message.
// Ref: TS 29.571 §5.2.4.6.
type RefToBinaryData struct {
	ContentID string `json:"contentId"`
}

// PlmnID identifies a PLMN. Ref: TS 29.571 §5.4.4.3.
type PlmnID struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
}

// UeContext carries the transferred UE context.
// Only the fields populated by this build are modelled. Ref: TS 29.518 §6.1.6.2.x,
// TS 29.571 §5.x.
type UeContext struct {
	Supi               string              `json:"supi,omitempty"`
	SupiUnauthInd      bool                `json:"supiUnauthInd,omitempty"`
	Pei                string              `json:"pei,omitempty"`
	MmContextList      []MmContext         `json:"mmContextList,omitempty"`
	SessionContextList []PduSessionContext `json:"sessionContextList,omitempty"`
	PcfID              string              `json:"pcfId,omitempty"`
}

// MmContext holds the per-access mobility-management (NAS) context, including
// the NAS security context. Ref: TS 29.518 §6.1.6.2.x (MmContext).
type MmContext struct {
	AccessType           string           `json:"accessType"`
	NasSecurityMode      *NasSecurityMode `json:"nasSecurityMode,omitempty"`
	NasDownlinkCount     uint32           `json:"nasDownlinkCount,omitempty"`
	NasUplinkCount       uint32           `json:"nasUplinkCount,omitempty"`
	UeSecurityCapability string           `json:"ueSecurityCapability,omitempty"` // base64 of the UE Security Capability IE
	// KAmf carries the 256-bit KAMF (base64). DEV/intra-operator only — the
	// production transfer relies on TLS for confidentiality of the key material.
	// Ref: TS 33.501 §6.9.3 (horizontal/AMF-change key handling).
	KAmf string `json:"kamf,omitempty"`
}

// NasSecurityMode names the selected NAS algorithms.
// Ref: TS 29.518 §6.1.6.2.x (NasSecurityMode), TS 24.501 §9.11.3.34.
type NasSecurityMode struct {
	IntegrityAlgorithm string `json:"integrityAlgorithm"` // NIA0..NIA3
	CipheringAlgorithm string `json:"cipheringAlgorithm"` // NEA0..NEA3
}

// PduSessionContext describes one established PDU session in the transferred
// context. Ref: TS 29.518 §6.1.6.2.x (PduSessionContext).
type PduSessionContext struct {
	PduSessionID  uint8   `json:"pduSessionId"`
	SmContextRef  string  `json:"smContextRef,omitempty"`
	SNssai        *Snssai `json:"sNssai,omitempty"`
	Dnn           string  `json:"dnn,omitempty"`
	AccessType    string  `json:"accessType,omitempty"`
	SmfInstanceID string  `json:"smfInstanceId,omitempty"`
}

// Snssai is a Single Network Slice Selection Assistance Information.
// Ref: TS 29.571 §5.4.4.2.
type Snssai struct {
	Sst uint8  `json:"sst"`
	Sd  string `json:"sd,omitempty"`
}

// ---- Namf_Communication_N1N2MessageTransfer (TS 29.518 §6.1.6.2.x) ----------

// N1N2 transfer result causes. Ref: TS 29.518 §6.1.6.3.x (N1N2MessageTransferCause).
const (
	CauseN1N2TransferInitiated = "N1_N2_TRANSFER_INITIATED"
	CauseAttemptingToReachUE   = "ATTEMPTING_TO_REACH_UE"
	CauseUENotReachable        = "UE_NOT_REACHABLE"
)

// N1N2MessageTransferReqData is the request body of N1N2MessageTransfer.
// Only the fields exercised by the Network-Triggered Service Request are modelled.
// Ref: TS 29.518 §6.1.6.2.5.
type N1N2MessageTransferReqData struct {
	N1MessageContainer *N1MessageContainer `json:"n1MessageContainer,omitempty"`
	N2InfoContainer    *N2InfoContainer    `json:"n2InfoContainer,omitempty"`
	PduSessionID       *uint8              `json:"pduSessionId,omitempty"`
	Ppi                *int                `json:"ppi,omitempty"`
	Arp                *Arp                `json:"arp,omitempty"`
	SupportedFeatures  string              `json:"supportedFeatures,omitempty"`
}

// N2InfoContainer carries N2 information (e.g. PDU session resource setup).
// Ref: TS 29.518 §6.1.6.2.11.
type N2InfoContainer struct {
	N2InformationClass string `json:"n2InformationClass"`
}

// Arp is the Allocation and Retention Priority. Ref: TS 29.571 §5.5.2.
type Arp struct {
	PriorityLevel int `json:"priorityLevel"`
}

// N1N2MessageTransferRspData is the response body of N1N2MessageTransfer.
// Ref: TS 29.518 §6.1.6.2.6.
type N1N2MessageTransferRspData struct {
	Cause string `json:"cause"`
}

// ProblemDetails is the RFC 7807 error body used across SBI.
// Ref: TS 29.571 §5.2.4.1.
type ProblemDetails struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title,omitempty"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Cause  string `json:"cause,omitempty"`
}

// ---- Namf_Location (TS 29.518 §5.2.2.6) -------------------------------------

// RequestLocInfo is the body of Namf_Location_ProvideLocationInfo (LMF → AMF).
// Ref: TS 29.518 §6.1.6.2.x; TS 23.273 §7.2.
type RequestLocInfo struct {
	// Req5gsLoc requests the current 5GS location (TAI + NRCGI of serving cell).
	// Mandatory for the Cell-ID positioning MVP.
	// Ref: TS 29.518 §6.1.6.2.x.
	Req5gsLoc bool `json:"req5gsLoc"`
	// ReqCurrentLoc requests a fresh measurement (triggers NGAP LocationReportingControl).
	// When false the AMF may return last-known location.
	ReqCurrentLoc bool `json:"reqCurrentLoc,omitempty"`
	// SupportedGADShapes is the list of GAD shapes the consumer can decode.
	SupportedGADShapes []string `json:"supportedGADShapes,omitempty"`
}

// LocationData is the Namf_Location response body (AMF → LMF).
// Carries the serving cell NRCGI and TAI from the NGAP LocationReport.
// Ref: TS 29.518 §6.1.6.2.x; TS 29.572 §6.1.6.2.2.
type LocationData struct {
	// LocationEstimate is a minimal GAD POINT shape. For Cell-ID positioning the
	// lat/lon are derived from a config map; absent entry → 0,0 placeholder.
	// Ref: TS 29.572 §6.1.6.2.2 (locationEstimate, GeographicArea shape=POINT).
	LocationEstimate *GeographicArea `json:"locationEstimate,omitempty"`
	// NRCellId is the serving NR cell rendered as a hex string (36-bit cell id).
	// Ref: TS 29.572 §6.1.6.2.2; TS 38.413 §9.3.1.x (NRCellIdentity).
	NRCellId string `json:"nrCellId,omitempty"`
	// Tai is the Tracking Area Identity of the serving cell.
	Tai *TaiLoc `json:"tai,omitempty"`
	// AgeOfLocationEstimate is minutes since the estimate (0 = fresh report).
	AgeOfLocationEstimate int `json:"ageOfLocationEstimate"`
}

// GeographicArea holds a minimal GAD POINT shape (lat/lon).
// Ref: TS 29.572 §6.1.6.2.x; TS 29.571 §5.4.4.x.
type GeographicArea struct {
	Shape string  `json:"shape"` // "POINT" for Cell-ID MVP
	Point *LatLon `json:"point,omitempty"`
}

// LatLon is a WGS84 coordinate pair.
type LatLon struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// TaiLoc is the Tracking Area Identity carried in LocationData.
// Ref: TS 29.571 §5.4.4.3; TS 38.413 §9.3.1.x.
type TaiLoc struct {
	PlmnId PlmnID `json:"plmnId"`
	Tac    string `json:"tac"` // 3-byte hex, e.g. "000001"
}

// ---- Cause constants for Namf_Location errors ----

// CauseLocationFailure is returned when the NGAP location exchange fails or times out.
// Ref: TS 29.572 §6.1.x; TS 29.518 §5.2.2.6.
const CauseLocationFailure = "LOCATION_FAILURE"

// nasAlgName maps a NAS algorithm identifier (0..3) to its 3GPP short name.
// Ref: TS 24.501 §9.11.3.34.
func nasIntegName(id byte) string {
	switch id {
	case 0:
		return "NIA0"
	case 1:
		return "NIA1"
	case 2:
		return "NIA2"
	case 3:
		return "NIA3"
	default:
		return "NIA0"
	}
}

func nasCipherName(id byte) string {
	switch id {
	case 0:
		return "NEA0"
	case 1:
		return "NEA1"
	case 2:
		return "NEA2"
	case 3:
		return "NEA3"
	default:
		return "NEA0"
	}
}
