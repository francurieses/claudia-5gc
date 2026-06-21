// Package sbi implements the AMF's inbound Service Based Interface server.
//
// This is the first inbound SBI server on the AMF. It serves the
// Namf_Communication service (namf-comm) — currently the UEContextTransfer
// operation used when the UE changes AMF during (Mobility) Registration.
//
// Ref: TS 29.518 §5.3.2 (Namf_Communication_UEContextTransfer),
//
//	TS 23.502 §4.2.2.2.3 (Registration with AMF change).
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
