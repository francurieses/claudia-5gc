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

import (
	"encoding/json"
	"fmt"
	"time"
)

// TransferReason enumerates why the new AMF is requesting the UE context.
// Ref: TS 29.518 §6.1.6.3.x (TransferReason).
const (
	ReasonInitReg            = "INIT_REG"
	ReasonMobiReg            = "MOBI_REG"
	ReasonMobiRegUEValidated = "MOBI_REG_UE_VALIDATED"
)

// UeContextTransferReqData is the request body of UEContextTransfer. reason
// and accessType are mandatory (validated under the rel19 profile).
// Ref: TS 29.518 §6.1.6.2.23 (Table 6.1.6.2.23-1).
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/UeContextTransferReqData
type UeContextTransferReqData struct {
	Reason     string `json:"reason"`
	AccessType string `json:"accessType,omitempty"`
	// PlmnID is the PLMN ID or SNPN ID of the consumer: PlmnIdNid since
	// Rel-18 (PlmnId in Rel-17; a superset, so both decode).
	PlmnID            *PlmnIDNid          `json:"plmnId,omitempty"`
	RegRequest        *N1MessageContainer `json:"regRequest,omitempty"`
	SupportedFeatures string              `json:"supportedFeatures,omitempty"`
}

// Access types. AccessType is a closed enumeration (plain enum in
// TS29571_CommonData.yaml, not an extensible anyOf). Ref: TS 29.571 §5.4.3.1.
const (
	AccessType3GPP    = "3GPP_ACCESS"
	AccessTypeNon3GPP = "NON_3GPP_ACCESS"
)

// PlmnIDNid is a PLMN ID, with the NID for an SNPN. Ref: TS 29.571 §5.4.4.33.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/PlmnIdNid
type PlmnIDNid struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
	Nid string `json:"nid,omitempty"`
}

// UeContextTransferRspData is the response body of UEContextTransfer.
// Ref: TS 29.518 §6.1.6.2.24.
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/UeContextTransferRspData
type UeContextTransferRspData struct {
	UeContext         UeContext `json:"ueContext"`
	SupportedFeatures string    `json:"supportedFeatures,omitempty"`
}

// N1MessageContainer wraps a NAS message carried over SBI.
// Ref: TS 29.518 §6.1.6.2.17.
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/N1MessageContainer
type N1MessageContainer struct {
	N1MessageClass   string          `json:"n1MessageClass"`
	N1MessageContent RefToBinaryData `json:"n1MessageContent"`
}

// RefToBinaryData references a binary part of a multipart message.
// Ref: TS 29.571 §5.2.4.6.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/RefToBinaryData
type RefToBinaryData struct {
	ContentID string `json:"contentId"`
}

// PlmnID identifies a PLMN. Ref: TS 29.571 §5.4.4.3.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/PlmnId
type PlmnID struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
}

// UeContext carries the transferred UE context.
// Only the fields populated by this build are modelled. Ref: TS 29.518 §6.1.6.2.x,
// TS 29.571 §5.x.
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/UeContext
type UeContext struct {
	Supi string `json:"supi,omitempty"`
	// SupiUnauthInd "shall be present if SUPI is present" (TS 29.518 Table
	// 6.1.6.2.25-1): set under rel19; nil (absent) under rel17, the frozen
	// baseline. A pointer so that false can be sent.
	SupiUnauthInd *bool  `json:"supiUnauthInd,omitempty"`
	Pei           string `json:"pei,omitempty"`
	// FiveGMmCapability is the UE's 5GMM capability IE from octet 1 (IEI,
	// length, value), base64; rel19 only, present when the UE sent the IE.
	// Ref: TS 29.518 Table 6.1.6.2.25-1 (5gMmCapability), §6.1.6.3.2.
	FiveGMmCapability  string              `json:"5gMmCapability,omitempty"`
	MmContextList      []MmContext         `json:"mmContextList,omitempty"`
	SessionContextList []PduSessionContext `json:"sessionContextList,omitempty"`
	PcfID              string              `json:"pcfId,omitempty"`
	// SeafData carries the SEAF key material under the rel19 (spec-literal)
	// profile: seafData.keyAmf replaces the project mmContextList[].kamf.
	// Ref: TS 29.518 §6.1.6.2.25 (UeContext.seafData), §6.1.6.2.35 (SeafData)
	SeafData *SeafData `json:"seafData,omitempty"`
}

// SeafData is the SEAF data of a UE context. Ref: TS 29.518 (SeafData).
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/SeafData
type SeafData struct {
	NgKsi  NgKsi  `json:"ngKsi"`
	KeyAmf KeyAmf `json:"keyAmf"`
}

// NgKsi is the key set identifier. Ref: TS 29.518 (NgKsi), TS 33.501 §6.9.2.
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/NgKsi
type NgKsi struct {
	// Tsc is the security context type, NATIVE or MAPPED (ScType).
	Tsc string `json:"tsc"`
	// Ksi is the key set identifier value 0..6.
	Ksi int `json:"ksi"`
}

// KeyAmf carries KAMF (or K'AMF). Ref: TS 29.518 (KeyAmf, KeyAmfType).
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/KeyAmf
type KeyAmf struct {
	// KeyType is KAMF or KPRIMEAMF.
	KeyType string `json:"keyType"`
	// KeyVal is the key as a string of hexadecimal characters.
	KeyVal string `json:"keyVal"`
}

// MmContext holds the per-access mobility-management (NAS) context, including
// the NAS security context. Ref: TS 29.518 §6.1.6.2.34 (MmContext).
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/MmContext
type MmContext struct {
	AccessType      string           `json:"accessType"`
	NasSecurityMode *NasSecurityMode `json:"nasSecurityMode,omitempty"`
	// NasDownlinkCount / NasUplinkCount "shall be present if available"
	// (TS 29.518 Table 6.1.6.2.34-1), so a zero count is still sent under
	// rel19; rel17 keeps the legacy omission of a zero count.
	NasDownlinkCount *uint32 `json:"nasDownlinkCount,omitempty"`
	NasUplinkCount   *uint32 `json:"nasUplinkCount,omitempty"`
	// UeSecurityCapability is base64 of the UE security capability IE: from
	// octet 1 (IEI 0x2E, length, value) under rel19 (TS 29.518 §6.1.6.3.2),
	// the value octets only under rel17 (frozen baseline).
	UeSecurityCapability string `json:"ueSecurityCapability,omitempty"`
	// KAmf carries the 256-bit KAMF (base64) in the rel17-profile project member
	// "kamf" (see MarshalJSON). Under rel19 the key travels as UeContext.seafData.keyAmf
	// instead and this field stays empty. DEV/intra-operator only — the
	// production transfer relies on TLS for confidentiality of the key material.
	// Ref: TS 33.501 §6.9.3 (horizontal/AMF-change key handling).
	KAmf string `json:"-"`
}

// MarshalJSON appends the legacy "kamf" member (last, as before) when KAmf is set.
func (m MmContext) MarshalJSON() ([]byte, error) {
	type plain MmContext
	b, err := json.Marshal(struct {
		plain
		KAmf string `json:"kamf,omitempty"`
	}{plain(m), m.KAmf})
	if err != nil {
		return nil, fmt.Errorf("amf: sbi: marshal MmContext: %w", err)
	}
	return b, nil
}

// UnmarshalJSON accepts the legacy "kamf" member next to the spec attributes.
func (m *MmContext) UnmarshalJSON(b []byte) error {
	type plain MmContext
	aux := struct {
		*plain
		KAmf string `json:"kamf"`
	}{plain: (*plain)(m)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return fmt.Errorf("amf: sbi: decode MmContext: %w", err)
	}
	m.KAmf = aux.KAmf
	return nil
}

// NasSecurityMode names the selected NAS algorithms.
// Ref: TS 29.518 §6.1.6.2.36 (NasSecurityMode), TS 24.501 §9.11.3.34.
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/NasSecurityMode
type NasSecurityMode struct {
	IntegrityAlgorithm string `json:"integrityAlgorithm"` // NIA0..NIA3
	CipheringAlgorithm string `json:"cipheringAlgorithm"` // NEA0..NEA3
}

// PduSessionContext describes one established PDU session in the transferred
// context. smContextRef, sNssai, dnn and accessType are mandatory: the tags
// keep omitempty for the frozen rel17 bytes, and the rel19 builder only emits
// sessions that have them all.
// Ref: TS 29.518 §6.1.6.2.37 (PduSessionContext).
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/PduSessionContext
type PduSessionContext struct {
	PduSessionID uint8   `json:"pduSessionId"`
	SmContextRef string  `json:"smContextRef,omitempty"`
	SNssai       *Snssai `json:"sNssai,omitempty"`
	Dnn          string  `json:"dnn,omitempty"`
	AccessType   string  `json:"accessType,omitempty"`
	// HsmfID is the NF instance id of the (H-)SMF. This AMF never sets it: it
	// keeps no SMF NF instance id (PDUSession.SMFInstanceID is the SM context
	// reference). Decoded when a peer sends it.
	// Ref: TS 29.518 Table 6.1.6.2.37-1 (hsmfId)
	HsmfID string `json:"hsmfId,omitempty"`
	// SmfInstanceID is the rel17-profile project member "smfInstanceId" (see
	// MarshalJSON), carrying the SM context reference; absent under rel19.
	SmfInstanceID string `json:"-"`
}

// MarshalJSON appends the legacy "smfInstanceId" member (last, as before) when set.
func (c PduSessionContext) MarshalJSON() ([]byte, error) {
	type plain PduSessionContext
	b, err := json.Marshal(struct {
		plain
		SmfInstanceID string `json:"smfInstanceId,omitempty"`
	}{plain(c), c.SmfInstanceID})
	if err != nil {
		return nil, fmt.Errorf("amf: sbi: marshal PduSessionContext: %w", err)
	}
	return b, nil
}

// UnmarshalJSON accepts the legacy "smfInstanceId" member next to the spec attributes.
func (c *PduSessionContext) UnmarshalJSON(b []byte) error {
	type plain PduSessionContext
	aux := struct {
		*plain
		SmfInstanceID string `json:"smfInstanceId"`
	}{plain: (*plain)(c)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return fmt.Errorf("amf: sbi: decode PduSessionContext: %w", err)
	}
	c.SmfInstanceID = aux.SmfInstanceID
	return nil
}

// Snssai is a Single Network Slice Selection Assistance Information.
// Ref: TS 29.571 §5.4.4.2.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Snssai
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
// Ref: TS 29.518 §6.1.6.2.18.
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/N1N2MessageTransferReqData
type N1N2MessageTransferReqData struct {
	N1MessageContainer *N1MessageContainer `json:"n1MessageContainer,omitempty"`
	N2InfoContainer    *N2InfoContainer    `json:"n2InfoContainer,omitempty"`
	PduSessionID       *uint8              `json:"pduSessionId,omitempty"`
	Ppi                *int                `json:"ppi,omitempty"`
	Arp                *Arp                `json:"arp,omitempty"`
	SupportedFeatures  string              `json:"supportedFeatures,omitempty"`
}

// N2InfoContainer carries N2 information (e.g. PDU session resource setup).
// Ref: TS 29.518 §6.1.6.2.15.
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/N2InfoContainer
type N2InfoContainer struct {
	N2InformationClass string `json:"n2InformationClass"`
}

// Arp is the Allocation and Retention Priority. Ref: TS 29.571 §5.5.4.1.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Arp
type Arp struct {
	PriorityLevel int `json:"priorityLevel"`
	// PreemptCap is the preemption capability (NOT_PREEMPT, MAY_PREEMPT). Held as
	// a plain string: the enum is extensible (anyOf enum + string), so unknown
	// values pass through and are never rejected. Omitted when empty, so
	// legacy peers see unchanged bytes. Ref: TS 29.571 §5.5.4.1.
	PreemptCap string `json:"preemptCap,omitempty"`
	// PreemptVuln is the preemption vulnerability (NOT_PREEMPTABLE, PREEMPTABLE);
	// tolerant string as PreemptCap. Ref: TS 29.571 §5.5.4.1.
	PreemptVuln string `json:"preemptVuln,omitempty"`
}

// N1N2MessageTransferRspData is the response body of N1N2MessageTransfer.
// Ref: TS 29.518 §6.1.6.2.19.
//
// oapi: TS29518_Namf_Communication.yaml#/components/schemas/N1N2MessageTransferRspData
type N1N2MessageTransferRspData struct {
	Cause string `json:"cause"`
	// SupportedFeatures is the negotiated Namf_Communication feature set
	// (TS 29.500 §6.6.2; TS 29.571 §5.2.2); omitted under the rel17 profile
	// when the request carried none.
	SupportedFeatures string `json:"supportedFeatures,omitempty"`
}

// ProblemDetails is the RFC 7807 error body used across SBI.
// Ref: TS 29.571 §5.2.4.1.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/ProblemDetails
type ProblemDetails struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title,omitempty"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Cause  string `json:"cause,omitempty"`
	// InvalidParams lists the request parameters that failed validation.
	// Ref: TS 29.571 §5.2.4.6 (InvalidParam).
	InvalidParams []InvalidParam `json:"invalidParams,omitempty"`
}

// ---- Namf_Location (TS 29.518 §5.5, §6.4) ----

// RequestLocInfo is the body of Namf_Location_ProvideLocationInfo (LMF → AMF).
// Ref: TS 29.518 §6.4.6.2.5 (RequestLocInfo); TS 23.273 §7.2.
//
// oapi: TS29518_Namf_Location.yaml#/components/schemas/RequestLocInfo
type RequestLocInfo struct {
	// Req5gsLoc requests the 5GS location (TAI + NRCGI of serving cell). It is
	// conditional, not mandatory: absent/false means "not requested" (TS 29.518
	// Table 6.4.6.2.5-1). rel17 (frozen) still rejects such a request with
	// 400; rel19 answers the NPLI that was requested without a location.
	Req5gsLoc bool `json:"req5gsLoc"`
	// ReqCurrentLoc requests a fresh measurement (triggers NGAP LocationReportingControl).
	// When false the AMF may return last-known location.
	ReqCurrentLoc bool `json:"reqCurrentLoc,omitempty"`
	// ReqRatType requests the RAT type of the UE in the NPLI.
	// Ref: TS 29.518 Table 6.4.6.2.5-1.
	ReqRatType bool `json:"reqRatType,omitempty"`
	// ReqTimeZone requests the local time zone of the UE. The AMF keeps no UE
	// time zone, so it is never returned (timezone is optional, Table 6.4.6.2.6-1).
	ReqTimeZone bool `json:"reqTimeZone,omitempty"`
	// (The LMF client still sends a supportedGADShapes member for the rel17
	// baseline; RequestLocInfo has no such attribute and the AMF never used it,
	// so it is ignored on decode, TS 29.500 §6.6.2.)
}

// LocationData is the Rel-17-profile Namf_Location response body (AMF → LMF).
// Carries the serving cell NRCGI and TAI from the NGAP LocationReport.
// It is the frozen baseline wire shape: it is NOT the TS 29.518 ProvideLocInfo
// data type. Under the rel19 profile the AMF answers with ProvideLocInfo
// instead (see handleProvideLocInfo); the LMF consumer decodes both.
// Ref: TS 29.518 §6.4.6.2.6 (ProvideLocInfo, legacy shape); TS 29.572 §6.1.6.2.2.
//
// oapi: none legacy Rel-17-profile wire shape of ProvideLocInfo, see ProvideLocInfo
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

// ProvideLocInfo is the Namf_Location_ProvideLocationInfo 200 response body
// under the rel19 (spec-literal) profile.
// Ref: TS 29.518 §6.4.6.2.6 (ProvideLocInfo), §5.5.2.4.
//
// oapi: TS29518_Namf_Location.yaml#/components/schemas/ProvideLocInfo
type ProvideLocInfo struct {
	// CurrentLoc is true when the location is the current one (fresh NGAP
	// LocationReport), false when it is the last known one. Present only when
	// the 5GS location was requested (TS 29.518 Table 6.4.6.2.6-1), hence a
	// pointer: an NPLI answer without a location omits it.
	CurrentLoc *bool `json:"currentLoc,omitempty"`
	// Location is the 5GS user location (nrLocation for the NR serving cell).
	Location *UserLocation `json:"location,omitempty"`
	// GeoInfo is the geographical area of the UE; omitted by this AMF, which
	// has no real point estimate (the Cell-ID position is derived by the LMF).
	GeoInfo *GeographicArea `json:"geoInfo,omitempty"`
	// LocationAge is the age of the location estimate in minutes (0 = fresh);
	// omitted with the location (optional, Table 6.4.6.2.6-1).
	LocationAge *int `json:"locationAge,omitempty"`
	// RatType is the RAT of the serving access (TS 29.571 §5.4.3.2 RatType).
	RatType string `json:"ratType,omitempty"`
}

// UserLocation is the TS 29.571 user location; only the NR leg is produced.
// Ref: TS 29.571 UserLocation schema.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/UserLocation
type UserLocation struct {
	NrLocation *NrLocation `json:"nrLocation,omitempty"`
}

// NrLocation is the NR user location (serving TAI + NCGI).
// Ref: TS 29.571 NrLocation schema.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/NrLocation
type NrLocation struct {
	// Tai is mandatory.
	Tai TaiLoc `json:"tai"`
	// Ncgi is mandatory.
	Ncgi Ncgi `json:"ncgi"`
	// AgeOfLocationInformation is minutes since the last network contact
	// (0 = obtained after a successful NG-RAN location reporting procedure).
	AgeOfLocationInformation int `json:"ageOfLocationInformation"`
}

// Ncgi is the NR Cell Global Identity.
// Ref: TS 29.571 Ncgi schema.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Ncgi
type Ncgi struct {
	PlmnId PlmnID `json:"plmnId"`
	// NrCellId is the 36-bit NR cell identity as 9 hex characters.
	NrCellId string `json:"nrCellId"`
}

// GeographicArea holds a minimal GAD POINT shape (lat/lon).
// Ref: TS 29.572 §6.1.6.2.x; TS 29.571 §5.4.4.x.
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/Point
type GeographicArea struct {
	Shape string  `json:"shape"` // "POINT" for Cell-ID MVP
	Point *LatLon `json:"point,omitempty"`
}

// LatLon is a WGS84 coordinate pair.
//
// oapi: TS29572_Nlmf_Location.yaml#/components/schemas/GeographicalCoordinates
type LatLon struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

// TaiLoc is the Tracking Area Identity carried in LocationData.
// Ref: TS 29.571 §5.4.4.3; TS 38.413 §9.3.1.x.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/Tai
type TaiLoc struct {
	PlmnId PlmnID `json:"plmnId"`
	Tac    string `json:"tac"` // 3-byte hex, e.g. "000001"
}

// ---- Cause constants for Namf_Location errors ----

// CauseSystemFailure is the generic 500 application error used when the AMF
// cannot build a spec-valid answer (rel19 ProvideLocInfo without TAI/NCGI).
// table 6.4.3.2.4.3.2-2 of TS 29.518 lists no 5xx cause, so the TS 29.500
// §5.2.7.2 generic 500 cause applies.
const CauseSystemFailure = "SYSTEM_FAILURE"

// CauseLocationFailure is returned when the NGAP location exchange fails or times out.
// Ref: TS 29.572 §6.1.x; TS 29.518 §5.2.2.6.
const CauseLocationFailure = "LOCATION_FAILURE"

// CauseNRPPaRelayFailure is returned when the NGAP NRPPa Transport exchange fails or times out.
// Ref: TS 38.413 §8.17.3; TS 29.518 §5.2.2.6 (error path for NRPPa relay).
const CauseNRPPaRelayFailure = "NRPPA_RELAY_FAILURE"

// nrppaTimeout is the maximum time the dl-nrppa-info handler waits for a matching
// UplinkUEAssociatedNRPPaTransport from the gNB. Mirrors locationTimeout.
// Ref: TS 23.273 §7.2 (guard timer for NRPPa relay path); TS 38.455 §8.2.
const nrppaTimeout = 10 * time.Second

// ---- NRPPa relay SBI types (Namf_Location, TS 29.518 §5.2.2.6 extension) ----

// DLNRPPaInfoReq is the request body for POST .../dl-nrppa-info.
// The LMF sends a base64-encoded NRPPa PDU; the AMF relays it transparently to the gNB.
// Ref: TS 29.518 §5.2.2.6; TS 38.455 §8.2 (NRPPa transparent container).
//
// oapi: none project extension of Namf_Location (dl-nrppa-info / dl-lpp-info relay; 3GPP equivalent: Namf_Communication N1N2MessageTransfer with NrppaInformation / N1 class LPP), no YAML path
type DLNRPPaInfoReq struct {
	// NrppaPdu is the base64url-encoded NRPPa PDU to relay to the gNB.
	// The AMF MUST NOT inspect or modify this content.
	// Ref: TS 38.413 §9.3.x (NRPPa-PDU IE id=46, opaque container).
	NrppaPdu string `json:"nrppaPdu"`
	// RoutingId is the optional LMF routing identity (base64url-encoded).
	// Carried as NGAP RoutingID IE id=89.
	// Ref: TS 38.413 §9.3.x (Routing ID IE).
	RoutingId string `json:"routingId,omitempty"`
}

// DLNRPPaInfoRsp is the response body for POST .../dl-nrppa-info (HTTP 200).
// Carries the UL NRPPa PDU received from the gNB, base64url-encoded.
// Ref: TS 29.518 §5.2.2.6.
//
// oapi: none project extension of Namf_Location (dl-nrppa-info / dl-lpp-info relay; 3GPP equivalent: Namf_Communication N1N2MessageTransfer with NrppaInformation / N1 class LPP), no YAML path
type DLNRPPaInfoRsp struct {
	// NrppaPdu is the base64url-encoded UL NRPPa PDU received from the gNB.
	NrppaPdu string `json:"nrppaPdu"`
}

// ---- LPP relay SBI types (Namf_Location, TS 29.518 §5.2.2.6 extension, LMF-005) ----

// CauseLPPRelayFailure is returned when the DL/UL LPP relay over NAS N1 fails
// or times out. Ref: TS 24.501 §8.7.4; TS 23.273 §7.2; TS 29.518 §5.2.2.6.
const CauseLPPRelayFailure = "LPP_RELAY_FAILURE"

// lppTimeout is the maximum time the dl-lpp-info handler waits for a matching
// UL NAS Transport (payload container type 0x03) from the UE. Mirrors
// nrppaTimeout; TS 23.273 §7.2 has no normative timer for this guard.
const lppTimeout = 10 * time.Second

// DLLPPInfoReq is the request body for POST .../dl-lpp-info.
// The LMF sends a base64-encoded opaque LPP-PDU; the AMF relays it
// transparently to the UE via a DL NAS Transport (payload container type
// 0x03) — it MUST NOT inspect or modify this content.
// Ref: TS 29.518 §5.2.2.6; TS 24.501 §8.7.4 / §9.11.3.40; TS 37.355 §6.
//
// oapi: none project extension of Namf_Location (dl-nrppa-info / dl-lpp-info relay; 3GPP equivalent: Namf_Communication N1N2MessageTransfer with NrppaInformation / N1 class LPP), no YAML path
type DLLPPInfoReq struct {
	// LppPdu is the base64-encoded LPP-PDU to relay to the UE.
	LppPdu string `json:"lppPdu"`
	// LppTransactionId is an optional LMF-assigned correlation aid (not used
	// for AMF-side correlation, which keys on AMF-UE-NGAP-ID).
	LppTransactionId int64 `json:"lppTransactionId,omitempty"`
	// ExpectUlResponse (ADDITIVE, LMF-009; nil/absent defaults to true)
	// selects the relay mode. true: LMF-005 synchronous behaviour — register
	// a pendingLPP waiter, block for the matching UL NAS Transport
	// (PCT=0x03), return 200 with the UL LPP-PDU. false (DL-only leg —
	// TS 37.355 assistance-data delivery is unsolicited with no response
	// message): send the DL NAS Transport and return 204 No Content
	// immediately, WITHOUT registering a waiter.
	// Ref: docs/procedures/LPPRelay.md §Endpoints; TS 37.355 §6.5.2.
	ExpectUlResponse *bool `json:"expectUlResponse,omitempty"`
}

// DLLPPInfoRsp is the response body for POST .../dl-lpp-info (HTTP 200).
// Carries the UL LPP-PDU received from the UE, base64-encoded.
// Ref: TS 29.518 §5.2.2.6.
//
// oapi: none project extension of Namf_Location (dl-nrppa-info / dl-lpp-info relay; 3GPP equivalent: Namf_Communication N1N2MessageTransfer with NrppaInformation / N1 class LPP), no YAML path
type DLLPPInfoRsp struct {
	// LppPdu is the base64-encoded UL LPP-PDU received from the UE.
	LppPdu string `json:"lppPdu"`
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
