package server

// hr_types.go — Nsmf_PDUSession types and helpers shared by the home-routed (HR) roaming roles:
// the H-SMF handlers (hr_hsmf.go) and the V-SMF pass that follows. The JSON types are
// hand-written from specs/3gpp-openapi TS29502_Nsmf_PDUSession.yaml (no codegen); only the
// attributes this SMF reads or writes are modelled, unknown attributes are ignored on decode.
// Design: docs/procedures/HomeRoutedPduSession.md §4, §5, §7.2, §7.4.
// Ref: TS 29.502 §6.1.6.2.9 (PduSessionCreateData), §6.1.6.2.10 (PduSessionCreatedData),
// §6.1.6.2.13 (ReleaseData), §6.1.6.2.37 (PduSessionCreateError); TS 23.501 §4.2.4.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"regexp"
	"strings"
)

// HRRole is the role of this SMF for one home-routed PDU session.
// The empty value is a non-roaming (or LBO) session.
type HRRole string

// HR roles. Ref: TS 23.501 §4.2.4.2 (V-SMF / H-SMF), docs/procedures/HomeRoutedPduSession.md §7.2.
const (
	// HRRoleVSMF is the visited-PLMN SMF anchoring the V-UPF (V-SMF pass).
	HRRoleVSMF HRRole = "VSMF"
	// HRRoleHSMF is the home-PLMN SMF anchoring the H-UPF (this pass).
	HRRoleHSMF HRRole = "HSMF"
)

// HRTunnel is a GTP-U N9 tunnel endpoint (IPv4 + TEID).
type HRTunnel struct {
	IP   net.IP
	TEID uint32
}

// HRSession carries the home-routed attributes of a Session (docs/procedures/HomeRoutedPduSession.md
// §7.2). On the H-SMF PeerTunnel is vcnTunnelInfo (the V-UPF DL N9 endpoint) and Session.ULTEID is
// the H-UPF UL N9 TEID returned in hcnTunnelInfo; the V-SMF pass stores hcnTunnelInfo in PeerTunnel.
type HRSession struct {
	Role HRRole
	// HSmfURI is the API URI of the selected H-SMF (V-SMF side).
	HSmfURI string
	// HSmfPduSessionRef is the pduSessionRef taken from the 201 Location (V-SMF side).
	HSmfPduSessionRef string
	// VSmfPduSessionURI is the V-SMF callback resource (vsmfPduSessionUri, H-SMF side).
	VSmfPduSessionURI string
	// VsmfID is the V-SMF NF instance id (vsmfId, H-SMF side).
	VsmfID string
	// PeerTunnel is the remote N9 endpoint, see the type comment.
	PeerTunnel HRTunnel
	// HplmnSnssai is the HPLMN S-NSSAI of the session.
	HplmnSnssai SliceID
	// N9DLTEID is the V-UPF DL N9 TEID announced in vcnTunnelInfo (V-SMF side).
	N9DLTEID uint32
	// UEIPv4 / UEIPv6Prefix are the H-SMF-allocated UE address (V-SMF side). The V-SMF keeps
	// them here, not in Session.UEIP, so local pool release never touches a foreign address.
	UEIPv4       net.IP
	UEIPv6Prefix string
	// ChargingID is the decimal Charging ID assigned by the V-SMF (TS 32.255 §5.1.9.1).
	ChargingID string
	// OriginPLMN is the "MCC-MNC" of the servingNetwork that created the session (H-SMF side);
	// a release carrying another PLMN in 3gpp-Sbi-Originating-Network-Id is refused (TS 29.500 §5.2.3.2.15).
	OriginPLMN string
	// Per-leg release state (V-SMF side, guarded by Server.sessionMu, in memory only). A leg flag is set
	// only when that leg really succeeded, so the later DeleteSMContext (vsmfReleaseHome) retries just the
	// missing legs: HomeN16Done = H-SMF told (N16 Update 2xx or N16 Release 2xx/204 or no ref),
	// VUPFDeleted = V-UPF N4 session deleted (or N4 stale / nothing to delete).
	HomeN16Done bool
	VUPFDeleted bool
	// UEReleaseInProgress marks a UE-initiated release (0xD1) being processed; a concurrent request gets
	// 409 PDU_SESSION_RELEASING and a DELETE arriving meanwhile sets DeleteDeferred (the handler then
	// finishes the missing legs itself). UEReleaseDone/UEReleaseResult make a retransmission after
	// completion answer the same Release Command with the real earlier result label.
	UEReleaseInProgress bool
	UEReleaseDone       bool
	UEReleaseResult     string
	DeleteDeferred      bool
	// N16UpdateUnknown: the UE-initiated N16 Update got no usable answer, so the H-SMF may have released
	// already; a later N16 Release answered 404 CONTEXT_NOT_FOUND then counts as released.
	N16UpdateUnknown bool
}

// Locking: Session / HRSession fields that change after the session is published in
// Server.sessions (State, N4*, QoS/AMBR, UE address, PDUSessionType, HR.PeerTunnel,
// HR.HSmfPduSessionRef, HR.UEIPv4/UEIPv6Prefix) are read and written with Server.sessionMu held;
// SUPI, PDUSessionID, DNN, SliceID, SEID, ULTEID and HR.{Role,HSmfURI,HplmnSnssai,N9DLTEID,
// ChargingID,OriginPLMN,VsmfID,VSmfPduSessionURI} are set before publication and never written again.

// Application error causes of PostPduSessions / ReleasePduSession answers.
// Ref: TS 29.502 Table 6.1.3.5.3.1-3, Table 6.1.7.3-1; TS 29.500 Table 5.2.7.2-1.
const (
	causeMandatoryIEMissing   = "MANDATORY_IE_MISSING"
	causeMandatoryIEIncorrect = "MANDATORY_IE_INCORRECT"
	causeInvalidMsgFormat     = "INVALID_MSG_FORMAT"
	causeDNNDenied            = "DNN_DENIED"
	causeDNNNotSupported      = "DNN_NOT_SUPPORTED"
	causeSNSSAIDenied         = "SNSSAI_DENIED"
	causeSubscriptionDenied   = "SUBSCRIPTION_DENIED"
	causeN1SMError            = "N1_SM_ERROR"
	causeNotSupportedWithISMF = "NOT_SUPPORTED_WITH_ISMF"
	causeInsufficientResSlice = "INSUFFICIENT_RESOURCES_SLICE_DNN"
	causeContextNotFound      = "CONTEXT_NOT_FOUND"
	causeInsufficientResSl    = "INSUFFICIENT_RESOURCES_SLICE"
	causeDNNCongestion        = "DNN_CONGESTION"
	causeSNSSAICongestion     = "S_NSSAI_CONGESTION"
	// causeMaxJSONSizeExceeded is the 413 cause of TS 29.500 Table 5.2.7.2-1; causePLMNIDMismatch the
	// 403 cause of TS 29.500 Table 5.2.7.4-1 (PLMN of the caller differs from the one of the context).
	causeMaxJSONSizeExceeded = "MAX_JSON_SIZE_EXCEEDED"
	causePLMNIDMismatch      = "PLMNID_MISMATCH"
	// causeMissingParameter is the 403 cause of TS 29.500 Table 5.2.7.2-1 "one or more information
	// elements of the requester required to authorize the requester are missing" (a missing
	// 3gpp-Sbi-Originating-Network-Id on the ReleasePduSession / Update requests, D/#17).
	causeMissingParameter = "MISSING_PARAMETER"
)

// 5GSM cause values proposed in PduSessionCreateError.n1smCause (TS 24.501 §9.11.4.2).
const (
	n1smCauseInsufficientResources = 26  // #26
	n1smCauseMissingOrUnknownDNN   = 27  // #27
	n1smCauseUnknownPDUType        = 28  // #28
	n1smCauseNotSubscribed         = 33  // #33
	n1smCauseNetworkFailure        = 38  // #38
	n1smCauseInsufficientResSlice  = 67  // #67 (slice and DNN)
	n1smCauseProtocolError         = 111 // #111
)

// JSON types ------------------------------------------------------------------------------

// HRSnssai is Snssai (TS 29.571 §5.4.4.2).
type HRSnssai struct {
	SST int    `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// HRPlmnIDNid is PlmnIdNid (TS 29.571 §5.4.4.33).
type HRPlmnIDNid struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
	NID string `json:"nid,omitempty"`
}

// HRTunnelInfo is TunnelInfo (TS 29.502 §6.1.6.2.28); gtpTeid is 8 hex digits.
type HRTunnelInfo struct {
	IPv4Addr string `json:"ipv4Addr,omitempty"`
	IPv6Addr string `json:"ipv6Addr,omitempty"`
	GtpTeid  string `json:"gtpTeid"`
	AnType   string `json:"anType,omitempty"`
}

// HRRefToBinaryData is RefToBinaryData (TS 29.571 §5.4.4.14).
type HRRefToBinaryData struct {
	ContentID string `json:"contentId"`
}

// HRAmbr is Ambr (TS 29.571 §5.5.4.2), e.g. "100000 Kbps".
type HRAmbr struct {
	Uplink   string `json:"uplink"`
	Downlink string `json:"downlink"`
}

// HRArp is Arp (TS 29.571 §5.5.4.1).
type HRArp struct {
	PriorityLevel int    `json:"priorityLevel"`
	PreemptCap    string `json:"preemptCap"`
	PreemptVuln   string `json:"preemptVuln"`
}

// HRQosFlowProfile is QosFlowProfile (TS 29.502 §6.1.6.2.22), non-GBR subset.
type HRQosFlowProfile struct {
	FiveQI int    `json:"5qi"`
	ARP    *HRArp `json:"arp,omitempty"`
}

// HRQosFlowSetupItem is QosFlowSetupItem (TS 29.502 §6.1.6.2.19); qosRules and
// qosFlowDescription are base64 (TS 29.571 Bytes) of TS 24.501 §9.11.4.13 / §9.11.4.12 octets.
type HRQosFlowSetupItem struct {
	QFI                int               `json:"qfi"`
	QosRules           string            `json:"qosRules"`
	QosFlowDescription string            `json:"qosFlowDescription,omitempty"`
	QosFlowProfile     *HRQosFlowProfile `json:"qosFlowProfile,omitempty"`
	DefaultQosRuleInd  bool              `json:"defaultQosRuleInd,omitempty"`
}

// PduSessionCreateData is the body of PostPduSessions (TS 29.502 Table 6.1.6.2.9-1).
type PduSessionCreateData struct {
	SUPI              string        `json:"supi,omitempty"`
	PEI               string        `json:"pei,omitempty"`
	PduSessionID      *int          `json:"pduSessionId,omitempty"`
	DNN               string        `json:"dnn"`
	SNSSAI            *HRSnssai     `json:"sNssai,omitempty"`
	VsmfID            string        `json:"vsmfId,omitempty"`
	IsmfID            string        `json:"ismfId,omitempty"`
	ServingNetwork    *HRPlmnIDNid  `json:"servingNetwork"`
	RequestType       string        `json:"requestType,omitempty"`
	EpsBearerID       []int         `json:"epsBearerId,omitempty"`
	PgwS8cFteid       string        `json:"pgwS8cFteid,omitempty"`
	VsmfPduSessionURI string        `json:"vsmfPduSessionUri,omitempty"`
	IsmfPduSessionURI string        `json:"ismfPduSessionUri,omitempty"`
	VcnTunnelInfo     *HRTunnelInfo `json:"vcnTunnelInfo,omitempty"`
	AnType            string        `json:"anType"`
	RatType           string        `json:"ratType,omitempty"`
	ChargingID        string        `json:"chargingId,omitempty"`
	// MaxIntegrityProtectedDataRateUl/Dl: "64_KBPS" | "MAX_UE_RATE" (TS 29.502 §6.1.6.3.13).
	MaxIntegrityProtectedDataRateUl string             `json:"maxIntegrityProtectedDataRateUl,omitempty"`
	MaxIntegrityProtectedDataRateDl string             `json:"maxIntegrityProtectedDataRateDl,omitempty"`
	N1SmInfoFromUe                  *HRRefToBinaryData `json:"n1SmInfoFromUe,omitempty"`
	UnknownN1SmInfo                 *HRRefToBinaryData `json:"unknownN1SmInfo,omitempty"`
	AlwaysOnRequested               bool               `json:"alwaysOnRequested,omitempty"`
	AmfNfID                         string             `json:"amfNfId,omitempty"`
	SupportedFeatures               string             `json:"supportedFeatures,omitempty"`
	CpCiotEnabled                   bool               `json:"cpCiotEnabled,omitempty"`
}

// PduSessionCreatedData is the 201 body of PostPduSessions (TS 29.502 Table 6.1.6.2.10-1).
type PduSessionCreatedData struct {
	PduSessionType    string               `json:"pduSessionType"`
	SscMode           string               `json:"sscMode"`
	HcnTunnelInfo     *HRTunnelInfo        `json:"hcnTunnelInfo,omitempty"`
	SessionAmbr       *HRAmbr              `json:"sessionAmbr,omitempty"`
	QosFlowsSetupList []HRQosFlowSetupItem `json:"qosFlowsSetupList,omitempty"`
	HSmfInstanceID    string               `json:"hSmfInstanceId,omitempty"`
	UeIPv4Address     string               `json:"ueIpv4Address,omitempty"`
	UeIPv6Prefix      string               `json:"ueIpv6Prefix,omitempty"`
	N1SmInfoToUe      *HRRefToBinaryData   `json:"n1SmInfoToUe,omitempty"`
	SupportedFeatures string               `json:"supportedFeatures,omitempty"`
}

// HRInvalidParam is InvalidParam (TS 29.571 §5.2.4.6); Param is a JSON Pointer.
type HRInvalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

// HRProblemDetails is ProblemDetails (TS 29.571 §5.2.4.1).
type HRProblemDetails struct {
	Title         string           `json:"title,omitempty"`
	Status        int              `json:"status"`
	Detail        string           `json:"detail,omitempty"`
	Cause         string           `json:"cause,omitempty"`
	InvalidParams []HRInvalidParam `json:"invalidParams,omitempty"`
}

// PduSessionCreateError is the 4xx/5xx body of PostPduSessions (TS 29.502 Table 6.1.6.2.37-1).
// N1smCause is two upper-case hex digits (the 5GSM cause the H-SMF proposes).
type PduSessionCreateError struct {
	Error     HRProblemDetails `json:"error"`
	N1smCause string           `json:"n1smCause,omitempty"`
}

// ReleaseData is the body of ReleasePduSession (TS 29.502 Table 6.1.6.2.13-1); all optional.
type ReleaseData struct {
	Cause string `json:"cause,omitempty"`
}

// requestIndication values of HsmfUpdateData (TS 29.502 §6.1.6.3.x RequestIndication). Only the UE
// requested release is implemented by the H-SMF (TS 29.502 §5.2.2.8.2.3).
const (
	requestIndicationUEReqPduSesRel = "UE_REQ_PDU_SES_REL"
	requestIndicationNWReqPduSesRel = "NW_REQ_PDU_SES_REL"
)

// HsmfUpdateData is the request body of the Update (modify) operation towards the H-SMF
// (TS 29.502 Table 6.1.6.2.14-1); only the attributes this SMF sends or reads are modelled.
// PTI is a pointer so that PTI 0 (unassigned) is still serialized.
type HsmfUpdateData struct {
	RequestIndication string `json:"requestIndication,omitempty"`
	PTI               *uint8 `json:"pti,omitempty"`
}

// HsmfUpdatedData is the optional 200 body of the Update operation (TS 29.502 Table 6.1.6.2.15-1).
type HsmfUpdatedData struct {
	PTI *uint8 `json:"pti,omitempty"`
}

// HsmfUpdateError is the 4xx/5xx body of the Update operation (TS 29.502 Table 6.1.6.2.16-1).
type HsmfUpdateError struct {
	Error HRProblemDetails `json:"error"`
	PTI   *uint8           `json:"pti,omitempty"`
}

// Helpers ---------------------------------------------------------------------------------

// checkVcnAddress validates the N9 address announced in vcnTunnelInfo (the H-UPF later sends GTP-U
// to it, so an attacker-chosen address would turn the H-UPF into a reflector towards loopback,
// link-local or multicast targets): loopback, link-local (unicast and multicast), multicast,
// unspecified, "this network" (0.0.0.0/8) and reserved/broadcast (240.0.0.0/4) addresses are refused
// (IPv4-mapped IPv6 is judged by its IPv4 part); an unparsable address is MANDATORY_IE_INCORRECT; when allowed is non-empty the address
// must also lie inside one of its networks.
// It returns the invalid attributes as JSON Pointers (TS 29.571 §5.2.4.6) with a clear reason.
// Ref: TS 29.502 Table 6.1.6.2.28-1 (TunnelInfo); TS 29.500 Table 5.2.7.2-1 MANDATORY_IE_INCORRECT.
func checkVcnAddress(t *HRTunnelInfo, allowed []*net.IPNet) []HRInvalidParam {
	if t == nil {
		return nil
	}
	var bad []HRInvalidParam
	check := func(param, raw string) {
		ip := net.ParseIP(raw)
		if ip == nil {
			bad = append(bad, HRInvalidParam{Param: param, Reason: "vcnTunnelInfo address is not a valid IP address"})
			return
		}
		if why := unroutableN9Class(ip); why != "" {
			bad = append(bad, HRInvalidParam{Param: param, Reason: "vcnTunnelInfo address not routable: " + why})
			return
		}
		if len(allowed) == 0 {
			return
		}
		for _, n := range allowed {
			if n.Contains(ip) {
				return
			}
		}
		bad = append(bad, HRInvalidParam{Param: param, Reason: "vcnTunnelInfo address not in the allowed V-UPF N9 networks"})
	}
	if t.IPv4Addr != "" {
		check("/vcnTunnelInfo/ipv4Addr", t.IPv4Addr)
	}
	if t.IPv6Addr != "" {
		check("/vcnTunnelInfo/ipv6Addr", t.IPv6Addr)
	}
	return bad
}

// unroutableN9Class names the address class that can never be a V-UPF N9 endpoint, "" when none.
func unroutableN9Class(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast():
		return "link-local"
	case ip.IsLinkLocalMulticast():
		return "link-local multicast"
	case ip.IsMulticast():
		return "multicast"
	case ip.Equal(net.IPv4bcast):
		return "limited broadcast"
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0:
			return "this-network 0.0.0.0/8"
		case v4[0] >= 240:
			return "reserved 240.0.0.0/4"
		}
	}
	return ""
}

// n1smCauseHex formats a 5GSM cause as the two upper-case hex digits of PduSessionCreateError.n1smCause.
func n1smCauseHex(c int) string { return fmt.Sprintf("%02X", c) }

var (
	// fullDNNSuffixRe matches the Operator Identifier of a full DNN:
	// ".mnc<3 digits>.mcc<3 digits>.gprs" (TS 23.003 §9.1.2, case-insensitive per TS 29.571 Dnn).
	fullDNNSuffixRe = regexp.MustCompile(`(?i)\.mnc[0-9]{3}\.mcc[0-9]{3}\.gprs$`)
	// chargingIDRe is the Charging ID pattern: decimal 32-bit (TS 29.502 §6.1.6.2.9).
	chargingIDRe = regexp.MustCompile(`^(0|([1-9][0-9]{0,9}))$`)
)

// stripDNNOperatorID returns the DNN Network Identifier of a full DNN (NI + Operator Identifier);
// a DNN without Operator Identifier is returned unchanged. Ref: TS 23.003 §9.1.2; TS 29.571 Dnn.
func stripDNNOperatorID(dnn string) string {
	return fullDNNSuffixRe.ReplaceAllString(dnn, "")
}

// parseHRTunnel parses a TunnelInfo into an IPv4 N9 endpoint. It returns an error when the
// IPv4 address is missing/invalid or gtpTeid is not 8 hex digits (TS 29.502 §6.1.6.3.2 Teid).
func parseHRTunnel(t *HRTunnelInfo) (HRTunnel, error) {
	if t == nil {
		return HRTunnel{}, fmt.Errorf("smf: tunnel info missing")
	}
	b, err := hex.DecodeString(t.GtpTeid)
	if err != nil || len(b) != 4 {
		return HRTunnel{}, fmt.Errorf("smf: gtpTeid %q is not 8 hex digits", t.GtpTeid)
	}
	ip := net.ParseIP(t.IPv4Addr).To4()
	if ip == nil {
		return HRTunnel{}, fmt.Errorf("smf: ipv4Addr %q invalid", t.IPv4Addr)
	}
	return HRTunnel{IP: ip, TEID: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])}, nil
}

// formatTEID renders a TEID as the 8-hex-digit Teid string (TS 29.502 §6.1.6.3.2).
func formatTEID(t uint32) string { return fmt.Sprintf("%08X", t) }

// validatePduSessionCreateData checks the required attributes and the HR conditionals of
// PduSessionCreateData (TS 29.502 Table 6.1.6.2.9-1). It returns the missing and the incorrect
// attributes as JSON Pointers (TS 29.571 §5.2.4.6).
func validatePduSessionCreateData(d *PduSessionCreateData) (missing, incorrect []HRInvalidParam) {
	miss := func(p string) {
		missing = append(missing, HRInvalidParam{Param: p, Reason: "mandatory attribute missing"})
	}
	bad := func(p, why string) { incorrect = append(incorrect, HRInvalidParam{Param: p, Reason: why}) }

	if d.DNN == "" {
		miss("/dnn")
	}
	if d.ServingNetwork == nil {
		miss("/servingNetwork")
	} else if d.ServingNetwork.MCC == "" || d.ServingNetwork.MNC == "" {
		bad("/servingNetwork", "mcc and mnc are required")
	}
	if d.AnType == "" {
		miss("/anType")
	}
	// HR conditionals: "shall be present for a HR PDU session" (Table 6.1.6.2.9-1).
	if d.VsmfID == "" {
		miss("/vsmfId")
	}
	if d.VsmfPduSessionURI == "" {
		miss("/vsmfPduSessionUri")
	}
	if d.VcnTunnelInfo == nil {
		miss("/vcnTunnelInfo")
	} else if _, err := parseHRTunnel(d.VcnTunnelInfo); err != nil {
		bad("/vcnTunnelInfo", err.Error())
	}
	// Attributes this H-SMF needs to look up the subscription and key the session.
	if d.SUPI == "" {
		miss("/supi")
	}
	if d.PduSessionID == nil {
		miss("/pduSessionId")
	} else if *d.PduSessionID < 1 || *d.PduSessionID > 15 {
		bad("/pduSessionId", "must be 1..15")
	}
	if d.SNSSAI == nil {
		miss("/sNssai")
	}
	if d.ChargingID != "" && !chargingIDRe.MatchString(d.ChargingID) {
		bad("/chargingId", "must match "+chargingIDRe.String())
	}
	return missing, incorrect
}

// unsupportedHRFeature returns the JSON Pointer of the first attribute that selects functionality
// this H-SMF does not provide (I-SMF pair, CP CIoT, EPS interworking), or "".
// Ref: TS 29.502 §5.2.2.7.1 step 2b ("requested functionality not supported").
func unsupportedHRFeature(d *PduSessionCreateData) string {
	switch {
	case d.IsmfID != "":
		return "/ismfId"
	case d.IsmfPduSessionURI != "":
		return "/ismfPduSessionUri"
	case d.CpCiotEnabled:
		return "/cpCiotEnabled"
	case len(d.EpsBearerID) > 0:
		return "/epsBearerId"
	case d.PgwS8cFteid != "":
		return "/pgwS8cFteid"
	}
	return ""
}

// Content-Type / part names of the multipart/related PostPduSessions request (TS 29.502 §6.1.3.5.2.2).
const (
	mediaTypeJSON         = "application/json"
	mediaTypeMultipartRel = "multipart/related"
)

// Limits on N16 message bodies (implementation guards against a misbehaving peer, not 3GPP values).
const (
	// maxHRRequestBody bounds a whole N16 request body read by the H-SMF (TS 29.500 §5.2.7.2-1
	// MAX_JSON_SIZE_EXCEEDED family: oversize content is rejected).
	maxHRRequestBody = 1 << 20
	// maxHRPartBytes bounds one body part (JSON or binary).
	maxHRPartBytes = 1 << 20
	// maxHRMultipartParts bounds the parts of a multipart/related N16 message: the JSON part,
	// n1SmInfoFromUe and unknownN1SmInfo (TS 29.502 §6.1.3.5.2.2) plus one spare.
	maxHRMultipartParts = 4
	// maxHRSmDataBody bounds the UDM sm-data answer read by the H-SMF.
	maxHRSmDataBody = 1 << 20
)

// errHRBodyTooLarge is returned when an N16 body or body part exceeds its limit.
var errHRBodyTooLarge = errors.New("smf: n16 body too large")

// hrMultipartBody is a decoded PostPduSessions request: the JSON part and the binary parts by Content-Id.
type hrMultipartBody struct {
	JSON  []byte
	Parts map[string][]byte
}

// readLimited reads at most limit bytes and fails with errHRBodyTooLarge when more follow.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errHRBodyTooLarge
	}
	return b, nil
}

// readHRBody reads a PostPduSessions request body: plain application/json, or multipart/related
// whose first part is the JSON and whose other parts are binary, keyed by Content-Id (without
// angle brackets). At most maxHRMultipartParts parts of maxHRPartBytes each are accepted.
// Ref: TS 29.500 §6.1.2.4 (multipart messages), TS 29.502 §6.1.3.5.2.2.
func readHRBody(contentType string, body io.Reader) (*hrMultipartBody, error) {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mt, mediaTypeMultipartRel) {
		b, rerr := readLimited(body, maxHRPartBytes)
		if rerr != nil {
			return nil, fmt.Errorf("smf: read body: %w", rerr)
		}
		return &hrMultipartBody{JSON: b}, nil
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("smf: multipart/related without boundary")
	}
	mr := multipart.NewReader(body, boundary)
	out := &hrMultipartBody{Parts: map[string][]byte{}}
	first := true
	for n := 0; ; n++ {
		p, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			return nil, fmt.Errorf("smf: multipart part: %w", perr)
		}
		if n >= maxHRMultipartParts {
			return nil, fmt.Errorf("smf: multipart/related has more than %d parts: %w", maxHRMultipartParts, errHRBodyTooLarge)
		}
		b, rerr := readLimited(p, maxHRPartBytes)
		if rerr != nil {
			return nil, fmt.Errorf("smf: multipart read: %w", rerr)
		}
		if first {
			out.JSON = b
			first = false
			continue
		}
		id := strings.Trim(p.Header.Get("Content-Id"), "<> ")
		out.Parts[id] = b
	}
	if out.JSON == nil {
		return nil, fmt.Errorf("smf: multipart/related without JSON part")
	}
	return out, nil
}

// n1IEFormat is the wire format of a 5GSM IE of the PDU SESSION ESTABLISHMENT REQUEST.
type n1IEFormat uint8

const (
	n1IEHalf  n1IEFormat = iota // type 1 (TV, half octet) or type 2 (T): one octet in total
	n1IEFixed                   // TV with a fixed total length (n1IEInfo.total)
	n1IETLV                     // type 4: IEI, 1-octet length, value
	n1IETLVE                    // type 6: IEI, 2-octet length, value
)

type n1IEInfo struct {
	format n1IEFormat
	total  int // n1IEFixed only
}

// n1ComprehendedIEs lists the optional IEs of the PDU SESSION ESTABLISHMENT REQUEST this V-SMF
// knows (TS 24.501 Table 8.3.1.1.1); the key of a half-octet IE is its high nibble << 4. These
// are carried in n1SmInfoFromUe, except Always-on PDU session requested (0xB-) which is mapped to
// PduSessionCreateData.alwaysOnRequested; any other IEI is unknown to the V-SMF and goes in
// unknownN1SmInfo. Ref: TS 29.502 §5.2.3.1.2; TS 24.501 §8.3.1.
var n1ComprehendedIEs = map[byte]n1IEInfo{
	0x90: {format: n1IEHalf},            // PDU session type
	0xA0: {format: n1IEHalf},            // SSC mode
	0x28: {format: n1IETLV},             // 5GSM capability
	0x55: {format: n1IEFixed, total: 3}, // Maximum number of supported packet filters
	0x39: {format: n1IETLV},             // SM PDU DN request container
	0x7B: {format: n1IETLVE},            // Extended protocol configuration options
	0x66: {format: n1IETLV},             // IP header compression configuration
	0x6E: {format: n1IETLV},             // DS-TT Ethernet port MAC address
	0x6F: {format: n1IETLV},             // UE-DS-TT residence time
	0x74: {format: n1IETLVE},            // Port management information container
	0x1F: {format: n1IETLV},             // Ethernet header compression configuration
	0x29: {format: n1IETLV},             // Suggested interface identifier
	0x72: {format: n1IETLVE},            // Service-level-AA container
	0x70: {format: n1IETLVE},            // Requested MBS container
	0x34: {format: n1IETLV},             // PDU session pair ID
	0x35: {format: n1IETLV},             // RSN
	0x36: {format: n1IETLV},             // URSP rule enforcement reports
}

// splitN1SmInfoFromUe splits the optional IEs of a PDU SESSION ESTABLISHMENT REQUEST (after the
// integrity protection maximum data rate) into the IEs the V-SMF comprehends (n1SmInfoFromUe)
// and those it does not (unknownN1SmInfo), preserving the order inside each part. An IE of
// unknown IEI is sized by the TS 24.007 §11.2.4 rule (bit 8 set: one octet; 0x70-0x7F: TLV-E;
// otherwise TLV). Bytes that cannot be framed are kept in the comprehended part unchanged.
// Ref: TS 29.502 §5.2.3.1.2; TS 24.007 §11.2.4.
func splitN1SmInfoFromUe(b []byte) (known, unknown []byte) {
	known, unknown, _ = splitN1SmInfo(b)
	return known, unknown
}

// n1IEIAlwaysOn is the high nibble of the Always-on PDU session requested IE (type 1, TS 24.501
// §9.11.4.4, Table 8.3.1.1.1); bit 1 = 1 means "always-on PDU session requested".
const n1IEIAlwaysOn = 0xB0

// splitN1SmInfo is splitN1SmInfoFromUe plus the Always-on PDU session requested IE: that IE is
// removed from both parts and reported as alwaysOn (-> alwaysOnRequested, TS 29.502 Table
// 6.1.6.2.9-1; the binary n1SmInfoFromUe must not duplicate it).
func splitN1SmInfo(b []byte) (known, unknown []byte, alwaysOn bool) {
	for i := 0; i < len(b); {
		iei := b[i]
		if iei&0xF0 == n1IEIAlwaysOn {
			alwaysOn = alwaysOn || iei&0x01 == 1
			i++
			continue
		}
		key := iei
		if iei >= 0x80 {
			key = iei & 0xF0
		}
		info, ok := n1ComprehendedIEs[key]
		if !ok {
			switch {
			case iei >= 0x80:
				info = n1IEInfo{format: n1IEHalf}
			case iei >= 0x70:
				info = n1IEInfo{format: n1IETLVE}
			default:
				info = n1IEInfo{format: n1IETLV}
			}
		}
		n := 0
		switch info.format {
		case n1IEHalf:
			n = 1
		case n1IEFixed:
			n = info.total
		case n1IETLV:
			if i+1 < len(b) {
				n = 2 + int(b[i+1])
			}
		case n1IETLVE:
			if i+2 < len(b) {
				n = 3 + (int(b[i+1])<<8 | int(b[i+2]))
			}
		}
		if n == 0 || i+n > len(b) {
			known = append(known, b[i:]...) // unframeable tail: forward unchanged
			return known, unknown, alwaysOn
		}
		if ok {
			known = append(known, b[i:i+n]...)
		} else {
			unknown = append(unknown, b[i:i+n]...)
		}
		i += n
	}
	return known, unknown, alwaysOn
}
