// cause.go: complete 5GMM cause (TS 24.501 §9.11.3.2, Table
// 9.11.3.2.1) and 5GSM cause (§9.11.4.2, Table 9.11.4.2.1) value sets,
// transcribed from V19.8.0, with the release that first lists each value and
// the spec-mandated mapping of unknown values.
//
// Constants only: no encoder or decoder in this package changes behaviour
// because of this file.

package nas

import (
	"strconv"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// 5GMM cause values (TS 24.501 §9.11.3.2, Table 9.11.3.2.1, V19.8.0).
// The Cause5GMM type and the first values (#3-#22, #90-#92, #111) are declared
// in ie.go. Values #8, #14, #16-#19, #25, #29,
// #30, #32-#35, #37-#42, #44-#61, #63, #64, #66, #68, #70 and #83-#89 are not
// in the table and are handled by Cause5GMMUnknownMapping.
const (
	// CauseUESecurityCapabilitiesMismatch is #23 "UE security capabilities mismatch" (Rel-15).
	CauseUESecurityCapabilitiesMismatch Cause5GMM = 23
	// CauseSecurityModeRejectedUnspecified is #24 "Security mode rejected, unspecified" (Rel-15).
	CauseSecurityModeRejectedUnspecified Cause5GMM = 24
	// CauseNon5GAuthenticationUnacceptable is #26 "Non-5G authentication unacceptable" (Rel-15).
	CauseNon5GAuthenticationUnacceptable Cause5GMM = 26
	// CauseN1ModeNotAllowed is #27 "N1 mode not allowed" (Rel-15).
	CauseN1ModeNotAllowed Cause5GMM = 27
	// CauseRestrictedServiceArea is #28 "Restricted service area" (Rel-15).
	CauseRestrictedServiceArea Cause5GMM = 28
	// CauseRedirectionToEPCRequired is #31 "Redirection to EPC required" (Rel-16).
	CauseRedirectionToEPCRequired Cause5GMM = 31
	// CauseIABNodeOperationNotAuthorized is #36 "IAB-node operation not authorized" (Rel-16).
	CauseIABNodeOperationNotAuthorized Cause5GMM = 36
	// CauseLADNNotAvailable is #43 "LADN not available" (Rel-15).
	CauseLADNNotAvailable Cause5GMM = 43
	// CauseNoNetworkSlicesAvailable is #62 "No network slices available" (Rel-16).
	CauseNoNetworkSlicesAvailable Cause5GMM = 62
	// CauseMaxPDUSessionsReached is #65 "Maximum number of PDU sessions reached" (Rel-15).
	CauseMaxPDUSessionsReached Cause5GMM = 65
	// CauseInsufficientResourcesSliceDNN is #67 "Insufficient resources for specific slice and DNN" (Rel-15).
	CauseInsufficientResourcesSliceDNN Cause5GMM = 67
	// CauseInsufficientResourcesSlice is #69 "Insufficient resources for specific slice" (Rel-15).
	CauseInsufficientResourcesSlice Cause5GMM = 69
	// CausengKSIAlreadyInUse is #71 "ngKSI already in use" (Rel-15).
	CausengKSIAlreadyInUse Cause5GMM = 71
	// CauseNon3GPPAccessNotAllowed is #72 "Non-3GPP access to 5GCN not allowed" (Rel-15).
	CauseNon3GPPAccessNotAllowed Cause5GMM = 72
	// CauseServingNetworkNotAuthorized is #73 "Serving network not authorized" (Rel-15).
	CauseServingNetworkNotAuthorized Cause5GMM = 73
	// CauseTempNotAuthorizedForSNPN is #74 "Temporarily not authorized for this SNPN" (Rel-16).
	CauseTempNotAuthorizedForSNPN Cause5GMM = 74
	// CausePermNotAuthorizedForSNPN is #75 "Permanently not authorized for this SNPN" (Rel-16).
	CausePermNotAuthorizedForSNPN Cause5GMM = 75
	// CauseNotAuthorizedForCAG is #76 "Not authorized for this CAG or authorized for CAG cells only" (Rel-16).
	CauseNotAuthorizedForCAG Cause5GMM = 76
	// CauseWirelineAccessAreaNotAllowed is #77 "Wireline access area not allowed" (Rel-16).
	CauseWirelineAccessAreaNotAllowed Cause5GMM = 77
	// CausePLMNNotAllowedAtUELocation is #78 "PLMN not allowed to operate at the present UE location" (Rel-17).
	CausePLMNNotAllowedAtUELocation Cause5GMM = 78
	// CauseUASServicesNotAllowed is #79 "UAS services not allowed" (Rel-17).
	CauseUASServicesNotAllowed Cause5GMM = 79
	// CauseDisasterRoamingNotAllowed is #80 "Disaster roaming for the determined PLMN with disaster condition not allowed" (Rel-17).
	CauseDisasterRoamingNotAllowed Cause5GMM = 80
	// CauseN3IWFNotCompatibleWithAllowedNSSAI is #81 "Selected N3IWF is not compatible with the allowed NSSAI" (Rel-18).
	CauseN3IWFNotCompatibleWithAllowedNSSAI Cause5GMM = 81
	// CauseTNGFNotCompatibleWithAllowedNSSAI is #82 "Selected TNGF is not compatible with the allowed NSSAI" (Rel-18).
	CauseTNGFNotCompatibleWithAllowedNSSAI Cause5GMM = 82
	// CauseOnboardingServicesTerminated is #93 "Onboarding services terminated" (Rel-17).
	CauseOnboardingServicesTerminated Cause5GMM = 93
	// CauseUserPlanePositioningNotAuthorized is #94 "User plane positioning not authorized" (Rel-18).
	CauseUserPlanePositioningNotAuthorized Cause5GMM = 94
	// CauseSemanticallyIncorrectMessage is #95 "Semantically incorrect message" (Rel-15).
	CauseSemanticallyIncorrectMessage Cause5GMM = 95
	// CauseInvalidMandatoryInformation is #96 "Invalid mandatory information" (Rel-15).
	CauseInvalidMandatoryInformation Cause5GMM = 96
	// CauseMessageTypeNonExistent is #97 "Message type non-existent or not implemented" (Rel-15).
	CauseMessageTypeNonExistent Cause5GMM = 97
	// CauseMessageTypeNotCompatibleWithState is #98 "Message type not compatible with the protocol state" (Rel-15).
	CauseMessageTypeNotCompatibleWithState Cause5GMM = 98
	// CauseIENonExistent is #99 "Information element non-existent or not implemented" (Rel-15).
	CauseIENonExistent Cause5GMM = 99
	// CauseConditionalIEError is #100 "Conditional IE error" (Rel-15).
	CauseConditionalIEError Cause5GMM = 100
	// CauseMessageNotCompatibleWithState is #101 "Message not compatible with the protocol state" (Rel-15).
	CauseMessageNotCompatibleWithState Cause5GMM = 101
)

// CauseInfo describes one row of Table 9.11.3.2.1 or 9.11.4.2.1.
type CauseInfo struct {
	// Value is the cause value (octet 2).
	Value uint8
	// Name is the cause name as written in the table.
	Name string
	// Introduced is the release whose final TS 24.501 version first lists
	// the value in the table (V15.7.0 -> Rel15, V16.15.0 -> Rel16,
	// V17.18.1 -> Rel17, V18.14.0 -> Rel18, V19.8.0 -> Rel19). Exact at
	// release granularity only; nothing gates on it.
	Introduced capability.Release
}

// cause5GMMTable is Table 9.11.3.2.1 of V19.8.0 in value order.
var cause5GMMTable = []CauseInfo{
	{3, "Illegal UE", capability.Rel15},
	{5, "PEI not accepted", capability.Rel15},
	{6, "Illegal ME", capability.Rel15},
	{7, "5GS services not allowed", capability.Rel15},
	{9, "UE identity cannot be derived by the network", capability.Rel15},
	{10, "Implicitly de-registered", capability.Rel15},
	{11, "PLMN not allowed", capability.Rel15},
	{12, "Tracking area not allowed", capability.Rel15},
	{13, "Roaming not allowed in this tracking area", capability.Rel15},
	{15, "No suitable cells in tracking area", capability.Rel15},
	{20, "MAC failure", capability.Rel15},
	{21, "Synch failure", capability.Rel15},
	{22, "Congestion", capability.Rel15},
	{23, "UE security capabilities mismatch", capability.Rel15},
	{24, "Security mode rejected, unspecified", capability.Rel15},
	{26, "Non-5G authentication unacceptable", capability.Rel15},
	{27, "N1 mode not allowed", capability.Rel15},
	{28, "Restricted service area", capability.Rel15},
	{31, "Redirection to EPC required", capability.Rel16},
	{36, "IAB-node operation not authorized", capability.Rel16},
	{43, "LADN not available", capability.Rel15},
	{62, "No network slices available", capability.Rel16},
	{65, "Maximum number of PDU sessions reached", capability.Rel15},
	{67, "Insufficient resources for specific slice and DNN", capability.Rel15},
	{69, "Insufficient resources for specific slice", capability.Rel15},
	{71, "ngKSI already in use", capability.Rel15},
	{72, "Non-3GPP access to 5GCN not allowed", capability.Rel15},
	{73, "Serving network not authorized", capability.Rel15},
	{74, "Temporarily not authorized for this SNPN", capability.Rel16},
	{75, "Permanently not authorized for this SNPN", capability.Rel16},
	{76, "Not authorized for this CAG or authorized for CAG cells only", capability.Rel16},
	{77, "Wireline access area not allowed", capability.Rel16},
	{78, "PLMN not allowed to operate at the present UE location", capability.Rel17},
	{79, "UAS services not allowed", capability.Rel17},
	{80, "Disaster roaming for the determined PLMN with disaster condition not allowed", capability.Rel17},
	{81, "Selected N3IWF is not compatible with the allowed NSSAI", capability.Rel18},
	{82, "Selected TNGF is not compatible with the allowed NSSAI", capability.Rel18},
	{90, "Payload was not forwarded", capability.Rel15},
	{91, "DNN not supported or not subscribed in the slice", capability.Rel15},
	{92, "Insufficient user-plane resources for the PDU session", capability.Rel15},
	{93, "Onboarding services terminated", capability.Rel17},
	{94, "User plane positioning not authorized", capability.Rel18},
	{95, "Semantically incorrect message", capability.Rel15},
	{96, "Invalid mandatory information", capability.Rel15},
	{97, "Message type non-existent or not implemented", capability.Rel15},
	{98, "Message type not compatible with the protocol state", capability.Rel15},
	{99, "Information element non-existent or not implemented", capability.Rel15},
	{100, "Conditional IE error", capability.Rel15},
	{101, "Message not compatible with the protocol state", capability.Rel15},
	{111, "Protocol error, unspecified", capability.Rel15},
}

// 5GSM cause values (TS 24.501 §9.11.4.2, Table 9.11.4.2.1, V19.8.0). Values
// already declared elsewhere in this package are not repeated here:
// Cause5GSMRegularDeactivation (#36) and Cause5GSMNetworkFailure (#38) in
// pdu_session.go, Cause5GSMUserAuthOrAuthorizationFailed (#29) in
// secondary_auth.go and Cause5GSMPDUSessionTypeIPv4/IPv6OnlyAllowed (#50,
// #51) in pdu_session.go.
const (
	// Cause5GSMOperatorDeterminedBarring is #8 "Operator determined barring" (Rel-15).
	Cause5GSMOperatorDeterminedBarring uint8 = 8
	// Cause5GSMInsufficientResources is #26 "Insufficient resources" (Rel-15).
	Cause5GSMInsufficientResources uint8 = 26
	// Cause5GSMMissingOrUnknownDNN is #27 "Missing or unknown DNN" (Rel-15).
	Cause5GSMMissingOrUnknownDNN uint8 = 27
	// Cause5GSMUnknownPDUSessionType is #28 "Unknown PDU session type" (Rel-15).
	Cause5GSMUnknownPDUSessionType uint8 = 28
	// Cause5GSMRequestRejectedUnspecified is #31 "Request rejected, unspecified" (Rel-15).
	Cause5GSMRequestRejectedUnspecified uint8 = 31
	// Cause5GSMServiceOptionNotSupported is #32 "Service option not supported" (Rel-15).
	Cause5GSMServiceOptionNotSupported uint8 = 32
	// Cause5GSMRequestedServiceOptionNotSubscribed is #33 "Requested service option not subscribed" (Rel-15).
	Cause5GSMRequestedServiceOptionNotSubscribed uint8 = 33
	// Cause5GSMPTIAlreadyInUse is #35 "PTI already in use" (Rel-15).
	Cause5GSMPTIAlreadyInUse uint8 = 35
	// Cause5GSMQoSNotAccepted is #37 "5GS QoS not accepted" (first listed in the Rel-17 table).
	Cause5GSMQoSNotAccepted uint8 = 37
	// Cause5GSMReactivationRequested is #39 "Reactivation requested" (Rel-15).
	// Previously mis-declared as 0x1D (#29), which is "User authentication or
	// authorization failed"; it had no callers.
	Cause5GSMReactivationRequested uint8 = 39
	// Cause5GSMSemanticErrorInTFT is #41 "Semantic error in the TFT operation" (Rel-16).
	Cause5GSMSemanticErrorInTFT uint8 = 41
	// Cause5GSMSyntacticalErrorInTFT is #42 "Syntactical error in the TFT operation" (Rel-16).
	Cause5GSMSyntacticalErrorInTFT uint8 = 42
	// Cause5GSMInvalidPDUSessionIdentity is #43 "Invalid PDU session identity" (Rel-15).
	Cause5GSMInvalidPDUSessionIdentity uint8 = 43
	// Cause5GSMSemanticErrorsInPacketFilters is #44 "Semantic errors in packet filter(s)" (Rel-15).
	Cause5GSMSemanticErrorsInPacketFilters uint8 = 44
	// Cause5GSMSyntacticalErrorsInPacketFilters is #45 "Syntactical error in packet filter(s)" (Rel-15).
	Cause5GSMSyntacticalErrorsInPacketFilters uint8 = 45
	// Cause5GSMOutOfLADNServiceArea is #46 "Out of LADN service area" (Rel-15).
	Cause5GSMOutOfLADNServiceArea uint8 = 46
	// Cause5GSMPTIMismatch is #47 "PTI mismatch" (Rel-15).
	Cause5GSMPTIMismatch uint8 = 47
	// Cause5GSMPDUSessionDoesNotExist is #54 "PDU session does not exist" (Rel-15).
	Cause5GSMPDUSessionDoesNotExist uint8 = 54
	// Cause5GSMPDUSessionTypeIPv4v6OnlyAllowed is #57 "PDU session type IPv4v6 only allowed" (Rel-16).
	Cause5GSMPDUSessionTypeIPv4v6OnlyAllowed uint8 = 57
	// Cause5GSMPDUSessionTypeUnstructuredOnlyAllowed is #58 "PDU session type Unstructured only allowed" (Rel-16).
	Cause5GSMPDUSessionTypeUnstructuredOnlyAllowed uint8 = 58
	// Cause5GSMUnsupported5QIValue is #59 "Unsupported 5QI value" (Rel-16).
	Cause5GSMUnsupported5QIValue uint8 = 59
	// Cause5GSMPDUSessionTypeEthernetOnlyAllowed is #61 "PDU session type Ethernet only allowed" (Rel-16).
	Cause5GSMPDUSessionTypeEthernetOnlyAllowed uint8 = 61
	// Cause5GSMInsufficientResourcesSliceDNN is #67 "Insufficient resources for specific slice and DNN" (Rel-15).
	Cause5GSMInsufficientResourcesSliceDNN uint8 = 67
	// Cause5GSMNotSupportedSSCMode is #68 "Not supported SSC mode" (Rel-15).
	Cause5GSMNotSupportedSSCMode uint8 = 68
	// Cause5GSMInsufficientResourcesSlice is #69 "Insufficient resources for specific slice" (Rel-15).
	Cause5GSMInsufficientResourcesSlice uint8 = 69
	// Cause5GSMMissingOrUnknownDNNInSlice is #70 "Missing or unknown DNN in a slice" (Rel-15).
	Cause5GSMMissingOrUnknownDNNInSlice uint8 = 70
	// Cause5GSMInvalidPTIValue is #81 "Invalid PTI value" (Rel-15).
	Cause5GSMInvalidPTIValue uint8 = 81
	// Cause5GSMMaxDataRateIntegrityTooLow is #82 "Maximum data rate per UE for user-plane integrity protection is too low" (Rel-15).
	Cause5GSMMaxDataRateIntegrityTooLow uint8 = 82
	// Cause5GSMSemanticErrorInQoSOperation is #83 "Semantic error in the QoS operation" (Rel-15).
	Cause5GSMSemanticErrorInQoSOperation uint8 = 83
	// Cause5GSMSyntacticalErrorInQoSOperation is #84 "Syntactical error in the QoS operation" (Rel-15).
	Cause5GSMSyntacticalErrorInQoSOperation uint8 = 84
	// Cause5GSMInvalidMappedEPSBearerIdentity is #85 "Invalid mapped EPS bearer identity" (Rel-15).
	Cause5GSMInvalidMappedEPSBearerIdentity uint8 = 85
	// Cause5GSMUASServicesNotAllowed is #86 "UAS services not allowed" (Rel-17).
	Cause5GSMUASServicesNotAllowed uint8 = 86
	// Cause5GSMQoSDifferentiationNon3GPPNotAvailable is #87 "QoS differentiation for non-3GPP device identifier(s) not available" (Rel-19).
	Cause5GSMQoSDifferentiationNon3GPPNotAvailable uint8 = 87
	// Cause5GSMSemanticallyIncorrectMessage is #95 "Semantically incorrect message" (Rel-15).
	Cause5GSMSemanticallyIncorrectMessage uint8 = 95
	// Cause5GSMInvalidMandatoryInformation is #96 "Invalid mandatory information" (Rel-15).
	Cause5GSMInvalidMandatoryInformation uint8 = 96
	// Cause5GSMMessageTypeNonExistent is #97 "Message type non-existent or not implemented" (Rel-15).
	Cause5GSMMessageTypeNonExistent uint8 = 97
	// Cause5GSMMessageTypeNotCompatibleWithState is #98 "Message type not compatible with the protocol state" (Rel-15).
	Cause5GSMMessageTypeNotCompatibleWithState uint8 = 98
	// Cause5GSMIENonExistent is #99 "Information element non-existent or not implemented" (Rel-15).
	Cause5GSMIENonExistent uint8 = 99
	// Cause5GSMConditionalIEError is #100 "Conditional IE error" (Rel-15).
	Cause5GSMConditionalIEError uint8 = 100
	// Cause5GSMMessageNotCompatibleWithState is #101 "Message not compatible with the protocol state" (Rel-15).
	Cause5GSMMessageNotCompatibleWithState uint8 = 101
	// Cause5GSMProtocolErrorUnspecified is #111 "Protocol error, unspecified" (Rel-15).
	Cause5GSMProtocolErrorUnspecified uint8 = 111
)

// cause5GSMTable is Table 9.11.4.2.1 of V19.8.0 in value order.
var cause5GSMTable = []CauseInfo{
	{8, "Operator determined barring", capability.Rel15},
	{26, "Insufficient resources", capability.Rel15},
	{27, "Missing or unknown DNN", capability.Rel15},
	{28, "Unknown PDU session type", capability.Rel15},
	{29, "User authentication or authorization failed", capability.Rel15},
	{31, "Request rejected, unspecified", capability.Rel15},
	{32, "Service option not supported", capability.Rel15},
	{33, "Requested service option not subscribed", capability.Rel15},
	{35, "PTI already in use", capability.Rel15},
	{36, "Regular deactivation", capability.Rel15},
	{37, "5GS QoS not accepted", capability.Rel17},
	{38, "Network failure", capability.Rel15},
	{39, "Reactivation requested", capability.Rel15},
	{41, "Semantic error in the TFT operation", capability.Rel16},
	{42, "Syntactical error in the TFT operation", capability.Rel16},
	{43, "Invalid PDU session identity", capability.Rel15},
	{44, "Semantic errors in packet filter(s)", capability.Rel15},
	{45, "Syntactical error in packet filter(s)", capability.Rel15},
	{46, "Out of LADN service area", capability.Rel15},
	{47, "PTI mismatch", capability.Rel15},
	{50, "PDU session type IPv4 only allowed", capability.Rel15},
	{51, "PDU session type IPv6 only allowed", capability.Rel15},
	{54, "PDU session does not exist", capability.Rel15},
	{57, "PDU session type IPv4v6 only allowed", capability.Rel16},
	{58, "PDU session type Unstructured only allowed", capability.Rel16},
	{59, "Unsupported 5QI value", capability.Rel16},
	{61, "PDU session type Ethernet only allowed", capability.Rel16},
	{67, "Insufficient resources for specific slice and DNN", capability.Rel15},
	{68, "Not supported SSC mode", capability.Rel15},
	{69, "Insufficient resources for specific slice", capability.Rel15},
	{70, "Missing or unknown DNN in a slice", capability.Rel15},
	{81, "Invalid PTI value", capability.Rel15},
	{82, "Maximum data rate per UE for user-plane integrity protection is too low", capability.Rel15},
	{83, "Semantic error in the QoS operation", capability.Rel15},
	{84, "Syntactical error in the QoS operation", capability.Rel15},
	{85, "Invalid mapped EPS bearer identity", capability.Rel15},
	{86, "UAS services not allowed", capability.Rel17},
	{87, "QoS differentiation for non-3GPP device identifier(s) not available", capability.Rel19},
	{95, "Semantically incorrect message", capability.Rel15},
	{96, "Invalid mandatory information", capability.Rel15},
	{97, "Message type non-existent or not implemented", capability.Rel15},
	{98, "Message type not compatible with the protocol state", capability.Rel15},
	{99, "Information element non-existent or not implemented", capability.Rel15},
	{100, "Conditional IE error", capability.Rel15},
	{101, "Message not compatible with the protocol state", capability.Rel15},
	{111, "Protocol error, unspecified", capability.Rel15},
}

func lookupCause(tab []CauseInfo, v uint8) (CauseInfo, bool) {
	for _, c := range tab {
		if c.Value == v {
			return c, true
		}
	}
	return CauseInfo{}, false
}

// Cause5GMMTable returns a copy of Table 9.11.3.2.1 (V19.8.0).
func Cause5GMMTable() []CauseInfo { return append([]CauseInfo(nil), cause5GMMTable...) }

// Cause5GSMTable returns a copy of Table 9.11.4.2.1 (V19.8.0).
func Cause5GSMTable() []CauseInfo { return append([]CauseInfo(nil), cause5GSMTable...) }

// LookupCause5GMM returns the Table 9.11.3.2.1 row for v, if v is defined.
func LookupCause5GMM(v uint8) (CauseInfo, bool) { return lookupCause(cause5GMMTable, v) }

// LookupCause5GSM returns the Table 9.11.4.2.1 row for v, if v is defined.
func LookupCause5GSM(v uint8) (CauseInfo, bool) { return lookupCause(cause5GSMTable, v) }

// String returns the Table 9.11.3.2.1 name of the cause, or "unknown (#N)".
func (c Cause5GMM) String() string {
	if i, ok := LookupCause5GMM(uint8(c)); ok {
		return i.Name
	}
	return "unknown (#" + strconv.Itoa(int(c)) + ")"
}

// Cause5GSMName returns the Table 9.11.4.2.1 name of the cause, or "unknown (#N)".
func Cause5GSMName(v uint8) string {
	if i, ok := LookupCause5GSM(v); ok {
		return i.Name
	}
	return "unknown (#" + strconv.Itoa(int(v)) + ")"
}

// Cause5GMMUnknownMapping maps a 5GMM cause value received in a message to
// the value the receiver shall act on.
//
// TS 24.501 §9.11.3.2 (V19.8.0): "Any other value received by the mobile
// station shall be treated as 0110 1111, "protocol error, unspecified".
// Any other value received by the network shall be treated as 0110 1111,
// "protocol error, unspecified"." Both directions therefore map to #111.
func Cause5GMMUnknownMapping(v uint8) Cause5GMM {
	if _, ok := LookupCause5GMM(v); ok {
		return Cause5GMM(v)
	}
	return CauseUnspecified
}

// Cause5GSMUnknownMapping maps a 5GSM cause value received in a message to
// the value the receiver shall act on. fromNetwork is true when the receiver
// is the network (message sent by the UE).
//
// TS 24.501 §9.11.4.2 (V19.8.0): "Any other value received by the UE shall
// be treated as 0001 1111, "Request rejected, unspecified". Any other value
// received by the network shall be treated as 0110 1111, "protocol error,
// unspecified"." So the UE maps unknown values to #31 and the network to #111.
func Cause5GSMUnknownMapping(v uint8, fromNetwork bool) uint8 {
	if _, ok := LookupCause5GSM(v); ok {
		return v
	}
	if fromNetwork {
		return Cause5GSMProtocolErrorUnspecified
	}
	return Cause5GSMRequestRejectedUnspecified
}
