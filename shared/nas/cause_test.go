package nas

import (
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// want5GMM is Table 9.11.3.2.1 (V19.8.0) transcribed independently of cause.go
// as value -> name.
var want5GMM = map[uint8]string{
	3: "Illegal UE", 5: "PEI not accepted", 6: "Illegal ME", 7: "5GS services not allowed",
	9: "UE identity cannot be derived by the network", 10: "Implicitly de-registered",
	11: "PLMN not allowed", 12: "Tracking area not allowed",
	13: "Roaming not allowed in this tracking area", 15: "No suitable cells in tracking area",
	20: "MAC failure", 21: "Synch failure", 22: "Congestion",
	23: "UE security capabilities mismatch", 24: "Security mode rejected, unspecified",
	26: "Non-5G authentication unacceptable", 27: "N1 mode not allowed", 28: "Restricted service area",
	31: "Redirection to EPC required", 36: "IAB-node operation not authorized", 43: "LADN not available",
	62: "No network slices available", 65: "Maximum number of PDU sessions reached",
	67: "Insufficient resources for specific slice and DNN", 69: "Insufficient resources for specific slice",
	71: "ngKSI already in use", 72: "Non-3GPP access to 5GCN not allowed", 73: "Serving network not authorized",
	74: "Temporarily not authorized for this SNPN", 75: "Permanently not authorized for this SNPN",
	76: "Not authorized for this CAG or authorized for CAG cells only", 77: "Wireline access area not allowed",
	78: "PLMN not allowed to operate at the present UE location", 79: "UAS services not allowed",
	80: "Disaster roaming for the determined PLMN with disaster condition not allowed",
	81: "Selected N3IWF is not compatible with the allowed NSSAI",
	82: "Selected TNGF is not compatible with the allowed NSSAI",
	90: "Payload was not forwarded", 91: "DNN not supported or not subscribed in the slice",
	92: "Insufficient user-plane resources for the PDU session", 93: "Onboarding services terminated",
	94: "User plane positioning not authorized", 95: "Semantically incorrect message",
	96: "Invalid mandatory information", 97: "Message type non-existent or not implemented",
	98: "Message type not compatible with the protocol state",
	99: "Information element non-existent or not implemented", 100: "Conditional IE error",
	101: "Message not compatible with the protocol state", 111: "Protocol error, unspecified",
}

// want5GSM is Table 9.11.4.2.1 (V19.8.0).
var want5GSM = map[uint8]string{
	8: "Operator determined barring", 26: "Insufficient resources", 27: "Missing or unknown DNN",
	28: "Unknown PDU session type", 29: "User authentication or authorization failed",
	31: "Request rejected, unspecified", 32: "Service option not supported",
	33: "Requested service option not subscribed", 35: "PTI already in use", 36: "Regular deactivation",
	37: "5GS QoS not accepted", 38: "Network failure", 39: "Reactivation requested",
	41: "Semantic error in the TFT operation", 42: "Syntactical error in the TFT operation",
	43: "Invalid PDU session identity", 44: "Semantic errors in packet filter(s)",
	45: "Syntactical error in packet filter(s)", 46: "Out of LADN service area", 47: "PTI mismatch",
	50: "PDU session type IPv4 only allowed", 51: "PDU session type IPv6 only allowed",
	54: "PDU session does not exist", 57: "PDU session type IPv4v6 only allowed",
	58: "PDU session type Unstructured only allowed", 59: "Unsupported 5QI value",
	61: "PDU session type Ethernet only allowed", 67: "Insufficient resources for specific slice and DNN",
	68: "Not supported SSC mode", 69: "Insufficient resources for specific slice",
	70: "Missing or unknown DNN in a slice", 81: "Invalid PTI value",
	82: "Maximum data rate per UE for user-plane integrity protection is too low",
	83: "Semantic error in the QoS operation", 84: "Syntactical error in the QoS operation",
	85: "Invalid mapped EPS bearer identity", 86: "UAS services not allowed",
	87: "QoS differentiation for non-3GPP device identifier(s) not available",
	95: "Semantically incorrect message", 96: "Invalid mandatory information",
	97: "Message type non-existent or not implemented", 98: "Message type not compatible with the protocol state",
	99: "Information element non-existent or not implemented", 100: "Conditional IE error",
	101: "Message not compatible with the protocol state", 111: "Protocol error, unspecified",
}

func checkTable(t *testing.T, got []CauseInfo, want map[uint8]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("table has %d rows, want %d", len(got), len(want))
	}
	seen := map[uint8]bool{}
	prev := -1
	for _, c := range got {
		if seen[c.Value] {
			t.Errorf("duplicate value %d", c.Value)
		}
		seen[c.Value] = true
		if int(c.Value) <= prev {
			t.Errorf("value %d not in ascending order", c.Value)
		}
		prev = int(c.Value)
		if want[c.Value] != c.Name {
			t.Errorf("value %d: name %q, want %q", c.Value, c.Name, want[c.Value])
		}
		if c.Introduced < capability.Rel15 || c.Introduced > capability.Rel19 {
			t.Errorf("value %d: bad Introduced %v", c.Value, c.Introduced)
		}
	}
}

func TestCauseTables(t *testing.T) {
	t.Run("5GMM table", func(t *testing.T) { checkTable(t, Cause5GMMTable(), want5GMM) })
	t.Run("5GSM table", func(t *testing.T) { checkTable(t, Cause5GSMTable(), want5GSM) })

	t.Run("5GMM constants", func(t *testing.T) {
		for v, c := range map[uint8]Cause5GMM{
			3: CauseIllegalUE, 5: CausePEINotAccepted, 6: CauseIllegalME, 7: Cause5GSServicesNotAllowed,
			9: CauseUEIdentityNotDerived, 10: CauseImplicitlyDeregistered, 11: CausePLMNNotAllowed,
			12: CauseTANotAllowed, 13: CauseRoamingNotAllowed, 15: CauseNoSuitableCellsInTA,
			20: CauseMACFailure, 21: CauseSynchFailure, 22: CauseCongestion,
			23: CauseUESecurityCapabilitiesMismatch, 24: CauseSecurityModeRejectedUnspecified,
			26: CauseNon5GAuthenticationUnacceptable, 27: CauseN1ModeNotAllowed, 28: CauseRestrictedServiceArea,
			31: CauseRedirectionToEPCRequired, 36: CauseIABNodeOperationNotAuthorized, 43: CauseLADNNotAvailable,
			62: CauseNoNetworkSlicesAvailable, 65: CauseMaxPDUSessionsReached,
			67: CauseInsufficientResourcesSliceDNN, 69: CauseInsufficientResourcesSlice,
			71: CausengKSIAlreadyInUse, 72: CauseNon3GPPAccessNotAllowed, 73: CauseServingNetworkNotAuthorized,
			74: CauseTempNotAuthorizedForSNPN, 75: CausePermNotAuthorizedForSNPN, 76: CauseNotAuthorizedForCAG,
			77: CauseWirelineAccessAreaNotAllowed, 78: CausePLMNNotAllowedAtUELocation,
			79: CauseUASServicesNotAllowed, 80: CauseDisasterRoamingNotAllowed,
			81: CauseN3IWFNotCompatibleWithAllowedNSSAI, 82: CauseTNGFNotCompatibleWithAllowedNSSAI,
			90: CausePayloadNotForwarded, 91: CauseDNNNotSupportedInSlice, 92: CauseInsufficientUPResource,
			93: CauseOnboardingServicesTerminated, 94: CauseUserPlanePositioningNotAuthorized,
			95: CauseSemanticallyIncorrectMessage, 96: CauseInvalidMandatoryInformation,
			97: CauseMessageTypeNonExistent, 98: CauseMessageTypeNotCompatibleWithState,
			99: CauseIENonExistent, 100: CauseConditionalIEError, 101: CauseMessageNotCompatibleWithState,
			111: CauseUnspecified,
		} {
			if uint8(c) != v {
				t.Errorf("constant for #%d has value %d", v, c)
			}
			if _, ok := want5GMM[v]; !ok {
				t.Errorf("#%d not in table", v)
			}
			if c.String() != want5GMM[v] {
				t.Errorf("#%d String() = %q", v, c.String())
			}
		}
	})

	t.Run("5GSM constants", func(t *testing.T) {
		for v, c := range map[uint8]uint8{
			8: Cause5GSMOperatorDeterminedBarring, 26: Cause5GSMInsufficientResources,
			27: Cause5GSMMissingOrUnknownDNN, 28: Cause5GSMUnknownPDUSessionType,
			29: Cause5GSMUserAuthOrAuthorizationFailed, 31: Cause5GSMRequestRejectedUnspecified,
			32: Cause5GSMServiceOptionNotSupported, 33: Cause5GSMRequestedServiceOptionNotSubscribed,
			35: Cause5GSMPTIAlreadyInUse, 36: Cause5GSMRegularDeactivation, 37: Cause5GSMQoSNotAccepted,
			38: Cause5GSMNetworkFailure, 39: Cause5GSMReactivationRequested,
			41: Cause5GSMSemanticErrorInTFT, 42: Cause5GSMSyntacticalErrorInTFT,
			43: Cause5GSMInvalidPDUSessionIdentity, 44: Cause5GSMSemanticErrorsInPacketFilters,
			45: Cause5GSMSyntacticalErrorsInPacketFilters, 46: Cause5GSMOutOfLADNServiceArea,
			47: Cause5GSMPTIMismatch, 50: Cause5GSMPDUSessionTypeIPv4OnlyAllowed,
			51: Cause5GSMPDUSessionTypeIPv6OnlyAllowed, 54: Cause5GSMPDUSessionDoesNotExist,
			57: Cause5GSMPDUSessionTypeIPv4v6OnlyAllowed, 58: Cause5GSMPDUSessionTypeUnstructuredOnlyAllowed,
			59: Cause5GSMUnsupported5QIValue, 61: Cause5GSMPDUSessionTypeEthernetOnlyAllowed,
			67: Cause5GSMInsufficientResourcesSliceDNN, 68: Cause5GSMNotSupportedSSCMode,
			69: Cause5GSMInsufficientResourcesSlice, 70: Cause5GSMMissingOrUnknownDNNInSlice,
			81: Cause5GSMInvalidPTIValue, 82: Cause5GSMMaxDataRateIntegrityTooLow,
			83: Cause5GSMSemanticErrorInQoSOperation, 84: Cause5GSMSyntacticalErrorInQoSOperation,
			85: Cause5GSMInvalidMappedEPSBearerIdentity, 86: Cause5GSMUASServicesNotAllowed,
			87: Cause5GSMQoSDifferentiationNon3GPPNotAvailable, 95: Cause5GSMSemanticallyIncorrectMessage,
			96: Cause5GSMInvalidMandatoryInformation, 97: Cause5GSMMessageTypeNonExistent,
			98: Cause5GSMMessageTypeNotCompatibleWithState, 99: Cause5GSMIENonExistent,
			100: Cause5GSMConditionalIEError, 101: Cause5GSMMessageNotCompatibleWithState,
			111: Cause5GSMProtocolErrorUnspecified,
		} {
			if c != v {
				t.Errorf("constant for #%d has value %d", v, c)
			}
			if Cause5GSMName(v) != want5GSM[v] {
				t.Errorf("#%d name %q", v, Cause5GSMName(v))
			}
		}
		// Wire values of constants used by the AMF/SMF must not move.
		if Cause5GSMRegularDeactivation != 0x24 || Cause5GSMNetworkFailure != 0x26 ||
			Cause5GSMUserAuthOrAuthorizationFailed != 0x1D {
			t.Error("pre-existing 5GSM cause wire values changed")
		}
	})

	t.Run("unknown mapping 5GMM", func(t *testing.T) {
		for v := 0; v < 256; v++ {
			got := Cause5GMMUnknownMapping(uint8(v))
			if _, ok := want5GMM[uint8(v)]; ok {
				if uint8(got) != uint8(v) {
					t.Errorf("defined #%d remapped to %d", v, got)
				}
			} else if got != CauseUnspecified {
				t.Errorf("unknown #%d -> %d, want 111", v, got)
			}
		}
	})

	t.Run("unknown mapping 5GSM", func(t *testing.T) {
		for v := 0; v < 256; v++ {
			_, def := want5GSM[uint8(v)]
			ue, nw := Cause5GSMUnknownMapping(uint8(v), false), Cause5GSMUnknownMapping(uint8(v), true)
			switch {
			case def && (ue != uint8(v) || nw != uint8(v)):
				t.Errorf("defined #%d remapped (%d,%d)", v, ue, nw)
			case !def && (ue != 31 || nw != 111):
				t.Errorf("unknown #%d -> UE %d, network %d; want 31, 111", v, ue, nw)
			}
		}
	})

	t.Run("String of unknown", func(t *testing.T) {
		if got := Cause5GMM(8).String(); got != "unknown (#8)" {
			t.Errorf("got %q", got)
		}
		if got := Cause5GSMName(255); got != "unknown (#255)" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("Introduced per row", func(t *testing.T) {
		checkRel(t, Cause5GMMTable(), want5GMM, wantRelFrom(want5GMM, map[capability.Release][]uint8{
			capability.Rel16: {31, 36, 62, 74, 75, 76, 77},
			capability.Rel17: {78, 79, 80, 93},
			capability.Rel18: {81, 82, 94},
		}))
		checkRel(t, Cause5GSMTable(), want5GSM, wantRelFrom(want5GSM, map[capability.Release][]uint8{
			capability.Rel16: {41, 42, 57, 58, 59, 61},
			capability.Rel17: {37, 86},
			capability.Rel19: {87},
		}))
	})
}

// wantRelFrom builds the value -> release transcription of a cause table:
// every value is Rel15 unless listed under a later release (TS 24.501
// V15.7.0 / V16.15.0 / V17.18.1 / V18.14.0 / V19.8.0 tables).
func wantRelFrom(names map[uint8]string, later map[capability.Release][]uint8) map[uint8]capability.Release {
	out := make(map[uint8]capability.Release, len(names))
	for v := range names {
		out[v] = capability.Rel15
	}
	for rel, vs := range later {
		for _, v := range vs {
			if _, ok := out[v]; !ok {
				panic("wantRelFrom: value not in table")
			}
			out[v] = rel
		}
	}
	return out
}

func checkRel(t *testing.T, got []CauseInfo, names map[uint8]string, want map[uint8]capability.Release) {
	t.Helper()
	if len(got) != len(want) || len(want) != len(names) {
		t.Fatalf("rows %d, wantRel %d, names %d", len(got), len(want), len(names))
	}
	for _, c := range got {
		if r, ok := want[c.Value]; !ok || c.Introduced != r {
			t.Errorf("#%d: Introduced %v, want %v (ok=%v)", c.Value, c.Introduced, r, ok)
		}
	}
}

// TestServiceTypeValues covers TS 24.501 Table 9.11.3.50.1 (V19.8.0) and the
// decode of every value of the service type nibble (NAS-001).
func TestServiceTypeValues(t *testing.T) {
	defined := map[byte]byte{
		ServiceTypeSignalling: 0x00, ServiceTypeData: 0x01, ServiceTypeMobileTerminated: 0x02,
		ServiceTypeEmergencyServices: 0x03, ServiceTypeEmergencyServicesFallback: 0x04,
		ServiceTypeHighPriorityAccess: 0x05, ServiceTypeElevatedSignalling: 0x06,
	}
	if ServiceTypeHighPriorityAccess != 5 || ServiceTypeEmergencyServicesFallback != 4 || ServiceTypeElevatedSignalling != 6 {
		t.Fatal("service type constants do not match Table 9.11.3.50.1")
	}
	for v := 0; v < 16; v++ {
		// SERVICE REQUEST octet 4: service type (high nibble) | ngKSI (low nibble).
		body := []byte{byte(v<<4) | 0x01}
		sr, err := DecodeServiceRequest(body)
		if err != nil {
			t.Fatalf("value %d: %v", v, err)
		}
		if sr.ServiceType != byte(v) {
			t.Errorf("value %d decoded as %d", v, sr.ServiceType)
		}
		got, ok := InterpretServiceType(byte(v))
		switch {
		case v <= 6:
			if !ok || got != defined[byte(v)] {
				t.Errorf("defined %d: (%d,%v)", v, got, ok)
			}
		case v == 7 || v == 8:
			if !ok || got != ServiceTypeSignalling {
				t.Errorf("unused %d: (%d,%v), want signalling", v, got, ok)
			}
		case v >= 9 && v <= 11:
			if !ok || got != ServiceTypeData {
				t.Errorf("unused %d: (%d,%v), want data", v, got, ok)
			}
		default:
			if ok || got != byte(v) {
				t.Errorf("reserved %d: (%d,%v)", v, got, ok)
			}
		}
	}
}

// TestIEIConstants cross-checks the Rel-18/19 IEI constants against the
// transcribed message tables in ietable.go.
func TestIEIConstants(t *testing.T) {
	for _, tc := range []struct {
		msg  IEMessage
		iei  uint8
		name string
		rel  capability.Release
	}{
		{IEMsgRegistrationRequest, IEIRegReqUnavailabilityInformation, "Unavailability information", capability.Rel18},
		{IEMsgRegistrationRequest, IEIRegReqNon3GPPPathSwitchingInformation, "Non-3GPP path switching information", capability.Rel18},
		{IEMsgRegistrationRequest, IEIRegReqAUN3Indication, "AUN3 indication", capability.Rel18},
		{IEMsgRegistrationRequest, IEIRegReqRequestedLPWUSPSAssistanceInformation, "Requested LP-WUSPS assistance information", capability.Rel19},
		{IEMsgRegistrationAccept, IEIRegAccEquivalentSNPNs, "Equivalent SNPNs", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccNID, "NID", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccRegistrationAcceptType6IEContainer, "Registration accept type 6 IE container", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccRANTimingSynchronization, "RAN timing synchronization", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccAlternativeNSSAI, "Alternative NSSAI", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccDiscontinuousCoverageMaximumTimeOffset, "Discontinuous coverage maximum time offset", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccSNSSAITimeValidityInformation, "S-NSSAI time validity information", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccUnavailabilityConfiguration, "Unavailability configuration", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccFeatureAuthorizationIndication, "Feature authorization indication", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccOndemandNSSAI, "On-demand NSSAI", capability.Rel18},
		{IEMsgRegistrationAccept, IEIRegAccAccessTechnologyUtilizationControl, "Access technology utilization control", capability.Rel19},
		{IEMsgRegistrationAccept, IEIRegAccNegotiatedLPWUSPSAssistanceInformation, "Negotiated LP-WUSPS assistance information", capability.Rel19},
		{IEMsgRegistrationAccept, IEIRegAccLPWUSStatus, "LP-WUS status", capability.Rel19},
		{IEMsgPDUSessionEstablishmentRequest, IEIPDUSessEstReqURSPRuleEnforcementReports, "URSP rule enforcement reports", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdRANTimingSynchronization, "RAN timing synchronization", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdExtendedLADNInformation, "Extended LADN information", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdAlternativeNSSAI, "Alternative NSSAI", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdSNSSAILocationValidityInformation, "S-NSSAI location validity information", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdSNSSAITimeValidityInformation, "S-NSSAI time validity information", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdDiscontinuousCoverageMaximumTimeOffset, "Discontinuous coverage maximum time offset", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdPartiallyAllowedNSSAI, "Partially allowed NSSAI", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdPartiallyRejectedNSSAI, "Partially rejected NSSAI", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdFeatureAuthorizationIndication, "Feature authorization indication", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdOndemandNSSAI, "On-demand NSSAI", capability.Rel18},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdAccessTechnologyUtilizationControl, "Access technology utilization control", capability.Rel19},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdUpdatedLPWUSPSAssistanceInformation, "Updated LP-WUSPS assistance information", capability.Rel19},
		{IEMsgConfigurationUpdateCommand, IEICfgUpdCmdLPWUSStatus, "LP-WUS status", capability.Rel19},
		{IEMsgULNASTransport, IEIULNASTransportNon3GPPAccessPathSwitchingIndication, "Non-3GPP access path switching indication", capability.Rel18},
		{IEMsgULNASTransport, IEIULNASTransportAlternativeSNSSAI, "Alternative S-NSSAI", capability.Rel18},
		{IEMsgULNASTransport, IEIULNASTransportPayloadContainerInformation, "Payload container information", capability.Rel18},
		{IEMsgSecurityModeCommand, IEISMCAUN3DeviceSecurityKey, "AUN3 device security key", capability.Rel18},
	} {
		d, ok := LookupIE(tc.msg, tc.iei)
		if !ok {
			t.Errorf("%s: IEI 0x%02X missing in ietable", tc.msg, tc.iei)
			continue
		}
		if d.Name != tc.name || d.Introduced != tc.rel {
			t.Errorf("%s 0x%02X: table has %q/%v, constant documents %q/%v", tc.msg, tc.iei, d.Name, d.Introduced, tc.name, tc.rel)
		}
	}
}
