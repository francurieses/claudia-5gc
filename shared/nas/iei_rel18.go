// Package nas — iei_rel18.go: named constants for the Rel-18/Rel-19 optional
// IEIs listed in the message-content tables of TS 24.501 V19.8.0 clause 8.
//
// Constants only. IEI values are scoped per message (the same value is reused
// by different IEs in different messages), hence the message prefix in each
// name. The decoders' IE tables in ietable.go are unchanged; TestIEIConstants
// cross-checks every constant here against that table.
package nas

// Rel-18/19 IEIs by message. Format is TLV/TLV-E/TV1 per the table row.
const (
	// IEIRegReqUnavailabilityInformation is the "Unavailability information" IE of RegistrationRequest (Rel18, TS 24.501 §9.11.2.20).
	IEIRegReqUnavailabilityInformation uint8 = 0x3C
	// IEIRegReqNon3GPPPathSwitchingInformation is the "Non-3GPP path switching information" IE of RegistrationRequest (Rel18, TS 24.501 §9.11.3.102).
	IEIRegReqNon3GPPPathSwitchingInformation uint8 = 0x3F
	// IEIRegReqAUN3Indication is the "AUN3 indication" IE of RegistrationRequest (Rel18, TS 24.501 §9.11.3.104).
	IEIRegReqAUN3Indication uint8 = 0x56
	// IEIRegReqRequestedLPWUSPSAssistanceInformation is the "Requested LP-WUSPS assistance information" IE of RegistrationRequest (Rel19, TS 24.501 §9.11.3.111).
	IEIRegReqRequestedLPWUSPSAssistanceInformation uint8 = 0x64
	// IEIRegAccEquivalentSNPNs is the "Equivalent SNPNs" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.3.92).
	IEIRegAccEquivalentSNPNs uint8 = 0x3D
	// IEIRegAccNID is the "NID" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.3.79).
	IEIRegAccNID uint8 = 0x32
	// IEIRegAccRegistrationAcceptType6IEContainer is the "Registration accept type 6 IE container" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.3.98).
	IEIRegAccRegistrationAcceptType6IEContainer uint8 = 0x7D
	// IEIRegAccRANTimingSynchronization is the "RAN timing synchronization" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.3.95).
	IEIRegAccRANTimingSynchronization uint8 = 0x4B
	// IEIRegAccAlternativeNSSAI is the "Alternative NSSAI" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.3.97).
	IEIRegAccAlternativeNSSAI uint8 = 0x4C
	// IEIRegAccDiscontinuousCoverageMaximumTimeOffset is the "Discontinuous coverage maximum time offset" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.2.5).
	IEIRegAccDiscontinuousCoverageMaximumTimeOffset uint8 = 0x4F
	// IEIRegAccSNSSAITimeValidityInformation is the "S-NSSAI time validity information" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.3.101).
	IEIRegAccSNSSAITimeValidityInformation uint8 = 0x5B
	// IEIRegAccUnavailabilityConfiguration is the "Unavailability configuration" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.2.21).
	IEIRegAccUnavailabilityConfiguration uint8 = 0x3C
	// IEIRegAccFeatureAuthorizationIndication is the "Feature authorization indication" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.3.105).
	IEIRegAccFeatureAuthorizationIndication uint8 = 0x5C
	// IEIRegAccOndemandNSSAI is the "On-demand NSSAI" IE of RegistrationAccept (Rel18, TS 24.501 §9.11.3.108).
	IEIRegAccOndemandNSSAI uint8 = 0x61
	// IEIRegAccAccessTechnologyUtilizationControl is the "Access technology utilization control" IE of RegistrationAccept (Rel19, TS 24.501 §9.11.3.110).
	IEIRegAccAccessTechnologyUtilizationControl uint8 = 0x63
	// IEIRegAccNegotiatedLPWUSPSAssistanceInformation is the "Negotiated LP-WUSPS assistance information" IE of RegistrationAccept (Rel19, TS 24.501 §9.11.3.111).
	IEIRegAccNegotiatedLPWUSPSAssistanceInformation uint8 = 0x64
	// IEIRegAccLPWUSStatus is the "LP-WUS status" IE of RegistrationAccept (Rel19, TS 24.501 §9.11.3.112).
	IEIRegAccLPWUSStatus uint8 = 0x80
	// IEIPDUSessEstReqURSPRuleEnforcementReports is the "URSP rule enforcement reports" IE of PDUSessionEstablishmentRequest (Rel18, TS 24.501 §9.11.4.38).
	IEIPDUSessEstReqURSPRuleEnforcementReports uint8 = 0x36
	// IEICfgUpdCmdRANTimingSynchronization is the "RAN timing synchronization" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.95).
	IEICfgUpdCmdRANTimingSynchronization uint8 = 0x4B
	// IEICfgUpdCmdExtendedLADNInformation is the "Extended LADN information" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.96).
	IEICfgUpdCmdExtendedLADNInformation uint8 = 0x78
	// IEICfgUpdCmdAlternativeNSSAI is the "Alternative NSSAI" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.97).
	IEICfgUpdCmdAlternativeNSSAI uint8 = 0x4C
	// IEICfgUpdCmdSNSSAILocationValidityInformation is the "S-NSSAI location validity information" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.100).
	IEICfgUpdCmdSNSSAILocationValidityInformation uint8 = 0x7B
	// IEICfgUpdCmdSNSSAITimeValidityInformation is the "S-NSSAI time validity information" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.101).
	IEICfgUpdCmdSNSSAITimeValidityInformation uint8 = 0x5B
	// IEICfgUpdCmdDiscontinuousCoverageMaximumTimeOffset is the "Discontinuous coverage maximum time offset" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.2.5).
	IEICfgUpdCmdDiscontinuousCoverageMaximumTimeOffset uint8 = 0x4F
	// IEICfgUpdCmdPartiallyAllowedNSSAI is the "Partially allowed NSSAI" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.103).
	IEICfgUpdCmdPartiallyAllowedNSSAI uint8 = 0x74
	// IEICfgUpdCmdPartiallyRejectedNSSAI is the "Partially rejected NSSAI" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.103).
	IEICfgUpdCmdPartiallyRejectedNSSAI uint8 = 0x7A
	// IEICfgUpdCmdFeatureAuthorizationIndication is the "Feature authorization indication" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.105).
	IEICfgUpdCmdFeatureAuthorizationIndication uint8 = 0x5C
	// IEICfgUpdCmdOndemandNSSAI is the "On-demand NSSAI" IE of ConfigurationUpdateCommand (Rel18, TS 24.501 §9.11.3.108).
	IEICfgUpdCmdOndemandNSSAI uint8 = 0x61
	// IEICfgUpdCmdAccessTechnologyUtilizationControl is the "Access technology utilization control" IE of ConfigurationUpdateCommand (Rel19, TS 24.501 §9.11.3.110).
	IEICfgUpdCmdAccessTechnologyUtilizationControl uint8 = 0x63
	// IEICfgUpdCmdUpdatedLPWUSPSAssistanceInformation is the "Updated LP-WUSPS assistance information" IE of ConfigurationUpdateCommand (Rel19, TS 24.501 §9.11.3.111).
	IEICfgUpdCmdUpdatedLPWUSPSAssistanceInformation uint8 = 0x64
	// IEICfgUpdCmdLPWUSStatus is the "LP-WUS status" IE of ConfigurationUpdateCommand (Rel19, TS 24.501 §9.11.3.112).
	IEICfgUpdCmdLPWUSStatus uint8 = 0x80
	// IEIULNASTransportNon3GPPAccessPathSwitchingIndication is the "Non-3GPP access path switching indication" IE of ULNASTransport (Rel18, TS 24.501 §9.11.3.99).
	IEIULNASTransportNon3GPPAccessPathSwitchingIndication uint8 = 0x4E
	// IEIULNASTransportAlternativeSNSSAI is the "Alternative S-NSSAI" IE of ULNASTransport (Rel18, TS 24.501 §9.11.2.8).
	IEIULNASTransportAlternativeSNSSAI uint8 = 0x5A
	// IEIULNASTransportPayloadContainerInformation is the "Payload container information" IE of ULNASTransport (Rel18, TS 24.501 §9.11.3.106).
	IEIULNASTransportPayloadContainerInformation uint8 = 0x90
	// IEISMCAUN3DeviceSecurityKey is the "AUN3 device security key" IE of SecurityModeCommand (Rel18, TS 24.501 §9.11.3.107).
	IEISMCAUN3DeviceSecurityKey uint8 = 0x55
)
