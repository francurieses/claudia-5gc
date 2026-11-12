// Rel-19 IE type table, generated from TS 29.244 V19.6.0 Table 8.1.2-1.

package pfcpx

// IE type values above 271 (TS 29.244 V19.6.0 Table 8.1.2-1). Names follow
// the table; the parenthesised reference is the defining table/clause.
// Types 273 (Spare) and 381 ("Can be used") are unassigned; 404-32767 are
// spare and 32768-65535 are reserved for vendor-specific IEs.
const (
	// PartialFailureInformation is IE type 272: Partial Failure Information (Table 7.5.3.1-2).
	PartialFailureInformation uint16 = 272
	// OffendingIEInformation is IE type 274: Offending IE Information (Clause 8.2.185).
	OffendingIEInformation uint16 = 274
	// RATType is IE type 275: RAT Type (Clause 8.2.186).
	RATType uint16 = 275
	// L2TPTunnelInformation is IE type 276: L2TP Tunnel Information (Table 7.5.2.1-2).
	L2TPTunnelInformation uint16 = 276
	// L2TPSessionInformation is IE type 277: L2TP Session Information (Table 7.5.2.1-3).
	L2TPSessionInformation uint16 = 277
	// L2TPUserAuthentication is IE type 278: L2TP User Authentication (Clause 8.2.187).
	L2TPUserAuthentication uint16 = 278
	// CreatedL2TPSession is IE type 279: Created L2TP Session (Table 7.5.3.1-3).
	CreatedL2TPSession uint16 = 279
	// LNSAddress is IE type 280: LNS Address (Clause 8.2.188).
	LNSAddress uint16 = 280
	// TunnelPreference is IE type 281: Tunnel Preference (Clause 8.2.189).
	TunnelPreference uint16 = 281
	// CallingNumber is IE type 282: Calling Number (Clause 8.2.190).
	CallingNumber uint16 = 282
	// CalledNumber is IE type 283: Called Number (Clause 8.2.191).
	CalledNumber uint16 = 283
	// L2TPSessionIndications is IE type 284: L2TP Session Indications (Clause 8.2.192).
	L2TPSessionIndications uint16 = 284
	// DNSServerAddress is IE type 285: DNS Server Address (Clause 8.2.193).
	DNSServerAddress uint16 = 285
	// NBNSServerAddress is IE type 286: NBNS Server Address (Clause 8.2.194).
	NBNSServerAddress uint16 = 286
	// MaximumReceiveUnit is IE type 287: Maximum Receive Unit (Clause 8.2.195).
	MaximumReceiveUnit uint16 = 287
	// Thresholds is IE type 288: Thresholds (Clause 8.2.196).
	Thresholds uint16 = 288
	// SteeringModeIndicator is IE type 289: Steering Mode Indicator (Clause 8.2.197).
	SteeringModeIndicator uint16 = 289
	// PFCPSessionChangeInfo is IE type 290: PFCP Session Change Info (Table 7.4.7.1-2).
	PFCPSessionChangeInfo uint16 = 290
	// GroupID is IE type 291: Group ID (Clause 8.2.198).
	GroupID uint16 = 291
	// CPIPAddress is IE type 292: CP IP Address (Clause 8.2.199).
	CPIPAddress uint16 = 292
	// IPAddressAndPortNumberReplacement is IE type 293: IP Address and Port number Replacement (Clause 8.2.200).
	IPAddressAndPortNumberReplacement uint16 = 293
	// DNSQueryResponseFilter is IE type 294: DNS Query/Response Filter (Clause 8.2.201).
	DNSQueryResponseFilter uint16 = 294
	// DirectReportingInformation is IE type 295: Direct Reporting Information (Table 7.5.2.9-4).
	DirectReportingInformation uint16 = 295
	// EventNotificationURI is IE type 296: Event Notification URI (Clause 8.2.202).
	EventNotificationURI uint16 = 296
	// NotificationCorrelationID is IE type 297: Notification Correlation ID (Clause 8.2.203).
	NotificationCorrelationID uint16 = 297
	// ReportingFlags is IE type 298: Reporting Flags (Clause 8.2.204).
	ReportingFlags uint16 = 298
	// PredefinedRulesName is IE type 299: Predefined Rules Name (Clause 8.2.205).
	PredefinedRulesName uint16 = 299
	// MBSSessionN4mbControlInformation is IE type 300: MBS Session N4mb Control Information (Table 7.5.2.1-4).
	MBSSessionN4mbControlInformation uint16 = 300
	// MBSMulticastParameters is IE type 301: MBS Multicast Parameters (Table 7.5.2.3-5).
	MBSMulticastParameters uint16 = 301
	// AddMBSUnicastParameters is IE type 302: Add MBS Unicast Parameters (Table 7.5.2.3-6).
	AddMBSUnicastParameters uint16 = 302
	// MBSSessionN4mbInformation is IE type 303: MBS Session N4mb Information (Table 7.5.3.1-4).
	MBSSessionN4mbInformation uint16 = 303
	// RemoveMBSUnicastParameters is IE type 304: Remove MBS Unicast Parameters (Table 7.5.4.3-4).
	RemoveMBSUnicastParameters uint16 = 304
	// MBSSessionIdentifier is IE type 305: MBS Session Identifier (Clause 8.2.206).
	MBSSessionIdentifier uint16 = 305
	// MulticastTransportInformation is IE type 306: Multicast Transport Information (Clause 8.2.207).
	MulticastTransportInformation uint16 = 306
	// MBSN4mbReqFlags is IE type 307: MBSN4mbReq-Flags (Clause 8.2.208).
	MBSN4mbReqFlags uint16 = 307
	// LocalIngressTunnel is IE type 308: Local Ingress Tunnel (Clause 8.2.209).
	LocalIngressTunnel uint16 = 308
	// MBSUnicastParametersID is IE type 309: MBS Unicast Parameters ID (Clause 8.2.210).
	MBSUnicastParametersID uint16 = 309
	// MBSSessionN4ControlInformation is IE type 310: MBS Session N4 Control Information (Table 7.5.2.1-5).
	MBSSessionN4ControlInformation uint16 = 310
	// MBSSessionN4Information is IE type 311: MBS Session N4 Information (Table 7.5.3.1-5).
	MBSSessionN4Information uint16 = 311
	// MBSN4RespFlags is IE type 312: MBSN4Resp-Flags (Clause 8.2.211).
	MBSN4RespFlags uint16 = 312
	// TunnelPassword is IE type 313: Tunnel Password (Clause 8.2.212).
	TunnelPassword uint16 = 313
	// AreaSessionID is IE type 314: Area Session ID (Clause 8.2.213).
	AreaSessionID uint16 = 314
	// PeerUPRestartReport is IE type 315: Peer UP Restart Report (Clause 7.4.5.1.7).
	PeerUPRestartReport uint16 = 315
	// DSCPToPPIControlInformation is IE type 316: DSCP to PPI Control Information (Table 7.5.2.1-6).
	DSCPToPPIControlInformation uint16 = 316
	// DSCPToPPIMappingInformation is IE type 317: DSCP to PPI Mapping Information (Clause 8.2.214).
	DSCPToPPIMappingInformation uint16 = 317
	// PFCPSDRspFlags is IE type 318: PFCPSDRsp-Flags (Clause 8.2.215).
	PFCPSDRspFlags uint16 = 318
	// QERIndications is IE type 319: QER Indications (Clause 8.2.216).
	QERIndications uint16 = 319
	// VendorSpecificNodeReportType is IE type 320: Vendor-Specific Node Report Type (Clause 8.2.217).
	VendorSpecificNodeReportType uint16 = 320
	// ConfiguredTimeDomain is IE type 321: Configured Time Domain (Clause 8.2.218).
	ConfiguredTimeDomain uint16 = 321
	// Metadata is IE type 322: Metadata (Clause 8.2.219).
	Metadata uint16 = 322
	// TrafficParameterMeasurementControlInformation is IE type 323: Traffic Parameter Measurement Control Information (Table 7.5.2.9-5).
	TrafficParameterMeasurementControlInformation uint16 = 323
	// TrafficParameterMeasurementReport is IE type 324: Traffic Parameter Measurement Report (Table 7.5.8.6-4).
	TrafficParameterMeasurementReport uint16 = 324
	// TrafficParameterThreshold is IE type 325: Traffic Parameter Threshold (Clause 8.2.220).
	TrafficParameterThreshold uint16 = 325
	// DLPeriodicity is IE type 326: DL Periodicity (Clause 8.2.221).
	DLPeriodicity uint16 = 326
	// N6JitterMeasurement is IE type 327: N6 Jitter Measurement (Clause 8.2.222).
	N6JitterMeasurement uint16 = 327
	// TrafficParameterMeasurementIndication is IE type 328: Traffic Parameter Measurement Indication (Clause 8.2.223).
	TrafficParameterMeasurementIndication uint16 = 328
	// ULPeriodicity is IE type 329: UL Periodicity (Clause 8.2.224).
	ULPeriodicity uint16 = 329
	// MPQUICControlInformation is IE type 330: MPQUIC Control Information (Clause 8.2.225).
	MPQUICControlInformation uint16 = 330
	// MPQUICParameters is IE type 331: MPQUIC Parameters (Table 7.5.3.7-5).
	MPQUICParameters uint16 = 331
	// MPQUICAddressInformation is IE type 332: MPQUIC Address Information (Clause 8.2.226).
	MPQUICAddressInformation uint16 = 332
	// TransportMode is IE type 333: Transport Mode (Clause 8.2.227).
	TransportMode uint16 = 333
	// ProtocolDescription is IE type 334: Protocol Description (Table 7.5.2.2-7).
	ProtocolDescription uint16 = 334
	// ReportingSuggestionInfo is IE type 335: Reporting Suggestion Info (Clause 8.2.229).
	ReportingSuggestionInfo uint16 = 335
	// TLContainer is IE type 336: TL-Container (Clause 8.2.230).
	TLContainer uint16 = 336
	// MeasurementIndication is IE type 337: Measurement Indication (Clause 8.2.231).
	MeasurementIndication uint16 = 337
	// HPLMNSNSSAI is IE type 338: HPLMN S-NSSAI (Clause 8.2.232).
	HPLMNSNSSAI uint16 = 338
	// MediaTransportProtocol is IE type 339: Media Transport Protocol (Clause 8.2.233).
	MediaTransportProtocol uint16 = 339
	// RTPHeaderExtensionInformation is IE type 340: RTP Header Extension Information (Table 7.5.2.2-8).
	RTPHeaderExtensionInformation uint16 = 340
	// RTPPayloadInformation is IE type 341: RTP Payload Information (Table 7.5.2.2-9).
	RTPPayloadInformation uint16 = 341
	// RTPHeaderExtensionType is IE type 342: RTP Header Extension Type (Clause 8.2.234).
	RTPHeaderExtensionType uint16 = 342
	// RTPHeaderExtensionID is IE type 343: RTP Header Extension ID (Clause 8.2.235).
	RTPHeaderExtensionID uint16 = 343
	// RTPPayloadType is IE type 344: RTP Payload Type (Clause 8.2.236).
	RTPPayloadType uint16 = 344
	// RTPPayloadFormat is IE type 345: RTP Payload Format (Clause 8.2.237).
	RTPPayloadFormat uint16 = 345
	// ExtendedDLBufferingNotificationPolicy is IE type 346: Extended DL Buffering Notification Policy (Clause 8.2.238).
	ExtendedDLBufferingNotificationPolicy uint16 = 346
	// MTSDTControlInformation is IE type 347: MT-SDT Control Information (Clause 8.2.239).
	MTSDTControlInformation uint16 = 347
	// ReportingThresholds is IE type 348: Reporting Thresholds (Clause 8.2.240).
	ReportingThresholds uint16 = 348
	// RTPHeaderExtensionAdditionalInformation is IE type 349: RTP Header Extension Additional Information (Clause 8.2.241).
	RTPHeaderExtensionAdditionalInformation uint16 = 349
	// MappedN6IPAddress is IE type 350: Mapped N6 IP Address (Clause 8.2.242).
	MappedN6IPAddress uint16 = 350
	// N6RoutingInformation is IE type 351: N6 Routing Information (Clause 8.2.243).
	N6RoutingInformation uint16 = 351
	// URI is IE type 352: URI (Clause 8.2.244).
	URI uint16 = 352
	// UELevelMeasurementsConfiguration is IE type 353: UE Level Measurements Configuration (Clause 8.2.245).
	UELevelMeasurementsConfiguration uint16 = 353
	// N6DelayMeasurementProtocols is IE type 354: N6 Delay Measurement Protocols (Clause 8.2.246).
	N6DelayMeasurementProtocols uint16 = 354
	// N6DelayMeasurementControlInformation is IE type 355: N6 Delay Measurement Control Information (Table 7.4.4.1.4-1).
	N6DelayMeasurementControlInformation uint16 = 355
	// N6DelayMeasurementReport is IE type 356: N6 Delay Measurement Report (PFCP Node Report Request) (Table 7.4.5.1.8-1).
	N6DelayMeasurementReport uint16 = 356
	// N6DelayMeasurementInformation is IE type 357: N6 Delay Measurement Information (Clause 8.2.247).
	N6DelayMeasurementInformation uint16 = 357
	// MeasurementEndpointAddress is IE type 358: Measurement Endpoint Address (Clause 8.2.248).
	MeasurementEndpointAddress uint16 = 358
	// OperatorConfigurableUPFCapability is IE type 359: Operator Configurable UPF Capability (Clause 8.2.249).
	OperatorConfigurableUPFCapability uint16 = 359
	// PacketInspectionFunctionality is IE type 360: Packet Inspection functionality (Clause 8.2.250).
	PacketInspectionFunctionality uint16 = 360
	// HeaderHandlingControlRule is IE type 361: Header Handling Control Rule (Table 7.5.2.3-7).
	HeaderHandlingControlRule uint16 = 361
	// HeaderHandlingReportingControlInfo is IE type 362: Header Handling Reporting Control Info (Table 7.5.2.3-8).
	HeaderHandlingReportingControlInfo uint16 = 362
	// HeaderHandlingControlInformation is IE type 363: Header Handling Control information (Table 7.5.2.3-9).
	HeaderHandlingControlInformation uint16 = 363
	// HeaderDetectionReference is IE type 364: Header Detection Reference (Clause 8.2.251).
	HeaderDetectionReference uint16 = 364
	// HeaderDetectionSupportInformation is IE type 365: Header Detection Support Information (Clause 8.2.252).
	HeaderDetectionSupportInformation uint16 = 365
	// ReportingEndpointID is IE type 366: Reporting Endpoint ID (Clause 8.2.253).
	ReportingEndpointID uint16 = 366
	// HeaderHandlingControlReference is IE type 367: Header Handling Control Reference (Clause 8.2.254).
	HeaderHandlingControlReference uint16 = 367
	// HeaderHandlingAction is IE type 368: Header Handling Action (Clause 8.2.255).
	HeaderHandlingAction uint16 = 368
	// HeaderInformation is IE type 369: Header Information (Clause 8.2.256).
	HeaderInformation uint16 = 369
	// HeaderValue is IE type 370: Header Value (Clause 8.2.257).
	HeaderValue uint16 = 370
	// HeaderHandlingCondition is IE type 371: Header Handling Condition (Clause 8.2.258).
	HeaderHandlingCondition uint16 = 371
	// HeaderHandlingControlID is IE type 372: Header Handling Control ID (Clause 8.2.259).
	HeaderHandlingControlID uint16 = 372
	// HeaderHandlingControlRuleID is IE type 373: Header Handling Control Rule ID (Clause 8.2.260).
	HeaderHandlingControlRuleID uint16 = 373
	// OnPathN6ConnectionInformation is IE type 374: On-path N6 Connection Information (Clause 8.2.261).
	OnPathN6ConnectionInformation uint16 = 374
	// MeasurementReportingType is IE type 375: Measurement Reporting Type (Clause 8.2.262).
	MeasurementReportingType uint16 = 375
	// N6DelayMeasurementFailureInformation is IE type 376: N6 Delay Measurement Failure Information (Clause 8.2.263).
	N6DelayMeasurementFailureInformation uint16 = 376
	// N6DelayMeasurementControlInformationID is IE type 377: N6 Delay Measurement Control Information ID (Clause 8.2.264).
	N6DelayMeasurementControlInformationID uint16 = 377
	// ProtocolSpecificConfigurationParameters is IE type 378: Protocol Specific Configuration Parameters (Table 7.4.4.1.4-2).
	ProtocolSpecificConfigurationParameters uint16 = 378
	// MeasurementEndpointPortNumber is IE type 379: Measurement Endpoint Port Number (Clause 8.2.265).
	MeasurementEndpointPortNumber uint16 = 379
	// HeaderHandlingReportingIndication is IE type 380: Header Handling Reporting Indication (Clause 8.2.266).
	HeaderHandlingReportingIndication uint16 = 380
	// SMFChangeReason is IE type 382: SMF Change Reason (Clause 8.2.267).
	SMFChangeReason uint16 = 382
	// ExtendedTransportLevelMarking is IE type 383: Extended Transport Level Marking (Table 7.5.2.3-10).
	ExtendedTransportLevelMarking uint16 = 383
	// PDUSetImportance is IE type 384: PDU Set Importance (Clause 8.2.268).
	PDUSetImportance uint16 = 384
	// MoQControlInformation is IE type 385: MoQ Control Information (Clause 8.2.269).
	MoQControlInformation uint16 = 385
	// MoQInformation is IE type 386: MoQ Information (Table 7.3.5.1-6).
	MoQInformation uint16 = 386
	// MoQRelayIPAddress is IE type 387: MoQ Relay IP Address (Clause 8.2.270).
	MoQRelayIPAddress uint16 = 387
	// MediaRelatedInformationTransferInfo is IE type 388: Media Related Information Transfer Info (Clause 8.2.271).
	MediaRelatedInformationTransferInfo uint16 = 388
	// ReportingControlInformation is IE type 389: Reporting Control Information (Clause 8.2.272).
	ReportingControlInformation uint16 = 389
	// SecurityModeSTAMP is IE type 390: Security Mode (STAMP) (Clause 8.2.273).
	SecurityModeSTAMP uint16 = 390
	// HMACKeySTAMP is IE type 391: HMAC Key (STAMP) (Clause 8.2.274).
	HMACKeySTAMP uint16 = 391
	// SecurityModeOWAMPOrTWAMP is IE type 392: Security Mode (OWAMP or TWAMP) (Clause 8.2.275).
	SecurityModeOWAMPOrTWAMP uint16 = 392
	// KeyIDAndSharedSecretOWAMPOrTWAMP is IE type 393: Key ID and Shared Secret (OWAMP or TWAMP) (Clause 8.2.276).
	KeyIDAndSharedSecretOWAMPOrTWAMP uint16 = 393
	// RemainingDataReportingIndication is IE type 394: Remaining Data Reporting Indication (Clause 8.2.277).
	RemainingDataReportingIndication uint16 = 394
	// ExpeditedTransferIndication is IE type 395: Expedited Transfer Indication (Clause 8.2.278).
	ExpeditedTransferIndication uint16 = 395
	// SessionReflectorModeSTAMP is IE type 396: Session Reflector Mode (STAMP) (Clause 8.2.279).
	SessionReflectorModeSTAMP uint16 = 396
	// PFDPartialFailureInformation is IE type 397: PFD Partial Failure Information (Table 7.4.3.2-2).
	PFDPartialFailureInformation uint16 = 397
	// TransportLevelMarkingIndications is IE type 398: Transport Level Marking Indications (Clause 8.2.280).
	TransportLevelMarkingIndications uint16 = 398
	// RedundantN3N9TransmissionInformation is IE type 399: Redundant N3/N9 Transmission Information (Table 7.5.8.6-5).
	RedundantN3N9TransmissionInformation uint16 = 399
	// LocalN3N9TunnelInformation is IE type 400: Local N3/N9 Tunnel Information (Table 7.5.8.6-6).
	LocalN3N9TunnelInformation uint16 = 400
	// RemoteN3N9TunnelInformation is IE type 401: Remote N3/N9 Tunnel Information (Table 7.5.8.6-7).
	RemoteN3N9TunnelInformation uint16 = 401
	// BindingIndication is IE type 402: Binding Indication (Clause 8.2.281).
	BindingIndication uint16 = 402
	// PDUSetImportanceForN6UnmarkedPDUs is IE type 403: PDU Set Importance for N6-unmarked PDUs (Clause 8.2.282).
	PDUSetImportanceForN6UnmarkedPDUs uint16 = 403
)

// lastSpecType is the highest IE type defined by TS 29.244 V19.6.0.
const lastSpecType uint16 = 403

var ieNames = map[uint16]string{
	272: "Partial Failure Information",
	274: "Offending IE Information",
	275: "RAT Type",
	276: "L2TP Tunnel Information",
	277: "L2TP Session Information",
	278: "L2TP User Authentication",
	279: "Created L2TP Session",
	280: "LNS Address",
	281: "Tunnel Preference",
	282: "Calling Number",
	283: "Called Number",
	284: "L2TP Session Indications",
	285: "DNS Server Address",
	286: "NBNS Server Address",
	287: "Maximum Receive Unit",
	288: "Thresholds",
	289: "Steering Mode Indicator",
	290: "PFCP Session Change Info",
	291: "Group ID",
	292: "CP IP Address",
	293: "IP Address and Port number Replacement",
	294: "DNS Query/Response Filter",
	295: "Direct Reporting Information",
	296: "Event Notification URI",
	297: "Notification Correlation ID",
	298: "Reporting Flags",
	299: "Predefined Rules Name",
	300: "MBS Session N4mb Control Information",
	301: "MBS Multicast Parameters",
	302: "Add MBS Unicast Parameters",
	303: "MBS Session N4mb Information",
	304: "Remove MBS Unicast Parameters",
	305: "MBS Session Identifier",
	306: "Multicast Transport Information",
	307: "MBSN4mbReq-Flags",
	308: "Local Ingress Tunnel",
	309: "MBS Unicast Parameters ID",
	310: "MBS Session N4 Control Information",
	311: "MBS Session N4 Information",
	312: "MBSN4Resp-Flags",
	313: "Tunnel Password",
	314: "Area Session ID",
	315: "Peer UP Restart Report",
	316: "DSCP to PPI Control Information",
	317: "DSCP to PPI Mapping Information",
	318: "PFCPSDRsp-Flags",
	319: "QER Indications",
	320: "Vendor-Specific Node Report Type",
	321: "Configured Time Domain",
	322: "Metadata",
	323: "Traffic Parameter Measurement Control Information",
	324: "Traffic Parameter Measurement Report",
	325: "Traffic Parameter Threshold",
	326: "DL Periodicity",
	327: "N6 Jitter Measurement",
	328: "Traffic Parameter Measurement Indication",
	329: "UL Periodicity",
	330: "MPQUIC Control Information",
	331: "MPQUIC Parameters",
	332: "MPQUIC Address Information",
	333: "Transport Mode",
	334: "Protocol Description",
	335: "Reporting Suggestion Info",
	336: "TL-Container",
	337: "Measurement Indication",
	338: "HPLMN S-NSSAI",
	339: "Media Transport Protocol",
	340: "RTP Header Extension Information",
	341: "RTP Payload Information",
	342: "RTP Header Extension Type",
	343: "RTP Header Extension ID",
	344: "RTP Payload Type",
	345: "RTP Payload Format",
	346: "Extended DL Buffering Notification Policy",
	347: "MT-SDT Control Information",
	348: "Reporting Thresholds",
	349: "RTP Header Extension Additional Information",
	350: "Mapped N6 IP Address",
	351: "N6 Routing Information",
	352: "URI",
	353: "UE Level Measurements Configuration",
	354: "N6 Delay Measurement Protocols",
	355: "N6 Delay Measurement Control Information",
	356: "N6 Delay Measurement Report (PFCP Node Report Request)",
	357: "N6 Delay Measurement Information",
	358: "Measurement Endpoint Address",
	359: "Operator Configurable UPF Capability",
	360: "Packet Inspection functionality",
	361: "Header Handling Control Rule",
	362: "Header Handling Reporting Control Info",
	363: "Header Handling Control information",
	364: "Header Detection Reference",
	365: "Header Detection Support Information",
	366: "Reporting Endpoint ID",
	367: "Header Handling Control Reference",
	368: "Header Handling Action",
	369: "Header Information",
	370: "Header Value",
	371: "Header Handling Condition",
	372: "Header Handling Control ID",
	373: "Header Handling Control Rule ID",
	374: "On-path N6 Connection Information",
	375: "Measurement Reporting Type",
	376: "N6 Delay Measurement Failure Information",
	377: "N6 Delay Measurement Control Information ID",
	378: "Protocol Specific Configuration Parameters",
	379: "Measurement Endpoint Port Number",
	380: "Header Handling Reporting Indication",
	382: "SMF Change Reason",
	383: "Extended Transport Level Marking",
	384: "PDU Set Importance",
	385: "MoQ Control Information",
	386: "MoQ Information",
	387: "MoQ Relay IP Address",
	388: "Media Related Information Transfer Info",
	389: "Reporting Control Information",
	390: "Security Mode (STAMP)",
	391: "HMAC Key (STAMP)",
	392: "Security Mode (OWAMP or TWAMP)",
	393: "Key ID and Shared Secret (OWAMP or TWAMP)",
	394: "Remaining Data Reporting Indication",
	395: "Expedited Transfer Indication",
	396: "Session Reflector Mode (STAMP)",
	397: "PFD Partial Failure Information",
	398: "Transport Level Marking Indications",
	399: "Redundant N3/N9 Transmission Information",
	400: "Local N3/N9 Tunnel Information",
	401: "Remote N3/N9 Tunnel Information",
	402: "Binding Indication",
	403: "PDU Set Importance for N6-unmarked PDUs",
}

// groupedTypes lists the extension types whose Table 8.1.2-1 entry refers to
// a grouped-IE table in clause 7 (TS 29.244 V19.6.0).
var groupedTypes = map[uint16]struct{}{
	PartialFailureInformation:                     {},
	L2TPTunnelInformation:                         {},
	L2TPSessionInformation:                        {},
	CreatedL2TPSession:                            {},
	PFCPSessionChangeInfo:                         {},
	DirectReportingInformation:                    {},
	MBSSessionN4mbControlInformation:              {},
	MBSMulticastParameters:                        {},
	AddMBSUnicastParameters:                       {},
	MBSSessionN4mbInformation:                     {},
	RemoveMBSUnicastParameters:                    {},
	MBSSessionN4ControlInformation:                {},
	MBSSessionN4Information:                       {},
	PeerUPRestartReport:                           {},
	DSCPToPPIControlInformation:                   {},
	TrafficParameterMeasurementControlInformation: {},
	TrafficParameterMeasurementReport:             {},
	MPQUICParameters:                              {},
	ProtocolDescription:                           {},
	RTPHeaderExtensionInformation:                 {},
	RTPPayloadInformation:                         {},
	N6DelayMeasurementControlInformation:          {},
	N6DelayMeasurementReport:                      {},
	HeaderHandlingControlRule:                     {},
	HeaderHandlingReportingControlInfo:            {},
	HeaderHandlingControlInformation:              {},
	ProtocolSpecificConfigurationParameters:       {},
	ExtendedTransportLevelMarking:                 {},
	MoQInformation:                                {},
	PFDPartialFailureInformation:                  {},
	RedundantN3N9TransmissionInformation:          {},
	LocalN3N9TunnelInformation:                    {},
	RemoteN3N9TunnelInformation:                   {},
}
