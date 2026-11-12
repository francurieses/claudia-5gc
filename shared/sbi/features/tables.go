// Per-API feature tables transcribed from the 3GPP "Supported Features"
// clauses, plus helpers to derive an NF's implemented subset.

package features

import (
	"fmt"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// Design note: the API tables are API facts, so they live once here in shared
// (one transcription for every producer and consumer of an API); each NF's
// internal/sbi/features.go builds its Catalog from them and marks what it
// implements with Implement. This deliberately refines PLAN 2.7 ("internal/
// sbi/features.go lists the API's features"), avoiding a dozen duplicated
// transcriptions.
//
// Release column: the spec table does not record whether a bit originated in
// Rel-15, 16 or 17. Every bit present in the V17 table is tagged Rel17 (all
// are <= the rel17 profile, so gating is unaffected); bits first appearing in
// the V18 table are Rel18 and those first in the V19 table are Rel19.
// Mandatory records "M" in the M/O column. Every entry has Implemented=false.

// NsmfPDUSessionEntries returns a fresh copy of Table 6.1.8-1 of TS 29.502
// (Nsmf_PDUSession, features 1-41), transcribed from V17.14.0, V18.12.0 and
// V19.8.0. Features 1-21 are in V17, 22-33 first appear in V18, 34-41 in V19.
func NsmfPDUSessionEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "CIOT", Release: capability.Rel17},
		{Number: 2, Name: "MAPDU", Release: capability.Rel17},
		{Number: 3, Name: "DTSSA", Release: capability.Rel17},
		{Number: 4, Name: "CARPT", Release: capability.Rel17},
		{Number: 5, Name: "CTXTR", Release: capability.Rel17},
		{Number: 6, Name: "VQOS", Release: capability.Rel17},
		{Number: 7, Name: "HOFAIL", Release: capability.Rel17, Mandatory: true},
		{Number: 8, Name: "ES3XX", Release: capability.Rel17, Mandatory: true},
		{Number: 9, Name: "DCE2ER", Release: capability.Rel17},
		{Number: 10, Name: "AASN", Release: capability.Rel17, Mandatory: true},
		{Number: 11, Name: "EnEDGE", Release: capability.Rel17},
		{Number: 12, Name: "SCPBU", Release: capability.Rel17},
		{Number: 13, Name: "ENPN", Release: capability.Rel17},
		{Number: 14, Name: "SPAE", Release: capability.Rel17},
		{Number: 15, Name: "5GSAT", Release: capability.Rel17},
		{Number: 16, Name: "UPIPE", Release: capability.Rel17},
		{Number: 17, Name: "BIUMR", Release: capability.Rel17},
		{Number: 18, Name: "ACSCR", Release: capability.Rel17},
		{Number: 19, Name: "PSETR", Release: capability.Rel17},
		{Number: 20, Name: "DLSET", Release: capability.Rel17},
		{Number: 21, Name: "N9FSC", Release: capability.Rel17},
		{Number: 22, Name: "DTSSA-Ext1", Release: capability.Rel18},
		{Number: 23, Name: "5GSATB", Release: capability.Rel18},
		{Number: 24, Name: "HR-SBO", Release: capability.Rel18},
		{Number: 25, Name: "N3GPS", Release: capability.Rel18},
		{Number: 26, Name: "NSRP", Release: capability.Rel18},
		{Number: 27, Name: "UPCSMT", Release: capability.Rel18},
		{Number: 28, Name: "PSER", Release: capability.Rel18},
		{Number: 29, Name: "SCID", Release: capability.Rel18, Mandatory: true},
		{Number: 30, Name: "PDUSH", Release: capability.Rel18},
		{Number: 31, Name: "EMECI", Release: capability.Rel18},
		{Number: 32, Name: "UEPSM", Release: capability.Rel18},
		{Number: 33, Name: "SAR", Release: capability.Rel18},
		{Number: 34, Name: "QME", Release: capability.Rel19},
		{Number: 35, Name: "NLIRN16", Release: capability.Rel19},
		{Number: 36, Name: "ISMF-LOM", Release: capability.Rel19},
		{Number: 37, Name: "N1N2BGER", Release: capability.Rel19},
		{Number: 38, Name: "SUBDMIG", Release: capability.Rel19},
		{Number: 39, Name: "AMF-RESYNCHED", Release: capability.Rel19},
		{Number: 40, Name: "5GSAT-ACCESS", Release: capability.Rel19},
		{Number: 41, Name: "AVABIT", Release: capability.Rel19},
	}
}

// NamfCommunicationEntries returns a fresh copy of Table 6.1.8-1 of TS 29.518
// (Namf_Communication, features 1-22), transcribed from V17.18.0, V18.15.0 and
// V19.8.0. Features 1-13 and 20 are in V17 (numbers 14-19 were unassigned
// there), 14-19 and 21 first appear in V18, 22 in V19.
func NamfCommunicationEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "DTSSA", Release: capability.Rel17},
		{Number: 2, Name: "ENS", Release: capability.Rel17},
		{Number: 3, Name: "CIOT", Release: capability.Rel17},
		{Number: 4, Name: "MAPDU", Release: capability.Rel17},
		{Number: 5, Name: "NPN", Release: capability.Rel17},
		{Number: 6, Name: "ELCS", Release: capability.Rel17},
		{Number: 7, Name: "ES3XX", Release: capability.Rel17, Mandatory: true},
		{Number: 8, Name: "EAEA", Release: capability.Rel17},
		{Number: 9, Name: "ProSe", Release: capability.Rel17},
		{Number: 10, Name: "UAV", Release: capability.Rel17},
		{Number: 11, Name: "SPAE", Release: capability.Rel17},
		{Number: 12, Name: "eNPN", Release: capability.Rel17},
		{Number: 13, Name: "3GA-N3GA-HO", Release: capability.Rel17},
		{Number: 14, Name: "PAR-NS", Release: capability.Rel18},
		{Number: 15, Name: "NTSSM", Release: capability.Rel18},
		{Number: 16, Name: "RACS", Release: capability.Rel18},
		{Number: 17, Name: "Ranging_SL", Release: capability.Rel18},
		{Number: 18, Name: "A2X", Release: capability.Rel18},
		{Number: 19, Name: "AoV-En", Release: capability.Rel18},
		{Number: 20, Name: "ASUC", Release: capability.Rel17},
		{Number: 21, Name: "SliceUsageCtrl", Release: capability.Rel18},
		{Number: 22, Name: "ProSe_Multihop", Release: capability.Rel19},
	}
}

// NausfUEAuthenticationEntries returns a fresh copy of Table 6.1.9-1 of TS
// 29.509 (Nausf_UEAuthentication, clause 6.1.9 "Feature Negotiation"),
// transcribed from V17.12.0, V18.6.0 and V19.6.0. The table has the single
// feature 1 ES3XX (M) in all three releases. The obligation sits on the NF
// Service Consumer (e.g. the AMF), so an AUSF producer never marks it.
func NausfUEAuthenticationEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "ES3XX", Release: capability.Rel17, Mandatory: true},
	}
}

// NudmUEAUEntries returns a fresh copy of Table 6.3.8-1 of TS 29.503
// (Nudm_UEAuthentication, "Nudm_UEAU", clause 6.3.8 "Feature Negotiation"),
// transcribed from V17.22.0, V18.13.0 and V19.7.0. The table is empty in V17
// and V18; V19 adds the single feature 1 SUBDMIG (Subscriber Data Migration
// attributes in the Data Restoration Notification).
func NudmUEAUEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "SUBDMIG", Release: capability.Rel19},
	}
}

// NudmSDMEntries returns a fresh copy of Table 6.1.8-1 of TS 29.503
// (Nudm_SDM, clause 6.1.8 "Feature Negotiation", features 1-25), transcribed
// from V17.22.0, V18.13.0 and V19.7.0. V17 lists features 1-15 and 19;
// 16-18 and 22 first appear in V18, 20, 21 and 23-25 in V19. The table has no
// M/O column and no reserved numbers, so no entry is Mandatory. On the
// Nudm_SDM Get operations the value travels in the "supported-features" query
// parameter (request) and the supportedFeatures attribute of the returned
// subscription data (response); on Subscribe in SdmSubscription.supportedFeatures.
func NudmSDMEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "SharedData", Release: capability.Rel17},
		{Number: 2, Name: "ImmediateReport", Release: capability.Rel17},
		{Number: 3, Name: "PatchReport", Release: capability.Rel17},
		{Number: 4, Name: "Nssaa", Release: capability.Rel17},
		{Number: 5, Name: "CAGFeature", Release: capability.Rel17},
		{Number: 6, Name: "SharedDataTreatment", Release: capability.Rel17},
		{Number: 7, Name: "sorTransparentSupport", Release: capability.Rel17},
		{Number: 8, Name: "Nsac", Release: capability.Rel17},
		{Number: 9, Name: "SharedSmSubsData", Release: capability.Rel17},
		{Number: 10, Name: "ENA", Release: capability.Rel17},
		{Number: 11, Name: "Nssrg", Release: capability.Rel17},
		{Number: 12, Name: "upuTransparentSupport", Release: capability.Rel17},
		{Number: 13, Name: "LimitedSubscriptions", Release: capability.Rel17},
		{Number: 14, Name: "SNPN-ID", Release: capability.Rel17},
		{Number: 15, Name: "UeConSmfDataSubFilter", Release: capability.Rel17},
		{Number: 16, Name: "TempSliceSupport", Release: capability.Rel18},
		{Number: 17, Name: "ExpectedBehaviourMap", Release: capability.Rel18},
		{Number: 18, Name: "SharedDataExt", Release: capability.Rel18},
		{Number: 19, Name: "SNPN-ID-EXT", Release: capability.Rel17},
		{Number: 20, Name: "OdbExemptedDnn", Release: capability.Rel19},
		{Number: 21, Name: "MultiSupiToGpsiTranslation", Release: capability.Rel19},
		{Number: 22, Name: "Cag-Info-With-Validity-Periods", Release: capability.Rel18},
		{Number: 23, Name: "SUBDMIG", Release: capability.Rel19},
		{Number: 24, Name: "ECRATU", Release: capability.Rel19},
		{Number: 25, Name: "PCPDEIVID", Release: capability.Rel19},
	}
}

// NudmUECMEntries returns a fresh copy of Table 6.2.8-1 of TS 29.503
// (Nudm_UECM, clause 6.2.8 "Feature Negotiation", features 1-6), transcribed
// from V17.22.0, V18.13.0 and V19.7.0. V17 lists features 1-3, V18 adds 4 and
// 5, V19 adds 6. The table has no M/O column, so no entry is Mandatory. The
// value travels in the supportedFeatures attribute of the registration
// resources (e.g. Amf3GppAccessRegistration).
func NudmUECMEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "SharedData", Release: capability.Rel17},
		{Number: 2, Name: "PatchReport", Release: capability.Rel17},
		{Number: 3, Name: "SharedDataTreatment", Release: capability.Rel17},
		{Number: 4, Name: "CAGFeature", Release: capability.Rel18},
		{Number: 5, Name: "DeregistrationResponseBody", Release: capability.Rel18},
		{Number: 6, Name: "SUBDMIG", Release: capability.Rel19},
	}
}

// AsSessionWithQoSEntries returns a fresh copy of Table 5.14.4-1 of TS 29.122
// (AsSessionWithQoS API, clause 5.14.4 "Used Features", features 1-38),
// transcribed from V17.14.0, V18.10.0 and V19.7.0; this is the API the NEF
// serves as 3gpp-as-session-with-qos. Features 1-15 are in V17, 16-29 first
// appear in V18 and 30-38 in V19. The table has no M/O column, so no entry is
// Mandatory. TS 29.122 clause 5.2.7 applies the TS 29.500 clause 6.6.2
// procedure to the northbound APIs.
func AsSessionWithQoSEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "Notification_websocket", Release: capability.Rel17},
		{Number: 2, Name: "Notification_test_event", Release: capability.Rel17},
		{Number: 3, Name: "EthAsSessionQoS_5G", Release: capability.Rel17},
		{Number: 4, Name: "MacAddressRange_5G", Release: capability.Rel17},
		{Number: 5, Name: "AlternativeQoS_5G", Release: capability.Rel17},
		{Number: 6, Name: "QoSMonitoring_5G", Release: capability.Rel17},
		{Number: 7, Name: "DisableUENotification_5G", Release: capability.Rel17},
		{Number: 8, Name: "TSC_5G", Release: capability.Rel17},
		{Number: 9, Name: "AppId", Release: capability.Rel17},
		{Number: 10, Name: "ExposureToEAS", Release: capability.Rel17},
		{Number: 11, Name: "enNB", Release: capability.Rel17},
		{Number: 12, Name: "AltQosWithIndParams_5G", Release: capability.Rel17},
		{Number: 13, Name: "EnEthAsSessionQoS_5G", Release: capability.Rel17},
		{Number: 14, Name: "enNB_5G", Release: capability.Rel17},
		{Number: 15, Name: "PacketDelayFailureReport", Release: capability.Rel17},
		{Number: 16, Name: "ToSTC_5G", Release: capability.Rel18},
		{Number: 17, Name: "EnTSCAC", Release: capability.Rel18},
		{Number: 18, Name: "AltQoSProfilesSupportReport", Release: capability.Rel18},
		{Number: 19, Name: "ExtQoS_5G", Release: capability.Rel18},
		{Number: 20, Name: "MultiMedia", Release: capability.Rel18},
		{Number: 21, Name: "ExtErrors", Release: capability.Rel18},
		{Number: 22, Name: "QoSTiming_5G", Release: capability.Rel18},
		{Number: 23, Name: "ListUE_5G", Release: capability.Rel18},
		{Number: 24, Name: "GMEC", Release: capability.Rel18},
		{Number: 25, Name: "PDUSetHandling", Release: capability.Rel18},
		{Number: 26, Name: "RTLatency", Release: capability.Rel18},
		{Number: 27, Name: "EnQoSMon", Release: capability.Rel18},
		{Number: 28, Name: "PowerSaving", Release: capability.Rel18},
		{Number: 29, Name: "L4S", Release: capability.Rel18},
		{Number: 30, Name: "QoSMonCapRepo", Release: capability.Rel19},
		{Number: 31, Name: "TrafficCharChange", Release: capability.Rel19},
		{Number: 32, Name: "MpxMedia", Release: capability.Rel19},
		{Number: 33, Name: "OnPathN6MediaInfo", Release: capability.Rel19},
		{Number: 34, Name: "RateLimitReport", Release: capability.Rel19},
		{Number: 35, Name: "AcceptableQosDetails", Release: capability.Rel19},
		{Number: 36, Name: "ExtQoSR19", Release: capability.Rel19},
		{Number: 37, Name: "EnQoSMon_v2", Release: capability.Rel19},
		{Number: 38, Name: "SmallBurstSizes", Release: capability.Rel19},
	}
}

// NbsfManagementEntries returns a fresh copy of Table 5.8-1 of TS 29.521
// (Nbsf_Management, clause 5.8 "Feature negotiation", features 1-8),
// transcribed from V17.11.0, V18.7.0 and V19.7.0. Features 1-6 (MultiUeAddr,
// BindingUpdate, SamePcf, ES3XX, ExtendedSamePcf, AddSnssaiDnnPair) are in V17
// and V18; 7 (Recovery) and 8 (ExpTime) first appear in V19. The table has no
// M/O column, so no entry is Mandatory. The attribute carrying the value is
// "suppFeat" (PcfBinding, BsfSubscription, ...) and the discovery query
// parameter is "supp-feat".
func NbsfManagementEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "MultiUeAddr", Release: capability.Rel17},
		{Number: 2, Name: "BindingUpdate", Release: capability.Rel17},
		{Number: 3, Name: "SamePcf", Release: capability.Rel17},
		{Number: 4, Name: "ES3XX", Release: capability.Rel17},
		{Number: 5, Name: "ExtendedSamePcf", Release: capability.Rel17},
		{Number: 6, Name: "AddSnssaiDnnPair", Release: capability.Rel17},
		{Number: 7, Name: "Recovery", Release: capability.Rel19},
		{Number: 8, Name: "ExpTime", Release: capability.Rel19},
	}
}

// NsmsfSMServiceEntries returns a fresh copy of Table 6.1.8-1 of TS 29.540
// (Nsmsf_SMService, clause 6.1.8 "Feature negotiation"), transcribed from
// V17.6.0, V18.5.0 and V19.6.0. The table is identical in all three: 1 ES3XX
// (M) and 2 PatchReport (O).
func NsmsfSMServiceEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "ES3XX", Release: capability.Rel17, Mandatory: true},
		{Number: 2, Name: "PatchReport", Release: capability.Rel17},
	}
}

// NlmfLocationEntries returns a fresh copy of Table 6.1.9-1 of TS 29.572
// (Nlmf_Location, clause 6.1.9 "Feature Negotiation", features 1-9),
// transcribed from V17.13.0, V18.11.0 and V19.7.0. V17 lists 1 ES3XX (M), 2 SAT,
// 3 MUTIQOS and 6 INTRES (numbers 4 and 5 are not assigned there); V18 adds
// 4 MBSR, 5 Ranging_SL and 7 CIMLR; V19 adds 8 MCTX and 9 MWAB.
func NlmfLocationEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "ES3XX", Release: capability.Rel17, Mandatory: true},
		{Number: 2, Name: "SAT", Release: capability.Rel17},
		{Number: 3, Name: "MUTIQOS", Release: capability.Rel17},
		{Number: 4, Name: "MBSR", Release: capability.Rel18},
		{Number: 5, Name: "Ranging_SL", Release: capability.Rel18},
		{Number: 6, Name: "INTRES", Release: capability.Rel17},
		{Number: 7, Name: "CIMLR", Release: capability.Rel18},
		{Number: 8, Name: "MCTX", Release: capability.Rel19},
		{Number: 9, Name: "MWAB", Release: capability.Rel19},
	}
}

// NnssfNSSelectionEntries returns a fresh copy of Table 6.1.8-1 of TS 29.531
// (Nnssf_NSSelection, clause 6.1.8 "Feature negotiation"), transcribed from
// V17.12.0, V18.10.0 and V19.7.0. The table is identical in all three: 1 ES3XX
// (M), 2 TargetNssai, 3 RSIPCE and 4 SIOP.
func NnssfNSSelectionEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "ES3XX", Release: capability.Rel17, Mandatory: true},
		{Number: 2, Name: "TargetNssai", Release: capability.Rel17},
		{Number: 3, Name: "RSIPCE", Release: capability.Rel17},
		{Number: 4, Name: "SIOP", Release: capability.Rel17},
	}
}

// NpcfSMPolicyControlEntries returns a fresh copy of Table 5.8-1 of TS 29.512
// (Npcf_SMPolicyControl, clause 5.8 "Feature negotiation", features 1-119),
// transcribed from V17.18.0, V18.13.0 and V19.7.0. Features 1-73 are in V17,
// 74-98 first appear in V18 and 99-119 in V19. The table has no M/O column, so
// no entry is Mandatory (ES3XX, 43, is a consumer-side capability here as in
// the other APIs). The attribute carrying the value is "suppFeat"
// (SmPolicyContextData in the request, SmPolicyDecision in the response).
func NpcfSMPolicyControlEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "TSC", Release: capability.Rel17},
		{Number: 2, Name: "ResShare", Release: capability.Rel17},
		{Number: 3, Name: "3GPP-PS-Data-Off", Release: capability.Rel17},
		{Number: 4, Name: "ADC", Release: capability.Rel17},
		{Number: 5, Name: "UMC", Release: capability.Rel17},
		{Number: 6, Name: "NetLoc", Release: capability.Rel17},
		{Number: 7, Name: "RAN-NAS-Cause", Release: capability.Rel17},
		{Number: 8, Name: "ProvAFsignalFlow", Release: capability.Rel17},
		{Number: 9, Name: "PCSCF-Restoration-Enhancement", Release: capability.Rel17},
		{Number: 10, Name: "PRA", Release: capability.Rel17},
		{Number: 11, Name: "RuleVersioning", Release: capability.Rel17},
		{Number: 12, Name: "SponsoredConnectivity", Release: capability.Rel17},
		{Number: 13, Name: "RAN-Support-Info", Release: capability.Rel17},
		{Number: 14, Name: "PolicyUpdateWhenUESuspends", Release: capability.Rel17},
		{Number: 15, Name: "AccessTypeCondition", Release: capability.Rel17},
		{Number: 16, Name: "MultiIpv6AddrPrefix", Release: capability.Rel17},
		{Number: 17, Name: "SessionRuleErrorHandling", Release: capability.Rel17},
		{Number: 18, Name: "AF_Charging_Identifier", Release: capability.Rel17},
		{Number: 19, Name: "ATSSS", Release: capability.Rel17},
		{Number: 20, Name: "PendingTransaction", Release: capability.Rel17},
		{Number: 21, Name: "URLLC", Release: capability.Rel17},
		{Number: 22, Name: "MacAddressRange", Release: capability.Rel17},
		{Number: 23, Name: "WWC", Release: capability.Rel17},
		{Number: 24, Name: "QosMonitoring", Release: capability.Rel17},
		{Number: 25, Name: "AuthorizationWithRequiredQoS", Release: capability.Rel17},
		{Number: 26, Name: "EnhancedBackgroundDataTransfer", Release: capability.Rel17},
		{Number: 27, Name: "DN-Authorization", Release: capability.Rel17},
		{Number: 28, Name: "PDUSessionRelCause", Release: capability.Rel17},
		{Number: 29, Name: "SamePcf", Release: capability.Rel17},
		{Number: 30, Name: "ADCmultiRedirection", Release: capability.Rel17},
		{Number: 31, Name: "RespBasedSessionRel", Release: capability.Rel17},
		{Number: 32, Name: "TimeSensitiveNetworking", Release: capability.Rel17},
		{Number: 33, Name: "EMDBV", Release: capability.Rel17},
		{Number: 34, Name: "DNNSelectionMode", Release: capability.Rel17},
		{Number: 35, Name: "EPSFallbackReport", Release: capability.Rel17},
		{Number: 36, Name: "PolicyDecisionErrorHandling", Release: capability.Rel17},
		{Number: 37, Name: "DDNEventPolicyControl", Release: capability.Rel17},
		{Number: 38, Name: "ReallocationOfCredit", Release: capability.Rel17},
		{Number: 39, Name: "BDTPolicyRenegotiation", Release: capability.Rel17},
		{Number: 40, Name: "ExtPolicyDecisionErrorHandling", Release: capability.Rel17},
		{Number: 41, Name: "ImmediateTermination", Release: capability.Rel17},
		{Number: 42, Name: "AggregatedUELocChanges", Release: capability.Rel17},
		{Number: 43, Name: "ES3XX", Release: capability.Rel17},
		{Number: 44, Name: "GroupIdListChange", Release: capability.Rel17},
		{Number: 45, Name: "DisableUENotification", Release: capability.Rel17},
		{Number: 46, Name: "OfflineChOnly", Release: capability.Rel17},
		{Number: 47, Name: "Dual-Connectivity-redundant-UP-paths", Release: capability.Rel17},
		{Number: 48, Name: "DDNEventPolicyControl2", Release: capability.Rel17},
		{Number: 49, Name: "VPLMN-QoS-Control", Release: capability.Rel17},
		{Number: 50, Name: "2G3GIWK", Release: capability.Rel17},
		{Number: 51, Name: "TimeSensitiveCommunication", Release: capability.Rel17},
		{Number: 52, Name: "AF_latency", Release: capability.Rel17},
		{Number: 53, Name: "SatBackhaulCategoryChg", Release: capability.Rel17},
		{Number: 54, Name: "CHFsetSupport", Release: capability.Rel17},
		{Number: 55, Name: "EnATSSS", Release: capability.Rel17},
		{Number: 56, Name: "MPSforDTS", Release: capability.Rel17},
		{Number: 57, Name: "RoutingInfoRemoval", Release: capability.Rel17},
		{Number: 58, Name: "ePRA", Release: capability.Rel17},
		{Number: 59, Name: "AMInfluence", Release: capability.Rel17},
		{Number: 60, Name: "PvsSupport", Release: capability.Rel17},
		{Number: 61, Name: "EneNA", Release: capability.Rel17},
		{Number: 62, Name: "BIUMR", Release: capability.Rel17},
		{Number: 63, Name: "EASIPreplacement", Release: capability.Rel17},
		{Number: 64, Name: "ExposureToEAS", Release: capability.Rel17},
		{Number: 65, Name: "SimultConnectivity", Release: capability.Rel17},
		{Number: 66, Name: "SGWRest", Release: capability.Rel17},
		{Number: 67, Name: "ReleaseToReactivate", Release: capability.Rel17},
		{Number: 68, Name: "EASDiscovery", Release: capability.Rel17},
		{Number: 69, Name: "AccNetChargId_String", Release: capability.Rel17},
		{Number: 70, Name: "WLAN_Location", Release: capability.Rel17},
		{Number: 71, Name: "PackFiltAllocPrecedence", Release: capability.Rel17},
		{Number: 72, Name: "SatBackhaulCategoryChg_v2", Release: capability.Rel17},
		{Number: 73, Name: "PacketDelayFailureReport", Release: capability.Rel17},
		{Number: 74, Name: "AltQoSProfilesSupportReport", Release: capability.Rel18},
		{Number: 75, Name: "Ext2PolicyDecisionErrorHandling", Release: capability.Rel18},
		{Number: 76, Name: "UEUnreachable", Release: capability.Rel18},
		{Number: 77, Name: "EnTSCAC", Release: capability.Rel18},
		{Number: 78, Name: "MTU_Size", Release: capability.Rel18},
		{Number: 79, Name: "EnSatBackhaulCatChg", Release: capability.Rel18},
		{Number: 80, Name: "SFC", Release: capability.Rel18},
		{Number: 81, Name: "EpsUrsp", Release: capability.Rel18},
		{Number: 82, Name: "CommonEASDNAI", Release: capability.Rel18},
		{Number: 83, Name: "UnlimitedMultiIpv6Prefix", Release: capability.Rel18},
		{Number: 84, Name: "NscSupportedFeatures", Release: capability.Rel18},
		{Number: 85, Name: "URSPEnforcement", Release: capability.Rel18},
		{Number: 86, Name: "VBCforIMS", Release: capability.Rel18},
		{Number: 87, Name: "ExposureToTSC", Release: capability.Rel18},
		{Number: 88, Name: "NetSliceRepl", Release: capability.Rel18},
		{Number: 89, Name: "SessQoSModEnforcementFailure", Release: capability.Rel18},
		{Number: 90, Name: "HR-SBO", Release: capability.Rel18},
		{Number: 91, Name: "EnATSSS_v2", Release: capability.Rel18},
		{Number: 92, Name: "NetSliceUsageCtrl", Release: capability.Rel18},
		{Number: 93, Name: "VPLMN-5QIPrioLevel", Release: capability.Rel18},
		{Number: 94, Name: "PDUSetHandling", Release: capability.Rel18},
		{Number: 95, Name: "EnQoSMon", Release: capability.Rel18},
		{Number: 96, Name: "PowerSaving", Release: capability.Rel18},
		{Number: 97, Name: "L4S", Release: capability.Rel18},
		{Number: 98, Name: "UPEAS", Release: capability.Rel18},
		{Number: 99, Name: "QoSMonCapRepo", Release: capability.Rel19},
		{Number: 100, Name: "LocalOffloading", Release: capability.Rel19},
		{Number: 101, Name: "TraffRouteReqOutcome", Release: capability.Rel19},
		{Number: 102, Name: "EnATSSS_v3", Release: capability.Rel19},
		{Number: 103, Name: "EnEpsUrsp", Release: capability.Rel19},
		{Number: 104, Name: "MpxMedia", Release: capability.Rel19},
		{Number: 105, Name: "N6DelayMeasurement", Release: capability.Rel19},
		{Number: 106, Name: "Non3gppDevice", Release: capability.Rel19},
		{Number: 107, Name: "TrafficCharChange", Release: capability.Rel19},
		{Number: 108, Name: "HeaderHandling", Release: capability.Rel19},
		{Number: 109, Name: "UeSatUeComm", Release: capability.Rel19},
		{Number: 110, Name: "ExtQoSR19", Release: capability.Rel19},
		{Number: 111, Name: "SimConnFailure", Release: capability.Rel19},
		{Number: 112, Name: "CHFGroupID", Release: capability.Rel19},
		{Number: 113, Name: "EnQoSMon_v2", Release: capability.Rel19},
		{Number: 114, Name: "MultiModaIId", Release: capability.Rel19},
		{Number: 115, Name: "OnPathN6MediaInfo", Release: capability.Rel19},
		{Number: 116, Name: "RuleVersioning_Ext", Release: capability.Rel19},
		{Number: 117, Name: "2G3GIWK_2", Release: capability.Rel19},
		{Number: 118, Name: "DDN_failure_SMPolicy_creation", Release: capability.Rel19},
		{Number: 119, Name: "CnHealthMonitor", Release: capability.Rel19},
	}
}

// NpcfAMPolicyControlEntries returns a fresh copy of Table 5.8-1 of TS 29.507
// (Npcf_AMPolicyControl, clause 5.8 "Feature negotiation", features 1-24),
// transcribed from V17.11.0, V18.8.0 and V19.7.0. Features 1-13 are in V17,
// 14-21 first appear in V18 and 22-24 in V19. The table has no M/O column, so
// no entry is Mandatory. The attribute carrying the value is "suppFeat"
// (PolicyAssociationRequest in the request, PolicyAssociation in the
// response).
func NpcfAMPolicyControlEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "SliceSupport", Release: capability.Rel17},
		{Number: 2, Name: "PendingTransaction", Release: capability.Rel17},
		{Number: 3, Name: "UE-AMBR_Authorization", Release: capability.Rel17},
		{Number: 4, Name: "DNNReplacementControl", Release: capability.Rel17},
		{Number: 5, Name: "MultipleAccessTypes", Release: capability.Rel17},
		{Number: 6, Name: "WirelineWirelessConvergence", Release: capability.Rel17},
		{Number: 7, Name: "ImmediateReport", Release: capability.Rel17},
		{Number: 8, Name: "ES3XX", Release: capability.Rel17},
		{Number: 9, Name: "UE-Slice-MBR_Authorization", Release: capability.Rel17},
		{Number: 10, Name: "AMInfluence", Release: capability.Rel17},
		{Number: 11, Name: "EneNA", Release: capability.Rel17},
		{Number: 12, Name: "TargetNSSAI", Release: capability.Rel17},
		{Number: 13, Name: "5GAccessStratumTime", Release: capability.Rel17},
		{Number: 14, Name: "FeatureRenegotiation", Release: capability.Rel18},
		{Number: 15, Name: "NetSliceRepl", Release: capability.Rel18},
		{Number: 16, Name: "RFSPValidityTime", Release: capability.Rel18},
		{Number: 17, Name: "NetTimeSyncStatus", Release: capability.Rel18},
		{Number: 18, Name: "NetSliceUsageCtrl", Release: capability.Rel18},
		{Number: 19, Name: "PartNetSliceSupport", Release: capability.Rel18},
		{Number: 20, Name: "SLAMUP", Release: capability.Rel18},
		{Number: 21, Name: "RatTypeChange", Release: capability.Rel18},
		{Number: 22, Name: "AfNetSliceRepl", Release: capability.Rel19},
		{Number: 23, Name: "Energy", Release: capability.Rel19},
		{Number: 24, Name: "CHFGroup", Release: capability.Rel19},
	}
}

// NpcfUEPolicyControlEntries returns a fresh copy of Table 5.8-1 of TS 29.525
// (Npcf_UEPolicyControl, clause 5.8 "Feature negotiation", features 1-28),
// transcribed from V17.11.0, V18.10.0 and V19.7.0. Features 1-9 are in V17,
// 10-25 first appear in V18 and 26-28 in V19. The table has no M/O column, so
// no entry is Mandatory. The attribute carrying the value is "suppFeat"
// (PolicyAssociationRequest in the request, PolicyAssociation in the
// response).
func NpcfUEPolicyControlEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "PendingTransaction", Release: capability.Rel17},
		{Number: 2, Name: "PlmnChange", Release: capability.Rel17},
		{Number: 3, Name: "ConnectivityStateChange", Release: capability.Rel17},
		{Number: 4, Name: "V2X", Release: capability.Rel17},
		{Number: 5, Name: "GroupIdListChange", Release: capability.Rel17},
		{Number: 6, Name: "ImmediateReport", Release: capability.Rel17},
		{Number: 7, Name: "ErrorResponse", Release: capability.Rel17},
		{Number: 8, Name: "ES3XX", Release: capability.Rel17},
		{Number: 9, Name: "ProSe", Release: capability.Rel17},
		{Number: 10, Name: "FeatureRenegotiation", Release: capability.Rel18},
		{Number: 11, Name: "SliceAwareANDSP", Release: capability.Rel18},
		{Number: 12, Name: "EpsUrsp", Release: capability.Rel18},
		{Number: 13, Name: "EnSatBackhaulCategoryChg", Release: capability.Rel18},
		{Number: 14, Name: "UECapabilityIndication", Release: capability.Rel18},
		{Number: 15, Name: "A2X", Release: capability.Rel18},
		{Number: 16, Name: "NssaiChange", Release: capability.Rel18},
		{Number: 17, Name: "ProSe_Ph2", Release: capability.Rel18},
		{Number: 18, Name: "PresenceInfo", Release: capability.Rel18},
		{Number: 19, Name: "URSPEnforcement", Release: capability.Rel18},
		{Number: 20, Name: "VPLMNSpecificURSP", Release: capability.Rel18},
		{Number: 21, Name: "Ranging_SL", Release: capability.Rel18},
		{Number: 22, Name: "AccessChange", Release: capability.Rel18},
		{Number: 23, Name: "EnErrorHandling", Release: capability.Rel18},
		{Number: 24, Name: "SLAMUP", Release: capability.Rel18},
		{Number: 25, Name: "EnhEstRoaming", Release: capability.Rel18},
		{Number: 26, Name: "ProSe_Ph3", Release: capability.Rel19},
		{Number: 27, Name: "CHFGroup", Release: capability.Rel19},
		{Number: 28, Name: "ExtDeliveryOutcome", Release: capability.Rel19},
	}
}

// NpcfPolicyAuthorizationEntries returns a fresh copy of Table 5.8-1 of
// TS 29.514 (Npcf_PolicyAuthorization, clause 5.8 "Feature negotiation",
// features 1-83), transcribed from V17.16.0, V18.13.0 and V19.8.0. V17 lists
// features 1-41 and 44 (numbers 42 and 43 are not assigned there); 42, 43 and
// 45-63 first appear in V18, 64-83 in V19. The table has no M/O column, so no
// entry is Mandatory. The attribute carrying the value is "suppFeat"
// (AppSessionContextReqData in the request, AppSessionContextRespData in the
// response).
func NpcfPolicyAuthorizationEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "InfluenceOnTrafficRouting", Release: capability.Rel17},
		{Number: 2, Name: "SponsoredConnectivity", Release: capability.Rel17},
		{Number: 3, Name: "MediaComponentVersioning", Release: capability.Rel17},
		{Number: 4, Name: "URLLC", Release: capability.Rel17},
		{Number: 5, Name: "IMS_SBI", Release: capability.Rel17},
		{Number: 6, Name: "NetLoc", Release: capability.Rel17},
		{Number: 7, Name: "ProvAFsignalFlow", Release: capability.Rel17},
		{Number: 8, Name: "ResourceSharing", Release: capability.Rel17},
		{Number: 9, Name: "MCPTT", Release: capability.Rel17},
		{Number: 10, Name: "MCVideo", Release: capability.Rel17},
		{Number: 11, Name: "PrioritySharing", Release: capability.Rel17},
		{Number: 12, Name: "MCPTT-Preemption", Release: capability.Rel17},
		{Number: 13, Name: "MacAddressRange", Release: capability.Rel17},
		{Number: 14, Name: "RAN-NAS-Cause", Release: capability.Rel17},
		{Number: 15, Name: "EnhancedSubscriptionToNotification", Release: capability.Rel17},
		{Number: 16, Name: "QoSMonitoring", Release: capability.Rel17},
		{Number: 17, Name: "AuthorizationWithRequiredQoS", Release: capability.Rel17},
		{Number: 18, Name: "TimeSensitiveNetworking", Release: capability.Rel17},
		{Number: 19, Name: "PCSCF-Restoration-Enhancement", Release: capability.Rel17},
		{Number: 20, Name: "CHEM", Release: capability.Rel17},
		{Number: 21, Name: "FLUS", Release: capability.Rel17},
		{Number: 22, Name: "EPSFallbackReport", Release: capability.Rel17},
		{Number: 23, Name: "ATSSS", Release: capability.Rel17},
		{Number: 24, Name: "QoSHint", Release: capability.Rel17},
		{Number: 25, Name: "ReallocationOfCredit", Release: capability.Rel17},
		{Number: 26, Name: "ES3XX", Release: capability.Rel17},
		{Number: 27, Name: "DisableUENotification", Release: capability.Rel17},
		{Number: 28, Name: "PatchCorrection", Release: capability.Rel17},
		{Number: 29, Name: "MPSforDTS", Release: capability.Rel17},
		{Number: 30, Name: "ApplicationDetectionEvents", Release: capability.Rel17},
		{Number: 31, Name: "TimeSensitiveCommunication", Release: capability.Rel17},
		{Number: 32, Name: "ExposureToEAS", Release: capability.Rel17},
		{Number: 33, Name: "SatelliteBackhaul", Release: capability.Rel17},
		{Number: 34, Name: "RoutingReqOutcome", Release: capability.Rel17},
		{Number: 35, Name: "EASDiscovery", Release: capability.Rel17},
		{Number: 36, Name: "AltSerReqsWithIndQoS", Release: capability.Rel17},
		{Number: 37, Name: "SimultConnectivity", Release: capability.Rel17},
		{Number: 38, Name: "EASIPreplacement", Release: capability.Rel17},
		{Number: 39, Name: "AccNetChargId_String", Release: capability.Rel17},
		{Number: 40, Name: "WLAN_Location", Release: capability.Rel17},
		{Number: 41, Name: "AF_latency", Release: capability.Rel17},
		{Number: 42, Name: "UEUnreachable", Release: capability.Rel18},
		{Number: 43, Name: "AltQoSProfilesSupportReport", Release: capability.Rel18},
		{Number: 44, Name: "PacketDelayFailureReport", Release: capability.Rel17},
		{Number: 45, Name: "EnTSCAC", Release: capability.Rel18},
		{Number: 46, Name: "SignalingPathValidation", Release: capability.Rel18},
		{Number: 47, Name: "ExtQoS", Release: capability.Rel18},
		{Number: 48, Name: "CommonEASDNAI", Release: capability.Rel18},
		{Number: 49, Name: "SFC", Release: capability.Rel18},
		{Number: 50, Name: "MultiMedia", Release: capability.Rel18},
		{Number: 51, Name: "EnSatBackhaulCatChg", Release: capability.Rel18},
		{Number: 52, Name: "MTU_Size", Release: capability.Rel18},
		{Number: 53, Name: "ExtraUEaddrReport", Release: capability.Rel18},
		{Number: 54, Name: "AuthorizationForMpsSignalling", Release: capability.Rel18},
		{Number: 55, Name: "ExposureToTSC", Release: capability.Rel18},
		{Number: 56, Name: "URSPEnforcement", Release: capability.Rel18},
		{Number: 57, Name: "AddFlowDescriptionInformation", Release: capability.Rel18},
		{Number: 58, Name: "QoSTiming_5G", Release: capability.Rel18},
		{Number: 59, Name: "PDUSetHandling", Release: capability.Rel18},
		{Number: 60, Name: "RTLatency", Release: capability.Rel18},
		{Number: 61, Name: "EnQoSMon", Release: capability.Rel18},
		{Number: 62, Name: "PowerSaving", Release: capability.Rel18},
		{Number: 63, Name: "L4S", Release: capability.Rel18},
		{Number: 64, Name: "QoSMonCapRepo", Release: capability.Rel19},
		{Number: 65, Name: "MPSforMessaging", Release: capability.Rel19},
		{Number: 66, Name: "VPLMNErrorRep", Release: capability.Rel19},
		{Number: 67, Name: "TraffRouteReqOutcome", Release: capability.Rel19},
		{Number: 68, Name: "MpxMedia", Release: capability.Rel19},
		{Number: 69, Name: "TrafficCharChange", Release: capability.Rel19},
		{Number: 70, Name: "N6DelayMeasurement", Release: capability.Rel19},
		{Number: 71, Name: "ReleasedUEaddrReport", Release: capability.Rel19},
		{Number: 72, Name: "UeSatUeComm", Release: capability.Rel19},
		{Number: 73, Name: "HeaderHandling", Release: capability.Rel19},
		{Number: 74, Name: "OnPathN6MediaInfo", Release: capability.Rel19},
		{Number: 75, Name: "RateLimitReport", Release: capability.Rel19},
		{Number: 76, Name: "EnCommonDnai", Release: capability.Rel19},
		{Number: 77, Name: "AcceptableQosDetails", Release: capability.Rel19},
		{Number: 78, Name: "ExtQoSR19", Release: capability.Rel19},
		{Number: 79, Name: "SimConnFailure", Release: capability.Rel19},
		{Number: 80, Name: "EnQoSMon_v2", Release: capability.Rel19},
		{Number: 81, Name: "SmfFailureDetection", Release: capability.Rel19},
		{Number: 82, Name: "CnHealthMonitor", Release: capability.Rel19},
		{Number: 83, Name: "SmallBurstSizes", Release: capability.Rel19},
	}
}

// N32HandshakeEntries returns a fresh copy of Table 6.1.7-1 of TS 29.573
// (N32 Handshake service, n32c-handshake, clause 6.1.7 "Features supported by
// the N32 Handshake service", features 1-5), transcribed from V19.7.0. The
// attribute carrying the value is supportedFeatures in SecNegotiateReqData
// (c-SEPP) and SecNegotiateRspData (p-SEPP). Releases: NFTLST is Rel-17
// (CR 0079, V17.4.0); PSEPRO, PSIU and SNDN32F are Rel-18 (CR 0174/0180,
// V18.6.0; CR 0206, V18.8.0); TLSCOR is Rel-18 per its mirror CR 0216 in
// V19.1.0. [VERIFY] TLSCOR release. Feature 3 (PSIU) is M.
func N32HandshakeEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "NFTLST", Release: capability.Rel17},
		{Number: 2, Name: "PSEPRO", Release: capability.Rel18},
		{Number: 3, Name: "PSIU", Release: capability.Rel18, Mandatory: true},
		{Number: 4, Name: "SNDN32F", Release: capability.Rel18},
		{Number: 5, Name: "TLSCOR", Release: capability.Rel18}, // [VERIFY] release
	}
}

// NnrfNFManagementEntries returns a fresh copy of Table 6.1.9-1 of TS 29.510
// (Nnrf_NFManagement, clause 6.1.9 "Features supported by the NFManagement
// service", features 1-10), transcribed from V17.16.0, V18.11.0 and V19.8.0.
// Features 1-4 are in V17, 5-10 first appear in V18; V19 is unchanged. Features
// 1 (Service-Map) and 3 (Inter-Plmn-Fqdn) are M. The attributes carrying the
// value are SubscriptionData.requesterFeatures (consumer, request) and
// SubscriptionData.nrfSupportedFeatures (NRF, response), and the
// "requester-features" query parameter of NFInstance retrieval.
func NnrfNFManagementEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "Service-Map", Release: capability.Rel17, Mandatory: true},
		{Number: 2, Name: "Empty-Objects-Nrf-Info", Release: capability.Rel17},
		{Number: 3, Name: "Inter-Plmn-Fqdn", Release: capability.Rel17, Mandatory: true},
		{Number: 4, Name: "NRFSET", Release: capability.Rel17},
		{Number: 5, Name: "Complete-Profile-Subscription", Release: capability.Rel18},
		{Number: 6, Name: "Allowed-ruleset", Release: capability.Rel18},
		{Number: 7, Name: "Canary-Release", Release: capability.Rel18},
		{Number: 8, Name: "DNN-List-Optimization", Release: capability.Rel18},
		{Number: 9, Name: "Shared-Data-Registration", Release: capability.Rel18},
		{Number: 10, Name: "Shared-Data-Retrieval", Release: capability.Rel18},
	}
}

// NnrfNFDiscoveryEntries returns a fresh copy of Table 6.2.9-1 of TS 29.510
// (Nnrf_NFDiscovery, clause 6.2.9 "Features supported by the NFDiscovery
// service", features 1-62), transcribed from V17.16.0, V18.11.0 and V19.8.0.
// V17 lists features 1-29 and 43; 30-42 and 44-50 first appear in V18, 51-62
// in V19. Feature 6 (Service-Map) is M. The spec spells feature 42 "Query-5G-
// RangingSlPos" (with a space); the stray space is dropped here. The
// attributes carrying the value are the "requester-features" query parameter
// (consumer) and SearchResult.nrfSupportedFeatures (NRF, response). The
// "supported-features" query parameter is a discovery FILTER on the target
// service's features, not a negotiation.
func NnrfNFDiscoveryEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "Complex-Query", Release: capability.Rel17},
		{Number: 2, Name: "Query-Params-Ext1", Release: capability.Rel17},
		{Number: 3, Name: "Query-Param-Analytics", Release: capability.Rel17},
		{Number: 4, Name: "MAPDU", Release: capability.Rel17},
		{Number: 5, Name: "Query-Params-Ext2", Release: capability.Rel17},
		{Number: 6, Name: "Service-Map", Release: capability.Rel17, Mandatory: true},
		{Number: 7, Name: "Query-Params-Ext3", Release: capability.Rel17},
		{Number: 8, Name: "Query-Params-Ext4", Release: capability.Rel17},
		{Number: 9, Name: "Query-Param-vSmf-Capability", Release: capability.Rel17},
		{Number: 10, Name: "Enh-NF-Discovery", Release: capability.Rel17},
		{Number: 11, Name: "Query-SBIProtoc17", Release: capability.Rel17},
		{Number: 12, Name: "SCPDRI", Release: capability.Rel17},
		{Number: 13, Name: "Query-Upf-Pfcp", Release: capability.Rel17},
		{Number: 14, Name: "Query-5G-ProSe", Release: capability.Rel17},
		{Number: 15, Name: "NSAC", Release: capability.Rel17},
		{Number: 16, Name: "Query-MBS", Release: capability.Rel17},
		{Number: 17, Name: "Query-eNA-PH2", Release: capability.Rel17},
		{Number: 18, Name: "Query-eLCS", Release: capability.Rel17},
		{Number: 19, Name: "Query-eEDGE-5GC", Release: capability.Rel17},
		{Number: 20, Name: "Collocated-NF-Selection", Release: capability.Rel17},
		{Number: 21, Name: "Query-ENPN", Release: capability.Rel17},
		{Number: 22, Name: "Query-ID_UAS", Release: capability.Rel17},
		{Number: 23, Name: "NRFSET", Release: capability.Rel17},
		{Number: 24, Name: "Query-Nw-Resolution", Release: capability.Rel17},
		{Number: 25, Name: "Query-Param-iSmf-Capability", Release: capability.Rel17},
		{Number: 26, Name: "Query-SBIProtoc17-Ext1", Release: capability.Rel17},
		{Number: 27, Name: "Query-Upf-IpIndex", Release: capability.Rel17},
		{Number: 28, Name: "Query-eNA-PH2-Ext1", Release: capability.Rel17},
		{Number: 29, Name: "Query-HLC", Release: capability.Rel17},
		{Number: 30, Name: "Query-SBIProtoc18", Release: capability.Rel18},
		{Number: 31, Name: "Complete-Profile-Discovery", Release: capability.Rel18},
		{Number: 32, Name: "Query-UPEAS", Release: capability.Rel18},
		{Number: 33, Name: "Enh-NF-Discovery-Ext1", Release: capability.Rel18},
		{Number: 34, Name: "Query-NG-RTC", Release: capability.Rel18},
		{Number: 35, Name: "Query-eLCS-PH3", Release: capability.Rel18},
		{Number: 36, Name: "Query-eNA-PH3", Release: capability.Rel18},
		{Number: 37, Name: "Query-A2X", Release: capability.Rel18},
		{Number: 38, Name: "Allowed-ruleset", Release: capability.Rel18},
		{Number: 39, Name: "Query-AIMLsys", Release: capability.Rel18},
		{Number: 40, Name: "Canary-Release", Release: capability.Rel18},
		{Number: 41, Name: "Query-UPF-Selection-N3GPP", Release: capability.Rel18},
		{Number: 42, Name: "Query-5G-RangingSlPos", Release: capability.Rel18},
		{Number: 43, Name: "Query-eNS-PH2", Release: capability.Rel17},
		{Number: 44, Name: "RID-NfGroupId-Mapping", Release: capability.Rel18},
		{Number: 45, Name: "Query_UEPO", Release: capability.Rel18},
		{Number: 46, Name: "DNN-List-Optimization", Release: capability.Rel18},
		{Number: 47, Name: "Shared-Data", Release: capability.Rel18},
		{Number: 48, Name: "Query-EDGE-Ph2", Release: capability.Rel18},
		{Number: 49, Name: "Query-TAI-LIST", Release: capability.Rel18},
		{Number: 50, Name: "Query-eNA-Ph3_EXT", Release: capability.Rel18},
		{Number: 51, Name: "NFsel_by_tPLMN", Release: capability.Rel19},
		{Number: 52, Name: "Query-Preferred-Serving-Scope", Release: capability.Rel19},
		{Number: 53, Name: "Query-UPEAS_Ph2", Release: capability.Rel19},
		{Number: 54, Name: "Enh-PCSCF-Disc", Release: capability.Rel19},
		{Number: 55, Name: "UPF-2G3G-SUPPORT", Release: capability.Rel19},
		{Number: 56, Name: "Query-AIML-CN", Release: capability.Rel19},
		{Number: 57, Name: "Query-EDGE-Ph3", Release: capability.Rel19},
		{Number: 58, Name: "Query-PRA-AMF", Release: capability.Rel19},
		{Number: 59, Name: "Query-AIoT", Release: capability.Rel19},
		{Number: 60, Name: "Query-Smf-IpIndex", Release: capability.Rel19},
		{Number: 61, Name: "Query-SBIProtoc19", Release: capability.Rel19},
		{Number: 62, Name: "Query-BSF-NonIP", Release: capability.Rel19},
	}
}

// NnrfAccessTokenEntries returns a fresh copy of Table 6.3.7-1 of TS 29.510
// (Nnrf_AccessToken, clause 6.3.7 "Features supported by the AccessToken
// service"), transcribed from V19.8.0. The clause does not exist in V17.16.0
// or V18.11.0, so the single feature 1 Retrieve-Key (O) is tagged Rel19. The
// Nnrf_AccessToken request and response data types carry no supportedFeatures
// attribute, so the table is never negotiated on the wire.
func NnrfAccessTokenEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "Retrieve-Key", Release: capability.Rel19},
	}
}

// NudrDataRepositoryEntries returns a fresh copy of Table 6.1.8-1 of TS 29.504
// (Nudr_DataRepository, clause 6.1.8 "Feature negotiation", features 1-80
// without the reserved numbers 14 and 59), transcribed from V17.21.0, V18.13.0
// and V19.8.0. This one table governs every Nudr_DataRepository data set:
// TS 29.505 (subscription data) and TS 29.519 clauses 5.6, 6.6 and 7.5
// (policy, application and exposure data) all refer to it. V17 lists features
// 1-13, 15-30, 42 and 54; 31-41, 43-53, 55-58, 60, 61 and 75 first appear in
// V18, 62-74 and 76-80 in V19. The table has no M/O column, so no entry is
// Mandatory. The attribute carrying the value is "supported-features" (query,
// TS 29.505 resources) or "supp-feat" (query, TS 29.519 resources); in
// bodies it is supportedFeatures or suppFeat depending on the data type.
func NudrDataRepositoryEntries() []Entry {
	return []Entry{
		{Number: 1, Name: "ResourceRemovalNotificationPolicyData", Release: capability.Rel17},
		{Number: 2, Name: "ResourceNotificationExposureDataFix", Release: capability.Rel17},
		{Number: 3, Name: "DomainNameProtocol", Release: capability.Rel17},
		{Number: 4, Name: "EnhancedBackgroundDataTransfer", Release: capability.Rel17},
		{Number: 5, Name: "MacAddressRange", Release: capability.Rel17},
		{Number: 6, Name: "MultiTemporalCondition", Release: capability.Rel17},
		{Number: 7, Name: "PatchReport", Release: capability.Rel17},
		{Number: 8, Name: "URLLC", Release: capability.Rel17},
		{Number: 9, Name: "SessionManagementPolicyDataPatch", Release: capability.Rel17},
		{Number: 10, Name: "ConditionalSubscriptionwithPartialNotification", Release: capability.Rel17},
		{Number: 11, Name: "EnhancedInfluDataNotification", Release: capability.Rel17},
		{Number: 12, Name: "PerUePerSnAuthStatus", Release: capability.Rel17},
		{Number: 13, Name: "OpSpecDataMapNotification", Release: capability.Rel17},
		{Number: 15, Name: "OSDResource_Create_Delete", Release: capability.Rel17},
		{Number: 16, Name: "AF_latency", Release: capability.Rel17},
		{Number: 17, Name: "CHFsetSupport", Release: capability.Rel17},
		{Number: 18, Name: "ConditionalSubscriptionWithExcludeNotification", Release: capability.Rel17},
		{Number: 19, Name: "ProSe", Release: capability.Rel17},
		{Number: 20, Name: "NSAC", Release: capability.Rel17},
		{Number: 21, Name: "UESubDataSetRetrieve", Release: capability.Rel17},
		{Number: 22, Name: "SharedSmSubsData", Release: capability.Rel17},
		{Number: 23, Name: "DeliveryOutcome", Release: capability.Rel17},
		{Number: 24, Name: "AfGuideURSP", Release: capability.Rel17},
		{Number: 25, Name: "EasDeployment", Release: capability.Rel17},
		{Number: 26, Name: "DCAMP", Release: capability.Rel17},
		{Number: 27, Name: "FilterAnyUE", Release: capability.Rel17},
		{Number: 28, Name: "SimultConnectivity", Release: capability.Rel17},
		{Number: 29, Name: "EeSubscriptionExt", Release: capability.Rel17},
		{Number: 30, Name: "PeiResource", Release: capability.Rel17},
		{Number: 31, Name: "ImmediateReportPcc", Release: capability.Rel18},
		{Number: 32, Name: "ImmediateReport", Release: capability.Rel18},
		{Number: 33, Name: "UESubDataSetRetrieveExt", Release: capability.Rel18},
		{Number: 34, Name: "SFC", Release: capability.Rel18},
		{Number: 35, Name: "SubscribedV2XPolicy", Release: capability.Rel18},
		{Number: 36, Name: "CommonEASDNAI", Release: capability.Rel18},
		{Number: 37, Name: "PolSubscRetrieval", Release: capability.Rel18},
		{Number: 38, Name: "A2X", Release: capability.Rel18},
		{Number: 39, Name: "EpsUrsp", Release: capability.Rel18},
		{Number: 40, Name: "DCAMP_Roaming_LBO", Release: capability.Rel18},
		{Number: 41, Name: "GMEC", Release: capability.Rel18},
		{Number: 42, Name: "PatchCorrection", Release: capability.Rel17},
		{Number: 43, Name: "EnhancedUePolicy", Release: capability.Rel18},
		{Number: 44, Name: "ProSe_Ph2", Release: capability.Rel18},
		{Number: 45, Name: "OpSpecAmPolicyData", Release: capability.Rel18},
		{Number: 46, Name: "CHFInformation", Release: capability.Rel18},
		{Number: 47, Name: "SLAMUP", Release: capability.Rel18},
		{Number: 48, Name: "AfGuideTNAPs", Release: capability.Rel18},
		{Number: 49, Name: "URSPEnforcement", Release: capability.Rel18},
		{Number: 50, Name: "VPLMNSpecificURSP", Release: capability.Rel18},
		{Number: 51, Name: "DnaiEasMappings", Release: capability.Rel18},
		{Number: 52, Name: "HR-SBO", Release: capability.Rel18},
		{Number: 53, Name: "FinerGranUEs", Release: capability.Rel18},
		{Number: 54, Name: "CachingTimer", Release: capability.Rel17},
		{Number: 55, Name: "AccessAndMobilityPolicyDataModify", Release: capability.Rel18},
		{Number: 56, Name: "Ranging_SL", Release: capability.Rel18},
		{Number: 57, Name: "PDTQ", Release: capability.Rel18},
		{Number: 58, Name: "PfdDetermination", Release: capability.Rel18},
		{Number: 60, Name: "TrafficInfluSubExt", Release: capability.Rel18},
		{Number: 61, Name: "MultiPduSessInfo", Release: capability.Rel18},
		{Number: 62, Name: "DCAMP_HPLMNFilter", Release: capability.Rel19},
		{Number: 63, Name: "VPSUrsp_HPLMNFilter", Release: capability.Rel19},
		{Number: 64, Name: "MultiTrafficInflu_Ext1", Release: capability.Rel19},
		{Number: 65, Name: "ProSe_Ph3", Release: capability.Rel19},
		{Number: 66, Name: "N6DelayMeasurement", Release: capability.Rel19},
		{Number: 67, Name: "HeaderHandling", Release: capability.Rel19},
		{Number: 68, Name: "TraffRoutReqOutcome", Release: capability.Rel19},
		{Number: 69, Name: "Non3gppDevice", Release: capability.Rel19},
		{Number: 70, Name: "SUBDMIG", Release: capability.Rel19},
		{Number: 71, Name: "AfNetSliceRepl", Release: capability.Rel19},
		{Number: 72, Name: "EnCommonDnai", Release: capability.Rel19},
		{Number: 73, Name: "Energy", Release: capability.Rel19},
		{Number: 74, Name: "SimConnFailure", Release: capability.Rel19},
		{Number: 75, Name: "NscSupportedFeatures", Release: capability.Rel18},
		{Number: 76, Name: "PCFSerParAuth", Release: capability.Rel19},
		{Number: 77, Name: "ExtDeliveryOutcome", Release: capability.Rel19},
		{Number: 78, Name: "NotifCorreIdsSupport", Release: capability.Rel19},
		{Number: 79, Name: "CHFGroup", Release: capability.Rel19},
		{Number: 80, Name: "BdtNotifUriPatch", Release: capability.Rel19},
	}
}

// Implement returns a copy of entries with Implemented=true for the listed
// feature numbers. It errors on a number that is not in entries, so an NF's
// declared subset cannot drift from the API table.
func Implement(entries []Entry, numbers ...int) ([]Entry, error) {
	out := append([]Entry(nil), entries...)
	idx := make(map[int]int, len(out))
	for i, e := range out {
		idx[e.Number] = i
	}
	for _, n := range numbers {
		i, ok := idx[n]
		if !ok {
			return nil, fmt.Errorf("features: implement: unknown feature number %d", n)
		}
		out[i].Implemented = true
	}
	return out, nil
}

// MustImplement is Implement that panics on error; for package initialisers.
func MustImplement(entries []Entry, numbers ...int) []Entry {
	out, err := Implement(entries, numbers...)
	if err != nil {
		panic(err)
	}
	return out
}
