// Package sbi holds the PCF's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2;
// TS 29.512 §5.8, TS 29.507 §5.8, TS 29.525 §5.8, TS 29.514 §5.8.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API tables are transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the PCF implements. None of
// the four producer APIs has an optional feature the PCF demonstrably
// implements, so it offers "0" under both profiles. The attribute carrying
// the value is "suppFeat" in all four APIs.
//
// Npcf_SMPolicyControl (TS 29.512 §5.8 Table 5.8-1, 119 bits). The PCF serves
// create / update / delete of the SM policy and answers with one hard-wired
// session rule, one PCC rule and one QoS decision. Every bit extends that:
//
//	5 UMC, 4 ADC        no usage monitoring or application detection control
//	                    (no UsageMonData / ADC redirection in the decision).
//	6 NetLoc, 10 PRA    no ANI or presence reporting area handling.
//	29 SamePcf          the PCF registers a PcfBinding at the BSF, but it does
//	                    not honour the SamePcf parameter combination.
//	43 ES3XX            consumer-side redirection handling; the PCF never
//	                    answers 307/308 (decision 2026-10-21).
//	24 QosMonitoring,
//	25 AuthorizationWithRequiredQoS
//	                    the decision carries no QoS monitoring or alternative
//	                    QoS data.
//	all others          no code path: the PCF never sends UpdateNotify, never
//	                    reads the corresponding request attributes (the create
//	                    body is kept as an untyped map) and never emits the
//	                    corresponding decision attributes.
//
// Npcf_AMPolicyControl (TS 29.507 §5.8 Table 5.8-1, 24 bits). The PCF returns
// only rfsp (the polAssoId is the Location header, not a body attribute):
//
//	1 SliceSupport      the allowed NSSAI of the request is not read.
//	8 ES3XX             consumer-side, never answered with 307/308.
//	14 FeatureRenegotiation
//	                    there is no policy association update operation.
//	others              no code path (no UE-AMBR, SLICE-MBR, DNN replacement,
//	                    target NSSAI, AS time distribution, ...).
//
// Npcf_UEPolicyControl (TS 29.525 §5.8 Table 5.8-1, 28 bits). The PCF returns
// one URSP container in uePolicy (the polAssoId is the Location header):
//
//	4 V2X, 9 ProSe, 15 A2X, 17 ProSe_Ph2, 21 Ranging_SL, 26 ProSe_Ph3
//	                    only URSP rules are delivered, no V2X / ProSe / A2X /
//	                    ranging policy sections.
//	7 ErrorResponse, 10 FeatureRenegotiation
//	                    no policy update notification and no association
//	                    update operation.
//	8 ES3XX             consumer-side, never answered with 307/308.
//	11 SliceAwareANDSP  only URSP is delivered (no ANDSP / WLANSP).
//	others              no code path.
//
// Npcf_PolicyAuthorization (TS 29.514 §5.8 Table 5.8-1, 83 bits). The PCF
// stores the AppSessionContext of create and removes it on delete; it does
// does not turn media components into PCC rules; the one bit implemented is
// 17 AuthorizationWithRequiredQoS (MediaComponent.qosReference is accepted,
// recorded and echoed; no PCC rule is derived from it):
//
//	1 InfluenceOnTrafficRouting, 2 SponsoredConnectivity, 16 QoSMonitoring
//	                    the ascReqData is recorded and echoed, never turned
//	                    into PCC rules (docs/procedures/network-exposure.md).
//	26 ES3XX            consumer-side, never answered with 307/308.
//	others              no code path (no update / events subscription / notify).
//
// The AMF-facing Npcf_AMPolicyControl and Npcf_PolicyAuthorization services are
// not registered in the NRF at HEAD (consumers use configured peers), so only
// the two registered services carry a per-service supportedFeatures.

// npcfFeatureAuthorizationWithRequiredQoS is Npcf_PolicyAuthorization feature
// 17: the PCF accepts MediaComponent.qosReference in ascReqData.medComponents
// and records/echoes it. Ref: TS 29.514 §5.8 Table 5.8-1, clause 4.2.2.32.
const npcfFeatureAuthorizationWithRequiredQoS = 17

var (
	npcfSMPolicyControlCatalog = features.MustCatalog(features.MustImplement(features.NpcfSMPolicyControlEntries())...)
	npcfAMPolicyControlCatalog = features.MustCatalog(features.MustImplement(features.NpcfAMPolicyControlEntries())...)
	npcfUEPolicyControlCatalog = features.MustCatalog(features.MustImplement(features.NpcfUEPolicyControlEntries())...)
	npcfPolicyAuthCatalog      = features.MustCatalog(features.MustImplement(features.NpcfPolicyAuthorizationEntries(), npcfFeatureAuthorizationWithRequiredQoS)...)
)

// Nudr_DataRepository, consumer role (TS 29.504 §6.1.8 Table 6.1.8-1; the
// policy-data resources of TS 29.519 refer to it). The PCF reads and writes
// UE policy sets and SM policy data at the UDR but processes no optional
// Nudr feature (no notification, no sponsor / BDT / IPTV data handling), so no
// bit is implemented: a rel19 PCF offers "0" in the supp-feat query parameter
// of the policy-data GETs, a rel17 PCF offers nothing (decision D2).
var nudrDataRepositoryCatalog = features.MustCatalog(features.NudrDataRepositoryEntries()...)

// NudrDataRepositoryCatalog returns the immutable Nudr_DataRepository catalog
// (consumer role). TS 29.504 §6.1.8.
func NudrDataRepositoryCatalog() *features.Catalog { return nudrDataRepositoryCatalog }

// NpcfSMPolicyControlCatalog returns the immutable Npcf_SMPolicyControl
// catalog (producer role). TS 29.512 §5.8.
func NpcfSMPolicyControlCatalog() *features.Catalog { return npcfSMPolicyControlCatalog }

// NpcfAMPolicyControlCatalog returns the immutable Npcf_AMPolicyControl
// catalog (producer role). TS 29.507 §5.8.
func NpcfAMPolicyControlCatalog() *features.Catalog { return npcfAMPolicyControlCatalog }

// NpcfUEPolicyControlCatalog returns the immutable Npcf_UEPolicyControl
// catalog (producer role). TS 29.525 §5.8.
func NpcfUEPolicyControlCatalog() *features.Catalog { return npcfUEPolicyControlCatalog }

// NpcfPolicyAuthorizationCatalog returns the immutable
// Npcf_PolicyAuthorization catalog (producer role). TS 29.514 §5.8.
func NpcfPolicyAuthorizationCatalog() *features.Catalog { return npcfPolicyAuthCatalog }

// BuildNFProfile returns the NFProfile the PCF registers at the NRF
// (npcf-smpolicycontrol, npcf-ue-policy-control, npcf-am-policy-control and
// npcf-policyauthorization services). The per-service
// supportedFeatures is advertised only under the rel19 profile
// (features.Request returns "" otherwise and the omitempty tag drops it), so
// the rel17 registration stays byte-identical. Ref: TS 29.510 §6.1.6.2.2
// (NFProfile), §6.1.6.2.3 (NFService); decision D2.
func BuildNFProfile(nfInstanceID string, p *capability.Profile, smCat, ueCat, amCat, authCat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "PCF",
		NFStatus:     "REGISTERED",
		NFServices: []nrf.NFService{
			{
				ServiceInstanceID: nfInstanceID + "-npcf-smpolicycontrol",
				ServiceName:       "npcf-smpolicycontrol",
				Scheme:            "https",
				NFServiceStatus:   "REGISTERED",
				Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NpcfSMPolicyControl)},
				SupportedFeatures: features.Request(smCat, p),
			},
			{
				ServiceInstanceID: nfInstanceID + "-npcf-ue-policy-control",
				ServiceName:       "npcf-ue-policy-control",
				Scheme:            "https",
				NFServiceStatus:   "REGISTERED",
				Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NpcfUEPolicyControl)},
				SupportedFeatures: features.Request(ueCat, p),
			},
			{
				ServiceInstanceID: nfInstanceID + "-npcf-am-policy-control",
				ServiceName:       "npcf-am-policy-control",
				Scheme:            "https",
				NFServiceStatus:   "REGISTERED",
				Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NpcfAMPolicyControl)},
				SupportedFeatures: features.Request(amCat, p),
			},
			{
				ServiceInstanceID: nfInstanceID + "-npcf-policyauthorization",
				ServiceName:       "npcf-policyauthorization",
				Scheme:            "https",
				NFServiceStatus:   "REGISTERED",
				Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NpcfPolicyAuth)},
				SupportedFeatures: features.Request(authCat, p),
			},
		},
	}
}
