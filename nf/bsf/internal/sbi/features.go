// Package sbi holds the BSF's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2;
// TS 29.521 §5.8.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API table is transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the BSF implements.
//
// Nbsf_Management (producer), TS 29.521 §5.8 Table 5.8-1 (V17.11.0, V18.7.0,
// V19.7.0). None of the eight bits is implemented, so the BSF offers "0"
// under both profiles:
//
//	1 MultiUeAddr      the PcfBinding here carries one ipv6Prefix / macAddr48,
//	                   not the ipv6Prefixes / macAddrs arrays.
//	2 BindingUpdate    there is no binding update (no PUT/PATCH route).
//	3 SamePcf          no pcf-ue-bindings / pcfForPduSessionBinding resources.
//	4 ES3XX            consumer-side redirection handling; the BSF never
//	                   answers 307/308 (SBI-FEAT-001 for the consumers).
//	5 ExtendedSamePcf  requires SamePcf, which is absent.
//	6 AddSnssaiDnnPair no BsfSubscription resource (events) is served.
//	7 Recovery         (Rel-19) no recovery time handling for UE bindings.
//	8 ExpTime          (Rel-19) no BSF subscriptions, so no expiry times.
//
// The attribute carrying the value is "suppFeat" (PcfBinding), and the
// discovery GET carries it in the optional "supp-feat" query parameter.

// nbsfCatalog is the Nbsf_Management producer catalog.
var nbsfCatalog = features.MustCatalog(features.MustImplement(features.NbsfManagementEntries())...)

// NbsfManagementCatalog returns the immutable Nbsf_Management catalog
// (producer role) of the BSF. TS 29.521 §5.8.
func NbsfManagementCatalog() *features.Catalog { return nbsfCatalog }

// BuildNFProfile returns the NFProfile the BSF registers at the NRF
// (nbsf-management service). The per-service supportedFeatures is advertised
// only under the rel19 profile (features.Request returns "" otherwise and the
// omitempty tag drops it), so the rel17 registration stays byte-identical.
// Ref: TS 29.510 §6.1.6.2.2 (NFProfile), §6.1.6.2.3 (NFService); decision D2.
func BuildNFProfile(nfInstanceID string, p *capability.Profile, cat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "BSF",
		NFStatus:     "REGISTERED",
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-nbsf-management",
			ServiceName:       "nbsf-management",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions: []nrf.NFServiceVersion{
				nrf.ServiceVersion(p, apiversion.NbsfManagement),
			},
			SupportedFeatures: features.Request(cat, p),
		}},
	}
}
