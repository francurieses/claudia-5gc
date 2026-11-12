// Package sbi holds the UDR's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2;
// TS 29.504 §6.1.8, TS 29.519 §5.6 / §6.6 / §7.5.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API table is transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the UDR implements.
//
// Nudr_DataRepository (producer), TS 29.504 §6.1.8 Table 6.1.8-1 (V17.21.0,
// V18.13.0, V19.8.0; 78 numbered features). One table governs every data set:
// TS 29.505 (subscription data) and TS 29.519 clauses 5.6 (policy data), 6.6
// (application data) and 7.5 (exposure data) all point at it. No bit is
// offered, so the UDR answers "0" under rel19 and the empty intersection
// under rel17 when the consumer sends a value. The UDR serves a small subset
// of the subscription and policy data sets (authentication, AM, SM and UECM
// registration for subscription data; UE policy set and SM policy data for
// policy data) with pragmatic JSON that differs from the OpenAPI schemas, so
// a feature bit is not claimed unless its behaviour is demonstrably
// implemented. The closest candidates, left unclaimed on purpose:
//
//	9 SessionManagementPolicyDataPatch  the policy sm-data PATCH exists but
//	                    merges SmPolicyData per S-NSSAI key instead of
//	                    applying a SmPolicyDataPatch merge patch (no null
//	                    deletions, no umData).
//	7 PatchReport       PATCH of authentication-subscription answers 204
//	                    only and decodes a bare {"sequenceNumber":{...}}
//	                    instead of a JSON Patch array, so it never reports.
//	42 PatchCorrection, 39 EpsUrsp, 43 EnhancedUePolicy, ...
//	                    the UE policy set is {id, supi, precedence, rules},
//	                    not a UePolicySet (no uePolicySections).
//	all others          no data set, notification or subscription resource.
var nudrCatalog = features.MustCatalog(features.MustImplement(features.NudrDataRepositoryEntries())...)

// NudrDataRepositoryCatalog returns the immutable Nudr_DataRepository catalog
// (producer role) of the UDR. TS 29.504 §6.1.8.
func NudrDataRepositoryCatalog() *features.Catalog { return nudrCatalog }

// BuildNFProfile returns the NFProfile the UDR registers at the NRF (nudr-dr
// service). The per-service supportedFeatures is advertised only under the
// rel19 profile (features.Request returns "" otherwise and the omitempty tag
// drops it), so the rel17 registration stays byte-identical. Ref: TS 29.510
// §6.1.6.2.2 (NFProfile), §6.1.6.2.3 (NFService); decision D2.
func BuildNFProfile(nfInstanceID string, p *capability.Profile, cat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "UDR",
		NFStatus:     "REGISTERED",
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-nudr-dr",
			ServiceName:       "nudr-dr",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NudrDR)},
			SupportedFeatures: features.Request(cat, p),
		}},
	}
}
