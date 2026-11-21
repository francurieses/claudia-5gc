// Package sbi holds the NRF's SBI feature-negotiation tables (REL19-2.7).
// Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2; TS 29.510 §6.1.9,
// §6.2.9, §6.3.7.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API tables are transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the NRF implements.
//
// Nnrf_NFManagement (producer), TS 29.510 §6.1.9 Table 6.1.9-1 (V17.16.0,
// V18.11.0, V19.8.0):
//
//	1 Service-Map (M)   implemented: NFRegister / NFUpdate accept the
//	                    "nfServiceList" map of NFProfile, the registry keeps
//	                    it verbatim, the service-names discovery filter reads
//	                    it (registry.allServices). Under rel19 retrieval,
//	                    discovery and notification convert between the
//	                    "nfServiceList" map and the deprecated "nfServices"
//	                    array per the requester's / subscriber's negotiation.
//	3 Inter-Plmn-Fqdn (M) implemented under the rel19 profile only (see
//	                    NnrfNFManagementCatalogFor): NFStatusNotify strips
//	                    "interPlmnFqdn" from the profile and every NFService of
//	                    intra-PLMN notifications to a subscriber that did not
//	                    indicate the feature. Under rel17 the stored profile is
//	                    still sent verbatim (frozen wire behaviour).
//	2, 4-10             not implemented (NRF-to-NRF registration, NRF sets,
//	                    complete-profile subscription, rule sets, canary
//	                    release, DNN list optimisation, shared data).
//
// Nnrf_NFDiscovery (producer), TS 29.510 §6.2.9 Table 6.2.9-1 (V17.16.0,
// V18.11.0, V19.8.0):
//
//	6 Service-Map (M)   implemented, same behaviour as NFManagement bit 1:
//	                    profiles with an "nfServiceList" are matched by
//	                    service name; under rel19 the response carries the
//	                    map only to a requester that negotiated the feature
//	                    and the array otherwise (TS 29.510 §6.2.6.2.3 NOTE 10).
//	others              not implemented: the query parameters of the
//	                    Query-* groups (limit, max-payload-size,
//	                    required-features, ...) are ignored, there is no
//	                    complex query, SCP domain routing information or
//	                    enhanced discovery.
//
// Nnrf_AccessToken, TS 29.510 §6.3.7 Table 6.3.7-1 (V19.8.0 only): 1
// Retrieve-Key is not implemented and the request / response data types carry
// no supportedFeatures attribute.
var (
	nnrfNFManagementCatalog = features.MustCatalog(features.MustImplement(features.NnrfNFManagementEntries(), 1, 3)...)
	// nnrfNFManagementLegacyCatalog is the frozen rel17 set (bit 1 only):
	// Inter-Plmn-Fqdn handling is a rel19-only wire change.
	nnrfNFManagementLegacyCatalog = features.MustCatalog(features.MustImplement(features.NnrfNFManagementEntries(), 1)...)
	nnrfNFDiscoveryCatalog        = features.MustCatalog(features.MustImplement(features.NnrfNFDiscoveryEntries(), 6)...)
	nnrfAccessTokenCatalog        = features.MustCatalog(features.NnrfAccessTokenEntries()...)
)

// NnrfNFManagementCatalog returns the immutable Nnrf_NFManagement catalog
// (producer role) of the NRF. TS 29.510 §6.1.9.
func NnrfNFManagementCatalog() *features.Catalog { return nnrfNFManagementCatalog }

// NnrfNFManagementCatalogFor returns the Nnrf_NFManagement catalog in force for
// a release profile: Service-Map and Inter-Plmn-Fqdn (answer "5") under the
// spec-literal rel19 profile, Service-Map only ("1") otherwise, so rel17 and
// nil-profile bytes stay frozen. TS 29.510 §6.1.9.
func NnrfNFManagementCatalogFor(p *capability.Profile) *features.Catalog {
	if features.SpecLiteral(p) {
		return nnrfNFManagementCatalog
	}
	return nnrfNFManagementLegacyCatalog
}

// NnrfNFDiscoveryCatalog returns the immutable Nnrf_NFDiscovery catalog
// (producer role) of the NRF. TS 29.510 §6.2.9.
func NnrfNFDiscoveryCatalog() *features.Catalog { return nnrfNFDiscoveryCatalog }

// NnrfAccessTokenCatalog returns the immutable Nnrf_AccessToken catalog of the
// NRF; nothing in it is implemented. TS 29.510 §6.3.7.
func NnrfAccessTokenCatalog() *features.Catalog { return nnrfAccessTokenCatalog }
