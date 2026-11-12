// Package sbi holds the NRF's SBI feature-negotiation tables (REL19-2.7).
// Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2; TS 29.510 §6.1.9,
// §6.2.9, §6.3.7.
package sbi

import "github.com/francurieses/claudia-5gc/shared/sbi/features"

// The API tables are transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the NRF implements.
//
// Nnrf_NFManagement (producer), TS 29.510 §6.1.9 Table 6.1.9-1 (V17.16.0,
// V18.11.0, V19.8.0):
//
//	1 Service-Map (M)   implemented: NFRegister / NFUpdate accept the
//	                    "nfServiceList" map of NFProfile, the registry keeps
//	                    it verbatim, the service-names discovery filter reads
//	                    it (registry.allServices) and retrieval returns it.
//	3 Inter-Plmn-Fqdn (M) NOT implemented: NFStatusNotify sends the stored
//	                    profile, "interPlmnFqdn" included, to every matching
//	                    subscriber, which the feature forbids for subscribers
//	                    that did not indicate it. No NF of this stack
//	                    registers the attribute.
//	2, 4-10             not implemented (NRF-to-NRF registration, NRF sets,
//	                    complete-profile subscription, rule sets, canary
//	                    release, DNN list optimisation, shared data).
//
// Nnrf_NFDiscovery (producer), TS 29.510 §6.2.9 Table 6.2.9-1 (V17.16.0,
// V18.11.0, V19.8.0):
//
//	6 Service-Map (M)   implemented, same behaviour as NFManagement bit 1:
//	                    profiles with an "nfServiceList" are matched by
//	                    service name and returned as registered. The NRF does
//	                    not rewrite the map to the deprecated "nfServices"
//	                    array for a requester that did not indicate the
//	                    feature (pre-existing gap).
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
	nnrfNFManagementCatalog = features.MustCatalog(features.MustImplement(features.NnrfNFManagementEntries(), 1)...)
	nnrfNFDiscoveryCatalog  = features.MustCatalog(features.MustImplement(features.NnrfNFDiscoveryEntries(), 6)...)
	nnrfAccessTokenCatalog  = features.MustCatalog(features.NnrfAccessTokenEntries()...)
)

// NnrfNFManagementCatalog returns the immutable Nnrf_NFManagement catalog
// (producer role) of the NRF. TS 29.510 §6.1.9.
func NnrfNFManagementCatalog() *features.Catalog { return nnrfNFManagementCatalog }

// NnrfNFDiscoveryCatalog returns the immutable Nnrf_NFDiscovery catalog
// (producer role) of the NRF. TS 29.510 §6.2.9.
func NnrfNFDiscoveryCatalog() *features.Catalog { return nnrfNFDiscoveryCatalog }

// NnrfAccessTokenCatalog returns the immutable Nnrf_AccessToken catalog of the
// NRF; nothing in it is implemented. TS 29.510 §6.3.7.
func NnrfAccessTokenCatalog() *features.Catalog { return nnrfAccessTokenCatalog }
