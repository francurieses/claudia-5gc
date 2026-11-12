// Package sbi holds the NSSF's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2;
// TS 29.531 §6.1.8.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API table is transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the NSSF implements.
//
// Nnssf_NSSelection (producer), TS 29.531 §6.1.8 Table 6.1.8-1 (V17.12.0,
// V18.10.0, V19.7.0; identical in all three). None of the four bits is
// implemented, so the NSSF offers "0" under both profiles:
//
//	1 ES3XX       (M) an NF Service Consumer obligation (handling of HTTP
//	              307/308); the NSSF never answers 307/308 (SBI-FEAT-001).
//	2 TargetNssai Target NSSAI handling (TS 23.501 §5.3.4.3.3, §5.15.5.2.1)
//	              is not implemented.
//	3 RSIPCE      slice information retrieval during PDN connection
//	              establishment (SMF+PGW-C) is not implemented.
//	4 SIOP        slice information retrieval for other purposes (NWDAF) is
//	              not implemented.
//
// Per §6.1.8 the consumer indicates its features in the supportedFeatures
// attribute of the GET request (the "supported-features" query parameter of
// the YAML) and the NSSF answers with supportedFeatures in the
// AuthorizedNetworkSliceInfo.

// nnssfCatalog is the Nnssf_NSSelection producer catalog.
var nnssfCatalog = features.MustCatalog(features.MustImplement(features.NnssfNSSelectionEntries())...)

// NnssfNSSelectionCatalog returns the immutable Nnssf_NSSelection catalog
// (producer role) of the NSSF. TS 29.531 §6.1.8.
func NnssfNSSelectionCatalog() *features.Catalog { return nnssfCatalog }

// BuildNFProfile returns the NFProfile the NSSF registers at the NRF
// (nnssf-nsselection service). The per-service supportedFeatures is
// advertised only under the rel19 profile (features.Request returns ""
// otherwise and the omitempty tag drops it), so the rel17 registration stays
// byte-identical. Ref: TS 29.510 §6.1.6.2.2 (NFProfile), §6.1.6.2.3
// (NFService); decision D2.
func BuildNFProfile(nfInstanceID string, snssais []nrf.SNSSAIEntry, p *capability.Profile, cat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "NSSF",
		NFStatus:     "REGISTERED",
		SNSSAIs:      snssais,
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-nnssf-nsselection",
			ServiceName:       "nnssf-nsselection",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NnssfNSSelection)},
			SupportedFeatures: features.Request(cat, p),
		}},
	}
}
