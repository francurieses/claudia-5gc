// Package sbi holds the LMF's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2;
// TS 29.572 §6.1.9.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API table is transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the LMF implements.
//
// Nlmf_Location (producer), TS 29.572 §6.1.9 Table 6.1.9-1 (V17.13.0, V18.11.0,
// V19.7.0). None of the nine bits is implemented, so the LMF offers "0" under
// both profiles:
//
//	1 ES3XX       (M) an NF Service Consumer obligation (handling of HTTP
//	              307/308); the LMF never answers 307/308 (SBI-FEAT-001).
//	2 SAT         the LMF cannot derive the country / area for PLMN selection
//	              verification (satellite access).
//	3 MUTIQOS     only a single LocationQoS is honoured.
//	4 MBSR        (Rel-18) no mobile base station relay positioning.
//	5 Ranging_SL  (Rel-18) no ranging / sidelink positioning.
//	6 INTRES      no integrity result is computed for location estimates.
//	7 CIMLR       (Rel-18) cancellation of immediate location (5G-MT-LR /
//	              5G-MO-LR) is not implemented; the cancel-location route cancels
//	              an in-flight DetermineLocation only and is not that procedure.
//	8 MCTX        (Rel-19) no LCS context transfer (location-context-transfer
//	              is not served).
//	9 MWAB        (Rel-19) no mobile gNB with wireless access backhauling.
//
// The DetermineLocation request (InputData) and response (LocationData) carry
// "supportedFeatures". The EventSubscription resource served on
// /nlmf-loc/v1/subscriptions is not a resource of TS29572_Nlmf_Location.yaml
// (neither Rel-17 nor Rel-19), so no attribute is added to it.

// nlmfCatalog is the Nlmf_Location producer catalog.
var nlmfCatalog = features.MustCatalog(features.MustImplement(features.NlmfLocationEntries())...)

// NlmfLocationCatalog returns the immutable Nlmf_Location catalog (producer
// role) of the LMF. TS 29.572 §6.1.9.
func NlmfLocationCatalog() *features.Catalog { return nlmfCatalog }

// BuildNFProfile returns the NFProfile the LMF registers at the NRF (nlmf-loc
// service). The per-service supportedFeatures is advertised only under the
// rel19 profile (features.Request returns "" otherwise and the omitempty tag
// drops it), so the rel17 registration stays byte-identical.
// Ref: TS 29.510 §6.1.6.2.2 (NFProfile), §6.1.6.2.3 (NFService); decision D2.
func BuildNFProfile(nfInstanceID, fqdn string, p *capability.Profile, cat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "LMF",
		NFStatus:     "REGISTERED",
		FQDN:         fqdn,
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-nlmf-loc",
			ServiceName:       "nlmf-loc",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions: []nrf.NFServiceVersion{
				nrf.ServiceVersion(p, apiversion.NlmfLoc),
			},
			SupportedFeatures: features.Request(cat, p),
		}},
	}
}
