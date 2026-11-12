// Package sbi holds the SMSF's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2;
// TS 29.540 §6.1.8.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API table is transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the SMSF implements.
//
// Nsmsf_SMService (producer), TS 29.540 §6.1.8 Table 6.1.8-1 (V17.6.0,
// V18.5.0, V19.6.0; identical in all three). Neither bit is implemented, so the
// SMSF offers "0" under both profiles:
//
//	1 ES3XX        (M) an NF Service Consumer obligation: "An NF Service
//	               Consumer (e.g. AMF) that supports this feature shall support
//	               handling of HTTP 307/308 redirection"; the SMSF never answers
//	               307/308 (SBI-FEAT-001 for the consumers).
//	2 PatchReport  (O) the SMSF reports partially failed PATCH modifications
//	               (TS 29.500 §5.2.7.2); the SMSF serves no PATCH on the UE SMS
//	               context.
//
// The UeSmsContextData carries the value in "supportedFeatures" in both the
// request and the response of Activate.

// nsmsfCatalog is the Nsmsf_SMService producer catalog.
var nsmsfCatalog = features.MustCatalog(features.MustImplement(features.NsmsfSMServiceEntries())...)

// NsmsfSMServiceCatalog returns the immutable Nsmsf_SMService catalog
// (producer role) of the SMSF. TS 29.540 §6.1.8.
func NsmsfSMServiceCatalog() *features.Catalog { return nsmsfCatalog }

// BuildNFProfile returns the NFProfile the SMSF registers at the NRF
// (nsmsf-sms service). The per-service supportedFeatures is advertised only
// under the rel19 profile (features.Request returns "" otherwise and the
// omitempty tag drops it), so the rel17 registration stays byte-identical.
// Ref: TS 29.510 §6.1.6.2.2 (NFProfile), §6.1.6.2.3 (NFService); decision D2.
func BuildNFProfile(nfInstanceID string, p *capability.Profile, cat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "SMSF",
		NFStatus:     "REGISTERED",
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-nsmsf-sms",
			ServiceName:       "nsmsf-sms",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions: []nrf.NFServiceVersion{
				nrf.ServiceVersion(p, apiversion.NsmsfSMS),
			},
			SupportedFeatures: features.Request(cat, p),
		}},
	}
}
