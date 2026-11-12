// Package sbi holds the AUSF's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API tables are transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the AUSF implements.
//
// Nausf_UEAuthentication (producer), TS 29.509 §6.1.9 Table 6.1.9-1: the only
// feature is 1 ES3XX (M), "Extended Support of HTTP 307/308 redirection". The
// table puts the obligation on the NF Service Consumer ("An NF Service
// Consumer (e.g. AMF) that supports this feature shall support handling of
// HTTP 307/308 redirection"); the AUSF never answers 307/308, so the bit stays
// unmarked and the AUSF offers "0" (decision for ES3XX, dev/REL19_PROGRAM.md
// §2, SBI-FEAT-001). Note: UEAuthenticationCtx (the 201 body) has no
// supportedFeatures attribute in the Rel-17 and Rel-19 YAMLs; only the request
// (AuthenticationInfo, ConfirmationData, EapSession) carries it. The AUSF
// therefore negotiates and logs but has no field to return the answer in.
//
// Nudm_UEAU (consumer), TS 29.503 §6.3.8 Table 6.3.8-1: empty in V17/V18; V19
// adds 1 SUBDMIG (Data Restoration Notification attributes), which the AUSF
// does not implement. Nothing is marked.

// nausfCatalog is the Nausf_UEAuthentication producer catalog.
var nausfCatalog = features.MustCatalog(features.MustImplement(features.NausfUEAuthenticationEntries())...)

// nudmUEAUCatalog is the Nudm_UEAU consumer catalog.
var nudmUEAUCatalog = features.MustCatalog(features.MustImplement(features.NudmUEAUEntries())...)

// NausfUEAuthenticationCatalog returns the immutable Nausf_UEAuthentication
// catalog (producer role) of the AUSF. TS 29.509 §6.1.9.
func NausfUEAuthenticationCatalog() *features.Catalog { return nausfCatalog }

// NudmUEAUCatalog returns the immutable Nudm_UEAU catalog (consumer role) of
// the AUSF. TS 29.503 §6.3.8.
func NudmUEAUCatalog() *features.Catalog { return nudmUEAUCatalog }

// BuildNFProfile returns the NFProfile the AUSF registers at the NRF (nausf-auth
// service). The per-service supportedFeatures is advertised only under the
// rel19 profile (features.Request returns "" otherwise and the omitempty tag
// drops it), so the rel17 registration stays byte-identical.
// Ref: TS 29.510 §6.1.6.2.2 (NFProfile), §6.1.6.2.3 (NFService); decision D2.
func BuildNFProfile(nfInstanceID string, p *capability.Profile, cat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "AUSF",
		NFStatus:     "REGISTERED",
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-nausf-auth",
			ServiceName:       "nausf-auth",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NausfAuth)},
			SupportedFeatures: features.Request(cat, p),
		}},
	}
}
