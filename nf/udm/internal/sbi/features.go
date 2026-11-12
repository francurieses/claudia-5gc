// Package sbi holds the UDM's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API table is transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the UDM implements.
//
// Nudm_UEAU (producer), TS 29.503 §6.3.8 Table 6.3.8-1: the table is empty in
// V17.22.0 and V18.13.0; V19.7.0 adds 1 SUBDMIG ("The UDM and the NF consumer
// supporting this feature shall support sending/receiving Subscriber Data
// Migration attributes (e.g. rediscoveryInd, noResynchronizationRequired,...)
// in the Data Restoration Notification message"). The UDM has no Data
// Restoration Notification, so the bit stays unmarked and the UDM offers "0".
//
// Nudm_SDM (producer), TS 29.503 §6.1.8 Table 6.1.8-1 (25 features), and
// Nudm_UECM (producer), §6.2.8 Table 6.2.8-1 (6 features): the UDM marks no bit
// and offers "0". Features that only gate content (4 Nssaa, 5 CAGFeature, 8
// Nsac, 16 TempSliceSupport, 22 Cag-Info-With-Validity-Periods, ...) would
// have to withhold that content from consumers that do not negotiate them;
// the UDM sends its data unconditionally (for example the per-S-NSSAI NSSAA
// flag in am-data) and gating it would change the legacy rel17 bytes, so
// advertising them would be false. SharedData*, ImmediateReport, PatchReport,
// LimitedSubscriptions, ENA, UeConSmfDataSubFilter, sorTransparentSupport,
// upuTransparentSupport and the SNPN-ID pair have no implementation behind
// them (no shared data, no PATCH, no SoR/UPU, no SNPN).

// nudmUEAUCatalog is the Nudm_UEAU producer catalog.
var nudmUEAUCatalog = features.MustCatalog(features.MustImplement(features.NudmUEAUEntries())...)

// NudmUEAUCatalog returns the immutable Nudm_UEAU catalog (producer role) of
// the UDM. TS 29.503 §6.3.8.
func NudmUEAUCatalog() *features.Catalog { return nudmUEAUCatalog }

// nudmSDMCatalog is the Nudm_SDM producer catalog.
var nudmSDMCatalog = features.MustCatalog(features.MustImplement(features.NudmSDMEntries())...)

// NudmSDMCatalog returns the immutable Nudm_SDM catalog (producer role) of the
// UDM. TS 29.503 §6.1.8.
func NudmSDMCatalog() *features.Catalog { return nudmSDMCatalog }

// nudmUECMCatalog is the Nudm_UECM producer catalog.
var nudmUECMCatalog = features.MustCatalog(features.MustImplement(features.NudmUECMEntries())...)

// NudmUECMCatalog returns the immutable Nudm_UECM catalog (producer role) of
// the UDM. TS 29.503 §6.2.8.
func NudmUECMCatalog() *features.Catalog { return nudmUECMCatalog }

// BuildNFProfile returns the NFProfile the UDM registers at the NRF. It lists
// the nudm-ueau service only: nudm-sdm and nudm-uecm are not registered today
// and adding them would change the rel17 registration bytes, so the Nudm_SDM
// and Nudm_UECM catalogs are not advertised at the NRF yet. The per-service
// supportedFeatures is advertised only under the rel19 profile (features.Request
// returns "" otherwise and the omitempty tag drops it), so the rel17
// registration stays byte-identical.
// Ref: TS 29.510 §6.1.6.2.2 (NFProfile), §6.1.6.2.3 (NFService); decision D2.
func BuildNFProfile(nfInstanceID string, p *capability.Profile, cat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "UDM",
		NFStatus:     "REGISTERED",
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-nudm-ueau",
			ServiceName:       "nudm-ueau",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NudmUEAU)},
			SupportedFeatures: features.Request(cat, p),
		}},
	}
}

// Nudr_DataRepository (consumer side), TS 29.504 §6.1.8 Table 6.1.8-1: the
// UDM marks no bit and offers "0" under the rel19 profile. It reads the
// authentication subscription, am-data and sm-data as stored by the UDR and
// does not post-process any optional Nudr feature.

// nudrDataRepositoryCatalog is the Nudr_DataRepository consumer catalog.
var nudrDataRepositoryCatalog = features.MustCatalog(features.NudrDataRepositoryEntries()...)

// NudrDataRepositoryCatalog returns the immutable Nudr_DataRepository catalog
// (consumer role) of the UDM. TS 29.504 §6.1.8.
func NudrDataRepositoryCatalog() *features.Catalog { return nudrDataRepositoryCatalog }
