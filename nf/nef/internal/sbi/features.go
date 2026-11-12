// Package sbi holds the NEF's SBI feature-negotiation tables and helpers
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.122 §5.2.7, §5.14.4;
// TS 29.571 §5.2.2.
package sbi

import (
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API table is transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the NEF implements.
//
// AsSessionWithQoS (producer, northbound), TS 29.122 §5.14.4 Table 5.14.4-1
// (38 features in V19.7.0; the negotiation is the TS 29.500 §6.6.2 procedure,
// TS 29.122 §5.2.7). The NEF implements the minimal Create/Get/Delete subset
// and none of the optional features, so no entry is marked Implemented and the
// NEF offers "0". Notably:
//   - 9 AppId governs the "exterAppId" attribute; the NEF maps the non-spec
//     "afAppId" to the PCF instead and does not support exterAppId (known
//     deviation, not changed by this pass).
//   - 5 AlternativeQoS_5G: altQoSReferences is accepted but only the first
//     reference is used, so the feature is not implemented.
//   - 1 Notification_websocket, 2 Notification_test_event, 6 QoSMonitoring_5G
//     and the rest of the table are not implemented.

// asSessionWithQoSCatalog is the AsSessionWithQoS producer catalog.
var asSessionWithQoSCatalog = features.MustCatalog(features.MustImplement(features.AsSessionWithQoSEntries())...)

// AsSessionWithQoSCatalog returns the immutable AsSessionWithQoS catalog
// (producer role) of the NEF. TS 29.122 §5.14.4.
func AsSessionWithQoSCatalog() *features.Catalog { return asSessionWithQoSCatalog }

// BuildNFProfile returns the NFProfile the NEF registers at the NRF. Unlike the
// other NFs it never sets the per-service supportedFeatures, in any profile:
// TS 29.122 §5.2.7 says "the SCEF should not register any feature for
// northbound APIs in the NRF", and TS 29.522 §5.2 replaces SCEF by NEF for the
// APIs it defines, so the NEF does not register features for northbound APIs
// either. The registration is therefore byte-identical in rel17 and rel19.
// The service version follows the release profile p (apiFullVersion, NRF-VER-001); cat is kept for signature symmetry.
// Ref: TS 29.510 §6.1.6.2.2 (NFProfile), §6.1.6.2.3 (NFService).
func BuildNFProfile(nfInstanceID, fqdn string, p *capability.Profile, _ *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "NEF",
		NFStatus:     "REGISTERED",
		FQDN:         fqdn,
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-3gpp-as-session-with-qos",
			ServiceName:       "3gpp-as-session-with-qos",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions: []nrf.NFServiceVersion{
				nrf.ServiceVersion(p, apiversion.AsSessionWithQoS),
			},
		}},
	}
}

// Consumer-side catalogs (REL19-2.7 slice 7). The NEF consumes two APIs while
// serving an AsSessionWithQoS Create; neither is exposed northbound, so the
// catalogs below describe only what the NEF's outbound client implements.
//
// ES3XX ("Extended Support of HTTP 307/308 redirection") is a consumer
// obligation: the NEF outbound client installs sbi.ApplyRedirectPolicy
// (TS 29.500 §6.10.9.1, follows 307/308 only, refuses 301/302/303 and
// https->http), which is independent of the release profile; only the bit
// offered is profile-gated (Rel-17 tagged, so offered under rel19 only because
// rel17 sends no supportedFeatures at all, decision D2). The BSF producer
// states the same reading (nf/bsf/internal/sbi/features.go, "consumer-side
// redirection handling"). Feature text (identical in TS 29.514 V17.16.0 /
// V19.8.0 Table 5.8-1 feature 26 and TS 29.521 V17.11.0 / V19.7.0 Table 5.8-1
// feature 4): "Extended Support for 3xx redirections. This feature indicates
// the support of redirection for any service operation, according to Stateless
// NF procedures as specified in clauses 6.5.3.2 and 6.5.3.3 of 3GPP TS 29.500
// and according to HTTP redirection principles for indirect communication, as
// specified in clause 6.10.9". Consumer obligation: follow 307/308
// (TS 29.500 §6.5.3.3, §6.10.9.1), implemented by sbi.ApplyRedirectPolicy,
// installed in server.NewOutboundClient (called from cmd/nef/main.go).

const (
	// npcfFeatureES3XX is Npcf_PolicyAuthorization feature 26, ES3XX.
	// Ref: TS 29.514 §5.8 Table 5.8-1.
	npcfFeatureES3XX = 26
	// npcfFeatureAuthorizationWithRequiredQoS is Npcf_PolicyAuthorization
	// feature 17: "Indicates support of policy authorization for the AF session
	// with required QoS"; it gates MediaComponent.qosReference, which the NEF
	// sends under rel19. Ref: TS 29.514 §5.8 Table 5.8-1, clause 4.2.2.32.
	npcfFeatureAuthorizationWithRequiredQoS = 17
	// nbsfFeatureES3XX is Nbsf_Management feature 4, ES3XX.
	// Ref: TS 29.521 §5.8 Table 5.8-1.
	nbsfFeatureES3XX = 4
)

// npcfPolicyAuthorizationCatalog is the Npcf_PolicyAuthorization consumer
// catalog: ES3XX (26) and AuthorizationWithRequiredQoS (17) are implemented.
// The other 81 features (e.g.
// InfluenceOnTrafficRouting, SponsoredConnectivity, MediaComponentVersioning)
// are not used by the NEF's single-flow Create/Delete.
var npcfPolicyAuthorizationCatalog = features.MustCatalog(features.MustImplement(features.NpcfPolicyAuthorizationEntries(), npcfFeatureES3XX, npcfFeatureAuthorizationWithRequiredQoS)...)

// NpcfPolicyAuthorizationCatalog returns the immutable Npcf_PolicyAuthorization
// catalog (consumer role) of the NEF. TS 29.514 §5.8.
func NpcfPolicyAuthorizationCatalog() *features.Catalog { return npcfPolicyAuthorizationCatalog }

// nbsfManagementCatalog is the Nbsf_Management consumer catalog: only ES3XX (4)
// is implemented; MultiUeAddr, BindingUpdate, SamePcf, ExtendedSamePcf,
// AddSnssaiDnnPair, Recovery and ExpTime are not used by the discovery GET.
var nbsfManagementCatalog = features.MustCatalog(features.MustImplement(features.NbsfManagementEntries(), nbsfFeatureES3XX)...)

// NbsfManagementCatalog returns the immutable Nbsf_Management catalog
// (consumer role) of the NEF. TS 29.521 §5.8.
func NbsfManagementCatalog() *features.Catalog { return nbsfManagementCatalog }
