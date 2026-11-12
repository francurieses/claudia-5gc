// features.go - supportedFeatures catalogs and negotiation helpers of the AMF
// (REL19-2.7). Ref: TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2.

package sbi

import (
	"context"
	"log/slog"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/sbi/apiversion"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// The API tables are transcribed once in shared/sbi/features (design note in
// tables.go); this file only decides which bits the AMF implements.
//
// Namf_Communication (producer side), TS 29.518 §6.1.8 Table 6.1.8-1: the AMF
// implements none of the optional features today (UEContextTransfer and
// N1N2MessageTransfer are the minimal control-plane subset; DTSSA, ENS, CIOT,
// MAPDU, NPN, ELCS, EAEA, ProSe, UAV, SPAE, eNPN, 3GA-N3GA-HO, ... are all
// absent), so no entry is marked Implemented and the AMF offers "0". The
// mandatory ES3XX (feature 7) carries its obligation on the NF Service
// Consumer, not on the producer; the AMF never emits a 307/308, so it stays
// unmarked here (SBI-FEAT-001).
//
// Nsmf_PDUSession (consumer side), TS 29.502 §6.1.8 Table 6.1.8-1:
//   - 8 ES3XX (M) is implemented: the SMF client follows 307/308 for every
//     SM-context operation (shared/sbi.ApplyRedirectPolicy, TS 29.500
//     §6.10.9.1), so the rel19 CreateSMContext offers "80" (SBI-FEAT-001).
//   - The other mandatory features are deferred (known conformance gap,
//     docs/procedures/feature-negotiation.md): 7 HOFAIL needs Notify SM
//     Context Status and non-3GPP access, 10 AASN needs Notify SM Context
//     Status and an I-SMF/V-SMF. 29 SCID is indicated by an H-SMF/V-SMF only
//     when SMF+PCF+CHF (HPLMN) or SMF+CHF (VPLMN) support the String based
//     Charging Identifier (TS 32.255); it places no behaviour on the AMF as
//     consumer and the stack has no CHF/Nchf. They stay unmarked, so they are
//     never offered.
//   - None of the optional features (CIOT, MAPDU, DTSSA, CARPT, CTXTR, VQOS,
//     ...) is implemented.

// Nausf_UEAuthentication, Nudm_SDM and Nudm_UECM (consumer side), TS 29.509
// §6.1.9 Table 6.1.9-1, TS 29.503 §6.1.8 Table 6.1.8-1 and §6.2.8 Table
// 6.2.8-1.
//   - Nausf 1 ES3XX (M) is marked: the shared SBI client follows 307/308
//     (sbi.ApplyRedirectPolicy, replayable bytes.Reader bodies), as for Nsmf, so
//     a rel19 AMF offers "1" in AuthenticationInfo and ConfirmationData.
//   - Nudm_SDM: the AMF reads the per-S-NSSAI NSSAA flag whatever the
//     negotiation says, and handles none of the optional features (SharedData,
//     Nsac, CAGFeature, sorTransparentSupport, upuTransparentSupport, Nssrg,
//     ...), so nothing may be claimed.
//   - Nudm_UECM: SharedData, PatchReport, CAGFeature, ... are not implemented.

// namfCommCatalog is the Namf_Communication producer catalog.
var namfCommCatalog = features.MustCatalog(features.MustImplement(features.NamfCommunicationEntries())...)

// nsmfFeatureES3XX is Nsmf_PDUSession feature 8, "Extended Support of HTTP
// 307/308 redirection". Ref: TS 29.502 §6.1.8 Table 6.1.8-1.
const nsmfFeatureES3XX = 8

// nsmfPDUSessionCatalog is the Nsmf_PDUSession consumer catalog.
var nsmfPDUSessionCatalog = features.MustCatalog(features.MustImplement(features.NsmfPDUSessionEntries(), nsmfFeatureES3XX)...)

// nausfFeatureES3XX is Nausf_UEAuthentication feature 1, "Extended Support of
// HTTP 307/308 redirection". Ref: TS 29.509 §6.1.9 Table 6.1.9-1.
const nausfFeatureES3XX = 1

// nausfUEAuthenticationCatalog is the Nausf_UEAuthentication consumer catalog.
var nausfUEAuthenticationCatalog = features.MustCatalog(features.MustImplement(features.NausfUEAuthenticationEntries(), nausfFeatureES3XX)...)

// nudmSDMCatalog is the Nudm_SDM consumer catalog.
var nudmSDMCatalog = features.MustCatalog(features.MustImplement(features.NudmSDMEntries())...)

// nudmUECMCatalog is the Nudm_UECM consumer catalog.
var nudmUECMCatalog = features.MustCatalog(features.MustImplement(features.NudmUECMEntries())...)

// nnrfNFDiscoveryCatalog is the Nnrf_NFDiscovery consumer catalog. TS 29.510
// §6.2.9 Table 6.2.9-1: the AMF forwards its query parameters and reads only
// the endpoints of the returned profiles, so it marks no bit and offers "0"
// under the rel19 profile.
var nnrfNFDiscoveryCatalog = features.MustCatalog(features.MustImplement(features.NnrfNFDiscoveryEntries())...)

// NnrfNFDiscoveryCatalog returns the immutable Nnrf_NFDiscovery catalog
// (consumer role) of the AMF. TS 29.510 §6.2.9.
func NnrfNFDiscoveryCatalog() *features.Catalog { return nnrfNFDiscoveryCatalog }

// NausfUEAuthenticationCatalog returns the immutable Nausf_UEAuthentication
// catalog (consumer role) of the AMF. TS 29.509 §6.1.9.
func NausfUEAuthenticationCatalog() *features.Catalog { return nausfUEAuthenticationCatalog }

// NudmSDMCatalog returns the immutable Nudm_SDM catalog (consumer role) of the
// AMF. TS 29.503 §6.1.8.
func NudmSDMCatalog() *features.Catalog { return nudmSDMCatalog }

// NudmUECMCatalog returns the immutable Nudm_UECM catalog (consumer role) of
// the AMF. TS 29.503 §6.2.8.
func NudmUECMCatalog() *features.Catalog { return nudmUECMCatalog }

// NamfCommunicationCatalog returns the immutable Namf_Communication catalog
// (producer role) of the AMF. TS 29.518 §6.1.8.
func NamfCommunicationCatalog() *features.Catalog { return namfCommCatalog }

// NsmfPDUSessionCatalog returns the immutable Nsmf_PDUSession catalog
// (consumer role) of the AMF. TS 29.502 §6.1.8.
func NsmfPDUSessionCatalog() *features.Catalog { return nsmfPDUSessionCatalog }

// CauseInvalidMsgFormat is the ProblemDetails cause for a malformed request
// attribute. Ref: TS 29.500 §5.2.7.2, Table 5.2.7.2-1.
const CauseInvalidMsgFormat = "INVALID_MSG_FORMAT"

// paramSupportedFeatures is the invalidParams "param" of a bad
// supportedFeatures attribute, encoded as a JSON Pointer. Ref: TS 29.571
// §5.2.4.6 (Table 5.2.4.6-1, InvalidParam.param).
const paramSupportedFeatures = "/supportedFeatures"

// InvalidParam names one request parameter that failed validation.
// Ref: TS 29.571 §5.2.4.6 (InvalidParam).
//
// oapi: TS29571_CommonData.yaml#/components/schemas/InvalidParam
type InvalidParam struct {
	Param  string `json:"param"`
	Reason string `json:"reason,omitempty"`
}

// BuildNFProfile returns the NFProfile the AMF registers at the NRF (namf-comm
// service). The per-service supportedFeatures is advertised only under the
// rel19 profile (features.Request returns "" otherwise and the omitempty tag
// drops it), so the rel17 registration stays byte-identical.
// Ref: TS 29.510 §6.1.6.2.2 (NFProfile), §6.1.6.2.3 (NFService); decision D2.
func BuildNFProfile(nfInstanceID string, p *capability.Profile, cat *features.Catalog) *nrf.NFProfile {
	return &nrf.NFProfile{
		NFInstanceID: nfInstanceID,
		NFType:       "AMF",
		NFStatus:     "REGISTERED",
		NFServices: []nrf.NFService{{
			ServiceInstanceID: nfInstanceID + "-namf-comm",
			ServiceName:       "namf-comm",
			Scheme:            "https",
			NFServiceStatus:   "REGISTERED",
			Versions:          []nrf.NFServiceVersion{nrf.ServiceVersion(p, apiversion.NamfComm)},
			SupportedFeatures: features.Request(cat, p),
		}},
	}
}

// Negotiation describes one FeatureNegotiation log record.
type Negotiation struct {
	Interface   string // Namf | Nsmf
	Direction   string // IN (producer) | OUT (consumer)
	PeerNF      string // peer NF type, e.g. SMF
	SpecRef     string // features.SpecRef, or features.SpecRefInvalid on a 400
	Result      string // OK | REJECT | FAILURE
	Cause       string // optional, e.g. INVALID_MSG_FORMAT
	Local       features.Set
	Peer        string // peer value as received
	PeerPresent bool   // false -> logged as "absent"
	Negotiated  features.Set
}

// LogNegotiation emits the canonical FeatureNegotiation record (TS 29.500
// §6.6.2): procedure, interface, direction, spec_ref, peer_nf_type,
// features_local / features_peer / features_negotiated and result. nf and
// nf_instance_id come from base (the process logger); correlation_id and the
// UE identifiers are taken from ctx by the procedure logger. extra carries
// resource identifiers (supi, pdu_session_id, ...). REJECT and FAILURE are
// logged at WARN, OK at INFO.
func LogNegotiation(ctx context.Context, base *slog.Logger, n Negotiation, extra ...any) {
	if base == nil {
		base = slog.Default()
	}
	// One fivegc_procedure_total{nf=AMF,procedure=FeatureNegotiation} per record.
	features.CountNegotiation("AMF", n.Result)
	log := logging.NewProcedureLogger(ctx, base, features.ProcedureName)
	attrs := []any{
		"interface", n.Interface,
		"direction", n.Direction,
		"spec_ref", n.SpecRef,
		"peer_nf_type", n.PeerNF,
	}
	attrs = append(attrs, features.LogAttrs(n.Local, n.Peer, n.PeerPresent, n.Negotiated)...)
	attrs = append(attrs, extra...)
	attrs = append(attrs, "result", n.Result)
	if n.Cause != "" {
		attrs = append(attrs, "cause", n.Cause)
	}
	if n.Result == "OK" {
		log.Info("supportedFeatures negotiated", attrs...)
		return
	}
	log.Warn("supportedFeatures negotiation did not complete", attrs...)
}
