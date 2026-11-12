// Package server: SBI supportedFeatures negotiation for the SMF
// (TS 29.500 §6.6.2, TS 29.571 §5.2.2).
//
// The SMF is the producer of Nsmf_PDUSession (feature table: TS 29.502
// §6.1.8, Table 6.1.8-1) and a consumer of Namf_Communication (TS 29.518
// §6.1.8, Table 6.1.8-1) when it sends N1N2MessageTransfer. The tables are
// transcribed once in shared/sbi/features; this file marks which features the
// SMF implements. Only Namf_Communication feature 7 ES3XX (consumer side:
// follow 307/308, shared/sbi.ApplyRedirectPolicy, TS 29.500 §6.10.9.1) is
// implemented (SBI-FEAT-001), so the rel19 N1N2MessageTransfer offers "40"
// (nothing on the wire under rel17). The Nsmf_PDUSession producer catalog
// implements nothing (ES3XX carries no producer obligation) and answers "0".

package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// nsmfPDUSessionCatalog is the Nsmf_PDUSession producer catalog (TS 29.502
// §6.1.8 Table 6.1.8-1). No feature is implemented: ES3XX (8) is a consumer
// obligation, HOFAIL/AASN are deferred (no Notify SM Context Status, no
// non-3GPP access, no I-SMF/V-SMF) and SCID (String based Charging
// Identifier, TS 32.255) is not offered because the stack has no CHF/Nchf.
var nsmfPDUSessionCatalog = features.MustCatalog(features.NsmfPDUSessionEntries()...)

// namfCommunicationCatalog is the Namf_Communication consumer catalog
// (TS 29.518 §6.1.8 Table 6.1.8-1). Implemented: 7 ES3XX (HTTP 307/308
// redirection handling for N1N2MessageTransfer).
var namfCommunicationCatalog = features.MustCatalog(features.MustImplement(features.NamfCommunicationEntries(), namfFeatureES3XX)...)

// namfFeatureES3XX is Namf_Communication feature 7, "Extended Support of HTTP
// 307/308 redirection". Ref: TS 29.518 §6.1.8 Table 6.1.8-1.
const namfFeatureES3XX = 7

// paramSupportedFeatures is the invalidParams "param" of a bad supportedFeatures
// attribute, a JSON Pointer to the attribute. Ref: TS 29.571 §5.2.4.6 (Table
// 5.2.4.6-1, InvalidParam.param).
const paramSupportedFeatures = "/supportedFeatures"

// Option customises a Server at construction.
type Option func(*Server)

// WithProfile sets the release profile that gates supportedFeatures wire
// behaviour (decisions D1/D2). Without it the server behaves as rel17.
func WithProfile(p *capability.Profile) Option {
	return func(s *Server) { s.profile = p }
}

// WithCatalogs overrides the Nsmf_PDUSession (producer) and Namf_Communication
// (consumer) catalogs; a nil argument keeps the default. Tests use it to
// negotiate non-empty sets.
func WithCatalogs(nsmf, namf *features.Catalog) Option {
	return func(s *Server) {
		if nsmf != nil {
			s.nsmfCat = nsmf
		}
		if namf != nil {
			s.namfCat = namf
		}
	}
}

// featureLog describes one FeatureNegotiation log line (TS 29.500 §6.6.2).
type featureLog struct {
	iface       string // Nsmf (producer) or Namf (consumer)
	direction   string // IN or OUT
	specRef     string
	local       features.Set
	peer        string
	peerPresent bool
	negotiated  features.Set
	result      string // OK, REJECT or FAILURE
	extra       []any  // cause, supi, pdu_session_id, correlation_id, error ...
}

// logFeatureNegotiation emits the canonical FeatureNegotiation line from base
// (the server logger, which already carries nf=SMF). REJECT and FAILURE log at WARN.
func logFeatureNegotiation(ctx context.Context, base *slog.Logger, f featureLog) {
	// One fivegc_procedure_total{nf=SMF,procedure=FeatureNegotiation} per record.
	features.CountNegotiation("SMF", f.result)

	// Built from the base server logger (nf only), never from a handler logger
	// that already carries procedure/interface/direction: slog's JSON handler
	// does not de-duplicate keys. NewProcedureLogger adds procedure and, when
	// ctx has one, correlation_id.
	log := logging.NewProcedureLogger(ctx, base, features.ProcedureName)
	attrs := []any{
		"interface", f.iface,
		"direction", f.direction,
		"spec_ref", f.specRef,
		"peer_nf_type", "AMF",
	}
	attrs = append(attrs, features.LogAttrs(f.local, f.peer, f.peerPresent, f.negotiated)...)
	attrs = append(attrs, "result", f.result)
	attrs = append(attrs, f.extra...)
	level := slog.LevelInfo
	if f.result != "OK" {
		level = slog.LevelWarn
	}
	log.Log(ctx, level, "feature negotiation", attrs...)
}

// negotiateCreateFeatures applies the producer side of TS 29.500 §6.6.2 to a
// decoded CreateSMContext request. It returns the negotiated set and the
// string to put in the response (empty = omit the attribute, decision D1).
//
// A present, non-null supportedFeatures that is not a string or fails
// features.Validate is rejected here with 400 INVALID_MSG_FORMAT and
// invalidParams[{param: /supportedFeatures}] (JSON Pointer, TS 29.571 §5.2.4.6) (TS 29.500 §5.2.7.2) and ok=false;
// the caller must return immediately. JSON null is treated as absent.
func (s *Server) negotiateCreateFeatures(ctx context.Context, w http.ResponseWriter, req map[string]interface{}) (features.Set, string, bool) {
	supi, _ := req["supi"].(string)
	extra := []any{"supi", supi}
	if psi, ok := req["pduSessionId"].(float64); ok {
		extra = append(extra, "pdu_session_id", uint8(psi))
	}
	local := s.nsmfCat.Supported(s.profile)

	raw, present := req["supportedFeatures"]
	if raw == nil {
		present = false
	}
	peer, isString := raw.(string)
	// An explicit "" is logged "absent", like a missing attribute and like the
	// AMF (a Go omitempty string cannot tell them apart); Answer treats both
	// as "no features".
	logPresent := present && peer != ""
	if present && (!isString || features.Validate(peer) != nil) {
		shown := peer
		if !isString {
			shown = "<non-string>"
		}
		logFeatureNegotiation(ctx, s.logger, featureLog{
			iface: "Nsmf", direction: "IN", specRef: features.SpecRefInvalid,
			local: local, peer: shown, peerPresent: true, result: "REJECT",
			extra: append(extra, "cause", "INVALID_MSG_FORMAT"),
		})
		problemWithParams(w, http.StatusBadRequest, "INVALID_MSG_FORMAT",
			"supportedFeatures is not a valid hexadecimal string",
			[]map[string]string{{"param": paramSupportedFeatures}})
		return features.Set{}, "", false
	}

	answer, negotiated := features.Answer(s.nsmfCat, s.profile, peer)
	logFeatureNegotiation(ctx, s.logger, featureLog{
		iface: "Nsmf", direction: "IN", specRef: features.SpecRef,
		local: local, peer: peer, peerPresent: logPresent, negotiated: negotiated,
		result: "OK", extra: extra,
	})
	return negotiated, answer, true
}

// n1n2Offer is the supportedFeatures value the SMF, as Namf_Communication
// consumer, puts in an N1N2MessageTransfer request: features.Request under the
// rel19 profile ("0" when nothing is offered), "" under rel17 (the caller
// omits the attribute so the body stays byte-identical). Decision D2.
func (s *Server) n1n2Offer() string {
	return features.Request(s.namfCat, s.profile)
}

// acceptN1N2Features processes the supportedFeatures of the AMF's
// N1N2MessageTransfer answer (consumer side, TS 29.500 §6.6.2) and logs the
// FeatureNegotiation line. There is no resource to store the result on. A
// non-hex answer negotiates nothing and is logged result=FAILURE; the
// procedure is never failed (R13).
func (s *Server) acceptN1N2Features(ctx context.Context, offer, answer string, extra ...any) features.Set {
	local := s.namfCat.Supported(s.profile)
	negotiated, err := features.Accept(offer, answer)
	f := featureLog{
		iface: "Namf", direction: "OUT", specRef: features.SpecRef,
		local: local, peer: answer, peerPresent: answer != "",
		negotiated: negotiated, result: "OK", extra: extra,
	}
	if err != nil {
		f.result = "FAILURE"
		f.extra = append(f.extra, "error", err.Error())
	}
	logFeatureNegotiation(ctx, s.logger, f)
	return negotiated
}
