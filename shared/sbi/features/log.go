// Canonical logging attributes for the FeatureNegotiation procedure.

package features

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// Constants shared by every NF so the FeatureNegotiation log lines are
// identical.
const (
	// ProcedureName is the canonical "procedure" log field value.
	ProcedureName = "FeatureNegotiation"
	// SpecRef is the canonical "spec_ref" for a negotiation.
	SpecRef = "TS 29.500 §6.6.2"
	// SpecRefInvalid is the "spec_ref" when the peer value is malformed and
	// the request is rejected with 400 INVALID_MSG_FORMAT.
	SpecRefInvalid = "TS 29.500 §5.2.7.2"
	// MaxLoggedPeerChars bounds the features_peer value written to the log: a
	// peer value is attacker-controlled and may be arbitrarily long (own bound,
	// not a spec value). Longer values are cut and suffixed with "...".
	MaxLoggedPeerChars = 64
	// MaxRequestBodyBytes is the request-body cap (1 MiB, own bound, not a spec
	// value) producers apply with http.MaxBytesReader on handlers that decode a
	// supportedFeatures-bearing body.
	MaxRequestBodyBytes = 1 << 20
	// PeerAbsent is the features_peer value when the peer sent no attribute.
	PeerAbsent = "absent"
)

// LogAttrs returns the key/value pairs features_local, features_peer and
// features_negotiated, ready for slog.Logger.Info(msg, attrs...). local and
// negotiated are rendered in canonical form; peer is logged as received (cut to MaxLoggedPeerChars with a "..." suffix), or
// "absent" when peerPresent is false.
func LogAttrs(local Set, peer string, peerPresent bool, negotiated Set) []any {
	if !peerPresent {
		peer = PeerAbsent
	} else {
		peer = truncatePeer(peer)
	}
	return []any{
		"features_local", local.String(),
		"features_peer", peer,
		"features_negotiated", negotiated.String(),
	}
}

// ParamSupportedFeatures is the invalidParams "param" of a bad
// supportedFeatures attribute: a JSON Pointer to the attribute. Ref: TS 29.571
// §5.2.4.6 (Table 5.2.4.6-1, InvalidParam.param).
const ParamSupportedFeatures = "/supportedFeatures"

// CauseInvalidMsgFormat is the ProblemDetails cause for a request attribute
// that violates its schema. Ref: TS 29.500 §5.2.7.2, Table 5.2.7.2-1.
const CauseInvalidMsgFormat = "INVALID_MSG_FORMAT"

// IsTypeError reports whether err is a JSON type error on the top-level
// supportedFeatures attribute (for instance a number where the schema wants a
// string). The producer maps it to 400 INVALID_MSG_FORMAT like a non-hex value
// (TS 29.500 §5.2.7.2, TS 29.571 §5.2.2); any other decode error is the
// caller's generic handling.
func IsTypeError(err error) bool { return IsTypeErrorOn(err, "supportedFeatures") }

// IsTypeErrorOn is IsTypeError for an API whose schema names the attribute
// differently (for instance "suppFeat" in TS 29.521 Nbsf_Management): it
// reports whether err is a JSON type error on the top-level attribute field.
//
// When the request struct embeds the type that declares the attribute, Go
// 1.26 reports the Go path of the promoted field ("SdmSubscription.field")
// while Go 1.27 reports the bare JSON name, so the trailing path element is
// compared too.
func IsTypeErrorOn(err error, field string) bool {
	var ute *json.UnmarshalTypeError
	if !errors.As(err, &ute) {
		return false
	}
	return ute.Field == field || strings.HasSuffix(ute.Field, "."+field)
}

// ParamQuerySupportedFeatures is the invalidParams "param" of a bad
// "supported-features" query parameter: "query <name>". Ref: TS 29.571
// §5.2.4.6 (InvalidParam.param for a query parameter).
const ParamQuerySupportedFeatures = "query supported-features"

// CauseOptionalQueryParamIncorrect is the ProblemDetails cause for a bad value
// in a known optional query parameter. Ref: TS 29.500 §5.2.7.2, Table
// 5.2.7.2-1.
const CauseOptionalQueryParamIncorrect = "OPTIONAL_QUERY_PARAM_INCORRECT"

// Negotiation describes one FeatureNegotiation log record.
type Negotiation struct {
	NF          string // emitting NF (nf label of fivegc_procedure_total); "" -> UnknownNF
	Interface   string // Nausf | Nudm | Nnef ...
	Direction   string // IN (producer) | OUT (consumer)
	PeerNF      string // peer NF type, e.g. AMF; "AF" for a northbound client
	SpecRef     string // SpecRef, or SpecRefInvalid on a 400
	Result      string // OK | REJECT | FAILURE
	Cause       string // optional, e.g. INVALID_MSG_FORMAT
	Local       Set
	Peer        string // peer value as received
	PeerPresent bool   // false -> logged as "absent"
	Negotiated  Set
}

// UnknownNF is the nf label of fivegc_procedure_total when the emitting NF
// did not set Negotiation.NF.
const UnknownNF = "UNKNOWN"

// CountNegotiation increments fivegc_procedure_total{nf, procedure=
// "FeatureNegotiation", result} once. Every emitter of a FeatureNegotiation
// record calls it (LogNegotiation does so itself) so that the number of
// records equals the counter. nf "" is labelled UnknownNF. No new metric: the
// generic procedure counter is reused. Ref: TS 29.500 §6.6.2.
func CountNegotiation(nf, result string) {
	if nf == "" {
		nf = UnknownNF
	}
	metrics.ProcedureTotal.WithLabelValues(nf, ProcedureName, result).Inc()
}

// LogNegotiation emits the canonical FeatureNegotiation record (TS 29.500
// §6.6.2): procedure, interface, direction, spec_ref, peer_nf_type,
// features_local / features_peer / features_negotiated and result. base must
// be the process logger (it carries nf and nf_instance_id); never pass a
// handler logger that already has procedure/interface, because slog's JSON
// handler does not de-duplicate keys. correlation_id and the UE identifiers
// come from ctx via the procedure logger, so extra must not repeat them.
// REJECT and FAILURE are logged at WARN, OK at INFO. It also increments
// fivegc_procedure_total{nf=n.NF, procedure="FeatureNegotiation",
// result=n.Result} (CountNegotiation).
func LogNegotiation(ctx context.Context, base *slog.Logger, n Negotiation, extra ...any) {
	if base == nil {
		base = slog.Default()
	}
	CountNegotiation(n.NF, n.Result)
	log := logging.NewProcedureLogger(ctx, base, ProcedureName)
	attrs := []any{
		"interface", n.Interface,
		"direction", n.Direction,
		"spec_ref", n.SpecRef,
		"peer_nf_type", n.PeerNF,
	}
	attrs = append(attrs, LogAttrs(n.Local, n.Peer, n.PeerPresent, n.Negotiated)...)
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

// truncatePeer cuts v to at most MaxLoggedPeerChars bytes on a rune boundary
// (no U+FFFD introduced) and appends "..." when it was cut.
func truncatePeer(v string) string {
	if len(v) <= MaxLoggedPeerChars {
		return v
	}
	cut := MaxLoggedPeerChars
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "..."
}

// nfTypePattern bounds an NF type token taken from a peer-controlled header or
// query value (own bound, not a spec value).
var nfTypePattern = regexp.MustCompile(`^[A-Z0-9_]{2,16}$`)

// ValidNFType reports whether v looks like an NFType token (^[A-Z0-9_]{2,16}$).
func ValidNFType(v string) bool { return nfTypePattern.MatchString(v) }

// PeerNFTypeFromUserAgent returns the NF type carried by a User-Agent header,
// format "<NFType>-<instance...>" (TS 29.500 §5.2.2.2): the part before the
// first '-'. Values not matching ^[A-Z0-9_]{2,16}$ yield fallback.
func PeerNFTypeFromUserAgent(ua, fallback string) string {
	t, _, _ := strings.Cut(ua, "-")
	if !ValidNFType(t) {
		return fallback
	}
	return t
}
