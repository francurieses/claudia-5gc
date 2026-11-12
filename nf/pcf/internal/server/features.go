// Package server - producer-side supportedFeatures negotiation of the four
// Npcf APIs the PCF serves (REL19-2.7 slice 4). Ref: TS 29.500 §6.6.2,
// §5.2.7.2; TS 29.571 §5.2.2, §5.2.4.6; TS 29.512 §5.8, TS 29.507 §5.8,
// TS 29.525 §5.8, TS 29.514 §5.8.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	pcfsbi "github.com/francurieses/claudia-5gc/nf/pcf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// apiKind selects one of the four producer APIs of the PCF.
type apiKind int

const (
	apiSMPolicy   apiKind = iota // Npcf_SMPolicyControl, TS 29.512
	apiAMPolicy                  // Npcf_AMPolicyControl, TS 29.507
	apiUEPolicy                  // Npcf_UEPolicyControl, TS 29.525
	apiPolicyAuth                // Npcf_PolicyAuthorization, TS 29.514
	apiCount
)

// attrSuppFeat is the JSON attribute carrying the features value in all four
// APIs (SmPolicyContextData, PolicyAssociationRequest, AppSessionContextReqData).
const attrSuppFeat = "suppFeat"

// apiInfo describes how one API names its attribute and who consumes it.
type apiInfo struct {
	// procedure is the procedure label of the create operation (metrics and
	// the generic counter fivegc_procedure_total).
	procedure string
	// field is the encoding/json UnmarshalTypeError.Field of the attribute.
	field string
	// param is the invalidParams "param": a JSON Pointer to the attribute
	// (TS 29.571 §5.2.4.6).
	param string
	// consumer is the TS consumer NF type used when the User-Agent has none
	// (TS 29.500 §5.2.2.2).
	consumer string
}

var apiInfos = [apiCount]apiInfo{
	apiSMPolicy:   {"SmPolicyCreate", attrSuppFeat, "/" + attrSuppFeat, "SMF"},
	apiAMPolicy:   {"AMPolicyCreate", attrSuppFeat, "/" + attrSuppFeat, "AMF"},
	apiUEPolicy:   {"UEPolicyCreate", attrSuppFeat, "/" + attrSuppFeat, "AMF"},
	apiPolicyAuth: {"PolicyAuthorizationCreate", "ascReqData." + attrSuppFeat, "/ascReqData/" + attrSuppFeat, "AF"},
}

// Catalogs groups the four producer catalogs; a nil member keeps the default.
type Catalogs struct {
	SMPolicy, AMPolicy, UEPolicy, PolicyAuth *features.Catalog
}

// SetProfile wires the release profile used for supportedFeatures negotiation
// (decisions D1/D2, dev/REL19_PROGRAM.md §2); nil behaves as rel17. Must be
// called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetCatalogs replaces producer catalogs (tests inject catalogs with
// Implemented entries); nil members restore the default. Must be called
// before Start().
func (s *Server) SetCatalogs(c Catalogs) {
	pick := func(v, def *features.Catalog) *features.Catalog {
		if v == nil {
			return def
		}
		return v
	}
	s.cats[apiSMPolicy] = pick(c.SMPolicy, pcfsbi.NpcfSMPolicyControlCatalog())
	s.cats[apiAMPolicy] = pick(c.AMPolicy, pcfsbi.NpcfAMPolicyControlCatalog())
	s.cats[apiUEPolicy] = pick(c.UEPolicy, pcfsbi.NpcfUEPolicyControlCatalog())
	s.cats[apiPolicyAuth] = pick(c.PolicyAuth, pcfsbi.NpcfPolicyAuthorizationCatalog())
}

// peerNFType is the NF type of the consumer for the FeatureNegotiation record.
func peerNFType(r *http.Request, k apiKind) string {
	return features.PeerNFTypeFromUserAgent(r.UserAgent(), apiInfos[k].consumer)
}

// suppFeatFromMap reads the suppFeat attribute of an untyped request body. A
// missing attribute, JSON null and "" are all "absent"; any non-string value
// is a type error (the caller answers 400 like a non-hex value).
func suppFeatFromMap(m map[string]any) (string, bool) {
	v, ok := m[attrSuppFeat]
	if !ok || v == nil {
		return "", true
	}
	str, isStr := v.(string)
	return str, isStr
}

// answer is the producer side of §6.6.2 for API k (decision D1): the
// intersection of the consumer's value with the PCF's offer; "" (attribute
// omitted) under rel17 when the request carried none.
func (s *Server) answer(k apiKind, peer string) (string, features.Set) {
	return features.Answer(s.cats[k], s.profile, peer)
}

// logAccepted records the negotiation of an accepted request.
func (s *Server) logAccepted(ctx context.Context, k apiKind, peerNF, peer string, negotiated features.Set) {
	features.LogNegotiation(ctx, s.baseLogger, features.Negotiation{
		NF:        "PCF",
		Interface: "Npcf", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.cats[k].Supported(s.profile), Peer: peer,
		PeerPresent: peer != "", Negotiated: negotiated,
	})
}

// Details of the 400 answered for a schema-invalid suppFeat.
const (
	detailNotHex    = attrSuppFeat + " is not a valid hexadecimal string"
	detailNotString = attrSuppFeat + " must be a JSON string"
)

// rejectSuppFeat answers a schema-invalid suppFeat with 400 INVALID_MSG_FORMAT
// and an invalidParams entry pointing at the attribute, after logging one
// REJECT record and counting it. Ref: TS 29.500 §5.2.7.2; TS 29.571 §5.2.4.6.
func (s *Server) rejectSuppFeat(ctx context.Context, w http.ResponseWriter, k apiKind, peerNF, shown string, cause error, detail string) {
	info := apiInfos[k]
	features.LogNegotiation(ctx, s.baseLogger, features.Negotiation{
		NF:        "PCF",
		Interface: "Npcf", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseInvalidMsgFormat,
		Local: s.cats[k].Supported(s.profile), Peer: shown, PeerPresent: true,
	}, "error", cause)
	metrics.ProcedureTotal.WithLabelValues("PCF", info.procedure, "REJECT").Inc()
	s.problemInvalidParam(ctx, w, features.CauseInvalidMsgFormat, info.param, detail)
}

// decodeBody decodes the JSON request body into v with the 1 MiB bound. It
// reports whether the body was too large (the caller answers 413).
func decodeBody(w http.ResponseWriter, r *http.Request, v any) (tooLarge bool, err error) {
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	err = json.NewDecoder(r.Body).Decode(v)
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe), err
}

// payloadTooLarge answers a body over features.MaxRequestBodyBytes with 413
// and a ProblemDetails without a cause (no 413 cause is defined), after
// logging one REJECT record and counting it under procedure (the name of the
// operation that received the body: a create or a delete custom operation, not
// necessarily apiInfos[k].procedure). Ref: TS 29.500 §5.2.7.1; TS 29.571 §5.2.4.1.
func (s *Server) payloadTooLarge(ctx context.Context, w http.ResponseWriter, _ apiKind, procedure string) {
	logging.NewProcedureLogger(ctx, s.baseLogger, procedure).Warn("request body too large",
		"interface", "Npcf", "direction", "IN", "result", "REJECT", "cause", "PAYLOAD_TOO_LARGE",
		"spec_ref", "TS 29.500 §5.2.7.1")
	metrics.ProcedureTotal.WithLabelValues("PCF", procedure, "REJECT").Inc()
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusRequestEntityTooLarge,
		"detail": "request body too large",
	}); err != nil {
		s.baseLogger.DebugContext(ctx, "write 413 problem details", "error", err)
	}
}

// problemInvalidParam writes a 400 ProblemDetails with one invalidParams entry.
// Ref: TS 29.571 §5.2.4.1 (ProblemDetails), §5.2.4.6 (InvalidParam).
func (s *Server) problemInvalidParam(ctx context.Context, w http.ResponseWriter, cause, param, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusBadRequest,
		"cause":  cause,
		"detail": detail,
		"invalidParams": []map[string]string{
			{"param": param},
		},
	}); err != nil {
		s.baseLogger.DebugContext(ctx, "write 400 problem details", "error", err)
	}
}
