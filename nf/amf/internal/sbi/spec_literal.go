package sbi

// spec_literal.go - rel19 (spec-literal) alignment of the Namf producer
// operations with TS 29.518 / TS 29.500 / TS29518_*.yaml (drift-amf). Every
// helper leaves the rel17 profile (and "no profile") byte-identical on the wire:
// decision D1, the frozen baseline (dev/REL19_PROGRAM.md §2).

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"

	"github.com/google/uuid"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	sharedsbi "github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// Common application errors of the AMF producer. Ref: TS 29.500 Table 5.2.7.2-1.
const (
	// CauseMandatoryIEMissing: a mandatory IE is not included in the request.
	CauseMandatoryIEMissing = "MANDATORY_IE_MISSING"
	// CauseMandatoryIEIncorrect: a mandatory IE has a semantically incorrect value.
	CauseMandatoryIEIncorrect = "MANDATORY_IE_INCORRECT"
)

// Namf_Location application errors (rel19 answers of ProvideLocationInfo).
// Ref: TS 29.518 Table 6.4.7.3-1.
const (
	// CauseUnreachableUser: the user could not be reached to perform positioning (504).
	CauseUnreachableUser = "UNREACHABLE_USER"
	// CausePeerNotResponding: no response from a remote peer (here the NG-RAN) (504).
	CausePeerNotResponding = "PEER_NOT_RESPONDING"
)

// JSON Pointers of the UeContextTransferReqData mandatory IEs, used as
// invalidParams "param" values. Ref: TS 29.571 §5.2.4.6; TS 29.518 Table 6.1.6.2.23-1.
const (
	paramReason     = "/reason"
	paramAccessType = "/accessType"
)

// mediaTypeJSON is the JSON request media type of the Namf operations.
// Ref: TS 29.500 §5.4 (multipart), TS29518_Namf_Communication.yaml requestBody.
const mediaTypeJSON = "application/json"

// IEIs of the REGISTRATION REQUEST IEs that TS 29.518 transfers as Bytes
// "starting from octet 1" (octet 1 = IEI, octet 2 = length).
// Ref: TS 24.501 Table 8.2.6.1.1, Figure 9.11.3.1.1, Figure 9.11.3.54.1; TS 29.518 §6.1.6.3.2.
const (
	iei5GMMCapability       = 0x10
	ieiUESecurityCapability = 0x2E
)

// errUnsupportedMediaType marks a request body whose Content-Type the operation
// does not define; answered with 415 (TS 29.500 §5.2.7.2).
var errUnsupportedMediaType = errors.New("amf: sbi: unsupported request media type")

// specLiteral reports whether the rel19 (spec-literal) profile is active.
func (s *Server) specLiteral() bool { return features.SpecLiteral(s.profile) }

// decodeBody decodes the JSON content of a Namf request into v.
//
// rel17 / no profile (frozen): plain JSON decode, whatever the Content-Type.
// rel19: application/json (or no Content-Type) is decoded as JSON; when the
// operation defines multipart/related (related, e.g. UEContextTransfer with the
// binary regRequest part, N1N2MessageTransfer with N1/N2 parts) its root part,
// which must be JSON, is decoded and the binary parts are not used; any other
// media type is errUnsupportedMediaType.
// Ref: TS 29.500 §5.2.7.2, §5.4; TS29518_Namf_Communication.yaml requestBody content.
func (s *Server) decodeBody(r *http.Request, related bool, v any) error {
	if !s.specLiteral() {
		return json.NewDecoder(r.Body).Decode(v)
	}
	ct := r.Header.Get("Content-Type")
	switch {
	case ct == "" || isJSONMediaType(ct):
		return json.NewDecoder(r.Body).Decode(v)
	case related && sharedsbi.IsRelated(ct):
		parts, err := sharedsbi.DecodeRelated(ct, r.Body)
		if err != nil {
			return fmt.Errorf("amf: sbi: decode multipart body: %w", err)
		}
		if len(parts) == 0 || !isJSONMediaType(parts[0].ContentType) {
			return errors.New("amf: sbi: multipart body without a JSON root part")
		}
		return json.Unmarshal(parts[0].Body, v)
	default:
		return fmt.Errorf("%w: %q", errUnsupportedMediaType, ct)
	}
}

// isJSONMediaType reports whether ct is application/json (parameters allowed).
func isJSONMediaType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == mediaTypeJSON
}

// rejectBody answers a request whose content could not be decoded: 415 for a
// media type the operation does not define (rel19 only), else 400 with the
// legacy MANDATORY_IE_MISSING (rel17, frozen) or INVALID_MSG_FORMAT (rel19,
// "the HTTP request has an invalid format"). what names the body in the log.
// Ref: TS 29.500 §5.2.7.2, Table 5.2.7.2-1.
func (s *Server) rejectBody(w http.ResponseWriter, log *slog.Logger, err error, what, procedure string) {
	status, cause, detail := http.StatusBadRequest, CauseMandatoryIEMissing, "invalid JSON body"
	switch {
	case errors.Is(err, errUnsupportedMediaType):
		// No application error is defined for 415: the status says it all.
		status, cause, detail = http.StatusUnsupportedMediaType, "", "unsupported request media type"
	case s.specLiteral():
		cause = CauseInvalidMsgFormat
	}
	args := []any{"result", "REJECT", "http_status", status, "error", err}
	if cause != "" {
		args = append(args, "cause", cause)
	}
	log.Warn("malformed "+what+" body", args...)
	s.problem(w, status, cause, detail)
	metrics.ProcedureTotal.WithLabelValues(nfName, procedure, "REJECT").Inc()
}

// rejectIE answers a missing or incorrect IE with 400 and cause. Under rel19
// the ProblemDetails carries invalidParams naming the IE (TS 29.500 Table
// 5.2.7.2-1 NOTE 1: "shall be included"); rel17 keeps the frozen body.
func (s *Server) rejectIE(w http.ResponseWriter, log *slog.Logger, cause, detail, param, procedure string) {
	log.Warn(procedure+" request rejected", "result", "REJECT", "cause", cause, "invalid_param", param)
	if s.specLiteral() {
		s.problemParams(w, http.StatusBadRequest, cause, detail, []InvalidParam{{Param: param, Reason: detail}})
	} else {
		s.problem(w, http.StatusBadRequest, cause, detail)
	}
	metrics.ProcedureTotal.WithLabelValues(nfName, procedure, "REJECT").Inc()
}

// accessTypeProblem validates the mandatory UeContextTransferReqData.accessType
// (rel19): absent is MANDATORY_IE_MISSING, a value outside the closed
// AccessType enumeration MANDATORY_IE_INCORRECT. ok is true when it is valid.
// Ref: TS 29.518 Table 6.1.6.2.23-1; TS 29.571 §5.4.3.1; TS 29.500 Table 5.2.7.2-1.
func accessTypeProblem(accessType string) (cause, detail string, ok bool) {
	switch accessType {
	case AccessType3GPP, AccessTypeNon3GPP:
		return "", "", true
	case "":
		return CauseMandatoryIEMissing, "accessType is mandatory", false
	default:
		return CauseMandatoryIEIncorrect, "accessType must be 3GPP_ACCESS or NON_3GPP_ACCESS", false
	}
}

// n1n2MessageLocation is the mandatory Location header of a 202 N1N2MessageTransfer
// answer: the URI of the n1N2Message resource created in the AMF. It only lets the
// consumer correlate a later N1N2TransferFailureNotification; the consumer shall
// not send requests to it, so the resource is not served.
// Ref: TS 29.518 §5.2.2.3.1.2, Table 6.1.3.5.3.1-3.
func n1n2MessageLocation(r *http.Request, ueContextID string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/namf-comm/v1/ue-contexts/%s/n1-n2-messages/%s",
		scheme, r.Host, url.PathEscape(ueContextID), uuid.NewString())
}

// nasIEFromOctet1 returns a TLV NAS IE from octet 1 (IEI, length, value), the
// form TS 29.518 uses for its NAS-derived Bytes types. ok is false when value
// is empty or longer than a one-octet length can express.
// Ref: TS 29.518 §6.1.6.3.2; TS 24.501 §9.11.3.1, §9.11.3.54.
func nasIEFromOctet1(iei byte, value []byte) (ie []byte, ok bool) {
	if len(value) == 0 || len(value) > 0xFF {
		return nil, false
	}
	ie = make([]byte, 0, 2+len(value))
	ie = append(ie, iei, byte(len(value)))
	return append(ie, value...), true
}

// locStatus returns the ProvideLocationInfo failure status and cause: the
// legacy pair under rel17 (frozen) and, under rel19, a Namf_Location
// application error (TS 29.518 Table 6.4.7.3-1) or a common one (TS 29.500
// Table 5.2.7.2-1). The legacy LOCATION_FAILURE / UE_NOT_REACHABLE causes are
// defined in neither table.
func (s *Server) locStatus(legacyStatus int, legacyCause string, specStatus int, specCause string) (int, string) {
	if s.specLiteral() {
		return specStatus, specCause
	}
	return legacyStatus, legacyCause
}

// provideNPLIWithoutLocation answers a rel19 ProvideLocationInfo that does not
// request the 5GS location (req5gsLoc absent or false): no paging and no NG-RAN
// location reporting. Only the RAT type is returned, when requested (NR: the
// AMF serves 3GPP access over NG-RAN only); the AMF keeps no UE time zone, so
// reqTimeZone yields nothing (timezone is optional).
// Ref: TS 29.518 §5.5.2.4.1 step 2a, Table 6.4.6.2.5-1, Table 6.4.6.2.6-1.
func (s *Server) provideNPLIWithoutLocation(w http.ResponseWriter, log *slog.Logger, req RequestLocInfo) {
	var rsp ProvideLocInfo
	if req.ReqRatType {
		rsp.RatType = ratTypeNR
	}
	w.Header().Set("Content-Type", mediaTypeJSON)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rsp)
	log.Info("ProvideLocationInfo complete without 5GS location (not requested)",
		"req_rat_type", req.ReqRatType, "req_time_zone", req.ReqTimeZone,
		"result", "OK", "spec_ref", "TS 29.518 §5.5.2.4.1")
	metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "OK").Inc()
}

// nasCount returns the NAS COUNT for MmContext: always under rel19 ("shall be
// present if available", TS 29.518 Table 6.1.6.2.34-1); under rel17 a zero
// count stays omitted as in the frozen baseline.
func nasCount(v uint32, spec bool) *uint32 {
	if v == 0 && !spec {
		return nil
	}
	return &v
}

// ptr returns a pointer to v (optional JSON members that may be false or 0).
func ptr[T any](v T) *T { return &v }
