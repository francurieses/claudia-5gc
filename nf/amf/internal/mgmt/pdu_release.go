package mgmt

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// pduReleaseProcedure is the canonical procedure name of the O&M release logs.
	pduReleaseProcedure = "NetworkPDUSessionRelease"
	// pduReleaseSpecRef is the spec reference of the network-initiated release.
	pduReleaseSpecRef = "TS 23.502 §4.3.4.2"
	// pduSessionsSegment separates the SUPI and the PSI in the DELETE path.
	pduSessionsSegment = "/pdu-sessions/"
	// maxPSI is the highest PDU session identity. Ref: TS 24.007 §11.2.3.1b.
	maxPSI = 15
)

// PDUSessionReleaser starts a network-initiated PDU session release (satisfied
// by *nas.Handler).
type PDUSessionReleaser interface {
	InitiateNetworkPDUSessionRelease(ctx context.Context, ue *amfctx.UEContext, psi uint8, cause uint8) error
}

// SplitPDUSessionPath splits the part of the DELETE path after
// "/amf/v1/ue-contexts/" into the SUPI and the PSI text when it has the form
// "{supi}/pdu-sessions/{psi}".
func SplitPDUSessionPath(path string) (supi, psi string, ok bool) {
	i := strings.Index(path, pduSessionsSegment)
	if i <= 0 {
		return "", "", false
	}
	supi, psi = path[:i], path[i+len(pduSessionsSegment):]
	if psi == "" {
		return "", "", false
	}
	return supi, psi, true
}

// ParseReleaseCause parses the optional ?cause= query value: absent = 36
// "regular deactivation", accepted {36, 39}. Ref: TS 24.501 §9.11.4.2.
func ParseReleaseCause(raw string, present bool) (uint8, bool) {
	if !present {
		return nas.Cause5GSMRegularDeactivation, true
	}
	v, err := strconv.ParseUint(raw, 10, 8)
	if err != nil || !nasmsg.ValidReleaseCause(uint8(v)) {
		return 0, false
	}
	return uint8(v), true
}

// HandlePDUSessionRelease serves DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}[?cause=].
// Responses: 202 started or already pending, 400 bad psi/cause, 404 unknown UE
// or PSI, 500 encode/send failure. Anything outliving the request runs on a
// detached context. Ref: TS 23.502 §4.3.4.2; docs/procedures/SmfRestartRecovery.md §4.4.
func HandlePDUSessionRelease(w http.ResponseWriter, r *http.Request, ues UELookup,
	rel PDUSessionReleaser, supi, psiText string, logger *slog.Logger) {

	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get(correlationHeader))
	ctx = logging.WithSUPI(ctx, supi)
	l := logging.NewProcedureLogger(ctx, logger, pduReleaseProcedure)
	reject := func(code int, reason, msg string) {
		metrics.ProcedureTotal.WithLabelValues(anReleaseNF, pduReleaseProcedure, "REJECT").Inc()
		l.WarnContext(ctx, "O&M PDU session release rejected",
			"interface", "Namf-mgmt", "direction", "IN", "spec_ref", pduReleaseSpecRef,
			"result", "REJECT", "reason", reason, "http_status", code, "pdu_session_id", psiText)
		http.Error(w, msg, code)
	}

	psi, err := strconv.ParseUint(psiText, 10, 8)
	if err != nil || psi == 0 || psi > maxPSI {
		reject(http.StatusBadRequest, "invalid pdu session id", "invalid pdu session id")
		return
	}
	rawCause := r.URL.Query().Get("cause")
	cause, ok := ParseReleaseCause(rawCause, r.URL.Query().Has("cause"))
	if !ok {
		reject(http.StatusBadRequest, "unsupported 5gsm cause", "unsupported cause (allowed: 36, 39)")
		return
	}
	ue, found := ues.GetBySUPI(supi)
	if !found {
		reject(http.StatusNotFound, "ue not found", "UE not found")
		return
	}

	detached := context.WithoutCancel(ctx)
	if err := rel.InitiateNetworkPDUSessionRelease(detached, ue, uint8(psi), cause); err != nil {
		if errors.Is(err, nasmsg.ErrPDUSessionNotFound) {
			reject(http.StatusNotFound, "pdu session not found", "PDU session not found")
			return
		}
		metrics.ProcedureTotal.WithLabelValues(anReleaseNF, pduReleaseProcedure, "FAILURE").Inc()
		l.ErrorContext(ctx, "O&M PDU session release failed",
			"interface", "Namf-mgmt", "direction", "OUT", "spec_ref", pduReleaseSpecRef,
			"result", "FAILURE", "pdu_session_id", psi, "cause", cause, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	metrics.ProcedureTotal.WithLabelValues(anReleaseNF, pduReleaseProcedure, "OK").Inc()
	l.InfoContext(ctx, "NW-initiated PDU Session Release triggered",
		"interface", "Namf-mgmt", "direction", "OUT", "spec_ref", pduReleaseSpecRef,
		"result", "OK", "pdu_session_id", psi, "cause", cause)
	w.WriteHeader(http.StatusAccepted)
}
