package mgmt

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"

	"github.com/free5gc/ngap/ngapType"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// anReleaseProcedure is the canonical procedure name for AN Release logs.
	anReleaseProcedure = "ANRelease"
	// anReleaseSpecRef is the spec reference for the AMF-initiated AN Release trigger.
	anReleaseSpecRef = "TS 23.502 §4.2.6 step 2"
	// anReleaseRespSpecRef is the spec_ref echoed in the 202 body.
	anReleaseRespSpecRef = "TS 23.502 §4.2.6 step 2; TS 38.413 §8.3.3"
	// anReleaseCauseLabel is the human-readable NGAP cause used in logs.
	// Ref: TS 38.413 §9.3.1.2 (CauseMisc om-intervention = 3).
	anReleaseCauseLabel = "misc/om-intervention"
	// correlationHeader carries the correlation ID (ULID) on the mgmt API.
	correlationHeader = "X-Correlation-Id"
	// anReleaseNF is the nf label of fivegc_procedure_total for this handler.
	anReleaseNF = "AMF"
)

// UELookup resolves a UE context by SUPI (satisfied by *context.Manager).
type UELookup interface {
	GetBySUPI(supi string) (*amfctx.UEContext, bool)
}

// ANReleaser is the NGAP side needed by the AN release handler (satisfied by
// *ngap.Server).
type ANReleaser interface {
	// HasN2Association reports whether the UE has a serving gNB association.
	HasN2Association(ue *amfctx.UEContext) bool
	// SendUEContextReleaseCommandForUEStrict sends the NGAP UE Context Release
	// Command and returns ngap.ErrNoN2Association if it had to skip the send.
	SendUEContextReleaseCommandForUEStrict(ue *amfctx.UEContext, causePresent int, causeValue int64) error
}

type anReleaseResponse struct {
	Accepted            bool   `json:"accepted"`
	SUPI                string `json:"supi"`
	PreviousCMState     string `json:"previous_cm_state"`
	AffectedPDUSessions []int  `json:"affected_pdu_sessions"`
	SpecRef             string `json:"spec_ref"`
}

// ANReleaseHandler serves POST /amf/v1/ue-contexts/{supi}/an-release: an
// O&M-triggered, AMF-initiated AN Release. It sends an NGAP UE Context Release
// Command with Cause misc/om-intervention; the existing Release Complete path
// moves the UE to CM-IDLE and notifies the SMF (upCnxState DEACTIVATED). The
// UE stays RM-REGISTERED; PendingRemoval is never set. No guard timer is armed
// if the gNB never answers (documented limitation).
// Responses: 202, 404 unknown SUPI, 409 CM-IDLE or deregistration pending,
// 503 no N2 association, 500 send failure.
// Ref: TS 23.502 §4.2.6, TS 38.413 §8.3.3.
func ANReleaseHandler(ues UELookup, rel ANReleaser, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		supi := r.PathValue("supi")
		ctx := logging.WithCorrelationID(r.Context(), r.Header.Get(correlationHeader))
		ctx = logging.WithSUPI(ctx, supi)
		l := logging.NewProcedureLogger(ctx, logger, anReleaseProcedure)
		logReject := func(ue *amfctx.UEContext, code int, reason string) {
			metrics.ProcedureTotal.WithLabelValues(anReleaseNF, anReleaseProcedure, "REJECT").Inc()
			args := []any{
				"interface", "N2", "direction", "OUT",
				"spec_ref", anReleaseSpecRef, "result", "REJECT",
				"cause", anReleaseCauseLabel, "reason", reason, "http_status", code,
			}
			if ue != nil {
				args = append(args, "amf_ue_ngap_id", ue.AMFUENGAPId, "ran_ue_ngap_id", ue.RANUENGAPId)
			}
			l.WarnContext(ctx, "O&M AN release rejected", args...)
		}

		ue, ok := ues.GetBySUPI(supi)
		if !ok {
			logReject(nil, http.StatusNotFound, "ue not found")
			http.Error(w, "UE not found", http.StatusNotFound)
			return
		}

		ue.Lock()
		pending := ue.PendingRemoval
		cm := ue.CMState
		amfID, ranID := ue.AMFUENGAPId, ue.RANUENGAPId
		psis := make([]int, 0, len(ue.PDUSessions))
		for psi := range ue.PDUSessions {
			psis = append(psis, int(psi))
		}
		ue.Unlock()
		sort.Ints(psis)

		if pending {
			logReject(ue, http.StatusConflict, "deregistration pending")
			http.Error(w, "UE deregistration in progress", http.StatusConflict)
			return
		}
		if cm == amfctx.CMIdle {
			logReject(ue, http.StatusConflict, "ue cm-idle")
			http.Error(w, "UE is CM-IDLE", http.StatusConflict)
			return
		}
		if !rel.HasN2Association(ue) {
			logReject(ue, http.StatusServiceUnavailable, "no gnb association")
			http.Error(w, "no gNB association for UE", http.StatusServiceUnavailable)
			return
		}

		// Re-check state immediately before sending: a deregistration or gNB
		// AN release may have interleaved since the snapshot above.
		ue.Lock()
		pending, cm2 := ue.PendingRemoval, ue.CMState
		ue.Unlock()
		if pending {
			logReject(ue, http.StatusConflict, "deregistration pending")
			http.Error(w, "UE deregistration in progress", http.StatusConflict)
			return
		}
		if cm2 == amfctx.CMIdle {
			logReject(ue, http.StatusConflict, "ue cm-idle")
			http.Error(w, "UE is CM-IDLE", http.StatusConflict)
			return
		}

		// The strict variant does the gNB lookup and the send in one call and
		// reports a skipped send, so a 202 is never returned for an unsent command.
		err := rel.SendUEContextReleaseCommandForUEStrict(ue,
			ngapType.CausePresentMisc, int64(ngapType.CauseMiscPresentOmIntervention))
		if errors.Is(err, ngap.ErrNoN2Association) {
			logReject(ue, http.StatusServiceUnavailable, "no gnb association")
			http.Error(w, "no gNB association for UE", http.StatusServiceUnavailable)
			return
		}
		if err != nil {
			metrics.ProcedureTotal.WithLabelValues(anReleaseNF, anReleaseProcedure, "FAILURE").Inc()
			l.ErrorContext(ctx, "O&M AN release send failed",
				"interface", "N2", "direction", "OUT",
				"spec_ref", anReleaseSpecRef, "result", "FAILURE",
				"cause", anReleaseCauseLabel, "error", err,
				"amf_ue_ngap_id", amfID, "ran_ue_ngap_id", ranID)
			http.Error(w, "failed to send UE Context Release Command", http.StatusInternalServerError)
			return
		}

		metrics.ProcedureTotal.WithLabelValues(anReleaseNF, anReleaseProcedure, "OK").Inc()
		l.InfoContext(ctx, "UE Context Release Command sent (O&M AN release)",
			"interface", "N2", "direction", "OUT",
			"message_type", "UEContextReleaseCommand",
			"spec_ref", anReleaseSpecRef, "result", "OK",
			"cause", anReleaseCauseLabel,
			"amf_ue_ngap_id", amfID, "ran_ue_ngap_id", ranID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(anReleaseResponse{
			Accepted:            true,
			SUPI:                supi,
			PreviousCMState:     cm.String(),
			AffectedPDUSessions: psis,
			SpecRef:             anReleaseRespSpecRef,
		})
	})
}

// ANReleaseMethodNotAllowed answers 405 with "Allow: POST" for any method
// other than POST on the AN release path. Registered method-less so it wins
// over the "/amf/v1/ue-contexts/" catch-all for that path.
func ANReleaseMethodNotAllowed() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		metrics.ProcedureTotal.WithLabelValues(anReleaseNF, anReleaseProcedure, "REJECT").Inc()
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
}

// RegisterANRelease wires the AN release routes on mux. The POST pattern is
// more specific than the method-less 405 pattern, which in turn is more
// specific than the catch-all subtree, so Go 1.22+ ServeMux resolves all
// three without conflict.
func RegisterANRelease(mux *http.ServeMux, ues UELookup, rel ANReleaser, logger *slog.Logger) {
	const path = "/amf/v1/ue-contexts/{supi}/an-release"
	mux.Handle("POST "+path, ANReleaseHandler(ues, rel, logger))
	mux.Handle(path, ANReleaseMethodNotAllowed())
}
