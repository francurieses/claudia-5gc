package server

// SMF restart recovery (SMF-012, docs/procedures/SmfRestartRecovery.md):
// orphaned PDU sessions of the previous run are released towards the AMF/UE
// with 5GSM cause #39, and CreateSMContext is gated on the first PFCP
// Association Setup of this run.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// procSmfRestartRecovery is the procedure name in logs and metrics.
	procSmfRestartRecovery = "SmfRestartRecovery"
	// specSmfRestart is the restoration clause: SMF restart, PDU sessions released.
	specSmfRestart = "TS 23.527 §4.4.2"
	// specAssocGate cites the PFCP Association Setup that must precede N4 sessions.
	specAssocGate = "TS 29.244 §6.2.6.2.2"
	// causeAlreadyReleased is the log cause of an AMF 404 (nothing left to
	// release; the AMF may also not know the UE at all, which is equivalent).
	causeAlreadyReleased = "ALREADY_RELEASED"
	// causeShutdown is the log cause of an orphan release abandoned because
	// the SMF is shutting down (context cancelled).
	causeShutdown = "SHUTDOWN"

	// amfReleaseCause39 is 5GSM cause #39 "reactivation requested" (TS 24.501
	// §9.11.4.2, §6.3.3.3): the UE re-establishes the PDU session.
	amfReleaseCause39 = nas.Cause5GSMReactivationRequested

	// defaultOrphanReleaseMaxAttempts bounds the AMF release tries per orphan
	// (implementation choice, docs/procedures/SmfRestartRecovery.md §5).
	defaultOrphanReleaseMaxAttempts = 3
	// defaultOrphanReleaseBackoffInitial is the first wait between tries (2 s,
	// then doubled up to defaultOrphanReleaseBackoffMax); no 3GPP value, the
	// release is an internal management call (TS 23.527 §4.4.2 gives no timing).
	defaultOrphanReleaseBackoffInitial = 2 * time.Second
	// defaultOrphanReleaseBackoffMax caps the exponential back-off.
	defaultOrphanReleaseBackoffMax = 8 * time.Second

	// defaultAssocGateTimeout is how long CreateSMContext waits for the first
	// PFCP Association Setup of this run. Implementation choice: long enough for
	// one Association Setup round trip at start-up, short enough for the AMF's
	// SBI timeout (TS 29.244 §6.2.6.2.2: no N4 session before association).
	defaultAssocGateTimeout = 3 * time.Second
)

// orphanReleaseConfig is the retry policy of the orphan release; tests and
// step definitions override it through WithOrphanReleaseRetry.
type orphanReleaseConfig struct {
	maxAttempts    int
	backoffInitial time.Duration
	backoffMax     time.Duration
}

func defaultOrphanReleaseConfig() orphanReleaseConfig {
	return orphanReleaseConfig{
		maxAttempts:    defaultOrphanReleaseMaxAttempts,
		backoffInitial: defaultOrphanReleaseBackoffInitial,
		backoffMax:     defaultOrphanReleaseBackoffMax,
	}
}

// WithOrphanReleaseRetry overrides the orphan release retry policy (tests).
func WithOrphanReleaseRetry(maxAttempts int, backoffInitial, backoffMax time.Duration) Option {
	return func(s *Server) {
		s.orphanRelease = orphanReleaseConfig{maxAttempts: max(maxAttempts, 1),
			backoffInitial: backoffInitial, backoffMax: max(backoffMax, backoffInitial)}
	}
}

// WithAssocGateTimeout overrides the CreateSMContext association gate timeout (tests).
func WithAssocGateTimeout(d time.Duration) Option {
	return func(s *Server) { s.assocGateTimeout = d }
}

// restartOrphan is a PDU session persisted by a previous SMF run.
type restartOrphan struct {
	supi string
	psi  uint8
}

// WaitOrphanRelease blocks until the orphan release goroutine has ended (tests).
func (s *Server) WaitOrphanRelease() { s.orphanWG.Wait() }

// releaseOrphansOfPreviousRun asks the AMF to release, with 5GSM cause #39, the
// PDU sessions this SMF lost by restarting (the UPF drops its side on the
// repeated Association Setup, TS 29.244 §6.2.6.2.2), so the UE re-establishes
// them. It starts once, after the first successful Association Setup, and runs
// on a goroutine bound to ctx (the supervisor context): it never blocks the
// association and ends on shutdown. Ref: TS 23.527 §4.4.2, TS 23.502 §4.3.4.2.
func (s *Server) releaseOrphansOfPreviousRun(ctx context.Context) {
	s.sessionMu.Lock()
	orphans := s.orphanedByRestart
	s.orphanedByRestart = nil
	s.sessionMu.Unlock()
	if len(orphans) == 0 {
		return
	}
	ctx = logging.WithCorrelationID(ctx, ulid.Make().String())
	s.orphanWG.Add(1)
	go func() {
		defer s.orphanWG.Done()
		s.runOrphanRelease(ctx, orphans)
	}()
}

// runOrphanRelease releases every orphan (bounded concurrency) and logs one
// INFO summary.
func (s *Server) runOrphanRelease(ctx context.Context, orphans []restartOrphan) {
	log := logging.NewProcedureLogger(ctx, s.logger, procSmfRestartRecovery)
	var released, already, failed atomic.Int64
	work := make(chan restartOrphan)
	var wg sync.WaitGroup
	for i := 0; i < min(amfReleaseConcurrency, len(orphans)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range work {
				switch s.releaseOrphan(ctx, log, o) {
				case orphanReleased:
					released.Add(1)
				case orphanAlreadyReleased:
					already.Add(1)
				default:
					failed.Add(1)
				}
			}
		}()
	}
feed:
	for _, o := range orphans {
		select {
		case work <- o:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	// Orphans not attempted because of shutdown count as failed.
	failed.Store(int64(len(orphans)) - released.Load() - already.Load())
	result := "OK"
	if failed.Load() > 0 {
		result = "FAILURE"
	}
	log.InfoContext(ctx, "SMF restart: orphaned PDU session release finished",
		"interface", "Namf-mgmt", "direction", "OUT", "spec_ref", specSmfRestart,
		"result", result, "orphans", len(orphans), "released", released.Load(),
		"already_released", already.Load(), "failed", failed.Load())
}

type orphanOutcome int

const (
	orphanFailed orphanOutcome = iota
	orphanReleased
	orphanAlreadyReleased
)

// releaseOrphan releases one orphan with cause #39, retrying transport errors
// and 5xx with exponential back-off up to orphanRelease.maxAttempts tries.
func (s *Server) releaseOrphan(ctx context.Context, log *slog.Logger, o restartOrphan) orphanOutcome {
	cfg := s.orphanRelease
	attrs := []any{"interface", "Namf-mgmt", "direction", "OUT", "spec_ref", specSmfRestart,
		"supi", o.supi, "pdu_session_id", o.psi, "5gsm_cause", amfReleaseCause39}
	backoff := cfg.backoffInitial
	var err error
	for attempt := 1; attempt <= cfg.maxAttempts; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			err = cerr
			break
		}
		var already bool
		already, err = s.amfReleaseCall(ctx, o.supi, o.psi, amfReleaseCause39)
		if err == nil {
			metrics.ProcedureTotal.WithLabelValues("SMF", procSmfRestartRecovery, "OK").Inc()
			if already {
				log.InfoContext(ctx, "SMF restart: orphaned PDU session already released in the AMF",
					append(attrs, "result", "OK", "cause", causeAlreadyReleased)...)
				return orphanAlreadyReleased
			}
			log.InfoContext(ctx, "SMF restart: AMF asked to release orphaned PDU session",
				append(attrs, "result", "OK", "attempt", attempt)...)
			return orphanReleased
		}
		var re *amfReleaseError
		if !errors.As(err, &re) || !re.retryable || attempt == cfg.maxAttempts || ctx.Err() != nil {
			break
		}
		log.WarnContext(ctx, "SMF restart: AMF release of orphaned PDU session failed, retrying",
			append(attrs, "result", "FAILURE", "attempt", attempt, "backoff_ms", backoff.Milliseconds(), "error", err)...)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		backoff = min(backoff*2, cfg.backoffMax)
	}
	metrics.ProcedureTotal.WithLabelValues("SMF", procSmfRestartRecovery, "FAILURE").Inc()
	cause := causeAMFReleaseFailed
	if ctx.Err() != nil {
		cause = causeShutdown
	}
	log.WarnContext(ctx, "SMF restart: AMF release of orphaned PDU session failed",
		append(attrs, "result", "FAILURE", "cause", cause, "error", err)...)
	return orphanFailed
}

// passAssociationGate implements G5: before the first successful PFCP
// Association Setup of this run no PFCP Session Establishment may be sent
// (the UPF would purge it with the previous run's sessions, TS 29.244
// §6.2.6.2.2), so CreateSMContext waits up to assocGateTimeout. On timeout it
// answers an SmContextCreateError carrying a PDU SESSION ESTABLISHMENT REJECT
// with 5GSM cause #26 and returns false. The gate is inactive until the PFCP
// supervisor runs (unit tests without a supervisor) and after the first
// association (later re-association windows keep only the WARN).
func (s *Server) passAssociationGate(ctx context.Context, log *slog.Logger, w http.ResponseWriter, req map[string]interface{}, corrID string) bool {
	if !s.assocGateActive.Load() {
		return true
	}
	select {
	case <-s.firstAssoc:
		return true
	default:
	}
	select { // nudge an immediate Association Setup attempt
	case s.assocKick <- struct{}{}:
	default:
	}
	timer := time.NewTimer(s.assocGateTimeout)
	defer timer.Stop()
	select {
	case <-s.firstAssoc:
		return true
	case <-timer.C:
	case <-ctx.Done():
	}
	psi, _ := req["pduSessionId"].(float64)
	var pti uint8
	if b, err := base64.StdEncoding.DecodeString(strOf(req["n1SmMsg"])); err == nil && len(b) > 2 {
		pti = b[2]
	}
	supi, _ := req["supi"].(string)
	log.Warn("CreateSMContext rejected: no PFCP association with the UPF yet",
		"interface", "Nsmf", "direction", "IN", "spec_ref", specAssocGate, "correlation_id", corrID,
		"supi", supi, "pdu_session_id", uint8(psi), "result", "REJECT",
		"cause", nas.Cause5GSMInsufficientResources, "gate_timeout_ms", s.assocGateTimeout.Milliseconds())
	metrics.ProcedureTotal.WithLabelValues("SMF", procSmfRestartRecovery, "REJECT").Inc()
	n1 := nas.WrapPDUSessionEstablishmentRejectBody(uint8(psi), pti, nas.Cause5GSMInsufficientResources, nil)
	// SmContextCreateError (TS 29.502 §6.1.6.2.4): ProblemDetails + n1SmMsg.
	// Status 500 SYSTEM_FAILURE: the failure is internal and transient (N4 not
	// up), not a request error (4xx) nor a slice-capacity condition (the 403
	// INSUFFICIENT_RESOURCES_SLICE causes of TS 29.502 §6.1.7.3 are slice
	// scoped). [VERIFY: TS 29.502 Table 6.1.3.2.4.2-2 status/cause choice]
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{"status": http.StatusInternalServerError, "cause": "SYSTEM_FAILURE",
			"detail": "PFCP association with the UPF not established yet"},
		"n1SmMsg": base64.StdEncoding.EncodeToString(n1),
	}); err != nil {
		log.Debug("CreateSMContext rejection: response write failed", "interface", "Nsmf", "direction", "OUT",
			"spec_ref", specAssocGate, "correlation_id", corrID, "error", err)
	}
	return false
}

func strOf(v interface{}) string { s, _ := v.(string); return s }
