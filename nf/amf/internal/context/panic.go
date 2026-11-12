// panic.go — panic containment for the AMF's NAS / NGAP processing goroutines.
//
// A bug triggered by one UE's message must cost only that UE's procedure, never
// the AMF process (every UE, every gNB association). The per-UE serial queue
// (EnqueueSerial) and the NGAP SCTP dispatch recover a panic, log it with the
// canonical fields (result=FAILURE, cause=internal_panic), count it in
// fivegc_procedure_total{procedure="PanicRecovery",result="FAILURE"} and, on the
// serial queue, release the affected UE through the Manager's PanicReleaser.
// Programme rule (resilience): nothing may panic the NF on malformed or hostile
// input; no 3GPP clause applies.

package context

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// correlationSUCISuffixLen is the number of trailing SUCI characters used in a
// UE log correlation ID (implementation choice, not a 3GPP value).
const correlationSUCISuffixLen = 8

// PanicRecoveryProcedure is the canonical procedure name of a recovered panic
// in logs and in the fivegc_procedure_total metric.
const PanicRecoveryProcedure = "PanicRecovery"

// PanicRecoveryCause is the cause logged for a recovered panic.
const PanicRecoveryCause = "internal_panic"

// panicReleaseTimeout bounds the release of a UE after a recovered panic on its
// serial queue (implementation limit, not a 3GPP timer).
const panicReleaseTimeout = 5 * time.Second

// PanicReleaser releases a UE whose serial task panicked. remove=true when the
// UE is not 5GMM-REGISTERED (the context must be removed), false when the
// registration is kept and only the N2/RRC connection is released. It returns
// true when a UE CONTEXT RELEASE COMMAND was sent (the release completion then
// finishes the cleanup), false when no N2 association exists.
type PanicReleaser func(ctx context.Context, ue *UEContext, remove bool) (sent bool)

// SetPanicReleaser installs the releaser used after a recovered serial-queue
// panic (wired in cmd/amf to the NAS handler). Nil disables the N2 release; a
// non-registered UE is then still removed locally.
func (m *Manager) SetPanicReleaser(r PanicReleaser) {
	m.mu.Lock()
	m.panicReleaser = r
	m.mu.Unlock()
}

// RecoverPanic must be deferred directly (defer amfctx.RecoverPanic(...)) by a
// NAS / NGAP processing goroutine. On a panic it logs it with the canonical
// fields and counts it; ue may be nil when the affected UE is unknown (NGAP
// dispatch before routing). It does not release any UE.
func RecoverPanic(ctx context.Context, logger *slog.Logger, iface string, ue *UEContext) {
	if r := recover(); r != nil {
		logPanic(ctx, logger, iface, ue, r)
	}
}

// logPanic emits the canonical FAILURE log line and the metric of a recovered panic.
func logPanic(ctx context.Context, logger *slog.Logger, iface string, ue *UEContext, r any) {
	if logger == nil {
		logger = slog.Default()
	}
	fields := []any{
		"nf", "AMF",
		"interface", iface,
		"direction", "IN",
		"result", "FAILURE",
		"cause", PanicRecoveryCause,
		"panic", fmt.Sprint(r),
		"stack", string(debug.Stack()),
		"spec_ref", "resilience: no NF panic on malformed or hostile input",
	}
	if ue != nil {
		fields = append(fields, "amf_ue_ngap_id", ue.AMFUENGAPId, "ran_ue_ngap_id", ue.RANUENGAPId)
		if ue.SUPI != "" {
			fields = append(fields, "supi", ue.SUPI)
		}
	}
	logging.NewProcedureLogger(ctx, logger, PanicRecoveryProcedure).ErrorContext(ctx,
		"panic recovered in NAS/NGAP processing goroutine", fields...)
	metrics.ProcedureTotal.WithLabelValues("AMF", PanicRecoveryProcedure, "FAILURE").Inc()
}

// runSerialTask runs one serial-queue task, containing a panic: it is logged,
// counted and the UE is released, then the drain loop goes on with the next task.
func (u *UEContext) runSerialTask(f func()) {
	defer func() {
		if r := recover(); r != nil {
			u.afterSerialPanic(r)
		}
	}()
	f()
}

// afterSerialPanic logs a recovered serial-task panic and releases the UE: a
// 5GMM-REGISTERED UE keeps its registration (N2 release only, CM-IDLE on the
// release completion); any other UE is removed (through the release completion
// when a release command was sent, locally otherwise).
func (u *UEContext) afterSerialPanic(r any) {
	ctx, cancel := context.WithTimeout(context.Background(), panicReleaseTimeout)
	defer cancel()
	ctx = logging.WithCorrelationID(ctx, u.CorrelationID())
	m := u.mgr
	var logger *slog.Logger
	var release PanicReleaser
	if m != nil {
		logger = m.logger
		m.mu.RLock()
		release = m.panicReleaser
		m.mu.RUnlock()
	}
	logPanic(ctx, logger, "N1", u, r)
	if m == nil {
		return
	}
	// A panic in the release itself is contained too: the drain loop must survive.
	defer func() {
		if r2 := recover(); r2 != nil {
			logPanic(ctx, logger, "N1", u, r2)
		}
	}()
	remove := u.State != GMMRegistered
	sent := release != nil && release(ctx, u, remove)
	if !sent && remove {
		m.Remove(ctx, u)
	}
}
