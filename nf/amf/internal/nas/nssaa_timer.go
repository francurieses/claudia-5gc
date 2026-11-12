package nasmsg

// nssaa_timer.go - T3575 supervision of the NETWORK SLICE-SPECIFIC
// AUTHENTICATION COMMAND (rel19 only) and the PENDING-slice retry trigger.
//
// State machine per UE (one slice in progress at a time):
//
//	COMMAND sent, T3575 started (15 s)
//	  | COMPLETE received      -> T3575 stopped; relay to NSSAAF; next COMMAND
//	  |                          (T3575 restarted) or RESULT (no timer)
//	  | T3575 expiry 1..4      -> COMMAND retransmitted, T3575 restarted
//	  | T3575 expiry 5         -> procedure completed as a failure for the S-NSSAI:
//	                             exchange stopped, no RESULT, slice rejected (never
//	                             retried), next queued slice started
//
// Concurrency: every NSSAA state change runs on the UE's serial queue
// (UEContext.EnqueueSerial), like all other NAS work of the UE. The timer
// callback only posts the expiry work to that queue, so it can never race the
// registration path (SplitPendingNSSAA), a COMPLETE (which holds the queue
// across the Nnssaaf call) or the DL NAS COUNT. The timer state lives on the
// UE context (stopped by Remove / re-registration), not in handler-wide maps.
//
// Ref: TS 24.501 §5.4.7.2.1, §5.4.7.2.2, §5.4.7.2.3 a), §10.2 (Table 10.2.2)

import (
	"context"
	"errors"
	"log/slog"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	// NSSAAT3575Duration is the value of timer T3575, started per S-NSSAI when the
	// NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND is sent (15 s; 60 s in
	// WB-N1/CE mode and 27 s via satellite NG-RAN are not modelled).
	// Ref: TS 24.501 §10.2 Table 10.2.2 (T3575), §5.4.7.2.1
	NSSAAT3575Duration = 15 * time.Second

	// NSSAAT3575MaxRetransmissions is the number of COMMAND retransmissions: the
	// first four T3575 expiries retransmit, the fifth aborts the procedure for the
	// S-NSSAI. Ref: TS 24.501 §5.4.7.2.3 a)
	NSSAAT3575MaxRetransmissions = 4
)

// NSSAAPersistTimeout bounds the PersistUE of the timer path, which has no
// request context. Implementation bound, not a 3GPP value.
const NSSAAPersistTimeout = 5 * time.Second

// errNSSAAT3575Expiry is the cause recorded when the fifth T3575 expiry aborts
// the exchange.
var errNSSAAT3575Expiry = errors.New("amf: nssaa: T3575 expired, no COMPLETE from the UE")

// nssaaStopper is the stop handle of a scheduled timer (time.Timer or a fake).
type nssaaStopper = amfctx.NSSAATimerStopper

// armNSSAAT3575 (re)starts T3575 for cmd. Called on the UE's serial queue. A
// no-op under the rel17 profile, which has no T3575 supervision (frozen
// behaviour). The timer goroutine only enqueues the expiry on the serial queue.
func (h *Handler) armNSSAAT3575(ue *amfctx.UEContext, cmd *nas.NSSAAuthCommand, expiries int) {
	if !h.reg.NSSAASpecLiteral() {
		return
	}
	ue.ArmNSSAATimer(cmd, expiries, func(gen uint64) nssaaStopper {
		return h.scheduleTimer(NSSAAT3575Duration, func() {
			ue.EnqueueSerial(func() { h.onNSSAAT3575Expiry(ue, gen) })
		})
	})
}

// stopNSSAAT3575 stops T3575 (COMPLETE received, exchange resolved). The
// generation is bumped so an expiry already queued is ignored.
func (h *Handler) stopNSSAAT3575(ue *amfctx.UEContext) { ue.StopNSSAATimer() }

// sendNSSAACommand sends a COMMAND on N1 and starts T3575. Called on the UE's
// serial queue. expiries carries the expiry count over a retransmission.
func (h *Handler) sendNSSAACommand(ue *amfctx.UEContext, cmd *nas.NSSAAuthCommand, expiries int) {
	if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
		nas.MsgTypeNetworkSliceSpecificAuthCommand, cmd); err != nil {
		h.logger.Warn("NSSAA COMMAND send failed",
			"procedure", "NSSAA", "supi", ue.SUPI, "error", err,
			"spec_ref", "TS 24.501 §8.2.31")
	}
	h.armNSSAAT3575(ue, cmd, expiries)
}

// onNSSAAT3575Expiry is the T3575 expiry work; it runs on the UE's serial queue.
// Ref: TS 24.501 §5.4.7.2.3 a)
func (h *Handler) onNSSAAT3575Expiry(ue *amfctx.UEContext, gen uint64) {
	cur, expiries, ok := ue.NSSAATimerCurrent(gen)
	if !ok {
		return // stopped or replaced while the expiry waited in the queue
	}
	cmd, _ := cur.(*nas.NSSAAuthCommand)
	log := h.logger.With("procedure", "NSSAA", "supi", ue.SUPI,
		"interface", "N1", "direction", "OUT", "timer", "T3575",
		"spec_ref", "TS 24.501 §5.4.7.2.3 a)")
	slice := ue.NSSAAInProgress
	if cmd == nil || slice == nil || ue.State != amfctx.GMMRegistered ||
		slice.SST != cmd.SNSSAI.SST || nas.SDFromString(slice.SD) != cmd.SNSSAI.SD {
		ue.StopNSSAATimer()
		return // exchange no longer exists (re-registration, de-registration)
	}
	expiries++
	if expiries <= NSSAAT3575MaxRetransmissions {
		log.Info("T3575 expired - NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND retransmitted",
			"sst", slice.SST, "sd", slice.SD, "expiry", expiries,
			"message_type", "NetworkSliceSpecificAuthCommand")
		h.sendNSSAACommand(ue, cmd, expiries)
		return
	}
	log.Warn("T3575 expired for the fifth time - NSSAA completed as a failure, slice rejected",
		"sst", slice.SST, "sd", slice.SD, "expiry", expiries, "result", "REJECT")
	ue.StopNSSAATimer()
	out := h.reg.AbortNSSAA(ue, errNSSAAT3575Expiry)
	if out != nil {
		if out.NextCommand != nil {
			h.sendNSSAACommand(ue, out.NextCommand, 0)
		} else {
			h.finishNSSAA(context.Background(), ue, out)
		}
	}
	pctx, cancel := context.WithTimeout(context.Background(), NSSAAPersistTimeout)
	defer cancel()
	h.reg.PersistUE(pctx, ue)
}

// retryPendingNSSAA re-initiates NSSAA for slices left PENDING by an earlier
// attempt (rel19), at most once per procedures.NSSAAPendingRetryMinInterval per
// slice. Called on the UE's serial queue after a UE-initiated mobility/periodic registration
// update or service request, which do not recompute the Allowed NSSAI; a full
// registration re-queues them in the registration path. No-op under rel17.
// Ref: TS 23.502 §4.2.9.2 (no retry timer is defined: UE-initiated trigger)
func (h *Handler) retryPendingNSSAA(ctx context.Context, ue *amfctx.UEContext, trigger string) {
	if !h.reg.NSSAASpecLiteral() {
		return
	}
	if !h.reg.RetryPendingNSSAA(ue) {
		return
	}
	slog.InfoContext(ctx, "NSSAA retry of PENDING slices",
		"nf", "AMF", "procedure", "NSSAA", "supi", ue.SUPI, "trigger", trigger,
		"interface", "N1", "direction", "OUT", "spec_ref", "TS 23.502 §4.2.9.2")
	h.StartNSSAA(ctx, ue)
}
