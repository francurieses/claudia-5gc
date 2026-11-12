package nasmsg

// dereg_timer.go - T3522 supervision of the network-initiated DEREGISTRATION
// REQUEST (rel19 only; the rel17 profile has no T3522, frozen behaviour) and the
// timer scheduler seam shared with T3575 (nssaa_timer.go).
//
// State machine per UE:
//
//	DEREGISTRATION REQUEST sent, T3522 started (6 s), 5GMM-DEREGISTERED-INITIATED
//	  | DEREGISTRATION ACCEPT   -> T3522 stopped, teardown (handleNWDeregistrationAccept)
//	  | REGISTRATION REQUEST    -> T3522 stopped, registration progresses (§5.5.2.3.5 d/e)
//	  | T3522 expiry 1..4       -> REQUEST retransmitted, T3522 restarted
//	  | T3522 expiry 5          -> procedure aborted: local de-registration (the same
//	                               teardown as on ACCEPT), UE -> 5GMM-DEREGISTERED
//
// Concurrency: the timer state lives on the UE context (UEContext.ArmDeregTimer,
// like T3575); the timer goroutine only enqueues the expiry on the UE's serial
// queue (UEContext.EnqueueSerial), so it never races the NAS work of the UE.
//
// Ref: TS 24.501 §5.5.2.3.1, §5.5.2.3.5 a), §10.2 Table 10.2.2 (T3522)

import (
	"context"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	// NWDeregT3522Duration is the value of timer T3522, started when the network
	// sends the DEREGISTRATION REQUEST (6 s; the WB-N1/CE 24 s and satellite 11 s
	// variants are not modelled). Ref: TS 24.501 §10.2 Table 10.2.2 (T3522)
	NWDeregT3522Duration = 6 * time.Second

	// NWDeregT3522MaxRetransmissions is the number of DEREGISTRATION REQUEST
	// retransmissions: the first four T3522 expiries retransmit, the fifth aborts
	// the de-registration. Ref: TS 24.501 §5.5.2.3.5 a)
	NWDeregT3522MaxRetransmissions = 4

	// NWDeregAbortTimeout bounds the local teardown run by the fifth T3522
	// expiry, which has no request context. Implementation bound, not a 3GPP value.
	NWDeregAbortTimeout = 30 * time.Second
)

// TimerScheduler runs f after d and returns the stop handle; time.AfterFunc is
// the production implementation.
type TimerScheduler func(d time.Duration, f func()) amfctx.TimerStopper

// SetTimerSchedulerForTest replaces the scheduler of the supervision timers T3575
// and T3522 (nil restores time.AfterFunc). TEST SEAM: production code must not
// call it (the handler is wired once at start-up). It exists so that the
// integration test in cmd/amf, which owns the SBI client the NAS handler needs,
// can fire the timers deterministically without reflection. Call it before the
// handler serves traffic: the field is not synchronised.
func (h *Handler) SetTimerSchedulerForTest(s TimerScheduler) {
	if s == nil {
		h.timerAfter = nil
		return
	}
	h.timerAfter = s
}

// scheduleTimer runs f after d using the injected scheduler (tests) or
// time.AfterFunc.
func (h *Handler) scheduleTimer(d time.Duration, f func()) amfctx.TimerStopper {
	if h.timerAfter != nil {
		return h.timerAfter(d, f)
	}
	return time.AfterFunc(d, f)
}

// armDeregT3522 (re)starts T3522 for req. Called after a successful send. A
// no-op under the rel17 profile. The timer goroutine only enqueues the expiry.
func (h *Handler) armDeregT3522(ue *amfctx.UEContext, req *nas.DeregistrationRequestNW, expiries int) {
	if !h.reg.NSSAASpecLiteral() {
		return
	}
	ue.ArmDeregTimer(req, expiries, func(gen uint64) amfctx.TimerStopper {
		return h.scheduleTimer(NWDeregT3522Duration, func() {
			ue.EnqueueSerial(func() { h.onDeregT3522Expiry(ue, gen) })
		})
	})
}

// onDeregT3522Expiry is the T3522 expiry work; it runs on the UE's serial queue.
// Expiries 1..4 retransmit the DEREGISTRATION REQUEST and restart T3522; the
// fifth aborts the procedure and de-registers the UE locally (the UE enters
// 5GMM-DEREGISTERED, PDU sessions / UDM / PCF / N2 are released as on ACCEPT). A
// failed retransmission is a lower-layer failure: same abort.
// Ref: TS 24.501 §5.5.2.3.5 a), b)
func (h *Handler) onDeregT3522Expiry(ue *amfctx.UEContext, gen uint64) {
	cur, expiries, ok := ue.DeregTimerCurrent(gen)
	if !ok {
		return // stopped or replaced while the expiry waited in the queue
	}
	req, _ := cur.(*nas.DeregistrationRequestNW)
	log := h.logger.With("procedure", "NetworkDeregistration", "supi", ue.SUPI,
		"amf_ue_ngap_id", ue.AMFUENGAPId, "interface", "N1", "direction", "OUT",
		"timer", "T3522", "spec_ref", "TS 24.501 §5.5.2.3.5 a)")
	if req == nil || ue.State != amfctx.GMMDeregisteredInitiated {
		ue.StopDeregTimer()
		return // the de-registration no longer exists (registration, accept)
	}
	expiries++
	if expiries <= NWDeregT3522MaxRetransmissions {
		if err := h.sendNASSecuredViaDownlink(ue, nas.PDMobilityManagement,
			nas.MsgTypeDeregistrationRequestNW, req); err != nil {
			log.Warn("DEREGISTRATION REQUEST retransmission failed - de-registration aborted",
				"expiry", expiries, "error", err, "result", "FAILURE",
				"spec_ref", "TS 24.501 §5.5.2.3.5 b)")
			h.abortNWDeregistration(ue)
			return
		}
		log.Info("T3522 expired - DEREGISTRATION REQUEST retransmitted",
			"expiry", expiries, "message_type", "DeregistrationRequestNW")
		h.armDeregT3522(ue, req, expiries)
		return
	}
	log.Warn("T3522 expired for the fifth time - de-registration aborted, UE de-registered locally",
		"expiry", expiries, "result", "FAILURE")
	h.abortNWDeregistration(ue)
}

// abortNWDeregistration ends a network-initiated de-registration without the UE's
// ACCEPT: T3522 is stopped and the UE is de-registered locally.
// Ref: TS 24.501 §5.5.2.3.5 a)
func (h *Handler) abortNWDeregistration(ue *amfctx.UEContext) {
	ue.StopDeregTimer()
	ctx, cancel := context.WithTimeout(context.Background(), NWDeregAbortTimeout)
	defer cancel()
	h.completeNWDeregistration(ctx, ue, h.logger.With("procedure", "NetworkDeregistration",
		"supi", ue.SUPI, "amf_ue_ngap_id", ue.AMFUENGAPId, "interface", "N1", "direction", "IN",
		"spec_ref", "TS 24.501 §5.5.2.3.5 a)"))
}
