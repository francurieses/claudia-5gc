package nasmsg

// reg_timer.go - network-side supervision of the registration common procedures:
// T3570 (IDENTITY REQUEST), T3560 (AUTHENTICATION REQUEST, SECURITY MODE COMMAND)
// and T3550 (REGISTRATION ACCEPT carrying a new 5G-GUTI), plus the pending-procedure
// gate that ignores unsolicited / duplicate UE messages.
//
// State machine per UE (one outstanding message at a time, UEContext.regT):
//
//	message sent, timer started (default 6 s, configurable)
//	  | the UE's answer               -> timer stopped, procedure continues
//	  | timer expiry 1..4             -> NAS message retransmitted (a protected one is
//	                                     re-protected with a fresh DL NAS COUNT), timer restarted
//	  | timer expiry 5 (T3560/T3570)  -> procedure aborted, N1 connection released
//	  | timer expiry 5 (T3550)        -> registration aborted, UE enters 5GMM-REGISTERED,
//	                                     context kept (initial and mobility/periodic)
//
// REGISTRATION ACCEPT carrying a new 5G-GUTI: the UE is in
// 5GMM-COMMON-PROCEDURE-INITIATED until the REGISTRATION COMPLETE arrives, then
// 5GMM-REGISTERED.
//
// Concurrency: the timer goroutine only enqueues the expiry on the UE's serial
// queue (UEContext.EnqueueSerial), like T3522/T3575.
//
// Ref: TS 24.501 §5.4.1.3.7 b), §5.4.2.7 b), §5.4.3.6 b), §5.5.1.2.4, §5.5.1.2.8 c),
// §5.5.1.3.8 c), §10.2 Table 10.2.2

import (
	"context"
	"log/slog"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	// RegProcMaxRetransmissions is the number of retransmissions of an IDENTITY
	// REQUEST / AUTHENTICATION REQUEST / SECURITY MODE COMMAND / REGISTRATION ACCEPT:
	// expiries 1..4 retransmit, the fifth aborts. Ref: TS 24.501 §5.4.1.3.7 b),
	// §5.4.2.7 b), §5.4.3.6 b), §5.5.1.2.8 c)
	RegProcMaxRetransmissions = 4

	// regProcAbortTimeout bounds the local cleanup of an aborted registration (the
	// fifth-expiry path has no request context). Implementation bound, not a 3GPP value.
	regProcAbortTimeout = 30 * time.Second

	regTimerT3550 = "T3550"
	regTimerT3560 = "T3560"
	regTimerT3570 = "T3570"
)

// regTimerFor returns the timer name and its effective duration for stage.
func (h *Handler) regTimerFor(stage amfctx.RegStage) (string, time.Duration) {
	v := h.reg.NASTimers()
	switch stage {
	case amfctx.RegStageIdentity:
		return regTimerT3570, v.T3570()
	case amfctx.RegStageAcceptSent:
		return regTimerT3550, v.T3550()
	default: // authentication, security mode
		return regTimerT3560, v.T3560()
	}
}

// armRegTimer (re)starts the supervision of msg with the given expiry count.
func (h *Handler) armRegTimer(ue *amfctx.UEContext, msg *amfctx.RegRetx, expiries int) {
	_, d := h.regTimerFor(msg.Stage)
	ue.ArmRegTimer(msg, expiries,
		func(gen uint64) amfctx.TimerStopper {
			return h.scheduleTimer(d, func() {
				ue.EnqueueSerial(func() { h.onRegTimerExpiry(ue, gen) })
			})
		})
}

// sendRegProc sends the unprotected pdu in DOWNLINK NAS TRANSPORT and, once sent,
// records stage as the pending registration procedure and starts its supervision
// timer. The same bytes are resent on expiry (no security header, no NAS COUNT).
func (h *Handler) sendRegProc(ue *amfctx.UEContext, stage amfctx.RegStage, pdu []byte) error {
	return h.sendRegMsg(ue, pdu, &amfctx.RegRetx{Stage: stage, PDU: pdu})
}

// sendRegProcProtected sends the security protected pdu (the protection of plain
// with sht) and supervises it; every retransmission re-protects plain with a fresh
// downlink NAS COUNT. Ref: TS 24.501 §4.4.3.1
func (h *Handler) sendRegProcProtected(ue *amfctx.UEContext, stage amfctx.RegStage,
	pdu, plain []byte, sht nas.SecurityHeaderType) error {
	return h.sendRegMsg(ue, pdu, &amfctx.RegRetx{Stage: stage, PDU: pdu, Plain: plain, SHT: byte(sht)})
}

func (h *Handler) sendRegMsg(ue *amfctx.UEContext, pdu []byte, msg *amfctx.RegRetx) error {
	if err := h.sender.SendDownlinkNASTransport(ue, pdu); err != nil {
		return err
	}
	ue.SetRegStage(msg.Stage)
	msg.Timer, _ = h.regTimerFor(msg.Stage)
	h.armRegTimer(ue, msg, 0)
	return nil
}

// reprotectRegMsg returns the PDU of a retransmission of msg: a security protected
// message is protected again with the next downlink NAS COUNT, an unprotected one
// is returned unchanged. Ref: TS 24.501 §4.4.3.1
func (h *Handler) reprotectRegMsg(ue *amfctx.UEContext, msg *amfctx.RegRetx) ([]byte, error) {
	if len(msg.Plain) == 0 {
		return msg.PDU, nil
	}
	if nas.SecurityHeaderType(msg.SHT) == nas.SecurityHeaderIntegrityProtectedAndCiphered {
		return h.cipherProtectNAS(ue, msg.Plain)
	}
	return h.integrityProtectNAS(ue, msg.Plain, nas.SecurityHeaderType(msg.SHT))
}

// onRegTimerExpiry runs on the UE's serial queue.
func (h *Handler) onRegTimerExpiry(ue *amfctx.UEContext, gen uint64) {
	msg, expiries, ok := ue.RegTimerCurrent(gen)
	if !ok {
		return // stopped or replaced while the expiry waited in the queue
	}
	log := h.logger.With("nf", "AMF", "procedure", "InitialRegistration",
		"supi", ue.SUPI, "amf_ue_ngap_id", ue.AMFUENGAPId, "interface", "N1",
		"direction", "OUT", "timer", msg.Timer, "stage", msg.Stage.String(),
		"spec_ref", regTimerSpecRef(msg.Stage))
	if got := ue.RegStage(); got != msg.Stage {
		log.Warn("supervision timer expired for a stage that is no longer pending - timer stopped",
			"pending_stage", got.String(), "result", "IGNORED")
		ue.StopRegTimer()
		return
	}
	expiries++
	if expiries <= RegProcMaxRetransmissions {
		pdu, err := h.reprotectRegMsg(ue, msg)
		if err == nil {
			err = h.sender.SendDownlinkNASTransport(ue, pdu)
		}
		if err != nil {
			log.Warn("NAS retransmission failed - registration procedure aborted",
				"expiry", expiries, "error", err, "result", "FAILURE")
			metrics.ProcedureTotal.WithLabelValues("AMF", "InitialRegistration", "FAILURE").Inc()
			h.abortRegProc(ue, log)
			return
		}
		log.Info("supervision timer expired - NAS message retransmitted",
			"expiry", expiries, "result", "RETRANSMIT")
		h.armRegTimer(ue, msg, expiries)
		return
	}
	log.Warn("supervision timer expired for the fifth time - registration procedure aborted",
		"expiry", expiries, "result", "FAILURE")
	metrics.ProcedureTotal.WithLabelValues("AMF", "InitialRegistration", "FAILURE").Inc()
	h.abortRegProc(ue, log)
}

// regTimerSpecRef returns the clause governing the abort of stage.
func regTimerSpecRef(stage amfctx.RegStage) string {
	switch stage {
	case amfctx.RegStageIdentity:
		return "TS 24.501 §5.4.3.6 b)"
	case amfctx.RegStageAuth:
		return "TS 24.501 §5.4.1.3.7 b)"
	case amfctx.RegStageSMC:
		return "TS 24.501 §5.4.2.7 b)"
	default:
		return "TS 24.501 §5.5.1.2.8 c), §5.5.1.3.8 c)"
	}
}

// abortRegProc ends the pending registration procedure after the fifth expiry (or
// a failed retransmission). Identity / authentication / security mode: the N1
// connection is released. REGISTRATION ACCEPT: the registration is aborted and the
// UE enters 5GMM-REGISTERED with its context kept (initial registration, §5.5.1.2.8
// c); mobility / periodic update, §5.5.1.3.8 c)); nothing is rejected or released.
// Ref: TS 24.501 §5.4.1.3.7 b), §5.4.2.7 b), §5.4.3.6 b), §5.5.1.2.8 c), §5.5.1.3.8 c)
func (h *Handler) abortRegProc(ue *amfctx.UEContext, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), regProcAbortTimeout)
	defer cancel()
	stage := ue.RegStage()
	if stage == amfctx.RegStageAcceptSent {
		prior, _ := ue.AbortRegAccept()
		log.Info("registration aborted - UE enters 5GMM-REGISTERED, context kept",
			"prior_registered", prior, "result", "FAILURE")
		return
	}
	// Procedure aborted: a new context that never took effect is dropped, the one
	// in use stays (no-op when none is pending). Ref: TS 24.501 §5.4.2.5, §5.4.2.7 b)
	h.rollbackSecurityCtx(ue, "T3560_abort")
	ue.ClearRegProc()
	ue.Lock()
	registered := ue.State == amfctx.GMMRegistered
	ue.Unlock()
	if registered {
		// authentication of a registered UE aborted: release the N1 connection only
		h.releaseN2(ue, ngapCausePresentNas, ngapCauseNasNormalRelease, false)
		return
	}
	h.releaseAfterReject(ctx, ue, ngapCauseNasNormalRelease)
}
