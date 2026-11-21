package nasmsg

// sm_release_restart.go - network-initiated PDU session release for CM-IDLE UEs
// and for PDU sessions orphaned by an SMF restart (SMF-012). A restart orphan is
// released with 5GSM cause #39 "reactivation requested": a CM-IDLE UE is paged,
// the PDU session is never re-activated at the SMF in the resulting Service
// Request, and the PDU SESSION RELEASE COMMAND follows the Service Accept in a
// ciphered DL NAS Transport (no N2 resource release, TS 23.502 §4.3.4.2 steps
// 6-7 are skipped). Design: docs/procedures/SmfRestartRecovery.md §7.2.
//
// Ref: TS 23.502 §4.3.4.2; TS 24.501 §6.3.3.2, §6.3.3.3, §5.6.1.4.1; TS 23.527 §4.4.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// restartReleasePagingGuard bounds how long a pending #39 release waits for the
// paged UE to send its Service Request. No Rel-19 timer applies (the AMF has no
// T3513 today); the value follows the paging retry budget of the NGAP layer.
// On expiry the PDU session is released locally (TS 24.501 §5.6.1.4: the UE is
// synchronised by the PDU session status IE on its next contact).
// Ref: TS 23.502 §4.3.4.2 step 4; TS 23.502 §4.2.3.3.
const restartReleasePagingGuard = 30 * time.Second

// restartReleaseCauses lists the 5GSM causes the O&M release may use.
// Ref: TS 24.501 §9.11.4.2 (36 regular deactivation, 39 reactivation requested).
var restartReleaseCauses = map[uint8]struct{}{
	nas.Cause5GSMRegularDeactivation:   {},
	nas.Cause5GSMReactivationRequested: {},
}

// ValidReleaseCause reports whether cause is accepted by the O&M PDU session
// release ({36, 39}).
func ValidReleaseCause(cause uint8) bool {
	_, ok := restartReleaseCauses[cause]
	return ok
}

// Errors of the network-initiated PDU session release.
var (
	// ErrPDUSessionNotFound: the PSI is not established for the UE (mgmt 404).
	ErrPDUSessionNotFound = errors.New("nas: pdu session not found")
	// ErrSMContextNotFound: the SMF answered 404 CONTEXT_NOT_FOUND for an SM
	// context reference (the SMF restarted and lost it, or it was released).
	// SMF clients wrap it so callers can use errors.Is.
	ErrSMContextNotFound = errors.New("smf: sm context not found")
)

// Pager triggers an NGAP Paging for a CM-IDLE UE (implemented by the NGAP server).
type Pager interface {
	SendPaging(ue *amfctx.UEContext) error
}

// SetPager wires the NGAP paging trigger used for CM-IDLE #39 releases.
func (h *Handler) SetPager(p Pager) { h.pager = p }

// SetReleaseGuardsForTest overrides the paging guard and the T3592 guard
// durations (0 keeps the default). Never called in production.
func (h *Handler) SetReleaseGuardsForTest(paging, t3592 time.Duration) {
	h.pagingGuardOverride, h.t3592GuardOverride = paging, t3592
}

func (h *Handler) pagingGuard() time.Duration {
	if h.pagingGuardOverride > 0 {
		return h.pagingGuardOverride
	}
	return restartReleasePagingGuard
}

func (h *Handler) releaseGuard() time.Duration {
	if h.t3592GuardOverride > 0 {
		return h.t3592GuardOverride
	}
	return t3592Guard
}

// startPendingSMRelease records psi as pending (cause), arms the paging guard
// and, when page is set, pages the UE. A paging failure is not fatal: the UE
// may still reach the AMF by itself before the guard expires. Returns false
// when a release was already pending.
// Ref: TS 23.502 §4.3.4.2 step 4; TS 38.413 §8.5.
func (h *Handler) startPendingSMRelease(ctx context.Context, ue *amfctx.UEContext, psi, cause uint8, page bool, log *slog.Logger) bool {
	added, first := ue.AddPendingSMReleaseFirst(psi, cause)
	if !added {
		return false
	}
	// One NGAP Paging per paging cycle: later PSIs ride on the first paging.
	page = page && first
	detached := context.WithoutCancel(ctx)
	ue.SetPendingSMReleaseGuard(psi, time.AfterFunc(h.pagingGuard(), func() {
		h.pagingGuardExpired(detached, ue, psi)
	}))
	if page {
		if h.pager == nil {
			metrics.ProcedureTotal.WithLabelValues("AMF", "NetworkPDUSessionRelease", "FAILURE").Inc()
			log.Warn("no Pager wired - UE not paged for pending PDU session release",
				"result", "FAILURE", "cause", "no_pager",
				"spec_ref", "TS 23.502 §4.3.4.2 step 4")
		} else if err := h.pager.SendPaging(ue); err != nil {
			metrics.ProcedureTotal.WithLabelValues("AMF", "NetworkPDUSessionRelease", "FAILURE").Inc()
			log.Warn("paging for pending PDU session release failed - waiting for the paging guard",
				"interface", "N2", "direction", "OUT", "result", "FAILURE", "cause", "paging_failed", "error", err,
				"spec_ref", "TS 38.413 §8.5.1; TS 23.502 §4.3.4.2 step 4")
		} else {
			log.Info("UE paged for pending PDU session release",
				"interface", "N2", "direction", "OUT", "message_type", "Paging",
				"cause", cause, "result", "OK",
				"spec_ref", "TS 23.502 §4.3.4.2 step 4; TS 38.413 §9.2.4.1")
		}
	}
	return true
}

// pagingGuardExpired releases psi locally when the UE never answered paging.
// Ref: TS 24.501 §5.6.1.4 (PDU session status synchronisation on next contact).
func (h *Handler) pagingGuardExpired(ctx context.Context, ue *amfctx.UEContext, psi uint8) {
	if !ue.ClearPendingSMRelease(psi) {
		return // the UE answered (or the context went away) meanwhile
	}
	metrics.ProcedureTotal.WithLabelValues("AMF", "NetworkPDUSessionRelease", "FAILURE").Inc()
	h.logger.Warn("paging guard expired - PDU session released locally",
		"procedure", "NetworkPDUSessionRelease", "nf", "AMF",
		"supi", ue.SUPI, "amf_ue_ngap_id", ue.AMFUENGAPId, "pdu_session_id", psi,
		"result", "FAILURE", "cause", "paging_guard_expired",
		"spec_ref", "TS 23.502 §4.3.4.2 step 4; TS 24.501 §5.6.1.4")
	h.releaseLocally(ctx, ue, psi, "PAGING_GUARD_EXPIRY")
}

// releaseLocally removes psi without any N1/N2 signalling: the SM context is
// released at the SMF (best effort) and the PDU session leaves the UE context.
// It reuses the completion path of the NW release, which makes it idempotent.
func (h *Handler) releaseLocally(ctx context.Context, ue *amfctx.UEContext, psi uint8, reason string) {
	ue.Lock()
	sess, ok := ue.PDUSessions[psi]
	ref := ""
	if ok {
		ref = sess.SMFInstanceID
	}
	ue.Unlock()
	if !ok {
		return
	}
	key := pendingReleaseKey(ue.AMFUENGAPId, psi)
	h.pendingRelease.LoadOrStore(key, &pendingReleaseState{smContextRef: ref})
	h.completeNetworkPDUSessionRelease(ctx, ue, psi, reason)
}

// dropPendingReleases clears the pending and in-flight releases and stops the guards of every NW release in flight for
// of the UE's PDU sessions (de-registration).
func (h *Handler) dropPendingReleases(ue *amfctx.UEContext, psis []uint8) {
	ue.ClearAllPendingSMReleases()
	for _, psi := range psis {
		if v, ok := h.pendingRelease.LoadAndDelete(pendingReleaseKey(ue.AMFUENGAPId, psi)); ok {
			if g := v.(*pendingReleaseState).guard; g != nil {
				g.Stop()
			}
		}
	}
}

// deliverPendingSMReleases runs after the Service Accept (and ICS) has been
// sent: the UE answered paging, so the paging guards stop and one PDU SESSION
// RELEASE COMMAND per pending PSI is queued on the UE serial queue, in a
// ciphered DL NAS Transport (never an N2 resource release), armed with the
// T3592 guard. A PSI that is gone (UE reported it inactive) is dropped.
// Ref: TS 23.502 §4.3.4.2 step 4; TS 24.501 §6.3.3.2, §8.3.14.
func (h *Handler) deliverPendingSMReleases(ctx context.Context, ue *amfctx.UEContext) {
	pending := ue.PendingSMReleases()
	if len(pending) == 0 {
		return
	}
	ue.StopPendingSMReleaseGuards()
	detached := context.WithoutCancel(ctx)
	for _, p := range pending {
		p := p
		ue.EnqueueSerial(func() { h.sendQueuedRelease(detached, ue, p) })
	}
}

func (h *Handler) sendQueuedRelease(ctx context.Context, ue *amfctx.UEContext, p amfctx.PendingSMRelease) {
	log := h.logger.With(
		"nf", "AMF", "procedure", "NetworkPDUSessionRelease",
		"amf_ue_ngap_id", ue.AMFUENGAPId, "supi", ue.SUPI, "pdu_session_id", p.PSI,
		"interface", "N1", "direction", "OUT", "cause", p.Cause,
		"spec_ref", "TS 23.502 §4.3.4.2 step 4; TS 24.501 §6.3.3.2")
	ue.Lock()
	sess, ok := ue.PDUSessions[p.PSI]
	ue.Unlock()
	if !ok {
		ue.ClearPendingSMRelease(p.PSI) // released meanwhile (UE-reported inactive)
		return
	}
	// Claim the in-flight slot atomically before sending: two paths must never
	// both send a Release Command for the same PSI.
	if !h.armReleaseGuard(ctx, ue, p.PSI, sess.SMFInstanceID, log) {
		ue.ClearPendingSMRelease(p.PSI)
		return
	}
	ue.LockDLNAS() // COUNT allocation + encode + send atomic per UE
	nasPDU, err := h.buildReleaseCommandPDU(ue, p.PSI, p.Cause)
	if err == nil {
		err = h.sender.SendDownlinkNASTransport(ue, nasPDU)
	}
	ue.UnlockDLNAS()
	if err != nil {
		log.Warn("PDU SESSION RELEASE COMMAND not delivered - releasing locally",
			"result", "FAILURE", "error", err)
		ue.ClearPendingSMRelease(p.PSI)
		if v, ok := h.pendingRelease.LoadAndDelete(pendingReleaseKey(ue.AMFUENGAPId, p.PSI)); ok {
			if g := v.(*pendingReleaseState).guard; g != nil {
				g.Stop() // undo the claim; releaseLocally re-registers its own
			}
		}
		h.releaseLocally(ctx, ue, p.PSI, "RELEASE_COMMAND_SEND_FAILED")
		return
	}
	ue.ClearPendingSMRelease(p.PSI) // the pendingRelease entry now owns idempotency
	log.Info("PDU SESSION RELEASE COMMAND sent after Service Accept",
		"message_type", "DLNASTransport", "result", "OK")
}

// buildReleaseCommandPDU builds the ciphered DL NAS Transport carrying the
// PDU SESSION RELEASE COMMAND (PTI 0, cause value only, no IEI).
// Ref: TS 24.501 §8.3.14, §8.2.11.
func (h *Handler) buildReleaseCommandPDU(ue *amfctx.UEContext, psi, cause uint8) ([]byte, error) {
	const nwPTI uint8 = 0 // TS 24.501 §6.3.3.2: not UE-triggered
	cmd := nas.WrapPDUSessionReleaseCommandBody(psi, nwPTI, cause)
	id := psi
	pdu, err := h.sendNASSecured(ue, nas.PDMobilityManagement, nas.MsgTypeDLNASTransport,
		&nas.DLNASTransport{
			PayloadContainerType: nas.PayloadContainerTypeN1SM,
			PayloadContainer:     cmd,
			PDUSessionID:         &id,
		})
	if err != nil {
		return nil, fmt.Errorf("nas: NW PDU release: encode DL NAS Transport: %w", err)
	}
	return pdu, nil
}

// armReleaseGuard registers the in-flight release and its T3592 guard; expiry
// completes it (SM context release + local removal). It claims the slot with
// LoadOrStore and returns false (nothing armed) when a release is already in
// flight for the PSI.
// Ref: TS 24.501 §10.3 (T3592), TS 23.502 §4.3.4.2.
func (h *Handler) armReleaseGuard(ctx context.Context, ue *amfctx.UEContext, psi uint8, smRef string, log *slog.Logger) bool {
	detached := context.WithoutCancel(ctx)
	st := &pendingReleaseState{smContextRef: smRef}
	st.guard = time.AfterFunc(h.releaseGuard(), func() {
		log.Warn("PDU Session Release Complete not received before T3592 - releasing SM context anyway",
			"spec_ref", "TS 24.501 §10.3")
		h.completeNetworkPDUSessionRelease(detached, ue, psi, "T3592_EXPIRY")
	})
	if _, loaded := h.pendingRelease.LoadOrStore(pendingReleaseKey(ue.AMFUENGAPId, psi), st); loaded {
		st.guard.Stop()
		return false
	}
	return true
}
