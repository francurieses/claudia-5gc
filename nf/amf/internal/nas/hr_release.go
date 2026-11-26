package nasmsg

// hr_release.go - UE-initiated release of a home-routed PDU session: the V-SMF
// (not the AMF) builds the PDU SESSION RELEASE COMMAND and drives the H-SMF
// release. Ref: TS 23.502 §4.3.4.3 step 1a, §4.3.4.2 steps 1a, 3-7;
// TS 29.502 §5.2.2.3.

import (
	"context"
	"errors"
	"fmt"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// hrReleaseUpdateTimeout bounds the HR Nsmf_PDUSession_UpdateSMContext (UE
// release request) to the V-SMF. The V-SMF bounds its whole UE-release handling
// (including the H-SMF leg) to 7 s, so this must exceed that budget: the AMF
// then receives the V-SMF's answer (or its error) instead of timing out first
// and building a second, competing release. It stays below the 10 s
// releaseSMContextTimeout of the delete path. Ref: TS 29.502 §5.2.2.3.
const hrReleaseUpdateTimeout = 9 * time.Second

// maxReleaseCommandLen caps the V-SMF's 5GSM PDU SESSION RELEASE COMMAND. A real
// command is a handful of bytes plus small optional IEs; anything larger is
// treated as invalid (the AMF-built release is used). Ref: TS 24.501 §8.3.14.
const maxReleaseCommandLen = 4096

// hrReleaseFallbackResult is the fivegc_procedure_total result label counting
// fallbacks from the V-SMF-built to the AMF-built release.
const hrReleaseFallbackResult = "FALLBACK"

// releaseHomeRouted forwards the UE's PDU SESSION RELEASE REQUEST to the V-SMF
// (Nsmf_PDUSession_UpdateSMContext), relays the V-SMF's Release Command to the
// UE and arms the shared completion mechanism (Release Complete or T3592
// guard -> DeleteSMContext). It returns false, having sent nothing to the UE,
// when the caller must fall back to the AMF-built release.
func (h *Handler) releaseHomeRouted(ctx context.Context, ue *amfctx.UEContext, psi, pti uint8, smRef string, n1SmMsg []byte) bool {
	log := h.logger.With(
		"nf", "AMF",
		"procedure", "PDUSessionRelease",
		"amf_ue_ngap_id", ue.AMFUENGAPId,
		"supi", ue.SUPI,
		"pdu_session_id", psi,
	)
	if _, inFlight := h.pendingRelease.Load(pendingReleaseKey(ue.AMFUENGAPId, psi)); inFlight {
		log.Info("PDU Session Release already in progress - ignoring repeated request",
			"interface", "N1", "direction", "IN", "spec_ref", "TS 24.501 §6.3.3", "result", "OK")
		return true
	}
	smfModify, ok := h.sender.(interface {
		ModifySMContext(ctx context.Context, smContextRef string, n1SmMsg []byte, pduSessionID uint8) (n1SmResp []byte, n2SmInfo []byte, err error)
	})
	if !ok || smRef == "" || len(n1SmMsg) == 0 {
		log.Warn("home-routed release: V-SMF forwarding unavailable - AMF-built release",
			"spec_ref", "TS 23.502 §4.3.4.3 step 1a")
		metrics.ProcedureTotal.WithLabelValues("AMF", "PDUSessionRelease", hrReleaseFallbackResult).Inc()
		return false
	}

	callCtx, cancel := context.WithTimeout(ctx, hrReleaseUpdateTimeout)
	defer cancel()
	log.Info("Nsmf_PDUSession_UpdateSMContext (UE release request) sent to V-SMF",
		"interface", "Nsmf", "direction", "OUT",
		"spec_ref", "TS 23.502 §4.3.4.3 step 1a", "smContextRef", smRef)
	cmd, _, err := smfModify.ModifySMContext(callCtx, smRef, n1SmMsg, psi)
	if err == nil {
		err = validateReleaseCommand(cmd, psi, pti)
	}
	if err != nil {
		log.Warn("home-routed release: V-SMF did not return a valid Release Command - AMF-built release",
			"interface", "Nsmf", "direction", "IN", "result", "FAILURE", "error", err,
			"spec_ref", "TS 29.502 §5.2.2.3")
		metrics.ProcedureTotal.WithLabelValues("AMF", "PDUSessionRelease", hrReleaseFallbackResult).Inc()
		return false
	}

	id := psi
	ue.LockDLNAS()
	nasPDU, err := h.sendNASSecured(ue, nas.PDMobilityManagement, nas.MsgTypeDLNASTransport,
		&nas.DLNASTransport{
			PayloadContainerType: nas.PayloadContainerTypeN1SM,
			PayloadContainer:     cmd,
			PDUSessionID:         &id,
		})
	if err != nil {
		ue.UnlockDLNAS()
		log.Warn("home-routed release: encode DL NAS Transport failed - AMF-built release", "error", err)
		metrics.ProcedureTotal.WithLabelValues("AMF", "PDUSessionRelease", hrReleaseFallbackResult).Inc()
		return false
	}
	sendErr := h.sender.SendPDUSessionResourceReleaseCommand(ue, psi, nasPDU)
	ue.UnlockDLNAS()
	if sendErr != nil {
		// The command may be on the wire: do not release a second time.
		log.Error("SendPDUSessionResourceReleaseCommand failed", "error", sendErr,
			"interface", "N2", "direction", "OUT", "spec_ref", "TS 38.413 §8.2.2", "result", "FAILURE")
		h.armReleaseGuard(ctx, ue, psi, smRef, log)
		return true
	}

	// Step 7: the SM context is deleted after Release Complete or the T3592 guard.
	h.armReleaseGuard(ctx, ue, psi, smRef, log)
	log.Info("PDU Session Release Command (from V-SMF) sent",
		"interface", "N2", "direction", "OUT",
		"spec_ref", "TS 38.413 §8.2.2; TS 23.502 §4.3.4.3", "result", "OK")
	return true
}

// validateReleaseCommand checks the V-SMF's 5GSM PDU SESSION RELEASE COMMAND:
// EPD 0x2E | PSI | PTI | 0xD3 | cause. Ref: TS 24.501 §8.3.14.
func validateReleaseCommand(cmd []byte, psi, pti uint8) error {
	switch {
	case len(cmd) == 0:
		return errors.New("empty n1SmMsg")
	case len(cmd) > maxReleaseCommandLen:
		return fmt.Errorf("n1SmMsg too long (%d bytes, max %d)", len(cmd), maxReleaseCommandLen)
	case len(cmd) < 5:
		return fmt.Errorf("n1SmMsg too short (%d bytes)", len(cmd))
	case cmd[0] != nas.PDGroupSessionManagement:
		return fmt.Errorf("unexpected EPD 0x%02X", cmd[0])
	case cmd[3] != byte(nas.MsgTypePDUSessionReleaseCommand):
		return fmt.Errorf("unexpected message type 0x%02X", cmd[3])
	case cmd[1] != psi:
		return fmt.Errorf("PSI %d does not match %d", cmd[1], psi)
	case cmd[2] != pti:
		return fmt.Errorf("PTI %d does not match %d", cmd[2], pti)
	}
	return nil
}
