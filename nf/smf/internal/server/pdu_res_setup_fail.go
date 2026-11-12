package server

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/free5gc/aper"
)

// handlePduResSetupFail serves n2SmInfoType PDU_RES_SETUP_FAIL: the gNB could not set up the
// PDU session resources (Failed to Setup list of INITIAL CONTEXT SETUP RESPONSE / PDU SESSION
// RESOURCE SETUP RESPONSE, or INITIAL CONTEXT SETUP FAILURE), relayed by the AMF with the
// PDUSessionResourceSetupUnsuccessfulTransfer. The SMF keeps the PDU session with the user plane
// deactivated (Update FAR DROP, State IDLE) and answers 204 No Content; the session is never
// released here. An undecodable transfer is logged and still deactivates. A RELEASING / N4Stale
// session or an already inactive one gets no N4. Unknown context -> 404, RELEASING -> 409.
// Ref: TS 23.502 §4.2.3.2 steps 12-15; TS 29.502 §5.2.2.3.2; TS 38.413 §9.3.4.16.
func (s *Server) handlePduResSetupFail(ctx context.Context, w http.ResponseWriter, base *slog.Logger, smContextRef string, n2SmInfo []byte) {
	log := base.With("procedure", "ServiceRequest", "interface", "Nsmf", "direction", "IN",
		"n2_sm_info_type", n2SmInfoTypePduResSetupFail)
	const specRef = "TS 23.502 §4.2.3.2 steps 12-15; TS 38.413 §9.3.4.16"

	s.sessionMu.Lock()
	sess := s.sessions[smContextRef]
	s.sessionMu.Unlock()
	if sess == nil {
		log.Warn("PDU session resource setup failure: session not found", "result", "REJECT",
			"cause", "CONTEXT_NOT_FOUND", "spec_ref", "TS 29.502 §5.2.2.3.2")
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "sm context not found")
		return
	}
	if s.rejectIfReleasing(w, log, sess, "PDU_RES_SETUP_FAIL", false) {
		return
	}

	var tr ngapType.PDUSessionResourceSetupUnsuccessfulTransfer
	if err := aper.UnmarshalWithParams(n2SmInfo, &tr, "valueExt"); err != nil {
		log.Warn("PDUSessionResourceSetupUnsuccessfulTransfer undecodable (deactivating anyway)",
			"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "result", "OK",
			"cause", "undecodable", "error", err, "spec_ref", specRef)
	} else {
		log.Info("PDU session resource setup failed at gNB (relayed by AMF)",
			"supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID, "result", "OK",
			"cause", ngapCauseValue(tr.Cause), "ngap_cause_group", tr.Cause.Present, "spec_ref", specRef)
	}

	s.sessionMu.Lock()
	skipN4 := sess.State == "IDLE" || sess.N4Stale
	s.sessionMu.Unlock()
	w.WriteHeader(http.StatusNoContent)
	if skipN4 {
		return
	}
	dctx := context.WithoutCancel(ctx)
	s.goHO(func() {
		if _, err := s.pfcpDeactivateDL(dctx, base, "ServiceRequest", sess); err != nil {
			log.WarnContext(dctx, "PDU session UP deactivation after setup failure failed",
				"interface", "N4", "direction", "OUT", "supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID,
				"result", "FAILURE", "error", err, "spec_ref", "TS 23.502 §4.2.3.2 step 12")
			return
		}
		s.sessionMu.Lock()
		if sess.State != sessionStateReleasing {
			sess.State = "IDLE"
		}
		s.sessionMu.Unlock()
		log.InfoContext(dctx, "PDU session UP connection deactivated after setup failure",
			"interface", "N4", "direction", "OUT", "supi", sess.SUPI, "pdu_session_id", sess.PDUSessionID,
			"result", "OK", "spec_ref", "TS 23.502 §4.2.3.2 step 12")
	})
}
