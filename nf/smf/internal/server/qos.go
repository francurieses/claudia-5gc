// qos.go — QoS subscription fetch (N10), 5QI validation, and the
// /nsmf-management QoS API.
//
// The management endpoints are NOT 3GPP-standardised; they are an internal
// operator API (consumed by the MCP server and the management portal) that
// triggers the standard NW-initiated PDU Session Modification procedure.
//
// 3GPP references:
//   - TS 29.503 §6.1.6.2.7 — SessionManagementSubscriptionData (N10 sm-data)
//   - TS 23.501 §5.7 / Table 5.7.4-1 — 5QI characteristics
//   - TS 23.502 §4.3.3.2 — NW-initiated PDU Session Modification
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// QoS source labels reported by the management API and MCP tools.
const (
	QoSSourcePCFOverride     = "PCF_OVERRIDE"     // per-subscriber override stored in the PCF
	QoSSourceUDMSubscription = "UDM_SUBSCRIPTION" // subscribed default QoS from UDM sm-data
	QoSSourceOperatorDefault = "OPERATOR_DEFAULT" // PCF/SMF configured defaults
	QoSSourceManualOverride  = "MANUAL_OVERRIDE"  // set via /nsmf-management QoS API
	QoSSourceNWModification  = "NW_MODIFICATION"  // NW-initiated modification (TS 23.502 §4.3.3.2)
)

// subscribedQoS holds the subscriber's default QoS fetched from UDM over N10.
// Ref: TS 29.503 §6.1.6.2.9 (5gQosProfile), §6.1.6.2.8 (sessionAmbr)
type subscribedQoS struct {
	FiveQI         int
	ARPPriority    int
	ARPPreemptCap  string
	ARPPreemptVuln string
	AMBRULMbps     int
	AMBRDLMbps     int
}

// fetchSubscribedQoS calls Nudm_SDM Get sm-data (N10) and extracts the
// subscribed default QoS for the given DNN + slice. Returns nil when the UDM
// is unreachable or no matching subscription exists (non-fatal: PCF/operator
// defaults apply).
// Ref: TS 23.502 §4.3.2.2.1 step 4, TS 29.503 §5.2.2.2
func (s *Server) fetchSubscribedQoS(ctx context.Context, supi, dnn string, slice SliceID) *subscribedQoS {
	if s.cfg.Peers.UDM == "" || supi == "" {
		return nil
	}
	snssaiFilter, _ := json.Marshal(map[string]any{"sst": slice.SST, "sd": slice.SD})
	u := fmt.Sprintf("https://%s/nudm-sdm/v2/%s/sm-data?dnn=%s&single-nssai=%s",
		s.cfg.Peers.UDM, url.PathEscape(supi), url.QueryEscape(dnn), url.QueryEscape(string(snssaiFilter)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Warn("UDM: sm-data fetch failed — subscribed QoS unavailable",
			"supi", supi, "error", err, "interface", "N10",
			"spec_ref", "TS 29.503 §5.2.2.2")
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.logger.Warn("UDM: sm-data unexpected status", "supi", supi, "status", resp.StatusCode)
		return nil
	}

	var entries []struct {
		SingleNSSAI struct {
			SST int    `json:"sst"`
			SD  string `json:"sd"`
		} `json:"singleNssai"`
		DNNConfigurations map[string]struct {
			QoSProfile struct {
				FiveQI int `json:"5qi"`
				ARP    struct {
					PriorityLevel int    `json:"priorityLevel"`
					PreemptCap    string `json:"preemptCap"`
					PreemptVuln   string `json:"preemptVuln"`
				} `json:"arp"`
			} `json:"5gQosProfile"`
			SessionAMBR struct {
				Uplink   string `json:"uplink"`
				Downlink string `json:"downlink"`
			} `json:"sessionAmbr"`
		} `json:"dnnConfigurations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		s.logger.Warn("UDM: sm-data decode failed", "supi", supi, "error", err)
		return nil
	}
	for _, e := range entries {
		cfg, ok := e.DNNConfigurations[dnn]
		if !ok || cfg.QoSProfile.FiveQI == 0 {
			continue
		}
		q := &subscribedQoS{
			FiveQI:         cfg.QoSProfile.FiveQI,
			ARPPriority:    cfg.QoSProfile.ARP.PriorityLevel,
			ARPPreemptCap:  cfg.QoSProfile.ARP.PreemptCap,
			ARPPreemptVuln: cfg.QoSProfile.ARP.PreemptVuln,
			AMBRULMbps:     parseMbps(cfg.SessionAMBR.Uplink, 100),
			AMBRDLMbps:     parseMbps(cfg.SessionAMBR.Downlink, 100),
		}
		s.logger.Info("UDM: subscribed default QoS fetched",
			"supi", supi, "dnn", dnn,
			"5qi", q.FiveQI, "ambr_ul_mbps", q.AMBRULMbps, "ambr_dl_mbps", q.AMBRDLMbps,
			"interface", "N10", "direction", "IN",
			"spec_ref", "TS 29.503 §6.1.6.2.7",
		)
		return q
	}
	return nil
}

// ValidFiveQI reports whether v is a standardised 5QI (TS 23.501 Table 5.7.4-1)
// or an operator-defined value (128–254).
func ValidFiveQI(v int) bool {
	switch v {
	case 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		65, 66, 67, 69, 70, 71, 72, 73, 74, 75, 76,
		79, 80, 82, 83, 84, 85, 86, 87, 88, 89, 90:
		return true
	}
	return v >= 128 && v <= 254
}

// ---- /nsmf-management/v1 handlers -----------------------------------------

// sessionView is the JSON shape returned by the management session endpoints.
type sessionView struct {
	SmContextRef string `json:"smContextRef"`
	SUPI         string `json:"supi"`
	PDUSessionID uint8  `json:"pduSessionId"`
	DNN          string `json:"dnn"`
	SNSSAI       struct {
		SST uint8  `json:"sst"`
		SD  string `json:"sd,omitempty"`
	} `json:"sNssai"`
	FiveQI      uint8  `json:"current5qi"`
	ARPPriority int    `json:"arpPriorityLevel,omitempty"`
	QoSSource   string `json:"qosSource"`
	AMBRULMbps  int    `json:"sessionAmbrUlMbps"`
	AMBRDLMbps  int    `json:"sessionAmbrDlMbps"`
	UEIP        string `json:"ueIp"`
	UPFTeid     uint32 `json:"upfTeid"`
	SEID        uint64 `json:"seid"`
	State       string `json:"sessionState"`
	CreatedAt   string `json:"createdAt,omitempty"`
}

func (s *Server) sessionToView(ref string, sess *Session) sessionView {
	v := sessionView{
		SmContextRef: ref,
		SUPI:         sess.SUPI,
		PDUSessionID: sess.PDUSessionID,
		DNN:          sess.DNN,
		FiveQI:       sess.FiveQI,
		ARPPriority:  sess.ARPPriority,
		QoSSource:    sess.QoSSource,
		AMBRULMbps:   sess.AMBRULMbps,
		AMBRDLMbps:   sess.AMBRDLMbps,
		UEIP:         sess.UEIP.String(),
		UPFTeid:      sess.ULTEID,
		SEID:         sess.SEID,
		State:        sess.State,
	}
	v.SNSSAI.SST = sess.SliceID.SST
	v.SNSSAI.SD = sess.SliceID.SD
	if !sess.CreatedAt.IsZero() {
		v.CreatedAt = sess.CreatedAt.UTC().Format(time.RFC3339)
	}
	return v
}

// handleMgmtListSessions returns all active PDU sessions held by this SMF.
// GET /nsmf-management/v1/sessions
func (s *Server) handleMgmtListSessions(w http.ResponseWriter, r *http.Request) {
	s.sessionMu.Lock()
	views := make([]sessionView, 0, len(s.sessions))
	for ref, sess := range s.sessions {
		views = append(views, s.sessionToView(ref, sess))
	}
	s.sessionMu.Unlock()

	sort.Slice(views, func(i, j int) bool {
		if views[i].SUPI != views[j].SUPI {
			return views[i].SUPI < views[j].SUPI
		}
		return views[i].PDUSessionID < views[j].PDUSessionID
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"sessions": views, "count": len(views)})
}

// findSessionsByPSI returns sessions matching the PDU session ID, optionally
// narrowed by SUPI. The returned refs and sessions are index-aligned.
func (s *Server) findSessionsByPSI(psi uint8, supi string) ([]string, []*Session) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	var refs []string
	var out []*Session
	for ref, sess := range s.sessions {
		if sess.PDUSessionID != psi {
			continue
		}
		if supi != "" && sess.SUPI != supi {
			continue
		}
		refs = append(refs, ref)
		out = append(out, sess)
	}
	return refs, out
}

// handleMgmtGetSession returns one session with its QoS flow + SMF-side QER view.
// GET /nsmf-management/v1/sessions/{pduSessionId}[?supi=...]
func (s *Server) handleMgmtGetSession(w http.ResponseWriter, r *http.Request) {
	psi64, err := strconv.ParseUint(r.PathValue("pduSessionId"), 10, 8)
	if err != nil {
		problem(w, http.StatusBadRequest, "INVALID_PARAM", "pduSessionId must be 0-255")
		return
	}
	supi := r.URL.Query().Get("supi")
	refs, sessions := s.findSessionsByPSI(uint8(psi64), supi)
	if len(sessions) == 0 {
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no session with that pduSessionId")
		return
	}
	if len(sessions) > 1 {
		supis := make([]string, len(sessions))
		for i, sess := range sessions {
			supis[i] = sess.SUPI
		}
		problem(w, http.StatusConflict, "AMBIGUOUS_SESSION",
			"multiple sessions match pduSessionId; disambiguate with ?supi= — candidates: "+strings.Join(supis, ", "))
		return
	}

	sess := sessions[0]
	view := s.sessionToView(refs[0], sess)
	resp := map[string]any{
		"session": view,
		"qosFlows": []map[string]any{{
			"qfi":    1,
			"fiveQi": sess.FiveQI,
			"gbr":    isGBRFiveQI(sess.FiveQI),
		}},
		// SMF-side view of the QER installed in the UPF (TS 29.244 §7.5.2.5).
		"pfcpQer": map[string]any{
			"qerId":     1,
			"qfi":       1,
			"gateUl":    "OPEN",
			"gateDl":    "OPEN",
			"mbrUlKbps": sess.AMBRULMbps * 1000,
			"mbrDlKbps": sess.AMBRDLMbps * 1000,
			"seid":      sess.SEID,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// isGBRFiveQI mirrors nas.Is5QIGBR for the SMF's int-typed 5QI values.
func isGBRFiveQI(v uint8) bool {
	switch {
	case v >= 1 && v <= 4, v >= 65 && v <= 67, v >= 71 && v <= 76, v >= 82 && v <= 85:
		return true
	}
	return false
}

// handleMgmtSetQoS triggers the full NW-initiated PDU Session Modification
// (TS 23.502 §4.3.3.2) for one session:
//
//	POST /nsmf-management/v1/sessions/{pduSessionId}/qos
//	Body: {"5qi": <int>, "reason": "<string>", "supi": "<optional>",
//	       "ambr_dl_mbps": <optional>, "ambr_ul_mbps": <optional>}
//
// The SMF delegates N1/N2 delivery to the AMF management API; the AMF calls
// back into Nsmf_PDUSession_UpdateSMContext (policyUpdate), which updates the
// session state, pushes the new QER to the UPF over N4, and returns the 5GSM
// Modification Command + N2SM Modify Request Transfer.
func (s *Server) handleMgmtSetQoS(w http.ResponseWriter, r *http.Request) {
	psi64, err := strconv.ParseUint(r.PathValue("pduSessionId"), 10, 8)
	if err != nil {
		problem(w, http.StatusBadRequest, "INVALID_PARAM", "pduSessionId must be 0-255")
		return
	}
	var body struct {
		FiveQI     int    `json:"5qi"`
		Reason     string `json:"reason"`
		SUPI       string `json:"supi"`
		AMBRDLMbps int    `json:"ambr_dl_mbps"`
		AMBRULMbps int    `json:"ambr_ul_mbps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if !ValidFiveQI(body.FiveQI) {
		problem(w, http.StatusBadRequest, "INVALID_5QI",
			fmt.Sprintf("5qi %d is neither standardised (TS 23.501 Table 5.7.4-1) nor operator-defined (128-254)", body.FiveQI))
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		problem(w, http.StatusBadRequest, "MISSING_FIELD", "reason is required")
		return
	}

	psi := uint8(psi64)
	_, sessions := s.findSessionsByPSI(psi, body.SUPI)
	if len(sessions) == 0 {
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no session with that pduSessionId")
		return
	}
	if len(sessions) > 1 {
		supis := make([]string, len(sessions))
		for i, sess := range sessions {
			supis[i] = sess.SUPI
		}
		problem(w, http.StatusConflict, "AMBIGUOUS_SESSION",
			"multiple sessions match pduSessionId; disambiguate with body field supi — candidates: "+strings.Join(supis, ", "))
		return
	}
	sess := sessions[0]

	s.sessionMu.Lock()
	previous5QI := sess.FiveQI
	ambrDL := sess.AMBRDLMbps
	ambrUL := sess.AMBRULMbps
	supi := sess.SUPI
	s.sessionMu.Unlock()
	if body.AMBRDLMbps > 0 {
		ambrDL = body.AMBRDLMbps
	}
	if body.AMBRULMbps > 0 {
		ambrUL = body.AMBRULMbps
	}

	log := s.logger.With(
		"procedure", "NetworkQoSModification",
		"interface", "Nsmf",
		"supi", supi,
		"pdu_session_id", psi,
		"previous_5qi", previous5QI,
		"new_5qi", body.FiveQI,
		"reason", body.Reason,
		"spec_ref", "TS 23.502 §4.3.3.2",
	)
	log.Info("management QoS change requested", "direction", "IN")

	// Delegate N1/N2 delivery to the AMF: it calls back into our
	// policyUpdate handler (session + N4 QER update) and then sends the
	// Modification Command to the UE and the N2 Modify Request to the gNB.
	if err := s.triggerAMFQoSModification(r.Context(), supi, psi, body.FiveQI, ambrDL, ambrUL); err != nil {
		log.Error("AMF QoS modification trigger failed", "error", err, "result", "FAILURE")
		problem(w, http.StatusBadGateway, "PEER_NOT_RESPONDING", err.Error())
		return
	}

	s.sessionMu.Lock()
	sess.QoSSource = QoSSourceManualOverride
	new5QI := sess.FiveQI
	s.sessionMu.Unlock()

	log.Info("management QoS change applied", "direction", "OUT", "result", "OK")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"result":       "success",
		"supi":         supi,
		"pduSessionId": psi,
		"previous5qi":  previous5QI,
		"new5qi":       new5QI,
		"ambrDlMbps":   ambrDL,
		"ambrUlMbps":   ambrUL,
		"reason":       body.Reason,
		"modifiedAt":   time.Now().UTC().Format(time.RFC3339),
	})
}

// triggerAMFQoSModification calls the AMF management API, which drives the
// N1 (5GSM Modification Command) and N2 (PDU Session Resource Modify Request)
// legs of the NW-initiated modification.
func (s *Server) triggerAMFQoSModification(ctx context.Context, supi string, psi uint8, fiveQI, ambrDL, ambrUL int) error {
	if s.cfg.Peers.AMFMgmt == "" {
		return fmt.Errorf("smf: amf_mgmt peer not configured")
	}
	payload, _ := json.Marshal(map[string]any{
		"5qi":          fiveQI,
		"ambr_dl_mbps": ambrDL,
		"ambr_ul_mbps": ambrUL,
	})
	u := fmt.Sprintf("http://%s/amf/v1/ue-contexts/%s/pdu-sessions/%d/qos",
		s.cfg.Peers.AMFMgmt, url.PathEscape(supi), psi)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("smf: build AMF qos request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.mgmtHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("smf: AMF qos modify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		var detail map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&detail)
		return fmt.Errorf("smf: AMF qos modify: status %d: %v", resp.StatusCode, detail)
	}
	return nil
}
