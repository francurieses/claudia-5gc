package server

// sm_policy_update.go — Npcf_SMPolicyControl SM Policy Association Update
// (TS 29.512 §5.2.2.3). The SMF consults the PCF when a PDU session's QoS is
// modified; the PCF authorises the requested 5QI / Session-AMBR or rejects it.
//
// This is the custom "update" operation on the individual SM Policy resource:
//
//	POST /npcf-smpolicycontrol/v1/sm-policies/{smPolicyId}/update
//	  body:     SmPolicyUpdateContextData (subset; reqQos carries the change)
//	  200 resp: SmPolicyDecision (qosDecs + sessRules + x5gcQosSource)
//	  403 resp: ProblemDetails{cause: REQUESTED_QOS_NOT_AUTHORIZED}
//
// Ref: TS 29.512 §5.2.2.3, §5.6.2.5 (SmPolicyUpdateContextData), §5.6.2.6 (SmPolicyDecision).

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// smPolicyUpdateRequest is the subset of SmPolicyUpdateContextData this PCF consumes.
// ReqQos is an additive convenience object carrying the requested QoS change; TS 29.512
// conveys a UE-requested change via repPolicyCtrlReqTriggers=[RES_MO_RE] plus the rule.
type smPolicyUpdateRequest struct {
	RepPolicyCtrlReqTriggers []string `json:"repPolicyCtrlReqTriggers,omitempty"`
	ReqQos                   *struct {
		FiveQI int `json:"5qi,omitempty"`
		AMBR   *struct {
			Uplink   string `json:"uplink,omitempty"`
			Downlink string `json:"downlink,omitempty"`
		} `json:"ambr,omitempty"`
	} `json:"reqQos,omitempty"`
	// Optional fallbacks if the stored policy lacks supi/dnn (defensive).
	SUPI string `json:"supi,omitempty"`
	DNN  string `json:"dnn,omitempty"`
}

// handleUpdateSmPolicy authorises a QoS modification for an existing SM policy.
func (s *Server) handleUpdateSmPolicy(w http.ResponseWriter, r *http.Request) {
	smPolicyId := r.PathValue("smPolicyId")
	log := s.logger.With(
		"procedure", "SmPolicyUpdate",
		"interface", "Npcf",
		"direction", "IN",
		"correlation_id", r.Header.Get("X-Correlation-Id"),
		"smPolicyId", smPolicyId,
		"spec_ref", "TS 29.512 §5.2.2.3",
	)

	// Resolve the stored policy created at establishment (TS 29.512 §5.2.2.2).
	s.policiesMu.Lock()
	stored, found := s.policies[smPolicyId]
	s.policiesMu.Unlock()
	if !found {
		log.Info("SmPolicyUpdate: unknown smPolicyId", "result", "REJECT", "cause", "CONTEXT_NOT_FOUND")
		problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no SM policy with id "+smPolicyId)
		return
	}

	var req smPolicyUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}

	supi, _ := stored["supi"].(string)
	dnn, _ := stored["dnn"].(string)
	if supi == "" {
		supi = req.SUPI
	}
	if dnn == "" {
		dnn = req.DNN
	}

	// Requested change (defaults to operator config when the SMF reports nothing).
	reqFiveQI := s.cfg.DefaultSMPolicy.FiveQI
	reqUL := s.cfg.DefaultSMPolicy.SessionAMBRUplink
	reqDL := s.cfg.DefaultSMPolicy.SessionAMBRDownlink
	if req.ReqQos != nil {
		if req.ReqQos.FiveQI > 0 {
			reqFiveQI = req.ReqQos.FiveQI
		}
		if req.ReqQos.AMBR != nil {
			if req.ReqQos.AMBR.Uplink != "" {
				reqUL = req.ReqQos.AMBR.Uplink
			}
			if req.ReqQos.AMBR.Downlink != "" {
				reqDL = req.ReqQos.AMBR.Downlink
			}
		}
	}

	arpPriority := s.cfg.DefaultSMPolicy.ARPPriorityLevel

	// A per-subscriber / DNN-scoped override is the PCF's own authoritative decision
	// and supersedes the requested value (mirrors handleCreateSmPolicy precedence).
	s.policiesMu.Lock()
	ov, hasOverride := s.smPolicyOverrides[overrideKey(supi, dnn)]
	if !hasOverride {
		ov, hasOverride = s.smPolicyOverrides[supi]
	}
	s.policiesMu.Unlock()

	if hasOverride {
		grantedFiveQI := ov.FiveQI
		grantedUL, grantedDL := reqUL, reqDL
		if ov.ARPPriorityLevel != 0 {
			arpPriority = ov.ARPPriorityLevel
		}
		if ov.AMBRUplink != "" {
			grantedUL = ov.AMBRUplink
		}
		if ov.AMBRDownlink != "" {
			grantedDL = ov.AMBRDownlink
		}
		log.Info("SmPolicyUpdate: per-subscriber override applied — request superseded",
			"supi", supi, "dnn", dnn, "requested_5qi", reqFiveQI, "granted_5qi", grantedFiveQI,
			"direction", "OUT", "result", "OK")
		writeSmPolicyDecision(w, grantedFiveQI, arpPriority, grantedUL, grantedDL, QoSSourcePCFOverride)
		return
	}

	// Authorisation against the operator policy.
	if !s.is5QIAuthorized(reqFiveQI) {
		log.Info("SmPolicyUpdate: requested 5QI not authorised",
			"supi", supi, "requested_5qi", reqFiveQI, "result", "REJECT",
			"cause", "REQUESTED_QOS_NOT_AUTHORIZED")
		problem(w, http.StatusForbidden, "REQUESTED_QOS_NOT_AUTHORIZED",
			"5qi "+strconv.Itoa(reqFiveQI)+" not in authorized set")
		return
	}
	if max := s.cfg.DefaultSMPolicy.MaxSessionAMBRMbps; max > 0 {
		if ambrMbps(reqUL) > max || ambrMbps(reqDL) > max {
			log.Info("SmPolicyUpdate: requested Session-AMBR over ceiling",
				"supi", supi, "requested_ul", reqUL, "requested_dl", reqDL,
				"max_mbps", max, "result", "REJECT", "cause", "REQUESTED_QOS_NOT_AUTHORIZED")
			problem(w, http.StatusForbidden, "REQUESTED_QOS_NOT_AUTHORIZED",
				"requested Session-AMBR exceeds authorized ceiling of "+strconv.Itoa(max)+" Mbps")
			return
		}
	}

	log.Info("SmPolicyUpdate: change authorised",
		"supi", supi, "dnn", dnn, "granted_5qi", reqFiveQI,
		"granted_ul", reqUL, "granted_dl", reqDL,
		"direction", "OUT", "result", "OK")
	writeSmPolicyDecision(w, reqFiveQI, arpPriority, reqUL, reqDL, "PCF_AUTHORIZED")
}

// is5QIAuthorized reports whether the PCF policy permits the given 5QI on an update.
// An empty authorized set means any value is allowed.
func (s *Server) is5QIAuthorized(fiveQI int) bool {
	set := s.cfg.DefaultSMPolicy.Authorized5QI
	if len(set) == 0 {
		return true
	}
	for _, v := range set {
		if v == fiveQI {
			return true
		}
	}
	return false
}

// QoSSourcePCFOverride mirrors the SMF-side label for an override-driven decision.
const QoSSourcePCFOverride = "PCF_OVERRIDE"

// writeSmPolicyDecision emits a 200 SmPolicyDecision with the granted QoS.
func writeSmPolicyDecision(w http.ResponseWriter, fiveQI, arpPriority int, ambrUL, ambrDL, qosSource string) {
	resp := map[string]interface{}{
		"x5gcQosSource": qosSource,
		"sessRules": map[string]interface{}{
			"sr-1": map[string]interface{}{
				"sessAmbr": map[string]string{
					"uplink":   ambrUL,
					"downlink": ambrDL,
				},
			},
		},
		"qosDecs": map[string]interface{}{
			"qd-1": map[string]interface{}{
				"5qi": fiveQI,
				"arp": map[string]interface{}{
					"priorityLevel": arpPriority,
				},
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ambrMbps extracts the integer Mbps value from an AMBR string like "100 Mbps".
// Returns 0 when the value cannot be parsed (treated as "no constraint hit").
func ambrMbps(s string) int {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0
	}
	v, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0
	}
	return v
}
