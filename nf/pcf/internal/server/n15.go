package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/policy"
	"github.com/francurieses/claudia-5gc/shared/types"
)

// ---- N15 — Npcf_UEPolicyControl -----------------------------------------
//
// The AMF calls these endpoints at UE registration to retrieve URSP rules,
// and at deregistration to release the policy association.
// Ref: TS 29.525 §4.2.2

// handleCreateUEPolicy handles POST /npcf-ue-policy-control/v1/ue-policies
// Ref: TS 29.525 §4.2.2.2 (UEPolicyControl_Create)
func (s *Server) handleCreateUEPolicy(w http.ResponseWriter, r *http.Request) {
	corrID := r.Header.Get("X-Correlation-Id")
	log := s.logger.With(
		"procedure", "UEPolicyCreate",
		"interface", "N15",
		"direction", "IN",
		"correlation_id", corrID,
		"spec_ref", "TS 29.525 §4.2.2.2",
	)

	var req struct {
		SUPI         string `json:"supi"`
		ServingPlmn  string `json:"servingPlmn"`
		ServingAMFID string `json:"servingAmfId,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}
	if req.SUPI == "" {
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "supi is required")
		return
	}

	log = log.With("supi", req.SUPI)
	log.Info("UEPolicyControl_Create received")

	rules, err := s.resolveURSPRules(r.Context(), req.SUPI, log)
	if err != nil {
		log.Error("failed to resolve URSP rules", "error", err)
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}

	container, err := policy.EncodeURSPRules(rules, s.cfg.PLMN.MCC+s.cfg.PLMN.MNC)
	if err != nil {
		log.Error("failed to encode URSP rules", "error", err)
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}

	polAssoID := uuid.NewString()

	s.policiesMu.Lock()
	s.policies[polAssoID] = map[string]interface{}{
		"supi": req.SUPI,
		"type": "ue-policy",
	}
	s.policiesMu.Unlock()

	resp := map[string]interface{}{
		"polAssoId": polAssoID,
	}
	if len(container) > 0 {
		resp["uePolicySections"] = map[string]interface{}{
			"upsi-0x0101": map[string]interface{}{
				"uePolicySectionContent": base64.StdEncoding.EncodeToString(container),
			},
		}
	}

	log.Info("UEPolicyControl_Create responded",
		"pol_asso_id", polAssoID,
		"container_bytes", len(container),
		"rule_count", len(rules),
		"direction", "OUT",
		"result", "OK",
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/npcf-ue-policy-control/v1/ue-policies/"+polAssoID)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleDeleteUEPolicy handles DELETE /npcf-ue-policy-control/v1/ue-policies/{polAssoId}
// Ref: TS 29.525 §4.2.2.3 (UEPolicyControl_Delete)
func (s *Server) handleDeleteUEPolicy(w http.ResponseWriter, r *http.Request) {
	polAssoID := r.PathValue("polAssoId")
	corrID := r.Header.Get("X-Correlation-Id")
	s.logger.With(
		"procedure", "UEPolicyDelete",
		"interface", "N15",
		"direction", "IN",
		"correlation_id", corrID,
		"pol_asso_id", polAssoID,
		"spec_ref", "TS 29.525 §4.2.2.3",
	).Info("UEPolicyControl_Delete", "result", "OK")

	s.policiesMu.Lock()
	delete(s.policies, polAssoID)
	s.policiesMu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// resolveURSPRules returns URSP rules for a SUPI.
// Priority: per-subscriber UDR override → PCF config defaults.
func (s *Server) resolveURSPRules(ctx context.Context, supi string, log *slog.Logger) ([]types.URSPRule, error) {
	if s.udrClient != nil {
		sub, err := s.udrClient.GetPolicySubscription(ctx, supi)
		if err != nil {
			log.Warn("UDR GetPolicySubscription failed (using config defaults)",
				"error", err, "interface", "N36")
		} else if sub != nil && len(sub.Rules) > 0 {
			log.Info("using per-subscriber URSP rules from UDR",
				"rule_count", len(sub.Rules), "interface", "N36")
			return sub.Rules, nil
		}
	}
	rules := s.defaultURSPRules()
	log.Info("using config default URSP rules", "rule_count", len(rules))
	return rules, nil
}

// defaultURSPRules converts the PCF config URSP defaults into types.URSPRule values.
func (s *Server) defaultURSPRules() []types.URSPRule {
	var rules []types.URSPRule
	for _, rc := range s.cfg.DefaultURSP.Rules {
		r := types.URSPRule{
			Precedence: rc.Precedence,
			TrafficDescriptor: types.TrafficDescriptor{
				MatchAll:    rc.TrafficDescriptor.MatchAll,
				DNNs:        rc.TrafficDescriptor.DNNs,
				FQDNs:       rc.TrafficDescriptor.FQDNs,
				IPv4Addrs:   rc.TrafficDescriptor.IPv4Addrs,
				ProtocolIDs: rc.TrafficDescriptor.ProtocolIDs,
			},
		}
		for _, rd := range rc.RouteDescriptors {
			rsd := types.RouteSelectionDescriptor{
				Precedence:     rd.Precedence,
				SSCMode:        rd.SSCMode,
				PDUSessionType: rd.PDUSessionType,
				DNN:            rd.DNN,
			}
			if rd.SNSSAI != nil {
				rsd.SNSSAI = &types.SNSSAI{
					SST: rd.SNSSAI.SST,
					SD:  rd.SNSSAI.SD,
				}
			}
			r.RouteSelDescriptors = append(r.RouteSelDescriptors, rsd)
		}
		rules = append(rules, r)
	}
	return rules
}
