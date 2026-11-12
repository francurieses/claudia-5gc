package server

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/policy"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
	"github.com/francurieses/claudia-5gc/shared/types"
)

// ---- N15 — Npcf_UEPolicyControl -----------------------------------------
//
// The AMF calls these endpoints at UE registration to retrieve URSP rules,
// and at deregistration to release the policy association.
// Ref: TS 29.525 §4.2.2

// UE policy association procedure names, clauses and the log interface label
// (logs and fivegc_procedure_total).
const (
	procUEPolicyCreate    = "UEPolicyCreate"
	procUEPolicyDelete    = "UEPolicyDelete"
	uePolicyCreateSpecRef = "TS 29.525 §4.2.2.2"
	uePolicyDeleteSpecRef = "TS 29.525 §4.2.5"
	ifaceN15              = "N15"
)

// handleCreateUEPolicy handles POST /npcf-ue-policy-control/v1/policies.
// The 201 body is a PolicyAssociation (TS 29.525 §5.6.2.2): the UE policy
// container is carried in `uePolicy` (Bytes, base64) and the polAssoId only in
// the Location header (TS 29.501 §4.4.1).
// Ref: TS 29.525 §4.2.2.2 (UEPolicyControl_Create)
func (s *Server) handleCreateUEPolicy(w http.ResponseWriter, r *http.Request) {
	corrID := r.Header.Get("X-Correlation-Id")
	base := s.procLog(r, procUEPolicyCreate)
	log := dirLog(base, ifaceN15, dirIn, uePolicyCreateSpecRef)
	out := dirLog(base, ifaceN15, dirOut, uePolicyCreateSpecRef)

	var req struct {
		SUPI         string `json:"supi"`
		ServingPlmn  string `json:"servingPlmn"`
		ServingAMFID string `json:"servingAmfId,omitempty"`
		SuppFeat     string `json:"suppFeat,omitempty"`
	}
	ctx := logging.WithCorrelationID(r.Context(), corrID)
	peerNF := peerNFType(r, apiUEPolicy)
	if tooLarge, err := decodeBody(w, r, &req); err != nil {
		if tooLarge {
			s.payloadTooLarge(ctx, w, apiUEPolicy, procUEPolicyCreate)
			return
		}
		if features.IsTypeErrorOn(err, apiInfos[apiUEPolicy].field) {
			s.rejectSuppFeat(ctx, w, apiUEPolicy, peerNF, "<non-string>", err, detailNotString)
			return
		}
		log.Warn("UEPolicyControl_Create: request body rejected", "error", err,
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", err.Error())
		return
	}
	// suppFeat must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	if err := features.Validate(req.SuppFeat); err != nil {
		s.rejectSuppFeat(ctx, w, apiUEPolicy, peerNF, req.SuppFeat, err, detailNotHex)
		return
	}
	// Producer side (decision D1). Ref: TS 29.525 §5.8.
	suppAnswer, suppSet := s.answer(apiUEPolicy, req.SuppFeat)
	if req.SUPI == "" {
		log.Warn("UEPolicyControl_Create: supi missing", "result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "supi is required")
		return
	}

	log = log.With("supi", req.SUPI)
	out = out.With("supi", req.SUPI)
	base = base.With("supi", req.SUPI)
	log.Info("UEPolicyControl_Create received")

	rules, err := s.resolveURSPRules(r.Context(), req.SUPI, base)
	if err != nil {
		out.Error("failed to resolve URSP rules", "error", err, "result", "FAILURE")
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}

	container, err := policy.EncodeURSPRules(rules, s.cfg.PLMN.MCC+s.cfg.PLMN.MNC)
	if err != nil {
		out.Error("failed to encode URSP rules", "error", err, "result", "FAILURE")
		problem(w, http.StatusInternalServerError, "SYSTEM_FAILURE", err.Error())
		return
	}

	polAssoID := uuid.NewString()

	s.policiesMu.Lock()
	s.policies[polAssoID] = map[string]interface{}{
		"supi":        req.SUPI,
		recordTypeKey: recordTypeUEPolicy,
	}
	s.ueFeatures[polAssoID] = suppSet
	s.policiesMu.Unlock()

	// PolicyAssociation (TS 29.525 §5.6.2.2): `uePolicy` is the UE policy
	// container as Bytes (TS 29.571 §5.2.2, base64); there is no polAssoId
	// attribute - the identifier is only in the Location header.
	resp := map[string]interface{}{}
	if len(container) > 0 {
		resp["uePolicy"] = base64.StdEncoding.EncodeToString(container)
	}

	if suppAnswer != "" {
		resp["suppFeat"] = suppAnswer
	}
	// Request accepted: record the negotiation (TS 29.500 §6.6.2).
	s.logAccepted(ctx, apiUEPolicy, peerNF, req.SuppFeat, suppSet)

	out.Info("UEPolicyControl_Create responded",
		"pol_asso_id", polAssoID,
		"container_bytes", len(container),
		"rule_count", len(rules),
		"result", "OK",
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", s.apiRoot(r)+"/npcf-ue-policy-control/v1/policies/"+polAssoID)
	w.WriteHeader(http.StatusCreated)
	encodeBody(out, w, resp)
}

// handleDeleteUEPolicy handles DELETE /npcf-ue-policy-control/v1/policies/{polAssoId}.
// 204 when the UE policy association exists, 404 ProblemDetails
// POLICY_ASSOCIATION_NOT_FOUND when it does not. The 404 ProblemDetails is per
// the TS 29.525 YAML (DeleteIndividualUEPolicyAssociation 404); the cause name
// mirrors TS 29.507/29.512 practice, pending confirmation against TS 29.525
// Table 5.7.3-1.
// Ref: TS 29.525 §4.2.5 (UEPolicyControl_Delete)
func (s *Server) handleDeleteUEPolicy(w http.ResponseWriter, r *http.Request) {
	polAssoID := r.PathValue("polAssoId")
	base := s.procLog(r, procUEPolicyDelete).With("pol_asso_id", polAssoID)
	dirLog(base, ifaceN15, dirIn, uePolicyDeleteSpecRef).Info("UEPolicyControl_Delete received")
	out := dirLog(base, ifaceN15, dirOut, uePolicyDeleteSpecRef)

	// The policies map is shared with SM policies: only a "ue-policy" record is
	// a UE policy association.
	s.policiesMu.Lock()
	rec, found := s.policies[polAssoID]
	known := found && isRecordType(rec, recordTypeUEPolicy)
	if known {
		delete(s.policies, polAssoID)
		delete(s.ueFeatures, polAssoID)
	}
	s.policiesMu.Unlock()

	if !known {
		out.Warn("UEPolicyControl_Delete: UE policy association not found",
			"result", "REJECT", "cause", "POLICY_ASSOCIATION_NOT_FOUND")
		problem(w, http.StatusNotFound, "POLICY_ASSOCIATION_NOT_FOUND",
			"UE policy association "+polAssoID+" not found")
		return
	}
	out.Info("UEPolicyControl_Delete", "result", "OK")
	w.WriteHeader(http.StatusNoContent)
}

// resolveURSPRules returns URSP rules for a SUPI.
// Priority: per-subscriber UDR override → PCF config defaults.
// base is the procedure-level logger (no interface/direction/spec_ref set).
func (s *Server) resolveURSPRules(ctx context.Context, supi string, base *slog.Logger) ([]types.URSPRule, error) {
	if s.udrClient != nil {
		udrLog := dirLog(base, "N36", dirOut, udrQuerySpecRef)
		sub, err := s.udrClient.GetPolicySubscription(ctx, supi)
		if err != nil {
			udrLog.Warn("UDR GetPolicySubscription failed (using config defaults)",
				"error", err, "result", "FAILURE")
		} else if sub != nil && len(sub.Rules) > 0 {
			udrLog.Info("using per-subscriber URSP rules from UDR",
				"rule_count", len(sub.Rules), "result", "OK")
			return sub.Rules, nil
		}
	}
	rules := s.defaultURSPRules()
	dirLog(base, ifaceN15, dirIn, uePolicyCreateSpecRef).Info("using config default URSP rules", "rule_count", len(rules))
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
