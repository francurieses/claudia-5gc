package server

// sm_policy_decision.go — single builder for the SmPolicyDecision (TS 29.512
// §5.6.2.4) shared by SM Policy Create and Update so both have the same shape.

import "github.com/francurieses/claudia-5gc/nf/pcf/internal/config"

// Identifiers of the single QoS data, session rule and PCC rule the PCF emits
// (map keys; TS 29.512 §5.6.2.4 SmPolicyDecision maps).
const (
	qosDataID  = "qd-1"
	sessRuleID = "sr-1"
	pccRuleID  = "pr-1"
)

// ARP enumerations (TS 29.571 §5.4.4.7 PreemptionCapability / PreemptionVulnerability).
const (
	ARPPreemptCapNot      = "NOT_PREEMPT"
	ARPPreemptCapMay      = "MAY_PREEMPT"
	ARPPreemptVulnNot     = "NOT_PREEMPTABLE"
	ARPPreemptVulnPreempt = "PREEMPTABLE"
)

// buildSmPolicyDecision assembles the SmPolicyDecision body. QosData.qosId,
// SessionRule.sessRuleId and PccRule.pccRuleId are required (TS 29.512 §5.6.2);
// Rel-17 SessionRule carries authSessAmbr; flowInfos is omitted when no flow
// description is configured (minItems 1). x5gcQosSource is a non-3GPP additive
// field. PCC rules are emitted only when withPccRules.
func buildSmPolicyDecision(p config.SMPolicyDefaults, fiveQI, arpPriority int, ambrUL, ambrDL, qosSource string, withPccRules bool) map[string]interface{} {
	capab, vuln := p.ARPPreemptCap, p.ARPPreemptVuln
	if capab == "" {
		capab = ARPPreemptCapNot
	}
	if vuln == "" {
		vuln = ARPPreemptVulnNot
	}
	resp := map[string]interface{}{
		"x5gcQosSource": qosSource,
		"sessRules": map[string]interface{}{
			sessRuleID: map[string]interface{}{
				"sessRuleId":   sessRuleID,
				"authSessAmbr": map[string]string{"uplink": ambrUL, "downlink": ambrDL},
			},
		},
		"qosDecs": map[string]interface{}{
			qosDataID: map[string]interface{}{
				"qosId": qosDataID,
				"5qi":   fiveQI,
				"arp": map[string]interface{}{
					"priorityLevel": arpPriority,
					"preemptCap":    capab,
					"preemptVuln":   vuln,
				},
			},
		},
	}
	if withPccRules {
		rule := map[string]interface{}{
			"pccRuleId":  pccRuleID,
			"precedence": p.FlowPrecedence,
			"refQosData": []string{qosDataID},
		}
		if p.FlowDescription != "" {
			rule["flowInfos"] = []map[string]string{{"flowDescription": p.FlowDescription}}
		}
		resp["pccRules"] = map[string]interface{}{pccRuleID: rule}
	}
	return resp
}
