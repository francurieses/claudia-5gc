package server

import (
	"testing"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
)

// TestBuildSmPolicyDecisionSchema checks required fields of the SmPolicyDecision
// (TS 29.512 §5.6.2.4, TS 29.571 §5.4.4.7) for Create and Update shapes.
func TestBuildSmPolicyDecisionSchema(t *testing.T) {
	cases := []struct {
		name     string
		p        config.SMPolicyDefaults
		pcc      bool
		wantFlow bool
		wantCap  string
		wantVuln string
	}{
		{"create", config.SMPolicyDefaults{FlowDescription: "permit out ip from any to assigned", FlowPrecedence: 100, ARPPreemptCap: "MAY_PREEMPT", ARPPreemptVuln: "PREEMPTABLE"}, true, true, ARPPreemptCapMay, ARPPreemptVulnPreempt},
		{"create empty flow and arp", config.SMPolicyDefaults{}, true, false, ARPPreemptCapNot, ARPPreemptVulnNot},
		{"update", config.SMPolicyDefaults{FlowDescription: "x"}, false, false, ARPPreemptCapNot, ARPPreemptVulnNot},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := buildSmPolicyDecision(tc.p, 9, 8, "1 Mbps", "2 Mbps", "SRC", tc.pcc)
			qd := d["qosDecs"].(map[string]interface{})
			q := qd[qosDataID].(map[string]interface{})
			if q["qosId"] != qosDataID {
				t.Errorf("qosId: %v", q["qosId"])
			}
			arp := q["arp"].(map[string]interface{})
			if arp["preemptCap"] != tc.wantCap || arp["preemptVuln"] != tc.wantVuln || arp["priorityLevel"] != 8 {
				t.Errorf("arp: %v", arp)
			}
			sr := d["sessRules"].(map[string]interface{})[sessRuleID].(map[string]interface{})
			if sr["sessRuleId"] != sessRuleID || sr["authSessAmbr"] == nil {
				t.Errorf("sessRule: %v", sr)
			}
			if _, bad := sr["sessAmbr"]; bad {
				t.Error("non-standard sessAmbr emitted")
			}
			pr, has := d["pccRules"]
			if has != tc.pcc {
				t.Fatalf("pccRules presence %v want %v", has, tc.pcc)
			}
			if !tc.pcc {
				return
			}
			r := pr.(map[string]interface{})[pccRuleID].(map[string]interface{})
			ref := r["refQosData"].([]string)
			if r["pccRuleId"] != pccRuleID || len(ref) != 1 {
				t.Fatalf("pccRule: %v", r)
			}
			if _, ok := qd[ref[0]]; !ok {
				t.Errorf("refQosData %q not in qosDecs", ref[0])
			}
			fi, hasFI := r["flowInfos"]
			if hasFI != tc.wantFlow {
				t.Fatalf("flowInfos presence %v want %v", hasFI, tc.wantFlow)
			}
			if hasFI {
				item := fi.([]map[string]string)[0]
				if _, bad := item["flowDesc"]; bad || item["flowDescription"] == "" {
					t.Errorf("flowInfos item: %v", item)
				}
			}
		})
	}
}
