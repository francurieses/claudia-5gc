//go:build functional

package features_test

// Step definitions for sm_policy_decision_schema.feature (PCF-004).
// Ref: TS 29.512 §5.6.2.4/.7/.8/.9, TS 29.571 §5.4.4.7.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cucumber/godog"
)

// decisionMap returns the named top-level object attribute of the last response.
// A missing attribute yields (nil, false, nil) so callers decide whether that is an error.
func (w *world) decisionMap(attr string) (map[string]any, bool, error) {
	if w.obj == nil {
		return nil, false, fmt.Errorf("last response is not a JSON object: %s", w.body)
	}
	raw, ok := w.obj[attr]
	if !ok {
		return nil, false, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, true, fmt.Errorf("%s is %T, want JSON object", attr, raw)
	}
	return m, true, nil
}

func (w *world) requiredMap(attr string) (map[string]any, error) {
	m, ok, err := w.decisionMap(attr)
	if err != nil {
		return nil, err
	}
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("decision has no non-empty %q: %s", attr, w.body)
	}
	return m, nil
}

func (w *world) smfCreatesSMPolicy(supi, dnn string) error {
	b, _ := json.Marshal(map[string]string{"supi": supi, "dnn": dnn})
	return w.do(http.MethodPost, kinds["SM policy"].createPath, b, "")
}

func (w *world) defaultPreempt(capab, vuln string) error {
	if err := w.needCfg(); err != nil {
		return err
	}
	w.cfg.DefaultSMPolicy.ARPPreemptCap = capab
	w.cfg.DefaultSMPolicy.ARPPreemptVuln = vuln
	return nil
}

func (w *world) defaultFlowDescription(fd string) error {
	if err := w.needCfg(); err != nil {
		return err
	}
	w.cfg.DefaultSMPolicy.FlowDescription = fd
	return nil
}

func (w *world) mapKeyEqualsID(attr, idField string) error {
	m, err := w.requiredMap(attr)
	if err != nil {
		return err
	}
	for k, v := range m {
		e, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s[%q] is %T, want object", attr, k, v)
		}
		if id, _ := e[idField].(string); id == "" || id != k {
			return fmt.Errorf("%s[%q].%s = %v, want %q", attr, k, idField, e[idField], k)
		}
	}
	return nil
}

func (w *world) qosDecsArp(check func(arp map[string]any) error) error {
	m, err := w.requiredMap("qosDecs")
	if err != nil {
		return err
	}
	for k, v := range m {
		e, _ := v.(map[string]any)
		arp, ok := e["arp"].(map[string]any)
		if !ok {
			return fmt.Errorf("qosDecs[%q] has no arp object: %s", k, w.body)
		}
		if err := check(arp); err != nil {
			return fmt.Errorf("qosDecs[%q].arp: %w", k, err)
		}
	}
	return nil
}

func inCSV(csv, v string) bool {
	for _, f := range strings.Split(csv, ",") {
		if f == v {
			return true
		}
	}
	return false
}

func (w *world) arpConformant(capCSV, vulnCSV string) error {
	return w.qosDecsArp(func(arp map[string]any) error {
		if pl, ok := arp["priorityLevel"].(float64); !ok || pl < 1 || pl > 15 {
			return fmt.Errorf("priorityLevel = %v, want integer 1..15", arp["priorityLevel"])
		}
		if c, _ := arp["preemptCap"].(string); !inCSV(capCSV, c) {
			return fmt.Errorf("preemptCap = %v, want one of %s", arp["preemptCap"], capCSV)
		}
		if v, _ := arp["preemptVuln"].(string); !inCSV(vulnCSV, v) {
			return fmt.Errorf("preemptVuln = %v, want one of %s", arp["preemptVuln"], vulnCSV)
		}
		return nil
	})
}

func (w *world) arpEquals(capab, vuln string) error {
	return w.qosDecsArp(func(arp map[string]any) error {
		if arp["preemptCap"] != capab || arp["preemptVuln"] != vuln {
			return fmt.Errorf("preemptCap/preemptVuln = %v/%v, want %s/%s", arp["preemptCap"], arp["preemptVuln"], capab, vuln)
		}
		return nil
	})
}

// eachPccRule runs check on every pccRules entry. pccRules is absent on Update
// (that decision carries qosDecs+sessRules only), which makes the per-entry
// assertions vacuously true there.
func (w *world) eachPccRule(check func(id string, r map[string]any, qos map[string]any) error) error {
	rules, present, err := w.decisionMap("pccRules")
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	qos, _, err := w.decisionMap("qosDecs")
	if err != nil {
		return err
	}
	for id, v := range rules {
		r, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("pccRules[%q] is %T, want object", id, v)
		}
		if err := check(id, r, qos); err != nil {
			return err
		}
	}
	return nil
}

func (w *world) pccRuleIDEqualsKey() error {
	return w.eachPccRule(func(id string, r, _ map[string]any) error {
		if got, _ := r["pccRuleId"].(string); got == "" || got != id {
			return fmt.Errorf("pccRules[%q].pccRuleId = %v, want %q", id, r["pccRuleId"], id)
		}
		return nil
	})
}

func (w *world) pccRefQosData() error {
	return w.eachPccRule(func(id string, r, qos map[string]any) error {
		refs, ok := r["refQosData"].([]any)
		if !ok || len(refs) != 1 {
			return fmt.Errorf("pccRules[%q].refQosData = %v, want exactly one item", id, r["refQosData"])
		}
		ref, _ := refs[0].(string)
		if _, exists := qos[ref]; !exists {
			return fmt.Errorf("pccRules[%q].refQosData[0] = %q, not a qosDecs key", id, ref)
		}
		return nil
	})
}

func (w *world) flowInfosItems(check func(id string, item map[string]any) error) error {
	return w.eachPccRule(func(id string, r, _ map[string]any) error {
		raw, ok := r["flowInfos"]
		if !ok {
			return nil
		}
		items, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("pccRules[%q].flowInfos is %T, want array", id, raw)
		}
		for i, it := range items {
			m, ok := it.(map[string]any)
			if !ok {
				return fmt.Errorf("pccRules[%q].flowInfos[%d] is %T, want object", id, i, it)
			}
			if err := check(id, m); err != nil {
				return err
			}
		}
		return nil
	})
}

func (w *world) flowInfosUse(good, bad string) error {
	return w.flowInfosItems(func(id string, m map[string]any) error {
		if _, has := m[bad]; has {
			return fmt.Errorf("pccRules[%q].flowInfos item uses %q: %v", id, bad, m)
		}
		if _, has := m[good]; !has {
			return fmt.Errorf("pccRules[%q].flowInfos item lacks %q: %v", id, good, m)
		}
		return nil
	})
}

func (w *world) flowInfosNonEmpty(attr string) error {
	return w.flowInfosItems(func(id string, m map[string]any) error {
		if s, _ := m[attr].(string); s == "" {
			return fmt.Errorf("pccRules[%q].flowInfos item has empty %q: %v", id, attr, m)
		}
		return nil
	})
}

func (w *world) pccNoFlowInfos() error {
	rules, present, err := w.decisionMap("pccRules")
	if err != nil {
		return err
	}
	if !present || len(rules) == 0 {
		return fmt.Errorf("decision has no pccRules to inspect: %s", w.body)
	}
	for id, v := range rules {
		if r, _ := v.(map[string]any); r != nil {
			if _, has := r["flowInfos"]; has {
				return fmt.Errorf("pccRules[%q] has a flowInfos attribute: %v", id, r["flowInfos"])
			}
		}
	}
	return nil
}

func (w *world) configValidated(key, val string) error {
	if err := w.defaultConfig(); err != nil {
		return err
	}
	switch key {
	case "arp_preempt_cap":
		w.cfg.DefaultSMPolicy.ARPPreemptCap = val
	case "arp_preempt_vuln":
		w.cfg.DefaultSMPolicy.ARPPreemptVuln = val
	default:
		return fmt.Errorf("unknown default_sm_policy key %q", key)
	}
	w.validateErr = w.cfg.Validate()
	w.validated = true
	return nil
}

func (w *world) validationFailsNaming(key string) error {
	if !w.validated {
		return errors.New("configuration was not validated")
	}
	if w.validateErr == nil {
		return errors.New("Config.Validate() returned nil, want an error")
	}
	if !strings.Contains(w.validateErr.Error(), key) {
		return fmt.Errorf("validation error %q does not name %q", w.validateErr, key)
	}
	return nil
}

func registerSMPolicyDecisionSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^the SMF creates an SM policy for "([^"]*)" on dnn "([^"]*)"$`, w.smfCreatesSMPolicy)
	sc.Step(`^the create response status is (\d+)$`, func(s string) error { return w.statusIs(atoi(s)) })
	sc.Step(`^the PCF default SM policy has arp_preempt_cap "([^"]*)" and arp_preempt_vuln "([^"]*)"$`, w.defaultPreempt)
	sc.Step(`^the PCF default SM policy has flow_description "([^"]*)"$`, w.defaultFlowDescription)
	sc.Step(`^every qosDecs entry has a qosId equal to its map key$`, func() error { return w.mapKeyEqualsID("qosDecs", "qosId") })
	sc.Step(`^every sessRules entry has a sessRuleId equal to its map key$`, func() error { return w.mapKeyEqualsID("sessRules", "sessRuleId") })
	sc.Step(`^every qosDecs Arp has a priorityLevel, a preemptCap in "([^"]*)" and a preemptVuln in "([^"]*)"$`, w.arpConformant)
	sc.Step(`^every qosDecs Arp has preemptCap "([^"]*)" and preemptVuln "([^"]*)"$`, w.arpEquals)
	sc.Step(`^every pccRules entry has a pccRuleId equal to its map key$`, w.pccRuleIDEqualsKey)
	sc.Step(`^every pccRules entry has refQosData with exactly one item naming an existing qosDecs key$`, w.pccRefQosData)
	sc.Step(`^every pccRules flowInfos item uses "([^"]*)" and never "([^"]*)"$`, w.flowInfosUse)
	sc.Step(`^every pccRules flowInfos item has a non-empty "([^"]*)"$`, w.flowInfosNonEmpty)
	sc.Step(`^no pccRules entry has a flowInfos attribute$`, w.pccNoFlowInfos)
	sc.Step(`^no flowInfos item with an empty "([^"]*)" is emitted$`, w.flowInfosNonEmpty)
	sc.Step(`^the PCF configuration is validated with default_sm_policy (arp_preempt_cap|arp_preempt_vuln) "([^"]*)"$`, w.configValidated)
	sc.Step(`^the configuration validation fails with an error naming "([^"]*)"$`, w.validationFailsNaming)
}
