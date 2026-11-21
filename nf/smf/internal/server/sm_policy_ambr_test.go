package server

import "testing"

func TestSessRuleAmbr(t *testing.T) {
	amb := map[string]interface{}{"uplink": "1 Mbps"}
	tests := []struct {
		name string
		rule map[string]interface{}
		ok   bool
	}{
		{"authSessAmbr", map[string]interface{}{"authSessAmbr": amb}, true},
		{"legacy sessAmbr", map[string]interface{}{"sessAmbr": amb}, true},
		{"none", map[string]interface{}{}, false},
		{"authSessAmbr wins over legacy", map[string]interface{}{"authSessAmbr": amb, "sessAmbr": map[string]interface{}{"uplink": "9 Mbps"}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sessRuleAmbr(tc.rule)
			if ok != tc.ok || (ok && got["uplink"] != "1 Mbps") {
				t.Fatalf("got %v %v", got, ok)
			}
		})
	}
}
