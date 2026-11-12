package sbi

// types_arp_test.go - Arp round-trip and enum tolerance (REL19-3.5).

import (
	"encoding/json"
	"testing"
)

func TestArpTolerantEnums(t *testing.T) {
	var a Arp
	if err := json.Unmarshal([]byte(`{"priorityLevel":5,"preemptCap":"FUTURE_VALUE","preemptVuln":"PREEMPTABLE","x":1}`), &a); err != nil {
		t.Fatalf("unknown enum value rejected: %v", err)
	}
	if a.PreemptCap != "FUTURE_VALUE" || a.PreemptVuln != "PREEMPTABLE" {
		t.Fatalf("got %+v", a)
	}
	legacy, err := json.Marshal(Arp{PriorityLevel: 5})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(legacy) != `{"priorityLevel":5}` {
		t.Fatalf("legacy bytes changed: %s", legacy)
	}
}
