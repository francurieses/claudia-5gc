package api

import (
	"reflect"
	"testing"
)

// TestGuessUEContainer pins the SUPI plan of the UERANSIM scenarios
// (config/ueransim/ue-*.yaml) when every scenario runs at once (make ueransim-all).
func TestGuessUEContainer(t *testing.T) {
	all := []string{
		"ueransim-gnb", "ueransim-ue", "ueransim-gnb-ms",
		"ueransim-ue-internet", "ueransim-ue-gold", "ueransim-ue-silver", "ueransim-ue-bronze",
		"ueransim-ue-profile-a",
	}
	cases := []struct {
		supi    string
		running []string
		want    string
	}{
		{"imsi-001010000000001", all, "ueransim-ue"},
		{"imsi-001010000000003", all, "ueransim-ue"}, // UE_COUNT range
		{"imsi-001010000000201", all, "ueransim-ue-internet"},
		{"imsi-001010000000202", all, "ueransim-ue-gold"},
		{"imsi-001010000000203", all, "ueransim-ue-silver"},
		{"imsi-001010000000204", all, "ueransim-ue-bronze"},
		{"imsi-001010000000301", all, "ueransim-ue-profile-a"},
		{"imsi-001010000000301", []string{"ueransim-gnb", "ueransim-ue-profile-a"}, "ueransim-ue-profile-a"},
		{"imsi-001010000000202", []string{"ueransim-gnb", "ueransim-ue"}, "ueransim-ue"},
		{"imsi-001010000000001", nil, ""},
	}
	for _, c := range cases {
		if got := guessUEContainer(c.supi, c.running); got != c.want {
			t.Errorf("guessUEContainer(%s, %v) = %q, want %q", c.supi, c.running, got, c.want)
		}
	}
}

// TestUERANSIMScenariosCoexist checks that no scenario stops another one: the
// gNBs have distinct aliases/NCIs and the UEs distinct SUPIs.
func TestUERANSIMScenariosCoexist(t *testing.T) {
	for _, sc := range ueransimScenarios {
		if len(sc.conflicts) != 0 {
			t.Errorf("scenario %q declares conflicts %v; scenarios must coexist", sc.name, sc.conflicts)
		}
	}
}

// TestScenarioContainersToStop checks that a shared gNB survives stopping one
// scenario while another scenario's UE still uses it.
func TestScenarioContainersToStop(t *testing.T) {
	profileA := resolveScenario("profile-a")
	standard := resolveScenario("standard")
	slices := resolveScenario("slices")

	both := map[string]bool{"ueransim-gnb": true, "ueransim-ue": true, "ueransim-ue-profile-a": true}
	if got, want := scenarioContainersToStop(profileA, both), []string{"ueransim-ue-profile-a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("profile-a with standard running: got %v, want %v", got, want)
	}
	if got, want := scenarioContainersToStop(standard, both), []string{"ueransim-ue"}; !reflect.DeepEqual(got, want) {
		t.Errorf("standard with profile-a running: got %v, want %v", got, want)
	}
	alone := map[string]bool{"ueransim-gnb": true, "ueransim-ue-profile-a": true}
	if got, want := scenarioContainersToStop(profileA, alone), []string{"ueransim-ue-profile-a", "ueransim-gnb"}; !reflect.DeepEqual(got, want) {
		t.Errorf("profile-a alone: got %v, want %v", got, want)
	}
	if got := scenarioContainersToStop(slices, both); len(got) != 5 || got[4] != "ueransim-gnb-ms" {
		t.Errorf("slices: got %v, want all 5 containers ending with ueransim-gnb-ms", got)
	}
}
