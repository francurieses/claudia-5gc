package store

import "testing"

// TestBuildSMSubscriptions_UsesPortalDNN is the regression guard for the
// portal-added-slice bug: the DNN configured for a slice must key its
// DNNConfiguration. Before this, every entry was hardcoded to "internet", so a
// slice provisioned with dnn=gaming had no matching DNNConfiguration and the SMF
// fell back to OPERATOR_DEFAULT QoS. Ref: TS 29.503 §6.1.6.2.7
func TestBuildSMSubscriptions_UsesPortalDNN(t *testing.T) {
	got := BuildSMSubscriptions([]SNSSAISubscribed{
		{SST: 1, SD: "001234", DNN: "gaming"},
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 SM entry, got %d", len(got))
	}
	if _, ok := got[0].DNNConfigurations["gaming"]; !ok {
		t.Fatalf("no DNNConfiguration keyed by the slice's DNN; got keys %v",
			keysOf(got[0].DNNConfigurations))
	}
	if got[0].SingleNSSAI.SST != 1 || got[0].SingleNSSAI.SD != "001234" {
		t.Errorf("slice mismatch: got %d/%s", got[0].SingleNSSAI.SST, got[0].SingleNSSAI.SD)
	}
}

// TestBuildSMSubscriptions_DefaultsToInternet: a slice with no DNN assigned
// keeps the previous behaviour, so the dev seed is unchanged.
func TestBuildSMSubscriptions_DefaultsToInternet(t *testing.T) {
	got := BuildSMSubscriptions([]SNSSAISubscribed{{SST: 1, SD: "000001"}})
	if _, ok := got[0].DNNConfigurations["internet"]; !ok {
		t.Errorf("slice without a DNN must default to internet; got keys %v",
			keysOf(got[0].DNNConfigurations))
	}
}

// TestBuildSMSubscriptions_QoSPerSlice pins the QoS each slice inherits to the
// UDR's own DefaultQoSForSlice/DefaultAMBRForSlice, which is the whole reason
// this derivation lives in the UDR rather than in the portal.
func TestBuildSMSubscriptions_QoSPerSlice(t *testing.T) {
	for _, tc := range []struct {
		name       string
		slice      SNSSAISubscribed
		wantFiveQI int
		wantUplink string
	}{
		{"internet", SNSSAISubscribed{SST: 1, SD: "000001"}, 9, "100 Mbps"},
		{"gold", SNSSAISubscribed{SST: 1, SD: "000002"}, 7, "200 Mbps"},
		{"silver", SNSSAISubscribed{SST: 2, SD: "000001"}, 8, "100 Mbps"},
		{"bronze", SNSSAISubscribed{SST: 3, SD: "000001"}, 9, "50 Mbps"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildSMSubscriptions([]SNSSAISubscribed{tc.slice})
			cfg := got[0].DNNConfigurations["internet"]
			if cfg.DefaultQos.FiveQI != tc.wantFiveQI {
				t.Errorf("5QI: got %d, want %d", cfg.DefaultQos.FiveQI, tc.wantFiveQI)
			}
			if cfg.SessionAMBR.Uplink != tc.wantUplink {
				t.Errorf("uplink AMBR: got %q, want %q", cfg.SessionAMBR.Uplink, tc.wantUplink)
			}
			if cfg.DefaultQos.FiveQI == 0 {
				t.Error("subscribed default 5QI must be non-zero (TS 29.503 §6.1.6.2.7)")
			}
		})
	}
}

func TestBuildSMSubscriptions_Empty(t *testing.T) {
	if got := BuildSMSubscriptions(nil); len(got) != 0 {
		t.Errorf("no slices must yield no SM entries, got %d", len(got))
	}
}

// TestSyncSMDataFromAM_RegeneratesFromSlices covers the portal path end to end
// against the in-memory store: slices written to am-data must show up in
// sm-data, including a slice added after the initial seed.
func TestSyncSMDataFromAM_RegeneratesFromSlices(t *testing.T) {
	s := NewInMemory()
	const supi = "imsi-001010000000001"

	if err := s.PutAMSubscription(&AccessAndMobilitySubscriptionData{
		SUPI: supi,
		NSSAI: AllowedNSSAI{SNSSAIs: []SNSSAISubscribed{
			{SST: 1, SD: "000001", DNN: "internet"},
			{SST: 1, SD: "001234", DNN: "gaming"},
		}},
	}); err != nil {
		t.Fatalf("PutAMSubscription: %v", err)
	}

	n, err := SyncSMDataFromAM(s, supi)
	if err != nil {
		t.Fatalf("SyncSMDataFromAM: %v", err)
	}
	if n != 2 {
		t.Fatalf("synced slice count: got %d, want 2", n)
	}

	subs, err := s.GetSMSubscriptions(supi)
	if err != nil {
		t.Fatalf("GetSMSubscriptions: %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("sm-data entries: got %d, want 2", len(subs))
	}
	// The portal-added gaming slice is the one that used to be missing.
	var found bool
	for _, sub := range subs {
		if sub.SingleNSSAI.SST == 1 && sub.SingleNSSAI.SD == "001234" {
			found = true
			if _, ok := sub.DNNConfigurations["gaming"]; !ok {
				t.Errorf("gaming slice has no gaming DNNConfiguration: %v",
					keysOf(sub.DNNConfigurations))
			}
		}
	}
	if !found {
		t.Error("portal-added slice 1/001234 missing from sm-data")
	}
}

// TestSyncSMDataFromAM_ReplacesStaleSlices: removing a slice from am-data must
// drop it from sm-data, otherwise a revoked slice keeps its QoS entry.
func TestSyncSMDataFromAM_ReplacesStaleSlices(t *testing.T) {
	s := NewInMemory()
	const supi = "imsi-001010000000002"

	if err := s.PutAMSubscription(&AccessAndMobilitySubscriptionData{
		SUPI:  supi,
		NSSAI: AllowedNSSAI{SNSSAIs: []SNSSAISubscribed{{SST: 1, SD: "000001"}, {SST: 1, SD: "000002"}}},
	}); err != nil {
		t.Fatalf("PutAMSubscription: %v", err)
	}
	if _, err := SyncSMDataFromAM(s, supi); err != nil {
		t.Fatalf("SyncSMDataFromAM: %v", err)
	}

	// Operator revokes the gold slice.
	if err := s.PutAMSubscription(&AccessAndMobilitySubscriptionData{
		SUPI:  supi,
		NSSAI: AllowedNSSAI{SNSSAIs: []SNSSAISubscribed{{SST: 1, SD: "000001"}}},
	}); err != nil {
		t.Fatalf("PutAMSubscription: %v", err)
	}
	n, err := SyncSMDataFromAM(s, supi)
	if err != nil {
		t.Fatalf("SyncSMDataFromAM: %v", err)
	}
	if n != 1 {
		t.Fatalf("synced slice count after revoke: got %d, want 1", n)
	}
	subs, _ := s.GetSMSubscriptions(supi)
	for _, sub := range subs {
		if sub.SingleNSSAI.SD == "000002" {
			t.Error("revoked slice 1/000002 still present in sm-data")
		}
	}
}

// TestSyncSMDataFromAM_UnknownSUPI: no am-data means nothing to derive from.
func TestSyncSMDataFromAM_UnknownSUPI(t *testing.T) {
	if _, err := SyncSMDataFromAM(NewInMemory(), "imsi-999999999999999"); err == nil {
		t.Error("expected an error for a SUPI with no am subscription")
	}
}

func keysOf(m map[string]DNNConfiguration) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
