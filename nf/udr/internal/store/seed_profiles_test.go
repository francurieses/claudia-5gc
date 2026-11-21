package store

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

func opWithDNNs(slices []operatorcfg.SNSSAIEntry, dnns ...string) *operatorcfg.OperatorConfig {
	op := &operatorcfg.OperatorConfig{SNSSAIs: slices}
	for _, d := range dnns {
		op.DNNs = append(op.DNNs, operatorcfg.DNNEntry{Name: d})
	}
	return op
}

func TestBuildSeedSliceProfiles_OperatorDNNs(t *testing.T) {
	op := opWithDNNs([]operatorcfg.SNSSAIEntry{
		{SST: 1, SD: "000001", DNN: "internet"},
		{SST: 1, SD: "000002", DNN: "gaming"},
		{SST: 2, SD: "000001", DNN: "ims"},
		{SST: 3, SD: "000001", DNN: "bronze"},
		{SST: 1, SD: "001234"},
	}, "internet", "gaming", "ims", "bronze")
	got := BuildSeedSliceProfiles(op, nil)
	inet := SNSSAISubscribed{SST: 1, SD: "000001"}
	want := [][]SNSSAISubscribed{
		{inet},
		{inet, {SST: 1, SD: "000002", DNN: "gaming"}},
		{inet, {SST: 2, SD: "000001", DNN: "ims"}},
		{inet, {SST: 3, SD: "000001", DNN: "bronze"}},
		{inet, {SST: 1, SD: "001234"}},
	}
	if len(got) != len(want) {
		t.Fatalf("profiles: %+v", got)
	}
	for i := range want {
		if len(got[i]) != len(want[i]) {
			t.Fatalf("profile %d: %+v", i, got[i])
		}
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Errorf("profile %d[%d]: got %+v want %+v", i, j, got[i][j], want[i][j])
			}
		}
	}
}

func TestBuildSeedSliceProfiles_Fallback(t *testing.T) {
	for _, op := range []*operatorcfg.OperatorConfig{nil, {}} {
		got := BuildSeedSliceProfiles(op, nil)
		if len(got) != 4 {
			t.Fatalf("fallback profiles: %+v", got)
		}
		for i, d := range []string{"gaming", "ims", "bronze"} {
			if g := got[i+1][1].DNN; g != d {
				t.Errorf("profile %d DNN = %q, want %q", i+1, g, d)
			}
		}
		if got[0][0].DNN != "" {
			t.Errorf("internet must be stored empty: %+v", got[0][0])
		}
	}
}

func TestBuildSeedSliceProfiles_UnknownDNNWarnsAndFallsBack(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&buf, nil))
	op := opWithDNNs([]operatorcfg.SNSSAIEntry{
		{SST: 1, SD: "000001"}, {SST: 1, SD: "000002", DNN: "nope"},
	}, "internet", "gaming")
	got := BuildSeedSliceProfiles(op, lg)
	if got[1][1].DNN != "" {
		t.Errorf("unknown DNN must fall back to internet (empty): %+v", got[1][1])
	}
	out := buf.String()
	for _, w := range []string{"unknown seed DNN, falling back to internet", `"procedure":"SubscriberSeed"`,
		`"spec_ref":"TS 29.503 §6.1.6.2.9"`, `"result":"REJECT"`, `"level":"WARN"`} {
		if !strings.Contains(out, w) {
			t.Errorf("log missing %s: %s", w, out)
		}
	}
}

func TestBuildSeedSliceProfiles_NormalisesCaseAndInternet(t *testing.T) {
	op := opWithDNNs([]operatorcfg.SNSSAIEntry{
		{SST: 1, SD: "000001", DNN: " Internet "}, {SST: 1, SD: "000002", DNN: " Gaming "},
	})
	got := BuildSeedSliceProfiles(op, nil)
	if got[0][0].DNN != "" {
		t.Errorf("internet must be empty: %+v", got[0][0])
	}
	if got[1][1].DNN != "gaming" {
		t.Errorf("DNN not normalised: %+v", got[1][1])
	}
}

func TestFormatSeedSNSSAIs(t *testing.T) {
	got := FormatSeedSNSSAIs([]SNSSAISubscribed{{SST: 1, SD: "000001"}, {SST: 1, SD: "000002", DNN: "gaming"}})
	if got[0] != "SST=1/SD=000001" || got[1] != "SST=1/SD=000002/DNN=gaming" {
		t.Errorf("got %v", got)
	}
}

func TestBuildSMSubscriptions_SeedGamingQoS(t *testing.T) {
	profiles := BuildSeedSliceProfiles(nil, nil)
	sm := BuildSMSubscriptions(profiles[1], nil)
	var gold *SessionManagementSubscriptionData
	for i := range sm {
		if sm[i].SingleNSSAI.SST == 1 && sm[i].SingleNSSAI.SD == "000002" {
			gold = &sm[i]
		}
	}
	if gold == nil {
		t.Fatalf("no sm-data for 1/000002: %+v", sm)
	}
	c, ok := gold.DNNConfigurations["gaming"]
	if !ok {
		t.Fatalf("not keyed on gaming: %v", keysOf(gold.DNNConfigurations))
	}
	if c.DefaultQos.FiveQI != 7 {
		t.Errorf("5QI = %d, want 7", c.DefaultQos.FiveQI)
	}
}

func TestSeedSliceDNNQoSFromOperator_PerSliceDNNRows(t *testing.T) {
	st := NewInMemory()
	if _, err := SeedSliceDNNQoSFromOperator(ctx, st, nil, slog.Default()); err != nil {
		t.Fatal(err)
	}
	for _, k := range []SliceKey{NewSliceKey(1, "000001", "internet"), NewSliceKey(1, "000002", "gaming"),
		NewSliceKey(2, "000001", "ims"), NewSliceKey(3, "000001", "bronze")} {
		q, err := st.GetSliceDNNQoS(ctx, k.SST, k.SD, k.DNN)
		if err != nil || q == nil {
			t.Errorf("missing slice_dnn_qos row %v: %v", k, err)
		}
	}
}
