package store

import (
	"context"
	"log/slog"
	"testing"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

var (
	ctx      = context.Background()
	inet1    = NewSliceKey(1, "000001", "internet")
	slice1   = SNSSAISubscribed{SST: 1, SD: "000001"}
	slice2   = SNSSAISubscribed{SST: 2, SD: "000001"}
	amb20_30 = AMBR{Uplink: "20 Mbps", Downlink: "30 Mbps"}
)

func seedDefaults(t *testing.T, st Store, slices ...SNSSAISubscribed) *SeedResult {
	t.Helper()
	res, err := SeedSliceDNNQoSFromEntries(ctx, st, slices, nil)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return res
}

func mustGet(t *testing.T, st Store, k SliceKey) *SliceDNNQoS {
	t.Helper()
	q, err := st.GetSliceDNNQoS(ctx, k.SST, k.SD, k.DNN)
	if err != nil || q == nil {
		t.Fatalf("get %s: %v, %v", k, q, err)
	}
	return q
}

func TestSeed_InsertsDefaults(t *testing.T) {
	st := NewInMemory()
	res := seedDefaults(t, st, slice1, slice2)
	if res.Inserted != 2 || len(res.ChangedKeys) != 0 {
		t.Fatalf("inserted=%d changed=%v; defaults equal the fallback so nothing is stale", res.Inserted, res.ChangedKeys)
	}
	q := mustGet(t, st, inet1)
	if q.Source != SourceDefault || q.SeedSource != SourceDefault || q.SessionAMBR != (AMBR{"100 Mbps", "100 Mbps"}) {
		t.Errorf("unexpected row %+v", q)
	}
	rows, _ := st.ListSliceDNNQoS(ctx)
	if len(rows) != 2 || rows[0].SST != 1 || rows[1].SST != 2 {
		t.Errorf("list not sorted by sst/sd/dnn: %+v", rows)
	}
}

func TestSeed_RefreshesNonEditedFromOperator(t *testing.T) {
	st := NewInMemory()
	seedDefaults(t, st, slice1)
	entries := []OperatorSeedEntry{{Key: inet1, AMBR: AMBR{"50 Mbps", "60 Mbps"}}}
	res, err := SeedSliceDNNQoSFromEntries(ctx, st, []SNSSAISubscribed{slice1}, entries)
	if err != nil {
		t.Fatal(err)
	}
	if res.Refreshed != 1 || len(res.ChangedKeys) != 1 || res.ChangedKeys[0] != inet1 {
		t.Fatalf("res=%+v", res)
	}
	q := mustGet(t, st, inet1)
	if q.Source != SourceOperator || q.SessionAMBR != (AMBR{"50 Mbps", "60 Mbps"}) || q.SeedSource != SourceOperator {
		t.Errorf("row %+v", q)
	}
	// Idempotent second run: unchanged, no resync.
	res, _ = SeedSliceDNNQoSFromEntries(ctx, st, []SNSSAISubscribed{slice1}, entries)
	if res.Unchanged != 1 || len(res.ChangedKeys) != 0 {
		t.Errorf("second run res=%+v", res)
	}
}

func TestSeed_NewOperatorRowDifferingFromFallbackIsChanged(t *testing.T) {
	st := NewInMemory()
	res, _ := SeedSliceDNNQoSFromEntries(ctx, st, []SNSSAISubscribed{slice1},
		[]OperatorSeedEntry{{Key: inet1, AMBR: AMBR{"50 Mbps", "60 Mbps"}}})
	if len(res.ChangedKeys) != 1 {
		t.Errorf("inserted operator value != fallback must flag a resync: %+v", res)
	}
}

func TestSeed_DoesNotOverwriteEdited_ButUpdatesRevertTarget(t *testing.T) {
	st := NewInMemory()
	seedDefaults(t, st, slice1)
	if _, _, err := st.PutSliceDNNQoSEdited(ctx, 1, "000001", "internet", amb20_30, DefaultSliceDNNQoS(inet1)); err != nil {
		t.Fatal(err)
	}
	res, _ := SeedSliceDNNQoSFromEntries(ctx, st, []SNSSAISubscribed{slice1},
		[]OperatorSeedEntry{{Key: inet1, AMBR: AMBR{"50 Mbps", "60 Mbps"}}})
	if res.EditedKept != 1 || len(res.ChangedKeys) != 0 {
		t.Fatalf("res=%+v", res)
	}
	q := mustGet(t, st, inet1)
	if q.Source != SourceEdited || q.SessionAMBR != amb20_30 {
		t.Errorf("edited row overwritten: %+v", q)
	}
	if q.SeedAMBR != (AMBR{"50 Mbps", "60 Mbps"}) || q.SeedSource != SourceOperator {
		t.Errorf("seed_* not refreshed: %+v", q)
	}
	rev, changed, err := st.RevertSliceDNNQoS(ctx, 1, "000001", "internet")
	if err != nil || !changed || rev.Source != SourceOperator || rev.SessionAMBR != (AMBR{"50 Mbps", "60 Mbps"}) {
		t.Errorf("revert: %+v %v %v", rev, changed, err)
	}
}

func TestPutEditedAndRevert(t *testing.T) {
	st := NewInMemory()
	seedDefaults(t, st, slice1)
	created, changed, err := st.PutSliceDNNQoSEdited(ctx, 1, "000001", "INTERNET", amb20_30, DefaultSliceDNNQoS(inet1))
	if err != nil || created || !changed {
		t.Fatalf("put existing: created=%v changed=%v err=%v", created, changed, err)
	}
	if _, changed, _ = st.PutSliceDNNQoSEdited(ctx, 1, "000001", "internet", amb20_30, DefaultSliceDNNQoS(inet1)); changed {
		t.Error("identical PUT must report changed=false")
	}
	k3 := NewSliceKey(3, "00000A", "ims")
	created, _, _ = st.PutSliceDNNQoSEdited(ctx, 3, "00000A", "ims", amb20_30, DefaultSliceDNNQoS(k3))
	if !created {
		t.Error("unseeded key must be created")
	}
	q := mustGet(t, st, k3)
	if q.SD != "00000a" || q.SeedAMBR != (AMBR{"50 Mbps", "50 Mbps"}) || q.SeedSource != SourceDefault {
		t.Errorf("unseeded row %+v", q)
	}

	rev, changed, err := st.RevertSliceDNNQoS(ctx, 1, "000001", "internet")
	if err != nil || !changed || rev.Source != SourceDefault || rev.SessionAMBR != (AMBR{"100 Mbps", "100 Mbps"}) {
		t.Fatalf("revert: %+v %v %v", rev, changed, err)
	}
	if _, changed, _ = st.RevertSliceDNNQoS(ctx, 1, "000001", "internet"); changed {
		t.Error("revert of non-edited row must be a no-op")
	}
	if _, _, err = st.RevertSliceDNNQoS(ctx, 9, "ffffff", "nonexistent"); err != ErrNotFound {
		t.Errorf("missing key: got %v, want ErrNotFound", err)
	}
	if q, err := st.GetSliceDNNQoS(ctx, 9, "ffffff", "x"); q != nil || err != nil {
		t.Errorf("absent get: %v %v", q, err)
	}
}

func TestBuildSMSubscriptions_TableValueAndFallback(t *testing.T) {
	st := NewInMemory()
	seedDefaults(t, st, slice1)
	_, _, _ = st.PutSliceDNNQoSEdited(ctx, 1, "000001", "internet", amb20_30, DefaultSliceDNNQoS(inet1))
	f, err := SessionAMBRResolver(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	got := BuildSMSubscriptions([]SNSSAISubscribed{slice1, {SST: 1, SD: "000002"}, {SST: 1, SD: "000001", DNN: "ims"}}, f)
	if a := got[0].DNNConfigurations["internet"].SessionAMBR; a != amb20_30 {
		t.Errorf("table value not used: %+v", a)
	}
	if a := got[1].DNNConfigurations["internet"].SessionAMBR; a != (AMBR{"200 Mbps", "500 Mbps"}) {
		t.Errorf("no row must fall back to DefaultAMBRForSlice: %+v", a)
	}
	if a := got[2].DNNConfigurations["ims"].SessionAMBR; a != (AMBR{"100 Mbps", "100 Mbps"}) {
		t.Errorf("other DNN on same slice must not take the internet value: %+v", a)
	}
	// nil resolver keeps the pure default.
	if a := BuildSMSubscriptions([]SNSSAISubscribed{slice1}, nil)[0].DNNConfigurations["internet"].SessionAMBR; a.Uplink != "100 Mbps" {
		t.Errorf("nil resolver: %+v", a)
	}
}

func putAM(t *testing.T, st Store, supi string, ns ...SNSSAISubscribed) {
	t.Helper()
	if err := st.PutAMSubscription(&AccessAndMobilitySubscriptionData{SUPI: supi, NSSAI: AllowedNSSAI{SNSSAIs: ns}}); err != nil {
		t.Fatal(err)
	}
}

func TestListSUPIsForSliceDNN_EmptyDNNIsInternet(t *testing.T) {
	st := NewInMemory()
	putAM(t, st, "imsi-001010000000001", slice1) // dnn "" -> internet
	putAM(t, st, "imsi-001010000000002", SNSSAISubscribed{SST: 1, SD: "000001", DNN: "Internet"})
	putAM(t, st, "imsi-001010000000003", SNSSAISubscribed{SST: 1, SD: "000001", DNN: "ims"})
	putAM(t, st, "imsi-001010000000004", slice2)
	got, _ := st.ListSUPIsForSliceDNN(ctx, 1, "000001", "internet")
	if len(got) != 2 || got[0] != "imsi-001010000000001" || got[1] != "imsi-001010000000002" {
		t.Errorf("internet: %v", got)
	}
	if got, _ = st.ListSUPIsForSliceDNN(ctx, 1, "000001", "ims"); len(got) != 1 {
		t.Errorf("ims: %v", got)
	}
}

func TestSyncSMDataFromAM_AfterEdit(t *testing.T) {
	st := NewInMemory()
	const supi = "imsi-001010000000001"
	seedDefaults(t, st, slice1)
	putAM(t, st, supi, slice1)
	if _, err := SyncSMDataFromAM(st, supi); err != nil {
		t.Fatal(err)
	}
	_, _, _ = st.PutSliceDNNQoSEdited(ctx, 1, "000001", "internet", amb20_30, DefaultSliceDNNQoS(inet1))
	rr, err := ResyncSliceDNN(ctx, st, inet1)
	if err != nil || rr.Affected != 1 || rr.Synced != 1 || len(rr.Failed) != 0 {
		t.Fatalf("resync %+v %v", rr, err)
	}
	subs, _ := st.GetSMSubscriptions(supi)
	if a := subs[0].DNNConfigurations["internet"].SessionAMBR; a != amb20_30 {
		t.Errorf("sm-data not re-derived: %+v", a)
	}
	_, _, _ = st.RevertSliceDNNQoS(ctx, 1, "000001", "internet")
	_, _ = ResyncSliceDNN(ctx, st, inet1)
	subs, _ = st.GetSMSubscriptions(supi)
	if a := subs[0].DNNConfigurations["internet"].SessionAMBR; a.Uplink != "100 Mbps" {
		t.Errorf("revert not propagated: %+v", a)
	}
}

func TestSeedTestSubscriber_UsesTable(t *testing.T) {
	st := NewInMemory()
	seedDefaults(t, st, slice1)
	_, _, _ = st.PutSliceDNNQoSEdited(ctx, 1, "000001", "internet", amb20_30, DefaultSliceDNNQoS(inet1))
	if err := SeedTestSubscriber(st, "imsi-001010000000009", "00", "00", "8000", "000000000001"); err != nil {
		t.Fatal(err)
	}
	subs, _ := st.GetSMSubscriptions("imsi-001010000000009")
	if a := subs[0].DNNConfigurations["internet"].SessionAMBR; a != amb20_30 {
		t.Errorf("seeded subscriber ignores table: %+v", a)
	}
}

func TestSeed_IncludesSlicesInUseFromAM(t *testing.T) {
	st := NewInMemory()
	putAM(t, st, "imsi-001010000000001", SNSSAISubscribed{SST: 1, SD: "001234", DNN: "gaming"})
	seedDefaults(t, st)
	if q, _ := st.GetSliceDNNQoS(ctx, 1, "001234", "gaming"); q == nil {
		t.Error("slice/DNN used in am-data must be seeded")
	}
}

func TestOperatorSeedEntries_Validation(t *testing.T) {
	op := &operatorcfg.OperatorConfig{
		SNSSAIs: []operatorcfg.SNSSAIEntry{{SST: 1, SD: "000001"}},
		SliceDNNQoS: []operatorcfg.SliceDNNQoSEntry{
			{SST: 1, SD: "000001", DNN: "internet", SessionAMBR: operatorcfg.SessionAMBREntry{Uplink: "50 Mbps", Downlink: "60 Mbps"}},
			{SST: 1, SD: "000001", DNN: "ims", SessionAMBR: operatorcfg.SessionAMBREntry{Uplink: "50Mbps", Downlink: "60 Mbps"}},
			{SST: 1, SD: "zz", DNN: "internet", SessionAMBR: operatorcfg.SessionAMBREntry{Uplink: "5 Mbps", Downlink: "6 Mbps"}},
			{SST: 300, SD: "000001", DNN: "internet", SessionAMBR: operatorcfg.SessionAMBREntry{Uplink: "5 Mbps", Downlink: "6 Mbps"}},
			{SST: 9, SD: "000001", DNN: "internet", SessionAMBR: operatorcfg.SessionAMBREntry{Uplink: "5 Mbps", Downlink: "6 Mbps"}},
			{SST: 1, SD: "000001", DNN: "", SessionAMBR: operatorcfg.SessionAMBREntry{Uplink: "5 Mbps", Downlink: "6 Mbps"}},
		},
	}
	got := OperatorSeedEntries(op, slog.New(slog.DiscardHandler))
	if len(got) != 1 || got[0].Key != inet1 || got[0].AMBR.Downlink != "60 Mbps" {
		t.Errorf("got %+v", got)
	}
	if OperatorSeedEntries(nil, nil) != nil {
		t.Error("nil operator config must yield no entries")
	}
}

func TestSeedAndResync_OperatorChangeResyncsSubscribers(t *testing.T) {
	st := NewInMemory()
	const supi = "imsi-001010000000001"
	if err := SeedTestSubscriber(st, supi, "00", "00", "8000", "000000000001"); err != nil {
		t.Fatal(err)
	}
	op := &operatorcfg.OperatorConfig{
		SNSSAIs: []operatorcfg.SNSSAIEntry{{SST: 1, SD: "000001"}},
		SliceDNNQoS: []operatorcfg.SliceDNNQoSEntry{
			{SST: 1, SD: "000001", DNN: "internet", SessionAMBR: operatorcfg.SessionAMBREntry{Uplink: "50 Mbps", Downlink: "60 Mbps"}},
		},
	}
	res, err := SeedAndResyncSliceDNNQoS(ctx, st, op, slog.New(slog.DiscardHandler))
	if err != nil || res.Resynced != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	subs, _ := st.GetSMSubscriptions(supi)
	if a := subs[0].DNNConfigurations["internet"].SessionAMBR; a != (AMBR{"50 Mbps", "60 Mbps"}) {
		t.Errorf("sm-data not resynced: %+v", a)
	}
}
