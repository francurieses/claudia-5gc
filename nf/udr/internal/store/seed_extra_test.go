package store

import (
	"reflect"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/types"
)

func TestParseSeedSUPIs(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantValid   []string
		wantInvalid []string
	}{
		{"empty", "", nil, nil},
		{"single", "imsi-001010000000101", []string{"imsi-001010000000101"}, nil},
		{"trim and dedupe", " imsi-001010000000101 , imsi-001010000000101,imsi-001010000000102 ",
			[]string{"imsi-001010000000101", "imsi-001010000000102"}, nil},
		{"invalid kept apart", "imsi-1,imsi-001010000000101,foo",
			[]string{"imsi-001010000000101"}, []string{"imsi-1", "foo"}},
		{"only separators", " , ,", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, invalid := ParseSeedSUPIs(tt.raw)
			if !reflect.DeepEqual(valid, tt.wantValid) || !reflect.DeepEqual(invalid, tt.wantInvalid) {
				t.Errorf("ParseSeedSUPIs(%q) = %v, %v; want %v, %v", tt.raw, valid, invalid, tt.wantValid, tt.wantInvalid)
			}
		})
	}
}

func TestSliceProfileForSUPI(t *testing.T) {
	in := SNSSAISubscribed{SST: 1, SD: "000001"}
	profiles := [][]SNSSAISubscribed{
		{in},
		{in, {SST: 1, SD: "000002"}},
		{in, {SST: 2, SD: "000001"}},
		{in, {SST: 3, SD: "000001"}},
	}
	tests := []struct {
		supi string
		want int
	}{
		{"imsi-001010000000101", 0},
		{"imsi-001010000000201", 0},
		{"imsi-001010000000202", 1},
		{"imsi-001010000000203", 2},
		{"imsi-001010000000204", 3},
		{"imsi-001010000000301", 0},
		{"imsi-001010000000003", 2},
		{"imsi-001010000000000", 0},
		{"garbage", 0},
	}
	for _, tc := range tests {
		got := SliceProfileForSUPI(tc.supi, profiles)
		if !reflect.DeepEqual(got, profiles[tc.want]) {
			t.Errorf("%s: got %v want profile %d", tc.supi, got, tc.want)
		}
	}
	if SliceProfileForSUPI("imsi-001010000000001", nil) != nil {
		t.Error("empty profiles must return nil")
	}
}

func TestSeedMSISDN(t *testing.T) {
	tests := []struct {
		supi, prefix, want string
		ok                 bool
	}{
		{"imsi-001010000000001", "490", "msisdn-4900000000001", true},
		{"imsi-001010000000204", "490", "msisdn-4900000000204", true},
		{"imsi-001010000000001", "", "msisdn-0000000001", true},
		{"imsi-001010000000001", "49", "msisdn-490000000001", true},
		{"imsi-001010000000001", "4a", "", false},
		{"imsi-001010000000001", "123456", "", false}, // 16 digits
		{"imsi-0010100000", "490", "", false},
		{"nai-foo", "490", "", false},
	}
	for _, tc := range tests {
		got, ok := SeedMSISDN(tc.supi, tc.prefix)
		if got != tc.want || ok != tc.ok {
			t.Errorf("SeedMSISDN(%q,%q) = %q,%v want %q,%v", tc.supi, tc.prefix, got, ok, tc.want, tc.ok)
		}
		if ok && !types.ValidGpsi(got) {
			t.Errorf("%q does not match the Gpsi pattern", got)
		}
	}
}

func TestSeedMSISDNStrict(t *testing.T) {
	for _, supi := range []string{"imsi-001010000000001", "imsi-001019999999999"} {
		g, ok := SeedMSISDN(supi, DefaultSeedMSISDNPrefix)
		if !ok || !types.StrictGpsi(g) {
			t.Errorf("SeedMSISDN(%q) = %q,%v not strict", supi, g, ok)
		}
	}
}

func seededAM(t *testing.T, st Store, supi string, gpsis []string) {
	t.Helper()
	if err := SeedTestSubscriber(st, supi, "00", "00", "b9b9", "000000000020"); err != nil {
		t.Fatal(err)
	}
	am, _ := st.GetAMSubscription(supi)
	cp := *am
	cp.GPSIS = gpsis
	if err := st.PutAMSubscription(&cp); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureSeedGPSI(t *testing.T) {
	const supi = "imsi-001010000000001"
	st := NewInMemory()
	seededAM(t, st, supi, nil)
	added, err := EnsureSeedGPSI(st, supi, DefaultSeedMSISDNPrefix)
	if err != nil || !added {
		t.Fatalf("first call added=%v err=%v", added, err)
	}
	am, _ := st.GetAMSubscription(supi)
	if len(am.GPSIS) != 1 || am.GPSIS[0] != "msisdn-4900000000001" {
		t.Fatalf("GPSIS = %v", am.GPSIS)
	}
	// Idempotent and never replaces provisioned GPSIs.
	am.GPSIS = []string{"extid-op@example.com"}
	if err := st.PutAMSubscription(am); err != nil {
		t.Fatal(err)
	}
	if added, err := EnsureSeedGPSI(st, supi, DefaultSeedMSISDNPrefix); err != nil || added {
		t.Fatalf("second call added=%v err=%v", added, err)
	}
	am, _ = st.GetAMSubscription(supi)
	if len(am.GPSIS) != 1 || am.GPSIS[0] != "extid-op@example.com" {
		t.Fatalf("provisioned GPSI replaced: %v", am.GPSIS)
	}
}

// A subscriber with auth data but no AM row is a quiet skip, not an error.
func TestEnsureSeedGPSINoAMRow(t *testing.T) {
	st := NewInMemory()
	added, err := EnsureSeedGPSI(st, "imsi-001019999999999", "490")
	if err != nil || added {
		t.Fatalf("added=%v err=%v, want false,nil", added, err)
	}
}

// Only the gpsis column changes: every other AM field survives the backfill.
func TestSetGPSIsIfEmptyOnlyTouchesGPSIs(t *testing.T) {
	const supi = "imsi-001010000000002"
	st := NewInMemory()
	seededAM(t, st, supi, nil)
	before, _ := st.GetAMSubscription(supi)
	snap := *before
	if ok, err := st.SetGPSIsIfEmpty(supi, []string{"msisdn-12345"}); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	after, _ := st.GetAMSubscription(supi)
	snap.GPSIS = []string{"msisdn-12345"}
	if !reflect.DeepEqual(*after, snap) {
		t.Fatalf("other fields changed: %+v vs %+v", *after, snap)
	}
}

func TestSetGPSIsIfEmptySQL(t *testing.T) {
	sql := strings.Join(strings.Fields(setGPSIsIfEmptySQL), " ")
	want := "UPDATE subscription_am SET gpsis = $1 WHERE supi = $2 AND (CASE WHEN jsonb_typeof(gpsis) = 'array' THEN jsonb_array_length(gpsis) = 0 ELSE true END)"
	if sql != want {
		t.Fatalf("SQL = %q", sql)
	}
}
