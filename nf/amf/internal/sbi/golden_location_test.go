package sbi

// golden_location_test.go - REL19-3.5 slice B byte-identity goldens for the
// Namf_Location ProvideLocationInfo answer. The rel17 / no-profile goldens were
// captured from the pre-change code (git worktree at bf9dd80, UPDATE_GOLDEN=1)
// and must pass UNCHANGED (decision D1: rel17 is the frozen wire baseline).
// Ref: TS 29.518 §5.2.2.6, §6.1.6.2.x (ProvideLocInfo); TS 29.500 §6.6.2.

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

// checkLocGolden compares got with testdata/<name>. UPDATE_GOLDEN=1 rewrites
// the file; only used on the pre-change tree (rel17 goldens) or to author the
// reviewed rel19 golden.
func checkLocGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s changed\n got: %q\nwant: %q", name, got, want)
	}
}

// provideLocInfoBody drives one ProvideLocationInfo exchange for a CM-CONNECTED
// UE served by a fake locator and returns the raw 200 body.
func provideLocInfoBody(t *testing.T, p *capability.Profile) []byte {
	t.Helper()
	srv, mgr := newTestServer(t)
	if p != nil {
		srv.SetProfile(p)
	}
	seedConnectedUE(mgr, "imsi-001010000000001")
	srv.SetLocator(&fakeLocator{result: ngap.LocationResult{
		NRCellID: "000000042",
		TAI:      &ngap.TAI{MCC: "001", MNC: "01", TAC: 1},
	}})
	resp, raw := postLocInfo(t, srv, "imsi-001010000000001", []byte(`{"req5gsLoc":true}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	return raw
}

func TestGolden_ProvideLocInfo_Rel17(t *testing.T) {
	t.Run("no profile", func(t *testing.T) {
		checkLocGolden(t, "provide_loc_info_rel17_200.json", provideLocInfoBody(t, nil))
	})
	t.Run("explicit rel17", func(t *testing.T) {
		checkLocGolden(t, "provide_loc_info_rel17_200.json", provideLocInfoBody(t, profileNamed(t, "rel17")))
	})
}
