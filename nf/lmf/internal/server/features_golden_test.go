package server

// features_golden_test.go - byte-identity golden for the LMF Nlmf_Location
// DetermineLocation answer (REL19-2.7 slice 3). Captured against the
// pre-change code (git worktree at HEAD); it must pass UNCHANGED under rel17 /
// no profile for a request WITHOUT supportedFeatures (decision D1,
// dev/REL19_PROGRAM.md section 2). The mock AMF returns a non-zero POINT so the
// time-dependent mobility model is not involved.

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkGolden compares got with testdata/<name>. UPDATE_GOLDEN=1 rewrites the
// file; only ever used on the pre-change tree (git worktree at HEAD).
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if got != string(b) {
		t.Fatalf("%s changed\n got: %q\nwant: %q", name, got, b)
	}
}

func goldenAMF() *mockAMFClient {
	return &mockAMFClient{
		ProvideFunc: func(_ context.Context, _ string) (*LocationData, string, error) {
			return &LocationData{
				LocationEstimate: &GeographicArea{Shape: "POINT", Point: &LatLon{Lat: 40.416775, Lon: -3.70379}},
				NRCellId:         "000000010",
				Tai:              &TaiLoc{PlmnId: PlmnID{MCC: "001", MNC: "01"}, Tac: "0001"},
			}, "", nil
		},
	}
}

func TestGolden_DetermineLocation(t *testing.T) {
	ts := newTestServer(t, goldenAMF())
	defer ts.Close()
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/nlmf-loc/v1/determine-location",
		strings.NewReader(`{"supi":"imsi-001010000000001"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	checkGolden(t, "golden_determine_location_200.txt",
		"status: "+http.StatusText(resp.StatusCode)+"\n"+
			"Content-Type: "+resp.Header.Get("Content-Type")+"\n\n"+string(raw))
}

// TestGolden_DetermineLocation_ExplicitRel17 is the explicit-profile pass of the
// byte-identity golden (REL19-3.5 slice B: the Nlmf answer is unchanged by the
// LocationData / AMF-answer split). Same input and golden file as above.
func TestGolden_DetermineLocation_ExplicitRel17(t *testing.T) {
	ts, _ := newFeatureLMF(t, profileNamed(t, "rel17"), nil)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/nlmf-loc/v1/determine-location",
		strings.NewReader(`{"supi":"imsi-001010000000001"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	checkGolden(t, "golden_determine_location_200.txt",
		"status: "+http.StatusText(resp.StatusCode)+"\n"+
			"Content-Type: "+resp.Header.Get("Content-Type")+"\n\n"+string(raw))
}
