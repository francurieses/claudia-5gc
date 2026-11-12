package server

// gpsi_test.go - AMF-020: the UDR serves AccessAndMobilitySubscriptionData.gpsis
// under the Rel-19 profile only (TS 29.503 §6.1.6.2.4 / TS 29.505, Gpsi
// pattern TS 29.571 §5.3.2). The legacy byte-identity proof is
// TestGolden_UDRAMGetWithStoredGPSIsLegacy.

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// profileFor returns the named release profile, nil for "".
func profileFor(t *testing.T, name string) *capability.Profile {
	t.Helper()
	if name == "" {
		return nil
	}
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func getAMGPSIs(t *testing.T, stored []string, profile string) (present bool, got []string) {
	t.Helper()
	prof := profileFor(t, profile)
	ts := goldenServerWithGPSIs(t, prof, stored)
	resp, err := ts.Client().Get(ts.URL + "/nudr-dr/v2/subscription-data/" + goldenSUPI + "/00101/provisioned-data/am-data")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var body struct {
		GPSIs *[]string `json:"gpsis"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.GPSIs == nil {
		return false, nil
	}
	return true, *body.GPSIs
}

func TestAMDataGPSIs(t *testing.T) {
	tests := []struct {
		name        string
		stored      []string
		profile     string
		wantPresent bool
		want        []string
	}{
		{"rel19 msisdn", []string{"msisdn-490123456789"}, "rel19", true, []string{"msisdn-490123456789"}},
		{"rel19 order kept, duplicate dropped", []string{"extid-u@x.org", "msisdn-490123456789", "extid-u@x.org"}, "rel19", true, []string{"extid-u@x.org", "msisdn-490123456789"}},
		{"rel19 invalid skipped", []string{"", "bad\nline", "msisdn-490123456789"}, "rel19", true, []string{"msisdn-490123456789"}},
		{"rel19 only invalid -> absent", []string{"", "x\ny"}, "rel19", false, nil},
		{"rel19 none stored -> absent", nil, "rel19", false, nil},
		{"rel17 stored GPSIs not emitted", []string{"msisdn-490123456789"}, "rel17", false, nil},
		{"no profile stored GPSIs not emitted", []string{"msisdn-490123456789"}, "", false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			present, got := getAMGPSIs(t, tc.stored, tc.profile)
			if present != tc.wantPresent || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("gpsis present=%v %v, want present=%v %v", present, got, tc.wantPresent, tc.want)
			}
		})
	}
}
