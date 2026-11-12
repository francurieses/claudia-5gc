package server

// gpsi_golden_test.go - AMF-020 byte-identity golden: a subscriber whose
// stored record carries GPSIs must still be served WITHOUT a gpsis attribute
// under rel17 / no profile. Captured at HEAD 430aa9e (before gpsis emission
// existed); it must pass UNCHANGED.

import (
	"net/http"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

func TestGolden_UDRAMGetWithStoredGPSIsLegacy(t *testing.T) {
	gp := []string{"msisdn-490123456789", "extid-user@example.com"}
	p17, err := capability.NewProfile(capability.ReleaseConfig{Profile: "rel17"}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]*capability.Profile{"no-profile": nil, "explicit-rel17": p17} {
		t.Run(name, func(t *testing.T) {
			ts := goldenServerWithGPSIs(t, p, gp)
			got := renderResp(t, ts, http.MethodGet, "/nudr-dr/v2/subscription-data/"+goldenSUPI+"/00101/provisioned-data/am-data", "")
			checkGolden(t, "golden_udr_am_get_gpsi_200.txt", got)
		})
	}
}
