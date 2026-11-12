package server

// wire_golden_test.go - REL19-3.5 slice 2 byte-identity goldens for the LMF
// wire shapes whose JSON is gated by the release profile. The goldens under
// testdata/ were captured at the pre-change HEAD (git worktree,
// UPDATE_GOLDEN=1); they must never be regenerated on a changed tree.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fullLocationData is a LocationData with every field populated.
func fullLocationData() LocationData {
	return LocationData{
		LocationEstimate:      &GeographicArea{Shape: "POINT", Point: &LatLon{Lat: 40.416775, Lon: -3.70379}},
		NRCellId:              "000000010",
		Tai:                   &TaiLoc{PlmnId: PlmnID{MCC: "001", MNC: "01"}, Tac: "0001"},
		AgeOfLocationEstimate: 3,
		PositioningDataList:   []string{"eCID"},
		SupportedFeatures:     "1",
	}
}

// TestGolden_AMFRequestBody pins the raw Namf_Location request body the LMF
// client sends (no profile and rel17 are the same client default).
func TestGolden_AMFRequestBody(t *testing.T) {
	var raw []byte
	amf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rerr error
		raw, rerr = io.ReadAll(r.Body)
		if rerr != nil {
			t.Errorf("read request body: %v", rerr)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nrCellId":"000000010","ageOfLocationEstimate":0}`))
	}))
	defer amf.Close()
	c := &HTTPAMFLocationClient{BaseURL: amf.URL, Client: amf.Client()}
	if _, _, err := c.ProvideLocationInfo(t.Context(), "imsi-001010000000001"); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "golden_amf_request_body.txt", string(raw))
}

// TestGolden_LocationDataMarshal pins json.Marshal of the Nlmf LocationData,
// of the legacy notification envelope that embeds it, and of locationDataExt.
func TestGolden_LocationDataMarshal(t *testing.T) {
	ld := fullLocationData()
	a, err := json.Marshal(ld)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(LocationNotification{SubId: "sub-1", NotificationItems: []NotificationItem{{LocationData: ld}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(locationDataExt{LocationData: ld, TimestampOfLocationEstimate: "2026-01-01T00:00:00Z",
		AcceptedPeriodicEventInfo: &periodicEventInfo{ReportingAmount: 2, ReportingInterval: 1}})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "golden_locationdata_marshal.txt", string(a)+"\n"+string(b)+"\n"+string(c)+"\n")
}
