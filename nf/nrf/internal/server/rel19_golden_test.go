package server

// rel19_golden_test.go - rel19 wire-shape goldens (NRF-003). The rel17
// goldens (features_golden_test.go) stay frozen; these capture the spec-literal
// responses under the rel19 profile. Only generated ids are masked (render).
// Regenerate with UPDATE_GOLDEN=1 go test -run TestGolden_NRFRel19 (never
// against the rel17 goldens).

import (
	"net/http"
	"testing"
)

func TestGolden_NRFRel19(t *testing.T) {
	regA := goldenReq{http.MethodPut, "/nnrf-nfm/v1/nf-instances/" + goldenIDA, goldenSMF}
	regB := goldenReq{http.MethodPut, "/nnrf-nfm/v1/nf-instances/" + goldenIDB, goldenSMFMap}
	steps := []struct {
		name, golden string
		setup        []goldenReq
		goldenReq
	}{
		// One NF per target type: deterministic instance order.
		{"discover array no features", "golden_nrf_rel19_discover_array_200.txt", []goldenReq{regA},
			goldenReq{http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF", ""}},
		{"discover array service-map", "golden_nrf_rel19_discover_array_servicemap_200.txt", []goldenReq{regA},
			goldenReq{http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&requester-features=20", ""}},
		{"discover map no features", "golden_nrf_rel19_discover_map_200.txt", []goldenReq{regB},
			goldenReq{http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF", ""}},
		{"discover map service-map", "golden_nrf_rel19_discover_map_servicemap_200.txt", []goldenReq{regB},
			goldenReq{http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF&requester-features=20", ""}},
		{"discover bad requester-features", "golden_nrf_rel19_discover_badrf_400.txt", nil,
			goldenReq{http.MethodGet, "/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&requester-features=zz", ""}},
		{"retrieve no features", "golden_nrf_rel19_get_200.txt", []goldenReq{regA},
			goldenReq{http.MethodGet, "/nnrf-nfm/v1/nf-instances/" + goldenIDA, ""}},
		{"retrieve service-map", "golden_nrf_rel19_get_servicemap_200.txt", []goldenReq{regA},
			goldenReq{http.MethodGet, "/nnrf-nfm/v1/nf-instances/" + goldenIDA + "?requester-features=1", ""}},
		{"subscribe", "golden_nrf_rel19_subscribe_201.txt", nil, goldenReq{http.MethodPost, "/nnrf-nfm/v1/subscriptions",
			`{"nfStatusNotificationUri":"http://amf.5gc/cb","reqNfType":"AMF","validityTime":"2030-01-01T00:00:00Z","requesterFeatures":"1"}`}},
		{"subscribe no uri", "golden_nrf_rel19_subscribe_400.txt", nil,
			goldenReq{http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{"reqNfType":"AMF"}`}},
		{"subscribe malformed", "golden_nrf_rel19_subscribe_malformed_400.txt", nil,
			goldenReq{http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{`}},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			s := newTestServer(t)
			s.SetProfile(profileNamed(t, "rel19"))
			for _, pre := range st.setup {
				if rec := do(t, s, pre.method, pre.path, pre.body); rec.Code != http.StatusCreated {
					t.Fatalf("setup %s %s: %d %s", pre.method, pre.path, rec.Code, rec.Body)
				}
			}
			checkGolden(t, st.golden, renderWith(do(t, s, st.method, st.path, st.body), reSubIDHyphenless))
		})
	}
}
