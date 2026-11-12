package main

// nrf_features_test.go - REL19-2.7 slice 6b-2 consumer side of
// Nnrf_NFDiscovery in the AMF: requester-features offer (decision D2: rel17
// sends nothing, rel19 sends the offer, "0" when nothing is implemented) and
// the negotiation with SearchResult.nrfSupportedFeatures (rules R11-R14).
// The rel17 bytes are pinned by golden_nrf_test.go.
// Ref: TS 29.500 §6.6.2; TS 29.510 §6.2.3.2.3.1, §6.2.6.2.2, §6.2.9.

import (
	"net/http"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// newNRFClient builds the discovery client under test (golden_nrf_test.go
// calls it for the rel17 modes).
func newNRFClient(addr string, hc *http.Client, p *capability.Profile) *HTTPNRFClient {
	return NewHTTPNRFClient(addr, hc).WithFeatures(p, nil)
}

func TestNRFDiscoverOfferAndAccept(t *testing.T) {
	// Bits 1 and 2 of Nnrf_NFDiscovery implemented, to exercise intersections.
	disc := features.MustCatalog(features.MustImplement(features.NnrfNFDiscoveryEntries(), 1, 2)...)
	sl := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	const noFeat = `{"nfInstances":[{"nfInstanceId":"smf-1","ipv4Addresses":["10.0.0.5"]}]}`
	withFeat := func(v string) string {
		return `{"nrfSupportedFeatures":"` + v + `","nfInstances":[{"nfInstanceId":"smf-1","ipv4Addresses":["10.0.0.5"]}]}`
	}
	tests := []struct {
		name, profile string
		cat           *features.Catalog
		answer        string
		wantQuery     string // requester-features sorts before requester-nf-type
		wantPeer      string
		wantLocal     string
		wantNeg       string
		wantResult    string
	}{
		{"rel17 absent", "rel17", nil, noFeat, "", "absent", "0", "0", "OK"},
		{"rel17 NRF answers anyway (R14)", "rel17", disc, withFeat("3"), "", "3", "3", "0", "OK"},
		{"rel19 offer 0, answer absent (R12)", "rel19", nil, noFeat, "requester-features=0&", "absent", "0", "0", "OK"},
		{"rel19 offer 0, answer 7", "rel19", nil, withFeat("7"), "requester-features=0&", "7", "0", "0", "OK"},
		{"rel19 offer 3, answer 2 is the NRF set", "rel19", disc, withFeat("2"), "requester-features=3&", "2", "3", "2", "OK"},
		{"rel19 answer has bits never offered (R11)", "rel19", disc, withFeat("ff"), "requester-features=3&", "ff", "3", "3", "OK"},
		{"rel19 uppercase hex answer", "rel19", disc, withFeat("1F"), "requester-features=3&", "1F", "3", "3", "OK"},
		{"rel19 malformed answer with offer (R13)", "rel19", disc, withFeat("zz"), "requester-features=3&", "zz", "3", "0", "FAILURE"},
		{"rel19 malformed answer with offer 0 (R14)", "rel19", nil, withFeat("zz"), "requester-features=0&", "zz", "0", "0", "FAILURE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newNRFStub(t, http.StatusOK, tc.answer)
			logs, logger := newLogs()
			c := NewHTTPNRFClient(s.addr, s.hc).WithFeatures(testProfile(t, tc.profile), logger)
			c.catalog = tc.cat
			eps, err := c.Discover(t.Context(), "SMF", "AMF", sl)
			if err != nil || len(eps) != 1 || eps[0].InstanceID != "smf-1" {
				t.Fatalf("discovery must continue: eps=%+v err=%v", eps, err)
			}
			want := "GET /nnrf-disc/v1/nf-instances?" + tc.wantQuery +
				"requester-nf-type=AMF&snssais=%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D%5D&target-nf-type=SMF [] "
			if *s.seen != want {
				t.Errorf("request\n got %s\nwant %s", *s.seen, want)
			}
			r := oneRecord(t, logs)
			if r["interface"] != "Nnrf" || r["peer_nf_type"] != "NRF" || r["target_nf_type"] != "SMF" ||
				r["features_peer"] != tc.wantPeer || r["features_local"] != tc.wantLocal ||
				r["features_negotiated"] != tc.wantNeg || r["result"] != tc.wantResult {
				t.Errorf("record %v", r)
			}
			if tc.wantResult == "FAILURE" && (r["level"] != "WARN" || r["error"] == nil) {
				t.Errorf("FAILURE must be WARN with an error: %v", r)
			}
		})
	}
}

// TestNRFDiscoverErrorNotNegotiated: a non-200 answer negotiates nothing.
func TestNRFDiscoverErrorNotNegotiated(t *testing.T) {
	s := newNRFStub(t, http.StatusNotFound, `{"nrfSupportedFeatures":"3"}`)
	logs, logger := newLogs()
	c := NewHTTPNRFClient(s.addr, s.hc).WithFeatures(testProfile(t, "rel19"), logger)
	if _, err := c.Discover(t.Context(), "SMF", "AMF", nil); err == nil {
		t.Fatal("Discover on 404 must fail")
	}
	if recs := negRecords(t, logs); len(recs) != 0 {
		t.Fatalf("records = %v", recs)
	}
}
