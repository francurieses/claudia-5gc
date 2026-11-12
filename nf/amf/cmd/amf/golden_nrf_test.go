package main

// golden_nrf_test.go - REL19-2.7 slice 6b-2 byte-identity goldens for the
// AMF's outbound Nnrf_NFDiscovery request. The expected request lines were
// verified against the pristine HEAD tree (before requester-features existed)
// and must keep passing UNCHANGED with no profile and under the explicit rel17
// profile (decision D2, dev/REL19_PROGRAM.md section 2). Each subtest builds
// its own NRF stub.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
)

const (
	nrfGoldenAnswer = `{"nfInstances":[{"nfInstanceId":"smf-1","ipv4Addresses":["10.0.0.5"],"nfServices":[{"ipEndPoints":[{"ipv4Address":"10.0.0.6","port":8000}]}]}]}`
	// goldenDiscoverURI: query keys sorted by url.Values.Encode.
	goldenDiscoverURI  = "/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&snssais=%5B%7B%22sst%22%3A1%2C%22sd%22%3A%22000001%22%7D%5D&target-nf-type=SMF"
	goldenDiscoverNoSl = "/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&target-nf-type=UDM"
)

type nrfStub struct {
	addr string
	hc   *http.Client
	seen *string
}

// newNRFStub answers every request with status/body and records the request
// line and the Accept / Content-Type headers.
func newNRFStub(t *testing.T, status int, body string) nrfStub {
	t.Helper()
	seen := new(string)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("stub: read body: %v", err)
		}
		*seen = r.Method + " " + r.URL.RequestURI() + " [" + r.Header.Get("Content-Type") + "] " + string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return nrfStub{strings.TrimPrefix(srv.URL, "https://"), srv.Client(), seen}
}

func TestGolden_NRFDiscoverRequests(t *testing.T) {
	sl := []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}
	tests := []struct {
		name string
		call func(c *HTTPNRFClient) error
		want string
	}{
		{"discover_with_slice", func(c *HTTPNRFClient) error {
			eps, err := c.Discover(t.Context(), "SMF", "AMF", sl)
			if err == nil && (len(eps) != 1 || eps[0].Address != "10.0.0.6:8000") {
				t.Errorf("endpoints: %+v", eps)
			}
			return err
		}, "GET " + goldenDiscoverURI + " [] "},
		{"discover_no_slice", func(c *HTTPNRFClient) error {
			_, err := c.Discover(t.Context(), "UDM", "AMF", nil)
			return err
		}, "GET " + goldenDiscoverNoSl + " [] "},
		{"discover_smf_address", func(c *HTTPNRFClient) error {
			addr, err := c.DiscoverSMFAddress(t.Context(), sl[0])
			if err == nil && addr != "10.0.0.6:8000" {
				t.Errorf("addr: %s", addr)
			}
			return err
		}, "GET " + goldenDiscoverURI + " [] "},
	}
	for _, mode := range []struct {
		name string
		p    *capability.Profile
	}{{"no-profile", nil}, {"explicit-rel17", testProfile(t, "rel17")}} {
		for _, tc := range tests {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				s := newNRFStub(t, http.StatusOK, nrfGoldenAnswer)
				if err := tc.call(newNRFClient(s.addr, s.hc, mode.p)); err != nil {
					t.Fatal(err)
				}
				if *s.seen != tc.want {
					t.Fatalf("request changed:\n got %s\nwant %s", *s.seen, tc.want)
				}
			})
		}
	}
}
