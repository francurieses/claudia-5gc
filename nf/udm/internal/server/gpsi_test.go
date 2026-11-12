package server

// gpsi_test.go - AMF-020: the UDM decodes AccessAndMobilitySubscriptionData.gpsis
// from the UDR answer under any profile and emits it in the Nudm_SDM am-data
// response under the Rel-19 profile only (TS 29.503 §6.1.6.2.4). The legacy
// byte-identity proof is TestGolden_SDMAMDataUDRGPSIsLegacy.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestUDRClientDecodesGPSIs(t *testing.T) {
	tests := []struct {
		name, profile, am string
		want              []string
	}{
		{"with gpsis rel17", "rel17", goldenUDRAMGPSIRsp, []string{"msisdn-490123456789", "extid-user@example.com"}},
		{"with gpsis rel19", "rel19", goldenUDRAMGPSIRsp, []string{"msisdn-490123456789", "extid-user@example.com"}},
		{"without gpsis", "rel19", goldenUDRAMRsp, nil},
		{"invalid skipped", "rel19", `{"gpsis":["","msisdn-490123456789","a\nb"],"nssai":{"defaultSingleNssais":[]}}`, []string{"msisdn-490123456789"}},
		{"empty array", "rel19", `{"gpsis":[],"nssai":{"defaultSingleNssais":[]}}`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newUDRStub(t, map[string]string{"am": tc.am})
			c := newTestUDRClient(st.address(), st.srv.Client(), profileNamed(t, tc.profile))
			got, err := c.GetAMData(context.Background(), goldenUDRSupi)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.GPSIs, tc.want) {
				t.Fatalf("GPSIs = %v, want %v", got.GPSIs, tc.want)
			}
		})
	}
}

func TestSDMAMDataEmitsGPSIsRel19Only(t *testing.T) {
	tests := []struct {
		name, profile, am string
		want              []string
	}{
		{"rel19 with gpsis", "rel19", goldenUDRAMGPSIRsp, []string{"msisdn-490123456789", "extid-user@example.com"}},
		{"rel19 without gpsis", "rel19", goldenUDRAMRsp, nil},
		{"rel17 with gpsis", "rel17", goldenUDRAMGPSIRsp, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newUDRStub(t, map[string]string{"am": tc.am})
			p := profileNamed(t, tc.profile)
			s := newSDMGoldenUDMWith(t, p, newTestUDRClient(st.address(), st.srv.Client(), p))
			r := httptest.NewRequest(http.MethodGet, "/nudm-sdm/v2/"+goldenUDRSupi+"/am-data", nil)
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			var body struct {
				GPSIs []string `json:"gpsis"`
			}
			if err := json.NewDecoder(strings.NewReader(w.Body.String())).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(body.GPSIs, tc.want) {
				t.Fatalf("gpsis = %v, want %v (body %s)", body.GPSIs, tc.want, w.Body)
			}
		})
	}
}

// Under rel17 nothing is emitted, so the invalid-entry WARN must not fire;
// under rel19 it fires once per rejected entry.
func TestUDRClientGPSIWarnOnlyRel19(t *testing.T) {
	const am = `{"gpsis":["","msisdn-490123456789"],"nssai":{"defaultSingleNssais":[]}}`
	for _, tc := range []struct {
		profile string
		warns   int
	}{{"rel17", 0}, {"rel19", 1}} {
		t.Run(tc.profile, func(t *testing.T) {
			st := newUDRStub(t, map[string]string{"am": am})
			var buf bytes.Buffer
			c := NewHTTPUDRClient(st.address(), st.srv.Client()).
				WithFeatures(profileNamed(t, tc.profile), slog.New(slog.NewJSONHandler(&buf, nil)))
			if _, err := c.GetAMData(context.Background(), goldenUDRSupi); err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(buf.String(), "INVALID_GPSI"); n != tc.warns {
				t.Fatalf("INVALID_GPSI logs = %d, want %d: %s", n, tc.warns, buf.String())
			}
		})
	}
}
