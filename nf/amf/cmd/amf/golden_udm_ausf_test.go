package main

// golden_udm_ausf_test.go - REL19-2.7 slice 6a byte-identity goldens for the
// AMF's outbound Nausf_UEAuthentication and Nudm_SDM / Nudm_UECM requests. The
// expected strings were verified against the pre-change code (HEAD) and must
// keep passing UNCHANGED with no profile and under the explicit rel17 profile
// (decision D2, dev/REL19_PROGRAM.md section 2). Method, path, query, content
// type and body are compared byte for byte; json.Marshal of a map sorts keys,
// so nothing needs normalising.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	goldenSN         = "5G:mnc001.mcc001.3gppnetwork.org"
	goldenSUCI       = "suci-0-001-01-0-0-0-0000000001"
	goldenSUPI       = "imsi-001010000000001"
	goldenAuthBody   = `{"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","supiOrSuci":"suci-0-001-01-0-0-0-0000000001"}`
	goldenResyncBody = `{"resynchronizationInfo":{"auts":"0a0b0c0d0e0f101112131415161718","rand":"000102030405060708090a0b0c0d0e0f"},"servingNetworkName":"5G:mnc001.mcc001.3gppnetwork.org","supiOrSuci":"suci-0-001-01-0-0-0-0000000001"}`
	// goldenRegBody is the rel17 Amf3GppAccessRegistration the AMF sends after
	// SetSelf (as production does): amfInstanceId, deregCallbackUri, guami and
	// ratType are mandatory in the Rel-17 YAML (TS 29.503 §6.2.6.2.2), no
	// supportedFeatures and no servingNetworkName. AMF-031 B conformance fix.
	goldenRegBody = `{"amfInstanceId":"amf-test-1","deregCallbackUri":"https://amf.test:8001/namf-callback/v1/udm-uecm/dereg-notify/imsi-001010000000001","guami":{"amfId":"020041","plmnId":{"mcc":"001","mnc":"01"}},"ratType":"NR"}`
)

// capturedReq is one request as seen by the test server.
type capturedReq struct{ method, uri, contentType, body string }

func (c capturedReq) String() string {
	return c.method + " " + c.uri + " [" + c.contentType + "] " + c.body
}

// captureServer answers every request with status and body and records it.
func captureServer(t *testing.T, status int, answer string, loc string) (addr string, got *capturedReq, client *http.Client) {
	t.Helper()
	got = new(capturedReq)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		*got = capturedReq{r.Method, r.URL.RequestURI(), r.Header.Get("Content-Type"), string(raw)}
		w.Header().Set("Content-Type", "application/json")
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), got, srv.Client()
}

const (
	goldenAuthAnswer = `{"authType":"5G_AKA","5gAuthData":{},"_links":{"5g-aka":{"href":"x"}},"rand":"000102030405060708090a0b0c0d0e0f","autn":"000102030405060708090a0b0c0d0e0f","hxresStar":"000102030405060708090a0b0c0d0e0f","supi":"imsi-001010000000001"}`
	goldenAMAnswer   = `{"nssai":{"defaultSingleNssais":[{"sst":1,"sd":"000001"}]},"subscribedUeAmbr":{"uplink":"1 Gbps","downlink":"2 Gbps"}}`
)

func TestGolden_AUSFRequests(t *testing.T) {
	tests := []struct {
		name string
		call func(c *HTTPAUSFClient) error
		want string
	}{
		{"initiate_auth", func(c *HTTPAUSFClient) error {
			_, err := c.InitiateAuth(t.Context(), goldenSUCI, goldenSN)
			return err
		}, "POST /nausf-auth/v1/ue-authentications [application/json] " + goldenAuthBody},
		{"resync_auth", func(c *HTTPAUSFClient) error {
			rnd := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
			_, err := c.ResyncAuth(t.Context(), goldenSUCI, goldenSN, rnd,
				[]byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24})
			return err
		}, "POST /nausf-auth/v1/ue-authentications [application/json] " + goldenResyncBody},
	}
	for _, mode := range goldenModes(t) {
		for _, tc := range tests {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				addr, got, hc := captureServer(t, http.StatusCreated, goldenAuthAnswer, "https://ausf/nausf-auth/v1/ue-authentications/ctx-1")
				c := newAUSFClient(addr, hc, mode)
				if err := tc.call(c); err != nil {
					t.Fatal(err)
				}
				if got.String() != tc.want {
					t.Fatalf("request changed:\n got %s\nwant %s", got, tc.want)
				}
			})
		}
	}
}

func TestGolden_UDMRequests(t *testing.T) {
	tests := []struct {
		name   string
		status int
		answer string
		call   func(c *HTTPUDMClient) error
		want   string
	}{
		{"get_am_data", http.StatusOK, goldenAMAnswer, func(c *HTTPUDMClient) error {
			sub, err := c.GetAMSubscriptionData(t.Context(), goldenSUPI)
			if err == nil && (len(sub.AllowedNSSAI) != 1 || sub.AMBRUplink != 1000000) {
				t.Errorf("parsed subscription: %+v", sub)
			}
			return err
		}, "GET /nudm-sdm/v2/" + goldenSUPI + "/am-data [] "},
		{"register_amf", http.StatusCreated, ``, func(c *HTTPUDMClient) error {
			return c.RegisterAMF(t.Context(), goldenSUPI, "amf-test-1", goldenSN)
		}, "PUT /nudm-uecm/v1/" + goldenSUPI + "/registrations/amf-3gpp-access [application/json] " + goldenRegBody},
		{"deregister", http.StatusNoContent, ``, func(c *HTTPUDMClient) error {
			return c.DeregisterUECM(t.Context(), goldenSUPI)
		}, "DELETE /nudm-uecm/v1/" + goldenSUPI + "/registrations/amf-3gpp-access [] "},
	}
	for _, mode := range goldenModes(t) {
		for _, tc := range tests {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				addr, got, hc := captureServer(t, tc.status, tc.answer, "")
				c := newUDMClient(addr, hc, mode)
				c.SetSelf("amf-test-1", "https://amf.test:8001", "001", "01", 2, 1, 1)
				if err := tc.call(c); err != nil {
					t.Fatal(err)
				}
				if got.String() != tc.want {
					t.Fatalf("request changed:\n got %s\nwant %s", got, tc.want)
				}
			})
		}
	}
}

// TestGolden_UECMRegisterSupportedFeatures pins the profile split of the
// Nudm_UECM registration body: rel17 (and no profile) never carries
// supportedFeatures, rel19 always does (TS 29.500 §6.6.2), and both carry the
// mandatory Rel-17 attributes (TS 29.503 §6.2.6.2.2).
func TestGolden_UECMRegisterSupportedFeatures(t *testing.T) {
	modes := append(goldenModes(t), goldenMode{"rel19", testProfile(t, "rel19")})
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			addr, got, hc := captureServer(t, http.StatusCreated, ``, "")
			c := newUDMClient(addr, hc, mode)
			c.SetSelf("amf-test-1", "https://amf.test:8001", "001", "01", 2, 1, 1)
			if err := c.RegisterAMF(t.Context(), goldenSUPI, "amf-test-1", goldenSN); err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal([]byte(got.body), &body); err != nil {
				t.Fatalf("decode body %q: %v", got.body, err)
			}
			for _, k := range []string{"amfInstanceId", "deregCallbackUri", "guami", "ratType"} {
				if _, ok := body[k]; !ok {
					t.Errorf("mandatory attribute %q missing: %s", k, got.body)
				}
			}
			if _, ok := body["servingNetworkName"]; ok {
				t.Errorf("servingNetworkName is not an Amf3GppAccessRegistration attribute: %s", got.body)
			}
			sf, has := body["supportedFeatures"]
			if mode.name == "rel19" {
				if s, ok := sf.(string); !has || !ok || s == "" {
					t.Fatalf("rel19 body lacks supportedFeatures: %s", got.body)
				}
				return
			}
			if has {
				t.Fatalf("%s body carries supportedFeatures %v", mode.name, sf)
			}
			if got.body != goldenRegBody {
				t.Fatalf("rel17 body changed:\n got %s\nwant %s", got.body, goldenRegBody)
			}
		})
	}
}
