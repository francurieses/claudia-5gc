package server

// sdm_uecm_golden_test.go - byte-identity goldens for the Nudm_SDM and
// Nudm_UECM endpoints touched by REL19-2.7 slice 6a. The files under testdata/
// were captured from the pre-change code (git worktree at HEAD) and must pass
// UNCHANGED under rel17 and under no profile for requests WITHOUT
// supportedFeatures (decision D1, dev/REL19_PROGRAM.md section 2). Only the
// generated subscription id is masked. Each subtest builds its own server.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
)

// sdmUDR is a deterministic UDR for the SDM goldens.
type sdmUDR struct{ goldenUDR }

func (sdmUDR) GetAMData(context.Context, string) (*UDRAMData, error) {
	return &UDRAMData{
		SNSSAIs: []SNSSAIEntry{
			{SST: 1, SD: "000001", DNN: "internet"},
			{SST: 2, SD: "000002", SubjectToNSSAA: true},
		},
		AMBRUplink: 1000000, AMBRDownlink: 2000000,
	}, nil
}

func (sdmUDR) GetSMData(context.Context, string) (json.RawMessage, error) {
	return json.RawMessage(`[{"singleNssai":{"sst":1,"sd":"000001"},"dnnConfigurations":{"internet":{"pduSessionTypes":{"defaultSessionType":"IPV4"}}}},` +
		`{"singleNssai":{"sst":2,"sd":"000002"},"dnnConfigurations":{"ims":{"pduSessionTypes":{"defaultSessionType":"IPV4"}}}}]`), nil
}

var subIDRE = regexp.MustCompile(`[0-9A-HJKMNP-TV-Z]{26}`)

// goldenProfiles are the two profile settings that must leave the legacy
// bytes unchanged: no profile loaded and the explicit rel17 profile.
func goldenProfiles(t *testing.T) map[string]*capability.Profile {
	t.Helper()
	return map[string]*capability.Profile{"no-profile": nil, "explicit-rel17": profileNamed(t, "rel17")}
}

func newSDMGoldenUDM(t *testing.T, p *capability.Profile) *Server {
	t.Helper()
	s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, sdmUDR{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p != nil {
		s.SetProfile(p)
	}
	return s
}

// snapshot renders status, selected headers and body of one request.
func snapshot(t *testing.T, s *Server, method, target, body string) string {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	w := httptest.NewRecorder()
	s.httpSrv.Handler.ServeHTTP(w, r)
	resp := w.Result()
	raw, _ := io.ReadAll(resp.Body)
	loc := subIDRE.ReplaceAllString(resp.Header.Get("Location"), "<ID>")
	return "status: " + http.StatusText(resp.StatusCode) + "\n" +
		"Content-Type: " + resp.Header.Get("Content-Type") + "\n" +
		"Location: " + loc + "\n\n" +
		subIDRE.ReplaceAllString(string(raw), "<ID>")
}

func TestGolden_SDMUECM(t *testing.T) {
	const supi = "imsi-001010000000001"
	tests := []struct {
		name, golden, method, target, body string
	}{
		{"am_data", "golden_sdm_am_data.txt", http.MethodGet, "/nudm-sdm/v2/" + supi + "/am-data", ""},
		{"sm_data", "golden_sdm_sm_data.txt", http.MethodGet, "/nudm-sdm/v2/" + supi + "/sm-data", ""},
		{"sm_data_dnn_filter", "golden_sdm_sm_data_dnn.txt", http.MethodGet, "/nudm-sdm/v2/" + supi + "/sm-data?dnn=ims", ""},
		{"lcs_privacy_data", "golden_sdm_lcs_privacy.txt", http.MethodGet, "/nudm-sdm/v2/" + supi + "/lcs-privacy-data", ""},
		{"sdm_subscribe", "golden_sdm_subscribe.txt", http.MethodPost, "/nudm-sdm/v2/" + supi + "/sdm-subscriptions",
			`{"nfInstanceId":"amf-1","callbackReference":"https://amf.example/cb","monitoredResourceUri":"https://udm/nudm-sdm/v2/` + supi + `/am-data","implicitUnsubscribe":true}`},
		{"sdm_subscribe_no_callback", "golden_sdm_subscribe_bad.txt", http.MethodPost, "/nudm-sdm/v2/" + supi + "/sdm-subscriptions", `{"nfInstanceId":"amf-1"}`},
		{"amf_registration", "golden_uecm_amf_reg.txt", http.MethodPut, "/nudm-uecm/v1/" + supi + "/registrations/amf-3gpp-access",
			`{"amfInstanceId":"11111111-2222-3333-4444-555555555555","deregCallbackUri":"https://amf/dereg","guami":{"plmnId":{"mcc":"001","mnc":"01"},"amfId":"cafe00"},"ratType":"NR"}`},
		{"amf_registration_garbled_body", "golden_uecm_amf_reg_garbled.txt", http.MethodPut, "/nudm-uecm/v1/" + supi + "/registrations/amf-3gpp-access", `{not json`},
		{"amf_registration_empty_body", "golden_uecm_amf_reg_empty.txt", http.MethodPut, "/nudm-uecm/v1/" + supi + "/registrations/amf-3gpp-access", ``},
		{"amf_deregistration", "golden_uecm_amf_dereg.txt", http.MethodDelete, "/nudm-uecm/v1/" + supi + "/registrations/amf-3gpp-access", ``},
	}
	for pname := range goldenProfiles(t) {
		for _, tc := range tests {
			t.Run(pname+"/"+tc.name, func(t *testing.T) {
				p := goldenProfiles(t)[pname]
				checkGolden(t, tc.golden, snapshot(t, newSDMGoldenUDM(t, p), tc.method, tc.target, tc.body))
			})
		}
	}
}
