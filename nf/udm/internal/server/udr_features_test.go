package server

// udr_features_test.go - the UDM's Nudr_DataRepository consumer negotiation
// (REL19-2.7 slice 6b-2): rel19 wire behaviour, answer parsing and the
// never-fail rule. The rel17 bytes are proved by TestGolden_UDRClientRequests.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// newTestUDRClient builds the client under test with the given profile and a
// discarding logger.
func newTestUDRClient(addr string, hc *http.Client, p *capability.Profile) *HTTPUDRClient {
	return NewHTTPUDRClient(addr, hc).WithFeatures(p, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
}

// udrLogRecords returns the FeatureNegotiation records of a JSON log buffer.
func udrLogRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["procedure"] == features.ProcedureName {
			out = append(out, rec)
		}
	}
	return out
}

func TestUDRClientRel19Offer(t *testing.T) {
	rel19 := profileNamed(t, "rel19")
	bit1 := features.MustCatalog(features.MustImplement(features.NudrDataRepositoryEntries(), 1)...)
	const base = "/nudr-dr/v2/subscription-data/" + goldenUDRSupi
	ops := []struct {
		name, uri string
		call      func(ctx context.Context, c *HTTPUDRClient) error
		negotiate bool // a 2xx body is read and a record is logged
	}{
		{"get_auth_subscription", base + "/authentication-data/authentication-subscription", func(ctx context.Context, c *HTTPUDRClient) error {
			_, err := c.GetAuthSubscription(ctx, goldenUDRSupi)
			return err
		}, true},
		{"patch_sqn", base + "/authentication-data/authentication-subscription", func(ctx context.Context, c *HTTPUDRClient) error {
			return c.UpdateSQN(ctx, goldenUDRSupi, "000000000040")
		}, false},
		{"get_sm_data", base + "/001/provisioned-data/sm-data", func(ctx context.Context, c *HTTPUDRClient) error {
			_, err := c.GetSMData(ctx, goldenUDRSupi)
			return err
		}, true},
		{"get_am_data", base + "/001/provisioned-data/am-data", func(ctx context.Context, c *HTTPUDRClient) error {
			_, err := c.GetAMData(ctx, goldenUDRSupi)
			return err
		}, true},
	}
	for _, tc := range []struct {
		name  string
		cat   *features.Catalog
		query string
	}{{"default catalog offers 0", nil, "?supported-features=0"}, {"implemented bit 1 offers 1", bit1, "?supported-features=1"}} {
		for _, op := range ops {
			t.Run(tc.name+"/"+op.name, func(t *testing.T) {
				st := newUDRStub(t, map[string]string{"auth": goldenUDRAuthRsp, "am": goldenUDRAMRsp, "sm": goldenUDRSMRsp})
				var logs bytes.Buffer
				c := NewHTTPUDRClient(st.address(), st.srv.Client()).WithFeatures(rel19, slog.New(slog.NewJSONHandler(&logs, nil)))
				c.SetCatalog(tc.cat)
				if err := op.call(context.Background(), c); err != nil {
					t.Fatal(err)
				}
				if !strings.HasPrefix(st.seen, "GET "+op.uri+tc.query+"\n") && !strings.HasPrefix(st.seen, "PATCH "+op.uri+tc.query+"\n") {
					t.Fatalf("request = %q, want URI %s%s", st.seen, op.uri, tc.query)
				}
				recs := udrLogRecords(t, &logs)
				if !op.negotiate {
					if len(recs) != 0 {
						t.Fatalf("PATCH has no answer, got records %v", recs)
					}
					return
				}
				if len(recs) != 1 {
					t.Fatalf("records = %v", recs)
				}
				r := recs[0]
				if r["interface"] != "Nudr" || r["direction"] != "OUT" || r["peer_nf_type"] != "UDR" ||
					r["supi"] != goldenUDRSupi || r["spec_ref"] != "TS 29.500 §6.6.2" || r["result"] != "OK" ||
					r["features_peer"] != "absent" || r["features_negotiated"] != "0" {
					t.Errorf("log = %v", r)
				}
			})
		}
	}
}

// TestUDRClientAMDataAnswer: the am-data supportedFeatures attribute is
// intersected with the offer; garbage is logged FAILURE and the data is still
// returned (R11-R14).
func TestUDRClientAMDataAnswer(t *testing.T) {
	rel19 := profileNamed(t, "rel19")
	cat := features.MustCatalog(features.MustImplement(features.NudrDataRepositoryEntries(), 1, 2)...)
	tests := []struct {
		name, rsp string
		cat       *features.Catalog
		wantPeer  string
		wantNeg   string
		wantRes   string
		wantLevel string
	}{
		{"intersection", `{"supportedFeatures":"2","nssai":{"defaultSingleNssais":[{"sst":1}]}}`, cat, "2", "2", "OK", "INFO"},
		{"empty offer ignores answer bits", `{"supportedFeatures":"f","nssai":{"defaultSingleNssais":[{"sst":1}]}}`, nil, "f", "0", "OK", "INFO"},
		{"not hex with empty offer", `{"supportedFeatures":"zz","nssai":{"defaultSingleNssais":[{"sst":1}]}}`, nil, "zz", "0", "FAILURE", "WARN"},
		{"non-string number", `{"supportedFeatures":3,"nssai":{"defaultSingleNssais":[{"sst":1}]}}`, nil, "3", "0", "FAILURE", "WARN"},
		{"non-string array with offer", `{"supportedFeatures":["1"],"nssai":{"defaultSingleNssais":[{"sst":1}]}}`, cat, `["1"]`, "0", "FAILURE", "WARN"},
		{"not hex with offer", `{"supportedFeatures":"zz","nssai":{"defaultSingleNssais":[{"sst":1}]}}`, cat, "zz", "0", "FAILURE", "WARN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newUDRStub(t, map[string]string{"am": tc.rsp})
			var logs bytes.Buffer
			c := NewHTTPUDRClient(st.address(), st.srv.Client()).WithFeatures(rel19, slog.New(slog.NewJSONHandler(&logs, nil)))
			c.SetCatalog(tc.cat)
			got, err := c.GetAMData(context.Background(), goldenUDRSupi)
			if err != nil || got == nil || len(got.SNSSAIs) != 1 {
				t.Fatalf("GetAMData = %+v, %v; the procedure must continue", got, err)
			}
			recs := udrLogRecords(t, &logs)
			if len(recs) != 1 {
				t.Fatalf("records = %v", recs)
			}
			r := recs[0]
			if r["features_peer"] != tc.wantPeer || r["features_negotiated"] != tc.wantNeg ||
				r["result"] != tc.wantRes || r["level"] != tc.wantLevel {
				t.Errorf("log = %v", r)
			}
			if tc.wantRes == "FAILURE" && r["error"] == nil {
				t.Errorf("FAILURE record carries no error: %v", r)
			}
		})
	}
}

// TestUDRClientNon2xxNotNegotiated: an error status negotiates nothing.
func TestUDRClientNon2xxNotNegotiated(t *testing.T) {
	st := newUDRStub(t, map[string]string{"sm": `{}`})
	st.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	var logs bytes.Buffer
	c := NewHTTPUDRClient(st.address(), st.srv.Client()).WithFeatures(profileNamed(t, "rel19"), slog.New(slog.NewJSONHandler(&logs, nil)))
	if got, err := c.GetSMData(context.Background(), goldenUDRSupi); err != nil || got != nil {
		t.Fatalf("GetSMData = %v, %v", got, err)
	}
	if recs := udrLogRecords(t, &logs); len(recs) != 0 {
		t.Fatalf("records = %v", recs)
	}
}

// TestUDRClientNonStringAnswerRel17: a non-string supportedFeatures answer must
// not fail the decode under the rel17 profile either (R13): the data is
// returned and a FAILURE record is logged.
func TestUDRClientNonStringAnswerRel17(t *testing.T) {
	st := newUDRStub(t, map[string]string{"am": `{"supportedFeatures":{"a":1},"nssai":{"defaultSingleNssais":[{"sst":1}]}}`})
	var logs bytes.Buffer
	c := NewHTTPUDRClient(st.address(), st.srv.Client()).WithFeatures(profileNamed(t, "rel17"), slog.New(slog.NewJSONHandler(&logs, nil)))
	got, err := c.GetAMData(context.Background(), goldenUDRSupi)
	if err != nil || got == nil || len(got.SNSSAIs) != 1 {
		t.Fatalf("GetAMData = %+v, %v", got, err)
	}
	if recs := udrLogRecords(t, &logs); len(recs) != 1 || recs[0]["result"] != "FAILURE" {
		t.Fatalf("records = %v", recs)
	}
}

// TestUDRClientDecodeErrorWrapped: a body that is not JSON returns a wrapped
// error.
func TestUDRClientDecodeErrorWrapped(t *testing.T) {
	st := newUDRStub(t, map[string]string{"am": `not json`})
	c := NewHTTPUDRClient(st.address(), st.srv.Client())
	_, err := c.GetAMData(context.Background(), goldenUDRSupi)
	if err == nil || !strings.HasPrefix(err.Error(), "udr: decode am data: ") {
		t.Fatalf("err = %v", err)
	}
}

// TestUDRNegotiationRecordsCarryCorrelationID: the Nudr consumer records
// emitted while serving an SDM/UEAU request carry the request's correlation id.
func TestUDRNegotiationRecordsCarryCorrelationID(t *testing.T) {
	st := newUDRStub(t, map[string]string{"am": goldenUDRAMRsp, "sm": goldenUDRSMRsp, "auth": goldenUDRAuthRsp})
	var logs bytes.Buffer
	udr := NewHTTPUDRClient(st.address(), st.srv.Client()).WithFeatures(profileNamed(t, "rel19"), slog.New(slog.NewJSONHandler(&logs, nil)))
	s, err := New("127.0.0.1:0", "5G:mnc001.mcc001.3gppnetwork.org", TLSConfig{}, udr, slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/am-data", "/sm-data"} {
		do(t, s, http.MethodGet, "/nudm-sdm/v2/"+goldenUDRSupi+path, "", "AMF-0001")
	}
	recs := udrLogRecords(t, &logs)
	if len(recs) != 2 {
		t.Fatalf("records = %v", recs)
	}
	for _, r := range recs {
		if r["correlation_id"] != "01TESTCORRELATIONID00000000" {
			t.Errorf("correlation_id missing: %v", r)
		}
	}
}
