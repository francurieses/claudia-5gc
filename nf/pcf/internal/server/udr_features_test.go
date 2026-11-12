package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
	"github.com/francurieses/claudia-5gc/shared/types"
)

const udrTestSUPI = "imsi-001010000000001"

// Golden request lines captured from the pre-change HEAD (git worktree) with
// the same fixtures: the legacy bytes a rel17 PCF must keep sending.
const (
	goldenUEPolicyURI = "/nudr-dr/v2/policy-data/imsi-001010000000001/ue-policy-set"
	goldenSMDataURI   = "/nudr-dr/v2/policy-data/imsi-001010000000001/sm-data"
	goldenPutSMBody   = `{"supi":"imsi-001010000000001","smPolicySnssaiData":{"1":{"snssai":{"sst":1},"smPolicyDnnData":{"internet":{"dnn":"internet","5qi":9,"arpPriorityLevel":8,"ambrUplink":"100 Mbps","ambrDownlink":"200 Mbps"}}}}}`
)

func udrTestProfile(t *testing.T, name string) *capability.Profile {
	t.Helper()
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type udrRequest struct {
	method, uri, accept, contentType, body string
}

// udrFixture is one private UDR stub plus the client under test and its log.
type udrFixture struct {
	c    *HTTPUDRClient
	logs *bytes.Buffer
	mu   *sync.Mutex
	reqs *[]udrRequest
}

func newUDRFixture(t *testing.T, p *capability.Profile, status int, respBody string) udrFixture {
	t.Helper()
	var mu sync.Mutex
	var reqs []udrRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		mu.Lock()
		reqs = append(reqs, udrRequest{r.Method, r.URL.RequestURI(), r.Header.Get("Accept"), r.Header.Get("Content-Type"), string(b)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	logs := &bytes.Buffer{}
	c := NewHTTPUDRClient(srv.URL, srv.Client())
	c.WithFeatures(p, slog.New(slog.NewJSONHandler(logs, nil)))
	return udrFixture{c: c, logs: logs, mu: &mu, reqs: &reqs}
}

func (f udrFixture) requests() []udrRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]udrRequest(nil), *f.reqs...)
}

func (f udrFixture) negotiation(t *testing.T) map[string]any {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["procedure"] == features.ProcedureName {
			return rec
		}
	}
	t.Fatalf("no FeatureNegotiation record in %s", f.logs.String())
	return nil
}

// udrOps are the two negotiating GETs of the client.
var udrOps = []struct {
	name string
	call func(c *HTTPUDRClient) error
	uri  string
}{
	{"GetPolicySubscription", func(c *HTTPUDRClient) error {
		_, err := c.GetPolicySubscription(context.Background(), udrTestSUPI)
		return err
	}, goldenUEPolicyURI},
	{"GetSmPolicyData", func(c *HTTPUDRClient) error {
		_, err := c.GetSmPolicyData(context.Background(), udrTestSUPI)
		return err
	}, goldenSMDataURI},
}

// TestUDRClientRel17Golden: nil profile and explicit rel17 send the exact
// legacy requests (no supp-feat), for the GETs and the PUT.
func TestUDRClientRel17Golden(t *testing.T) {
	for _, pc := range []struct {
		name string
		p    *capability.Profile
	}{
		{"nil profile", nil},
		{"explicit rel17", udrTestProfile(t, capability.ProfileRel17)},
	} {
		for _, op := range udrOps {
			t.Run(pc.name+"/"+op.name, func(t *testing.T) {
				f := newUDRFixture(t, pc.p, http.StatusOK, `{"suppFeat":"3"}`)
				if err := op.call(f.c); err != nil {
					t.Fatal(err)
				}
				got := f.requests()
				if len(got) != 1 || got[0].method != http.MethodGet || got[0].uri != op.uri || got[0].accept != "application/json" {
					t.Fatalf("requests = %+v, want one GET %s", got, op.uri)
				}
				if rec := f.negotiation(t); rec["features_negotiated"] != "0" || rec["result"] != "OK" {
					t.Errorf("log = %v", rec)
				}
			})
		}
		t.Run(pc.name+"/PutSmPolicyData", func(t *testing.T) {
			f := newUDRFixture(t, pc.p, http.StatusNoContent, "")
			data := &types.SmPolicyData{SUPI: udrTestSUPI, SmPolicySnssaiData: map[string]types.SmPolicySnssaiData{
				"1": {SNSSAI: types.SNSSAI{SST: 1}, SmPolicyDnnData: map[string]types.SmPolicyDnnData{
					"internet": {DNN: "internet", FiveQI: 9, ARPPriority: 8, AMBRUplink: "100 Mbps", AMBRDownlink: "200 Mbps"}}}}}
			if err := f.c.PutSmPolicyData(context.Background(), data); err != nil {
				t.Fatal(err)
			}
			got := f.requests()
			if len(got) != 1 || got[0].method != http.MethodPut || got[0].uri != goldenSMDataURI ||
				got[0].contentType != "application/json" || got[0].body != goldenPutSMBody {
				t.Fatalf("requests = %+v", got)
			}
		})
	}
}

// TestUDRClientRel19: the profile adds supp-feat to the GETs, the response
// suppFeat is negotiated, and PUT stays unchanged.
func TestUDRClientRel19(t *testing.T) {
	rel19 := udrTestProfile(t, capability.ProfileRel19)
	for _, op := range udrOps {
		t.Run(op.name+"/default catalog offers 0", func(t *testing.T) {
			f := newUDRFixture(t, rel19, http.StatusOK, `{"suppFeat":"3"}`)
			if err := op.call(f.c); err != nil {
				t.Fatal(err)
			}
			if got := f.requests(); len(got) != 1 || got[0].uri != op.uri+"?supp-feat=0" {
				t.Fatalf("requests = %+v", got)
			}
			rec := f.negotiation(t)
			if rec["interface"] != "Nudr" || rec["direction"] != "OUT" || rec["peer_nf_type"] != "UDR" ||
				rec["supi"] != udrTestSUPI || rec["spec_ref"] != "TS 29.500 §6.6.2" ||
				rec["features_peer"] != "3" || rec["features_negotiated"] != "0" || rec["result"] != "OK" {
				t.Errorf("log = %v", rec)
			}
		})
		t.Run(op.name+"/implemented bits intersect", func(t *testing.T) {
			cat, err := features.NewCatalog(features.MustImplement(features.NudrDataRepositoryEntries(), 1, 2)...)
			if err != nil {
				t.Fatal(err)
			}
			f := newUDRFixture(t, rel19, http.StatusOK, `{"suppFeat":"2"}`)
			f.c.SetCatalog(cat)
			if err := op.call(f.c); err != nil {
				t.Fatal(err)
			}
			if got := f.requests(); len(got) != 1 || got[0].uri != op.uri+"?supp-feat=3" {
				t.Fatalf("requests = %+v", got)
			}
			if rec := f.negotiation(t); rec["features_negotiated"] != "2" || rec["features_local"] != "3" {
				t.Errorf("log = %v", rec)
			}
		})
		t.Run(op.name+"/absent suppFeat", func(t *testing.T) {
			f := newUDRFixture(t, rel19, http.StatusOK, `{}`)
			if err := op.call(f.c); err != nil {
				t.Fatal(err)
			}
			if rec := f.negotiation(t); rec["features_peer"] != "absent" || rec["features_negotiated"] != "0" || rec["result"] != "OK" {
				t.Errorf("log = %v", rec)
			}
		})
	}
}

// TestUDRClientMalformedAnswer: a bad suppFeat (not hex, or not a string) is
// logged result=FAILURE at WARN and the GET still returns its data.
func TestUDRClientMalformedAnswer(t *testing.T) {
	for _, answer := range []string{`"zz"`, `5`} {
		for _, p := range []*capability.Profile{udrTestProfile(t, capability.ProfileRel19), nil} {
			t.Run(answer, func(t *testing.T) {
				f := newUDRFixture(t, p, http.StatusOK, `{"supi":"`+udrTestSUPI+`","precedence":7,"smPolicySnssaiData":{},"suppFeat":`+answer+`}`)
				sub, err := f.c.GetPolicySubscription(context.Background(), udrTestSUPI)
				if err != nil || sub == nil || sub.SUPI != udrTestSUPI || sub.Precedence != 7 {
					t.Fatalf("GetPolicySubscription = %+v, %v; procedure must continue", sub, err)
				}
				data, err := f.c.GetSmPolicyData(context.Background(), udrTestSUPI)
				if err != nil || data == nil || data.SUPI != udrTestSUPI {
					t.Fatalf("GetSmPolicyData = %+v, %v; procedure must continue", data, err)
				}
				rec := f.negotiation(t)
				if rec["result"] != "FAILURE" || rec["features_negotiated"] != "0" || rec["level"] != "WARN" || rec["error"] == nil {
					t.Errorf("log = %v", rec)
				}
			})
		}
	}
}
