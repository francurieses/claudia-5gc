//go:build functional

// feature_negotiation_steps_test.go - godog runner for the @namf-producer
// scenarios of feature_negotiation.feature (REL19-2.8): the AMF as
// Namf_Communication UEContextTransfer producer answering supportedFeatures
// (TS 29.500 §6.6.2, §5.2.7.2; decision D1). The @nsmf-consumer scenarios of the
// same file drive HTTPSMFClient (package main) and run in nf/amf/cmd/amf
// (TestFeatureNegotiationConsumer).
//
// The real internal/sbi server is driven over an in-process httptest server
// with the profile and test catalog injected through SetProfile / SetCatalog.
// OBS: the fivegc_procedure_total{nf="AMF",procedure="FeatureNegotiation"}
// delta is asserted in the counter Then-step (snapshot at the When step).
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfsbi "github.com/francurieses/claudia-5gc/nf/amf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

type fnLogBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *fnLogBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *fnLogBuf) negotiations() []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.b.String()), "\n") {
		var m map[string]any
		if line != "" && json.Unmarshal([]byte(line), &m) == nil && m["procedure"] == features.ProcedureName {
			out = append(out, m)
		}
	}
	return out
}

type fnWorld struct {
	catalog bool
	profile *capability.Profile
	logs    *fnLogBuf
	mgr     *amfctx.Manager
	ts      *httptest.Server
	ue      *amfctx.UEContext

	status int
	raw    []byte
	body   map[string]any
	before map[string]float64
}

var fnResults = []string{"OK", "REJECT", "FAILURE"}

func fnCounter(result string) float64 {
	return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("AMF", features.ProcedureName, result))
}

func (w *fnWorld) reset() {
	if w.ts != nil {
		w.ts.Close()
	}
	*w = fnWorld{logs: &fnLogBuf{}}
}

func (w *fnWorld) nsmfCatalogGiven() error { return nil }

func (w *fnWorld) namfCatalogGiven() error { w.catalog = true; return nil }

func (w *fnWorld) profileIs(name string) error {
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		return err
	}
	w.profile = p
	return nil
}

func (w *fnWorld) serverRunning() error {
	if !w.catalog {
		return fmt.Errorf("Namf_Communication test catalog not injected")
	}
	if w.profile == nil {
		return fmt.Errorf("release profile not set: the \"AMF runs with release profile\" step must precede server start")
	}
	w.mgr = amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	srv, err := amfsbi.New(amfsbi.Config{Address: "127.0.0.1:0"}, w.mgr,
		slog.New(slog.NewJSONHandler(w.logs, nil)).With("nf", "AMF"))
	if err != nil {
		return err
	}
	srv.SetProfile(w.profile)
	srv.SetCatalog(features.MustCatalog(
		features.Entry{Number: 1, Name: "F1", Release: capability.Rel17, Implemented: true},
		features.Entry{Number: 9, Name: "F9", Release: capability.Rel19, Implemented: true},
	))
	w.ts = httptest.NewServer(srv.HTTPHandler())
	return nil
}

func (w *fnWorld) ueRegistered(supi string) error {
	ue := w.mgr.AllocateUEContext(1)
	w.mgr.SetSUPI(ue, supi)
	w.mgr.AssignGUTI(context.Background(), ue)
	ue.SecurityCtx = amfctx.SecurityContext{
		Active: true, IntegrityAlgID: 2, CipheringAlgID: 2,
		KAMF: bytes.Repeat([]byte{0xAB}, 32), UplinkCount: 3, DownlinkCount: 4,
	}
	w.ue = ue
	return nil
}

// post sends a UEContextTransfer request; sf == nil omits supportedFeatures.
func (w *fnWorld) post(reason string, sf *string, extra map[string]any) error {
	if w.ue == nil || w.ts == nil {
		return fmt.Errorf("server or UE not set up")
	}
	w.before = map[string]float64{}
	for _, r := range fnResults {
		w.before[r] = fnCounter(r)
	}
	// accessType is mandatory (TS 29.518 Table 6.1.6.2.23-1), validated under rel19.
	req := map[string]any{"reason": reason, "accessType": "3GPP_ACCESS"}
	if sf != nil {
		req["supportedFeatures"] = *sf
	}
	for k, v := range extra {
		req[k] = v
	}
	b, _ := json.Marshal(req)
	r, _ := http.NewRequest(http.MethodPost, w.ts.URL+"/namf-comm/v1/ue-contexts/"+w.ue.SUPI+"/transfer", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01JTESTFEATNEG000000000000")
	resp, err := w.ts.Client().Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	w.status, w.raw = resp.StatusCode, buf.Bytes()
	w.body = map[string]any{}
	if err := json.Unmarshal(w.raw, &w.body); err != nil {
		return fmt.Errorf("response is not JSON: %w (%s)", err, w.raw)
	}
	return nil
}

func (w *fnWorld) postWith(reason, sf string) error { return w.post(reason, &sf, nil) }

func (w *fnWorld) postNone(reason string) error { return w.post(reason, nil, nil) }

func (w *fnWorld) postWithUnknown(reason, sf, attr string) error {
	return w.post(reason, &sf, map[string]any{attr: "x"})
}

func (w *fnWorld) is200(code int, want string) error {
	if w.status != code {
		return fmt.Errorf("status = %d, want %d: %s", w.status, code, w.raw)
	}
	if got, ok := w.body["supportedFeatures"]; !ok || got != want {
		return fmt.Errorf("supportedFeatures = %v (present=%v), want %q in %s", got, ok, want, w.raw)
	}
	if code == http.StatusOK {
		return w.transferred()
	}
	return nil
}

func (w *fnWorld) is200Plain(code int) error {
	if w.status != code {
		return fmt.Errorf("status = %d, want %d: %s", w.status, code, w.raw)
	}
	if code == http.StatusOK {
		return w.transferred()
	}
	return nil
}

func (w *fnWorld) noAttribute() error {
	if v, ok := w.body["supportedFeatures"]; ok {
		return fmt.Errorf("supportedFeatures present (%v), want absent, raw %s", v, w.raw)
	}
	return nil
}

func (w *fnWorld) problem(code int, cause, param string) error {
	if w.status != code {
		return fmt.Errorf("status = %d, want %d: %s", w.status, code, w.raw)
	}
	var pd struct {
		Cause         string `json:"cause"`
		InvalidParams []struct {
			Param string `json:"param"`
		} `json:"invalidParams"`
	}
	if err := json.Unmarshal(w.raw, &pd); err != nil {
		return err
	}
	if pd.Cause != cause {
		return fmt.Errorf("ProblemDetails cause = %q, want %q", pd.Cause, cause)
	}
	if len(pd.InvalidParams) == 0 || pd.InvalidParams[0].Param != param {
		return fmt.Errorf("invalidParams = %+v, want first param %q", pd.InvalidParams, param)
	}
	return nil
}

func (w *fnWorld) transferred() error {
	w.ue.Lock()
	t := w.ue.Transferred
	w.ue.Unlock()
	if !t {
		return fmt.Errorf("UE context not marked transferred after a 200 response (positive control)")
	}
	return nil
}

func (w *fnWorld) notTransferred() error {
	w.ue.Lock()
	t := w.ue.Transferred
	w.ue.Unlock()
	if t {
		return fmt.Errorf("UE context marked transferred after a rejected request")
	}
	return nil
}

func (w *fnWorld) expectRecord(want map[string]string) error {
	recs := w.logs.negotiations()
	if len(recs) != 1 {
		return fmt.Errorf("FeatureNegotiation records = %d, want 1", len(recs))
	}
	want["nf"] = "AMF"
	want["interface"] = "Namf"
	want["direction"] = "IN"
	want["correlation_id"] = "01JTESTFEATNEG000000000000"
	for k, v := range want {
		if recs[0][k] != v {
			return fmt.Errorf("log %s = %v, want %q (record %v)", k, recs[0][k], v, recs[0])
		}
	}
	return nil
}

func (w *fnWorld) logOK(peer, neg string) error {
	return w.expectRecord(map[string]string{"features_peer": peer, "features_negotiated": neg, "result": "OK"})
}

func (w *fnWorld) logReject(peer, cause, specRef string) error {
	return w.expectRecord(map[string]string{"features_peer": peer, "cause": cause, "spec_ref": specRef, "result": "REJECT"})
}

func (w *fnWorld) counterInc(result string) error {
	for _, r := range fnResults {
		want := 0.0
		if r == result {
			want = 1
		}
		if d := fnCounter(r) - w.before[r]; d != want {
			return fmt.Errorf("fivegc_procedure_total{nf=AMF,procedure=FeatureNegotiation,result=%s} delta = %v, want %v", r, d, want)
		}
	}
	return nil
}

func initFeatureNegotiationProducerSteps(sc *godog.ScenarioContext) {
	w := &fnWorld{logs: &fnLogBuf{}}
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if w.ts != nil {
			w.ts.Close()
			w.ts = nil
		}
		return ctx, nil
	})
	sc.Step(`^a test Nsmf_PDUSession feature catalog where F1 is bit 1 \(Rel-17\) and F9 is bit 9 \(Rel-19\)$`, w.nsmfCatalogGiven)
	sc.Step(`^a test Namf_Communication feature catalog where F1 is bit 1 \(Rel-17\) and F9 is bit 9 \(Rel-19\)$`, w.namfCatalogGiven)
	sc.Step(`^the AMF runs with release profile "([^"]*)"$`, w.profileIs)
	sc.Step(`^the AMF inbound namf-comm SBI server is running for feature negotiation$`, w.serverRunning)
	sc.Step(`^a UE "([^"]+)" is registered with an active NAS security context for feature negotiation$`, w.ueRegistered)

	sc.Step(`^a new AMF POSTs a UEContextTransfer request with reason "([^"]*)" and supportedFeatures "([^"]*)"$`, w.postWith)
	sc.Step(`^a new AMF POSTs a UEContextTransfer request with reason "([^"]*)" and no supportedFeatures$`, w.postNone)
	sc.Step(`^a new AMF POSTs a UEContextTransfer request with reason "([^"]*)", supportedFeatures "([^"]*)" and an unknown JSON attribute "([^"]*)"$`, w.postWithUnknown)

	sc.Step(`^the UEContextTransfer response is (\d+) with supportedFeatures "([^"]*)"$`, w.is200)
	sc.Step(`^the UEContextTransfer response is (\d+)$`, w.is200Plain)
	sc.Step(`^the UeContextTransferRspData has no supportedFeatures attribute$`, w.noAttribute)
	sc.Step(`^the UEContextTransfer response is (\d+) with ProblemDetails cause "([^"]*)" and invalidParams first param "([^"]*)"$`, w.problem)
	sc.Step(`^the old AMF does not mark the UE context as transferred for feature negotiation$`, w.notTransferred)
	sc.Step(`^a producer FeatureNegotiation log has features_peer "([^"]*)", features_negotiated "([^"]*)" and result "OK"$`, w.logOK)
	sc.Step(`^a producer FeatureNegotiation log has features_peer "([^"]*)", cause "([^"]*)", spec_ref "([^"]*)" and result "REJECT"$`, w.logReject)
	sc.Step(`^the AMF FeatureNegotiation counter with result "([^"]*)" increased by 1$`, w.counterInc)
}

// TestFeatureNegotiationProducer runs the @namf-producer scenarios strictly:
// undefined or pending steps fail.
func TestFeatureNegotiationProducer(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initFeatureNegotiationProducerSteps,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"feature_negotiation.feature"},
			Tags:     "@namf-producer",
			Strict:   true,
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
