//go:build functional

package server

// feature_negotiation_functional_test.go - godog runner for
// ../../tests/features/feature_negotiation.feature (REL19-2.8): the SMF as
// Nsmf_PDUSession producer answering CreateSMContext supportedFeatures
// (TS 29.500 §6.6.2, §5.2.7.2; TS 29.571 §5.2.2).
//
// The SMF is built with New() through the same seams as the unit tests
// (newFeatureServer: WithProfile + WithCatalogs) and the real
// handleCreateSMContext handler is driven with httptest. OBS: the
// fivegc_procedure_total{nf="SMF",procedure="FeatureNegotiation",result} delta
// is asserted in the counter Then-steps (snapshot taken at the When step).
//
// Run with: go test -tags=functional ./nf/smf/...  (make -C nf/smf test-functional)

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

type fnWorld struct {
	t       *testing.T
	catalog bool
	profile string
	srv     *Server
	logs    *syncBuffer

	status int
	raw    []byte
	body   map[string]any
	before map[string]float64
}

var fnResults = []string{"OK", "REJECT", "FAILURE"}

func fnCounter(result string) float64 {
	return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("SMF", features.ProcedureName, result))
}

func (w *fnWorld) catalogGiven() error { w.catalog = true; return nil }

func (w *fnWorld) serverRunning() error {
	if !w.catalog {
		return fmt.Errorf("feature catalog not injected")
	}
	return nil
}

func (w *fnWorld) profileIs(p string) error { w.profile = p; return nil }

// post builds the SMF for the scenario profile and POSTs CreateSMContext with
// the given extra top-level attributes.
func (w *fnWorld) post(extra map[string]any) error {
	w.srv, w.logs = newFeatureServer(w.t, w.profile, testCatalog(), nil)
	w.before = map[string]float64{}
	for _, r := range fnResults {
		w.before[r] = fnCounter(r)
	}
	req := map[string]any{
		"supi":         "imsi-001010000000001",
		"dnn":          "internet",
		"pduSessionId": float64(1),
		"n1SmMsg":      base64.StdEncoding.EncodeToString(buildEstablishmentRequest(1, 5)),
		"snssai":       map[string]any{"sst": float64(1), "sd": "000001"},
	}
	for k, v := range extra {
		req[k] = v
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Correlation-Id", "01TESTCORRELATIONID00000000")
	rec := httptest.NewRecorder()
	w.srv.handleCreateSMContext(rec, r.WithContext(context.Background()))
	w.status = rec.Code
	w.raw = rec.Body.Bytes()
	w.body = map[string]any{}
	if err := json.Unmarshal(w.raw, &w.body); err != nil {
		return fmt.Errorf("response is not JSON: %w (%s)", err, w.raw)
	}
	return nil
}

// postOffer: offer is the literal feature-file token, bare absent or "<v>".
func (w *fnWorld) postOffer(bare, quoted string) error {
	extra := map[string]any{}
	if bare != "absent" {
		extra["supportedFeatures"] = quoted
	}
	return w.post(extra)
}

func (w *fnWorld) postOfferUnknown(offer, attr string) error {
	return w.post(map[string]any{"supportedFeatures": offer, attr: "x"})
}

func (w *fnWorld) responds(code int) error {
	if w.status != code {
		return fmt.Errorf("status = %d, want %d: %s", w.status, code, w.raw)
	}
	return nil
}

func (w *fnWorld) answerIs(want string) error {
	got, ok := w.body["supportedFeatures"]
	if !ok {
		return fmt.Errorf("supportedFeatures absent from %s, want %q", w.raw, want)
	}
	if got != want {
		return fmt.Errorf("supportedFeatures = %v, want %q", got, want)
	}
	return nil
}

func (w *fnWorld) answerAbsent() error {
	if v, ok := w.body["supportedFeatures"]; ok {
		return fmt.Errorf("supportedFeatures present (%v), want absent", v)
	}
	return nil
}

func (w *fnWorld) session() (*Session, error) {
	w.srv.sessionMu.Lock()
	defer w.srv.sessionMu.Unlock()
	if len(w.srv.sessions) != 1 {
		return nil, fmt.Errorf("sessions = %d, want 1", len(w.srv.sessions))
	}
	for _, s := range w.srv.sessions {
		return s, nil
	}
	return nil, fmt.Errorf("unreachable")
}

func (w *fnWorld) storedSet(want string) error {
	s, err := w.session()
	if err != nil {
		return err
	}
	if got := s.Features.String(); got != want {
		return fmt.Errorf("stored negotiated feature set = %q, want %q", got, want)
	}
	return nil
}

// noF9: F9 has no tied IE in this symbolic catalog; the observable guarantee is
// that the SM context never carries feature 9 and the response holds no
// attribute beyond the baseline SmContextCreatedData ones.
func (w *fnWorld) noF9IE() error {
	s, err := w.session()
	if err != nil {
		return err
	}
	if s.Features.Has(9) {
		return fmt.Errorf("SM context negotiated F9 (%s)", s.Features.String())
	}
	for k := range w.body {
		switch k {
		case "n1SmMsg", "n2SmInfo", "n2SmInfoType", "smContextRef", "supportedFeatures":
		default:
			return fmt.Errorf("unexpected response attribute %q", k)
		}
	}
	return nil
}

func (w *fnWorld) byteIdentical() error {
	got := uuidRE.ReplaceAllString(string(w.raw), goldenSMContextRef)
	if want := string(readGolden(w.t, "golden_create_sm_context_201.json")); got != want {
		return fmt.Errorf("body differs from baseline\n got: %s\nwant: %s", got, want)
	}
	return nil
}

func (w *fnWorld) unknownNotEchoed(attr string) error {
	if _, ok := w.body[attr]; ok {
		return fmt.Errorf("unknown attribute %q echoed in %s", attr, w.raw)
	}
	return nil
}

func (w *fnWorld) problem() (cause, param string, err error) {
	var pd struct {
		Cause         string              `json:"cause"`
		InvalidParams []map[string]string `json:"invalidParams"`
	}
	if err := json.Unmarshal(w.raw, &pd); err != nil {
		return "", "", err
	}
	if len(pd.InvalidParams) > 0 {
		param = pd.InvalidParams[0]["param"]
	}
	return pd.Cause, param, nil
}

func (w *fnWorld) causeIs(want string) error {
	c, _, err := w.problem()
	if err != nil {
		return err
	}
	if c != want {
		return fmt.Errorf("ProblemDetails cause = %q, want %q", c, want)
	}
	return nil
}

func (w *fnWorld) paramIs(want string) error {
	_, p, err := w.problem()
	if err != nil {
		return err
	}
	if p != want {
		return fmt.Errorf("invalidParams[0].param = %q, want %q", p, want)
	}
	return nil
}

func (w *fnWorld) noContext() error {
	w.srv.sessionMu.Lock()
	n := len(w.srv.sessions)
	w.srv.sessionMu.Unlock()
	if n != 0 {
		return fmt.Errorf("sessions = %d, want 0", n)
	}
	return nil
}

func (w *fnWorld) records() ([]map[string]any, error) {
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace([]byte(w.logs.String())), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			return nil, err
		}
		if m["procedure"] == features.ProcedureName {
			out = append(out, m)
		}
	}
	if len(out) != 1 {
		return nil, fmt.Errorf("FeatureNegotiation records = %d, want 1", len(out))
	}
	return out, nil
}

func (w *fnWorld) expectRecord(want map[string]string) error {
	recs, err := w.records()
	if err != nil {
		return err
	}
	for k, v := range want {
		if recs[0][k] != v {
			return fmt.Errorf("log %s = %v, want %q (record %v)", k, recs[0][k], v, recs[0])
		}
	}
	if recs[0]["nf"] != "SMF" {
		return fmt.Errorf("log nf = %v, want SMF", recs[0]["nf"])
	}
	return nil
}

func (w *fnWorld) logFull(local, peer, neg, result string) error {
	return w.expectRecord(map[string]string{"features_local": local, "features_peer": peer, "features_negotiated": neg, "result": result})
}

func (w *fnWorld) logNeg(neg, result string) error {
	return w.expectRecord(map[string]string{"features_negotiated": neg, "result": result})
}

func (w *fnWorld) logReject(peer, cause, specRef, result string) error {
	return w.expectRecord(map[string]string{"features_peer": peer, "cause": cause, "spec_ref": specRef, "result": result})
}

func (w *fnWorld) counterInc(result string) error {
	for _, r := range fnResults {
		want := 0.0
		if r == result {
			want = 1
		}
		if d := fnCounter(r) - w.before[r]; d != want {
			return fmt.Errorf("fivegc_procedure_total{nf=SMF,procedure=FeatureNegotiation,result=%s} delta = %v, want %v", r, d, want)
		}
	}
	return nil
}

func initFeatureNegotiationScenario(t *testing.T) func(*godog.ScenarioContext) {
	return func(sc *godog.ScenarioContext) {
		w := &fnWorld{t: t}
		sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
			*w = fnWorld{t: t}
			return ctx, nil
		})
		sc.Step(`^a test Nsmf_PDUSession feature catalog where F1 is bit 1 \(Rel-17\) and F9 is bit 9 \(Rel-19\)$`, w.catalogGiven)
		sc.Step(`^the SMF SBI server is running for feature negotiation$`, w.serverRunning)
		sc.Step(`^the SMF runs with release profile "([^"]*)"$`, w.profileIs)

		sc.Step(`^the AMF POSTs CreateSMContext with supportedFeatures (absent|"([^"]*)")$`, w.postOffer)
		sc.Step(`^the AMF POSTs CreateSMContext with supportedFeatures "([^"]*)" and an unknown JSON attribute "([^"]*)"$`, w.postOfferUnknown)

		sc.Step(`^the SMF responds (\d+) (Created|Bad Request)$`, func(code int, text string) error {
			if want := http.StatusText(code); text != want {
				return fmt.Errorf("status text %q does not match code %d (%q)", text, code, want)
			}
			return w.responds(code)
		})
		sc.Step(`^the SmContextCreatedData supportedFeatures is "([^"]*)"$`, w.answerIs)
		sc.Step(`^the SmContextCreatedData has no supportedFeatures attribute$`, w.answerAbsent)
		sc.Step(`^the SM context stores the negotiated feature set "([^"]*)"$`, w.storedSet)
		sc.Step(`^the SMF sends no F9-tied IE in responses for that SM context$`, w.noF9IE)
		sc.Step(`^the SmContextCreatedData is byte-identical to the pre-negotiation baseline$`, w.byteIdentical)
		sc.Step(`^the unknown attribute "([^"]*)" is not echoed in the SmContextCreatedData$`, w.unknownNotEchoed)
		sc.Step(`^the ProblemDetails cause is "([^"]*)"$`, w.causeIs)
		sc.Step(`^the ProblemDetails invalidParams first param is "([^"]*)"$`, w.paramIs)
		sc.Step(`^no SM context is created$`, w.noContext)

		sc.Step(`^a FeatureNegotiation log has features_local "([^"]*)", features_peer "([^"]*)", features_negotiated "([^"]*)" and result "([^"]*)"$`, w.logFull)
		sc.Step(`^a FeatureNegotiation log has features_negotiated "([^"]*)" and result "([^"]*)"$`, w.logNeg)
		sc.Step(`^a FeatureNegotiation log has features_peer "([^"]*)", cause "([^"]*)", spec_ref "([^"]*)" and result "([^"]*)"$`, w.logReject)
		sc.Step(`^the FeatureNegotiation counter with result "([^"]*)" increased by 1$`, w.counterInc)
	}
}

func TestFeatureNegotiationFeature(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initFeatureNegotiationScenario(t),
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/feature_negotiation.feature"},
			Strict:   true,
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
