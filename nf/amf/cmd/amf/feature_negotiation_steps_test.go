package main

// feature_negotiation_steps_test.go - godog runner for the @nsmf-consumer
// scenarios of ../../tests/features/feature_negotiation.feature (REL19-2.8): the
// AMF as Nsmf_PDUSession consumer negotiating supportedFeatures on
// CreateSMContext (TS 29.500 §6.6.2; decisions D2, rules R1, R2, R11-R14).
//
// The suite lives in package main because HTTPSMFClient is declared here (same
// reason as sbi_redirection_steps_test.go). The @namf-producer scenarios of the
// same feature file run in nf/amf/tests/features (TestFeatureNegotiationProducer).
// `make -C nf/amf test-functional` runs this test explicitly with -run.
//
// "The AMF stores the negotiated feature set on PDU session N" is asserted on
// the set returned by HTTPSMFClient.CreateSMContext: that value is stored
// verbatim as amfctx.PDUSession.Features by the NAS handler (nas.go, after
// CallSMF). OBS: the fivegc_procedure_total{nf="AMF",procedure="FeatureNegotiation"}
// delta is asserted in the counter Then-step (snapshot at the When step).
// Ref: TS 29.502 §6.1.8 (Table 6.1.8-1), TS 29.571 §5.2.2.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

const fnCorrelationID = "01JTESTFEATNEG000000000000"

// fnCatalog is the symbolic test catalog: F1 = bit 1 (Rel-17), F9 = bit 9
// (Rel-19), both implemented. Local set: "1" under rel17, "101" under rel19.
func fnCatalog() *features.Catalog {
	return features.MustCatalog(
		features.Entry{Number: 1, Name: "F1", Release: capability.Rel17, Implemented: true},
		features.Entry{Number: 9, Name: "F9", Release: capability.Rel19, Implemented: true},
	)
}

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

type fnReq struct{ method, path, body string }

type fnWorld struct {
	catalog bool
	profile *capability.Profile
	smf     *httptest.Server
	mu      sync.Mutex
	reqs    []fnReq

	logs   *fnLogBuf
	client *HTTPSMFClient

	ref    string
	neg    features.Set
	err    error
	before map[string]float64
}

var fnResults = []string{"OK", "REJECT", "FAILURE"}

func fnCounter(result string) float64 {
	return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("AMF", features.ProcedureName, result))
}

func (w *fnWorld) reset() {
	if w.smf != nil {
		w.smf.Close()
	}
	*w = fnWorld{logs: &fnLogBuf{}}
}

func (w *fnWorld) catalogGiven() error { w.catalog = true; return nil }

func (w *fnWorld) namfCatalogGiven() error { return nil }

func (w *fnWorld) profileIs(name string) error {
	p, err := capability.NewProfile(capability.ReleaseConfig{Profile: name}, func(string) string { return "" })
	if err != nil {
		return err
	}
	w.profile = p
	return nil
}

// startSMF starts the mock SMF answering every request with 201 and body.
func (w *fnWorld) startSMF(body string) {
	w.smf = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.reqs = append(w.reqs, fnReq{r.Method, r.URL.Path, string(raw)})
		w.mu.Unlock()
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(rw, body)
	}))
}

func (w *fnWorld) mockAnswers(sf string) error {
	w.startSMF(`{"smContextRef":"ctx-1","supportedFeatures":` + strconv.Quote(sf) + `}`)
	return nil
}

func (w *fnWorld) mockAnswersNone() error {
	w.startSMF(`{"smContextRef":"ctx-1"}`)
	return nil
}

func (w *fnWorld) mockAnswersUnknown(sf, attr string) error {
	w.startSMF(`{"smContextRef":"ctx-1","supportedFeatures":` + strconv.Quote(sf) + `,` + strconv.Quote(attr) + `:{"x":1}}`)
	return nil
}

func (w *fnWorld) requests() []fnReq {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]fnReq(nil), w.reqs...)
}

func (w *fnWorld) newClient() {
	logger := slog.New(slog.NewJSONHandler(w.logs, nil)).With("nf", "AMF")
	w.client = &HTTPSMFClient{
		address: strings.TrimPrefix(w.smf.URL, "https://"),
		client:  w.smf.Client(),
		profile: w.profile,
		catalog: fnCatalog(),
		logger:  logger,
	}
}

func (w *fnWorld) createSMContext(psi int) error {
	if !w.catalog || w.smf == nil {
		return fmt.Errorf("catalog or mock SMF not set up")
	}
	if w.profile == nil {
		return fmt.Errorf("release profile not set: the \"AMF runs with release profile\" step did not run")
	}
	w.newClient()
	w.before = map[string]float64{}
	for _, r := range fnResults {
		w.before[r] = fnCounter(r)
	}
	ctx, cancel := context.WithTimeout(logging.WithCorrelationID(context.Background(), fnCorrelationID), 20*time.Second)
	defer cancel()
	w.ref, _, _, w.neg, w.err = w.client.CreateSMContext(ctx, "imsi-001010000000001", "internet", uint8(psi),
		[]byte{1, 2, 3}, amfctx.SNSSAISubscribed{SST: 1, SD: "000001"})
	return nil
}

func (w *fnWorld) firstBody() (map[string]any, string, error) {
	r := w.requests()
	if len(r) == 0 {
		return nil, "", fmt.Errorf("mock SMF received no request")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r[0].body), &m); err != nil {
		return nil, "", fmt.Errorf("request body is not JSON: %w", err)
	}
	return m, r[0].body, nil
}

func (w *fnWorld) receivedFeatures(want string) error {
	m, _, err := w.firstBody()
	if err != nil {
		return err
	}
	if got, ok := m["supportedFeatures"].(string); !ok || got != want {
		return fmt.Errorf("SmContextCreateData supportedFeatures = %q (present=%v), want %q", got, ok, want)
	}
	return nil
}

func (w *fnWorld) receivedNoFeatures() error {
	m, _, err := w.firstBody()
	if err != nil {
		return err
	}
	if v, ok := m["supportedFeatures"]; ok {
		return fmt.Errorf("SmContextCreateData carries supportedFeatures %v, want none", v)
	}
	return nil
}

func (w *fnWorld) receivedBaseline() error {
	_, raw, err := w.firstBody()
	if err != nil {
		return err
	}
	if raw != redirBaselineBody {
		return fmt.Errorf("request body differs from the pre-negotiation baseline\n got %s\nwant %s", raw, redirBaselineBody)
	}
	return nil
}

func (w *fnWorld) storedSet(want string, psi int) error {
	if psi != 1 {
		return fmt.Errorf("unexpected PDU session %d", psi)
	}
	if w.err != nil {
		return fmt.Errorf("CreateSMContext failed: %w", w.err)
	}
	if got := w.neg.String(); got != want {
		return fmt.Errorf("negotiated feature set = %q, want %q", got, want)
	}
	return nil
}

// noF9InUpdate: F9 has no tied IE in the symbolic catalog; the observable
// guarantee is that F9 is not negotiated and a real UpdateSMContext carries only
// its baseline attribute (n2SmInfo), never supportedFeatures or an F9-tied IE.
func (w *fnWorld) noF9InUpdate(psi int) error {
	if w.neg.Has(9) {
		return fmt.Errorf("F9 negotiated (%s)", w.neg)
	}
	before := len(w.requests())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := w.client.UpdateSMContext(ctx, w.ref, []byte{9}); err != nil {
		return err
	}
	r := w.requests()
	if len(r) != before+1 {
		return fmt.Errorf("UpdateSMContext requests = %d, want %d", len(r), before+1)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(r[before].body), &m); err != nil {
		return err
	}
	if len(m) != 1 || m["n2SmInfo"] == nil {
		return fmt.Errorf("SmContextUpdateData has unexpected attributes: %s", r[before].body)
	}
	return nil
}

func (w *fnWorld) succeeds() error {
	if w.err != nil {
		return fmt.Errorf("PDU session establishment failed: %w", w.err)
	}
	if w.ref != "ctx-1" {
		return fmt.Errorf("smContextRef = %q, want ctx-1", w.ref)
	}
	return nil
}

func (w *fnWorld) expectRecord(want map[string]string) error {
	recs := w.logs.negotiations()
	if len(recs) != 1 {
		return fmt.Errorf("FeatureNegotiation records = %d, want 1", len(recs))
	}
	want["nf"] = "AMF"
	want["interface"] = "Nsmf"
	want["direction"] = "OUT"
	want["peer_nf_type"] = "SMF"
	want["correlation_id"] = fnCorrelationID
	for k, v := range want {
		if recs[0][k] != v {
			return fmt.Errorf("log %s = %v, want %q (record %v)", k, recs[0][k], v, recs[0])
		}
	}
	return nil
}

func (w *fnWorld) logFull(local, peer, neg, result string) error {
	return w.expectRecord(map[string]string{"features_local": local, "features_peer": peer, "features_negotiated": neg, "result": result})
}

func (w *fnWorld) logPeerResult(peer, result string) error {
	return w.expectRecord(map[string]string{"features_peer": peer, "result": result})
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

func initFeatureNegotiationConsumerScenario() func(*godog.ScenarioContext) {
	return func(sc *godog.ScenarioContext) {
		w := &fnWorld{logs: &fnLogBuf{}}
		sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
			w.reset()
			return ctx, nil
		})
		sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
			if w.smf != nil {
				w.smf.Close()
				w.smf = nil
			}
			return ctx, nil
		})
		sc.Step(`^a test Nsmf_PDUSession feature catalog where F1 is bit 1 \(Rel-17\) and F9 is bit 9 \(Rel-19\)$`, w.catalogGiven)
		sc.Step(`^a test Namf_Communication feature catalog where F1 is bit 1 \(Rel-17\) and F9 is bit 9 \(Rel-19\)$`, w.namfCatalogGiven)
		sc.Step(`^the AMF runs with release profile "([^"]*)"$`, w.profileIs)

		sc.Step(`^a mock SMF answers CreateSMContext with 201 and supportedFeatures "([^"]*)"$`, w.mockAnswers)
		sc.Step(`^a mock SMF answers CreateSMContext with 201 and no supportedFeatures$`, w.mockAnswersNone)
		sc.Step(`^a mock SMF answers CreateSMContext with 201, supportedFeatures "([^"]*)" and an unknown JSON attribute "([^"]*)"$`, w.mockAnswersUnknown)
		sc.Step(`^the AMF creates an SM context for PDU session (\d+)$`, w.createSMContext)

		sc.Step(`^the mock SMF received supportedFeatures "([^"]*)" in SmContextCreateData$`, w.receivedFeatures)
		sc.Step(`^the mock SMF received SmContextCreateData without a supportedFeatures attribute$`, w.receivedNoFeatures)
		sc.Step(`^the mock SMF received a request body byte-identical to the pre-negotiation baseline$`, w.receivedBaseline)
		sc.Step(`^the AMF stores the negotiated feature set "([^"]*)" on PDU session (\d+)$`, w.storedSet)
		sc.Step(`^the AMF sends no F9-tied IE in later SmContextUpdateData for PDU session (\d+)$`, w.noF9InUpdate)
		sc.Step(`^the PDU session establishment succeeds$`, w.succeeds)
		sc.Step(`^a consumer FeatureNegotiation log has features_local "([^"]*)", features_peer "([^"]*)", features_negotiated "([^"]*)" and result "([^"]*)"$`, w.logFull)
		sc.Step(`^a consumer FeatureNegotiation log has features_peer "([^"]*)" and result "([^"]*)"$`, w.logPeerResult)
		sc.Step(`^the AMF FeatureNegotiation counter with result "([^"]*)" increased by 1$`, w.counterInc)
	}
}

func TestFeatureNegotiationConsumer(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initFeatureNegotiationConsumerScenario(),
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/feature_negotiation.feature"},
			Tags:     "@nsmf-consumer",
			Strict:   true,
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
