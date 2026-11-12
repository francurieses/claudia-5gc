//go:build functional

// Package features contains the godog BDD step definitions of the PCF. Run with:
//
//	make -C nf/pcf test-functional
//	go test -race -count=1 -tags=functional ./nf/pcf/tests/...
//
// Every scenario drives a real in-process PCF SBI server (server.New + Start on a
// free loopback port, plain HTTP/h2c unless the scenario is about TLS) with an
// http.Client, so the full middleware/mux/handler chain is exercised. Each scenario
// gets a fresh server, log buffer and config, so scenarios are order-independent.
//
// Feature files:
//
//	pcf_openapi_conformance.feature  Rel-17 OpenAPI wire behaviour (PCF-003)
//	am_policy.feature                Npcf_AMPolicyControl create/delete (TS 29.507)
//	sm_policy_update.feature         SM policy association update (TS 29.512 §5.2.2.3)
//	ursp.feature                     @e2e: needs AMF + UDR + UERANSIM, excluded here
//
// Tag handling: "@e2e" scenarios (live stack) are always excluded.
//
// Ref: TS 29.501 §4.4.1, TS 29.507, TS 29.512, TS 29.514, TS 29.525, TS 29.500.
package features_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/francurieses/claudia-5gc/nf/pcf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/pcf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const (
	testCorrID = "01TESTCORRELATIONID00000000"
	testSUPI   = "imsi-001010000000001"
	readyWait  = 10 * time.Second
)

// ---- thread-safe log buffer -------------------------------------------------

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

// ---- per-scenario world -----------------------------------------------------

type world struct {
	cfg     *config.Config
	profile string
	logs    *syncBuf

	srv    *server.Server
	cancel context.CancelFunc
	done   chan error
	addr   string // listen address host:port
	port   int

	// last response
	status int
	header http.Header
	body   []byte
	obj    map[string]any

	// existing resource (Given "an existing ...")
	existingKind string
	existingID   string

	// metric snapshot taken just before the last request of a 413 scenario
	metricBefore map[string]float64

	// legacy steps
	smSUPI, smDNN string
	smPolicyID    string
	lastLocation  string

	// TLS scenarios
	pki        *testPKI
	restoreEnv []func()
}

func newWorld() *world { return &world{} }

func (w *world) reset() {
	w.stop()
	for i := len(w.restoreEnv) - 1; i >= 0; i-- {
		w.restoreEnv[i]()
	}
	*w = world{}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// defaultConfig mirrors config/dev.yaml values relevant to the Npcf handlers.
func (w *world) defaultConfig() error {
	port, err := freePort()
	if err != nil {
		return fmt.Errorf("allocate free port: %w", err)
	}
	w.port = port
	w.addr = fmt.Sprintf("127.0.0.1:%d", port)
	w.logs = &syncBuf{}
	cfg := &config.Config{NFInstanceID: "00000000-0000-4006-8000-000000000001"}
	cfg.PLMN.MCC, cfg.PLMN.MNC = "001", "01"
	cfg.SBI.Address = w.addr
	cfg.DefaultSMPolicy = config.SMPolicyDefaults{
		SessionAMBRUplink:   "100 Mbps",
		SessionAMBRDownlink: "100 Mbps",
		FiveQI:              9,
		ARPPriorityLevel:    8,
		ARPPreemptCap:       "NOT_PREEMPT",
		ARPPreemptVuln:      "NOT_PREEMPTABLE",
		FlowDescription:     "permit out ip from any to assigned",
		FlowPrecedence:      100,
	}
	w.cfg = cfg
	return nil
}

func (w *world) needCfg() error {
	if w.cfg == nil {
		return errors.New("no PCF configuration: the scenario must start with 'a PCF instance with default configuration'")
	}
	return nil
}

// start builds and starts the PCF SBI server (idempotent). Configuration steps
// must run before the first request; the config is not mutated afterwards.
func (w *world) start() error {
	if w.srv != nil {
		return nil
	}
	if err := w.needCfg(); err != nil {
		return err
	}
	// Like cmd/pcf/main.go, the process logger already carries nf (exactly once).
	logger := slog.New(slog.NewJSONHandler(w.logs, nil)).With("nf", "PCF")
	s, err := server.New(w.cfg, logger)
	if err != nil {
		return fmt.Errorf("server.New: %w", err)
	}
	if w.profile != "" {
		p, err := capability.NewProfile(capability.ReleaseConfig{Profile: w.profile}, func(string) string { return "" })
		if err != nil {
			return fmt.Errorf("release profile %q: %w", w.profile, err)
		}
		s.SetProfile(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	w.srv, w.cancel, w.done = s, cancel, done

	deadline := time.Now().Add(readyWait)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return fmt.Errorf("PCF server exited during start: %v", err)
		default:
		}
		c, err := net.DialTimeout("tcp", w.addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond) // poll with a deadline
	}
	return fmt.Errorf("PCF server did not listen on %s within %s", w.addr, readyWait)
}

func (w *world) stop() {
	if w.cancel != nil {
		w.cancel()
		select {
		case <-w.done:
		case <-time.After(10 * time.Second):
		}
		w.cancel = nil
	}
	w.srv = nil
}

// ---- HTTP helper ------------------------------------------------------------

var plainClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// do sends one request to the PCF and stores the response. host overrides the
// Host header when non-empty.
func (w *world) do(method, path string, body []byte, host string) error {
	if err := w.start(); err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://"+w.addr+path, rd)
	if err != nil {
		return err
	}
	if host != "" {
		req.Host = host
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Correlation-Id", testCorrID)
	resp, err := plainClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s %s: read body: %w", method, path, err)
	}
	w.status, w.header, w.body, w.obj = resp.StatusCode, resp.Header, raw, nil
	if len(bytes.TrimSpace(raw)) > 0 {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			w.obj = m
		}
	}
	return nil
}

func lastSegment(s string) string { return s[strings.LastIndex(s, "/")+1:] }

// ---- request bodies / resource kinds ----------------------------------------

type kindInfo struct {
	createPath string
	body       string
	procCreate string
	procDelete string
}

var kinds = map[string]kindInfo{
	"SM policy": {"/npcf-smpolicycontrol/v1/sm-policies",
		`{"supi":"` + testSUPI + `","dnn":"internet"}`, "SmPolicyCreate", "SmPolicyDelete"},
	"AM policy association": {"/npcf-am-policy-control/v1/policies",
		`{"supi":"` + testSUPI + `","accessType":"3GPP_ACCESS","plmnId":{"mcc":"001","mnc":"01"}}`, "AMPolicyCreate", "AMPolicyDelete"},
	"UE policy association": {"/npcf-ue-policy-control/v1/policies",
		`{"supi":"` + testSUPI + `"}`, "UEPolicyCreate", "UEPolicyDelete"},
	"Policy authorization session": {"/npcf-policyauthorization/v1/app-sessions",
		`{"ascReqData":{"ueIpv4":"10.60.0.1","qosReference":"qos-1"}}`, "PolicyAuthorizationCreate", "PolicyAuthorizationDelete"},
}

// kindAliases maps the wording of "Given an existing <resource>" to a kind.
var kindAliases = map[string]string{
	"SM policy":             "SM policy",
	"AM policy":             "AM policy association",
	"UE policy":             "UE policy association",
	"app session":           "Policy authorization session",
	"AM policy association": "AM policy association",
	"UE policy association": "UE policy association",
}

func kindOf(name string) (kindInfo, error) {
	if a, ok := kindAliases[name]; ok {
		name = a
	}
	k, ok := kinds[name]
	if !ok {
		return kindInfo{}, fmt.Errorf("unknown resource/service %q", name)
	}
	return k, nil
}

// ---- Background / Given -----------------------------------------------------

func (w *world) aPCFWithDefaultConfig() error { return w.defaultConfig() }

func (w *world) fqdnOnFreePort(fqdn string) error {
	if err := w.needCfg(); err != nil {
		return err
	}
	w.cfg.SBI.FQDN = fqdn
	return nil
}

func (w *world) noFQDN() error {
	if err := w.needCfg(); err != nil {
		return err
	}
	w.cfg.SBI.FQDN = ""
	return nil
}

func (w *world) runsWithProfile(p string) error {
	if err := w.needCfg(); err != nil {
		return err
	}
	w.profile = p
	return nil
}

func (w *world) ursPolicyConfigured() error {
	if err := w.needCfg(); err != nil {
		return err
	}
	w.cfg.DefaultURSP.Rules = []config.URSPRuleConfig{{Precedence: 255}}
	w.cfg.DefaultURSP.Rules[0].TrafficDescriptor.MatchAll = true
	return nil
}

func (w *world) existingResource(name string) error {
	k, err := kindOf(name)
	if err != nil {
		return err
	}
	if err := w.do(http.MethodPost, k.createPath, []byte(k.body), ""); err != nil {
		return err
	}
	if w.status != http.StatusCreated {
		return fmt.Errorf("create %s: status %d, body %s", name, w.status, w.body)
	}
	loc := w.header.Get("Location")
	if loc == "" {
		return fmt.Errorf("create %s: no Location header", name)
	}
	w.existingKind, w.existingID = name, lastSegment(loc)
	return nil
}

// ---- When ---------------------------------------------------------------------

func (w *world) postValidBody(path, service string) error {
	return w.postValid(path, service, "")
}

func (w *world) postValidBodyHost(path, service, host string) error {
	return w.postValid(path, service, host)
}

func (w *world) postValidBodyNoSuppFeat(path, service, _ string) error {
	return w.postValid(path, service, "")
}

func (w *world) postValid(path, service, host string) error {
	k, err := kindOf(service)
	if err != nil {
		return err
	}
	return w.do(http.MethodPost, path, []byte(k.body), host)
}

func (w *world) sendsMethodPath(method, path string) error {
	path = strings.ReplaceAll(path, "{id}", w.existingID)
	var body []byte
	if method == http.MethodPost {
		body = []byte(`{}`)
	}
	return w.do(method, path, body, "")
}

func (w *world) postOversized(path string) error {
	path = strings.ReplaceAll(path, "{id}", w.existingID)
	w.metricBefore = metricSnapshot()
	// valid JSON, 1 MiB + 1 KiB: the body cap (1 MiB) is hit before any state change.
	pad := strings.Repeat("a", 1<<20+1024)
	return w.do(http.MethodPost, path, []byte(`{"pad":"`+pad+`"}`), "")
}

func (w *world) deleteThatResource() error {
	switch w.existingKind {
	case "UE policy association":
		return w.do(http.MethodDelete, "/npcf-ue-policy-control/v1/policies/"+w.existingID, nil, "")
	case "AM policy association":
		return w.do(http.MethodDelete, "/npcf-am-policy-control/v1/policies/"+w.existingID, nil, "")
	}
	return fmt.Errorf("no DELETE-style delete for %q", w.existingKind)
}

func (w *world) deleteThatNamed(name string) error {
	if kindAliases[name] != w.existingKind && name != w.existingKind {
		return fmt.Errorf("existing resource is %q, not %q", w.existingKind, name)
	}
	return w.deleteThatResource()
}

// ---- Then: status / headers / body -----------------------------------------------

func (w *world) statusIs(want int) error {
	if w.status != want {
		return fmt.Errorf("status = %d, want %d (body %s)", w.status, want, w.body)
	}
	return nil
}

func (w *world) status404or405() error {
	if w.status != http.StatusNotFound && w.status != http.StatusMethodNotAllowed {
		return fmt.Errorf("status = %d, want 404 or 405 (body %s)", w.status, w.body)
	}
	return nil
}

func (w *world) expandPort(s string) string {
	return strings.ReplaceAll(s, "{port}", strconv.Itoa(w.port))
}

func (w *world) locationStartsWith(prefix string) error {
	loc := w.header.Get("Location")
	prefix = w.expandPort(prefix)
	if loc == "" {
		return errors.New("no Location header")
	}
	if !strings.HasPrefix(loc, prefix) || len(loc) == len(prefix) {
		return fmt.Errorf("Location %q does not start with %q followed by an identifier", loc, prefix)
	}
	return nil
}

func (w *world) locationEndsWithID() error {
	loc := w.header.Get("Location")
	id := lastSegment(loc)
	if id == "" || strings.Contains(id, "?") {
		return fmt.Errorf("Location %q has no resource identifier", loc)
	}
	if v, ok := w.obj["smPolicyId"].(string); ok {
		return fmt.Errorf("body carries non-schema smPolicyId %q (id %q is only in Location)", v, id)
	}
	if v, ok := w.obj["appSessionId"].(string); ok {
		return fmt.Errorf("body carries non-schema appSessionId %q (id %q is only in Location)", v, id)
	}
	return nil
}

func (w *world) bodyEmpty() error {
	if len(bytes.TrimSpace(w.body)) != 0 {
		return fmt.Errorf("body not empty: %s", w.body)
	}
	return nil
}

func (w *world) problemCause(cause string) error {
	if w.obj == nil {
		return fmt.Errorf("response is not a JSON ProblemDetails: %s", w.body)
	}
	if got, _ := w.obj["cause"].(string); got != cause {
		return fmt.Errorf("ProblemDetails cause = %q, want %q (body %s)", got, cause, w.body)
	}
	if _, ok := w.obj["status"]; !ok {
		return fmt.Errorf("ProblemDetails lacks status: %s", w.body)
	}
	return nil
}

func (w *world) bodyHasNo(attr string) error {
	if w.obj == nil {
		return fmt.Errorf("response is not a JSON object: %q", w.body)
	}
	if _, present := w.obj[attr]; present {
		return fmt.Errorf("body carries %q: %s", attr, w.body)
	}
	return nil
}

func (w *world) bodyHasEqual(attr, want string) error {
	if w.obj == nil {
		return fmt.Errorf("response is not a JSON object: %q", w.body)
	}
	if got, _ := w.obj[attr].(string); got != want {
		return fmt.Errorf("body %q = %v, want %q (body %s)", attr, w.obj[attr], want, w.body)
	}
	return nil
}

func (w *world) bodyHasBase64(attr string) error {
	s, ok := w.obj[attr].(string)
	if !ok || s == "" {
		return fmt.Errorf("body %q missing or not a non-empty string: %s", attr, w.body)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) == 0 {
		return fmt.Errorf("body %q is not non-empty base64: %v", attr, err)
	}
	return nil
}

// ---- metrics ----------------------------------------------------------------------

var metricNames = []string{
	"SmPolicyCreate", "SmPolicyDelete", "PolicyAuthorizationCreate", "PolicyAuthorizationDelete",
}

func metricVal(proc, result string) float64 {
	return testutil.ToFloat64(metrics.ProcedureTotal.WithLabelValues("PCF", proc, result))
}

func metricSnapshot() map[string]float64 {
	m := map[string]float64{}
	for _, n := range metricNames {
		m[n] = metricVal(n, "REJECT")
	}
	return m
}

func (w *world) counterIncremented(proc, result string) error {
	if result != "REJECT" {
		return fmt.Errorf("only REJECT is snapshotted, got %q", result)
	}
	before, ok := w.metricBefore[proc]
	if !ok {
		return fmt.Errorf("no metric snapshot for %q", proc)
	}
	if d := metricVal(proc, result) - before; d != 1 {
		return fmt.Errorf("fivegc_procedure_total{nf=PCF,procedure=%s,result=%s} delta = %v, want 1", proc, result, d)
	}
	return nil
}

func (w *world) counterNotIncremented(proc string) error {
	before, ok := w.metricBefore[proc]
	if !ok {
		return fmt.Errorf("no metric snapshot for %q", proc)
	}
	if d := metricVal(proc, "REJECT") - before; d != 0 {
		return fmt.Errorf("fivegc_procedure_total{nf=PCF,procedure=%s,result=REJECT} delta = %v, want 0", proc, d)
	}
	return nil
}

// ---- logs -------------------------------------------------------------------------

// logRecords decodes the captured JSON lines and fails on a repeated top-level
// key (slog does not de-duplicate attributes).
func (w *world) logRecords() ([]map[string]any, error) {
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(w.logs.bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		if _, err := dec.Token(); err != nil {
			return nil, fmt.Errorf("log line is not JSON: %s", line)
		}
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("log line %s: %w", line, err)
			}
			key, _ := k.(string)
			if seen[key] {
				return nil, fmt.Errorf("duplicate key %q in log line: %s", key, line)
			}
			seen[key] = true
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, fmt.Errorf("log line %s: %w", line, err)
			}
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

func (w *world) logLineWith(proc, result string) error {
	recs, err := w.logRecords()
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r["procedure"] == proc && r["result"] == result {
			return nil
		}
	}
	return fmt.Errorf("no log line with procedure %q and result %q in:\n%s", proc, result, w.logs.bytes())
}

func (w *world) everyLineHasFieldOnce(field, want string) error {
	recs, err := w.logRecords() // rejects duplicate keys
	if err != nil {
		return err
	}
	if len(recs) == 0 {
		return errors.New("no log lines captured")
	}
	for _, r := range recs {
		if r[field] != want {
			return fmt.Errorf("log line %q has %s=%v, want %q", r["msg"], field, r[field], want)
		}
	}
	return nil
}

func (w *world) procRecord(proc, direction string, withResult bool) (map[string]any, error) {
	recs, err := w.logRecords()
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		_, hasRes := r["result"]
		if r["procedure"] == proc && r["direction"] == direction && hasRes == withResult {
			return r, nil
		}
	}
	return nil, fmt.Errorf("no %s log line (direction %s, result present=%v) for procedure %q in:\n%s",
		map[bool]string{true: "outcome", false: "received"}[withResult], direction, withResult, proc, w.logs.bytes())
}

func checkMandatory(r map[string]any) error {
	for _, k := range []string{"nf", "procedure", "correlation_id", "interface", "direction", "spec_ref"} {
		if v, _ := r[k].(string); v == "" {
			return fmt.Errorf("log line %q lacks %q: %v", r["msg"], k, r)
		}
	}
	return nil
}

func (w *world) receivedLine(proc, iface, dir string) error {
	r, err := w.procRecord(proc, dir, false)
	if err != nil {
		return err
	}
	if err := checkMandatory(r); err != nil {
		return err
	}
	if r["interface"] != iface {
		return fmt.Errorf("received line interface = %v, want %q", r["interface"], iface)
	}
	return nil
}

func (w *world) outcomeLine(proc, iface, dir, result string) error {
	r, err := w.procRecord(proc, dir, true)
	if err != nil {
		return err
	}
	if err := checkMandatory(r); err != nil {
		return err
	}
	if r["interface"] != iface || r["result"] != result {
		return fmt.Errorf("outcome line interface=%v result=%v, want %q/%q", r["interface"], r["result"], iface, result)
	}
	return nil
}

func (w *world) outcomeCorrAndSpecRef(prefix string) error {
	recs, err := w.logRecords()
	if err != nil {
		return err
	}
	found := false
	for _, r := range recs {
		if _, ok := r["result"]; !ok || r["direction"] != "OUT" {
			continue
		}
		found = true
		if c, _ := r["correlation_id"].(string); c == "" {
			return fmt.Errorf("outcome line %q has an empty correlation_id", r["msg"])
		}
		if sr, _ := r["spec_ref"].(string); !strings.HasPrefix(sr, prefix) {
			return fmt.Errorf("outcome line %q spec_ref = %q, want prefix %q", r["msg"], sr, prefix)
		}
	}
	if !found {
		return errors.New("no outcome log line found")
	}
	return nil
}

// ---- TLS scenario ---------------------------------------------------------------------

type testPKI struct {
	dir                       string
	caFile, certFile, keyFile string
	serverDER                 []byte
	caPool                    *x509.CertPool
	clientCert                tls.Certificate
	otherClient               tls.Certificate // signed by an unrelated CA
	caCert                    *x509.Certificate
	caKey                     *ecdsa.PrivateKey
}

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}

func issue(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, serial int64, eku x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, der, err
}

func newCA(cn string, serial int64) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, der, err
}

func buildPKI() (*testPKI, error) {
	dir, err := os.MkdirTemp("", "pcf-pki-")
	if err != nil {
		return nil, err
	}
	p := &testPKI{dir: dir, caFile: filepath.Join(dir, "ca.crt"), certFile: filepath.Join(dir, "pcf.crt"), keyFile: filepath.Join(dir, "pcf.key")}
	ca, caKey, caDER, err := newCA("test-ca", 1)
	if err != nil {
		return nil, err
	}
	p.caCert, p.caKey = ca, caKey
	p.caPool = x509.NewCertPool()
	p.caPool.AddCert(ca)
	if err := writePEM(p.caFile, "CERTIFICATE", caDER); err != nil {
		return nil, err
	}
	_, srvKey, srvDER, err := issue(ca, caKey, "pcf", 2, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	p.serverDER = srvDER
	keyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return nil, err
	}
	if err := writePEM(p.certFile, "CERTIFICATE", srvDER); err != nil {
		return nil, err
	}
	if err := writePEM(p.keyFile, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, err
	}
	_, cKey, cDER, err := issue(ca, caKey, "client", 3, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	p.clientCert = tls.Certificate{Certificate: [][]byte{cDER}, PrivateKey: cKey}
	oca, ocaKey, _, err := newCA("other-ca", 10)
	if err != nil {
		return nil, err
	}
	_, oKey, oDER, err := issue(oca, ocaKey, "rogue-client", 11, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	p.otherClient = tls.Certificate{Certificate: [][]byte{oDER}, PrivateKey: oKey}
	return p, nil
}

func (w *world) setEnv(k, v string) {
	old, had := os.LookupEnv(k)
	_ = os.Setenv(k, v)
	w.restoreEnv = append(w.restoreEnv, func() {
		if had {
			_ = os.Setenv(k, old)
		} else {
			_ = os.Unsetenv(k)
		}
	})
}

func (w *world) yamlConfigWithTLS() error {
	pki, err := buildPKI()
	if err != nil {
		return fmt.Errorf("build test PKI: %w", err)
	}
	w.pki = pki
	w.restoreEnv = append(w.restoreEnv, func() { _ = os.RemoveAll(pki.dir) })
	port, err := freePort()
	if err != nil {
		return err
	}
	w.port = port
	w.addr = fmt.Sprintf("127.0.0.1:%d", port)
	w.logs = &syncBuf{}
	yml := fmt.Sprintf("sbi:\n  address: %q\n  fqdn: \"pcf.test\"\n  tls:\n    cert_file: %q\n    key_file: %q\n    ca_file: %q\n",
		w.addr, pki.certFile, pki.keyFile, pki.caFile)
	cfgPath := filepath.Join(pki.dir, "pcf.yaml")
	if err := os.WriteFile(cfgPath, []byte(yml), 0o600); err != nil {
		return err
	}
	w.setEnv("CONFIG_PATH", cfgPath)
	w.setEnv("OPERATOR_CONFIG_PATH", filepath.Join(pki.dir, "absent-operator.yaml"))
	return nil
}

func (w *world) serverBuiltFromConfig() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config.Load: %w", err)
	}
	if cfg.SBI.TLS.CertFile != w.pki.certFile || cfg.SBI.TLS.KeyFile != w.pki.keyFile || cfg.SBI.TLS.CAFile != w.pki.caFile {
		return fmt.Errorf("nested sbi.tls keys not honoured by config.Load: %+v", cfg.SBI.TLS)
	}
	w.cfg = cfg
	return w.start() // server.New loads the key pair; a bad path or ignored key fails here
}

func (w *world) tlsUsesCertAndKey() error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", w.addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test: identity is compared byte for byte below
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
	})
	if err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if len(st.PeerCertificates) == 0 || !bytes.Equal(st.PeerCertificates[0].Raw, w.pki.serverDER) {
		return errors.New("server presented a certificate other than sbi.tls.cert_file")
	}
	if st.NegotiatedProtocol != "h2" {
		return fmt.Errorf("negotiated ALPN %q, want h2", st.NegotiatedProtocol)
	}
	return nil
}

func (w *world) get(client *tls.Config) (int, error) {
	tr := &http.Transport{TLSClientConfig: client, ForceAttemptHTTP2: true, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := c.Get("https://" + w.addr + "/healthz")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func (w *world) clientCAPoolAndRequired() error {
	base := func(certs ...tls.Certificate) *tls.Config {
		return &tls.Config{RootCAs: w.pki.caPool, MinVersion: tls.VersionTLS13, Certificates: certs}
	}
	if code, err := w.get(base()); err == nil {
		return fmt.Errorf("server accepted a client without a certificate (status %d): ClientAuth is not RequireAndVerifyClientCert and sbi.tls.ca_file is not used as ClientCAs", code)
	}
	if code, err := w.get(base(w.pki.otherClient)); err == nil {
		return fmt.Errorf("server accepted a client certificate from an unrelated CA (status %d)", code)
	}
	if code, err := w.get(base(w.pki.clientCert)); err != nil || code != http.StatusOK {
		return fmt.Errorf("client certificate signed by ca_file rejected: status %d err %v", code, err)
	}
	return nil
}

// ---- legacy feature steps -------------------------------------------------------------

func (w *world) amfCreatesAM(supi, access string) error {
	b, _ := json.Marshal(map[string]string{"supi": supi, "accessType": access})
	return w.do(http.MethodPost, kinds["AM policy association"].createPath, b, "")
}

func (w *world) amfCreatesAMWithoutSupi() error {
	return w.do(http.MethodPost, kinds["AM policy association"].createPath, []byte(`{"accessType":"3GPP_ACCESS"}`), "")
}

func (w *world) existingAMFor(supi string) error {
	if err := w.amfCreatesAM(supi, "3GPP_ACCESS"); err != nil {
		return err
	}
	if w.status != http.StatusCreated {
		return fmt.Errorf("create AM policy: %d %s", w.status, w.body)
	}
	w.existingKind, w.existingID = "AM policy association", lastSegment(w.header.Get("Location"))
	return nil
}

func (w *world) amfDeletesAM() error {
	if w.existingID == "" {
		return errors.New("no existing AM policy association")
	}
	return w.do(http.MethodDelete, kinds["AM policy association"].createPath+"/"+w.existingID, nil, "")
}

func (w *world) responseStatus(n int) error { return w.statusIs(n) }

func (w *world) causeIs(c string) error { return w.problemCause(c) }

func (w *world) locationAbsoluteAMResource() error {
	loc := w.header.Get("Location")
	pre := "https://" + w.addr + kinds["AM policy association"].createPath + "/"
	if !strings.HasPrefix(loc, pre) || len(loc) == len(pre) {
		return fmt.Errorf("Location %q, want absolute %s<polAssoId>", loc, pre)
	}
	w.lastLocation = loc
	return nil
}

func (w *world) bodyHasNoPolAssoID() error { return w.bodyHasNo("polAssoId") }

func (w *world) pcfWithExistingSMPolicy(supi, dnn string) error {
	if err := w.defaultConfig(); err != nil {
		return err
	}
	w.smSUPI, w.smDNN = supi, dnn // the policy is created lazily, after the config Givens
	return nil
}

// ensureSMPolicy creates the Background SM policy on first use.
func (w *world) ensureSMPolicy() error {
	if w.smPolicyID != "" {
		return nil
	}
	b, _ := json.Marshal(map[string]string{"supi": w.smSUPI, "dnn": w.smDNN})
	if err := w.do(http.MethodPost, kinds["SM policy"].createPath, b, ""); err != nil {
		return err
	}
	if w.status != http.StatusCreated {
		return fmt.Errorf("create SM policy: %d %s", w.status, w.body)
	}
	w.smPolicyID = lastSegment(w.header.Get("Location"))
	return nil
}

func (w *world) authorisedSet(csv string) error {
	if err := w.needCfg(); err != nil {
		return err
	}
	var set []int
	for _, f := range strings.Split(csv, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil {
			return fmt.Errorf("bad 5QI %q", f)
		}
		set = append(set, n)
	}
	w.cfg.DefaultSMPolicy.Authorized5QI = set
	return nil
}

func (w *world) noAuthorisedRestriction() error {
	if err := w.needCfg(); err != nil {
		return err
	}
	w.cfg.DefaultSMPolicy.Authorized5QI = nil
	return nil
}

func (w *world) maxAMBR(mbps int) error {
	if err := w.needCfg(); err != nil {
		return err
	}
	w.cfg.DefaultSMPolicy.MaxSessionAMBRMbps = mbps
	return nil
}

func (w *world) overrideSets5QI(fiveQI int, supi string) error {
	b, _ := json.Marshal(map[string]int{"5qi": fiveQI})
	if err := w.do(http.MethodPut, "/pcf-internal/v1/subscribers/"+supi+"/sm-policy-override", b, ""); err != nil {
		return err
	}
	if w.status != http.StatusOK {
		return fmt.Errorf("set override: %d %s", w.status, w.body)
	}
	return nil
}

func (w *world) smfUpdate(body string) error {
	if err := w.ensureSMPolicy(); err != nil {
		return err
	}
	return w.do(http.MethodPost, kinds["SM policy"].createPath+"/"+w.smPolicyID+"/update", []byte(body), "")
}

func (w *world) smfUpdate5QI(n int) error {
	return w.smfUpdate(fmt.Sprintf(`{"reqQos":{"5qi":%d}}`, n))
}

func (w *world) smfUpdateUplink(ul string) error {
	b, _ := json.Marshal(map[string]any{"reqQos": map[string]any{"ambr": map[string]string{"uplink": ul}}})
	return w.smfUpdate(string(b))
}

func (w *world) smfUpdateUnknown() error {
	if err := w.start(); err != nil {
		return err
	}
	return w.do(http.MethodPost, kinds["SM policy"].createPath+"/unknown-sm-policy/update", []byte(`{}`), "")
}

func (w *world) decision5QI(want int) error {
	qd, _ := w.obj["qosDecs"].(map[string]any)
	d, _ := qd["qd-1"].(map[string]any)
	got, ok := d["5qi"].(float64)
	if !ok {
		return fmt.Errorf("decision has no qosDecs.qd-1.5qi: %s", w.body)
	}
	if int(got) != want {
		return fmt.Errorf("decision 5QI = %d, want %d", int(got), want)
	}
	return nil
}

// ---- wiring -----------------------------------------------------------------------------

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func initializeScenario(sc *godog.ScenarioContext) {
	w := newWorld()
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.reset()
		return ctx, nil
	})

	// Background / Given
	sc.Step(`^a PCF instance with default configuration$`, w.aPCFWithDefaultConfig)
	sc.Step(`^the PCF SBI FQDN is "([^"]*)" and it listens on a free local port$`, w.fqdnOnFreePort)
	sc.Step(`^the PCF has no SBI FQDN configured$`, w.noFQDN)
	sc.Step(`^the PCF runs with profile "([^"]*)"$`, w.runsWithProfile)
	sc.Step(`^a URSP policy is configured for the UE$`, w.ursPolicyConfigured)
	sc.Step(`^an existing (SM policy|app session|AM policy association|UE policy association)$`, w.existingResource)

	// When
	sc.Step(`^a consumer sends POST "([^"]*)" with a valid (.+) create body$`, w.postValidBody)
	sc.Step(`^a consumer sends POST "([^"]*)" with a valid (.+) create body and Host "([^"]*)"$`, w.postValidBodyHost)
	sc.Step(`^a consumer sends POST "([^"]*)" with a valid (.+) create body that (omits suppFeat)$`, w.postValidBodyNoSuppFeat)
	sc.Step(`^a consumer sends POST "([^"]*)" with a body larger than 1 MiB$`, w.postOversized)
	sc.Step(`^a consumer sends (POST|DELETE) "([^"]*)"$`, w.sendsMethodPath)
	sc.Step(`^a consumer sends DELETE on that UE policy association$`, w.deleteThatResource)
	sc.Step(`^a consumer sends the delete request for that (AM policy association|UE policy association)$`, w.deleteThatNamed)
	sc.Step(`^the PCF SBI server is built from that configuration$`, w.serverBuiltFromConfig)

	// Then
	sc.Step(`^the PCF responds with status (\d+)$`, func(s string) error { return w.statusIs(atoi(s)) })
	sc.Step(`^the PCF responds with status 404 or 405$`, w.status404or405)
	sc.Step(`^the Location header starts with "([^"]*)"$`, w.locationStartsWith)
	sc.Step(`^the Location header ends with the identifier of the created resource$`, w.locationEndsWithID)
	sc.Step(`^the response body is empty$`, w.bodyEmpty)
	sc.Step(`^the response is a ProblemDetails with cause "([^"]*)"$`, w.problemCause)
	sc.Step(`^the response body has a base64 "([^"]*)" attribute carrying the URSP container$`, w.bodyHasBase64)
	sc.Step(`^the response body has no "([^"]*)" attribute$`, w.bodyHasNo)
	sc.Step(`^the response body has "([^"]*)" equal to "([^"]*)"$`, w.bodyHasEqual)
	sc.Step(`^the procedure counter "([^"]*)" is incremented with result "([^"]*)"$`, w.counterIncremented)
	sc.Step(`^the procedure counter "([^"]*)" is not incremented$`, w.counterNotIncremented)
	sc.Step(`^a log line with procedure "([^"]*)" and result "([^"]*)" is emitted$`, w.logLineWith)
	sc.Step(`^every PCF log line has field "([^"]*)" equal to "([^"]*)" exactly once$`, w.everyLineHasFieldOnce)
	sc.Step(`^the received log line has procedure "([^"]*)", interface "([^"]*)", direction "([^"]*)"$`, w.receivedLine)
	sc.Step(`^the outcome log line has procedure "([^"]*)", interface "([^"]*)", direction "([^"]*)", result "([^"]*)"$`, w.outcomeLine)
	sc.Step(`^the outcome log line has a non-empty "correlation_id" and a "spec_ref" starting with "([^"]*)"$`, w.outcomeCorrAndSpecRef)

	// TLS
	sc.Step(`^a PCF YAML config with sbi\.tls\.cert_file, sbi\.tls\.key_file and sbi\.tls\.ca_file set to test PKI files$`, w.yamlConfigWithTLS)
	sc.Step(`^the server TLS configuration uses that certificate and key$`, w.tlsUsesCertAndKey)
	sc.Step(`^the client CA pool contains the configured ca_file and client certificates are required$`, w.clientCAPoolAndRequired)

	// am_policy.feature
	sc.Step(`^AMF creates an AM policy association for "([^"]*)" with accessType "([^"]*)"$`, w.amfCreatesAM)
	sc.Step(`^AMF creates an AM policy association without a supi$`, w.amfCreatesAMWithoutSupi)
	sc.Step(`^an existing AM policy association for "([^"]*)"$`, w.existingAMFor)
	sc.Step(`^AMF deletes the AM policy association$`, w.amfDeletesAM)
	sc.Step(`^the response status is (\d+)$`, func(s string) error { return w.responseStatus(atoi(s)) })
	sc.Step(`^the delete response status is (\d+)$`, func(s string) error { return w.responseStatus(atoi(s)) })
	sc.Step(`^the cause is "([^"]*)"$`, w.causeIs)
	sc.Step(`^the Location header is an absolute URI of the AM policy resource carrying the polAssoId$`, w.locationAbsoluteAMResource)
	sc.Step(`^the response body has no polAssoId attribute$`, w.bodyHasNoPolAssoID)

	// sm_policy_update.feature
	sc.Step(`^a PCF instance with an existing SM policy for "([^"]*)" on dnn "([^"]*)"$`, w.pcfWithExistingSMPolicy)
	sc.Step(`^the PCF authorised 5QI set is "([^"]*)"$`, w.authorisedSet)
	sc.Step(`^the PCF has no authorised 5QI restriction$`, w.noAuthorisedRestriction)
	sc.Step(`^the PCF max Session-AMBR is (\d+) Mbps$`, func(s string) error { return w.maxAMBR(atoi(s)) })
	sc.Step(`^a per-subscriber override sets 5QI (\d+) for "([^"]*)"$`, func(q, supi string) error { return w.overrideSets5QI(atoi(q), supi) })
	sc.Step(`^the SMF requests an SM policy update with 5QI (\d+)$`, func(s string) error { return w.smfUpdate5QI(atoi(s)) })
	sc.Step(`^the SMF requests an SM policy update with uplink "([^"]*)"$`, w.smfUpdateUplink)
	sc.Step(`^the SMF requests an SM policy update for an unknown smPolicyId$`, w.smfUpdateUnknown)
	sc.Step(`^the update response status is (\d+)$`, func(s string) error { return w.statusIs(atoi(s)) })
	sc.Step(`^the update cause is "([^"]*)"$`, w.causeIs)
	sc.Step(`^the decision 5QI is (\d+)$`, func(s string) error { return w.decision5QI(atoi(s)) })
}

func TestFeatures(t *testing.T) {
	tags := "~@e2e"
	suite := godog.TestSuite{
		ScenarioInitializer: initializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"./"},
			Tags:     tags,
			Strict:   true,
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero exit status from godog test suite")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
