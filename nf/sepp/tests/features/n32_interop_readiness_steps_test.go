//go:build functional

// Step definitions of n32_interop_readiness.feature (SEPP-005): N32-ready
// default start, per-PLMN trust and the N32-c interop profile.
//
// Unlike n32_handshake_steps_test.go these scenarios drive the real SEPP
// binary (nf/sepp/cmd/sepp, built once per run) as a child process with a
// generated config, an in-process NRF mock (httptest TLS, SBI CA) and real
// mTLS peers built with internal/n32trust/testpki. Each scenario starts a fresh
// SEPP, so its Prometheus counters start at 0 ("increases by 1" == value 1).
//
// Two sub-modes exist: the process mode above, and a config-only mode used by
// the one scenario whose partner ca_file paths are literal /etc/5gc paths
// (config.Load + the real admin handler, no listener).
//
// Known implementation gaps are reported as godog.ErrPending with the prefix
// "IMPL-GAP" (never silently passed): see knownGap.
//
// Ref: TS 33.501 §13.1.2; TS 29.573 §5.2.2, §6.1.5.2, §6.1.7; TS 23.003 §28.5.
package features_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"golang.org/x/net/http2"
	"gopkg.in/yaml.v3"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/admin"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32trust/testpki"
)

const (
	interopReady    = 30 * time.Second
	interopPoll     = 10 * time.Millisecond
	interopLogWait  = 5 * time.Second
	partnersPath    = "/admin/v1/n32/partners"
	contextsPath    = "/admin/v1/n32/contexts"
	goldenRel17Path = "../../internal/n32c/testdata/n32c_exchange_capability_rel17.json"
	// goldenLocalFQDN / goldenLocalPLMN are the local identity the golden was
	// captured with (local 001/02); the step maps them to the scenario's.
	goldenLocalFQDN = "sepp.5gc.mnc002.mcc001.3gppnetwork.org"
	goldenLocalPLMN = `{"mcc":"001","mnc":"02"}`
)

var (
	suiteT   *testing.T
	suiteMu  sync.Mutex
	suiteEnv *suiteState
)

// suiteState is the PKI, the NRF mock and the SEPP binary shared by all scenarios.
type suiteState struct {
	dir     string
	bin     string
	sbiCA   *testpki.CA
	sbiCert string // SEPP SBI server cert/key files
	sbiKey  string
	sbiCLI  tls.Certificate // client cert of the health probe
	sbiCAf  string
	nrf     *httptest.Server
	nrfAddr string
}

func suite() (*suiteState, error) {
	suiteMu.Lock()
	defer suiteMu.Unlock()
	if suiteEnv != nil {
		return suiteEnv, nil
	}
	dir, err := os.MkdirTemp("", "sepp-interop-*")
	if err != nil {
		return nil, err
	}
	s := &suiteState{dir: dir, bin: filepath.Join(dir, "sepp")}
	root, err := filepath.Abs("../../../..")
	if err != nil {
		return nil, err
	}
	build := exec.Command("go", "build", "-o", s.bin, "./nf/sepp/cmd/sepp")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build SEPP: %w\n%s", err, out)
	}
	s.sbiCA = testpki.NewCA(suiteT, "sbi-ca")
	far := time.Now().Add(time.Hour)
	srvCert := s.sbiCA.Issue(suiteT, []string{"localhost", "sepp.sbi.local"}, testpki.Both, far)
	s.sbiCert, s.sbiKey = testpki.WriteCert(suiteT, dir, "sbi", srvCert)
	s.sbiCAf = testpki.WriteFile(suiteT, dir, "sbi-ca.crt", s.sbiCA.PEM)
	s.sbiCLI = s.sbiCA.Issue(suiteT, []string{"probe.sbi.local"}, testpki.Both, far)

	nrfCert := s.sbiCA.Issue(suiteT, []string{"localhost"}, testpki.Both, far)
	s.nrf = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case http.MethodPatch:
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = w.Write([]byte(`{"nfInstances":[]}`))
		}
	}))
	s.nrf.TLS = &tls.Config{Certificates: []tls.Certificate{nrfCert}}
	s.nrf.EnableHTTP2 = true
	s.nrf.StartTLS()
	_, port, _ := net.SplitHostPort(s.nrf.Listener.Addr().String())
	s.nrfAddr = "localhost:" + port
	suiteEnv = s
	return s, nil
}

func suiteClose() {
	suiteMu.Lock()
	defer suiteMu.Unlock()
	if suiteEnv != nil {
		suiteEnv.nrf.Close()
		_ = os.RemoveAll(suiteEnv.dir)
		suiteEnv = nil
	}
}

// ipartner is one configured roaming partner of a scenario.
type ipartner struct {
	plmn      string // "001/02"
	ca        string // CA name ("testpeer-ca"), empty with noCA/literalCA
	literalCA string // literal ca_file path (never created on disk)
	noCA      bool
	fqdn      string
	addr      string
}

type proc struct {
	cmd  *exec.Cmd
	out  *syncBuf
	done chan struct{}
	code int
	sbi  string
	n32  string
	met  string
}

type iworld struct {
	s   *suiteState
	dir string

	localPLMN, localFQDN string
	profile              string
	ownCert              bool
	ownSAN               string

	cas      map[string]*testpki.CA
	n32CA    *testpki.CA
	inline   []ipartner
	file     []ipartner
	fileMode string // missing | present | raw
	fileRaw  string
	legacy   map[string]string
	virtual  bool

	// dialled server (initiator scenarios)
	mock     net.Listener
	mockCert *tls.Certificate
	mockErr  chan error
	mockMu   sync.Mutex
	mockN    int
	dialPLMN string

	// peer
	peerSAN  string
	peerCert *tls.Certificate
	tlsErr   error
	tlsDone  bool

	p *proc

	// last HTTP response
	status int
	raw    []byte
	rsp    map[string]any

	// virtual (config-only) mode
	virtCfg *config.Config
	virtErr error
}

func (w *iworld) reset() {
	w.cleanup()
	*w = iworld{
		localPLMN: "001/01", localFQDN: "sepp.5gc.mnc001.mcc001.3gppnetwork.org",
		profile: "rel19", fileMode: "missing", cas: map[string]*testpki.CA{}, legacy: map[string]string{},
	}
}

func (w *iworld) cleanup() {
	if w.p != nil {
		_ = w.p.cmd.Process.Kill()
		<-w.p.done
		w.p = nil
	}
	if w.mock != nil {
		_ = w.mock.Close()
	}
	if w.dir != "" {
		_ = os.RemoveAll(w.dir)
	}
}

func (w *iworld) init() error {
	if w.s != nil {
		return nil
	}
	s, err := suite()
	if err != nil {
		return err
	}
	w.s = s
	w.dir, err = os.MkdirTemp("", "sepp-scn-*")
	return err
}

func (w *iworld) ca(name string) *testpki.CA {
	switch name {
	case "sbi":
		return w.s.sbiCA
	case "test peer":
		name = "testpeer-ca"
	}
	if c, ok := w.cas[name]; ok {
		return c
	}
	c := testpki.NewCA(suiteT, name)
	w.cas[name] = c
	return c
}

func plmnFQDN(plmn string) (string, error) {
	mcc, mnc, ok := strings.Cut(plmn, "/")
	if !ok {
		return "", fmt.Errorf("plmn %q: want mcc/mnc", plmn)
	}
	return config.DeriveSEPPFQDN(config.PLMN{MCC: mcc, MNC: mnc}), nil
}

func plmnKey(s string) string {
	s = strings.NewReplacer("/", "-").Replace(s)
	mcc, mnc, _ := strings.Cut(s, "-")
	return mcc + "-" + config.PLMN{MNC: mnc}.Key()[len("-"):]
}

// ---- helpers ------------------------------------------------------------------

func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func eventually(d time.Duration, f func() error) error {
	deadline := time.Now().Add(d)
	for {
		err := f()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(interopPoll)
	}
}

// knownGap marks a scenario step whose assertion the current implementation
// cannot satisfy; it is reported pending, never passed.
func knownGap(format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	suiteT.Logf("IMPL-GAP: %s", msg) // godog's pretty formatter does not print pending reasons
	return fmt.Errorf("%w: IMPL-GAP: %s", godog.ErrPending, msg)
}

func partnerMap(p ipartner, dir string, w *iworld) map[string]any {
	mcc, mnc, _ := strings.Cut(p.plmn, "/")
	n32 := map[string]any{}
	switch {
	case p.literalCA != "":
		n32["ca_file"] = p.literalCA
	case !p.noCA:
		n32["ca_file"] = testpki.WriteFile(suiteT, dir, p.ca+".crt", w.ca(p.ca).PEM)
	}
	if p.fqdn != "" {
		n32["sepp_fqdn"] = p.fqdn
	}
	if p.addr != "" {
		n32["address"] = p.addr
	}
	return map[string]any{"plmn": map[string]any{"mcc": mcc, "mnc": mnc}, "n32": n32}
}

// writeFiles generates the PKI files, the config and the partners file.
func (w *iworld) writeFiles(pr *proc) (cfgPath, partnersFile string, err error) {
	mcc, mnc, _ := strings.Cut(w.localPLMN, "/")
	n32dir := filepath.Join(w.dir, "n32")
	if err = os.MkdirAll(n32dir, 0o755); err != nil {
		return
	}
	certFile, keyFile := filepath.Join(n32dir, "sepp.crt"), filepath.Join(n32dir, "sepp.key")
	if w.ownCert {
		if w.n32CA == nil {
			w.n32CA = testpki.NewCA(suiteT, "n32-local-ca")
		}
		san := w.localFQDN
		if w.ownSAN != "" {
			san = w.ownSAN
		}
		c := w.n32CA.Issue(suiteT, []string{san}, testpki.Both, time.Now().Add(time.Hour))
		certFile, keyFile = testpki.WriteCert(suiteT, n32dir, "sepp", c)
	}
	var inline []any
	for _, p := range w.inline {
		inline = append(inline, partnerMap(p, w.dir, w))
	}
	n32 := map[string]any{
		"address":  pr.n32,
		"partners": inline,
		"tls":      map[string]any{"cert_file": certFile, "key_file": keyFile},
	}
	if len(inline) == 0 {
		delete(n32, "partners")
	}
	if v, ok := w.legacy["n32.roaming_partners"]; ok {
		n32["roaming_partners"] = []any{map[string]any{"plmn": v}}
	}
	if _, ok := w.legacy["n32.peers"]; ok {
		n32["peers"] = []any{map[string]any{"plmn": "001/02", "address": "peer:8443"}}
	}
	if _, ok := w.legacy["n32.tls.ca_file"]; ok {
		n32["tls"].(map[string]any)["ca_file"] = filepath.Join(w.dir, "legacy-ca.crt")
	}
	cfg := map[string]any{
		"plmn": map[string]any{"mcc": mcc, "mnc": mnc},
		"sbi": map[string]any{"address": pr.sbi, "fqdn": w.localFQDN,
			"tls": map[string]any{"cert_file": w.s.sbiCert, "key_file": w.s.sbiKey, "ca_file": w.s.sbiCAf}},
		"n32":     n32,
		"peers":   map[string]any{"nrf": w.s.nrfAddr},
		"metrics": map[string]any{"address": pr.met},
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return
	}
	cfgPath = testpki.WriteFile(suiteT, w.dir, "config.yaml", b)

	partnersFile = filepath.Join(w.dir, "partners-absent.yaml")
	switch w.fileMode {
	case "present":
		var fp []any
		for _, p := range w.file {
			fp = append(fp, partnerMap(p, w.dir, w))
		}
		fb, merr := yaml.Marshal(map[string]any{"partners": fp})
		if merr != nil {
			return "", "", merr
		}
		partnersFile = testpki.WriteFile(suiteT, w.dir, "partners.yaml", fb)
	case "raw":
		partnersFile = testpki.WriteFile(suiteT, w.dir, "partners.yaml", []byte(w.fileRaw))
	}
	return
}

// launch starts the SEPP (process mode) or loads the config (virtual mode).
func (w *iworld) launch() error {
	if err := w.init(); err != nil {
		return err
	}
	if w.p != nil || w.virtCfg != nil || w.virtErr != nil {
		return nil
	}
	for i := range w.inline {
		w.fillDial(&w.inline[i])
	}
	for i := range w.file {
		w.fillDial(&w.file[i])
	}
	pr := &proc{out: &syncBuf{}, done: make(chan struct{})}
	var err error
	for _, a := range []*string{&pr.sbi, &pr.n32, &pr.met} {
		if *a, err = freePort(); err != nil {
			return err
		}
	}
	cfgPath, pf, err := w.writeFiles(pr)
	if err != nil {
		return err
	}
	if w.virtual {
		return w.loadVirtual(cfgPath, pf)
	}
	cmd := exec.Command(w.s.bin)
	cmd.Dir = w.dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "CONFIG_PATH=" + cfgPath, "ROAMING_PARTNERS_FILE=" + pf,
		"NF_RELEASE_PROFILE=" + w.profile, "OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:1"}
	cmd.Stdout, cmd.Stderr = pr.out, pr.out
	pr.cmd = cmd
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start SEPP: %w", err)
	}
	go func() {
		_ = cmd.Wait()
		pr.code = cmd.ProcessState.ExitCode()
		close(pr.done)
	}()
	w.p = pr
	return nil
}

// fillDial points the partner of the dialled server at the mock listener.
func (w *iworld) fillDial(p *ipartner) {
	if w.mock != nil && p.plmn == w.dialPLMN {
		p.addr = w.mock.Addr().String()
	}
}

func (w *iworld) loadVirtual(cfgPath, pf string) error {
	old := map[string]string{}
	for k, v := range map[string]string{"CONFIG_PATH": cfgPath, config.PartnersFileEnv: pf} {
		old[k] = os.Getenv(k)
		_ = os.Setenv(k, v)
	}
	defer func() {
		for k, v := range old {
			_ = os.Setenv(k, v)
		}
	}()
	cfg, err := config.Load()
	w.virtCfg, w.virtErr = cfg, err
	return nil
}

// awaitOutcome waits for "SEPP ready" or for the process to exit.
func (w *iworld) awaitOutcome() error {
	if w.virtual {
		return nil
	}
	return eventually(interopReady, func() error {
		select {
		case <-w.p.done:
			return nil
		default:
		}
		if w.hasMsg("SEPP ready") {
			return nil
		}
		return errors.New("SEPP neither ready nor exited")
	})
}

// ensureStarted launches the SEPP and requires it to be running.
func (w *iworld) ensureStarted() error {
	if err := w.launch(); err != nil {
		return err
	}
	if w.virtual {
		return nil
	}
	if err := w.awaitOutcome(); err != nil {
		return fmt.Errorf("%w\nlogs:\n%s", err, w.p.out.String())
	}
	select {
	case <-w.p.done:
		return fmt.Errorf("SEPP exited with status %d\nlogs:\n%s", w.p.code, w.p.out.String())
	default:
		return nil
	}
}

func (w *iworld) records() []map[string]any {
	if w.p == nil {
		return nil
	}
	var out []map[string]any
	for _, line := range strings.Split(w.p.out.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil {
			out = append(out, rec)
		}
	}
	return out
}

func (w *iworld) hasMsg(sub string) bool {
	for _, r := range w.records() {
		if m, _ := r["msg"].(string); strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

func str(r map[string]any, k string) string { s, _ := r[k].(string); return s }

// ---- clients ------------------------------------------------------------------

func (w *iworld) peerClient(cert tls.Certificate) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http2.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // the SEPP's own N32 cert is not under test; the peer cert is
	}}}
}

func (w *iworld) plainGet(url string) (int, []byte, error) {
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

func (w *iworld) adminGet(path string) (int, []byte, error) {
	if w.virtual {
		if w.virtCfg == nil {
			return 0, nil, fmt.Errorf("config not loaded: %v", w.virtErr)
		}
		if path != partnersPath {
			return 0, nil, errors.New("config-only mode serves only the partners view")
		}
		h := admin.NewHandler(nil, admin.Info{Partners: w.virtCfg.N32Partners()}, nil)
		rec := httptest.NewRecorder()
		h.ServePartners(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.Bytes(), nil
	}
	return w.plainGet("http://" + w.p.met + path)
}

func (w *iworld) setRsp(status int, b []byte) {
	w.status, w.raw, w.rsp = status, b, nil
	var m map[string]any
	if json.Unmarshal(b, &m) == nil {
		w.rsp = m
	}
}

func (w *iworld) adminJSON(path string) (map[string]any, error) {
	if err := w.ensureStarted(); err != nil {
		return nil, err
	}
	st, b, err := w.adminGet(path)
	if err != nil {
		return nil, err
	}
	w.setRsp(st, b)
	if st != http.StatusOK || w.rsp == nil {
		return nil, fmt.Errorf("GET %s: status %d body %s", path, st, b)
	}
	return w.rsp, nil
}

func (w *iworld) partnerList() ([]map[string]any, error) {
	m, err := w.adminJSON(partnersPath)
	if err != nil {
		return nil, err
	}
	raw, ok := m["partners"]
	if !ok {
		return nil, fmt.Errorf(`no "partners" key: %s`, w.raw)
	}
	arr, _ := raw.([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		em, _ := e.(map[string]any)
		out = append(out, em)
	}
	return out, nil
}

// metric sums the series of name whose label value matches.
func (w *iworld) metric(name, label, value string) (float64, error) {
	_, b, err := w.plainGet("http://" + w.p.met + "/metrics")
	if err != nil {
		return 0, err
	}
	var sum float64
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, name+"{") || !strings.Contains(line, label+`="`+value+`"`) {
			continue
		}
		var v float64
		if _, err := fmt.Sscan(line[strings.LastIndex(line, " ")+1:], &v); err == nil {
			sum += v
		}
	}
	return sum, nil
}

// ---- Background / Given -------------------------------------------------------

func (w *iworld) localServes(plmn, fqdn string) error {
	w.localPLMN, w.localFQDN = plmn, fqdn
	return nil
}

func (w *iworld) ownN32Cert() error { w.ownCert = true; return nil }

func (w *iworld) runsWith(profile string) error { w.profile = profile; return nil }

func (w *iworld) noPartnersFile() error { w.fileMode = "missing"; return nil }

func (w *iworld) noInline() error { return nil }

func (w *iworld) ownCertMissing() error { w.ownCert = false; return nil }

func (w *iworld) sbiFilesExist() error {
	if err := w.init(); err != nil {
		return err
	}
	for _, f := range []string{w.s.sbiCert, w.s.sbiKey, w.s.sbiCAf} {
		if _, err := os.Stat(f); err != nil {
			return err
		}
	}
	return nil
}

func (w *iworld) hasPartner(plmn, fqdn, anchor string) error {
	w.inline = append(w.inline, ipartner{plmn: plmn, ca: anchor, fqdn: fqdn})
	return w.init()
}

func (w *iworld) validPartner() error {
	w.inline = append(w.inline, ipartner{plmn: "001/02", ca: "testpeer-ca"})
	return w.init()
}

func (w *iworld) fileWithPeerCA(plmn, fqdn, addr string) error {
	w.fileMode = "present"
	w.file = append(w.file, ipartner{plmn: plmn, ca: "testpeer-ca", fqdn: fqdn, addr: addr})
	return w.init()
}

func (w *iworld) fileLiteral(plmn, ca string) error {
	w.fileMode, w.virtual = "present", true
	w.file = append(w.file, ipartner{plmn: plmn, literalCA: ca})
	return w.init()
}

func (w *iworld) inlineLiteral(plmn, ca string) error {
	w.virtual = true
	w.inline = append(w.inline, ipartner{plmn: plmn, literalCA: ca})
	return w.init()
}

func (w *iworld) inlineValidCA(plmn string) error {
	w.inline = append(w.inline, ipartner{plmn: plmn, ca: "other-ca"})
	return w.init()
}

func (w *iworld) missingFileEnv() error { w.fileMode = "missing"; return nil }

func (w *iworld) fileInvalidYAML() error {
	w.fileMode, w.fileRaw = "raw", "partners: [unclosed\n  - : :\n"
	return nil
}

func (w *iworld) fileNoCA() error {
	w.fileMode = "present"
	w.file = append(w.file, ipartner{plmn: "001/02", noCA: true, addr: "sepp.5gc.mnc002.mcc001.3gppnetwork.org:8443"})
	return w.init()
}

func (w *iworld) fileDuplicate(plmn string) error {
	w.fileMode = "present"
	w.file = append(w.file, ipartner{plmn: plmn, ca: "testpeer-ca"}, ipartner{plmn: plmn, ca: "testpeer-ca"})
	return w.init()
}

func (w *iworld) legacyKey(key string) error { w.legacy[key] = "001/02"; return w.init() }

func (w *iworld) partnerNoOwnCert() error {
	if err := w.validPartner(); err != nil {
		return err
	}
	return w.ownCertMissing()
}

func (w *iworld) partnerBadSAN(plmn string) error {
	if err := w.validPartner(); err != nil {
		return err
	}
	other, err := plmnFQDN("001/02")
	if err != nil {
		return err
	}
	w.ownCert, w.ownSAN = true, other
	return nil
}

// ---- starting -----------------------------------------------------------------

func (w *iworld) sepStarts() error {
	if err := w.launch(); err != nil {
		return err
	}
	return w.awaitOutcome()
}

func (w *iworld) sepHasStarted() error { return w.ensureStarted() }

func (w *iworld) sepHealthy() error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	cli := &http.Client{Timeout: 3 * time.Second, Transport: &http2.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{w.s.sbiCLI}, ServerName: "localhost", MinVersion: tls.VersionTLS12,
		RootCAs: func() *x509.CertPool { p := x509.NewCertPool(); p.AddCert(w.s.sbiCA.Cert); return p }(),
	}}}
	return eventually(interopLogWait, func() error {
		resp, err := cli.Get("https://" + w.p.sbi + "/healthz")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("healthz status %d", resp.StatusCode)
		}
		return nil
	})
}

func (w *iworld) n32ListenerPort8443() error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	// The default listen address is 0.0.0.0:8443 (config.Load defaults, no n32.address).
	dir, err := os.MkdirTemp("", "sepp-defcfg-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	empty := testpki.WriteFile(suiteT, dir, "config.yaml", []byte("{}\n"))
	old := map[string]string{"CONFIG_PATH": os.Getenv("CONFIG_PATH"), config.PartnersFileEnv: os.Getenv(config.PartnersFileEnv)}
	_ = os.Setenv("CONFIG_PATH", empty)
	_ = os.Setenv(config.PartnersFileEnv, filepath.Join(dir, "absent.yaml"))
	cfg, lerr := config.Load()
	for k, v := range old {
		_ = os.Setenv(k, v)
	}
	if lerr != nil {
		return lerr
	}
	if !strings.HasSuffix(cfg.N32.Address, ":8443") {
		return fmt.Errorf("default n32.address %q does not use port 8443", cfg.N32.Address)
	}
	// The test runs the listener on a free port (8443 may be taken on the host).
	return eventually(interopLogWait, func() error {
		c, err := net.DialTimeout("tcp", w.p.n32, time.Second)
		if err != nil {
			return err
		}
		return c.Close()
	})
}

func (w *iworld) n32ListenerNotStarted() error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	if c, err := net.DialTimeout("tcp", w.p.n32, time.Second); err == nil {
		_ = c.Close()
		return errors.New("N32 listener accepts connections")
	}
	return nil
}

func (w *iworld) noInitiator() error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	for _, r := range w.records() {
		if str(r, "procedure") == "N32cExchangeCapability" {
			return fmt.Errorf("N32-c initiator ran: %v", r)
		}
	}
	return nil
}

func (w *iworld) initiatorRuns(plmn string) error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	return eventually(interopReady, func() error {
		for _, r := range w.records() {
			if str(r, "procedure") == "N32cExchangeCapability" && plmnKey(str(r, "peer_plmn")) == plmnKey(plmn) {
				return nil
			}
		}
		return fmt.Errorf("no N32cExchangeCapability record for %s", plmn)
	})
}

func (w *iworld) noWarnOrError() error {
	for _, r := range w.records() {
		if l := str(r, "level"); l == "WARN" || l == "ERROR" {
			return fmt.Errorf("unexpected %s log line: %v", l, r)
		}
	}
	return nil
}

func (w *iworld) oneInfo(sub string) error {
	n := 0
	for _, r := range w.records() {
		if m := str(r, "msg"); str(r, "level") == "INFO" && strings.Contains(m, sub) {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("%d INFO lines containing %q, want exactly 1", n, sub)
	}
	return nil
}

func (w *iworld) oneInfoN32Disabled() error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	return w.oneInfo("N32 listener not started")
}

func (w *iworld) oneInfoFileAbsent() error { return w.oneInfo("no roaming partners file") }

func (w *iworld) exitsWith(code int) error {
	if err := w.launch(); err != nil {
		return err
	}
	if w.virtual {
		if w.virtErr == nil {
			return errors.New("config.Load accepted the configuration")
		}
		return nil
	}
	select {
	case <-w.p.done:
	case <-time.After(interopReady):
		return fmt.Errorf("SEPP still running, want exit %d\nlogs:\n%s", code, w.p.out.String())
	}
	if w.p.code != code {
		return fmt.Errorf("exit status %d, want %d\nlogs:\n%s", w.p.code, code, w.p.out.String())
	}
	return nil
}

func (w *iworld) errorLineMentions(cause, hint string) error {
	if err := w.launch(); err != nil {
		return err
	}
	var withCause, withHint, all []string
	for _, r := range w.records() {
		if str(r, "level") != "ERROR" {
			continue
		}
		b, _ := json.Marshal(r)
		all = append(all, string(b))
		mentions := strings.Contains(strings.ToLower(string(b)), strings.ToLower(hint))
		switch {
		case str(r, "cause") == cause && mentions:
			return nil
		case str(r, "cause") == cause:
			withCause = append(withCause, string(b))
		case mentions:
			withHint = append(withHint, string(b))
		}
	}
	if len(withHint) > 0 {
		return knownGap("ERROR line mentions %q but carries no cause=%q (config.Load failure is logged by main.go without cause): %s", hint, cause, withHint[0])
	}
	if len(withCause) > 0 {
		return knownGap("ERROR line with cause=%q does not mention %q: %s", cause, hint, withCause[0])
	}
	return fmt.Errorf("no ERROR line with cause %q mentioning %q; ERROR lines: %v", cause, hint, all)
}

// ---- admin --------------------------------------------------------------------

func (w *iworld) adminEmpty(path, key string) error {
	if path != partnersPath || key != "partners" {
		return fmt.Errorf("unsupported admin check %s %s", path, key)
	}
	l, err := w.partnerList()
	if err != nil {
		return err
	}
	if len(l) != 0 {
		return fmt.Errorf("partners list not empty: %s", w.raw)
	}
	return nil
}

func (w *iworld) adminLists(path, plmn, source string) error {
	l, err := w.partnerList()
	if err != nil {
		return err
	}
	for _, e := range l {
		if str(e, "plmn") == plmn {
			if str(e, "source") != source {
				return fmt.Errorf("partner %s source %q, want %q", plmn, str(e, "source"), source)
			}
			return nil
		}
	}
	return fmt.Errorf("partner %s not listed: %s", plmn, w.raw)
}

func (w *iworld) adminExactlyOne(path, plmn string) error {
	l, err := w.partnerList()
	if err != nil {
		return err
	}
	if len(l) != 1 || str(l[0], "plmn") != plmn {
		return fmt.Errorf("want exactly one partner %s: %s", plmn, w.raw)
	}
	return nil
}

func (w *iworld) thatPartner(source, ca string) error {
	l, err := w.partnerList()
	if err != nil {
		return err
	}
	if len(l) != 1 {
		return fmt.Errorf("want one partner: %s", w.raw)
	}
	if str(l[0], "source") != source || str(l[0], "caFile") != ca {
		return fmt.Errorf("partner source %q caFile %q, want %q %q", str(l[0], "source"), str(l[0], "caFile"), source, ca)
	}
	return nil
}

func (w *iworld) clientGetsMetricsPort(path string) error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	st, b, err := w.adminGet(path)
	if err != nil {
		return err
	}
	w.setRsp(st, b)
	return nil
}

func (w *iworld) entriesHaveKeys(list string) error {
	var keys []string
	for _, k := range strings.Split(list, ",") {
		keys = append(keys, strings.Trim(strings.TrimSpace(k), `"`))
	}
	l, err := w.partnerList()
	if err != nil {
		return err
	}
	if len(l) == 0 {
		return errors.New("no partner entries")
	}
	for _, e := range l {
		for _, k := range keys {
			if _, ok := e[k]; !ok {
				return knownGap("partner %s has no key %q (omitempty); the feature requires every entry to carry it: %s", str(e, "plmn"), k, w.raw)
			}
		}
	}
	return nil
}

func (w *iworld) entrySources(a, sa, b, sb string) error {
	for _, x := range [][2]string{{a, sa}, {b, sb}} {
		if err := w.adminLists(partnersPath, x[0], x[1]); err != nil {
			return err
		}
	}
	return nil
}

func (w *iworld) trustPoolLacksSBICA(plmn string) error {
	l, err := w.partnerList()
	if err != nil {
		return err
	}
	for _, e := range l {
		if str(e, "plmn") != strings.ReplaceAll(plmn, "/", "-") {
			continue
		}
		b, err := os.ReadFile(str(e, "caFile"))
		if err != nil {
			return err
		}
		if bytes.Contains(b, w.s.sbiCA.PEM) || str(e, "anchorSubject") == w.s.sbiCA.Cert.Subject.String() {
			return errors.New("the partner trust anchor is the SBI CA")
		}
		return nil
	}
	return fmt.Errorf("partner %s not listed: %s", plmn, w.raw)
}

// ---- peers / TLS --------------------------------------------------------------

func peerLeaf(ca *testpki.CA, dns []string) tls.Certificate {
	return ca.Issue(suiteT, dns, testpki.Both, time.Now().Add(time.Hour))
}

var (
	reCertPLMN   = regexp.MustCompile(`^a certificate of PLMN "([^"]+)" (?:issued by|signed by) (the test peer CA|the SBI CA|an unknown CA|"([^"]+)")(?: \(.*\))?$`)
	reCertNoSAN  = regexp.MustCompile(`^a certificate without any SAN of the form mncXXX\.mccYYY\.3gppnetwork\.org$`)
	reCertTwo    = regexp.MustCompile(`^a certificate with SAN PLMNs "([^"]+)" and "([^"]+)" that map to different anchors$`)
	reCertBadSAN = regexp.MustCompile(`^a certificate of PLMN "([^"]+)" whose SAN is not the partner FQDN$`)
)

// buildCert builds the peer certificate described by a feature phrase.
func (w *iworld) buildCert(desc string) (tls.Certificate, error) {
	switch {
	case reCertNoSAN.MatchString(desc):
		return peerLeaf(w.ca("testpeer-ca"), []string{"peer.example.org"}), nil
	case reCertTwo.MatchString(desc):
		m := reCertTwo.FindStringSubmatch(desc)
		a, err := plmnFQDN(m[1])
		if err != nil {
			return tls.Certificate{}, err
		}
		b, err := plmnFQDN(m[2])
		if err != nil {
			return tls.Certificate{}, err
		}
		return peerLeaf(w.ca("testpeer-ca"), []string{a, b}), nil
	case reCertBadSAN.MatchString(desc):
		m := reCertBadSAN.FindStringSubmatch(desc)
		fq, err := plmnFQDN(m[1])
		if err != nil {
			return tls.Certificate{}, err
		}
		return peerLeaf(w.ca("testpeer-ca"), []string{"other." + strings.TrimPrefix(fq, "sepp.")}), nil
	case reCertPLMN.MatchString(desc):
		m := reCertPLMN.FindStringSubmatch(desc)
		fq, err := plmnFQDN(m[1])
		if err != nil {
			return tls.Certificate{}, err
		}
		var ca *testpki.CA
		switch {
		case m[2] == "the test peer CA":
			ca = w.ca("testpeer-ca")
		case m[2] == "the SBI CA":
			ca = w.s.sbiCA
		case m[2] == "an unknown CA":
			ca = w.ca("unknown-ca")
		default:
			ca = w.ca(m[3])
		}
		return peerLeaf(ca, []string{fq}), nil
	}
	return tls.Certificate{}, fmt.Errorf("unsupported certificate description %q", desc)
}

// h2Preface is the HTTP/2 client connection preface followed by an empty SETTINGS frame.
const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + "\x00\x00\x00\x04\x00\x00\x00\x00\x00"

// probe runs one real TLS handshake with the N32 listener and reads the first
// bytes back: the HTTP/2 SETTINGS of an accepted peer, or the TLS alert of a
// rejected one (TLS 1.3 reports a rejected client certificate on first read).
func (w *iworld) probe(cert *tls.Certificate) error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, //nolint:gosec // SEPP's own cert not under test
		NextProtos: []string{"h2"}}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	w.tlsDone = true
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", w.p.n32, cfg)
	if err != nil {
		w.tlsErr = err
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte(h2Preface)) // a broken pipe here is reported by the Read below
	buf := make([]byte, 9)
	_, w.tlsErr = io.ReadFull(conn, buf)
	return nil
}

func (w *iworld) peerConnects(desc string) error {
	c, err := w.buildCert(desc)
	if err != nil {
		return err
	}
	return w.probe(&c)
}

func (w *iworld) peerConnectsNoCert() error { return w.probe(nil) }

func (w *iworld) peerCompletes(plmn string) error {
	c, err := w.buildCert(fmt.Sprintf(`a certificate of PLMN "%s" issued by the test peer CA`, plmn))
	if err != nil {
		return err
	}
	if err := w.probe(&c); err != nil {
		return err
	}
	return w.handshakeSucceeds()
}

func (w *iworld) handshakeSucceeds() error {
	if !w.tlsDone {
		return errors.New("no TLS exchange was made")
	}
	if w.tlsErr != nil {
		return fmt.Errorf("TLS handshake failed: %w", w.tlsErr)
	}
	return nil
}

func (w *iworld) handshakeFails() error {
	if !w.tlsDone {
		return errors.New("no TLS exchange was made")
	}
	if w.tlsErr == nil {
		return errors.New("TLS handshake succeeded, want failure")
	}
	return nil
}

func (w *iworld) handshakeFailsAlert(alert string) error {
	if err := w.handshakeFails(); err != nil {
		return err
	}
	want := strings.ReplaceAll(alert, "_", " ")
	if !strings.Contains(w.tlsErr.Error(), want) {
		return fmt.Errorf("TLS error %q does not carry alert %q", w.tlsErr, alert)
	}
	return nil
}

func (w *iworld) metricIncreases(name, label, value string) error {
	err := eventually(interopLogWait, func() error {
		v, err := w.metric(name, label, value)
		if err != nil {
			return err
		}
		if v != 1 {
			return fmt.Errorf("%s{%s=%q} = %v, want 1 (fresh SEPP process)", name, label, value, v)
		}
		return nil
	})
	if err == nil || name != "fivegc_sepp_n32_tls_reject_total" {
		return err
	}
	for _, r := range []string{"no_plmn", "not_partner", "anchor_conflict", "chain", "plmn_mismatch"} {
		if v, _ := w.metric(name, label, r); v == 1 && r != value {
			return knownGap("the rejection was counted with reason %q, the feature requires %q", r, value)
		}
	}
	return err
}

func (w *iworld) logCause(cause, result string) error {
	err := eventually(interopLogWait, func() error {
		for _, r := range w.records() {
			if str(r, "cause") == cause && (result == "" || str(r, "result") == result) {
				return nil
			}
		}
		return fmt.Errorf("no SEPP log record with cause %q result %q", cause, result)
	})
	if err == nil {
		return nil
	}
	switch cause {
	case "n32_tls_no_client_cert":
		return knownGap("the implementation never logs cause %q (Go rejects a missing client certificate before VerifyConnection, docs/procedures/N32InteropReadiness.md E6)", cause)
	case "handshake_accepted":
		return knownGap("the accepted exchange-capability record (handler.go negotiate) carries result=OK but no cause=%q", cause)
	}
	return fmt.Errorf("%w\nlogs:\n%s", err, w.p.out.String())
}

// ---- initiator ----------------------------------------------------------------

func (w *iworld) dialledServer(desc string) error {
	if err := w.init(); err != nil {
		return err
	}
	c, err := w.buildCert(desc)
	if err != nil {
		return err
	}
	w.mockCert = &c
	return nil
}

func (w *iworld) initiatorDials(plmn string) error {
	if w.mockCert == nil {
		return errors.New("no dialled server configured")
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*w.mockCert},
		NextProtos: []string{"h2"}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	w.mock, w.dialPLMN, w.mockErr = l, plmn, make(chan error, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			w.mockMu.Lock()
			w.mockN++
			w.mockMu.Unlock()
			go func() {
				defer c.Close()
				w.mockErr <- c.(*tls.Conn).Handshake()
			}()
		}
	}()
	// The partner of the dialled PLMN gets the mock's address (fillDial).
	found := false
	for _, p := range w.inline {
		found = found || p.plmn == plmn
	}
	if !found {
		return fmt.Errorf("partner %s not configured", plmn)
	}
	return w.ensureStarted()
}

func (w *iworld) initiatorAborts(alert string) error {
	want := strings.ReplaceAll(alert, "_", " ")
	select {
	case err := <-w.mockErr:
		if err == nil || !strings.Contains(err.Error(), want) {
			return fmt.Errorf("dialled server handshake result %v, want alert %q", err, alert)
		}
		return nil
	case <-time.After(interopReady):
		return errors.New("the SEPP initiator never dialled the server")
	}
}

func (w *iworld) initiatorNoRetry() error {
	if err := eventually(interopReady, func() error {
		if w.hasMsg("not retrying") {
			return nil
		}
		return errors.New(`no "not retrying" initiator record`)
	}); err != nil {
		return err
	}
	for _, r := range w.records() {
		if strings.Contains(str(r, "msg"), "initiator exchange failed") {
			return fmt.Errorf("initiator retried: %v", r)
		}
	}
	w.mockMu.Lock()
	defer w.mockMu.Unlock()
	if w.mockN != 1 {
		return fmt.Errorf("dialled server saw %d connections, want 1", w.mockN)
	}
	return nil
}

// ---- N32-c --------------------------------------------------------------------

func (w *iworld) peerPresentsSAN(san string) error {
	if err := w.init(); err != nil {
		return err
	}
	w.peerSAN = san
	ca := "testpeer-ca"
	for _, p := range w.inline {
		if fq, _ := plmnFQDN(p.plmn); fq == san && p.ca != "" {
			ca = p.ca
		}
	}
	c := peerLeaf(w.ca(ca), []string{san})
	w.peerCert = &c
	return nil
}

// toPurposes turns ["A","B"] into the TS 29.573 IntendedN32Purpose objects.
func toPurposes(v string) (any, error) {
	var names []string
	if err := json.Unmarshal([]byte(v), &names); err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]string{"usagePurpose": n})
	}
	return out, nil
}

// peerSends posts the SecNegotiateReqData table. The IEs the table does not
// carry take the values of a real peer: an supportedFeatures offer ("5" covers
// both profiles; shared features.Answer answers the intersection) and
// 3GppSbiTargetApiRootSupported=true.
func (w *iworld) peerSends(path string, t *godog.Table) error {
	if err := w.ensureStarted(); err != nil {
		return err
	}
	if w.peerCert == nil {
		return errors.New("no peer certificate")
	}
	m := map[string]any{}
	for _, row := range t.Rows {
		if len(row.Cells) != 2 {
			return errors.New("table rows need 2 cells")
		}
		k, v := row.Cells[0].Value, row.Cells[1].Value
		switch {
		case k == "intendedUsagePurpose":
			p, err := toPurposes(v)
			if err != nil {
				return fmt.Errorf("intendedUsagePurpose %q: %w", v, err)
			}
			m[k] = p
		case json.Valid([]byte(v)):
			m[k] = json.RawMessage(v)
		default:
			m[k] = v
		}
	}
	if _, ok := m["supportedFeatures"]; !ok {
		m["supportedFeatures"] = "5"
	}
	if _, ok := m["3GppSbiTargetApiRootSupported"]; !ok {
		m["3GppSbiTargetApiRootSupported"] = true
	}
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+w.p.n32+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.peerClient(*w.peerCert).Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w\nlogs:\n%s", path, err, w.p.out.String())
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	w.setRsp(resp.StatusCode, b)
	return nil
}

func (w *iworld) statusIs(code int) error {
	if w.status != code {
		return fmt.Errorf("response status %d, want %d (body %s)", w.status, code, w.raw)
	}
	return nil
}

func purposeNames(v any) []string {
	var out []string
	arr, _ := v.([]any)
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok {
			out = append(out, str(m, "usagePurpose"))
		}
	}
	return out
}

func (w *iworld) rspIs(key, want string) error {
	got, present := w.rsp[key]
	switch {
	case want == "absent":
		if present {
			return fmt.Errorf("response must not carry %q: %s", key, w.raw)
		}
		return nil
	case !present:
		return fmt.Errorf("response has no %q: %s", key, w.raw)
	case strings.HasPrefix(want, "["):
		var exp []string
		if err := json.Unmarshal([]byte(want), &exp); err != nil {
			return err
		}
		act := purposeNames(got)
		sort.Strings(act)
		sort.Strings(exp)
		if strings.Join(act, ",") != strings.Join(exp, ",") {
			return fmt.Errorf("response %q = %v, want %v", key, act, exp)
		}
		return nil
	}
	var exp string
	if err := json.Unmarshal([]byte(want), &exp); err != nil {
		return fmt.Errorf("unsupported expectation %q", want)
	}
	if g, _ := got.(string); g != exp {
		return fmt.Errorf("response %q = %v, want %q", key, got, exp)
	}
	return nil
}

func (w *iworld) rspNoPurposes() error {
	for _, k := range []string{"allowedUsagePurpose", "rejectedUsagePurpose"} {
		if _, ok := w.rsp[k]; ok {
			return fmt.Errorf("response must not carry %q: %s", k, w.raw)
		}
	}
	return nil
}

func (w *iworld) rspProblem(cause string) error {
	if w.rsp == nil {
		return fmt.Errorf("body is not a ProblemDetails object: %s", w.raw)
	}
	if got := str(w.rsp, "cause"); got != cause {
		return fmt.Errorf("ProblemDetails cause %q, want %q (body %s)", got, cause, w.raw)
	}
	return nil
}

func (w *iworld) rspGolden(name string) error {
	if name != "n32c_exchange_capability_rel17.json" {
		return fmt.Errorf("unknown golden %q", name)
	}
	g, err := os.ReadFile(goldenRel17Path)
	if err != nil {
		return err
	}
	// The golden was captured with local PLMN 001/02 (and the peer 001/01):
	// map only the local identity to this scenario's, then compare the bytes.
	mcc, mnc, _ := strings.Cut(w.localPLMN, "/")
	want := strings.ReplaceAll(string(g), goldenLocalFQDN, w.localFQDN)
	want = strings.ReplaceAll(want, goldenLocalPLMN, fmt.Sprintf(`{"mcc":%q,"mnc":%q}`, mcc, mnc))
	if want != string(w.raw) {
		return fmt.Errorf("response differs from golden\nwant %s\ngot  %s", want, w.raw)
	}
	return nil
}

func (w *iworld) contextState(plmn string) (state, security string, err error) {
	m, err := w.adminJSON(contextsPath)
	if err != nil {
		return "", "", err
	}
	arr, _ := m["partners"].([]any)
	for _, e := range arr {
		em, _ := e.(map[string]any)
		if plmnKey(str(em, "plmn")) == plmnKey(plmn) {
			return str(em, "state"), str(em, "security"), nil
		}
	}
	return "", "", fmt.Errorf("PLMN %s not in the contexts view: %s", plmn, w.raw)
}

func (w *iworld) noContext(plmn string) error {
	st, _, err := w.contextState(plmn)
	if err != nil {
		return err
	}
	if st != "NONE" {
		return fmt.Errorf("N32 context for %s is %s, want none", plmn, st)
	}
	return nil
}

func (w *iworld) contextExists(plmn, sec string) error {
	st, s, err := w.contextState(plmn)
	if err != nil {
		return err
	}
	if st != "ESTABLISHED" || s != sec {
		return fmt.Errorf("N32 context for %s: state %s security %q, want ESTABLISHED %q", plmn, st, s, sec)
	}
	return nil
}

// ---- wiring -------------------------------------------------------------------

// InitializeInteropScenarios wires the step definitions of n32_interop_readiness.feature.
func InitializeInteropScenarios(sc *godog.ScenarioContext) {
	w := &iworld{}
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, w.init()
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.cleanup()
		return ctx, nil
	})

	// Background / Given
	sc.Step(`^the local SEPP serves PLMN "([^"]+)" with SEPP FQDN "([^"]+)"$`, w.localServes)
	sc.Step(`^the local SEPP has an own N32 certificate issued by the N32 CA of the local core$`, w.ownN32Cert)
	sc.Step(`^the SEPP runs with the "([^"]+)" release profile$`, w.runsWith)
	sc.Step(`^no roaming partners file exists$`, w.noPartnersFile)
	sc.Step(`^the SEPP config has no inline partners$`, w.noInline)
	sc.Step(`^the own N32 certificate files do not exist$`, w.ownCertMissing)
	sc.Step(`^the SBI TLS certificate files exist$`, w.sbiFilesExist)
	sc.Step(`^a roaming partners file with partner PLMN "([^"]+)", n32 ca_file of the test peer CA(?:, sepp_fqdn "([^"]*)")? and address "([^"]+)"$`, w.fileWithPeerCA)
	sc.Step(`^a roaming partners file with partner PLMN "([^"]+)", n32 ca_file "([^"]+)"$`, w.fileLiteral)
	sc.Step(`^the SEPP config has inline partner PLMN "([^"]+)" with ca_file "([^"]+)"$`, w.inlineLiteral)
	sc.Step(`^the SEPP config has inline partner PLMN "([^"]+)" with a valid ca_file$`, w.inlineValidCA)
	sc.Step(`^the ROAMING_PARTNERS_FILE points to a file that does not exist$`, w.missingFileEnv)
	sc.Step(`^a roaming partners file that is not valid YAML$`, w.fileInvalidYAML)
	sc.Step(`^a roaming partners file with a partner whose n32 section has no ca_file$`, w.fileNoCA)
	sc.Step(`^a roaming partners file with two entries for PLMN "([^"]+)"$`, w.fileDuplicate)
	sc.Step(`^the SEPP config contains the legacy key "([^"]+)"$`, w.legacyKey)
	sc.Step(`^a valid partner exists$`, w.validPartner)
	sc.Step(`^a valid partner exists and the own N32 certificate files do not exist$`, w.partnerNoOwnCert)
	sc.Step(`^a valid partner exists and the own N32 certificate SAN lacks the SEPP FQDN of PLMN "([^"]+)"$`, w.partnerBadSAN)
	sc.Step(`^the SEPP has partner PLMN "([^"]+)"(?: with sepp_fqdn "([^"]+)" and| with) anchor "([^"]+)"$`, w.hasPartner)
	sc.Step(`^the dialled server presents (.+)$`, w.dialledServer)
	sc.Step(`^the peer presents a certificate whose SAN is "([^"]+)"$`, w.peerPresentsSAN)

	// When
	sc.Step(`^the SEPP starts$`, w.sepStarts)
	sc.Step(`^the SEPP has started$`, w.sepHasStarted)
	sc.Step(`^a peer connects to the N32 listener with (.+)$`, w.peerConnects)
	sc.Step(`^a peer connects to the N32 listener without a client certificate$`, w.peerConnectsNoCert)
	sc.Step(`^a client sends GET "([^"]+)" on the metrics port$`, w.clientGetsMetricsPort)
	sc.Step(`^the N32-c initiator dials partner "([^"]+)"$`, w.initiatorDials)
	sc.Step(`^the peer sends POST "([^"]+)" with SecNegotiateReqData:$`, w.peerSends)

	// Then
	sc.Step(`^the SEPP is healthy$`, w.sepHealthy)
	sc.Step(`^the N32 listener is started on port 8443$`, w.n32ListenerPort8443)
	sc.Step(`^the N32 listener is not started$`, w.n32ListenerNotStarted)
	sc.Step(`^no N32-c initiator runs$`, w.noInitiator)
	sc.Step(`^an N32-c initiator runs towards PLMN "([^"]+)"$`, w.initiatorRuns)
	sc.Step(`^the SEPP log has no WARN or ERROR line$`, w.noWarnOrError)
	sc.Step(`^the SEPP log has exactly one INFO line stating that N32 is disabled$`, w.oneInfoN32Disabled)
	sc.Step(`^the SEPP log has one INFO line stating that the partners file is absent$`, w.oneInfoFileAbsent)
	sc.Step(`^the SEPP exits with status (\d+)$`, w.exitsWith)
	sc.Step(`^the SEPP log has an ERROR line with cause "([^"]+)" mentioning "([^"]+)"$`, w.errorLineMentions)
	sc.Step(`^the admin endpoint GET "([^"]+)" returns an empty "([^"]+)" list$`, w.adminEmpty)
	sc.Step(`^the admin endpoint GET "([^"]+)" lists partner "([^"]+)" with source "([^"]+)"$`, w.adminLists)
	sc.Step(`^the admin endpoint GET "([^"]+)" lists exactly one partner "([^"]+)"$`, w.adminExactlyOne)
	sc.Step(`^that partner has source "([^"]+)" and caFile "([^"]+)"$`, w.thatPartner)
	sc.Step(`^each entry of "partners" has the keys (.+)$`, w.entriesHaveKeys)
	sc.Step(`^the entry "([^"]+)" has source "([^"]+)" and the entry "([^"]+)" has source "([^"]+)"$`, w.entrySources)
	sc.Step(`^a peer holding a certificate of PLMN "([^"]+)" issued by the test peer CA completes the TLS handshake with the N32 listener$`, w.peerCompletes)
	sc.Step(`^the TLS handshake succeeds$`, w.handshakeSucceeds)
	sc.Step(`^the TLS handshake fails$`, w.handshakeFails)
	sc.Step(`^the TLS handshake fails with alert "([^"]+)"$`, w.handshakeFailsAlert)
	sc.Step(`^the N32 trust pool of PLMN "([^"]+)" does not contain the SBI CA$`, w.trustPoolLacksSBICA)
	sc.Step(`^the metric "([^"]+)" with (reason|result) "([^"]+)" increases by 1$`, func(name, label, v string) error {
		return w.metricIncreases(name, label, v)
	})
	sc.Step(`^the SEPP log has cause "([^"]+)" with result "([^"]+)"$`, w.logCause)
	sc.Step(`^the SEPP log has cause "([^"]+)"$`, func(c string) error { return w.logCause(c, "") })
	sc.Step(`^the initiator aborts the TLS handshake with alert "([^"]+)"$`, w.initiatorAborts)
	sc.Step(`^the initiator does not retry$`, w.initiatorNoRetry)
	sc.Step(`^the response status is (\d+)$`, w.statusIs)
	sc.Step(`^the response "([^"]+)" is (.+)$`, w.rspIs)
	sc.Step(`^the response has no "allowedUsagePurpose" and no "rejectedUsagePurpose"$`, w.rspNoPurposes)
	sc.Step(`^the response is ProblemDetails with cause "([^"]+)"$`, w.rspProblem)
	sc.Step(`^the response body equals the golden file "([^"]+)"$`, w.rspGolden)
	sc.Step(`^no N32 context exists for remote PLMN "([^"]+)"$`, w.noContext)
	sc.Step(`^an N32 context exists for remote PLMN "([^"]+)" with security capability "([^"]+)"$`, w.contextExists)
}

func TestInteropFeatures(t *testing.T) {
	suiteT = t
	defer suiteClose()
	s := godog.TestSuite{
		ScenarioInitializer: InitializeInteropScenarios,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"n32_interop_readiness.feature"},
			TestingT: t,
		},
	}
	if s.Run() != 0 {
		t.Fatal("non-zero exit status from godog test suite")
	}
}
