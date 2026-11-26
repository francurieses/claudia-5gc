//go:build functional

package features

// Step definitions for roaming_status_tools.feature (@mcp_roaming, tool roaming_status).
// The world is self-contained: it owns its mocked portal, Prometheus, AMF and SMF
// upstreams and its own guard + dispatcher. Every mock records the method and path of
// each request so that "received no request" and "no request other than GET" are real
// assertions. Contract: docs/procedures/RoamingStatus.md §4-§5.
//
// Feature words map to upstream values as follows: the feature's access_mode "viewer"
// is the lowest trust level and runs as the read-only access mode (ceiling READ_ONLY);
// the lower-case result/direction words become the upper-case Prometheus label values
// (ok -> OK, in -> IN); the portal and Prometheus PLMNs stay "MCC/MNC" as written.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/server/transport"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/status"
)

const roamInvalidParams = -32602

// roamSeries is one Prometheus sample of a fivegc_sepp_* family.
type roamSeries struct {
	family string
	labels map[string]string
	value  string
}

// roamMock is one recording upstream.
type roamMock struct {
	name string
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string // "METHOD path"
}

func (m *roamMock) record(r *http.Request) {
	m.mu.Lock()
	m.reqs = append(m.reqs, r.Method+" "+r.URL.Path)
	m.mu.Unlock()
}

func (m *roamMock) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.reqs...)
}

type roamWorld struct {
	mu sync.Mutex

	portal, prom, amf, smf *roamMock

	portalBody map[string]any
	series     []roamSeries
	amfUEs     []map[string]any
	smfSess    []map[string]any

	mode  string
	guard *guard.Guard
	reg   *registry.Registry
	srv   *httptest.Server

	isError bool
	content map[string]any
	code    float64
	tools   []string
}

func (w *roamWorld) mocks() []*roamMock { return []*roamMock{w.portal, w.prom, w.amf, w.smf} }

func (w *roamWorld) reset() {
	w.close()
	w.portalBody, w.series, w.amfUEs, w.smfSess = nil, nil, nil, nil
	w.mode = "read-only"
	w.guard, w.reg = nil, nil
	w.isError, w.content, w.code, w.tools = false, nil, 0, nil
}

func (w *roamWorld) close() {
	if w.srv != nil {
		w.srv.Close()
	}
	w.srv = nil
	for _, m := range w.mocks() {
		if m != nil && m.srv != nil {
			m.srv.Close()
		}
	}
	w.portal, w.prom, w.amf, w.smf = nil, nil, nil, nil
}

func roamWrite(rw http.ResponseWriter, status int, body any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	b, _ := json.Marshal(body)
	_, _ = rw.Write(b)
}

func (w *roamWorld) newMock(name string, h func(http.ResponseWriter, *http.Request)) *roamMock {
	m := &roamMock{name: name}
	m.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		m.record(r)
		h(rw, r)
	}))
	return m
}

// ---- mock handlers ----------------------------------------------------------

func (w *roamWorld) portalHandler(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	body := w.portalBody
	w.mu.Unlock()
	if r.URL.Path != "/api/v1/roaming/status" || body == nil {
		roamWrite(rw, 404, map[string]any{"error": "not found"})
		return
	}
	roamWrite(rw, 200, body)
}

func (w *roamWorld) promHandler(rw http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("query")
	if q == "" {
		_ = r.ParseForm()
		q = r.Form.Get("query")
	}
	family := ""
	for _, f := range []string{
		"fivegc_sepp_n32c_context_established", "fivegc_sepp_n32c_handshake_total",
		"fivegc_sepp_n32f_messages_total", "fivegc_sepp_n32_tls_reject_total",
	} {
		if strings.Contains(q, f) {
			family = f
		}
	}
	res := []any{}
	w.mu.Lock()
	for _, s := range w.series {
		if s.family == family {
			res = append(res, map[string]any{"metric": s.labels, "value": []any{1, s.value}})
		}
	}
	w.mu.Unlock()
	roamWrite(rw, 200, map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": res}})
}

func (w *roamWorld) amfHandler(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	list := append([]map[string]any{}, w.amfUEs...)
	w.mu.Unlock()
	if r.URL.Path != "/amf/v1/ue-contexts" {
		roamWrite(rw, 404, map[string]any{})
		return
	}
	roamWrite(rw, 200, list)
}

func (w *roamWorld) smfHandler(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	list := append([]map[string]any{}, w.smfSess...)
	w.mu.Unlock()
	if r.URL.Path != "/nsmf-management/v1/sessions" {
		roamWrite(rw, 404, map[string]any{})
		return
	}
	roamWrite(rw, 200, map[string]any{"count": len(list), "sessions": list})
}

// ---- Given ------------------------------------------------------------------

func (w *roamWorld) runsAgainstMocks() error {
	w.reset()
	w.portal = w.newMock("portal", w.portalHandler)
	w.prom = w.newMock("Prometheus", w.promHandler)
	w.amf = w.newMock("AMF", w.amfHandler)
	w.smf = w.newMock("SMF", w.smfHandler)
	return nil
}

// guardMode: "viewer" is a role, not an access mode; it maps to the read-only mode.
func (w *roamWorld) guardMode(mode string) error {
	if w.srv != nil {
		w.srv.Close()
		w.srv = nil
	}
	if mode == "viewer" {
		mode = "read-only"
	}
	w.mode = mode
	return nil
}

func (w *roamWorld) portalDeployed(state, local, partner string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.portalBody = map[string]any{
		"deployed": true,
		"link":     map[string]any{"state": state, "local_plmn": local, "partner_plmn": partner},
		"sepps":    []any{},
	}
	return nil
}

func (w *roamWorld) portalNotDeployed(state string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.portalBody = map[string]any{
		"deployed": false,
		"link":     map[string]any{"state": state},
		"sepps":    []any{},
	}
	return nil
}

func (w *roamWorld) portalPartner(sepp, plmn, state string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.portalBody == nil {
		return fmt.Errorf("portal mock has no roaming status yet")
	}
	local, _ := w.portalBody["link"].(map[string]any)["local_plmn"].(string)
	w.portalBody["sepps"] = append(w.portalBody["sepps"].([]any), map[string]any{
		"name": sepp,
		"n32": map[string]any{
			"local_plmn": local,
			"partners":   []any{map[string]any{"plmn": plmn, "state": state}},
		},
	})
	return nil
}

func (w *roamWorld) addSeries(family string, labels map[string]string, value string) {
	w.mu.Lock()
	w.series = append(w.series, roamSeries{family, labels, value})
	w.mu.Unlock()
}

func (w *roamWorld) promEstablished(val, role, peer string) error {
	w.addSeries("fivegc_sepp_n32c_context_established", map[string]string{"role": role, "peer_plmn": peer}, val)
	return nil
}

func (w *roamWorld) promHandshakes(okN, rejN, role, peer string) error {
	for res, n := range map[string]string{"OK": okN, "REJECT": rejN} {
		w.addSeries("fivegc_sepp_n32c_handshake_total",
			map[string]string{"role": role, "peer_plmn": peer, "result": res}, n)
	}
	return nil
}

var roamDirRe = regexp.MustCompile(`direction "([a-z]+)" result "([a-z]+)" (\d+)`)

func (w *roamWorld) promN32F(list, role, peer string) error {
	ms := roamDirRe.FindAllStringSubmatch(list, -1)
	if len(ms) == 0 {
		return fmt.Errorf("no direction/result/value triple in %q", list)
	}
	for _, m := range ms {
		w.addSeries("fivegc_sepp_n32f_messages_total", map[string]string{
			"role": role, "peer_plmn": peer, "direction": strings.ToUpper(m[1]), "result": strings.ToUpper(m[2]),
		}, m[3])
	}
	return nil
}

func (w *roamWorld) promN32FOther(role, p1, p2 string) error {
	for _, p := range []string{p1, p2} {
		w.addSeries("fivegc_sepp_n32f_messages_total", map[string]string{
			"role": role, "peer_plmn": p, "direction": "OUT", "result": "OK",
		}, "1")
	}
	return nil
}

func (w *roamWorld) promTLSReject(reason, n, role string) error {
	w.addSeries("fivegc_sepp_n32_tls_reject_total", map[string]string{"role": role, "reason": reason}, n)
	return nil
}

func (w *roamWorld) promNoSeries() error {
	w.mu.Lock()
	w.series = nil
	w.mu.Unlock()
	return nil
}

func (w *roamWorld) amfHolds(a, b string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range []string{a, b} {
		w.amfUEs = append(w.amfUEs, map[string]any{"supi": s, "gmm_state": "REGISTERED", "cm_state": "CONNECTED"})
	}
	return nil
}

func (w *roamWorld) smfHolds(supi string, psi int, dnn, ip string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.smfSess = append(w.smfSess, map[string]any{
		"supi": supi, "pduSessionId": psi, "dnn": dnn, "ueIp": ip, "sessionState": "ACTIVE",
		"sNssai": map[string]any{"sst": 1, "sd": "010203"},
	})
	return nil
}

func (w *roamWorld) unreachable(which string) error {
	var m *roamMock
	switch which {
	case "portal":
		m = w.portal
	case "Prometheus":
		m = w.prom
	case "AMF":
		m = w.amf
	case "SMF":
		m = w.smf
	}
	if m == nil {
		return fmt.Errorf("unknown mock %q (mocks not started?)", which)
	}
	m.srv.Close()
	return nil
}

// ---- server -----------------------------------------------------------------

func (w *roamWorld) ensureServer() error {
	if w.srv != nil {
		return nil
	}
	if w.portal == nil {
		return fmt.Errorf("mocks are not running")
	}
	m, err := guard.ParseAccessMode(w.mode)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w.guard = guard.New(guard.Options{Mode: m, MinInterval: 2 * time.Second}, logger)
	deps := status.Deps{
		Portal: clients.NewPortal(w.portal.srv.URL, http.DefaultClient),
		Prom:   promclient.New(w.prom.srv.URL, http.DefaultClient, 0),
		AMF:    clients.NewAMF(w.amf.srv.URL, http.DefaultClient),
		SMF:    clients.NewSMF(w.smf.srv.URL, http.DefaultClient),
		HTTP:   http.DefaultClient,
	}
	w.reg = registry.New()
	if err := w.reg.RegisterAll(status.All(deps)...); err != nil {
		return err
	}
	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true}}
	disp := server.NewDispatcher(w.reg, w.guard, logger)
	sse := transport.NewSSE(disp, w.reg, session.NewManager(logger), cfg, logger)
	w.srv = httptest.NewServer(sse.Handler())
	return nil
}

// ---- When -------------------------------------------------------------------

func (w *roamWorld) call(name, args string) error {
	if err := w.ensureServer(); err != nil {
		return err
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, name, args)
	resp, err := http.Post(w.srv.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if e, ok := env["error"].(map[string]any); ok {
		// JSON-RPC level error (e.g. schema validation before the tool runs).
		w.isError, w.content = true, e
		w.code, _ = e["code"].(float64)
		return nil
	}
	res, _ := env["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		return fmt.Errorf("no content in response: %v", env)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	w.content = map[string]any{}
	if err := json.Unmarshal([]byte(text), &w.content); err != nil {
		return fmt.Errorf("decode tool content %q: %w", text, err)
	}
	w.isError, _ = res["isError"].(bool)
	w.code = 0
	if w.isError {
		w.code, _ = w.content["code"].(float64)
	}
	return nil
}

func (w *roamWorld) listTools(mode string) error {
	if err := w.guardMode(mode); err != nil {
		return err
	}
	if err := w.ensureServer(); err != nil {
		return err
	}
	resp, err := http.Get(w.srv.URL + "/mcp/tools")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	w.tools = nil
	for _, t := range out.Tools {
		w.tools = append(w.tools, t.Name)
	}
	return nil
}

// ---- result path helpers ----------------------------------------------------

var roamIdxRe = regexp.MustCompile(`^([^\[\]]+)((?:\[\d+\])*)$`)

// lookup walks "a.b[0].c" through the call result; found is false if any hop is missing.
func (w *roamWorld) lookup(path string) (v any, found bool, err error) {
	if w.content == nil {
		return nil, false, fmt.Errorf("no call was made")
	}
	var cur any = w.content
	for _, seg := range strings.Split(path, ".") {
		m := roamIdxRe.FindStringSubmatch(seg)
		if m == nil {
			return nil, false, fmt.Errorf("bad path segment %q", seg)
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false, nil
		}
		if cur, ok = obj[m[1]]; !ok {
			return nil, false, nil
		}
		for _, ix := range regexp.MustCompile(`\d+`).FindAllString(m[2], -1) {
			n, _ := strconv.Atoi(ix)
			arr, ok := cur.([]any)
			if !ok || n >= len(arr) {
				return nil, false, nil
			}
			cur = arr[n]
		}
	}
	return cur, true, nil
}

func roamIsEmpty(v any, found bool) bool {
	if !found || v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && s == ""
}

// ---- Then -------------------------------------------------------------------

func (w *roamWorld) succeeds() error {
	if w.content == nil {
		return fmt.Errorf("no call was made")
	}
	if w.isError {
		return fmt.Errorf("call failed: %v", w.content)
	}
	return nil
}

func (w *roamWorld) invalidParams() error {
	if !w.isError {
		return fmt.Errorf("expected an invalid-params error, call succeeded: %v", w.content)
	}
	if int(w.code) != roamInvalidParams {
		return fmt.Errorf("error code: got %v, want %d (%v)", w.code, roamInvalidParams, w.content)
	}
	return nil
}

func (w *roamWorld) fieldBool(path, want string) error {
	v, found, err := w.lookup(path)
	if err != nil {
		return err
	}
	b, ok := v.(bool)
	if !found || !ok || b != (want == "true") {
		return fmt.Errorf("field %s: got %v (found=%v), want %s", path, v, found, want)
	}
	return nil
}

func (w *roamWorld) fieldString(path, want string) error {
	v, found, err := w.lookup(path)
	if err != nil {
		return err
	}
	if s, ok := v.(string); !found || !ok || s != want {
		return fmt.Errorf("field %s: got %v (found=%v), want %q", path, v, found, want)
	}
	return nil
}

func (w *roamWorld) fieldNumber(path string, want int) error {
	v, found, err := w.lookup(path)
	if err != nil {
		return err
	}
	if f, ok := v.(float64); !found || !ok || int(f) != want {
		return fmt.Errorf("field %s: got %v (found=%v), want %d", path, v, found, want)
	}
	return nil
}

func (w *roamWorld) fieldNotEmpty(path string) error {
	v, found, err := w.lookup(path)
	if err != nil {
		return err
	}
	if roamIsEmpty(v, found) {
		return fmt.Errorf("field %s is empty or absent", path)
	}
	return nil
}

func (w *roamWorld) fieldEmpty(path string) error {
	v, found, err := w.lookup(path)
	if err != nil {
		return err
	}
	if !roamIsEmpty(v, found) {
		return fmt.Errorf("field %s should be empty, got %v", path, v)
	}
	return nil
}

func (w *roamWorld) fieldContains(path, sub string) error {
	v, _, err := w.lookup(path)
	if err != nil {
		return err
	}
	if s, ok := v.(string); !ok || !strings.Contains(s, sub) {
		return fmt.Errorf("field %s: got %v, want it to contain %q", path, v, sub)
	}
	return nil
}

func (w *roamWorld) fieldErrorString(path string) error {
	v, _, err := w.lookup(path)
	if err != nil {
		return err
	}
	if s, ok := v.(string); !ok || s == "" || s == "ok" {
		return fmt.Errorf("field %s should be an error string, got %v", path, v)
	}
	return nil
}

func (w *roamWorld) partners() ([]map[string]any, error) {
	v, found, err := w.lookup("partners")
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !found || !ok {
		return nil, fmt.Errorf("partners is not an array: %v", v)
	}
	out := []map[string]any{}
	for _, p := range arr {
		m, _ := p.(map[string]any)
		out = append(out, m)
	}
	return out, nil
}

func (w *roamWorld) partnersExactly(list string) error {
	ps, err := w.partners()
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, s := range regexp.MustCompile(`[0-9]{3}-[0-9]{2,3}`).FindAllString(list, -1) {
		want[s] = true
	}
	got := map[string]bool{}
	for _, p := range ps {
		plmn, _ := p["plmn"].(string)
		got[plmn] = true
	}
	if len(got) != len(ps) || len(got) != len(want) {
		return fmt.Errorf("partners: got %v, want exactly %v", got, want)
	}
	for k := range want {
		if !got[k] {
			return fmt.Errorf("partners: got %v, want exactly %v", got, want)
		}
	}
	return nil
}

func (w *roamWorld) partnersEmpty() error {
	ps, err := w.partners()
	if err != nil {
		return err
	}
	if len(ps) != 0 {
		return fmt.Errorf("partners should be empty, got %v", ps)
	}
	return nil
}

func (w *roamWorld) noTLSRejects() error {
	v, found, err := w.lookup("tls_rejects")
	if err != nil {
		return err
	}
	if m, ok := v.(map[string]any); found && v != nil && (!ok || len(m) != 0) {
		return fmt.Errorf("tls_rejects should have no entries, got %v", v)
	}
	return nil
}

// seppEntry finds the per-SEPP block of a partner.
func (w *roamWorld) seppEntry(plmn, sepp string) (map[string]any, error) {
	ps, err := w.partners()
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		if p["plmn"] != plmn {
			continue
		}
		list, _ := p["sepps"].([]any)
		for _, e := range list {
			m, _ := e.(map[string]any)
			if m["sepp"] == sepp {
				return m, nil
			}
		}
		return nil, fmt.Errorf("partner %s has no sepp %q block: %v", plmn, sepp, p)
	}
	return nil, fmt.Errorf("no partner %s in %v", plmn, ps)
}

func (w *roamWorld) partnerState(plmn, sepp, state string) error {
	e, err := w.seppEntry(plmn, sepp)
	if err != nil {
		return err
	}
	if e["context_state"] != state {
		return fmt.Errorf("partner %s sepp %s context_state: got %v, want %q", plmn, sepp, e["context_state"], state)
	}
	return nil
}

func (w *roamWorld) partnerEstablished(plmn, sepp, want string) error {
	e, err := w.seppEntry(plmn, sepp)
	if err != nil {
		return err
	}
	if b, ok := e["context_established"].(bool); !ok || b != (want == "true") {
		return fmt.Errorf("partner %s sepp %s context_established: got %v, want %s", plmn, sepp, e["context_established"], want)
	}
	return nil
}

func (w *roamWorld) partnerStateAndEstablished(plmn, sepp, state, est string) error {
	if err := w.partnerState(plmn, sepp, state); err != nil {
		return err
	}
	return w.partnerEstablished(plmn, sepp, est)
}

func (w *roamWorld) partnerNoKey(plmn, sepp, key string) error {
	e, err := w.seppEntry(plmn, sepp)
	if err != nil {
		return err
	}
	if v, ok := e[key]; ok && v != nil && v != "" {
		return fmt.Errorf("partner %s sepp %s should have no %s, got %v", plmn, sepp, key, v)
	}
	return nil
}

func (w *roamWorld) partnerCounters(plmn, sepp, block string, want map[string]int) error {
	e, err := w.seppEntry(plmn, sepp)
	if err != nil {
		return err
	}
	m, ok := e[block].(map[string]any)
	if !ok {
		return fmt.Errorf("partner %s sepp %s has no %s block: %v", plmn, sepp, block, e)
	}
	for k, n := range want {
		if f, ok := m[k].(float64); !ok || int(f) != n {
			return fmt.Errorf("partner %s sepp %s %s.%s: got %v, want %d (%v)", plmn, sepp, block, k, m[k], n, m)
		}
	}
	return nil
}

func (w *roamWorld) partnerHandshakes(plmn, sepp string, ok, rej, fail int) error {
	return w.partnerCounters(plmn, sepp, "handshakes", map[string]int{"ok": ok, "reject": rej, "failure": fail})
}

func (w *roamWorld) partnerN32F(plmn, sepp string, out, in, rej, fail int) error {
	return w.partnerCounters(plmn, sepp, "n32f", map[string]int{"out_ok": out, "in_ok": in, "reject": rej, "failure": fail})
}

func (w *roamWorld) noRequests() error {
	for _, m := range w.mocks() {
		if r := m.snapshot(); len(r) != 0 {
			return fmt.Errorf("%s mock received %d request(s): %v", m.name, len(r), r)
		}
	}
	return nil
}

func (w *roamWorld) onlyGET() error {
	total := 0
	for _, m := range w.mocks() {
		for _, r := range m.snapshot() {
			total++
			if !strings.HasPrefix(r, http.MethodGet+" ") {
				return fmt.Errorf("%s mock received a non-GET request: %s", m.name, r)
			}
		}
	}
	if total == 0 {
		return fmt.Errorf("no upstream request was recorded at all; the recorders are not wired")
	}
	return nil
}

func (w *roamWorld) toolListed(name string) error {
	for _, n := range w.tools {
		if n == name {
			return nil
		}
	}
	return fmt.Errorf("tool list %v lacks %q", w.tools, name)
}

func (w *roamWorld) toolRisk(name, risk string) error {
	if err := w.ensureServer(); err != nil {
		return err
	}
	t, ok := w.reg.Get(name)
	if !ok {
		return fmt.Errorf("tool %q is not registered", name)
	}
	if got := t.Risk().String(); got != risk {
		return fmt.Errorf("tool %s risk: got %s, want %s", name, got, risk)
	}
	return nil
}

func (w *roamWorld) noAudit() error {
	if err := w.ensureServer(); err != nil {
		return err
	}
	if e := w.guard.Audit().Recent(0); len(e) != 0 {
		return fmt.Errorf("unexpected audit entries: %+v", e)
	}
	return nil
}

// ---- wiring -----------------------------------------------------------------

func initializeRoamingScenario(sc *godog.ScenarioContext) {
	w := &roamWorld{}
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.close()
		return ctx, nil
	})

	sc.Step(`^the MCP roaming status tool runs against mocked portal, Prometheus, AMF and SMF upstreams$`, w.runsAgainstMocks)
	sc.Step(`^the MCP guard runs with access_mode "([^"]+)"$`, w.guardMode)
	sc.Step(`^the portal mock reports roaming deployed with link state "([^"]+)", local_plmn "([^"]+)" and partner_plmn "([^"]+)"$`, w.portalDeployed)
	sc.Step(`^the portal mock reports roaming not deployed with link state "([^"]+)"$`, w.portalNotDeployed)
	sc.Step(`^the portal mock reports for SEPP "([^"]+)" an n32 partner "([^"]+)" with state "([^"]+)"$`, w.portalPartner)
	sc.Step(`^the Prometheus mock (?:also )?holds fivegc_sepp_n32c_context_established (\d+) for role "([^"]+)" and peer_plmn "([^"]+)"$`, w.promEstablished)
	sc.Step(`^the Prometheus mock (?:also )?holds fivegc_sepp_n32c_handshake_total result "ok" (\d+) and result "reject" (\d+) for role "([^"]+)" and peer_plmn "([^"]+)"$`, w.promHandshakes)
	sc.Step(`^the Prometheus mock (?:also )?holds fivegc_sepp_n32f_messages_total (direction .+) for role "([^"]+)" and peer_plmn "([^"]+)"$`, w.promN32F)
	sc.Step(`^the Prometheus mock (?:also )?holds fivegc_sepp_n32f_messages_total for role "([^"]+)" and peer_plmn "([^"]+)" and peer_plmn "([^"]+)"$`, w.promN32FOther)
	sc.Step(`^the Prometheus mock (?:also )?holds fivegc_sepp_n32_tls_reject_total reason "([^"]+)" (\d+) for role "([^"]+)"$`, w.promTLSReject)
	sc.Step(`^the Prometheus mock holds no fivegc_sepp series$`, w.promNoSeries)
	sc.Step(`^the AMF mock holds UEs "([^"]+)" and "([^"]+)"$`, w.amfHolds)
	sc.Step(`^the SMF mock holds a session for "([^"]+)" with pdu_session_id (\d+), dnn "([^"]+)" and ue_ip "([^"]+)"$`, w.smfHolds)
	sc.Step(`^the (portal|Prometheus|AMF|SMF) mock is unreachable$`, w.unreachable)

	sc.Step(`^I call "([^"]+)" with arguments (\{.*\})$`, w.call)
	sc.Step(`^I list the tools for access_mode "([^"]+)"$`, w.listTools)

	sc.Step(`^the call succeeds$`, w.succeeds)
	sc.Step(`^the call fails with an invalid-params error$`, w.invalidParams)
	sc.Step(`^the result field "([^"]+)" is (true|false)$`, w.fieldBool)
	sc.Step(`^the result field "([^"]+)" is "([^"]*)"$`, w.fieldString)
	sc.Step(`^the result field "([^"]+)" is (\d+)$`, w.fieldNumber)
	sc.Step(`^the result field "([^"]+)" is not empty$`, w.fieldNotEmpty)
	sc.Step(`^the result field "([^"]+)" is empty$`, w.fieldEmpty)
	sc.Step(`^the result field "([^"]+)" contains "([^"]*)"$`, w.fieldContains)
	sc.Step(`^the result field "([^"]+)" is an error string$`, w.fieldErrorString)
	sc.Step(`^the result partners contain exactly the plmns (.+)$`, w.partnersExactly)
	sc.Step(`^the result partners is an empty array$`, w.partnersEmpty)
	sc.Step(`^the result has no "tls_rejects" entries$`, w.noTLSRejects)
	sc.Step(`^the result partner "([^"]+)" on sepp "([^"]+)" has context_state "([^"]+)" and context_established (true|false)$`, w.partnerStateAndEstablished)
	sc.Step(`^the result partner "([^"]+)" on sepp "([^"]+)" has context_state "([^"]+)"$`, w.partnerState)
	sc.Step(`^the result partner "([^"]+)" on sepp "([^"]+)" has context_established (true|false)$`, w.partnerEstablished)
	sc.Step(`^the result partner "([^"]+)" on sepp "([^"]+)" has handshakes ok (\d+), reject (\d+), failure (\d+)$`, w.partnerHandshakes)
	sc.Step(`^the result partner "([^"]+)" on sepp "([^"]+)" has n32f out_ok (\d+), in_ok (\d+), reject (\d+), failure (\d+)$`, w.partnerN32F)
	sc.Step(`^the result partner "([^"]+)" on sepp "([^"]+)" has no (context_state|context_established|handshakes)$`, w.partnerNoKey)
	sc.Step(`^the portal mock, the Prometheus mock, the AMF mock and the SMF mock received no request$`, w.noRequests)
	sc.Step(`^the portal mock, the Prometheus mock, the AMF mock and the SMF mock received no request other than GET$`, w.onlyGET)
	sc.Step(`^the tool "([^"]+)" is listed$`, w.toolListed)
	sc.Step(`^the tool "([^"]+)" has risk "([^"]+)"$`, w.toolRisk)
	sc.Step(`^no audit entry is recorded$`, w.noAudit)
}

// TestRoamingStatusFeatures runs only the @mcp_roaming feature file.
func TestRoamingStatusFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initializeRoamingScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"roaming_status_tools.feature"},
			Tags:     "@mcp_roaming",
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero exit status from the @mcp_roaming godog suite")
	}
}
