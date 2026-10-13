//go:build functional

package features

// Step definitions for n4_inspection_tools.feature (@mcp012, tool n4_session_get).
// The world is self-contained: it owns its mocked SMF, Prometheus and UPF admin
// upstreams and its own guard + dispatcher, so it shares no state with the other
// suites. The suite is selected by the @mcp012 tag.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
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
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/analysis"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

type n4Req struct {
	method string
	path   string
	query  url.Values
}

// n4World holds the mocks and the last call result of one scenario.
type n4World struct {
	mu sync.Mutex

	smf, prom, upf *httptest.Server
	smfReqs        []n4Req
	upfReqs        []n4Req

	promHasTarget bool

	// SMF mock state
	smfSession  map[string]any // nil = holds none
	smfPSI      int
	smfStatus   map[string]int    // path -> forced status
	smfCause    map[string]string // path -> cause body
	smfDropSEID map[uint64]bool

	// UPF mock state
	upfSessions []map[string]any

	mode  string
	guard *guard.Guard
	reg   *registry.Registry
	srv   *httptest.Server

	// last result
	isError bool
	content map[string]any
	code    float64
	data    map[string]any
}

func (w *n4World) reset() {
	w.close()
	w.smfReqs, w.upfReqs = nil, nil
	w.promHasTarget = true
	w.smfSession, w.smfPSI = nil, 0
	w.smfStatus, w.smfCause = map[string]int{}, map[string]string{}
	w.smfDropSEID = map[uint64]bool{}
	w.upfSessions = nil
	w.mode = "operator"
	w.guard, w.reg = nil, nil
	w.isError, w.content, w.code, w.data = false, nil, 0, nil
}

func (w *n4World) close() {
	for _, s := range []*httptest.Server{w.srv, w.smf, w.prom, w.upf} {
		if s != nil {
			s.Close()
		}
	}
	w.srv, w.smf, w.prom, w.upf = nil, nil, nil, nil
}

// ---- pseudo-notation parsing ------------------------------------------------

var n4ObjRe = regexp.MustCompile(`\{([^}]*)\}`)

func n4Scalar(s string) any {
	switch s {
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return s
}

// n4Objs parses "[{key value, key value}, {...}]" into JSON-ready maps.
func n4Objs(s string) []map[string]any {
	out := []map[string]any{}
	for _, m := range n4ObjRe.FindAllStringSubmatch(s, -1) {
		o := map[string]any{}
		for _, kv := range strings.Split(m[1], ",") {
			kv = strings.TrimSpace(kv)
			if kv == "" {
				continue
			}
			parts := strings.SplitN(kv, " ", 2)
			if len(parts) == 2 {
				o[parts[0]] = n4Scalar(strings.TrimSpace(parts[1]))
			}
		}
		out = append(out, o)
	}
	return out
}

// n4Val parses an expected value: "str", null, or a number.
func n4Val(s string) any {
	s = strings.TrimSpace(s)
	if s == "null" {
		return nil
	}
	if strings.HasPrefix(s, `"`) {
		var v string
		if json.Unmarshal([]byte(s), &v) == nil {
			return v
		}
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f
	}
	return s
}

// ---- mocks ------------------------------------------------------------------

func (w *n4World) record(list *[]n4Req, r *http.Request) {
	w.mu.Lock()
	*list = append(*list, n4Req{r.Method, r.URL.Path, r.URL.Query()})
	w.mu.Unlock()
}

func n4Write(rw http.ResponseWriter, status int, body any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	b, _ := json.Marshal(body)
	_, _ = rw.Write(b)
}

func (w *n4World) smfHandler(rw http.ResponseWriter, r *http.Request) {
	w.record(&w.smfReqs, r)
	w.mu.Lock()
	defer w.mu.Unlock()
	if st, ok := w.smfStatus[r.URL.Path]; ok {
		body := map[string]any{}
		if c := w.smfCause[r.URL.Path]; c != "" {
			body["cause"] = c
		}
		n4Write(rw, st, body)
		return
	}
	if r.URL.Path == "/nsmf-management/v1/sessions" {
		list := []any{}
		if w.smfSession != nil {
			s := w.smfSession["session"].(map[string]any)
			if !w.smfDropSEID[uint64(s["seid"].(int))] {
				list = append(list, s)
			}
		}
		n4Write(rw, 200, map[string]any{"count": len(list), "sessions": list})
		return
	}
	if w.smfSession != nil && r.URL.Path == fmt.Sprintf("/nsmf-management/v1/sessions/%d", w.smfPSI) {
		s := w.smfSession["session"].(map[string]any)
		if !w.smfDropSEID[uint64(s["seid"].(int))] {
			n4Write(rw, 200, w.smfSession)
			return
		}
	}
	n4Write(rw, 404, map[string]any{"cause": "CONTEXT_NOT_FOUND"})
}

func (w *n4World) upfHandler(rw http.ResponseWriter, r *http.Request) {
	w.record(&w.upfReqs, r)
	w.mu.Lock()
	defer w.mu.Unlock()
	q := r.URL.Query()
	out := []any{}
	for _, s := range w.upfSessions {
		if v := q.Get("seid"); v != "" && strconv.Itoa(s["cp_seid"].(int)) != v {
			continue
		}
		if v := q.Get("ue_ip"); v != "" && s["ue_ipv4"] != v {
			continue
		}
		out = append(out, s)
	}
	n4Write(rw, 200, map[string]any{"count": len(out), "sessions": out})
}

// promQuery returns the PromQL expression of an instant-query request (GET or POST).
func promQuery(r *http.Request) string {
	if q := r.URL.Query().Get("query"); q != "" {
		return q
	}
	_ = r.ParseForm()
	return r.Form.Get("query")
}

func (w *n4World) promHandler(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	has := w.promHasTarget && strings.Contains(promQuery(r), `nf="UPF"`)
	w.mu.Unlock()
	res := []any{}
	if has {
		res = append(res, map[string]any{
			"metric": map[string]string{"nf": "UPF", "instance": strings.TrimPrefix(w.upf.URL, "http://")},
			"value":  []any{1, "1"},
		})
	}
	n4Write(rw, 200, map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": res}})
}

func (w *n4World) startMocks() error {
	w.reset()
	w.upf = httptest.NewServer(http.HandlerFunc(w.upfHandler))
	w.smf = httptest.NewServer(http.HandlerFunc(w.smfHandler))
	w.prom = httptest.NewServer(http.HandlerFunc(w.promHandler))
	return nil
}

// ---- server (lazy so that the access mode step can be repeated) -------------

func (w *n4World) ensureServer() error {
	if w.srv != nil {
		return nil
	}
	m, err := guard.ParseAccessMode(w.mode)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w.guard = guard.New(guard.Options{Mode: m, MinInterval: 2 * time.Second}, logger)
	pc := promclient.New(w.prom.URL, w.prom.Client(), 0)
	deps := analysis.Deps{
		SMF:     clients.NewSMF(w.smf.URL, http.DefaultClient),
		Prom:    pc,
		Targets: clients.NewTargets(pc, ""),
		HTTP:    http.DefaultClient,
	}
	w.reg = registry.New()
	if err := w.reg.RegisterAll(analysis.All(deps)...); err != nil {
		return err
	}
	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true}}
	disp := server.NewDispatcher(w.reg, w.guard, logger)
	sse := transport.NewSSE(disp, w.reg, session.NewManager(logger), cfg, logger)
	w.srv = httptest.NewServer(sse.Handler())
	return nil
}

// ---- Given ------------------------------------------------------------------

func (w *n4World) runsAgainstMocks() error { return w.startMocks() }

func (w *n4World) guardMode(mode string) error {
	if w.srv != nil {
		w.srv.Close()
		w.srv = nil
	}
	w.mode = mode
	return nil
}

func (w *n4World) promResolves(nf string) error {
	if nf != "upf" {
		return fmt.Errorf("only nf upf is mocked, got %q", nf)
	}
	w.mu.Lock()
	w.promHasTarget = true
	w.mu.Unlock()
	return nil
}

func (w *n4World) promNoTarget(nf string) error {
	w.mu.Lock()
	w.promHasTarget = false
	w.mu.Unlock()
	return nil
}

func (w *n4World) smfHolds(psi int, supi string, seid, teid int, ip, qers string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.smfPSI = psi
	w.smfSession = map[string]any{
		"session": map[string]any{
			"supi": supi, "pduSessionId": psi, "seid": seid, "upfTeid": teid, "ueIp": ip,
		},
		"pfcpQers": n4Objs(qers),
	}
	return nil
}

func (w *n4World) smfHoldsNoSEID(seid int) error {
	w.mu.Lock()
	w.smfDropSEID[uint64(seid)] = true
	w.mu.Unlock()
	return nil
}

func (w *n4World) smfAnswers(status int, path string) error {
	w.mu.Lock()
	w.smfStatus[path] = status
	w.mu.Unlock()
	return nil
}

func (w *n4World) smfAnswersCause(status int, cause, path string) error {
	w.mu.Lock()
	w.smfStatus[path] = status
	w.smfCause[path] = cause
	w.mu.Unlock()
	return nil
}

func (w *n4World) upfHolds(cp, up, teid int, ip, qers string) error {
	w.mu.Lock()
	w.upfSessions = append(w.upfSessions, map[string]any{
		"cp_seid": cp, "up_seid": up, "ul_teid": teid, "ue_ipv4": ip, "qers": n4Objs(qers),
	})
	w.mu.Unlock()
	return nil
}

func (w *n4World) upfAlsoHolds(cp, up int, ip string) error {
	w.mu.Lock()
	w.upfSessions = append(w.upfSessions, map[string]any{
		"cp_seid": cp, "up_seid": up, "ue_ipv4": ip, "qers": []any{},
	})
	w.mu.Unlock()
	return nil
}

func (w *n4World) upfHoldsNone() error {
	w.mu.Lock()
	w.upfSessions = nil
	w.mu.Unlock()
	return nil
}

func (w *n4World) upfShutDown() error {
	w.upf.Close()
	return nil
}

// ---- When -------------------------------------------------------------------

func (w *n4World) rpc(body string) (map[string]any, error) {
	if err := w.ensureServer(); err != nil {
		return nil, err
	}
	resp, err := http.Post(w.srv.URL+"/mcp", "application/json", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return out, nil
}

func (w *n4World) call(name, args string) error {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, name, args)
	env, err := w.rpc(body)
	if err != nil {
		return err
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
	w.code, w.data = 0, nil
	if w.isError {
		w.code, _ = w.content["code"].(float64)
		w.data, _ = w.content["data"].(map[string]any)
	}
	return nil
}

func (w *n4World) listTools() error {
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
	names := []any{}
	for _, t := range out.Tools {
		names = append(names, t.Name)
	}
	w.content = map[string]any{"tools": names}
	return nil
}

// ---- Then -------------------------------------------------------------------

func (w *n4World) succeeds() error {
	if w.content == nil {
		return fmt.Errorf("no call was made")
	}
	if w.isError {
		return fmt.Errorf("call failed: %v", w.content)
	}
	return nil
}

func (w *n4World) refused(code int) error {
	if !w.isError {
		return fmt.Errorf("expected refusal with code %d, call succeeded: %v", code, w.content)
	}
	if int(w.code) != code {
		return fmt.Errorf("code: got %v, want %d (%v)", w.code, code, w.content)
	}
	return nil
}

func (w *n4World) hasKeys(a, b, c string) error {
	for _, k := range []string{a, b, c} {
		if _, ok := w.content[k]; !ok {
			return fmt.Errorf("result lacks key %q: %v", k, w.content)
		}
	}
	return nil
}

func (w *n4World) upfQERs(n int) error {
	upf, ok := w.content["upf"].(map[string]any)
	if !ok {
		return fmt.Errorf("result upf is not an object: %v", w.content["upf"])
	}
	q, _ := upf["qers"].([]any)
	if len(q) != n {
		return fmt.Errorf("upf qers: got %d, want %d", len(q), n)
	}
	return nil
}

func (w *n4World) mismatches() ([]map[string]any, error) {
	raw, ok := w.content["smf_mismatches"].([]any)
	if !ok {
		return nil, fmt.Errorf("smf_mismatches is not an array: %v", w.content["smf_mismatches"])
	}
	out := []map[string]any{}
	for _, r := range raw {
		m, _ := r.(map[string]any)
		out = append(out, m)
	}
	return out, nil
}

func (w *n4World) mismatchesEmpty() error {
	mm, err := w.mismatches()
	if err != nil {
		return err
	}
	if len(mm) != 0 {
		return fmt.Errorf("smf_mismatches should be empty, got %v", mm)
	}
	return nil
}

func (w *n4World) mismatchesCount(n int) error {
	mm, err := w.mismatches()
	if err != nil {
		return err
	}
	if len(mm) != n {
		return fmt.Errorf("smf_mismatches: got %d entries, want %d: %v", len(mm), n, mm)
	}
	return nil
}

func n4Match(m map[string]any, field string, smf, upf any) bool {
	return m["field"] == field && reflect.DeepEqual(m["smf"], smf) && reflect.DeepEqual(m["upf"], upf)
}

func (w *n4World) entryHas(idx int, field, smf, upf string) error {
	mm, err := w.mismatches()
	if err != nil {
		return err
	}
	if idx < 1 || idx > len(mm) {
		return fmt.Errorf("no smf_mismatches entry %d in %v", idx, mm)
	}
	if !n4Match(mm[idx-1], field, n4Val(smf), n4Val(upf)) {
		return fmt.Errorf("entry %d = %v, want field %s smf %s upf %s", idx, mm[idx-1], field, smf, upf)
	}
	return nil
}

func (w *n4World) mismatchesContain(field, smf, upf string) error {
	mm, err := w.mismatches()
	if err != nil {
		return err
	}
	for _, m := range mm {
		if n4Match(m, field, n4Val(smf), n4Val(upf)) {
			return nil
		}
	}
	return fmt.Errorf("no mismatch field %s smf %s upf %s in %v", field, smf, upf, mm)
}

func (w *n4World) count(reqs []n4Req, method, path string, q url.Values) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, r := range reqs {
		if r.method != method || r.path != path {
			continue
		}
		ok := true
		for k := range q {
			if r.query.Get(k) != q.Get(k) {
				ok = false
			}
		}
		if ok {
			n++
		}
	}
	return n
}

func (w *n4World) smfExactlyGET(n int, path string) error {
	if got := w.count(w.smfReqs, http.MethodGet, path, nil); got != n {
		return fmt.Errorf("SMF GET %s: got %d, want %d (all: %v)", path, got, n, w.smfReqs)
	}
	return nil
}

func (w *n4World) upfExactlyGETQuery(n int, path, key, val string) error {
	if got := w.count(w.upfReqs, http.MethodGet, path, url.Values{key: {val}}); got != n {
		return fmt.Errorf("UPF GET %s?%s=%s: got %d, want %d (all: %v)", path, key, val, got, n, w.upfReqs)
	}
	return nil
}

func (w *n4World) upfOnlyGET() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.upfReqs {
		if r.method != http.MethodGet {
			return fmt.Errorf("UPF admin mock received %s %s", r.method, r.path)
		}
	}
	return nil
}

func (w *n4World) upfNoRequest() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.upfReqs) != 0 {
		return fmt.Errorf("UPF admin mock received %d request(s): %v", len(w.upfReqs), w.upfReqs)
	}
	return nil
}

func (w *n4World) smfNoRequest() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.smfReqs) != 0 {
		return fmt.Errorf("SMF mock received %d request(s): %v", len(w.smfReqs), w.smfReqs)
	}
	return nil
}

func (w *n4World) dataCode(code string) error {
	if got, _ := w.data["code"].(string); got != code {
		return fmt.Errorf("error data code: got %v, want %s (data %v)", w.data["code"], code, w.data)
	}
	return nil
}

func (w *n4World) dataNumber(key string, want float64) error {
	if got, ok := w.data[key].(float64); !ok || got != want {
		return fmt.Errorf("error data %s: got %v, want %v (data %v)", key, w.data[key], want, w.data)
	}
	return nil
}

func (w *n4World) dataSEIDs(list string) error {
	var want, got any
	if err := json.Unmarshal([]byte(list), &want); err != nil {
		return err
	}
	b, _ := json.Marshal(w.data["seids"])
	_ = json.Unmarshal(b, &got)
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("error data seids: got %s, want %s", b, list)
	}
	return nil
}

func (w *n4World) dataUpstream(up string) error {
	if got, _ := w.data["upstream"].(string); got != up {
		return fmt.Errorf("error data upstream: got %v, want %s (data %v)", w.data["upstream"], up, w.data)
	}
	return nil
}

func (w *n4World) dataSMFSEID(seid float64) error {
	smf, _ := w.data["smf"].(map[string]any)
	sess, _ := smf["session"].(map[string]any)
	if got, _ := sess["seid"].(float64); got != seid {
		return fmt.Errorf("error data smf view seid: got %v, want %v (data %v)", sess["seid"], seid, w.data)
	}
	return nil
}

func (w *n4World) dataUPFCPSEID(seid float64) error {
	upf, _ := w.data["upf"].(map[string]any)
	if got, _ := upf["cp_seid"].(float64); got != seid {
		return fmt.Errorf("error data upf view cp_seid: got %v, want %v (data %v)", upf["cp_seid"], seid, w.data)
	}
	return nil
}

func (w *n4World) dataSMFNull() error {
	v, ok := w.data["smf"]
	if !ok || v != nil {
		return fmt.Errorf("error data smf must be present and null, got %v (present=%v)", v, ok)
	}
	return nil
}

func (w *n4World) toolListContains(name string) error {
	names, _ := w.content["tools"].([]any)
	for _, n := range names {
		if n == name {
			return nil
		}
	}
	return fmt.Errorf("tool list %v lacks %q", names, name)
}

func (w *n4World) toolRisk(name, risk string) error {
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

func (w *n4World) notDryRun() error {
	if w.content == nil {
		return fmt.Errorf("no call was made")
	}
	if w.content["dry_run"] == true {
		return fmt.Errorf("call was a dry run: %v", w.content)
	}
	return nil
}

func (w *n4World) noAuditEntry(tool string) error {
	if err := w.ensureServer(); err != nil {
		return err
	}
	for _, e := range w.guard.Audit().Recent(0) {
		if e.Tool == tool {
			return fmt.Errorf("unexpected audit entry for %s: %+v", tool, e)
		}
	}
	return nil
}

// ---- live E2E (manual) ------------------------------------------------------

func n4Pending() error { return godog.ErrPending }

// ---- wiring -----------------------------------------------------------------

func initializeN4Scenario(sc *godog.ScenarioContext) {
	w := &n4World{}
	sc.Before(func(ctx context.Context, s *godog.Scenario) (context.Context, error) {
		for _, t := range s.Tags {
			if t.Name == "@e2e" && os.Getenv("E2E_TEST") != "1" {
				return ctx, godog.ErrSkip
			}
		}
		w.reset()
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		w.close()
		return ctx, nil
	})

	sc.Step(`^the MCP n4 inspection tool runs against mocked SMF, Prometheus and UPF admin upstreams$`, w.runsAgainstMocks)
	sc.Step(`^the MCP guard runs with access_mode "([^"]+)"$`, w.guardMode)
	sc.Step(`^the Prometheus mock resolves nf "([^"]+)" to the UPF admin mock$`, w.promResolves)
	sc.Step(`^the Prometheus mock has no target for nf "([^"]+)"$`, w.promNoTarget)
	sc.Step(`^the SMF mock holds session PDU session id (\d+) for "([^"]+)" with seid (\d+), upfTeid (\d+), ueIp "([^"]+)" and pfcpQers (\[.*\])$`, w.smfHolds)
	sc.Step(`^the SMF mock holds no session with seid (\d+)$`, w.smfHoldsNoSEID)
	sc.Step(`^the SMF mock answers (\d+) for GET "([^"]+)"$`, w.smfAnswers)
	sc.Step(`^the SMF mock answers (\d+) with cause "([^"]+)" for GET "([^"]+)"$`, w.smfAnswersCause)
	sc.Step(`^the UPF admin mock holds a session with cp_seid (\d+), up_seid (\d+), ul_teid (\d+), ue_ipv4 "([^"]+)" and qers (\[.*\])$`, w.upfHolds)
	sc.Step(`^the UPF admin mock also holds a session with cp_seid (\d+), up_seid (\d+) and ue_ipv4 "([^"]+)"$`, w.upfAlsoHolds)
	sc.Step(`^the UPF admin mock holds no sessions$`, w.upfHoldsNone)
	sc.Step(`^the UPF admin mock is shut down$`, w.upfShutDown)

	sc.Step(`^I call "([^"]+)" with arguments (\{.*\})$`, w.call)
	sc.Step(`^I list the tools$`, w.listTools)

	sc.Step(`^the call succeeds$`, w.succeeds)
	sc.Step(`^the call is refused with code (-?\d+)$`, w.refused)
	sc.Step(`^the result contains the keys "([^"]+)", "([^"]+)", "([^"]+)"$`, w.hasKeys)
	sc.Step(`^the result upf has exactly (\d+) qers$`, w.upfQERs)
	sc.Step(`^the result smf_mismatches is an empty array$`, w.mismatchesEmpty)
	sc.Step(`^the result smf_mismatches has exactly (\d+) entry$`, w.mismatchesCount)
	sc.Step(`^the smf_mismatches entry (\d+) has field "([^"]+)", smf (.+) and upf (.+)$`, w.entryHas)
	sc.Step(`^the smf_mismatches contain field "([^"]+)" with smf (.+) and upf (.+)$`, w.mismatchesContain)
	sc.Step(`^the SMF mock received exactly (\d+) GET to "([^"]+)"$`, w.smfExactlyGET)
	sc.Step(`^the UPF admin mock received exactly (\d+) GET to "([^"]+)" with query (seid|ue_ip) "([^"]+)"$`, w.upfExactlyGETQuery)
	sc.Step(`^the UPF admin mock received no request other than GET$`, w.upfOnlyGET)
	sc.Step(`^the UPF admin mock received no request$`, w.upfNoRequest)
	sc.Step(`^the SMF mock received no request$`, w.smfNoRequest)
	sc.Step(`^the error data code is "([^"]+)"$`, w.dataCode)
	sc.Step(`^the error data (pdu_session_id|seid) is (\d+)$`, func(k, v string) error {
		f, _ := strconv.ParseFloat(v, 64)
		return w.dataNumber(k, f)
	})
	sc.Step(`^the error data seids are (\[[0-9,]*\])$`, w.dataSEIDs)
	sc.Step(`^the error data upstream is "([^"]+)"$`, w.dataUpstream)
	sc.Step(`^the error data carries the SMF view with seid (\d+)$`, func(v string) error {
		f, _ := strconv.ParseFloat(v, 64)
		return w.dataSMFSEID(f)
	})
	sc.Step(`^the error data carries the UPF view with cp_seid (\d+)$`, func(v string) error {
		f, _ := strconv.ParseFloat(v, 64)
		return w.dataUPFCPSEID(f)
	})
	sc.Step(`^the error data smf is null$`, w.dataSMFNull)
	sc.Step(`^the tool list contains "([^"]+)"$`, w.toolListContains)
	sc.Step(`^the tool "([^"]+)" has risk "([^"]+)"$`, w.toolRisk)
	sc.Step(`^the call is not a dry run$`, w.notDryRun)
	sc.Step(`^the audit log has no entry for "([^"]+)"$`, w.noAuditEntry)

	// Live E2E scenario (@e2e @manual): gated by E2E_TEST=1 in Before; without a
	// live stack wired to the in-process suite these steps stay pending.
	sc.Step(`^the live stack is up with UE "([^"]+)" holding PDU session (\d+)$`, n4Pending)
	sc.Step(`^I record the current Session-AMBR of the slice of the UE$`, n4Pending)
	sc.Step(`^I call "slice_session_ambr_set" for that slice and DNN with downlink "([^"]+)", apply_to_active true and confirm true$`, n4Pending)
	sc.Step(`^I call "slice_session_ambr_set" with the recorded Session-AMBR, apply_to_active true and confirm true$`, n4Pending)
	sc.Step(`^the UPF qer (\d+) mbr_dl_kbps is (\d+)$`, n4Pending)
	sc.Step(`^the UPF qer (\d+) mbr_dl_kbps equals the recorded value$`, n4Pending)
	sc.Step(`^the procedure_summary shows zero failures for the run$`, n4Pending)
}

// TestN4InspectionFeatures runs only the @mcp012 feature file.
func TestN4InspectionFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: initializeN4Scenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"n4_inspection_tools.feature"},
			Tags:     "@mcp012",
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("non-zero exit status from the @mcp012 godog suite")
	}
}
