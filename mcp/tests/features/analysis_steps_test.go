//go:build functional

package features

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/status"
)

// lokiLine is one mocked Loki entry: a nanosecond timestamp and the JSON record.
type lokiLine struct {
	ts   int64
	line string
}

// analysisCtx holds the mocked upstreams and state of one analysis scenario.
// Every scenario builds fresh mocks, so scenarios are order independent.
type analysisCtx struct {
	c *mcpCtx
	g *guardCtx

	mu          sync.Mutex
	servers     []*httptest.Server
	amfUEs      map[string]map[string]string // supi -> AMF snapshot fields
	smfSessions []map[string]any
	lokiLines   []lokiLine
	lokiDir     string // direction query parameter of the last Loki request
	promRows    []map[string]any
	healthBody  string
	subscribers []map[string]any
	targetSUPI  string
	wave2       *wave2Ctx // set for the @mcp009 scenarios
	ctl         *ctlCtx   // set by registerControlSteps; shares the mock registry with @mcp011
}

func (a *analysisCtx) reset() {
	a.close()
	a.amfUEs = map[string]map[string]string{}
	a.smfSessions = nil
	a.lokiLines = nil
	a.lokiDir = ""
	a.promRows = nil
	a.healthBody = ""
	a.subscribers = nil
	a.targetSUPI = ""
}

func (a *analysisCtx) close() {
	for _, s := range a.servers {
		s.Close()
	}
	a.servers = nil
}

func (a *analysisCtx) mock(h http.Handler) string {
	s := httptest.NewServer(h)
	a.servers = append(a.servers, s)
	return s.URL
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// startMocks builds the AMF, SMF, PCF, UDM, Loki, Prometheus and portal mocks,
// the real tools against them, and a fresh MCP server that replaces the scenario one.
func (a *analysisCtx) startMocks() error {
	a.reset()

	amf := a.mock(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		supi := strings.TrimPrefix(r.URL.Path, "/amf/v1/ue-contexts/")
		a.mu.Lock()
		snap, ok := a.amfUEs[supi]
		a.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, snap)
	}))
	smf := a.mock(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nsmf-management/v1/sessions" {
			http.NotFound(w, r)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		out := a.smfSessions
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(w, out)
	}))
	notFound := a.mock(http.NotFoundHandler()) // PCF (no override) and UDM (no SM data)
	loki := a.mock(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.lokiDir = r.URL.Query().Get("direction")
		lines := append([]lokiLine(nil), a.lokiLines...)
		dir := a.lokiDir
		a.mu.Unlock()
		sort.SliceStable(lines, func(i, j int) bool {
			if dir == "backward" {
				return lines[i].ts > lines[j].ts
			}
			return lines[i].ts < lines[j].ts
		})
		if lim, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && len(lines) > lim {
			lines = lines[:lim]
		}
		values := make([][2]string, 0, len(lines))
		for _, l := range lines {
			values = append(values, [2]string{strconv.FormatInt(l.ts, 10), l.line})
		}
		writeJSON(w, map[string]any{"status": "success", "data": map[string]any{
			"resultType": "streams",
			"result":     []map[string]any{{"stream": map[string]string{"nf": "AMF"}, "values": values}},
		}})
	}))
	prom := a.mock(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		rows := a.promRows
		a.mu.Unlock()
		res := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			res = append(res, map[string]any{"metric": row["metric"], "value": []any{1, row["value"]}})
		}
		writeJSON(w, map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": res}})
	}))
	portal := a.mock(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/health":
			_, _ = io.WriteString(w, a.healthBody)
		case "/api/v1/subscribers":
			// A portal without its store answers 200 [] here (the bug being guarded).
			subs := a.subscribers
			if subs == nil || strings.Contains(a.healthBody, `"store":"down"`) {
				subs = []map[string]any{}
			}
			writeJSON(w, subs)
		default:
			http.NotFound(w, r)
		}
	}))

	hc := http.DefaultClient
	reg := registry.New()
	if err := reg.RegisterAll(analysis.All(analysis.Deps{
		Loki:   clients.NewLoki(loki, hc),
		AMF:    clients.NewAMF(amf, hc),
		SMF:    clients.NewSMF(smf, hc),
		PCF:    clients.NewPCF(notFound, hc),
		UDM:    clients.NewUDM(notFound, hc),
		Prom:   promclient.New(prom, hc, 0),
		Portal: clients.NewPortal(portal, hc),
	})...); err != nil {
		return err
	}
	if err := reg.RegisterAll(status.All(status.Deps{Portal: clients.NewPortal(portal, hc)})...); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	disp := server.NewDispatcher(reg, guard.New(guard.Options{Mode: guard.ModeLab}, logger), logger)
	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true}}
	sse := transport.NewSSE(disp, reg, session.NewManager(logger), cfg, logger)
	if a.c.srv != nil {
		a.c.srv.Close()
	}
	a.c.srv = httptest.NewServer(sse.Handler())
	return nil
}

func (a *analysisCtx) amfKnowsUE(supi, gmm string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.targetSUPI = supi
	a.amfUEs[supi] = map[string]string{"gmm_state": gmm, "cm_state": "CM-CONNECTED", "guti": "5g-guti-001010cafe00000001"}
	return nil
}

func (a *analysisCtx) amfReportsCM(cm string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	snap, ok := a.amfUEs[a.targetSUPI]
	if !ok {
		return fmt.Errorf("AMF mock has no UE %q", a.targetSUPI)
	}
	snap["cm_state"] = cm
	return nil
}

func (a *analysisCtx) amfAnswers404(supi string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.amfUEs, supi)
	return nil
}

func (a *analysisCtx) smfReportsSessions(n int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := 1; i <= n; i++ {
		a.smfSessions = append(a.smfSessions, map[string]any{"supi": a.targetSUPI, "pdu_session_id": i, "dnn": "internet"})
	}
	return nil
}

func errRecord(nf, proc, result, msg string) string {
	b, _ := json.Marshal(map[string]string{"nf": nf, "procedure": proc, "result": result, "msg": msg,
		"spec_ref": "TS 24.501 §5.5.1.2.5"})
	return string(b)
}

func (a *analysisCtx) lokiNewestFirst(newest, oldest string) error {
	now := time.Now().UnixNano()
	a.mu.Lock()
	defer a.mu.Unlock()
	// Appended newest first, like a backward Loki reply; the mock re-sorts by direction.
	a.lokiLines = append(a.lokiLines,
		lokiLine{ts: now - int64(time.Second), line: errRecord("AMF", "InitialRegistration", "REJECT", newest)},
		lokiLine{ts: now - int64(10*time.Second), line: errRecord("AMF", "InitialRegistration", "REJECT", oldest)})
	return nil
}

func (a *analysisCtx) lokiQueriedWith(dir string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lokiDir != dir {
		return fmt.Errorf("Loki direction: got %q, want %q", a.lokiDir, dir)
	}
	return nil
}

func (a *analysisCtx) lokiIdentical(n int, nf, proc, result, msg string) error {
	now := time.Now().UnixNano()
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := 0; i < n; i++ {
		a.lokiLines = append(a.lokiLines, lokiLine{ts: now - int64(i+1)*int64(time.Second), line: errRecord(nf, proc, result, msg)})
	}
	return nil
}

func (a *analysisCtx) lokiDistinct(kinds int) error {
	now := time.Now().UnixNano()
	a.mu.Lock()
	defer a.mu.Unlock()
	k := int64(0)
	for kind := 1; kind <= kinds; kind++ {
		for i := 0; i < kinds+1-kind; i++ { // kind 1 has 12 lines, kind 12 has 1
			k++
			a.lokiLines = append(a.lokiLines, lokiLine{ts: now - k*int64(time.Millisecond),
				line: errRecord("AMF", "InitialRegistration", "REJECT", fmt.Sprintf("kind-%02d", kind))})
		}
	}
	return nil
}

func (a *analysisCtx) result() map[string]any { return a.c.content }

func (a *analysisCtx) findings() ([]map[string]any, error) {
	v, present := a.result()["findings"]
	raw, ok := v.([]any)
	if !present || (!ok && v != nil) { // a null findings value means no findings
		return nil, fmt.Errorf("result has no findings array: %v", a.result())
	}
	out := make([]map[string]any, 0, len(raw))
	for _, f := range raw {
		m, _ := f.(map[string]any)
		out = append(out, m)
	}
	return out, nil
}

func (a *analysisCtx) findingsContain(sub, spec string) error {
	fs, err := a.findings()
	if err != nil {
		return err
	}
	for _, f := range fs {
		msg, _ := f["message"].(string)
		if strings.Contains(msg, sub) && f["spec_ref"] == spec {
			return nil
		}
	}
	return fmt.Errorf("no finding mentioning %q with spec_ref %q in %v", sub, spec, fs)
}

func (a *analysisCtx) findingsContainNo(sub string) error {
	fs, err := a.findings()
	if err != nil {
		return err
	}
	for _, f := range fs {
		if msg, _ := f["message"].(string); strings.Contains(msg, sub) {
			return fmt.Errorf("unexpected finding mentioning %q: %v", sub, f)
		}
	}
	return nil
}

func (a *analysisCtx) latestErrorRefersTo(msg string) error {
	fs, err := a.findings()
	if err != nil {
		return err
	}
	for _, f := range fs {
		m, _ := f["message"].(string)
		if i := strings.Index(m, "latest "); i >= 0 {
			if strings.HasSuffix(m, ": "+msg) {
				return nil
			}
			return fmt.Errorf("latest-error finding %q does not refer to msg %q", m, msg)
		}
	}
	return fmt.Errorf("no latest-error finding in %v", fs)
}

func (a *analysisCtx) recentErrors() ([]map[string]any, error) {
	raw, ok := a.result()["recent_errors"].([]any)
	if !ok {
		return nil, fmt.Errorf("result has no recent_errors array: %v", a.result())
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, _ := r.(map[string]any)
		out = append(out, m)
	}
	return out, nil
}

func (a *analysisCtx) recentErrorsExactly(n int) error {
	rows, err := a.recentErrors()
	if err != nil {
		return err
	}
	if len(rows) != n {
		return fmt.Errorf("recent_errors rows: got %d, want %d: %v", len(rows), n, rows)
	}
	return nil
}

func (a *analysisCtx) recentErrorsAtMost(n int) error {
	rows, err := a.recentErrors()
	if err != nil {
		return err
	}
	if len(rows) == 0 || len(rows) > n {
		return fmt.Errorf("recent_errors rows: got %d, want 1..%d", len(rows), n)
	}
	return nil
}

func (a *analysisCtx) recentErrorsRowHas(row, count int) error {
	rows, err := a.recentErrors()
	if err != nil {
		return err
	}
	if row < 1 || row > len(rows) {
		return fmt.Errorf("no recent_errors row %d (have %d)", row, len(rows))
	}
	r := rows[row-1]
	if got, _ := r["count"].(float64); int(got) != count {
		return fmt.Errorf("row %d count: got %v, want %d", row, r["count"], count)
	}
	for _, k := range []string{"first", "last"} {
		if s, _ := r[k].(string); s == "" || strings.HasPrefix(s, "0001-01-01") {
			return fmt.Errorf("row %d %s timestamp empty: %v", row, k, r[k])
		}
	}
	return nil
}

func (a *analysisCtx) recentErrorsDescending() error {
	rows, err := a.recentErrors()
	if err != nil {
		return err
	}
	prev := -1.0
	for i, r := range rows {
		cnt, _ := r["count"].(float64)
		if i > 0 && cnt > prev {
			return fmt.Errorf("row %d count %v exceeds previous %v", i+1, cnt, prev)
		}
		prev = cnt
	}
	return nil
}

func (a *analysisCtx) noPanic() error {
	if a.wave2 != nil && a.wave2.active {
		return a.wave2.noPanic()
	}
	if a.c.isError {
		return fmt.Errorf("tool failed instead of returning findings: %v", a.result())
	}
	if _, ok := a.result()["findings"]; !ok {
		return fmt.Errorf("tool returned no findings, it may have aborted: %v", a.result())
	}
	return nil
}

func (a *analysisCtx) promReturns(okProc string, okCount int, zeroProc string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	row := func(proc, result, v string) map[string]any {
		return map[string]any{"metric": map[string]string{"nf": "AMF", "procedure": proc, "result": result}, "value": v}
	}
	a.promRows = []map[string]any{
		row(okProc, "OK", strconv.Itoa(okCount)), row(okProc, "REJECT", "0"), row(okProc, "FAILURE", "0"),
		row(zeroProc, "OK", "0"), row(zeroProc, "REJECT", "0"), row(zeroProc, "FAILURE", "0"),
	}
	return nil
}

func (a *analysisCtx) statsProcedures() ([]string, error) {
	rows, ok := a.result()["rows"].([]any)
	if !ok {
		return nil, fmt.Errorf("result has no rows array: %v", a.result())
	}
	var names []string
	for _, r := range rows {
		m, _ := r.(map[string]any)
		p, _ := m["procedure"].(string)
		names = append(names, p)
	}
	return names, nil
}

func (a *analysisCtx) statsRowsContain(proc string) error {
	names, err := a.statsProcedures()
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == proc {
			return nil
		}
	}
	return fmt.Errorf("procedure_stats rows %v lack %q", names, proc)
}

func (a *analysisCtx) statsRowsDoNotContain(proc string) error {
	names, err := a.statsProcedures()
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == proc {
			return fmt.Errorf("procedure_stats rows %v must not contain %q", names, proc)
		}
	}
	return nil
}

func (a *analysisCtx) portalHealth(body string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.healthBody = body
	return nil
}

func (a *analysisCtx) portalHolds(s1, s2 string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range []string{s1, s2} {
		// The mock carries key material so the test proves the portal client redacts it.
		a.subscribers = append(a.subscribers, map[string]any{"supi": s, "k": "465B5CE8B199B49FAA5F0A2EE238A6BC",
			"opc": "E8ED289DEBA952E4283B54E88E6183CA", "sqn": "000000000020", "amf": "8000"})
	}
	return nil
}

func (a *analysisCtx) notEmptySubscriberList() error {
	var list []any
	if err := json.Unmarshal([]byte(a.g.rawText), &list); err == nil && len(list) == 0 {
		return fmt.Errorf("result is an empty subscriber list: %s", a.g.rawText)
	}
	if !a.c.isError {
		return fmt.Errorf("call must be refused, got result %s", a.g.rawText)
	}
	return nil
}

func (a *analysisCtx) subscriberListContains(supi string) error {
	var list []map[string]any
	if err := json.Unmarshal([]byte(a.g.rawText), &list); err != nil {
		return fmt.Errorf("subscriber list is not an array: %s", a.g.rawText)
	}
	for _, s := range list {
		if s["supi"] == supi {
			return nil
		}
	}
	return fmt.Errorf("subscriber list lacks %q: %s", supi, a.g.rawText)
}

func (a *analysisCtx) noKeyMaterial() error {
	// The result is a subscriber array (subscriber_list) or an object (subscriber_get).
	var doc any
	if err := json.Unmarshal([]byte(a.g.rawText), &doc); err != nil {
		return fmt.Errorf("subscriber result is not JSON: %s", a.g.rawText)
	}
	if err := checkRedacted(doc); err != nil {
		return err
	}
	for _, secret := range []string{"465B5CE8B199B49FAA5F0A2EE238A6BC", "E8ED289DEBA952E4283B54E88E6183CA", "000000000020"} {
		if strings.Contains(a.g.rawText, secret) {
			return fmt.Errorf("result contains key material %s", secret)
		}
	}
	return nil
}

// checkRedacted walks a decoded JSON document and fails on any k, opc, op or sqn
// value that is not "<redacted>".
func checkRedacted(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			switch k {
			case "k", "opc", "op", "sqn":
				if val != "<redacted>" {
					return fmt.Errorf("subscriber %v leaks %s=%v", t["supi"], k, val)
				}
			default:
				if err := checkRedacted(val); err != nil {
					return err
				}
			}
		}
	case []any:
		for _, e := range t {
			if err := checkRedacted(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// registerAnalysisSteps wires the analysis_tools.feature steps. The phrases
// `I call ... with arguments`, `the call succeeds` and `the call is refused ...`
// are registered once by the shared guardrail/base steps and reused here.
func registerAnalysisSteps(sc *godog.ScenarioContext, c *mcpCtx, g *guardCtx) *analysisCtx {
	a := &analysisCtx{c: c, g: g}
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		a.close()
		return ctx, nil
	})
	sc.Step(`^the MCP analysis tools run against mocked AMF, SMF, Loki, Prometheus and portal upstreams$`, a.startMocks)
	sc.Step(`^the AMF mock knows UE "([^"]+)" in 5GMM state "([^"]+)"$`, a.amfKnowsUE)
	sc.Step(`^the AMF mock reports cm_state "([^"]+)" for the UE$`, a.amfReportsCM)
	sc.Step(`^the AMF mock answers 404 for UE "([^"]+)"$`, a.amfAnswers404)
	sc.Step(`^the SMF mock reports (\d+) active PDU sessions? for the UE$`, a.smfReportsSessions)
	sc.Step(`^the findings contain a message mentioning "([^"]+)" with spec_ref "([^"]+)"$`, a.findingsContain)
	sc.Step(`^the findings contain no message mentioning "([^"]+)"$`, a.findingsContainNo)
	sc.Step(`^the Loki mock returns error lines newest first with msg "([^"]+)" newest and msg "([^"]+)" oldest$`, a.lokiNewestFirst)
	sc.Step(`^the Loki mock was queried with direction "([^"]+)"$`, a.lokiQueriedWith)
	sc.Step(`^the latest-error finding refers to msg "([^"]+)"$`, a.latestErrorRefersTo)
	sc.Step(`^the Loki mock returns (\d+) identical error lines for nf "([^"]+)", procedure "([^"]+)", result "([^"]+)", msg "([^"]+)"$`, a.lokiIdentical)
	sc.Step(`^the Loki mock returns (\d+) distinct error kinds with decreasing counts$`, a.lokiDistinct)
	sc.Step(`^recent_errors has exactly (\d+) rows?$`, a.recentErrorsExactly)
	sc.Step(`^recent_errors has at most (\d+) rows$`, a.recentErrorsAtMost)
	sc.Step(`^the recent_errors row (\d+) has count (\d+) and non-empty first and last timestamps$`, a.recentErrorsRowHas)
	sc.Step(`^recent_errors rows are ordered by descending count$`, a.recentErrorsDescending)
	sc.Step(`^no panic occurred in the tool$`, a.noPanic)
	sc.Step(`^the Prometheus mock returns procedure "([^"]+)" with OK (\d+) and procedure "([^"]+)" with all counts 0$`, a.promReturns)
	sc.Step(`^the procedure_stats rows contain "([^"]+)"$`, a.statsRowsContain)
	sc.Step(`^the procedure_stats rows do not contain "([^"]+)"$`, a.statsRowsDoNotContain)
	sc.Step(`^the portal mock health returns (\{.*\})$`, a.portalHealth)
	sc.Step(`^the portal mock holds subscribers "([^"]+)" and "([^"]+)"$`, a.portalHolds)
	sc.Step(`^the result is not an empty subscriber list$`, a.notEmptySubscriberList)
	sc.Step(`^the subscriber list contains "([^"]+)"$`, a.subscriberListContains)
	sc.Step(`^the subscriber list contains no key material$`, a.noKeyMaterial)
	return a
}
