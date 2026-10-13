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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/server/transport"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/analysis"
	metricstools "github.com/francurieses/claudia-5gc/mcp/internal/tools/metrics"
	qostools "github.com/francurieses/claudia-5gc/mcp/internal/tools/qos"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/status"
)

// wave2Tag marks the MCP-009 scenarios; only they get the wave-2 mocks.
const wave2Tag = "@mcp009"

// w2PromRow is one mocked Prometheus sample, returned for every query whose
// text contains metric (a misbehaving upstream: it ignores the nf filter).
type w2PromRow struct {
	metric string
	labels map[string]string
	value  string
}

// w2LokiGroup is one mocked Loki instant-vector sample.
type w2LokiGroup struct {
	labels map[string]string
	count  int
}

type w2UDMRoute struct {
	status int
	body   any
}

// wave2Ctx holds the mocked upstreams and per-scenario state of the MCP-009
// scenarios. Mock servers are created before every @mcp009 scenario; the MCP
// server over them is built right before the first tool call, so Given steps
// (access mode, a shut-down upstream) apply to it.
type wave2Ctx struct {
	c *mcpCtx
	g *guardCtx

	active bool
	built  bool
	mode   string

	mu          sync.Mutex
	srvAMF      *httptest.Server
	srvSMF      *httptest.Server
	srvBSF      *httptest.Server
	srvUDM      *httptest.Server
	srvLoki     *httptest.Server
	srvProm     *httptest.Server
	srvPortal   *httptest.Server
	srvPCF      *httptest.Server
	amfUEs      []map[string]any
	amfGNBs     []map[string]any
	smfSessions []map[string]any
	promRows    []w2PromRow
	promQueries []string
	lokiGroups  []w2LokiGroup
	lokiQuery   *url.Values // last instant query, nil when none arrived
	lokiPath    string
	portalItems []map[string]any
	bsfBindings []map[string]any
	bsfAll404   bool
	bsfQueries  []url.Values
	udmRoutes   map[string]w2UDMRoute
	udmRequests int

	lastFinding map[string]any
}

func (w *wave2Ctx) all() []*httptest.Server {
	return []*httptest.Server{w.srvAMF, w.srvSMF, w.srvBSF, w.srvUDM, w.srvLoki, w.srvProm, w.srvPortal, w.srvPCF}
}

func (w *wave2Ctx) close() {
	for _, s := range w.all() {
		if s != nil {
			s.Close()
		}
	}
	w.srvAMF, w.srvSMF, w.srvBSF, w.srvUDM = nil, nil, nil, nil
	w.srvLoki, w.srvProm, w.srvPortal, w.srvPCF = nil, nil, nil, nil
}

func (w *wave2Ctx) reset() {
	w.close()
	w.built = false
	w.mode = "lab"
	w.amfUEs, w.amfGNBs, w.smfSessions = nil, nil, nil
	w.promRows, w.promQueries, w.lokiGroups = nil, nil, nil
	w.lokiQuery, w.lokiPath = nil, ""
	w.portalItems, w.bsfBindings, w.bsfQueries = nil, nil, nil
	w.bsfAll404 = false
	w.udmRoutes = map[string]w2UDMRoute{}
	w.udmRequests = 0
	w.lastFinding = nil
}

func (w *wave2Ctx) newMocks() {
	w.srvAMF = httptest.NewServer(http.HandlerFunc(w.amfHandler))
	w.srvSMF = httptest.NewServer(http.HandlerFunc(w.smfHandler))
	w.srvBSF = httptest.NewServer(http.HandlerFunc(w.bsfHandler))
	w.srvUDM = httptest.NewServer(http.HandlerFunc(w.udmHandler))
	w.srvLoki = httptest.NewServer(http.HandlerFunc(w.lokiHandler))
	w.srvProm = httptest.NewServer(http.HandlerFunc(w.promHandler))
	w.srvPortal = httptest.NewServer(http.HandlerFunc(w.portalHandler))
	w.srvPCF = httptest.NewServer(http.NotFoundHandler())
}

// ---- mock handlers ----------------------------------------------------------

func (w *wave2Ctx) amfHandler(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch r.URL.Path {
	case "/amf/v1/ue-contexts":
		out := w.amfUEs
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(rw, out)
	case "/amf/v1/ran/gnbs":
		out := w.amfGNBs
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(rw, map[string]any{"gnbs": out})
	default:
		http.NotFound(rw, r)
	}
}

func (w *wave2Ctx) smfHandler(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/nsmf-management/v1/sessions" {
		http.NotFound(rw, r)
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.smfSessions
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(rw, map[string]any{"count": len(out), "sessions": out})
}

func (w *wave2Ctx) bsfHandler(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/nbsf-management/v1/pcfBindings" {
		http.NotFound(rw, r)
		return
	}
	q := r.URL.Query()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bsfQueries = append(w.bsfQueries, q)
	if !w.bsfAll404 {
		for _, b := range w.bsfBindings {
			if (q.Get("supi") != "" && b["supi"] == q.Get("supi")) ||
				(q.Get("ipv4Addr") != "" && b["ipv4Addr"] == q.Get("ipv4Addr")) {
				writeJSON(rw, b)
				return
			}
		}
	}
	http.NotFound(rw, r)
}

func (w *wave2Ctx) udmHandler(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !strings.HasPrefix(r.URL.Path, "/nudm-sdm/") {
		http.NotFound(rw, r)
		return
	}
	w.udmRequests++
	route, ok := w.udmRoutes[r.URL.Path]
	if !ok {
		http.NotFound(rw, r)
		return
	}
	if route.status != http.StatusOK {
		http.Error(rw, "not found", route.status)
		return
	}
	writeJSON(rw, route.body)
}

func (w *wave2Ctx) lokiHandler(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch r.URL.Path {
	case "/loki/api/v1/query":
		q := r.URL.Query()
		w.lokiQuery, w.lokiPath = &q, r.URL.Path
		res := make([]map[string]any, 0, len(w.lokiGroups))
		for _, g := range w.lokiGroups {
			res = append(res, map[string]any{"metric": g.labels, "value": []any{1, strconv.Itoa(g.count)}})
		}
		writeJSON(rw, map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": res}})
	case "/loki/api/v1/query_range":
		ts := strconv.FormatInt(time.Now().UnixNano(), 10)
		writeJSON(rw, map[string]any{"status": "success", "data": map[string]any{
			"resultType": "streams",
			"result": []map[string]any{{"stream": map[string]string{"nf": "AMF"},
				"values": [][2]string{{ts, `{"correlation_id":"01HWAVE2EXAMPLE0000000000"}`}}}},
		}})
	default:
		http.NotFound(rw, r)
	}
}

func (w *wave2Ctx) promHandler(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/query" {
		rw.WriteHeader(http.StatusOK) // reachability probes of mcp_info
		return
	}
	q := r.URL.Query().Get("query")
	w.mu.Lock()
	w.promQueries = append(w.promQueries, q)
	res := []map[string]any{}
	for _, row := range w.promRows {
		if strings.Contains(q, row.metric) {
			res = append(res, map[string]any{"metric": row.labels, "value": []any{1, row.value}})
		}
	}
	w.mu.Unlock()
	writeJSON(rw, map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": res}})
}

func (w *wave2Ctx) portalHandler(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if r.URL.Path == "/api/v1/slices/qos" {
		items := w.portalItems
		if items == nil {
			items = []map[string]any{}
		}
		writeJSON(rw, map[string]any{"items": items})
		return
	}
	http.NotFound(rw, r)
}

// ---- lifecycle --------------------------------------------------------------

// build replaces the scenario's MCP server with one over the wave-2 mocks.
func (w *wave2Ctx) build() error {
	hc := http.DefaultClient
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mode, err := guard.ParseAccessMode(w.mode)
	if err != nil {
		return err
	}
	g := guard.New(guard.Options{Mode: mode}, logger)
	reg := registry.New()

	prom := promclient.New(w.srvProm.URL, hc, 0)
	amf := clients.NewAMF(w.srvAMF.URL, hc)
	smf := clients.NewSMF(w.srvSMF.URL, hc)
	udm := clients.NewUDM(w.srvUDM.URL, hc)
	pcf := clients.NewPCF(w.srvPCF.URL, hc)
	portal := clients.NewPortal(w.srvPortal.URL, hc)

	if err := reg.RegisterAll(metricstools.All(prom)...); err != nil {
		return err
	}
	if err := reg.RegisterAll(analysis.All(analysis.Deps{
		Loki: clients.NewLoki(w.srvLoki.URL, hc), Prom: prom, AMF: amf, SMF: smf, PCF: pcf, UDM: udm, Portal: portal,
	})...); err != nil {
		return err
	}
	if err := reg.RegisterAll(qostools.Sessions(smf, udm, pcf)...); err != nil {
		return err
	}
	if err := reg.RegisterAll(status.All(status.Deps{
		Portal: portal, Prom: prom, HTTP: hc, AMF: amf, SMF: smf, BSF: clients.NewBSF(w.srvBSF.URL, hc),
		Registry: reg, Guard: g, Version: "test", BuildCommit: "wave2",
		Upstreams: []status.Upstream{
			{Name: "amf", Addr: w.srvAMF.URL},
			{Name: "smf", Addr: w.srvSMF.URL},
			{Name: "udm", Addr: w.srvUDM.URL},
			{Name: "bsf", Addr: w.srvBSF.URL},
			{Name: "portal", Addr: w.srvPortal.URL},
			{Name: "prometheus", Addr: w.srvProm.URL},
			{Name: "loki", Addr: w.srvLoki.URL},
		},
	})...); err != nil {
		return err
	}

	disp := server.NewDispatcher(reg, g, logger)
	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true}}
	sse := transport.NewSSE(disp, reg, session.NewManager(logger), cfg, logger)
	if w.c.srv != nil {
		w.c.srv.Close()
	}
	w.c.srv = httptest.NewServer(sse.Handler())
	w.built = true
	return nil
}

// ---- helpers ----------------------------------------------------------------

var quotedRe = regexp.MustCompile(`"([^"]+)"`)

func quotedList(s string) []string {
	var out []string
	for _, m := range quotedRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// listArray decodes the last tool result as a JSON array.
func (w *wave2Ctx) listArray() ([]map[string]any, error) {
	var list []map[string]any
	if err := json.Unmarshal([]byte(w.g.rawText), &list); err != nil {
		return nil, fmt.Errorf("result is not a JSON array: %s", w.g.rawText)
	}
	return list, nil
}

func (w *wave2Ctx) hasKeys(m map[string]any, keys []string) error {
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing key %q in %v", k, m)
		}
	}
	return nil
}

func rawJSONArray(s string) ([]any, error) {
	var arr []any
	if err := json.Unmarshal([]byte(s), &arr); err != nil {
		return nil, fmt.Errorf("%q is not a JSON array: %w", s, err)
	}
	return arr, nil
}

// ---- generic steps ----------------------------------------------------------

func (w *wave2Ctx) guardRunsWithMode(mode string) error {
	w.mode = mode
	return nil
}

func (w *wave2Ctx) refusedWithCode(code int) error {
	if !w.c.isError {
		return fmt.Errorf("expected a refusal, call succeeded: %s", w.g.rawText)
	}
	if int(w.g.lastCode) != code {
		return fmt.Errorf("code: got %v, want %d (%s)", w.g.lastCode, code, w.g.lastErr)
	}
	return nil
}

// noPanic accepts a structured tool error (code -32000 with a message): a
// panic would surface as an internal error (-32603) or no response at all.
func (w *wave2Ctx) noPanic() error {
	if !w.c.isError {
		return fmt.Errorf("expected a structured error, got a result: %s", w.g.rawText)
	}
	if int(w.g.lastCode) == mcperr.CodeInternal || w.g.lastErr == "" {
		return fmt.Errorf("error is not a structured tool error: code %v message %q", w.g.lastCode, w.g.lastErr)
	}
	return nil
}

func (w *wave2Ctx) resultFieldEquals(field string, want int) error {
	got, ok := w.c.content[field].(float64)
	if !ok || int(got) != want {
		return fmt.Errorf("result field %q: got %v, want %d", field, w.c.content[field], want)
	}
	return nil
}

func (w *wave2Ctx) resultContainsKeys(list string) error {
	return w.hasKeys(w.c.content, quotedList(list))
}

func (w *wave2Ctx) listedInToolsList(name string) error {
	if err := w.g.listTools(); err != nil {
		return err
	}
	return w.g.theToolListContains(name)
}

// ---- Prometheus -------------------------------------------------------------

func (w *wave2Ctx) addGauge(metric string, v int, nf string) {
	w.promRows = append(w.promRows, w2PromRow{metric: metric, labels: map[string]string{"nf": nf}, value: strconv.Itoa(v)})
}

func (w *wave2Ctx) promGauge(metric string, v int, nf string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addGauge(metric, v, nf)
	return nil
}

func (w *wave2Ctx) promGaugeTwo(metric string, v1 int, nf1 string, v2 int, nf2 string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addGauge(metric, v1, nf1)
	w.addGauge(metric, v2, nf2)
	return nil
}

func (w *wave2Ctx) promThroughput(dnn string, ul, dl int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for dir, v := range map[string]int{"uplink": ul, "downlink": dl} {
		w.promRows = append(w.promRows, w2PromRow{metric: "fivegc_upf_gtp_bytes_total",
			labels: map[string]string{"nf": "UPF", "dnn": dnn, "direction": dir}, value: strconv.Itoa(v)})
	}
	return nil
}

func (w *wave2Ctx) promSliceUEs(nf string, sst int, sd string, v int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.promRows = append(w.promRows, w2PromRow{metric: "fivegc_ue_registered_by_slice",
		labels: map[string]string{"nf": nf, "sst": strconv.Itoa(sst), "sd": sd}, value: strconv.Itoa(v)})
	return nil
}

func (w *wave2Ctx) promQueriedWithWindow(win string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.promQueries) == 0 {
		return fmt.Errorf("Prometheus mock received no query")
	}
	for _, q := range w.promQueries {
		if !strings.Contains(q, "["+win+"]") && strings.Contains(q, "rate(") {
			return fmt.Errorf("range query without window [%s]: %s", win, q)
		}
	}
	for _, q := range w.promQueries {
		if strings.Contains(q, "["+win+"]") {
			return nil
		}
	}
	return fmt.Errorf("no query carries range window [%s]: %v", win, w.promQueries)
}

func (w *wave2Ctx) promNoQuery() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.promQueries) != 0 {
		return fmt.Errorf("Prometheus mock received %d queries, want none: %v", len(w.promQueries), w.promQueries)
	}
	return nil
}

func (w *wave2Ctx) promAllFilterUPF() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.promQueries) == 0 {
		return fmt.Errorf("Prometheus mock received no query")
	}
	for _, q := range w.promQueries {
		if !strings.Contains(q, `nf="UPF"`) {
			return fmt.Errorf(`PromQL without nf="UPF": %s`, q)
		}
	}
	return nil
}

func (w *wave2Ctx) throughputFor(dnn string, ul, dl int) error {
	tp, ok := w.c.content["throughput_bps"].(map[string]any)
	if !ok {
		return fmt.Errorf("throughput_bps is not an object: %v", w.c.content["throughput_bps"])
	}
	row, ok := tp[dnn].(map[string]any)
	if !ok {
		return fmt.Errorf("throughput_bps has no dnn %q: %v", dnn, tp)
	}
	gotUL, _ := row["ul"].(float64)
	gotDL, _ := row["dl"].(float64)
	if int(gotUL) != ul || int(gotDL) != dl {
		return fmt.Errorf("throughput for %q: got ul %v dl %v, want ul %d dl %d", dnn, row["ul"], row["dl"], ul, dl)
	}
	return nil
}

// ---- AMF / SMF --------------------------------------------------------------

func (w *wave2Ctx) addUE(supi string, psis any) {
	w.amfUEs = append(w.amfUEs, map[string]any{"supi": supi, "gmm_state": "5GMM-REGISTERED", "pdu_session_ids": psis})
}

func (w *wave2Ctx) amfUEsB64(a, b, psis string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addUE(a, psis)
	w.addUE(b, psis)
	return nil
}

func (w *wave2Ctx) amfUEArray(supi, arr string) error {
	ids, err := rawJSONArray(arr)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addUE(supi, ids)
	return nil
}

func (w *wave2Ctx) addSession(supi string, psi int, extra map[string]any) {
	s := map[string]any{"supi": supi, "pduSessionId": psi, "dnn": "internet", "sessionState": "ACTIVE"}
	for k, v := range extra {
		s[k] = v
	}
	w.smfSessions = append(w.smfSessions, s)
}

func (w *wave2Ctx) smfSessionsTwo(a, b string, psi int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addSession(a, psi, nil)
	w.addSession(b, psi, nil)
	return nil
}

func (w *wave2Ctx) smfSessionsOne(a string, psi int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addSession(a, psi, nil)
	return nil
}

func (w *wave2Ctx) smfNoSessions() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.smfSessions = nil
	return nil
}

func (w *wave2Ctx) smfSliceSessions(n int, dnn string, sst int, sd string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := 1; i <= n; i++ {
		w.addSession(fmt.Sprintf("imsi-00101000000000%d", i), 1,
			map[string]any{"dnn": dnn, "sNssai": map[string]any{"sst": sst, "sd": sd}})
	}
	return nil
}

func (w *wave2Ctx) smfSessionsWithIPs(ip1, ip2 string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.addSession("imsi-001010000000001", 1, map[string]any{"ueIp": ip1})
	w.addSession("imsi-001010000000002", 1, map[string]any{"ueIp": ip2})
	return nil
}

func (w *wave2Ctx) amfGNBSupporting(sst int, sd string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.amfGNBs = append(w.amfGNBs, map[string]any{"state": "CONNECTED", "supported_tas": []any{
		map[string]any{"broadcast_plmns": []any{
			map[string]any{"slices": []any{map[string]any{"sst": sst, "sd": sd}}},
		}},
	}})
	return nil
}

func (w *wave2Ctx) portalSliceQoS(sst int, sd string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.portalItems = append(w.portalItems, map[string]any{
		"snssai": map[string]any{"sst": sst, "sd": sd}, "dnn": "internet",
		"sessionAmbr": map[string]any{"uplink": "1 Gbps", "downlink": "2 Gbps"},
	})
	return nil
}

func (w *wave2Ctx) amfShutDown() error {
	w.srvAMF.Close()
	return nil
}

// ---- core_consistency_check --------------------------------------------------

func (w *wave2Ctx) countsReport(spec string) error {
	counts, ok := w.c.content["counts"].(map[string]any)
	if !ok {
		return fmt.Errorf("result has no counts object: %v", w.c.content)
	}
	pairs := regexp.MustCompile(`([a-z_]+) (\d+)`).FindAllStringSubmatch(spec, -1)
	if len(pairs) == 0 {
		return fmt.Errorf("no count expectations in %q", spec)
	}
	for _, p := range pairs {
		want, _ := strconv.Atoi(p[2])
		got, ok := counts[p[1]].(float64)
		if !ok || int(got) != want {
			return fmt.Errorf("counts.%s: got %v, want %d", p[1], counts[p[1]], want)
		}
	}
	return nil
}

func (w *wave2Ctx) findingList() ([]map[string]any, error) {
	raw, ok := w.c.content["findings"].([]any)
	if !ok {
		return nil, fmt.Errorf("result has no findings array: %v", w.c.content)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, f := range raw {
		m, _ := f.(map[string]any)
		out = append(out, m)
	}
	return out, nil
}

func (w *wave2Ctx) noFindingWithSeverity(sev string) error {
	fs, err := w.findingList()
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f["severity"] == sev {
			return fmt.Errorf("unexpected %s finding: %v", sev, f)
		}
	}
	return nil
}

func (w *wave2Ctx) findingWithSeverityAndCheck(sev, check string) error {
	fs, err := w.findingList()
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f["severity"] == sev && f["check"] == check {
			w.lastFinding = f
			return nil
		}
	}
	return fmt.Errorf("no %s finding with check %q in %v", sev, check, fs)
}

func (w *wave2Ctx) findingWithCheck(check string) error {
	fs, err := w.findingList()
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f["check"] == check {
			w.lastFinding = f
			return nil
		}
	}
	return fmt.Errorf("no finding with check %q in %v", check, fs)
}

func (w *wave2Ctx) findingHasDetailAndSpecRef() error {
	if w.lastFinding == nil {
		return fmt.Errorf("no finding selected by a previous step")
	}
	for _, k := range []string{"detail", "spec_ref"} {
		if s, _ := w.lastFinding[k].(string); s == "" {
			return fmt.Errorf("finding %v has empty %s", w.lastFinding, k)
		}
	}
	return nil
}

// ---- error_summary -----------------------------------------------------------

func (w *wave2Ctx) lokiGroup(nf, proc, result, cause, spec string, count int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lokiGroups = append(w.lokiGroups, w2LokiGroup{count: count, labels: map[string]string{
		"nf": nf, "procedure": proc, "result": result, "cause": cause, "spec_ref": spec}})
	return nil
}

func (w *wave2Ctx) summaryRows() ([]map[string]any, error) {
	raw, ok := w.c.content["rows"].([]any)
	if !ok {
		return nil, fmt.Errorf("result has no rows array: %v", w.c.content)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, _ := r.(map[string]any)
		out = append(out, m)
	}
	return out, nil
}

func (w *wave2Ctx) summaryHasRows(n int) error {
	rows, err := w.summaryRows()
	if err != nil {
		return err
	}
	if len(rows) != n {
		return fmt.Errorf("error_summary rows: got %d, want %d: %v", len(rows), n, rows)
	}
	return nil
}

func (w *wave2Ctx) summaryRowIs(idx int, nf string, count int) error {
	rows, err := w.summaryRows()
	if err != nil {
		return err
	}
	if idx < 1 || idx > len(rows) {
		return fmt.Errorf("no error_summary row %d (have %d)", idx, len(rows))
	}
	r := rows[idx-1]
	if r["nf"] != nf {
		return fmt.Errorf("row %d nf: got %v, want %q", idx, r["nf"], nf)
	}
	if got, _ := r["count"].(float64); int(got) != count {
		return fmt.Errorf("row %d count: got %v, want %d", idx, r["count"], count)
	}
	return nil
}

func (w *wave2Ctx) summaryRowsHaveKeys(list string) error {
	rows, err := w.summaryRows()
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("error_summary has no rows")
	}
	for i, r := range rows {
		if err := w.hasKeys(r, quotedList(list)); err != nil {
			return fmt.Errorf("row %d: %w", i+1, err)
		}
	}
	return nil
}

func (w *wave2Ctx) lokiQueriedAt(path, fn, window string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lokiQuery == nil || w.lokiPath != path {
		return fmt.Errorf("Loki mock was not queried at %s (last %q)", path, w.lokiPath)
	}
	q := w.lokiQuery.Get("query")
	if !strings.Contains(q, fn) || !strings.Contains(q, "["+window+"]") {
		return fmt.Errorf("Loki query %q lacks %s over [%s]", q, fn, window)
	}
	return nil
}

// ---- mcp_info ----------------------------------------------------------------

func (w *wave2Ctx) toolCountMatchesList() error {
	tc, ok1 := w.c.content["tool_count"].(float64)
	ac, ok2 := w.c.content["alias_count"].(float64)
	if !ok1 || !ok2 {
		return fmt.Errorf("tool_count/alias_count missing or not numbers: %v", w.c.content)
	}
	if err := w.g.listTools(); err != nil {
		return err
	}
	if int(tc)+int(ac) != len(w.g.listed) {
		return fmt.Errorf("tool_count %v + alias_count %v != %d names in tools/list", tc, ac, len(w.g.listed))
	}
	return nil
}

func (w *wave2Ctx) upstream(name string) (map[string]any, error) {
	ups, ok := w.c.content["upstreams"].([]any)
	if !ok {
		return nil, fmt.Errorf("result has no upstreams array: %v", w.c.content)
	}
	for _, u := range ups {
		if m, _ := u.(map[string]any); m["name"] == name {
			return m, nil
		}
	}
	return nil, fmt.Errorf("upstream %q not reported: %v", name, ups)
}

func (w *wave2Ctx) upstreamUnreachable(name string) error {
	u, err := w.upstream(name)
	if err != nil {
		return err
	}
	if u["reachable"] != false {
		return fmt.Errorf("upstream %q reachable: got %v, want false", name, u["reachable"])
	}
	return nil
}

func (w *wave2Ctx) upstreamReachable(name string) error {
	u, err := w.upstream(name)
	if err != nil {
		return err
	}
	if u["reachable"] != true {
		return fmt.Errorf("upstream %q reachable: got %v, want true", name, u["reachable"])
	}
	if _, ok := u["latency_ms"].(float64); !ok {
		return fmt.Errorf("upstream %q has no latency_ms: %v", name, u)
	}
	return nil
}

// ---- slice_status ------------------------------------------------------------

func (w *wave2Ctx) sliceEntries(sst int, sd string) ([]map[string]any, error) {
	list, err := w.listArray()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, e := range list {
		sn, _ := e["snssai"].(map[string]any)
		if got, _ := sn["sst"].(float64); int(got) == sst && sn["sd"] == sd {
			out = append(out, e)
		}
	}
	return out, nil
}

func (w *wave2Ctx) sliceHasEntries(n, sst int, sd string) error {
	es, err := w.sliceEntries(sst, sd)
	if err != nil {
		return err
	}
	list, _ := w.listArray()
	if len(es) != n || len(list) != n {
		return fmt.Errorf("slice_status: %d matching entries of %d, want exactly %d: %s", len(es), len(list), n, w.g.rawText)
	}
	return nil
}

func (w *wave2Ctx) sliceEntryCounts(ues int, dnn string, sessions int) error {
	es, err := w.sliceEntries(1, "000001")
	if err != nil || len(es) != 1 {
		return fmt.Errorf("expected one slice entry for sst 1 sd 000001: %v %s", err, w.g.rawText)
	}
	e := es[0]
	if got, _ := e["registered_ues"].(float64); int(got) != ues {
		return fmt.Errorf("registered_ues: got %v, want %d", e["registered_ues"], ues)
	}
	by, _ := e["active_sessions_by_dnn"].(map[string]any)
	if got, _ := by[dnn].(float64); int(got) != sessions {
		return fmt.Errorf("active_sessions_by_dnn[%q]: got %v, want %d", dnn, by[dnn], sessions)
	}
	return nil
}

func (w *wave2Ctx) sliceEntryAMBRAndGNBs(gnbs int) error {
	es, err := w.sliceEntries(1, "000001")
	if err != nil || len(es) != 1 {
		return fmt.Errorf("expected one slice entry for sst 1 sd 000001: %v %s", err, w.g.rawText)
	}
	e := es[0]
	if l, _ := e["session_ambr_config"].([]any); len(l) == 0 {
		return fmt.Errorf("session_ambr_config is empty: %v", e["session_ambr_config"])
	}
	if got, _ := e["gnbs_supporting"].(float64); int(got) != gnbs {
		return fmt.Errorf("gnbs_supporting: got %v, want %d", e["gnbs_supporting"], gnbs)
	}
	return nil
}

// ---- subscription_am_get -----------------------------------------------------

func (w *wave2Ctx) udmAMData(path string, sst int, sd string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.udmRoutes[path] = w2UDMRoute{status: http.StatusOK, body: map[string]any{
		"nssai":            map[string]any{"defaultSingleNssais": []any{map[string]any{"sst": sst, "sd": sd}}},
		"subscribedUeAmbr": map[string]any{"uplink": "1 Gbps", "downlink": "2 Gbps"},
	}}
	return nil
}

func (w *wave2Ctx) udm404(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.udmRoutes[path] = w2UDMRoute{status: http.StatusNotFound}
	return nil
}

func (w *wave2Ctx) amDefaultNssaiContains(sst int, sd string) error {
	nssai, _ := w.c.content["nssai"].(map[string]any)
	list, _ := nssai["defaultSingleNssais"].([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		if got, _ := m["sst"].(float64); int(got) == sst && m["sd"] == sd {
			return nil
		}
	}
	return fmt.Errorf("nssai.defaultSingleNssais lacks sst %d sd %q: %v", sst, sd, w.c.content["nssai"])
}

func (w *wave2Ctx) udmNoRequest() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.udmRequests != 0 {
		return fmt.Errorf("UDM mock received %d requests, want none", w.udmRequests)
	}
	return nil
}

// ---- pcf_binding_list --------------------------------------------------------

func (w *wave2Ctx) binding(id, supi, ip, dnn string, sst int, sd string) map[string]any {
	return map[string]any{
		"bindingId": id, "supi": supi, "ipv4Addr": ip, "dnn": dnn,
		"snssai":  map[string]any{"sst": sst, "sd": sd},
		"pcfFqdn": "pcf.5gc.local", "pcfId": "11111111-2222-3333-4444-555555555555",
	}
}

func (w *wave2Ctx) bsfAnswersForSUPI(supi, ip, dnn string, sst int, sd string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bsfBindings = append(w.bsfBindings, w.binding("b-"+supi, supi, ip, dnn, sst, sd))
	return nil
}

func (w *wave2Ctx) bsfAnswersForIPs(ip1, ip2 string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, ip := range []string{ip1, ip2} {
		w.bsfBindings = append(w.bsfBindings,
			w.binding(fmt.Sprintf("b-%d", i+1), fmt.Sprintf("imsi-00101000000000%d", i+1), ip, "internet", 1, "000001"))
	}
	return nil
}

func (w *wave2Ctx) bsf404() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bsfAll404 = true
	return nil
}

func (w *wave2Ctx) bindings() ([]map[string]any, error) {
	raw, ok := w.c.content["bindings"].([]any)
	if !ok {
		return nil, fmt.Errorf("result has no bindings array: %v", w.c.content)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, b := range raw {
		m, _ := b.(map[string]any)
		out = append(out, m)
	}
	return out, nil
}

func (w *wave2Ctx) bindingsExactlyForSUPI(n int, supi string) error {
	bs, err := w.bindings()
	if err != nil {
		return err
	}
	if len(bs) != n {
		return fmt.Errorf("bindings: got %d, want %d: %v", len(bs), n, bs)
	}
	for _, b := range bs {
		if b["supi"] != supi {
			return fmt.Errorf("binding supi: got %v, want %q", b["supi"], supi)
		}
	}
	return nil
}

func (w *wave2Ctx) bindingsExactly(n int) error {
	bs, err := w.bindings()
	if err != nil {
		return err
	}
	if len(bs) != n {
		return fmt.Errorf("bindings: got %d, want %d: %v", len(bs), n, bs)
	}
	return nil
}

func (w *wave2Ctx) eachBindingHasKeys(list string) error {
	bs, err := w.bindings()
	if err != nil {
		return err
	}
	if len(bs) == 0 {
		return fmt.Errorf("no bindings returned")
	}
	for i, b := range bs {
		if err := w.hasKeys(b, quotedList(list)); err != nil {
			return fmt.Errorf("binding %d: %w", i+1, err)
		}
	}
	return nil
}

func (w *wave2Ctx) bsfReceivedQueriesWith(n int, param string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.bsfQueries) != n {
		return fmt.Errorf("BSF mock queries: got %d, want %d: %v", len(w.bsfQueries), n, w.bsfQueries)
	}
	for _, q := range w.bsfQueries {
		if q.Get(param) == "" {
			return fmt.Errorf("BSF query without %q parameter: %v", param, q)
		}
	}
	return nil
}

func (w *wave2Ctx) bsfNoRequest() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.bsfQueries) != 0 {
		return fmt.Errorf("BSF mock received %d requests, want none", len(w.bsfQueries))
	}
	return nil
}

// ---- wiring ------------------------------------------------------------------

// registerWave2Steps wires the @mcp009 steps. The MCP server over the wave-2
// mocks is built right before the first `I call` step of a tagged scenario.
func registerWave2Steps(sc *godog.ScenarioContext, c *mcpCtx, g *guardCtx, a *analysisCtx) {
	w := &wave2Ctx{c: c, g: g}
	a.wave2 = w

	sc.Before(func(ctx context.Context, s *godog.Scenario) (context.Context, error) {
		w.active = false
		for _, t := range s.Tags {
			if t.Name == wave2Tag {
				w.active = true
			}
		}
		if w.active {
			w.reset()
			w.newMocks()
		}
		return ctx, nil
	})
	sc.StepContext().Before(func(ctx context.Context, st *godog.Step) (context.Context, error) {
		if w.active && !w.built && strings.HasPrefix(st.Text, `I call "`) {
			if err := w.build(); err != nil {
				return ctx, fmt.Errorf("build wave-2 MCP server: %w", err)
			}
		}
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if w.active {
			w.close()
		}
		return ctx, nil
	})

	keys := `((?:"[^"]+"(?:, )?)+)`
	sc.Step(`^the MCP guard runs with access_mode "([^"]+)"$`, w.guardRunsWithMode)
	sc.Step(`^the call is refused with code (-?\d+)$`, func(code int) error { return w.refusedWithCode(code) })
	sc.Step(`^the result field "([^"]+)" equals (\d+)$`, w.resultFieldEquals)
	sc.Step(`^the result contains the keys `+keys+`$`, w.resultContainsKeys)
	sc.Step(`^"([^"]+)" is listed in tools/list$`, w.listedInToolsList)

	// Prometheus
	sc.Step(`^the Prometheus mock returns gauge "([^"]+)" with value (\d+) for nf "([^"]+)" and value (\d+) for nf "([^"]+)"$`, w.promGaugeTwo)
	sc.Step(`^the Prometheus mock returns gauge "([^"]+)" with value (\d+) for nf "([^"]+)"$`, w.promGauge)
	sc.Step(`^the Prometheus mock returns UPF throughput for dnn "([^"]+)" with ul (\d+) and dl (\d+)$`, w.promThroughput)
	sc.Step(`^the Prometheus mock returns fivegc_ue_registered_by_slice for nf "([^"]+)" snssai sst (\d+) sd "([^"]+)" with value (\d+)$`, w.promSliceUEs)
	sc.Step(`^the Prometheus mock was queried with range window "([^"]+)"$`, w.promQueriedWithWindow)
	sc.Step(`^the Prometheus mock received no query$`, w.promNoQuery)
	sc.Step(`^every PromQL sent to the Prometheus mock filters nf="UPF"$`, w.promAllFilterUPF)
	sc.Step(`^the result throughput_bps for dnn "([^"]+)" has ul (\d+) and dl (\d+)$`, w.throughputFor)

	// AMF / SMF / portal
	sc.Step(`^the AMF mock holds UEs "([^"]+)" and "([^"]+)" each with pdu_session_ids "([^"]+)"$`, w.amfUEsB64)
	sc.Step(`^the AMF mock holds UE "([^"]+)" with pdu_session_ids (\[[0-9, ]*\])$`, w.amfUEArray)
	sc.Step(`^the SMF mock holds sessions for "([^"]+)" and "([^"]+)" with PDU session id (\d+)$`, w.smfSessionsTwo)
	sc.Step(`^the SMF mock holds sessions for "([^"]+)" with PDU session id (\d+)$`, w.smfSessionsOne)
	sc.Step(`^the SMF mock holds no sessions$`, w.smfNoSessions)
	sc.Step(`^the SMF mock holds (\d+) sessions on dnn "([^"]+)" in slice sst (\d+) sd "([^"]+)"$`, w.smfSliceSessions)
	sc.Step(`^the SMF mock holds sessions with ueIp "([^"]+)" and "([^"]+)"$`, w.smfSessionsWithIPs)
	sc.Step(`^the AMF mock lists a gNB supporting slice sst (\d+) sd "([^"]+)"$`, w.amfGNBSupporting)
	sc.Step(`^the portal mock returns slice QoS for sst (\d+) sd "([^"]+)" with a Session-AMBR$`, w.portalSliceQoS)
	sc.Step(`^the mocked AMF upstream is shut down$`, w.amfShutDown)

	// core_consistency_check
	sc.Step(`^the counts report (.+)$`, w.countsReport)
	sc.Step(`^no finding has severity "([^"]+)"$`, w.noFindingWithSeverity)
	sc.Step(`^a finding has severity "([^"]+)" and check "([^"]+)"$`, w.findingWithSeverityAndCheck)
	sc.Step(`^a finding has check "([^"]+)"$`, w.findingWithCheck)
	sc.Step(`^that finding has a non-empty detail and a non-empty spec_ref$`, w.findingHasDetailAndSpecRef)

	// error_summary
	sc.Step(`^the Loki instant-query mock (?:returns a vector with|also returns) group nf "([^"]*)", procedure "([^"]*)", result "([^"]*)", cause "([^"]*)", spec_ref "([^"]*)" and count (\d+)$`, w.lokiGroup)
	sc.Step(`^the error_summary has exactly (\d+) rows$`, w.summaryHasRows)
	sc.Step(`^error_summary row (\d+) has nf "([^"]+)" and count (\d+)$`, w.summaryRowIs)
	sc.Step(`^every error_summary row has the keys `+keys+`$`, w.summaryRowsHaveKeys)
	sc.Step(`^the Loki mock was queried at "([^"]+)" with a "([^"]+)" expression over window "([^"]+)"$`, w.lokiQueriedAt)

	// mcp_info
	sc.Step(`^tool_count plus alias_count equals the number of names in tools/list$`, w.toolCountMatchesList)
	sc.Step(`^the upstream "([^"]+)" is reported with reachable false$`, w.upstreamUnreachable)
	sc.Step(`^the upstream "([^"]+)" is reported with reachable true and a latency_ms$`, w.upstreamReachable)

	// slice_status
	sc.Step(`^the slice_status has exactly (\d+) entry for snssai sst (\d+) sd "([^"]+)"$`, w.sliceHasEntries)
	sc.Step(`^that entry has registered_ues (\d+) and active_sessions_by_dnn "([^"]+)" (\d+)$`, w.sliceEntryCounts)
	sc.Step(`^that entry has a non-empty session_ambr_config and gnbs_supporting (\d+)$`, w.sliceEntryAMBRAndGNBs)

	// subscription_am_get
	sc.Step(`^the UDM mock answers GET "([^"]+)" with nssai defaultSingleNssais sst (\d+) sd "([^"]+)"$`, w.udmAMData)
	sc.Step(`^the UDM mock answers 404 for GET "([^"]+)"$`, w.udm404)
	sc.Step(`^the result nssai\.defaultSingleNssais contains sst (\d+) sd "([^"]+)"$`, w.amDefaultNssaiContains)
	sc.Step(`^the UDM mock received no request$`, w.udmNoRequest)

	// pcf_binding_list
	sc.Step(`^the BSF mock answers GET "/nbsf-management/v1/pcfBindings" for supi "([^"]+)" with binding ipv4Addr "([^"]+)", dnn "([^"]+)", snssai sst (\d+) sd "([^"]+)"$`, w.bsfAnswersForSUPI)
	sc.Step(`^the BSF mock answers a binding for each of the ueIps "([^"]+)" and "([^"]+)"$`, w.bsfAnswersForIPs)
	sc.Step(`^the BSF mock answers 404 for GET "/nbsf-management/v1/pcfBindings"$`, w.bsf404)
	sc.Step(`^the pcf_binding_list has exactly (\d+) bindings? for supi "([^"]+)"$`, w.bindingsExactlyForSUPI)
	sc.Step(`^the pcf_binding_list has exactly (\d+) bindings?$`, w.bindingsExactly)
	sc.Step(`^each binding has the keys `+keys+`$`, w.eachBindingHasKeys)
	sc.Step(`^the result bindings_active equals (\d+)$`, func(n int) error { return w.resultFieldEquals("bindings_active", n) })
	sc.Step(`^the BSF mock received exactly (\d+) queries each carrying an "([^"]+)" query parameter$`, w.bsfReceivedQueriesWith)
	sc.Step(`^the BSF mock received no request$`, w.bsfNoRequest)
}
