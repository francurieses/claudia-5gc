//go:build functional

package features

import (
	"bytes"
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
	"time"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/config"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/server/transport"
	"github.com/francurieses/claudia-5gc/mcp/internal/session"
	qostools "github.com/francurieses/claudia-5gc/mcp/internal/tools/qos"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/runtimecfg"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/status"
)

// adminToken is the bearer token that carries the admin role in the @mcp011 scenarios.
const adminToken = "admin-token"

// rtModeRe finds the access mode a Given step selects, in both phrasings.
var rtModeRe = regexp.MustCompile(`^the MCP (?:guard runs with access_mode|server runs with access mode) "([^"]+)"`)

// lockedBuf is a goroutine-safe buffer for the slog capture.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// rtCtx holds the state of one MCP-011 scenario. It reuses the control mock
// registry (ctlCtx: request log, route table, request counters) for the AMF, PCF
// and portal upstreams and builds its own MCP server over them.
type rtCtx struct {
	c *mcpCtx
	g *guardCtx
	x *ctlCtx
	w *wave2Ctx

	active bool
	built  bool
	mode   string

	logBuf   *lockedBuf
	prevSlog *slog.Logger

	mu          sync.Mutex
	timerBase   [3]int // base t3512, guard, implicit detach
	subs        map[string]map[string]any
	deleted     map[string]bool
	storePosts  bool
	pcfStateful bool
	pcfList     []map[string]any
}

func (r *rtCtx) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timerBase = [3]int{}
	r.subs = map[string]map[string]any{}
	r.deleted = map[string]bool{}
	r.storePosts, r.pcfStateful = false, false
	r.pcfList = nil
}

// ---- lifecycle ------------------------------------------------------------------

func (r *rtCtx) startMocks() error {
	x := r.x
	x.closeMocks()
	x.a.reset() // the shared "portal mock holds subscribers" phrase fills a.subscribers
	x.mu.Lock()
	x.mocks = map[string]*ctlMock{}
	x.subs = map[string]bool{}
	x.mu.Unlock()
	r.reset()
	r.active, r.built = true, false
	r.mode = "operator"

	x.newMock("AMF", nil)
	x.newMock("PCF", r.pcfFallback)
	x.newMock("portal", r.portalFallback)
	r.guardPortalAmbr(x.mocks["portal"].srv)
	// The shared "mocked AMF upstream is shut down" phrase closes this server.
	r.w.srvAMF = x.mocks["AMF"].srv

	r.logBuf = &lockedBuf{}
	r.prevSlog = slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(r.logBuf, nil)))
	return nil
}

// build replaces the scenario's MCP server with one over the runtime mocks.
func (r *rtCtx) build() error {
	hc := http.DefaultClient
	logger := slog.New(slog.NewJSONHandler(r.logBuf, nil))
	mode, err := guard.ParseAccessMode(r.mode)
	if err != nil {
		return err
	}
	// MinInterval must be set or a second confirmed call is rate-limited.
	gd := guard.New(guard.Options{Mode: mode, MinInterval: time.Nanosecond}, logger)
	r.g.guard = gd

	portal := clients.NewPortal(r.x.mocks["portal"].srv.URL, hc)
	reg := registry.New()
	if err := reg.RegisterAll(runtimecfg.All(runtimecfg.Deps{
		Portal: portal, AMF: clients.NewAMF(r.x.mocks["AMF"].srv.URL, hc), Guard: gd, HTTP: hc,
	})...); err != nil {
		return err
	}
	if err := reg.RegisterAll(qostools.All(clients.NewPCF(r.x.mocks["PCF"].srv.URL, hc))...); err != nil {
		return err
	}
	if err := reg.RegisterAll(status.All(status.Deps{Portal: portal, HTTP: hc})...); err != nil {
		return err
	}
	disp := server.NewDispatcher(reg, gd, logger)
	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true},
		Auth: config.Auth{BearerToken: operatorToken, Tokens: []config.AuthToken{
			{Token: viewerToken, Role: "viewer"}, {Token: adminToken, Role: "admin"}}}}
	sse := transport.NewSSE(disp, reg, session.NewManager(logger), cfg, logger)
	if r.c.srv != nil {
		r.c.srv.Close()
	}
	r.c.srv = httptest.NewServer(sse.Handler())
	r.built = true
	return nil
}

// ---- mock fallbacks ---------------------------------------------------------------

func (r *rtCtx) lastBody(name string) []byte {
	r.x.mu.Lock()
	defer r.x.mu.Unlock()
	reqs := r.x.mocks[name].reqs
	if len(reqs) == 0 {
		return nil
	}
	return []byte(reqs[len(reqs)-1].body)
}

// lookupSub returns the stored subscriber, from this context or from the shared
// "portal mock holds subscribers" phrase, unless it was deleted.
func (r *rtCtx) lookupSub(supi string) map[string]any {
	r.mu.Lock()
	if r.deleted[supi] {
		r.mu.Unlock()
		return nil
	}
	if rec, ok := r.subs[supi]; ok {
		r.mu.Unlock()
		return rec
	}
	r.mu.Unlock()
	r.x.a.mu.Lock()
	defer r.x.a.mu.Unlock()
	for _, s := range r.x.a.subscribers {
		if s["supi"] == supi {
			return s
		}
	}
	return nil
}

const portalSubs = "/api/v1/subscribers"

// portalAmbrBody mirrors the real mgmt-portal Subscriber: ambr_ul and ambr_dl are
// uint64 kbps, so a string such as "200 Mbps" does not decode.
type portalAmbrBody struct {
	AmbrUL *uint64 `json:"ambr_ul"`
	AmbrDL *uint64 `json:"ambr_dl"`
}

// guardPortalAmbr wraps the portal mock so a PUT or POST on /api/v1/subscribers whose
// body carries a non-integer ambr field is answered 400, exactly like the real portal.
// The inner handler still runs (into a recorder) so the request is counted.
func (r *rtCtx) guardPortalAmbr(srv *httptest.Server) {
	inner := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if (req.Method == http.MethodPut || req.Method == http.MethodPost) && strings.HasPrefix(req.URL.Path, portalSubs) {
			b, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(b))
			rec := httptest.NewRecorder()
			inner.ServeHTTP(rec, req)
			var probe portalAmbrBody
			if err := json.Unmarshal(b, &probe); err != nil {
				http.Error(rw, "invalid subscriber body: "+err.Error(), http.StatusBadRequest)
				return
			}
			for k, v := range rec.Header() {
				rw.Header()[k] = v
			}
			rw.WriteHeader(rec.Code)
			_, _ = rw.Write(rec.Body.Bytes())
			return
		}
		inner.ServeHTTP(rw, req)
	})
}

func (r *rtCtx) portalFallback(rw http.ResponseWriter, req *http.Request, _ *ctlCtx) bool {
	p := req.URL.Path
	if req.Method == http.MethodPost && p == portalSubs {
		r.mu.Lock()
		store := r.storePosts
		r.mu.Unlock()
		if !store {
			return false
		}
		var rec map[string]any
		if json.Unmarshal(r.lastBody("portal"), &rec) != nil || rec["supi"] == nil {
			http.Error(rw, "bad subscriber", http.StatusBadRequest)
			return true
		}
		r.mu.Lock()
		r.subs[fmt.Sprint(rec["supi"])] = rec
		r.mu.Unlock()
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(rw).Encode(map[string]any{"supi": rec["supi"]})
		return true
	}
	supi, ok := strings.CutPrefix(p, portalSubs+"/")
	if !ok || supi == "" || strings.Contains(supi, "/") {
		return false
	}
	rec := r.lookupSub(supi)
	if rec == nil {
		return false
	}
	switch req.Method {
	case http.MethodGet:
		writeJSON(rw, rec)
		return true
	case http.MethodDelete:
		r.mu.Lock()
		r.deleted[supi] = true
		r.mu.Unlock()
		rw.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

const pcfList = "/pcf-internal/v1/sm-policy-overrides"

func (r *rtCtx) pcfFallback(rw http.ResponseWriter, req *http.Request, _ *ctlCtx) bool {
	r.mu.Lock()
	stateful := r.pcfStateful
	r.mu.Unlock()
	if !stateful {
		return false
	}
	const pfx, sfx = "/pcf-internal/v1/subscribers/", "/sm-policy-override"
	if req.Method == http.MethodPut && strings.HasPrefix(req.URL.Path, pfx) && strings.HasSuffix(req.URL.Path, sfx) {
		supi := strings.TrimSuffix(strings.TrimPrefix(req.URL.Path, pfx), sfx)
		var rec map[string]any
		if json.Unmarshal(r.lastBody("PCF"), &rec) != nil {
			http.Error(rw, "bad override", http.StatusBadRequest)
			return true
		}
		rec["supi"] = supi
		r.mu.Lock()
		r.pcfList = append(r.pcfList, rec)
		r.mu.Unlock()
		rw.WriteHeader(http.StatusOK)
		return true
	}
	if req.Method == http.MethodGet && req.URL.Path == pcfList {
		r.mu.Lock()
		out := []map[string]any{}
		for _, o := range r.pcfList {
			if f := req.URL.Query().Get("supi"); f == "" || o["supi"] == f {
				out = append(out, o)
			}
		}
		r.mu.Unlock()
		writeJSON(rw, out)
		return true
	}
	return false
}

// ---- Given ----------------------------------------------------------------------

func (r *rtCtx) callerRole(role string) error {
	switch role {
	case "admin":
		r.g.header = "Bearer " + adminToken
	case "operator":
		r.g.header = "Bearer " + operatorToken
	case "viewer":
		r.g.header = "Bearer " + viewerToken
	default:
		return fmt.Errorf("unknown caller role %q", role)
	}
	return nil
}

// timerBody renders the AMF GET/PUT /amf/v1/config/timers answer. Mobile reachable
// is T3512 plus the guard (TS 24.501 §5.3.7).
func (r *rtCtx) timerBody(t, g, i int) string {
	vals := func(t, g, i int) map[string]int {
		return map[string]int{"t3512_secs": t, "mobile_reachable_guard_secs": g,
			"mobile_reachable_secs": t + g, "implicit_detach_secs": i}
	}
	r.mu.Lock()
	b := r.timerBase
	r.mu.Unlock()
	out, _ := json.Marshal(map[string]any{"effective": vals(t, g, i), "base": vals(b[0], b[1], b[2]),
		"persisted": false, "spec_ref": "TS 24.501 §5.3.7, §10.2; TS 23.501 §5.4.1.1"})
	return string(out)
}

func (r *rtCtx) amfHoldsTimers(t, g, i, base int) error {
	r.mu.Lock()
	r.timerBase = [3]int{base, g, i}
	r.mu.Unlock()
	r.x.route("AMF", http.MethodGet, "/amf/v1/config/timers",
		ctlReply{status: http.StatusOK, body: r.timerBody(t, g, i), header: map[string]string{"Content-Type": "application/json"}})
	return nil
}

func (r *rtCtx) amfAcceptsPUT(path string, t, g, i int) error {
	r.x.route("AMF", http.MethodPut, path,
		ctlReply{status: http.StatusOK, body: r.timerBody(t, g, i), header: map[string]string{"Content-Type": "application/json"}})
	return nil
}

func (r *rtCtx) answersStatus(nf string, status int, method, path string) error {
	body := `{"title":"mock failure","detail":"mock upstream answers ` + fmt.Sprint(status) + `"}`
	r.x.route(nf, method, path, ctlReply{status: status, body: body,
		header: map[string]string{"Content-Type": "application/problem+json"}})
	return nil
}

func (r *rtCtx) pcfHolds(supi, dnn string, qi, arp int, ul, dl string) error {
	b, _ := json.Marshal([]map[string]any{{"supi": supi, "dnn": dnn, "5qi": qi,
		"arp_priority_level": arp, "ambr_uplink": ul, "ambr_downlink": dl}})
	r.x.route("PCF", http.MethodGet, pcfList, ctlReply{status: http.StatusOK, body: string(b),
		header: map[string]string{"Content-Type": "application/json"}})
	return nil
}

func (r *rtCtx) pcfHoldsNone() error {
	r.x.route("PCF", http.MethodGet, pcfList, ctlReply{status: http.StatusOK, body: `[]`,
		header: map[string]string{"Content-Type": "application/json"}})
	return nil
}

func (r *rtCtx) pcfStatefulFor(_ string) error {
	r.mu.Lock()
	r.pcfStateful = true
	r.mu.Unlock()
	return nil
}

func (r *rtCtx) portalHoldsSubscriber(supi, k, opc, ul, dl string) error {
	ulK, err := strconv.ParseUint(ul, 10, 64)
	if err != nil {
		return fmt.Errorf("ambr_ul %q must be an integer kbps: %w", ul, err)
	}
	dlK, err := strconv.ParseUint(dl, 10, 64)
	if err != nil {
		return fmt.Errorf("ambr_dl %q must be an integer kbps: %w", dl, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subs[supi] = map[string]any{"supi": supi, "k": k, "opc": opc, "amf": "8000", "sqn": "000000000020",
		"ambr_ul": ulK, "ambr_dl": dlK, "slices": []map[string]any{{"sst": 1, "sd": "010203", "dnn": "internet"}}}
	return nil
}

func (r *rtCtx) portalAcceptsPUT(path string) error {
	r.x.route("portal", http.MethodPut, path, ctlReply{status: http.StatusOK,
		body:   `{"supi":"` + strings.TrimPrefix(path, portalSubs+"/") + `","deregistered":true,"sm_data_synced":true}`,
		header: map[string]string{"Content-Type": "application/json"}})
	return nil
}

func (r *rtCtx) portalStoresPosts(_ string) error {
	r.mu.Lock()
	r.storePosts = true
	r.mu.Unlock()
	return nil
}

// ---- Then: counters and requests ----------------------------------------------------

func (r *rtCtx) receivedMethod(nf string, n int, method string) error {
	return r.x.countIs(nf, method, "", n)
}

func (r *rtCtx) receivedAny(nf string, n int) error {
	return r.x.countIs(nf, "", "", n)
}

func (r *rtCtx) putTimerValue(n int, path string, want int) error {
	if err := r.x.countIs("AMF", http.MethodPut, path, n); err != nil {
		return err
	}
	for _, q := range r.x.matching("AMF", http.MethodPut, path) {
		var b map[string]any
		if err := json.Unmarshal([]byte(q.body), &b); err != nil {
			return fmt.Errorf("AMF PUT body %q is not JSON: %w", q.body, err)
		}
		if got, _ := b["t3512_secs"].(float64); int(got) != want {
			return fmt.Errorf("AMF PUT body %q: t3512_secs want %d", q.body, want)
		}
	}
	return nil
}

func (r *rtCtx) putSubscriberMerged(n int, path string, dlKbps int) error {
	if err := r.x.countIs("portal", http.MethodPut, path, n); err != nil {
		return err
	}
	stored := r.lookupSub(strings.TrimPrefix(path, portalSubs+"/"))
	if stored == nil {
		return fmt.Errorf("no stored subscriber for %s", path)
	}
	for _, q := range r.x.matching("portal", http.MethodPut, path) {
		var b map[string]any
		if err := json.Unmarshal([]byte(q.body), &b); err != nil {
			return fmt.Errorf("portal PUT body is not JSON: %w", err)
		}
		if got, ok := b["ambr_dl"].(float64); !ok || int(got) != dlKbps {
			return fmt.Errorf("portal PUT ambr_dl: got %v (%T), want the number %d kbps", b["ambr_dl"], b["ambr_dl"], dlKbps)
		}
		if b["k"] != stored["k"] || b["opc"] != stored["opc"] {
			return fmt.Errorf("portal PUT must carry the stored k and opc unchanged")
		}
		if ul, ok := b["ambr_ul"].(float64); !ok || uint64(ul) != stored["ambr_ul"] {
			return fmt.Errorf("portal PUT ambr_ul: got %v, want the unchanged %v", b["ambr_ul"], stored["ambr_ul"])
		}
	}
	return nil
}

// ---- Then: results ----------------------------------------------------------------------

func (r *rtCtx) effectiveTimerEquals(field string, want int) error {
	eff, ok := r.c.content["effective"].(map[string]any)
	if !ok {
		return fmt.Errorf("result has no effective object: %s", r.g.rawText)
	}
	if got, ok := eff[field].(float64); !ok || int(got) != want {
		return fmt.Errorf("effective timer %q: got %v, want %d", field, eff[field], want)
	}
	return nil
}

func (r *rtCtx) fieldIsFalse(field string) error {
	if v, ok := r.c.content[field].(bool); !ok || v {
		return fmt.Errorf("result field %q: got %v, want false", field, r.c.content[field])
	}
	return nil
}

func (r *rtCtx) list() ([]map[string]any, error) {
	var out []map[string]any
	if err := json.Unmarshal([]byte(r.g.rawText), &out); err != nil {
		return nil, fmt.Errorf("result is not a JSON array: %s", r.g.rawText)
	}
	return out, nil
}

func (r *rtCtx) listHasEntriesFor(n int, supi string) error {
	l, err := r.list()
	if err != nil {
		return err
	}
	got := 0
	for _, e := range l {
		if e["supi"] == supi {
			got++
		}
	}
	if got != n {
		return fmt.Errorf("qos_policy_list entries for %s: got %d, want %d: %s", supi, got, n, r.g.rawText)
	}
	return nil
}

func (r *rtCtx) listIsEmpty() error {
	l, err := r.list()
	if err != nil {
		return err
	}
	if len(l) != 0 {
		return fmt.Errorf("qos_policy_list: got %d entries, want none", len(l))
	}
	return nil
}

func (r *rtCtx) entriesHaveKeys(list string) error {
	l, err := r.list()
	if err != nil {
		return err
	}
	if len(l) == 0 {
		return fmt.Errorf("qos_policy_list is empty")
	}
	for i, e := range l {
		if err := r.w.hasKeys(e, quotedList(list)); err != nil {
			return fmt.Errorf("entry %d: %w", i+1, err)
		}
	}
	return nil
}

func (r *rtCtx) planAnnouncesDeregistration() error {
	plan, ok := r.c.content["plan"].(map[string]any)
	if !ok {
		return fmt.Errorf("dry-run has no plan object: %s", r.g.rawText)
	}
	if v, _ := plan["ue_will_be_deregistered"].(bool); !v {
		return fmt.Errorf("plan does not announce deregistration: %v", plan)
	}
	return nil
}

func (r *rtCtx) outputNeither(a, b string) error {
	for _, s := range []string{a, b} {
		if strings.Contains(r.g.rawText, s) {
			return fmt.Errorf("output leaks %q: %s", s, r.g.rawText)
		}
	}
	return nil
}

func (r *rtCtx) auditAndSlogNeither(a, b string) error {
	audit, err := json.Marshal(r.g.guard.Audit().Recent(0))
	if err != nil {
		return err
	}
	if len(audit) <= 2 {
		return fmt.Errorf("audit log is empty, nothing was checked")
	}
	logs := r.logBuf.String()
	if logs == "" {
		return fmt.Errorf("slog capture is empty, nothing was checked")
	}
	for _, s := range []string{a, b} {
		if strings.Contains(string(audit), s) {
			return fmt.Errorf("audit log leaks %q", s)
		}
		if strings.Contains(logs, s) {
			return fmt.Errorf("slog output leaks %q", s)
		}
	}
	return nil
}

// registerRuntimeSteps wires the runtime_tools.feature (MCP-011) steps. It must
// run after registerControlSteps, whose mock registry and counters it reuses. The
// MCP server over the mocks is built right before the first `I call`, `I list the
// tools` or tools/list step, so earlier Given steps (access mode) apply to it.
func registerRuntimeSteps(sc *godog.ScenarioContext, c *mcpCtx, g *guardCtx, a *analysisCtx) {
	r := &rtCtx{c: c, g: g, x: a.ctl, w: a.wave2}

	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		r.active, r.built = false, false
		return ctx, nil
	})
	sc.StepContext().Before(func(ctx context.Context, st *godog.Step) (context.Context, error) {
		if !r.active {
			return ctx, nil
		}
		if m := rtModeRe.FindStringSubmatch(st.Text); m != nil {
			r.mode = m[1]
		}
		if !r.built && (strings.HasPrefix(st.Text, `I call "`) ||
			strings.HasPrefix(st.Text, "I list the tools") || strings.Contains(st.Text, "tools/list")) {
			if err := r.build(); err != nil {
				return ctx, fmt.Errorf("build runtime MCP server: %w", err)
			}
		}
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if r.active {
			r.x.closeMocks()
			slog.SetDefault(r.prevSlog)
			r.active = false
		}
		return ctx, nil
	})

	keys := `((?:"[^"]+"(?:, )?)+)`
	sc.Step(`^the MCP runtime tools run against mocked AMF, PCF and portal upstreams$`, r.startMocks)
	sc.Step(`^the caller role is "([^"]+)"$`, r.callerRole)
	sc.Step(`^the AMF mock holds timer config t3512_secs (\d+), mobile_reachable_guard_secs (\d+), implicit_detach_secs (\d+) with base t3512_secs (\d+)$`, r.amfHoldsTimers)
	sc.Step(`^the AMF mock accepts PUT "([^"]+)" returning t3512_secs (\d+), mobile_reachable_guard_secs (\d+), implicit_detach_secs (\d+)$`, r.amfAcceptsPUT)
	sc.Step(`^the (AMF|PCF|portal) mock answers (\d+) for (GET|PUT|DELETE) "([^"]+)"$`, r.answersStatus)
	sc.Step(`^the (PCF|portal) mock answers (\d+) for (POST) "([^"]+)"$`, r.answersStatus)
	sc.Step(`^the PCF mock holds an sm-policy override for supi "([^"]+)" dnn "([^"]+)" 5qi (\d+) arp (\d+) ambr_ul "([^"]+)" ambr_dl "([^"]+)"$`, r.pcfHolds)
	sc.Step(`^the PCF mock holds no sm-policy overrides$`, r.pcfHoldsNone)
	sc.Step(`^the PCF mock accepts qos_policy_set for supi "([^"]+)" and then lists it$`, r.pcfStatefulFor)
	sc.Step(`^the portal mock holds subscriber "([^"]+)" with k "([^"]+)", opc "([^"]+)", ambr_ul "([^"]+)" and ambr_dl "([^"]+)"$`, r.portalHoldsSubscriber)
	sc.Step(`^the portal mock accepts PUT "([^"]+)" reporting deregistered true$`, r.portalAcceptsPUT)
	sc.Step(`^the portal mock stores subscribers POSTed to "([^"]+)"$`, r.portalStoresPosts)

	sc.Step(`^the (AMF|portal) mock received (\d+) (PUT|DELETE) requests?$`, r.receivedMethod)
	sc.Step(`^the (PCF|portal) mock received (\d+) requests$`, r.receivedAny)
	sc.Step(`^the AMF mock received exactly (\d+) PUT to "([^"]+)" with t3512_secs (\d+)$`, r.putTimerValue)
	sc.Step(`^the portal mock received exactly (\d+) PUT to "([^"]+)" with ambr_dl (\d+) kbps and the stored k and opc unchanged$`, r.putSubscriberMerged)

	sc.Step(`^the effective timer "([^"]+)" equals (\d+)$`, r.effectiveTimerEquals)
	sc.Step(`^the result field "([^"]+)" is false$`, r.fieldIsFalse)
	sc.Step(`^the qos_policy_list has exactly (\d+) entr(?:y|ies) for supi "([^"]+)"$`, r.listHasEntriesFor)
	sc.Step(`^the qos_policy_list is an empty list$`, r.listIsEmpty)
	sc.Step(`^each qos_policy_list entry has the keys `+keys+`$`, r.entriesHaveKeys)
	sc.Step(`^the dry-run plan states that the UE will be deregistered$`, r.planAnnouncesDeregistration)
	sc.Step(`^the output contains neither "([^"]+)" nor "([^"]+)"$`, r.outputNeither)
	sc.Step(`^the audit log and slog contain neither "([^"]+)" nor "([^"]+)"$`, r.auditAndSlogNeither)
}
