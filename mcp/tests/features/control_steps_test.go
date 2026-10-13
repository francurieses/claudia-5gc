//go:build functional

package features

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/control"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
	"github.com/francurieses/claudia-5gc/shared/oauth2"
)

// controlTag marks the MCP-010 scenarios.
const controlTag = "@mcp010"

// ctlReq is one request a mocked upstream received.
type ctlReq struct {
	method string
	path   string
	auth   string
	body   string
	form   url.Values
}

// ctlReply is a canned upstream answer.
type ctlReply struct {
	status int
	body   string
	header map[string]string
}

// ctlMock is a mocked upstream that records every request and answers by
// "METHOD path" from its route table, falling back to fallback (or 404).
type ctlMock struct {
	srv      *httptest.Server
	reqs     []ctlReq
	routes   map[string]ctlReply
	fallback func(rw http.ResponseWriter, r *http.Request, c *ctlCtx) bool
}

// ctlCtx holds the mocked upstreams and state of one @mcp010 scenario. The
// shared AMF/SMF phrases (analysis and wave-2 steps) fill the analysis and
// wave-2 stores; the AMF and SMF mocks here read from them.
type ctlCtx struct {
	c *mcpCtx
	g *guardCtx
	a *analysisCtx
	w *wave2Ctx

	active bool
	built  bool

	mu    sync.Mutex
	mocks map[string]*ctlMock // AMF SMF NRF NEF SMSF portal
	subs  map[string]bool     // NEF subscriptions: "<scs>/<id>"
}

func (x *ctlCtx) closeMocks() {
	for _, m := range x.mocks {
		if m.srv != nil {
			m.srv.Close()
		}
	}
	x.mocks = nil
}

func (x *ctlCtx) newMock(name string, fb func(http.ResponseWriter, *http.Request, *ctlCtx) bool) {
	m := &ctlMock{routes: map[string]ctlReply{}, fallback: fb}
	m.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec := ctlReq{method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"), body: string(b)}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			rec.form, _ = url.ParseQuery(string(b))
		}
		x.mu.Lock()
		m.reqs = append(m.reqs, rec)
		rep, ok := m.routes[r.Method+" "+r.URL.Path]
		x.mu.Unlock()
		if ok {
			for k, v := range rep.header {
				rw.Header().Set(k, v)
			}
			rw.WriteHeader(rep.status)
			_, _ = rw.Write([]byte(rep.body))
			return
		}
		if m.fallback != nil && m.fallback(rw, r, x) {
			return
		}
		http.NotFound(rw, r)
	}))
	x.mocks[name] = m
}

func (x *ctlCtx) route(name, method, path string, rep ctlReply) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.mocks[name].routes[method+" "+path] = rep
}

// count returns the number of requests the mock received for method and path.
// An empty method or path matches any.
func (x *ctlCtx) count(name, method, path string) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	n := 0
	for _, r := range x.mocks[name].reqs {
		if (method == "" || r.method == method) && (path == "" || r.path == path) {
			n++
		}
	}
	return n
}

func (x *ctlCtx) matching(name, method, path string) []ctlReq {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []ctlReq
	for _, r := range x.mocks[name].reqs {
		if r.method == method && r.path == path {
			out = append(out, r)
		}
	}
	return out
}

// ---- mock fallbacks -----------------------------------------------------------

func ctlAMF(rw http.ResponseWriter, r *http.Request, x *ctlCtx) bool {
	const pfx = "/amf/v1/ue-contexts/"
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, pfx) || strings.Contains(strings.TrimPrefix(r.URL.Path, pfx), "/") {
		return false
	}
	supi := strings.TrimPrefix(r.URL.Path, pfx)
	x.a.mu.Lock()
	snap, ok := x.a.amfUEs[supi]
	out := map[string]any{}
	for k, v := range snap {
		out[k] = v
	}
	x.a.mu.Unlock()
	if !ok {
		return false
	}
	out["supi"] = supi
	x.w.mu.Lock()
	for _, ue := range x.w.amfUEs {
		if ue["supi"] == supi {
			out["pdu_session_ids"] = ue["pdu_session_ids"]
		}
	}
	x.w.mu.Unlock()
	writeJSON(rw, out)
	return true
}

func ctlSMF(rw http.ResponseWriter, r *http.Request, x *ctlCtx) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/nsmf-management/v1/sessions" {
		return false
	}
	x.w.mu.Lock()
	out := append([]map[string]any{}, x.w.smfSessions...)
	x.w.mu.Unlock()
	writeJSON(rw, map[string]any{"count": len(out), "sessions": out})
	return true
}

const nefBase = "/3gpp-as-session-with-qos/v1/"

func ctlNEF(rw http.ResponseWriter, r *http.Request, x *ctlCtx) bool {
	if !strings.HasPrefix(r.URL.Path, nefBase) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, nefBase), "/") // scs, "subscriptions", id
	if len(parts) != 3 || parts[1] != "subscriptions" {
		return false
	}
	key := parts[0] + "/" + parts[2]
	x.mu.Lock()
	has := x.subs[key]
	if has && r.Method == http.MethodDelete {
		delete(x.subs, key)
	}
	x.mu.Unlock()
	if !has {
		return false
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(rw, map[string]any{"subscriptionId": parts[2], "qosReference": "qos-gbr-1"})
	case http.MethodDelete:
		rw.WriteHeader(http.StatusNoContent)
	default:
		return false
	}
	return true
}

// ---- lifecycle ------------------------------------------------------------------

func (x *ctlCtx) startMocks() error {
	x.closeMocks()
	x.a.reset() // fresh AMF store for the shared "AMF mock" phrases
	x.w.mu.Lock()
	x.w.amfUEs, x.w.smfSessions = nil, nil
	x.w.mode = "operator"
	x.w.mu.Unlock()
	x.mu.Lock()
	x.mocks = map[string]*ctlMock{}
	x.subs = map[string]bool{}
	x.mu.Unlock()
	x.active, x.built = true, false
	x.newMock("AMF", ctlAMF)
	x.newMock("SMF", ctlSMF)
	x.newMock("NRF", nil)
	x.newMock("NEF", ctlNEF)
	x.newMock("SMSF", nil)
	x.newMock("portal", nil)
	return nil
}

// build replaces the scenario's MCP server with one over the control mocks.
func (x *ctlCtx) build() error {
	hc := http.DefaultClient
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mode, err := guard.ParseAccessMode(x.w.mode)
	if err != nil {
		return err
	}
	// MinInterval must be set or a second confirmed call is rate-limited.
	gd := guard.New(guard.Options{Mode: mode, MinInterval: time.Nanosecond}, logger)
	x.g.guard = gd

	tokens := oauth2.NewTokenCache(hc, x.mocks["NRF"].srv.URL+"/oauth2/v1/token",
		"6d63702d-0000-4000-8000-000000000010", "nnef-afsessionwithqos")
	reg := registry.New()
	if err := reg.RegisterAll(control.All(control.Deps{
		AMF:    clients.NewAMF(x.mocks["AMF"].srv.URL, hc),
		SMF:    clients.NewSMF(x.mocks["SMF"].srv.URL, hc),
		Portal: clients.NewPortal(x.mocks["portal"].srv.URL, hc),
		NEF:    clients.NewNEF(x.mocks["NEF"].srv.URL, hc, tokens),
		SMSF:   clients.NewSMSF(x.mocks["SMSF"].srv.URL, hc),
	})...); err != nil {
		return err
	}
	disp := server.NewDispatcher(reg, gd, logger)
	cfg := &config.Config{Transport: config.TransportSSE, SSE: config.SSE{Debug: true}}
	sse := transport.NewSSE(disp, reg, session.NewManager(logger), cfg, logger)
	if x.c.srv != nil {
		x.c.srv.Close()
	}
	x.c.srv = httptest.NewServer(sse.Handler())
	x.built = true
	return nil
}

// ---- Given: AMF / SMF -----------------------------------------------------------

func (x *ctlCtx) amfAccepts(path string) error {
	x.route("AMF", http.MethodPost, path, ctlReply{status: http.StatusAccepted, body: `{}`})
	return nil
}

func (x *ctlCtx) amfAnswersPOST(status int, path string) error {
	x.route("AMF", http.MethodPost, path, ctlReply{status: status, body: `{"cause":"UE_BUSY"}`})
	return nil
}

// ---- Given: portal --------------------------------------------------------------

func (x *ctlCtx) portalLocation(path, lat, lon string, acc int, cell, tac string) error {
	la, err := strconv.ParseFloat(lat, 64)
	if err != nil {
		return err
	}
	lo, err := strconv.ParseFloat(lon, 64)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(map[string]any{"reachable": true, "latitude": la, "longitude": lo,
		"accuracy_m": acc, "nr_cell_id": cell, "tac": tac})
	x.route("portal", http.MethodGet, path, ctlReply{status: http.StatusOK, body: string(b)})
	return nil
}

func (x *ctlCtx) portalAccepts(path string) error {
	x.route("portal", http.MethodPost, path, ctlReply{status: http.StatusOK, body: `{"status":"resent"}`})
	return nil
}

// ---- Given: NRF / NEF / SMSF ----------------------------------------------------

func (x *ctlCtx) nrfIssues(token, scope, path string) error {
	b, _ := json.Marshal(map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": scope})
	x.route("NRF", http.MethodPost, path, ctlReply{status: http.StatusOK, body: string(b),
		header: map[string]string{"Content-Type": "application/json"}})
	return nil
}

func (x *ctlCtx) nefAnswersPOST(path string, status int, id string) error {
	b, _ := json.Marshal(map[string]string{"subscriptionId": id})
	x.route("NEF", http.MethodPost, path, ctlReply{status: status, body: string(b),
		header: map[string]string{"Location": path + "/" + id, "Content-Type": "application/json"}})
	return nil
}

func (x *ctlCtx) nefHolds(id, scs string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.subs[scs+"/"+id] = true
	return nil
}

func (x *ctlCtx) smsfAnswers200(path, status string) error {
	b, _ := json.Marshal(map[string]string{"status": status})
	x.route("SMSF", http.MethodPost, path, ctlReply{status: http.StatusOK, body: string(b)})
	return nil
}

func (x *ctlCtx) smsfAnswers404(cause, path string) error {
	b, _ := json.Marshal(map[string]string{"cause": cause})
	x.route("SMSF", http.MethodPost, path, ctlReply{status: http.StatusNotFound, body: string(b),
		header: map[string]string{"Content-Type": "application/problem+json"}})
	return nil
}

// ---- When -----------------------------------------------------------------------

func (x *ctlCtx) callSMS(nbytes int, supi, confirm string) error {
	args, _ := json.Marshal(map[string]any{"supi": supi,
		"payload_b64": base64.StdEncoding.EncodeToString(make([]byte, nbytes)), "confirm": confirm == "true"})
	return x.g.call("sms_send_mt", string(args))
}

// ---- Then: results ----------------------------------------------------------------

func (x *ctlCtx) planLists(prev string, psi1, psi2 int) error {
	plan, ok := x.c.content["plan"].(map[string]any)
	if !ok {
		return fmt.Errorf("dry-run has no plan object: %v", x.c.content)
	}
	if got, _ := plan["previous_cm_state"].(string); got != prev {
		return fmt.Errorf("plan previous_cm_state: got %q, want %q", got, prev)
	}
	return intList(plan["affected_pdu_sessions"], psi1, psi2)
}

func intList(v any, want ...int) error {
	arr, ok := v.([]any)
	if !ok || len(arr) != len(want) {
		return fmt.Errorf("affected_pdu_sessions: got %v, want %v", v, want)
	}
	for i, w := range want {
		if f, _ := arr[i].(float64); int(f) != w {
			return fmt.Errorf("affected_pdu_sessions: got %v, want %v", v, want)
		}
	}
	return nil
}

func (x *ctlCtx) resultAffected(psi int) error {
	return intList(x.c.content["affected_pdu_sessions"], psi)
}

func (x *ctlCtx) refusalMentions(text string) error {
	if !x.c.isError {
		return fmt.Errorf("expected a refusal, call succeeded: %s", x.g.rawText)
	}
	if !strings.Contains(x.g.lastErr, text) {
		return fmt.Errorf("refusal message %q does not mention %q", x.g.lastErr, text)
	}
	return nil
}

func (x *ctlCtx) fieldIsTrue(field string) error {
	if v, ok := x.c.content[field].(bool); !ok || !v {
		return fmt.Errorf("result field %q: got %v, want true", field, x.c.content[field])
	}
	return nil
}

func (x *ctlCtx) fieldIsString(field, want string) error {
	if got, _ := x.c.content[field].(string); got != want {
		return fmt.Errorf("result field %q: got %v, want %q", field, x.c.content[field], want)
	}
	return nil
}

func (x *ctlCtx) fieldContains(field, want string) error {
	// A string field is searched as is; an object or array field is searched in its JSON text.
	got, ok := x.c.content[field].(string)
	if !ok {
		b, _ := json.Marshal(x.c.content[field])
		got = string(b)
	}
	if !strings.Contains(got, want) {
		return fmt.Errorf("result field %q: got %v, want it to contain %q", field, x.c.content[field], want)
	}
	return nil
}

func (x *ctlCtx) noToolPrefixed(p1, p2 string) error {
	if err := x.g.listTools(); err != nil {
		return err
	}
	if len(x.g.listed) == 0 {
		return fmt.Errorf("tool list is empty")
	}
	for _, n := range x.g.listed {
		if strings.HasPrefix(n, p1) || strings.HasPrefix(n, p2) {
			return fmt.Errorf("tool list contains %q", n)
		}
	}
	return nil
}

// ---- Then: upstream request counts --------------------------------------------------

func (x *ctlCtx) countIs(name, method, path string, want int) error {
	if got := x.count(name, method, path); got != want {
		return fmt.Errorf("%s mock received %d %s %s request(s), want %d", name, got, method, path, want)
	}
	return nil
}

func (x *ctlCtx) exactly(name string, n int, method, path string) error {
	return x.countIs(name, method, path, n)
}

func (x *ctlCtx) exactlyWithHeader(name string, n int, method, path, header, want string) error {
	if err := x.countIs(name, method, path, n); err != nil {
		return err
	}
	if header != "Authorization" {
		return fmt.Errorf("only the Authorization header is recorded, not %q", header)
	}
	for _, r := range x.matching(name, method, path) {
		if r.auth != want {
			return fmt.Errorf("%s %s header %s: got %q, want %q", method, path, header, r.auth, want)
		}
	}
	return nil
}

func (x *ctlCtx) smsfPayload(n int, path, want string) error {
	if err := x.countIs("SMSF", http.MethodPost, path, n); err != nil {
		return err
	}
	for _, r := range x.matching("SMSF", http.MethodPost, path) {
		var b struct {
			SMSPayload string `json:"smsPayload"`
		}
		if err := json.Unmarshal([]byte(r.body), &b); err != nil || b.SMSPayload != want {
			return fmt.Errorf("SMSF body %q: smsPayload want %q", r.body, want)
		}
	}
	return nil
}

func (x *ctlCtx) nrfTokenRequest(scope string) error {
	reqs := x.matching("NRF", http.MethodPost, "/oauth2/v1/token")
	if len(reqs) == 0 {
		return fmt.Errorf("NRF mock received no token request")
	}
	for _, r := range reqs {
		if r.form.Get("grant_type") == "client_credentials" && r.form.Get("scope") == scope {
			return nil
		}
	}
	return fmt.Errorf("no client_credentials token request for scope %q: %+v", scope, reqs)
}

// ---- wiring -----------------------------------------------------------------------

// registerControlSteps wires the control_tools.feature steps. It must run after
// registerWave2Steps, whose context it shares for the AMF PDU-session and SMF
// session phrases. The MCP server over the mocks is built right before the
// first `I call`, `I list the tools` or tools/list step of a tagged scenario.
func registerControlSteps(sc *godog.ScenarioContext, c *mcpCtx, g *guardCtx, a *analysisCtx) {
	x := &ctlCtx{c: c, g: g, a: a, w: a.wave2}
	a.ctl = x // shared with the @mcp011 runtime steps (mock registry and request counters)

	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		x.active, x.built = false, false
		return ctx, nil
	})
	sc.StepContext().Before(func(ctx context.Context, st *godog.Step) (context.Context, error) {
		if x.active && !x.built && (strings.HasPrefix(st.Text, `I call "`) ||
			strings.HasPrefix(st.Text, "I list the tools") || strings.Contains(st.Text, "tools/list")) {
			if err := x.build(); err != nil {
				return ctx, fmt.Errorf("build control MCP server: %w", err)
			}
		}
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if x.active {
			x.closeMocks()
			x.active = false
		}
		return ctx, nil
	})

	sc.Step(`^the MCP control tools run against mocked AMF, SMF, NRF, NEF, SMSF and portal upstreams$`, x.startMocks)

	sc.Step(`^the AMF mock accepts POST "([^"]+)"$`, x.amfAccepts)
	sc.Step(`^the AMF mock answers (\d+) for POST "([^"]+)"$`, x.amfAnswersPOST)
	sc.Step(`^the portal mock answers GET "([^"]+)" with reachable true, latitude (-?[0-9.]+), longitude (-?[0-9.]+), accuracy_m (\d+), nr_cell_id "([^"]+)", tac "([^"]+)"$`, x.portalLocation)
	sc.Step(`^the portal mock accepts POST "([^"]+)"$`, x.portalAccepts)
	sc.Step(`^the NRF mock issues an access token "([^"]+)" for scope "([^"]+)" on POST "([^"]+)"$`, x.nrfIssues)
	sc.Step(`^the NEF mock answers POST "([^"]+)" with (\d+) and subscription id "([^"]+)"$`, x.nefAnswersPOST)
	sc.Step(`^the NEF mock holds subscription "([^"]+)" for scsAsId "([^"]+)"$`, x.nefHolds)
	sc.Step(`^the SMSF mock answers POST "([^"]+)" with 200 and status "([^"]+)"$`, x.smsfAnswers200)
	sc.Step(`^the SMSF mock answers 404 with cause "([^"]+)" for POST "([^"]+)"$`, x.smsfAnswers404)

	sc.Step(`^I call "sms_send_mt" with arguments carrying a payload_b64 of (\d+) decoded bytes for "([^"]+)" and confirm (true|false)$`, x.callSMS)

	sc.Step(`^the dry-run plan lists previous_cm_state "([^"]+)" and affected PDU session ids (\d+) and (\d+)$`, x.planLists)
	sc.Step(`^the result affected_pdu_sessions are (\d+)$`, x.resultAffected)
	sc.Step(`^the refusal message mentions "([^"]+)"$`, x.refusalMentions)
	sc.Step(`^the result field "([^"]+)" is true$`, x.fieldIsTrue)
	sc.Step(`^the result field "([^"]+)" is "([^"]+)"$`, x.fieldIsString)
	sc.Step(`^the result field "([^"]+)" contains "([^"]+)"$`, x.fieldContains)
	sc.Step(`^the tool list contains no name starting with "([^"]+)" or "([^"]+)"$`, x.noToolPrefixed)

	sc.Step(`^the AMF mock received (\d+) POST requests?$`, func(n int) error { return x.countIs("AMF", http.MethodPost, "", n) })
	sc.Step(`^the portal mock received (\d+) POST requests to "([^"]+)"$`, func(n int, p string) error {
		return x.countIs("portal", http.MethodPost, p, n)
	})
	sc.Step(`^the portal mock received (\d+) location requests$`, func(n int) error {
		return x.countIs("portal", http.MethodGet, "", n)
	})
	sc.Step(`^the (NEF|SMSF) mock received (\d+) requests$`, func(nf string, n int) error { return x.countIs(nf, "", "", n) })
	sc.Step(`^the NEF mock received (\d+) DELETE requests$`, func(n int) error { return x.countIs("NEF", http.MethodDelete, "", n) })
	sc.Step(`^the NRF mock received (\d+) token requests$`, func(n int) error { return x.countIs("NRF", "", "", n) })
	sc.Step(`^the (AMF|portal|NEF|SMSF|PCF) mock received exactly (\d+) (GET|POST|PUT|DELETE) to "([^"]+)"$`, x.exactly)
	sc.Step(`^the (NEF) mock received exactly (\d+) (POST) to "([^"]+)" with header "([^"]+)" equal to "([^"]+)"$`, x.exactlyWithHeader)
	sc.Step(`^the SMSF mock received exactly (\d+) POST to "([^"]+)" with smsPayload "([^"]+)"$`, x.smsfPayload)
	sc.Step(`^the NRF mock received a client_credentials token request for scope "([^"]+)"$`, x.nrfTokenRequest)
}
