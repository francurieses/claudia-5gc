package runtimecfg

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/jsonrpc"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/server"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

const (
	testK   = "00112233445566778899aabbccddeeff"
	testOPc = "ffeeddccbbaa99887766554433221100"
)

// subStore is an in-memory portal subscriber API. It keeps the full records, keys
// included, as the real portal does, and records every request.
type subStore struct {
	mu     sync.Mutex
	subs   map[string]map[string]any
	calls  []string
	bodies []string
	force  map[string]int // "METHOD path" -> forced status
}

func (s *subStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	s.calls = append(s.calls, key)
	s.bodies = append(s.bodies, string(b))
	if st, ok := s.force[key]; ok {
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{"error":"forced"}`))
		return
	}
	const base = "/api/v1/subscribers"
	switch {
	case r.URL.Path == base && r.Method == http.MethodPost:
		var rec map[string]any
		_ = json.Unmarshal(b, &rec)
		if !portalAcceptsAmbr(b) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"json: cannot unmarshal into Subscriber ambr (uint64)"}`))
			return
		}
		s.subs[rec["supi"].(string)] = rec
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"supi":"` + rec["supi"].(string) + `"}`))
	case strings.HasPrefix(r.URL.Path, base+"/"):
		supi := strings.TrimPrefix(r.URL.Path, base+"/")
		rec, ok := s.subs[supi]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(rec)
		case http.MethodPut:
			var nrec map[string]any
			_ = json.Unmarshal(b, &nrec)
			if !portalAcceptsAmbr(b) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"json: cannot unmarshal into Subscriber ambr (uint64)"}`))
				return
			}
			s.subs[supi] = nrec
			_, _ = w.Write([]byte(`{"supi":"` + supi + `","deregistered":true,"sm_data_synced":true}`))
		case http.MethodDelete:
			delete(s.subs, supi)
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		http.NotFound(w, r)
	}
}

// portalAcceptsAmbr mimics the real portal Subscriber model
// (tools/mgmt-portal/internal/store/store.go): ambr_ul and ambr_dl are uint64 kbps,
// so a BitRate string or a fraction is a 400.
func portalAcceptsAmbr(body []byte) bool {
	var sub struct {
		AMBRUL uint64 `json:"ambr_ul"`
		AMBRDL uint64 `json:"ambr_dl"`
	}
	return json.Unmarshal(body, &sub) == nil
}

func (s *subStore) count(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if c == key {
			n++
		}
	}
	return n
}

func (s *subStore) body(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.calls {
		if c == key {
			return s.bodies[i]
		}
	}
	return ""
}

func newStore(supis ...string) *subStore {
	st := &subStore{subs: map[string]map[string]any{}, force: map[string]int{}}
	for _, s := range supis {
		st.subs[s] = map[string]any{"supi": s, "k": testK, "opc": testOPc, "amf": "8000", "sqn": "000000000001",
			"ambr_ul": 50000, "ambr_dl": 100000,
			"slices": []any{map[string]any{"sst": 1, "sd": "000001", "dnn": "internet"}}}
	}
	return st
}

// harness wires the new tools to a portal store and an AMF mock behind a guard and
// a dispatcher; the slog output of every component is captured in logs.
type harness struct {
	store *subStore
	amf   *amfMock
	g     *guard.Guard
	disp  *server.Dispatcher
	logs  *bytes.Buffer
}

type amfMock struct {
	mu     sync.Mutex
	calls  []string
	bodies []string
	status int
	reply  string
}

func (a *amfMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.calls = append(a.calls, r.Method+" "+r.URL.Path)
	a.bodies = append(a.bodies, string(b))
	st, reply := a.status, a.reply
	a.mu.Unlock()
	if st == 0 {
		st = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(st)
	_, _ = w.Write([]byte(reply))
}

const timersReply = `{"effective":{"t3512_secs":1800,"mobile_reachable_guard_secs":240,"mobile_reachable_secs":2040,"implicit_detach_secs":3840},` +
	`"base":{"t3512_secs":3240,"mobile_reachable_guard_secs":240,"mobile_reachable_secs":3480,"implicit_detach_secs":3840},"persisted":false}`

func newHarness(t *testing.T, mode guard.AccessMode, supis ...string) *harness {
	t.Helper()
	h := &harness{store: newStore(supis...), amf: &amfMock{reply: timersReply}, logs: &bytes.Buffer{}}
	ps := httptest.NewServer(h.store)
	as := httptest.NewServer(h.amf)
	t.Cleanup(ps.Close)
	t.Cleanup(as.Close)
	logger := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	old := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(old) })
	h.g = guard.New(guard.Options{Mode: mode, MinInterval: 1}, logger)
	reg := registry.New()
	if err := reg.RegisterAll(All(Deps{Portal: clients.NewPortal(ps.URL, http.DefaultClient),
		AMF: clients.NewAMF(as.URL, http.DefaultClient), Guard: h.g})...); err != nil {
		t.Fatal(err)
	}
	h.disp = server.NewDispatcher(reg, h.g, logger)
	return h
}

// call runs one tools/call through the dispatcher and returns the raw response JSON.
func (h *harness) call(role guard.Role, tool, args string) (raw string, errCode int) {
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": json.RawMessage(args)})
	resp := h.disp.Dispatch(guard.WithRole(context.Background(), role), &jsonrpc.Request{
		JSONRPC: "2.0", Method: "tools/call", Params: params, ID: json.RawMessage("1")})
	b, _ := json.Marshal(resp)
	raw = string(b)
	return raw, 0
}

func toolsOf(t *testing.T) map[string]registry.Tool {
	t.Helper()
	m := map[string]registry.Tool{}
	for _, tl := range All(Deps{Portal: clients.NewPortal("http://127.0.0.1:1", http.DefaultClient),
		AMF: clients.NewAMF("http://127.0.0.1:1", http.DefaultClient)}) {
		m[tl.Name()] = tl
	}
	return m
}

func TestAMFTimerRiskFor(t *testing.T) {
	rf := toolsOf(t)["amf_timer_config"].(registry.ArgRisker)
	for in, want := range map[string]registry.Risk{
		`{}`:                                registry.ReadOnly,
		`{"reset":false}`:                   registry.ReadOnly,
		`{"t3512_secs":1800}`:               registry.Mutating,
		`{"implicit_detach_secs":120}`:      registry.Mutating,
		`{"mobile_reachable_guard_secs":0}`: registry.Mutating,
		`{"reset":true}`:                    registry.Mutating,
		`{"t3512_secs":"junk"}`:             registry.Mutating,
	} {
		if got := rf.RiskFor(json.RawMessage(in)); got != want {
			t.Errorf("RiskFor(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestAMFTimerValidation(t *testing.T) {
	h := newHarness(t, guard.ModeLab)
	cases := map[string]string{
		"not representable": `{"t3512_secs":61}`,
		"54 min":            `{"t3512_secs":3240}`,
		"too low":           `{"t3512_secs":30}`,
		"too high":          `{"t3512_secs":86460}`,
		"guard too high":    `{"mobile_reachable_guard_secs":3601}`,
		"guard negative":    `{"mobile_reachable_guard_secs":-1}`,
		"implicit too low":  `{"implicit_detach_secs":59}`,
		"float":             `{"t3512_secs":1800.5}`,
		"string":            `{"t3512_secs":"1800"}`,
		"null":              `{"t3512_secs":null}`,
		"reset with values": `{"reset":true,"t3512_secs":1800}`,
		"derived field":     `{"mobile_reachable_secs":300}`,
		"typo":              `{"t3512":1800}`,
		"reset not boolean": `{"reset":"yes"}`,
	}
	for name, args := range cases {
		raw, _ := h.call(guard.RoleAdmin, "amf_timer_config", args)
		if !strings.Contains(raw, "-32602") {
			t.Errorf("%s: want -32602, got %s", name, raw)
		}
	}
	if len(h.amf.calls) != 0 {
		t.Errorf("AMF must not be called on invalid input: %v", h.amf.calls)
	}
}

func TestT3512Representable(t *testing.T) {
	for _, v := range []int{60, 62, 120, 600, 930, 1800, 1860, 3600, 18600, 86400} {
		if !t3512Representable(v) {
			t.Errorf("%d must be representable", v)
		}
	}
	for _, v := range []int{61, 3240, 2000, 7260, 93000} {
		if t3512Representable(v) {
			t.Errorf("%d must not be representable", v)
		}
	}
	if lo, hi := t3512Neighbours(3240); lo != 3000 || hi != 3600 {
		t.Errorf("neighbours of 3240: %d %d", lo, hi)
	}
}

func TestAMFTimerGetAndPut(t *testing.T) {
	h := newHarness(t, guard.ModeOperator)
	raw, _ := h.call(guard.RoleOperator, "amf_timer_config", `{}`)
	if strings.Contains(raw, `"error"`) || !strings.Contains(raw, "Registration Accepts sent after the change") {
		t.Fatalf("read: %s", raw)
	}
	if len(h.amf.calls) != 1 || h.amf.calls[0] != "GET /amf/v1/config/timers" {
		t.Errorf("read must be one GET: %v", h.amf.calls)
	}
	h.call(guard.RoleOperator, "amf_timer_config", `{"t3512_secs":1800,"implicit_detach_secs":120}`)
	if len(h.amf.calls) != 2 || h.amf.calls[1] != "PUT /amf/v1/config/timers" {
		t.Fatalf("set must be one PUT: %v", h.amf.calls)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(h.amf.bodies[1]), &sent)
	if sent["t3512_secs"] != float64(1800) || sent["implicit_detach_secs"] != float64(120) || len(sent) != 2 {
		t.Errorf("PUT body: %s", h.amf.bodies[1])
	}
	h.call(guard.RoleOperator, "amf_timer_config", `{"reset":true}`)
	if h.amf.bodies[2] != `{"reset":true}` {
		t.Errorf("reset body: %s", h.amf.bodies[2])
	}
}

func TestAMFTimerReadOnlyModeBlocksSet(t *testing.T) {
	h := newHarness(t, guard.ModeReadOnly)
	raw, _ := h.call(guard.RoleAdmin, "amf_timer_config", `{"t3512_secs":1800}`)
	if !strings.Contains(raw, "-32000") || len(h.amf.calls) != 0 {
		t.Errorf("set in read-only mode: %s calls=%v", raw, h.amf.calls)
	}
	h.call(guard.RoleViewer, "amf_timer_config", `{}`)
	if len(h.amf.calls) != 1 {
		t.Errorf("read must work in read-only mode: %v", h.amf.calls)
	}
}

func TestAMFTimerUpstreamErrors(t *testing.T) {
	h := newHarness(t, guard.ModeLab)
	h.amf.status = 400
	h.amf.reply = `{"status":400,"title":"Bad Request","detail":"t3512_secs out of range","cause":"T3512_OUT_OF_RANGE"}`
	raw, _ := h.call(guard.RoleAdmin, "amf_timer_config", `{"t3512_secs":1800}`)
	for _, want := range []string{"-32000", "400", "T3512_OUT_OF_RANGE"} {
		if !strings.Contains(raw, want) {
			t.Errorf("want %q in %s", want, raw)
		}
	}
	// Unreachable AMF.
	deps := Deps{AMF: clients.NewAMF("http://127.0.0.1:1", http.DefaultClient)}
	_, err := timerConfigTool{deps}.Invoke(context.Background(), json.RawMessage(`{}`))
	if e, ok := err.(*mcperr.Error); !ok || e.Code != mcperr.CodeToolError {
		t.Errorf("unreachable AMF: %v %v", err, nil)
	}
}

func TestSubscriberProfileUpdateRejectsKeyAndUnknownFields(t *testing.T) {
	h := newHarness(t, guard.ModeOperator, "imsi-001010000000001")
	for _, f := range []string{"k", "opc", "op", "sqn", "amf", "whatever", "supi"} {
		args := `{"supi":"imsi-001010000000001","fields":{"` + f + `":"00112233445566778899aabbccddeeff"},"confirm":true}`
		raw, _ := h.call(guard.RoleAdmin, "subscriber_profile_update", args)
		if !strings.Contains(raw, "-32602") || strings.Contains(raw, testK) {
			t.Errorf("field %s: %s", f, raw)
		}
	}
	for _, args := range []string{
		`{"supi":"imsi-001010000000001","k":"00112233445566778899aabbccddeeff","fields":{"ambr_dl":"1 Mbps"},"confirm":true}`,
		`{"supi":"not-a-supi","fields":{"ambr_dl":"1 Mbps"},"confirm":true}`,
		`{"supi":"imsi-001010000000001","fields":{},"confirm":true}`,
		`{"supi":"imsi-001010000000001","fields":{"ambr_dl":"fast"},"confirm":true}`,
		`{"supi":"imsi-001010000000001","fields":{"slices":[{"sst":1,"sd":"zz"}]},"confirm":true}`,
		`{"supi":"imsi-001010000000001","fields":{"slices":[]},"confirm":true}`,
		`{"supi":"imsi-001010000000001","fields":{"slices":[{"sst":1,"extra":1}]},"confirm":true}`,
	} {
		raw, _ := h.call(guard.RoleAdmin, "subscriber_profile_update", args)
		if !strings.Contains(raw, "-32602") {
			t.Errorf("%s: %s", args, raw)
		}
	}
	if len(h.store.calls) != 0 {
		t.Errorf("no upstream call expected: %v", h.store.calls)
	}
}

func TestSubscriberProfileUpdateDryRunAndApply(t *testing.T) {
	const supi = "imsi-001010000000001"
	h := newHarness(t, guard.ModeOperator, supi)
	args := `{"supi":"` + supi + `","fields":{"ambr_dl":"200 Mbps"}`
	raw, _ := h.call(guard.RoleOperator, "subscriber_profile_update", args+`}`)
	if !strings.Contains(raw, "dry_run") || !strings.Contains(raw, "ue_will_be_deregistered") ||
		!strings.Contains(raw, "TS 23.502 §4.2.2.3.3") {
		t.Errorf("dry-run: %s", raw)
	}
	if h.store.count("PUT /api/v1/subscribers/"+supi) != 0 || h.store.count("GET /api/v1/subscribers/"+supi) != 1 {
		t.Errorf("dry-run must GET once and never PUT: %v", h.store.calls)
	}
	raw, _ = h.call(guard.RoleOperator, "subscriber_profile_update", args+`,"confirm":true}`)
	if !strings.Contains(raw, `\"updated\": true`) || !strings.Contains(raw, "100000") {
		t.Errorf("apply: %s", raw)
	}
	var put map[string]any
	_ = json.Unmarshal([]byte(h.store.body("PUT /api/v1/subscribers/"+supi)), &put)
	if put["ambr_dl"] != float64(200000) || put["ambr_ul"] != float64(50000) || put["k"] != testK || put["opc"] != testOPc {
		t.Errorf("PUT body must be the whole merged record with keys carried: %v", put)
	}
	if strings.Contains(raw, testK) || strings.Contains(raw, testOPc) {
		t.Errorf("keys leaked: %s", raw)
	}
}

func TestSubscriberProfileUpdateUnknownSubscriber(t *testing.T) {
	h := newHarness(t, guard.ModeOperator)
	raw, _ := h.call(guard.RoleOperator, "subscriber_profile_update",
		`{"supi":"imsi-001010000000099","fields":{"ambr_dl":"1 Mbps"},"confirm":true}`)
	if !strings.Contains(raw, "-32000") || !strings.Contains(raw, "404") {
		t.Errorf("unknown subscriber: %s", raw)
	}
	if h.store.count("PUT /api/v1/subscribers/imsi-001010000000099") != 0 {
		t.Error("no PUT expected")
	}
}

func TestSubscriberProvisionValidation(t *testing.T) {
	h := newHarness(t, guard.ModeLab)
	base := func(k, opc, extra string) string {
		return `{"supi":"imsi-001010000000077","k":"` + k + `","opc":"` + opc + `"` + extra + `,"confirm":true}`
	}
	for name, args := range map[string]string{
		"short k":   base("00112233445566778899aabbccddee", testOPc, ""),
		"non-hex k": base("00112233445566778899aabbccddeegg", testOPc, ""),
		"short opc": base(testK, "ffeeddccbbaa998877665544332211", ""),
		"bad sqn":   base(testK, testOPc, `,"sqn":"12"`),
		"bad amf":   base(testK, testOPc, `,"amf":"zz"`),
		"bad ambr":  base(testK, testOPc, `,"profile":{"ambr_ul":"fast"}`),
		"bad prof":  base(testK, testOPc, `,"profile":{"k":"x"}`),
		"bad supi":  `{"supi":"nope","k":"` + testK + `","opc":"` + testOPc + `","confirm":true}`,
		"no k":      `{"supi":"imsi-001010000000077","opc":"` + testOPc + `","confirm":true}`,
	} {
		raw, _ := h.call(guard.RoleAdmin, "subscriber_provision", args)
		if !strings.Contains(raw, "-32602") {
			t.Errorf("%s: want -32602, got %s", name, raw)
		}
		if strings.Contains(raw, testK) || strings.Contains(raw, testOPc) {
			t.Errorf("%s: key echoed: %s", name, raw)
		}
	}
	if len(h.store.calls) != 0 {
		t.Errorf("no upstream call expected: %v", h.store.calls)
	}
}

func TestSubscriberProvisionRoleAndMode(t *testing.T) {
	args := `{"supi":"imsi-001010000000077","k":"` + testK + `","opc":"` + testOPc + `","confirm":true}`
	h := newHarness(t, guard.ModeOperator)
	raw, _ := h.call(guard.RoleAdmin, "subscriber_provision", args)
	if !strings.Contains(raw, "access_mode operator does not allow it") {
		t.Errorf("operator mode: %s", raw)
	}
	h = newHarness(t, guard.ModeLab)
	for _, role := range []guard.Role{guard.RoleOperator, guard.RoleViewer} {
		raw, _ = h.call(role, "subscriber_provision", args)
		if !strings.Contains(raw, "role "+string(role)) {
			t.Errorf("role %s: %s", role, raw)
		}
	}
	if len(h.store.calls) != 0 {
		t.Errorf("no portal call expected: %v", h.store.calls)
	}
}

func TestSubscriberProvisionDeleteLifecycle(t *testing.T) {
	const supi = "imsi-001010000000077"
	h := newHarness(t, guard.ModeLab)
	prov := `{"supi":"` + supi + `","k":"` + testK + `","opc":"` + testOPc + `","sqn":"000000000020","amf":"8000","profile":{"ambr_ul":"50 Mbps","ambr_dl":"100 Mbps","slices":[{"sst":1,"sd":"000001","dnn":"internet"}]}`
	raw, _ := h.call(guard.RoleAdmin, "subscriber_provision", prov+`}`)
	if !strings.Contains(raw, "dry_run") || h.store.count("POST /api/v1/subscribers") != 0 {
		t.Fatalf("dry-run: %s", raw)
	}
	raw, _ = h.call(guard.RoleAdmin, "subscriber_provision", prov+`,"confirm":true}`)
	if !strings.Contains(raw, `\"created\": true`) || h.store.count("POST /api/v1/subscribers") != 1 {
		t.Fatalf("provision: %s", raw)
	}
	var posted map[string]any
	_ = json.Unmarshal([]byte(h.store.body("POST /api/v1/subscribers")), &posted)
	if posted["k"] != testK || posted["opc"] != testOPc || posted["sqn"] != "000000000020" || posted["ambr_dl"] != float64(100000) {
		t.Errorf("POST body: %v", posted)
	}
	// delete dry-run, then delete, then 404 on a repeat.
	raw, _ = h.call(guard.RoleAdmin, "subscriber_delete", `{"supi":"`+supi+`"}`)
	if !strings.Contains(raw, "dry_run") || h.store.count("DELETE /api/v1/subscribers/"+supi) != 0 {
		t.Fatalf("delete dry-run: %s", raw)
	}
	if strings.Contains(raw, testK) || strings.Contains(raw, testOPc) {
		t.Errorf("delete plan leaked keys: %s", raw)
	}
	raw, _ = h.call(guard.RoleAdmin, "subscriber_delete", `{"supi":"`+supi+`","confirm":true}`)
	if !strings.Contains(raw, `\"deleted\": true`) {
		t.Fatalf("delete: %s", raw)
	}
	raw, _ = h.call(guard.RoleAdmin, "subscriber_delete", `{"supi":"`+supi+`","confirm":true}`)
	if !strings.Contains(raw, "-32000") || !strings.Contains(raw, "subscriber not found") {
		t.Errorf("delete unknown: %s", raw)
	}
	if h.store.count("DELETE /api/v1/subscribers/"+supi) != 1 {
		t.Errorf("unknown SUPI must not be sent as DELETE: %v", h.store.calls)
	}
	raw, _ = h.call(guard.RoleAdmin, "subscriber_delete", `{"supi":"`+supi+`"}`)
	if !strings.Contains(raw, "-32000") || !strings.Contains(raw, "not found") {
		t.Errorf("delete plan for unknown must be refused: %s", raw)
	}
	raw, _ = h.call(guard.RoleAdmin, "subscriber_delete", `{"supi":"bad","confirm":true}`)
	if !strings.Contains(raw, "-32602") {
		t.Errorf("bad supi: %s", raw)
	}
}

func TestSubscriberProvisionConflictDoesNotEchoKeys(t *testing.T) {
	const supi = "imsi-001010000000077"
	h := newHarness(t, guard.ModeLab)
	h.store.force["POST /api/v1/subscribers"] = http.StatusConflict
	raw, _ := h.call(guard.RoleAdmin, "subscriber_provision",
		`{"supi":"`+supi+`","k":"`+testK+`","opc":"`+testOPc+`","confirm":true}`)
	if !strings.Contains(raw, "-32000") || !strings.Contains(raw, "409") {
		t.Errorf("conflict: %s", raw)
	}
	assertNoKeys(t, "conflict", raw, h)
}

func assertNoKeys(t *testing.T, where, out string, h *harness) {
	t.Helper()
	auditJSON, _ := json.Marshal(h.g.Audit().Recent(256))
	for name, text := range map[string]string{"result": out, "audit": string(auditJSON), "slog": h.logs.String()} {
		for _, secret := range []string{testK, testOPc, "000000000020"} {
			if strings.Contains(strings.ToLower(text), secret) {
				t.Errorf("%s: %s leaks %s:\n%s", where, name, secret, text)
			}
		}
	}
}

// TestSubscriberProvisionKeyLeak runs subscriber_provision through the dispatcher,
// the guard and a captured slog handler on the success, dry-run, validation,
// refusal and upstream-failure paths. The key hex must appear nowhere: not in a
// result, a plan, an error, an audit entry or a log line.
func TestSubscriberProvisionKeyLeak(t *testing.T) {
	h := newHarness(t, guard.ModeLab)
	args := `{"supi":"imsi-001010000000077","k":"` + testK + `","opc":"` + testOPc + `","sqn":"000000000020","amf":"8000"`
	var outs []string
	run := func(role guard.Role, a string) {
		raw, _ := h.call(role, "subscriber_provision", a)
		outs = append(outs, raw)
	}
	run(guard.RoleAdmin, args+`}`)                   // dry-run
	run(guard.RoleAdmin, args+`,"confirm":true}`)    // success
	run(guard.RoleOperator, args+`,"confirm":true}`) // refused by role
	run(guard.RoleViewer, args+`}`)                  // refused by role (dry-run path)
	run(guard.RoleAdmin, `{"supi":"imsi-001010000000077","k":"`+testK+`","opc":"short","confirm":true}`)
	h.store.force["POST /api/v1/subscribers"] = http.StatusBadRequest
	run(guard.RoleAdmin, args+`,"confirm":true}`) // upstream failure
	for i, o := range outs {
		assertNoKeys(t, "provision path "+string(rune('0'+i)), o, h)
	}
	if got := len(h.g.Audit().Recent(256)); got < 4 {
		t.Errorf("audit entries: %d, want at least 4 (dry_run, executed, refused, failed)", got)
	}
}

// TestSubscriberProfileUpdateKeyLeak: the record read for the whole-record PUT holds
// the keys; they must not surface anywhere.
func TestSubscriberProfileUpdateKeyLeak(t *testing.T) {
	const supi = "imsi-001010000000001"
	h := newHarness(t, guard.ModeLab, supi)
	a := `{"supi":"` + supi + `","fields":{"ambr_ul":"60 Mbps"}`
	var outs []string
	for _, args := range []string{a + `}`, a + `,"confirm":true}`,
		`{"supi":"` + supi + `","fields":{"k":"` + testK + `"},"confirm":true}`} {
		raw, _ := h.call(guard.RoleAdmin, "subscriber_profile_update", args)
		outs = append(outs, raw)
	}
	h.store.force["PUT /api/v1/subscribers/"+supi] = http.StatusInternalServerError
	raw, _ := h.call(guard.RoleAdmin, "subscriber_profile_update", a+`,"confirm":true}`)
	outs = append(outs, raw)
	for _, o := range outs {
		assertNoKeys(t, "profile update", o, h)
	}
}

func TestRedactArgsKeepsHashStable(t *testing.T) {
	tl := toolsOf(t)["subscriber_provision"]
	a1 := json.RawMessage(`{"supi":"imsi-1","k":"` + testK + `","opc":"` + testOPc + `"}`)
	a2 := json.RawMessage(`{"supi":"imsi-1","k":"` + testOPc + `","opc":"` + testK + `"}`)
	if guard.HashFor(tl, a1) != guard.HashFor(tl, a2) {
		t.Error("the audit hash must not depend on key values")
	}
	if _, ok := tl.(registry.Redactor); !ok {
		t.Error("subscriber_provision must implement registry.Redactor")
	}
}

func TestBitRateToKbps(t *testing.T) {
	ok := map[string]uint64{
		"1000 bps": 1, "1 Kbps": 1, "100 Kbps": 100, "200 Mbps": 200000, "1.5 Mbps": 1500,
		"2 Gbps": 2000000, "1 Tbps": 1000000000, "0.001 Gbps": 1000, "1.000 Kbps": 1,
	}
	for in, want := range ok {
		got, err := bitRateToKbps(in)
		if err != nil || got != want {
			t.Errorf("%q: got %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"500 bps", "1.5 Kbps", "0 Mbps", "0 bps", "fast", "", "100", "100 mbps",
		"-1 Mbps", "1.0000000000001 Mbps", "99999999999999999999 Tbps"} {
		if v, err := bitRateToKbps(in); err == nil {
			t.Errorf("%q: want error, got %d", in, v)
		}
	}
}

// TestSubscriberAmbrConvertedToKbps: the tools accept BitRate strings and the portal
// receives integer kbps (live defect: "200 Mbps" gave a portal 400).
func TestSubscriberAmbrConvertedToKbps(t *testing.T) {
	const supi = "imsi-001010000000001"
	h := newHarness(t, guard.ModeOperator, supi)
	args := `{"supi":"` + supi + `","fields":{"ambr_dl":"200 Mbps","ambr_ul":"1.5 Mbps"}`
	raw, _ := h.call(guard.RoleOperator, "subscriber_profile_update", args+`}`)
	for _, w := range []string{"to_bitrate", "200 Mbps", "200000", "1500", "kbps", "100000"} {
		if !strings.Contains(raw, w) {
			t.Errorf("dry-run lacks %q: %s", w, raw)
		}
	}
	raw, _ = h.call(guard.RoleOperator, "subscriber_profile_update", args+`,"confirm":true}`)
	if !strings.Contains(raw, `\"updated\": true`) {
		t.Fatalf("apply: %s", raw)
	}
	var put map[string]any
	_ = json.Unmarshal([]byte(h.store.body("PUT /api/v1/subscribers/"+supi)), &put)
	if put["ambr_dl"] != float64(200000) || put["ambr_ul"] != float64(1500) {
		t.Errorf("PUT ambr must be integer kbps: %v", put)
	}
	for name, a := range map[string]string{
		"500 bps": `{"supi":"` + supi + `","fields":{"ambr_dl":"500 bps"},"confirm":true}`,
		"1.5Kbps": `{"supi":"` + supi + `","fields":{"ambr_dl":"1.5 Kbps"},"confirm":true}`,
		"zero":    `{"supi":"` + supi + `","fields":{"ambr_ul":"0 Mbps"},"confirm":true}`,
	} {
		if r, _ := h.call(guard.RoleOperator, "subscriber_profile_update", a); !strings.Contains(r, "-32602") {
			t.Errorf("%s: want -32602, got %s", name, r)
		}
	}
}

// TestSubscriberProvisionRefusesExisting: the portal POST is an upsert, so an
// existing SUPI is refused on the dry-run and the confirm path with 0 POSTs.
func TestSubscriberProvisionRefusesExisting(t *testing.T) {
	const supi = "imsi-001010000000001"
	h := newHarness(t, guard.ModeLab, supi)
	args := `{"supi":"` + supi + `","k":"` + testK + `","opc":"` + testOPc + `"`
	for _, a := range []string{args + `}`, args + `,"confirm":true}`} {
		raw, _ := h.call(guard.RoleAdmin, "subscriber_provision", a)
		if !strings.Contains(raw, "-32000") || !strings.Contains(raw, "subscriber already exists") {
			t.Errorf("want refusal, got %s", raw)
		}
		assertNoKeys(t, "existing", raw, h)
	}
	if n := h.store.count("POST /api/v1/subscribers"); n != 0 {
		t.Errorf("POSTs = %d, want 0", n)
	}
	if h.store.subs[supi]["k"] != testK {
		t.Error("record was modified")
	}
}

// TestSubscriberProvisionGetErrorRefuses: a GET failure other than 404 never lets
// the POST go out blind.
func TestSubscriberProvisionGetErrorRefuses(t *testing.T) {
	const supi = "imsi-001010000000077"
	h := newHarness(t, guard.ModeLab)
	h.store.force["GET /api/v1/subscribers/"+supi] = http.StatusInternalServerError
	args := `{"supi":"` + supi + `","k":"` + testK + `","opc":"` + testOPc + `"`
	for _, a := range []string{args + `}`, args + `,"confirm":true}`} {
		raw, _ := h.call(guard.RoleAdmin, "subscriber_provision", a)
		if !strings.Contains(raw, "-32000") {
			t.Errorf("want -32000, got %s", raw)
		}
		assertNoKeys(t, "get error", raw, h)
	}
	if n := h.store.count("POST /api/v1/subscribers"); n != 0 {
		t.Errorf("POSTs = %d, want 0", n)
	}
}

func TestSubscriberProvisionPlanShowsNotExisting(t *testing.T) {
	h := newHarness(t, guard.ModeLab)
	raw, _ := h.call(guard.RoleAdmin, "subscriber_provision",
		`{"supi":"imsi-001010000000077","k":"`+testK+`","opc":"`+testOPc+`"}`)
	if !strings.Contains(raw, "dry_run") || !strings.Contains(raw, `\"exists\": false`) {
		t.Errorf("plan: %s", raw)
	}
}

func TestSubscriberDeleteUnknownRefused(t *testing.T) {
	h := newHarness(t, guard.ModeLab)
	for _, a := range []string{`{"supi":"imsi-001010000000099"}`, `{"supi":"imsi-001010000000099","confirm":true}`} {
		raw, _ := h.call(guard.RoleAdmin, "subscriber_delete", a)
		if !strings.Contains(raw, "-32000") || !strings.Contains(raw, "subscriber not found") {
			t.Errorf("%s: %s", a, raw)
		}
	}
	if n := h.store.count("DELETE /api/v1/subscribers/imsi-001010000000099"); n != 0 {
		t.Errorf("DELETEs = %d, want 0", n)
	}
}

func TestSubscriberUnknownTopLevelArgsRejected(t *testing.T) {
	const supi = "imsi-001010000000001"
	h := newHarness(t, guard.ModeLab, supi)
	prov := `"supi":"imsi-001010000000077","k":"` + testK + `","opc":"` + testOPc + `"`
	cases := []struct{ tool, args, want string }{
		{"subscriber_provision", `{` + prov + `,"overwrite":true,"confirm":true}`, "overwrite"},
		{"subscriber_provision", `{` + prov + `,"OP":"` + testK + `","confirm":true}`, "unsupported argument"},
		{"subscriber_profile_update", `{"supi":"` + supi + `","fields":{"ambr_dl":"1 Mbps"},"force":1,"confirm":true}`, "force"},
		{"subscriber_delete", `{"supi":"` + supi + `","all":true,"confirm":true}`, "all"},
	}
	for _, c := range cases {
		raw, _ := h.call(guard.RoleAdmin, c.tool, c.args)
		if !strings.Contains(raw, "-32602") || !strings.Contains(raw, c.want) {
			t.Errorf("%s: %s", c.tool, raw)
		}
		if strings.Contains(raw, testK) {
			t.Errorf("%s echoed a value: %s", c.tool, raw)
		}
	}
	// A secret-looking key is never named.
	raw, _ := h.call(guard.RoleAdmin, "subscriber_provision", `{`+prov+`,"SQN2":"x","Op":"y","confirm":true}`)
	if strings.Contains(raw, `\"Op\"`) {
		t.Errorf("secret-looking key echoed: %s", raw)
	}
	if len(h.store.calls) != 0 {
		t.Errorf("no upstream call expected: %v", h.store.calls)
	}
}

// TestSubscriberProfileUpdateScrubsSQN: sqn from the record is scrubbed from an upstream error.
func TestSubscriberProfileUpdateScrubsSQN(t *testing.T) {
	const supi = "imsi-001010000000001"
	h := newHarness(t, guard.ModeLab, supi)
	h.store.subs[supi]["sqn"] = "0123456789ab"
	h.store.force["PUT /api/v1/subscribers/"+supi] = http.StatusInternalServerError
	got := portalFailure("t", 500, json.RawMessage(`{"error":"bad sqn 0123456789ab"}`), recordSecrets(h.store.subs[supi])...)
	if strings.Contains(got.Error(), "0123456789ab") || strings.Contains(got.Error(), testK) {
		t.Errorf("not scrubbed: %v", got)
	}
}
