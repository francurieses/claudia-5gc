package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/guard"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

// reply is a canned upstream answer.
type reply struct {
	status int
	body   string
	header map[string]string
}

// routed is an upstream that answers by "METHOD path" and records every request.
type routed struct {
	mu     sync.Mutex
	calls  []string
	bodies map[string]string
	auth   map[string]string
	routes map[string]reply
}

func (r *routed) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	key := req.Method + " " + req.URL.Path
	r.mu.Lock()
	r.calls = append(r.calls, key)
	r.bodies[key] = string(b)
	r.auth[key] = req.Header.Get("Authorization")
	rep, ok := r.routes[key]
	r.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	for k, v := range rep.header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(rep.status)
	_, _ = w.Write([]byte(rep.body))
}

func (r *routed) count(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

const (
	testSUPI = "imsi-001010000000001"
	amfCtx   = "/amf/v1/ue-contexts/" + testSUPI
	nefSubs  = "/3gpp-as-session-with-qos/v1/as-1/subscriptions"
	smsPath  = "/nsmsf-sms-internal/v1/ue-contexts/" + testSUPI + "/mt-sms"
)

func ctxBody(cm string, psis string) string {
	return `{"supi":"` + testSUPI + `","gmm_state":"5GMM-REGISTERED","cm_state":"` + cm + `","pdu_session_ids":` + psis + `}`
}

func netHarness(t *testing.T, routes map[string]reply) (map[string]registry.Tool, *routed, *guard.Guard) {
	t.Helper()
	up := &routed{routes: routes, bodies: map[string]string{}, auth: map[string]string{}}
	srv := httptest.NewServer(up)
	t.Cleanup(srv.Close)
	tools := map[string]registry.Tool{}
	for _, tl := range All(Deps{
		AMF:    clients.NewAMF(srv.URL, srv.Client()),
		SMF:    clients.NewSMF(srv.URL, srv.Client()),
		Portal: clients.NewPortal(srv.URL, srv.Client()),
		NEF:    clients.NewNEF(srv.URL, srv.Client(), staticToken("tok-abc")),
		SMSF:   clients.NewSMSF(srv.URL, srv.Client()),
	}) {
		tools[tl.Name()] = tl
	}
	g := guard.New(guard.Options{Mode: guard.ModeLab, MinInterval: time.Nanosecond}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return tools, up, g
}

// runx is run, but a guard refusal (including a failed Plan) comes back as err.
func runx(t *testing.T, g *guard.Guard, tl registry.Tool, args string) (any, *guard.Decision, error) {
	t.Helper()
	out, d, err := run(t, g, tl, args)
	if d != nil && d.Verdict == guard.Refused {
		return nil, d, d.Err
	}
	return out, d, err
}

func ok(body string) reply { return reply{status: 200, body: body} }

const smfSessions = `{"count":2,"sessions":[{"supi":"imsi-001010000000001","ueIp":"10.60.0.1"},{"supi":"imsi-001010000000002","ueIp":"10.60.0.2"}]}`

func TestNetctlDryRunSendsNothingToMutatingUpstreams(t *testing.T) {
	routes := map[string]reply{
		"GET " + amfCtx:                    ok(ctxBody("CM-CONNECTED", "[1,2]")),
		"GET /nsmf-management/v1/sessions": ok(smfSessions),
		"GET " + nefSubs + "/sub-1":        ok(`{"subscriptionId":"sub-1"}`),
	}
	tools, up, g := netHarness(t, routes)
	for _, c := range []struct{ tool, args, forbidden string }{
		{"ue_an_release_nw", `{"supi":"` + testSUPI + `"}`, "POST " + amfCtx + "/an-release"},
		{"ue_location_get", `{"supi":"` + testSUPI + `"}`, "GET /api/v1/location"},
		{"af_qos_session_create", `{"scs_as_id":"as-1","ue_ipv4":"10.60.0.1","qos_reference":"q1"}`, "POST " + nefSubs},
		{"af_qos_session_delete", `{"scs_as_id":"as-1","subscription_id":"sub-1"}`, "DELETE "},
		{"pws_resend", `{"message_identifier":4370,"serial_number":16384}`, "POST /api/v1/pws/resend"},
		{"sms_send_mt", `{"supi":"` + testSUPI + `","payload_b64":"AQIDBA=="}`, "POST " + smsPath},
	} {
		out, d, err := runx(t, g, tools[c.tool], c.args)
		if err != nil || out != nil {
			t.Fatalf("%s: dry-run must not execute (out=%v err=%v)", c.tool, out, err)
		}
		if d.Verdict != guard.DryRun {
			t.Errorf("%s: verdict %v, want DryRun", c.tool, d.Verdict)
		}
		if n := up.count(c.forbidden); n != 0 {
			t.Errorf("%s: dry-run reached %s (%d)", c.tool, c.forbidden, n)
		}
	}
	if n := up.count("POST /oauth2"); n != 0 {
		t.Errorf("dry-run requested a token %d times", n)
	}
}

func TestANReleaseDryRunPlanAndConfirmed(t *testing.T) {
	routes := map[string]reply{
		"GET " + amfCtx:                  ok(ctxBody("CM-CONNECTED", "[1,2]")),
		"POST " + amfCtx + "/an-release": {status: 202, body: `{"accepted":true,"previous_cm_state":"CM-CONNECTED","affected_pdu_sessions":[1,2]}`},
	}
	tools, up, g := netHarness(t, routes)
	plan, err := tools["ue_an_release_nw"].(registry.Planner).Plan(operator(), json.RawMessage(`{"supi":"`+testSUPI+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	p := plan.(map[string]any)
	if p["previous_cm_state"] != "CM-CONNECTED" || len(p["affected_pdu_sessions"].([]int)) != 2 {
		t.Errorf("plan: %v", p)
	}
	out, _, err := runx(t, g, tools["ue_an_release_nw"], `{"supi":"`+testSUPI+`","confirm":true}`)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["accepted"] != true || m["previous_cm_state"] != "CM-CONNECTED" || !strings.Contains(m["spec_ref"].(string), "TS 23.502 §4.2.6") {
		t.Errorf("result: %v", m)
	}
	if got := m["affected_pdu_sessions"].([]int); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("sessions: %v", got)
	}
	if n := up.count("POST " + amfCtx + "/an-release"); n != 1 {
		t.Errorf("an-release POSTs: %d", n)
	}
}

func TestANReleaseRefusals(t *testing.T) {
	cases := []struct {
		name   string
		routes map[string]reply
		args   string
		code   int
		msg    string
	}{
		{"idle", map[string]reply{"GET " + amfCtx: ok(ctxBody("CM-IDLE", "[1]"))}, `{"supi":"` + testSUPI + `","confirm":true}`, mcperr.CodeToolError, "CM-IDLE"},
		{"idle short", map[string]reply{"GET " + amfCtx: ok(ctxBody("IDLE", "[]"))}, `{"supi":"` + testSUPI + `","confirm":true}`, mcperr.CodeToolError, "CM-IDLE"},
		{"unknown state", map[string]reply{"GET " + amfCtx: ok(ctxBody("", "[]"))}, `{"supi":"` + testSUPI + `","confirm":true}`, mcperr.CodeToolError, "unknown"},
		{"unknown ue", map[string]reply{}, `{"supi":"` + testSUPI + `","confirm":true}`, mcperr.CodeToolError, "UE not found"},
		{"409", map[string]reply{"GET " + amfCtx: ok(ctxBody("CM-CONNECTED", "[]")), "POST " + amfCtx + "/an-release": {status: 409, body: "busy"}},
			`{"supi":"` + testSUPI + `","confirm":true}`, mcperr.CodeToolError, "409"},
		{"503", map[string]reply{"GET " + amfCtx: ok(ctxBody("CM-CONNECTED", "[]")), "POST " + amfCtx + "/an-release": {status: 503, body: "no gnb"}},
			`{"supi":"` + testSUPI + `","confirm":true}`, mcperr.CodeToolError, "503"},
		{"bad supi", map[string]reply{}, `{"supi":"not-a-supi","confirm":true}`, mcperr.CodeInvalidParams, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tools, up, g := netHarness(t, c.routes)
			_, _, err := runx(t, g, tools["ue_an_release_nw"], c.args)
			if err == nil {
				t.Fatal("want error")
			}
			if codeOf(t, err) != c.code || !strings.Contains(err.Error(), c.msg) {
				t.Errorf("got %v, want code %d containing %q", err, c.code, c.msg)
			}
			if c.name != "409" && c.name != "503" && up.count("POST") != 0 {
				t.Errorf("POST sent: %v", up.calls)
			}
		})
	}
}

func TestLocationConfirmedMapsPortalReply(t *testing.T) {
	routes := map[string]reply{
		"GET /api/v1/location/ue/" + testSUPI: ok(`{"supi":"` + testSUPI + `","reachable":true,"latitude":40.4168,"longitude":-3.7038,"accuracy_m":50,"nr_cell_id":"000000010","tac":"000001"}`),
	}
	tools, up, g := netHarness(t, routes)
	out, _, err := runx(t, g, tools["ue_location_get"], `{"supi":"`+testSUPI+`","confirm":true}`)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	for _, k := range []string{"reachable", "latitude", "longitude", "accuracy_m", "nr_cell_id", "tac"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
	if m["reachable"] != true || m["nr_cell_id"] != "000000010" || m["latitude"] != 40.4168 {
		t.Errorf("result: %v", m)
	}
	if up.count("GET /api/v1/location/ue/"+testSUPI) != 1 {
		t.Errorf("calls: %v", up.calls)
	}
}

func TestLocationPlanRefusesUnknownUEAndPortalErrorCarriesStatus(t *testing.T) {
	tools, up, g := netHarness(t, map[string]reply{})
	_, _, err := runx(t, g, tools["ue_location_get"], `{"supi":"`+testSUPI+`"}`)
	if err == nil || codeOf(t, err) != mcperr.CodeToolError {
		t.Fatalf("want -32000, got %v", err)
	}
	if up.count("GET /api/v1/location") != 0 {
		t.Error("portal called for an unknown UE")
	}
	tools, _, g = netHarness(t, map[string]reply{"GET /api/v1/location/ue/" + testSUPI: {status: 502, body: "lmf down"}})
	_, _, err = runx(t, g, tools["ue_location_get"], `{"supi":"`+testSUPI+`","confirm":true}`)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("want 502 error, got %v", err)
	}
}

func TestAFQoSCreateConfirmed(t *testing.T) {
	routes := map[string]reply{
		"GET /nsmf-management/v1/sessions": ok(smfSessions),
		"POST " + nefSubs: {status: 201, body: `{"subscriptionId":"sub-1"}`,
			header: map[string]string{"Location": "https://nef:8011" + nefSubs + "/sub-1"}},
	}
	tools, up, g := netHarness(t, routes)
	out, _, err := runx(t, g, tools["af_qos_session_create"],
		`{"scs_as_id":"as-1","ue_ipv4":"10.60.0.1","qos_reference":"qos-gbr-1","flow_descriptions":["permit out ip from any to any"],"notification_destination":"http://af/cb","confirm":true}`)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["subscription_id"] != "sub-1" || m["accepted"] != true || m["self_link"] == "" {
		t.Errorf("result: %v", m)
	}
	if up.auth["POST "+nefSubs] != "Bearer tok-abc" {
		t.Errorf("auth: %q", up.auth["POST "+nefSubs])
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(up.bodies["POST "+nefSubs]), &body); err != nil {
		t.Fatal(err)
	}
	fi := body["flowInfo"].([]any)[0].(map[string]any)
	if body["ueIpv4Addr"] != "10.60.0.1" || body["qosReference"] != "qos-gbr-1" ||
		body["notificationDestination"] != "http://af/cb" || fi["flowId"] != float64(1) {
		t.Errorf("body: %v", body)
	}
}

func TestAFQoSCreateRefusalsAndValidation(t *testing.T) {
	tools, up, g := netHarness(t, map[string]reply{"GET /nsmf-management/v1/sessions": ok(smfSessions)})
	_, _, err := runx(t, g, tools["af_qos_session_create"], `{"scs_as_id":"as-1","ue_ipv4":"10.60.0.99","qos_reference":"q"}`)
	if err == nil || codeOf(t, err) != mcperr.CodeToolError {
		t.Errorf("unknown IP: %v", err)
	}
	for _, args := range []string{
		`{"scs_as_id":"as-1","ue_ipv4":"999.1.1.1","qos_reference":"q","confirm":true}`,
		`{"scs_as_id":"as-1","ue_ipv4":"::1","qos_reference":"q","confirm":true}`,
		`{"scs_as_id":"a/b","ue_ipv4":"10.60.0.1","qos_reference":"q","confirm":true}`,
		`{"scs_as_id":"as-1","ue_ipv4":"10.60.0.1","qos_reference":"","confirm":true}`,
		`{"scs_as_id":"as-1","ue_ipv4":"10.60.0.1","qos_reference":"q","notification_destination":"ftp://x","confirm":true}`,
	} {
		if _, _, err := runx(t, g, tools["af_qos_session_create"], args); err == nil || codeOf(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602, got %v", args, err)
		}
	}
	if up.count("POST") != 0 {
		t.Errorf("POST sent: %v", up.calls)
	}
}

func TestAFQoSCreateNEFErrorCarriesStatus(t *testing.T) {
	tools, _, g := netHarness(t, map[string]reply{
		"GET /nsmf-management/v1/sessions": ok(smfSessions),
		"POST " + nefSubs:                  {status: 401, body: `{"cause":"UNAUTHORIZED"}`},
	})
	_, _, err := runx(t, g, tools["af_qos_session_create"], `{"scs_as_id":"as-1","ue_ipv4":"10.60.0.1","qos_reference":"q","confirm":true}`)
	var e *mcperr.Error
	if !errors.As(err, &e) || e.Code != mcperr.CodeToolError || !strings.Contains(e.Message, "401") {
		t.Fatalf("got %v", err)
	}
}

func TestAFQoSGetAndDelete(t *testing.T) {
	routes := map[string]reply{
		"GET " + nefSubs + "/sub-1":    ok(`{"subscriptionId":"sub-1"}`),
		"DELETE " + nefSubs + "/sub-1": {status: 204},
		"GET " + nefSubs + "/gone":     {status: 404, body: `{"cause":"CONTEXT_NOT_FOUND"}`},
	}
	tools, up, g := netHarness(t, routes)
	if _, _, err := runx(t, g, tools["af_qos_session_get"], `{"scs_as_id":"as-1","subscription_id":"sub-1"}`); err != nil {
		t.Fatal(err)
	}
	if up.auth["GET "+nefSubs+"/sub-1"] != "Bearer tok-abc" {
		t.Error("get without bearer")
	}
	_, _, err := runx(t, g, tools["af_qos_session_get"], `{"scs_as_id":"as-1","subscription_id":"gone"}`)
	if err == nil || codeOf(t, err) != mcperr.CodeToolError || !strings.Contains(err.Error(), "404") {
		t.Errorf("get 404: %v", err)
	}
	out, _, err := runx(t, g, tools["af_qos_session_delete"], `{"scs_as_id":"as-1","subscription_id":"sub-1","confirm":true}`)
	if err != nil || out.(map[string]any)["deleted"] != true {
		t.Fatalf("delete: %v %v", out, err)
	}
	if up.count("DELETE "+nefSubs+"/sub-1") != 1 {
		t.Errorf("calls: %v", up.calls)
	}
	// Plan of a missing subscription is refused.
	_, _, err = runx(t, g, tools["af_qos_session_delete"], `{"scs_as_id":"as-1","subscription_id":"gone"}`)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("delete plan 404: %v", err)
	}
	if _, _, err = runx(t, g, tools["af_qos_session_get"], `{"scs_as_id":"as-1","subscription_id":"a b"}`); err == nil || codeOf(t, err) != mcperr.CodeInvalidParams {
		t.Errorf("bad id: %v", err)
	}
}

func TestPWSResend(t *testing.T) {
	tools, up, g := netHarness(t, map[string]reply{"POST /api/v1/pws/resend": ok(`{"status":"sent"}`)})
	out, _, err := runx(t, g, tools["pws_resend"], `{"message_identifier":4370,"serial_number":16384,"confirm":true}`)
	if err != nil || out.(map[string]any)["resent"] != true {
		t.Fatalf("resend: %v %v", out, err)
	}
	if got := up.bodies["POST /api/v1/pws/resend"]; got != `{"messageIdentifier":4370,"serialNumber":16384}` {
		t.Errorf("body: %s", got)
	}
	for _, args := range []string{
		`{"serial_number":1,"confirm":true}`,
		`{"message_identifier":65536,"serial_number":1,"confirm":true}`,
		`{"message_identifier":1,"serial_number":-1,"confirm":true}`,
	} {
		if _, _, err := runx(t, g, tools["pws_resend"], args); err == nil || codeOf(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%s: want -32602, got %v", args, err)
		}
	}
	tools, _, g = netHarness(t, map[string]reply{"POST /api/v1/pws/resend": {status: 404, body: "no stored broadcast"}})
	if _, _, err := runx(t, g, tools["pws_resend"], `{"message_identifier":1,"serial_number":2,"confirm":true}`); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("404: %v", err)
	}
}

func TestSMSSendMT(t *testing.T) {
	tools, up, g := netHarness(t, map[string]reply{"POST " + smsPath: {status: 202, body: `{"status":"delivered"}`}})
	out, _, err := runx(t, g, tools["sms_send_mt"], `{"supi":"`+testSUPI+`","payload_b64":"AQIDBA==","confirm":true}`)
	if err != nil || out.(map[string]any)["status"] != "delivered" {
		t.Fatalf("send: %v %v", out, err)
	}
	if got := up.bodies["POST "+smsPath]; got != `{"smsPayload":"AQIDBA=="}` {
		t.Errorf("body: %s", got)
	}

	big := base64.StdEncoding.EncodeToString(make([]byte, 256))
	max := base64.StdEncoding.EncodeToString(make([]byte, 255))
	for _, args := range []string{
		`{"supi":"` + testSUPI + `","payload_b64":"%%%not-base64%%%","confirm":true}`,
		`{"supi":"` + testSUPI + `","payload_b64":"AQIDBA","confirm":true}`, // unpadded: strict
		`{"supi":"` + testSUPI + `","payload_b64":"","confirm":true}`,
		`{"supi":"` + testSUPI + `","payload_b64":"` + big + `","confirm":true}`,
		`{"supi":"bad","payload_b64":"AQIDBA==","confirm":true}`,
	} {
		if _, _, err := runx(t, g, tools["sms_send_mt"], args); err == nil || codeOf(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%.60s: want -32602, got %v", args, err)
		}
	}
	if n := up.count("POST"); n != 1 {
		t.Errorf("upstream POSTs: %d, want only the valid one", n)
	}
	out, d, err := runx(t, g, tools["sms_send_mt"], `{"supi":"`+testSUPI+`","payload_b64":"`+max+`"}`)
	if err != nil || out != nil || d.Verdict != guard.DryRun {
		t.Errorf("255-byte dry run: %v %v %v", out, d, err)
	}
}

func TestSMSSendMTContextNotFound(t *testing.T) {
	tools, _, g := netHarness(t, map[string]reply{"POST " + smsPath: {status: 404, body: `{"cause":"CONTEXT_NOT_FOUND"}`}})
	_, _, err := runx(t, g, tools["sms_send_mt"], `{"supi":"`+testSUPI+`","payload_b64":"AQIDBA==","confirm":true}`)
	var e *mcperr.Error
	if !errors.As(err, &e) || e.Code != mcperr.CodeToolError || !strings.Contains(e.Message, "CONTEXT_NOT_FOUND") {
		t.Fatalf("got %v", err)
	}
	data := e.Data
	if data["cause"] != "CONTEXT_NOT_FOUND" || data["status"] != 404 {
		t.Errorf("data: %v", e.Data)
	}
}
