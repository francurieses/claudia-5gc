package status

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/francurieses/claudia-5gc/mcp/internal/clients"
	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
)

const (
	rsPortalJSON = `{"deployed":true,"link":{"state":"UP","reason":"ok","local_plmn":"001/001","partner_plmn":"001/002"},
"sepps":[{"name":"sepp","n32":{"local_plmn":"001/001","partners":[{"plmn":"001/002","state":"ESTABLISHED"}]}},
{"name":"hsepp","n32":{"local_plmn":"001/002","partners":[{"plmn":"001/001","state":"ESTABLISHED"}]}}]}`
	rsAMFJSON = `[{"supi":"imsi-001010000000001","gmm_state":"5GMM-REGISTERED","cm_state":"CM-CONNECTED"},
{"supi":"imsi-001020000000007","gmm_state":"5GMM-REGISTERED","cm_state":"CM-CONNECTED"},
{"supi":"nai-user@example.com"}]`
	rsSMFJSON = `{"sessions":[{"supi":"imsi-001020000000007","pduSessionId":1,"dnn":"internet","sNssai":{"sst":1,"sd":"000001"},"ueIp":"10.60.0.9","sessionState":"ACTIVE"},
{"supi":"imsi-001010000000001","pduSessionId":1,"dnn":"internet","sNssai":{"sst":1},"ueIp":"10.60.0.1","sessionState":"ACTIVE"}]}`
)

func vec(rows ...string) string {
	return `{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(rows, ",") + `]}}`
}

func row(v string, kv ...string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	b, _ := json.Marshal(m)
	return fmt.Sprintf(`{"metric":%s,"value":[1,"%s"]}`, b, v)
}

type rsUp struct {
	portal, prom, amf, smf string // "" = down
	portalCode             int    // non-zero: portal answers this HTTP status
	hits                   atomic.Int32
	nonGET                 atomic.Int32
}

// promHandler answers only the exact PromQL strings the tool sends; any other
// query fails the test.
func promHandler(t *testing.T, bodies map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		body, ok := bodies[q]
		if !ok {
			t.Errorf("unexpected PromQL query %q", q)
			http.Error(w, "unknown query", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(body))
	}
}

func rsDeps(t *testing.T, u *rsUp) Deps {
	t.Helper()
	mk := func(body string, prom bool, bodies map[string]string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u.hits.Add(1)
			if r.Method != http.MethodGet {
				u.nonGET.Add(1)
			}
			if prom {
				promHandler(t, bodies)(w, r)
				return
			}
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(s.Close)
		return s
	}
	down := func() string {
		s := httptest.NewServer(http.NotFoundHandler())
		url := s.URL
		s.Close()
		return url
	}
	d := Deps{}
	pick := func(body string, prom bool) string {
		if body == "" {
			return down()
		}
		return mk(body, prom, nil).URL
	}
	portalURL := down()
	if u.portal != "" {
		ps := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u.hits.Add(1)
			if r.Method != http.MethodGet {
				u.nonGET.Add(1)
			}
			if r.URL.Path != "/api/v1/roaming/status" {
				t.Errorf("portal path = %q, want /api/v1/roaming/status", r.URL.Path)
				http.NotFound(w, r)
				return
			}
			if u.portalCode != 0 {
				http.Error(w, "boom", u.portalCode)
				return
			}
			_, _ = w.Write([]byte(u.portal))
		}))
		t.Cleanup(ps.Close)
		portalURL = ps.URL
	}
	d.Portal = clients.NewPortal(portalURL, http.DefaultClient)
	d.AMF = clients.NewAMF(pick(u.amf, false), http.DefaultClient)
	d.SMF = clients.NewSMF(pick(u.smf, false), http.DefaultClient)
	if u.prom == "" {
		d.Prom = promclient.New(down(), http.DefaultClient, 0)
	} else {
		var bodies map[string]string
		_ = json.Unmarshal([]byte(u.prom), &bodies)
		d.Prom = promclient.New(mk("", true, bodies).URL, http.DefaultClient, 0)
	}
	return d
}

func rsPromAll() string {
	b, _ := json.Marshal(map[string]string{
		roamQueryEstablished: vec(
			row("1", "role", "sepp", "peer_plmn", "001/002"),
			row("1", "role", "hsepp", "peer_plmn", "001/001"),
			row("1", "role", "sepp", "peer_plmn", "other"),
			row("1", "role", "sepp", "peer_plmn", "unknown")),
		roamQueryHandshake: vec(
			row("3", "role", "sepp", "peer_plmn", "001/002", "result", "OK"),
			row("1", "role", "sepp", "peer_plmn", "001/002", "result", "REJECT")),
		roamQueryN32F: vec(
			row("7", "role", "sepp", "peer_plmn", "001/002", "direction", "OUT", "result", "OK"),
			row("5", "role", "sepp", "peer_plmn", "001/002", "direction", "IN", "result", "OK"),
			row("2", "role", "sepp", "peer_plmn", "001/002", "direction", "IN", "result", "REJECT"),
			row("9", "role", "sepp", "peer_plmn", "other", "direction", "IN", "result", "OK")),
		roamQueryTLSReject: vec(row("2", "role", "sepp", "reason", "not_partner")),
	})
	return string(b)
}

func invokeRS(t *testing.T, d Deps, args string) map[string]any {
	t.Helper()
	out, err := roamingStatusTool{d}.Invoke(context.Background(), json.RawMessage(args))
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func sub(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

func partnerSEPP(t *testing.T, m map[string]any, plmn, sepp string) map[string]any {
	t.Helper()
	ps, _ := m["partners"].([]any)
	for _, p := range ps {
		pm := p.(map[string]any)
		if pm["plmn"] != plmn {
			continue
		}
		for _, s := range pm["sepps"].([]any) {
			if sm := s.(map[string]any); sm["sepp"] == sepp {
				return sm
			}
		}
	}
	return nil
}

func plmns(m map[string]any) []string {
	var out []string
	for _, p := range m["partners"].([]any) {
		out = append(out, p.(map[string]any)["plmn"].(string))
	}
	return out
}

func TestRoamingStatusHappyPath(t *testing.T) {
	u := &rsUp{portal: rsPortalJSON, prom: rsPromAll(), amf: rsAMFJSON, smf: rsSMFJSON}
	m := invokeRS(t, rsDeps(t, u), `{}`)
	if m["deployed"] != true || m["local_plmn"] != "001-001" || sub(m, "link", "state") != "UP" {
		t.Fatalf("header: %v", m)
	}
	if got := plmns(m); len(got) != 1 || got[0] != "001-002" {
		t.Fatalf("partners (other/unknown must drop): %v", got)
	}
	s := partnerSEPP(t, m, "001-002", "sepp")
	if s == nil || s["context_state"] != "ESTABLISHED" || s["context_established"] != true {
		t.Fatalf("sepp: %v", s)
	}
	if hs := s["handshakes"].(map[string]any); hs["ok"] != 3.0 || hs["reject"] != 1.0 || hs["failure"] != 0.0 {
		t.Fatalf("handshakes: %v", hs)
	}
	if f := s["n32f"].(map[string]any); f["out_ok"] != 7.0 || f["in_ok"] != 5.0 || f["reject"] != 2.0 || f["failure"] != 0.0 {
		t.Fatalf("n32f: %v", f)
	}
	h := partnerSEPP(t, m, "001-002", "hsepp")
	if h == nil || h["context_established"] != true || h["context_state"] != "ESTABLISHED" {
		t.Fatalf("hsepp attach: %v", h)
	}
	if sub(m, "tls_rejects", "sepp", "not_partner") != 2.0 {
		t.Fatalf("tls_rejects: %v", m["tls_rejects"])
	}
	ues := sub(m, "roaming_ues").(map[string]any)
	if ues["available"] != true || ues["count"] != 1.0 {
		t.Fatalf("ues: %v", ues)
	}
	ue := ues["ues"].([]any)[0].(map[string]any)
	if ue["supi"] != "imsi-001020000000007" || ue["home_plmn"] != "001-002" {
		t.Fatalf("ue: %v", ue)
	}
	hr := sub(m, "home_routed_sessions").(map[string]any)
	if hr["count"] != 1.0 || hr["note"] == "" || sub(hr, "sessions") == nil {
		t.Fatalf("hr: %v", hr)
	}
	ss := hr["sessions"].([]any)[0].(map[string]any)
	if ss["supi"] != "imsi-001020000000007" || ss["home_plmn"] != "001-002" || ss["pdu_session_id"] != 1.0 ||
		ss["dnn"] != "internet" || sub(ss, "snssai", "sst") != 1.0 || sub(ss, "snssai", "sd") != "000001" ||
		ss["ue_ip"] != "10.60.0.9" || ss["state"] != "ACTIVE" {
		t.Fatalf("session: %v", ss)
	}
	for _, k := range []string{"portal", "prometheus", "amf", "smf"} {
		if sub(m, "sources", k) != "ok" {
			t.Fatalf("sources.%s = %v", k, sub(m, "sources", k))
		}
	}
	if u.nonGET.Load() != 0 {
		t.Fatal("non-GET request sent")
	}
}

func TestRoamingStatusFilterAndPadding(t *testing.T) {
	prom := rsPromAll()
	var b map[string]string
	_ = json.Unmarshal([]byte(prom), &b)
	b[roamQueryEstablished] = vec(row("1", "role", "sepp", "peer_plmn", "001/002"), row("1", "role", "sepp", "peer_plmn", "001/003"))
	nb, _ := json.Marshal(b)
	tests := []struct {
		args    string
		want    []string
		ueCount float64
	}{
		{`{"partner_plmn":"001-002"}`, []string{"001-002"}, 1},
		{`{"partner_plmn":"001-02"}`, []string{"001-002"}, 1},
		{`{"partner_plmn":"001-003"}`, []string{"001-003"}, 0},
		{`{"partner_plmn":"999-99"}`, nil, 0},
	}
	for _, tc := range tests {
		m := invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, prom: string(nb), amf: rsAMFJSON, smf: rsSMFJSON}), tc.args)
		got := plmns(m)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: partners %v want %v", tc.args, got, tc.want)
		}
		if sub(m, "roaming_ues", "count") != tc.ueCount || sub(m, "home_routed_sessions", "count") != tc.ueCount {
			t.Errorf("%s: counts ues=%v hr=%v", tc.args, sub(m, "roaming_ues", "count"), sub(m, "home_routed_sessions", "count"))
		}
	}
}

func TestRoamingStatusInvalidInput(t *testing.T) {
	for _, v := range []string{"1-2", "abc", "001/02", "001-2"} {
		u := &rsUp{portal: rsPortalJSON, prom: rsPromAll(), amf: rsAMFJSON, smf: rsSMFJSON}
		_, err := roamingStatusTool{rsDeps(t, u)}.Invoke(context.Background(), json.RawMessage(`{"partner_plmn":"`+v+`"}`))
		if err == nil || asCode(t, err) != mcperr.CodeInvalidParams {
			t.Errorf("%q: want invalid params, got %v", v, err)
		}
		if u.hits.Load() != 0 {
			t.Errorf("%q: upstream called", v)
		}
	}
}

func TestRoamingStatusD4NotDeployed(t *testing.T) {
	u := &rsUp{portal: `{"deployed":false,"link":{"state":"NOT_DEPLOYED"}}`, prom: promJSON(vec(), vec(), vec(), vec()), amf: `[]`, smf: `{}`}
	m := invokeRS(t, rsDeps(t, u), `{}`)
	if m["deployed"] != false || !strings.Contains(m["message"].(string), "--profile roaming") {
		t.Fatalf("D4: %v", m)
	}
	if len(m["partners"].([]any)) != 0 {
		t.Fatal("partners must be empty")
	}
}

func promJSON(est, hs, f, tls string) string {
	b, _ := json.Marshal(map[string]string{roamQueryEstablished: est, roamQueryHandshake: hs, roamQueryN32F: f, roamQueryTLSReject: tls})
	return string(b)
}

func TestRoamingStatusD2PortalDown(t *testing.T) {
	m := invokeRS(t, rsDeps(t, &rsUp{prom: rsPromAll(), amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	if sub(m, "sources", "portal") == "ok" || sub(m, "link", "state") != "" {
		t.Fatalf("portal src/link: %v", m)
	}
	s := partnerSEPP(t, m, "001-002", "sepp")
	if s == nil || s["context_state"] != nil || s["context_established"] != true || s["handshakes"] == nil {
		t.Fatalf("sepp: %v", s)
	}
	// D6: no local PLMN.
	if m["local_plmn"] != "" || sub(m, "roaming_ues", "available") != false ||
		sub(m, "roaming_ues", "error") != "local PLMN unknown" || sub(m, "home_routed_sessions", "error") != "local PLMN unknown" {
		t.Fatalf("D6: %v", m)
	}
	// One partner, no portal: hsepp attached.
	if partnerSEPP(t, m, "001-002", "hsepp") == nil {
		t.Fatal("hsepp must attach when exactly one partner")
	}
}

func TestRoamingStatusD3PromDown(t *testing.T) {
	m := invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	if sub(m, "sources", "prometheus") == "ok" || m["deployed"] != true {
		t.Fatalf("%v", m)
	}
	s := partnerSEPP(t, m, "001-002", "sepp")
	if s == nil || s["context_state"] != "ESTABLISHED" || s["context_established"] != nil || s["handshakes"] != nil || s["n32f"] != nil {
		t.Fatalf("sepp: %v", s)
	}
	if _, has := m["tls_rejects"]; has {
		t.Fatal("tls_rejects must be absent")
	}
}

func TestRoamingStatusD5BothDown(t *testing.T) {
	m := invokeRS(t, rsDeps(t, &rsUp{amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	if m["deployed"] != false || !strings.Contains(m["message"].(string), "unreachable") || len(m["partners"].([]any)) != 0 {
		t.Fatalf("D5: %v", m)
	}
}

func TestRoamingStatusD7AMFDown(t *testing.T) {
	m := invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, prom: rsPromAll(), smf: rsSMFJSON}), `{}`)
	if sub(m, "roaming_ues", "available") != false || sub(m, "roaming_ues", "error") == "" ||
		sub(m, "home_routed_sessions", "available") != true || sub(m, "home_routed_sessions", "count") != 1.0 ||
		sub(m, "sources", "amf") == "ok" {
		t.Fatalf("D7: %v", m)
	}
}

func TestRoamingStatusD8SMFDown(t *testing.T) {
	m := invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, prom: rsPromAll(), amf: rsAMFJSON}), `{}`)
	if sub(m, "home_routed_sessions", "available") != false || sub(m, "home_routed_sessions", "error") == "" ||
		sub(m, "roaming_ues", "available") != true || sub(m, "roaming_ues", "count") != 1.0 {
		t.Fatalf("D8: %v", m)
	}
}

func TestRoamingStatusNilClients(t *testing.T) {
	out, err := roamingStatusTool{Deps{}}.Invoke(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := out.(roamResult); r.Deployed {
		t.Fatalf("nil deps: %+v", r)
	}
}

func TestRoamingClassify(t *testing.T) {
	partners := map[string]bool{"001-002": true, "310-410": true, "208-093": true}
	tests := []struct {
		supi, home string
		roaming    bool
	}{
		{"imsi-001010000000001", "", false}, // local 2-digit form of 001-001
		{"imsi-001001000000001", "", false}, // local 3-digit
		{"imsi-001020000000007", "001-002", true},
		{"imsi-310410123456789", "310-410", true},
		{"imsi-20893123456789", "208-093", true}, // 2-digit MNC 93 padded
		{"imsi-999990000000001", "unknown", true},
		{"nai-a@b", "", false},
	}
	for _, tc := range tests {
		home, roaming := classify(tc.supi, "001-001", partners)
		if home != tc.home || roaming != tc.roaming {
			t.Errorf("%s: got (%q,%v) want (%q,%v)", tc.supi, home, roaming, tc.home, tc.roaming)
		}
	}
}

func TestNormPLMN(t *testing.T) {
	for in, want := range map[string]string{"001/002": "001-002", "001-02": "001-002", "001/01": "001-001", "310-410": "310-410", "other": "", "unknown": ""} {
		if got, _ := normPLMN(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestRoamingStatusUnknownArgRefused(t *testing.T) {
	u := &rsUp{portal: rsPortalJSON, prom: rsPromAll(), amf: rsAMFJSON, smf: rsSMFJSON}
	_, err := roamingStatusTool{rsDeps(t, u)}.Invoke(context.Background(), json.RawMessage(`{"bogus":1}`))
	if err == nil || asCode(t, err) != mcperr.CodeInvalidParams {
		t.Fatalf("want invalid params, got %v", err)
	}
	if u.hits.Load() != 0 {
		t.Fatal("upstream called")
	}
}

func TestRoamingStatusNaNAndNegativeSamples(t *testing.T) {
	prom := promJSON(
		vec(row("NaN", "role", "sepp", "peer_plmn", "001/002"), row("+Inf", "role", "hsepp", "peer_plmn", "001/001")),
		vec(row("NaN", "role", "sepp", "peer_plmn", "001/002", "result", "OK"), row("-3", "role", "sepp", "peer_plmn", "001/002", "result", "REJECT")),
		vec(row("NaN", "role", "sepp", "peer_plmn", "001/002", "direction", "OUT", "result", "OK")),
		vec(row("-Inf", "role", "sepp", "reason", "not_partner")))
	m := invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, prom: prom, amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	s := partnerSEPP(t, m, "001-002", "sepp")
	if s == nil || s["context_established"] != nil || s["handshakes"] != nil || s["n32f"] != nil {
		t.Fatalf("non-finite samples must be absent: %v", s)
	}
	if sub(m, "tls_rejects", "sepp") != nil {
		t.Fatalf("tls_rejects: %v", m["tls_rejects"])
	}
	// Only non-finite series: Prometheus does not count as deployment evidence.
	u := &rsUp{portal: `{"deployed":false,"link":{"state":"NOT_DEPLOYED"}}`, prom: prom, amf: `[]`, smf: `{}`}
	if d := invokeRS(t, rsDeps(t, u), `{}`); d["deployed"] != false {
		t.Fatalf("D4 with only NaN series: %v", d)
	}
	// A finite 0 is a known "not established".
	z := promJSON(vec(row("0", "role", "sepp", "peer_plmn", "001/002")), vec(), vec(), vec())
	m = invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, prom: z, amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	if s := partnerSEPP(t, m, "001-002", "sepp"); s == nil || s["context_established"] != false {
		t.Fatalf("finite 0: %v", s)
	}
}

func TestRoamingStatusTwoPartnersHSEPPByPortalLocalPLMN(t *testing.T) {
	portal := `{"deployed":true,"link":{"state":"UP","local_plmn":"001/001"},
"sepps":[{"name":"sepp","n32":{"local_plmn":"001/001","partners":[{"plmn":"001/002","state":"ESTABLISHED"},{"plmn":"001/003","state":"ESTABLISHED"}]}},
{"name":"hsepp","n32":{"local_plmn":"001/003","partners":[{"plmn":"001/001","state":"ESTABLISHED"}]}}]}`
	prom := promJSON(
		vec(row("1", "role", "sepp", "peer_plmn", "001/002"), row("1", "role", "sepp", "peer_plmn", "001/003"), row("1", "role", "hsepp", "peer_plmn", "001/001")),
		vec(), vec(), vec())
	for i := 0; i < 20; i++ { // map order must not matter
		m := invokeRS(t, rsDeps(t, &rsUp{portal: portal, prom: prom, amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
		if partnerSEPP(t, m, "001-003", "hsepp") == nil || partnerSEPP(t, m, "001-002", "hsepp") != nil {
			t.Fatalf("hsepp must attach to 001-003 only: %v", m["partners"])
		}
	}
	// Two partners, local PLMN and hsepp local_plmn unknown: no attachment.
	noInfo := promJSON(
		vec(row("1", "role", "sepp", "peer_plmn", "001/002"), row("1", "role", "sepp", "peer_plmn", "001/003"), row("1", "role", "hsepp", "peer_plmn", "001/001")),
		vec(), vec(), vec())
	m := invokeRS(t, rsDeps(t, &rsUp{prom: noInfo}), `{}`)
	if partnerSEPP(t, m, "001-002", "hsepp") != nil || partnerSEPP(t, m, "001-003", "hsepp") != nil {
		t.Fatalf("hsepp must not attach with two partners and no portal: %v", m["partners"])
	}
}

func TestRoamingStatusMalformedLocalPLMNCause(t *testing.T) {
	portal := `{"deployed":true,"link":{"state":"UP","local_plmn":"x"},"sepps":[]}`
	m := invokeRS(t, rsDeps(t, &rsUp{portal: portal, prom: rsPromAll(), amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	want := `local PLMN unknown: portal local_plmn "x" malformed`
	if sub(m, "roaming_ues", "error") != want || sub(m, "home_routed_sessions", "error") != want {
		t.Fatalf("cause: %v", m["roaming_ues"])
	}
}

func TestRoamingStatusLocalSEPPUnreachableD4(t *testing.T) {
	portal := `{"deployed":true,"link":{"state":"DOWN"},"sepps":[{"name":"sepp","error":"dial tcp: refused"}]}`
	u := &rsUp{portal: portal, prom: promJSON(vec(), vec(), vec(), vec()), amf: `[]`, smf: `{}`}
	m := invokeRS(t, rsDeps(t, u), `{}`)
	if m["deployed"] != false || !strings.Contains(m["message"].(string), "--profile roaming") {
		t.Fatalf("D4: %v", m)
	}
	// With fivegc_sepp series the SEPP is deployed.
	u = &rsUp{portal: portal, prom: rsPromAll(), amf: rsAMFJSON, smf: rsSMFJSON}
	if m := invokeRS(t, rsDeps(t, u), `{}`); m["deployed"] != true {
		t.Fatalf("with series: %v", m)
	}
}

func TestRoamingStatusPortalNon2xx(t *testing.T) {
	m := invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, portalCode: 500, prom: rsPromAll(), amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	if sub(m, "sources", "portal") == "ok" || m["deployed"] != true || sub(m, "sources", "prometheus") != "ok" {
		t.Fatalf("portal 500: %v", m["sources"])
	}
}

func TestRoamingStatusPromErrorsJoined(t *testing.T) {
	m := invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	if n := strings.Count(m["sources"].(map[string]any)["prometheus"].(string), "\n"); n < 3 {
		t.Fatalf("want all 4 query errors joined, got %v", m["sources"])
	}
}

func TestRoamingStatusFailureCounts(t *testing.T) {
	prom := promJSON(
		vec(row("1", "role", "sepp", "peer_plmn", "001/002")),
		vec(row("4", "role", "sepp", "peer_plmn", "001/002", "result", "FAILURE")),
		vec(row("6", "role", "sepp", "peer_plmn", "001/002", "direction", "OUT", "result", "FAILURE")),
		vec())
	m := invokeRS(t, rsDeps(t, &rsUp{portal: rsPortalJSON, prom: prom, amf: rsAMFJSON, smf: rsSMFJSON}), `{}`)
	s := partnerSEPP(t, m, "001-002", "sepp")
	if hs := s["handshakes"].(map[string]any); hs["failure"] != 4.0 || hs["ok"] != 0.0 {
		t.Fatalf("handshakes: %v", hs)
	}
	if f := s["n32f"].(map[string]any); f["failure"] != 6.0 || f["out_ok"] != 0.0 {
		t.Fatalf("n32f: %v", f)
	}
}

func TestImsiDigitsLength(t *testing.T) {
	for supi, want := range map[string]bool{"imsi-00101": false, "imsi-001010": true, "imsi-001010123456789": true, "imsi-0010101234567890": false} {
		if _, ok := imsiDigits(supi); ok != want {
			t.Errorf("%s: %v want %v", supi, ok, want)
		}
	}
}
