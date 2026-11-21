package server

// shape_test.go - NRF-003: Service-Map conversion, Inter-Plmn-Fqdn stripping,
// SubscriptionData 201 / validityTime and ProblemDetails 400 under the rel19
// profile, plus the rel17 frozen behaviour. Ref: TS 29.510 §6.1.6.2.2
// NOTE 15, §6.2.6.2.3 NOTE 10, §6.1.6.2.16, §6.1.9 Table 6.1.9-1.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/francurieses/claudia-5gc/nf/nrf/internal/registry"
)

func objOf(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not an object %s: %v", b, err)
	}
	return m
}

func TestShapeProfile(t *testing.T) {
	const arr = `{"nfType":"AMF","nfServices":[` +
		`{"serviceInstanceId":"b","serviceName":"namf-comm","vendorExt":{"x":[1,2]}},` +
		`{"serviceInstanceId":"a","serviceName":"namf-evts"}]}`
	const lst = `{"nfType":"AMF","nfServiceList":{` +
		`"svc-b":{"serviceInstanceId":"svc-b","serviceName":"x","vendorExt":true},` +
		`"svc-a":{"serviceInstanceId":"svc-a","serviceName":"y"}}}`
	const both = `{"nfServices":[{"serviceInstanceId":"arr"}],"nfServiceList":{"lst":{"serviceInstanceId":"lst"}}}`

	tests := []struct {
		name, in string
		wantMap  bool
		want     string // exact output
		skipped  int
	}{
		{"array to map", arr, true,
			`{"nfServiceList":{"a":{"serviceInstanceId":"a","serviceName":"namf-evts"},` +
				`"b":{"serviceInstanceId":"b","serviceName":"namf-comm","vendorExt":{"x":[1,2]}}},"nfType":"AMF"}`, 0},
		{"map to array sorted by key", lst, false,
			`{"nfServices":[{"serviceInstanceId":"svc-a","serviceName":"y"},` +
				`{"serviceInstanceId":"svc-b","serviceName":"x","vendorExt":true}],"nfType":"AMF"}`, 0},
		{"map stays map", lst, true,
			`{"nfServiceList":{"svc-b":{"serviceInstanceId":"svc-b","serviceName":"x","vendorExt":true},` +
				`"svc-a":{"serviceInstanceId":"svc-a","serviceName":"y"}},"nfType":"AMF"}`, 0}, // kept verbatim
		{"array stays array", arr, false,
			`{"nfServices":[{"serviceInstanceId":"b","serviceName":"namf-comm","vendorExt":{"x":[1,2]}},` +
				`{"serviceInstanceId":"a","serviceName":"namf-evts"}],"nfType":"AMF"}`, 0},
		{"both present, map wins", both, true, `{"nfServiceList":{"lst":{"serviceInstanceId":"lst"}}}`, 0},
		{"both present, array wins", both, false, `{"nfServices":[{"serviceInstanceId":"arr"}]}`, 0},
		{"neither", `{"nfType":"AMF"}`, true, `{"nfType":"AMF"}`, 0},
		{"array entry without id skipped", `{"nfServices":[{"serviceName":"n"},{"serviceInstanceId":"k"}]}`, true,
			`{"nfServiceList":{"k":{"serviceInstanceId":"k"}}}`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, skipped, err := shapeProfile([]byte(tc.in), shapeOpts{serviceMap: tc.wantMap})
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != tc.want || skipped != tc.skipped {
				t.Errorf("got  %s (skipped %d)\nwant %s (skipped %d)", out, skipped, tc.want, tc.skipped)
			}
		})
	}
	if _, _, err := shapeProfile([]byte(`[1]`), shapeOpts{}); err == nil {
		t.Error("non-object profile must error")
	}
}

func TestShapeProfileStripInterPlmnFqdn(t *testing.T) {
	const in = `{"nfType":"AMF","fqdn":"a","interPlmnFqdn":"a.inter","nfServices":[` +
		`{"serviceInstanceId":"s1","interPlmnFqdn":"s1.inter","fqdn":"s1"}],"nfServiceList":{` +
		`"s2":{"serviceInstanceId":"s2","interPlmnFqdn":"s2.inter","vendorExt":1}}}`
	for _, wantMap := range []bool{true, false} {
		out, _, err := shapeProfile([]byte(in), shapeOpts{serviceMap: wantMap, stripInterPlmnFqdn: true})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("interPlmnFqdn")) {
			t.Errorf("map=%v: interPlmnFqdn survived: %s", wantMap, out)
		}
		if !bytes.Contains(out, []byte(`"fqdn":"a"`)) {
			t.Errorf("map=%v: fqdn lost: %s", wantMap, out)
		}
	}
	// The strip applies to the "nfServiceList" map even when it is the shape kept.
	out, _, _ := shapeProfile([]byte(in), shapeOpts{serviceMap: true, stripInterPlmnFqdn: true})
	if !bytes.Contains(out, []byte(`"vendorExt":1`)) {
		t.Errorf("unknown service attribute lost: %s", out)
	}
	// Not stripped when not asked.
	out, _, _ = shapeProfile([]byte(in), shapeOpts{serviceMap: true})
	if strings.Count(string(out), "interPlmnFqdn") != 2 { // profile + map service (array dropped)
		t.Errorf("interPlmnFqdn dropped without strip: %s", out)
	}
}

func TestSubscriptionValidity(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name, req, want string
	}{
		{"future echoed verbatim", "2030-01-01T00:00:00Z", "2030-01-01T00:00:00Z"},
		{"future with offset echoed verbatim", "2030-01-01T01:00:00+01:00", "2030-01-01T01:00:00+01:00"},
		{"past replaced", "2020-01-01T00:00:00Z", now.Add(DefaultSubscriptionValidity).Format(time.RFC3339)},
		{"absent defaulted", "", now.Add(DefaultSubscriptionValidity).Format(time.RFC3339)},
		{"unparsable defaulted", "soon", now.Add(DefaultSubscriptionValidity).Format(time.RFC3339)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ts := subscriptionValidity(tc.req, now)
			if got != tc.want || !ts.After(now) {
				t.Errorf("got %q (%v) want %q", got, ts, tc.want)
			}
		})
	}
}

func TestIntraPLMN(t *testing.T) {
	tests := []struct {
		name, list string
		want       bool
	}{
		{"absent", ``, true},
		{"empty", `[]`, true},
		{"own plmn", `[{"mcc":"001","mnc":"01"}]`, true},
		{"own among others", `[{"mcc":"999","mnc":"99"},{"mcc":"001","mnc":"01"}]`, true},
		{"foreign only", `[{"mcc":"999","mnc":"99"}]`, false},
	}
	for _, tc := range tests {
		if got, err := intraPLMN(json.RawMessage(tc.list), "001", "01"); err != nil || got != tc.want {
			t.Errorf("%s: got %v err %v", tc.name, got, err)
		}
	}
	if _, err := intraPLMN(json.RawMessage(`"x"`), "001", "01"); err == nil {
		t.Error("malformed reqPlmnList must error")
	}
}

const (
	amfMapIn = `{"nfType":"AMF","nfServiceList":{"svc-b":{"serviceInstanceId":"svc-b","serviceName":"namf-comm","vendorExt":"v"},` +
		`"svc-a":{"serviceInstanceId":"svc-a","serviceName":"namf-evts","vendorExt":"v"}}}`
	amfArrIn = `{"nfType":"AMF","nfServices":[{"serviceInstanceId":"namf-comm-1","serviceName":"namf-comm"},` +
		`{"serviceInstanceId":"namf-evts-1","serviceName":"namf-evts"}]}`
	amfID = "00000000-0000-4000-8000-000000000101"
)

func register(t *testing.T, s *Server, id, body string) {
	t.Helper()
	if rec := doReq(s, http.MethodPut, "/nnrf-nfm/v1/nf-instances/"+id, body, ""); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
}

func firstInstance(t *testing.T, rec interface{ Bytes() []byte }) map[string]json.RawMessage {
	t.Helper()
	var sr struct {
		NFInstances []map[string]json.RawMessage `json:"nfInstances"`
	}
	if err := json.Unmarshal(rec.Bytes(), &sr); err != nil || len(sr.NFInstances) != 1 {
		t.Fatalf("search result %s: %v", rec.Bytes(), err)
	}
	return sr.NFInstances[0]
}

func TestDiscoverServiceMapRel19(t *testing.T) {
	const url = "/nnrf-disc/v1/nf-instances?target-nf-type=AMF&requester-nf-type=SMF"
	tests := []struct {
		name, reg, query         string
		wantList, wantServices   bool
		wantSortedKeysOrFirstSvc string
	}{
		{"array registered, Service-Map negotiated", amfArrIn, "&requester-features=20", true, false, ""},
		{"array registered, no requester-features", amfArrIn, "", false, true, "namf-comm-1"},
		{"map registered, no requester-features", amfMapIn, "", false, true, "svc-a"},
		{"map registered, Service-Map negotiated", amfMapIn, "&requester-features=20", true, false, ""},
		{"requester-features without bit 6", amfMapIn, "&requester-features=1", false, true, "svc-a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
			register(t, s, amfID, tc.reg)
			rec := doReq(s, http.MethodGet, url+tc.query, "", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			inst := firstInstance(t, rec.Body)
			_, hasList := inst["nfServiceList"]
			_, hasArr := inst["nfServices"]
			if hasList != tc.wantList || hasArr != tc.wantServices {
				t.Fatalf("nfServiceList=%v nfServices=%v: %s", hasList, hasArr, rec.Body)
			}
			if tc.wantServices {
				var svcs []map[string]any
				_ = json.Unmarshal(inst["nfServices"], &svcs)
				if svcs[0]["serviceInstanceId"] != tc.wantSortedKeysOrFirstSvc {
					t.Errorf("first service %v", svcs[0])
				}
			}
			if bodyMap(t, rec)["nrfSupportedFeatures"] != "20" {
				t.Errorf("nrfSupportedFeatures missing: %s", rec.Body)
			}
		})
	}
	// Unknown nested attribute survives the conversion.
	s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	register(t, s, amfID, amfMapIn)
	if rec := doReq(s, http.MethodGet, url, "", ""); strings.Count(rec.Body.String(), `"vendorExt":"v"`) != 2 {
		t.Errorf("vendorExt lost: %s", rec.Body)
	}
}

func TestRetrieveServiceMapRel19(t *testing.T) {
	url := "/nnrf-nfm/v1/nf-instances/" + amfID
	s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	register(t, s, amfID, amfArrIn)
	for q, wantList := range map[string]bool{"": false, "?requester-features=1": true, "?requester-features=2": false} {
		rec := doReq(s, http.MethodGet, url+q, "", "")
		obj := objOf(t, rec.Body.Bytes())
		_, hasList := obj["nfServiceList"]
		_, hasArr := obj["nfServices"]
		if rec.Code != http.StatusOK || hasList != wantList || hasArr == wantList {
			t.Errorf("%q: %d list=%v arr=%v %s", q, rec.Code, hasList, hasArr, rec.Body)
		}
	}
	// Register / update responses and NFListRetrieval stay as registered.
	rec := doReq(s, http.MethodPut, "/nnrf-nfm/v1/nf-instances/"+amfID, amfArrIn, "")
	if obj := objOf(t, rec.Body.Bytes()); obj["nfServices"] == nil || obj["nfServiceList"] != nil {
		t.Errorf("register response reshaped: %s", rec.Body)
	}
	rec = doReq(s, http.MethodGet, "/nnrf-nfm/v1/nf-instances?detail=true", "", "")
	if !strings.Contains(rec.Body.String(), `"nfServices"`) || strings.Contains(rec.Body.String(), `"nfServiceList"`) {
		t.Errorf("list reshaped: %s", rec.Body)
	}
}

func TestRetrieveServiceMapRel17Untouched(t *testing.T) {
	s, _ := newFeatureNRF(t, profileNamed(t, "rel17"), nil, nil)
	register(t, s, amfID, amfMapIn)
	rec := doReq(s, http.MethodGet, "/nnrf-nfm/v1/nf-instances/"+amfID+"?requester-features=1", "", "")
	if obj := objOf(t, rec.Body.Bytes()); obj["nfServiceList"] == nil || obj["nfServices"] != nil {
		t.Errorf("rel17 reshaped: %s", rec.Body)
	}
}

// capture swaps the notify client for one that records request bodies per
// notification URI.
type capture struct{ ch chan [2]string }

func (c capture) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	c.ch <- [2]string{r.URL.Host, string(b)}
	return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

func subscribe(t *testing.T, s *Server, host, extra string) {
	t.Helper()
	body := `{"nfStatusNotificationUri":"http://` + host + `/cb","reqNfType":"AMF"` + extra + `}`
	if rec := doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", body, ""); rec.Code != http.StatusCreated {
		t.Fatalf("subscribe %s: %d %s", host, rec.Code, rec.Body)
	}
}

func collect(t *testing.T, ch chan [2]string, n int) map[string]map[string]json.RawMessage {
	t.Helper()
	out := map[string]map[string]json.RawMessage{}
	for i := 0; i < n; i++ {
		select {
		case m := <-ch:
			var nd struct {
				Profile map[string]json.RawMessage `json:"nfProfile"`
			}
			if err := json.Unmarshal([]byte(m[1]), &nd); err != nil {
				t.Fatalf("notification %s: %v", m[1], err)
			}
			out[m[0]] = nd.Profile
		case <-time.After(3 * time.Second):
			t.Fatalf("timeout waiting for notification %d/%d", i+1, n)
		}
	}
	return out
}

func TestNotifyServiceMapAndInterPlmnFqdnRel19(t *testing.T) {
	s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	ch := make(chan [2]string, 8)
	s.httpClient = &http.Client{Transport: capture{ch}}
	subscribe(t, s, "plain", ``)                                            // no features
	subscribe(t, s, "map", `,"requesterFeatures":"1"`)                      // Service-Map only
	subscribe(t, s, "ipf", `,"requesterFeatures":"5"`)                      // Service-Map + Inter-Plmn-Fqdn
	subscribe(t, s, "foreign", `,"reqPlmnList":[{"mcc":"999","mnc":"99"}]`) // inter-PLMN, no bit 3
	const reg = `{"nfType":"AMF","interPlmnFqdn":"amf.inter","nfServices":[` +
		`{"serviceInstanceId":"s1","serviceName":"namf-comm","interPlmnFqdn":"s1.inter","vendorExt":1}]}`
	register(t, s, amfID, reg)
	got := collect(t, ch, 4)
	type want struct{ list, ipf bool }
	for host, w := range map[string]want{"plain": {false, false}, "map": {true, false}, "ipf": {true, true}, "foreign": {false, true}} {
		p := got[host]
		if p == nil {
			t.Fatalf("%s: no notification", host)
		}
		_, hasList := p["nfServiceList"]
		_, hasArr := p["nfServices"]
		raw, _ := json.Marshal(p)
		hasIPF := bytes.Contains(raw, []byte("interPlmnFqdn"))
		if hasList != w.list || hasArr == w.list || hasIPF != w.ipf {
			t.Errorf("%s: list=%v arr=%v ipf=%v want %+v: %s", host, hasList, hasArr, hasIPF, w, raw)
		}
		if w.ipf && bytes.Count(raw, []byte("interPlmnFqdn")) != 2 {
			t.Errorf("%s: interPlmnFqdn must stay at profile and service level: %s", host, raw)
		}
		if !bytes.Contains(raw, []byte(`"vendorExt":1`)) {
			t.Errorf("%s: unknown attribute lost: %s", host, raw)
		}
	}
}

func TestNotifyRel17Verbatim(t *testing.T) {
	s, _ := newFeatureNRF(t, profileNamed(t, "rel17"), nil, nil)
	ch := make(chan [2]string, 2)
	s.httpClient = &http.Client{Transport: capture{ch}}
	subscribe(t, s, "plain", ``)
	register(t, s, amfID, `{"nfType":"AMF","interPlmnFqdn":"amf.inter","nfServiceList":{"k":{"serviceInstanceId":"k","interPlmnFqdn":"k.inter"}}}`)
	raw, _ := json.Marshal(collect(t, ch, 1)["plain"])
	if bytes.Count(raw, []byte("interPlmnFqdn")) != 2 || !bytes.Contains(raw, []byte("nfServiceList")) {
		t.Errorf("rel17 notification altered: %s", raw)
	}
}

func TestNotifySkipsExpiredSubscription(t *testing.T) {
	s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	ch := make(chan [2]string, 4)
	s.httpClient = &http.Client{Transport: capture{ch}}
	subscribe(t, s, "live", ``)
	subscribe(t, s, "dead", ``)
	for _, sub := range s.subs.Matching("AMF", "") {
		if strings.Contains(sub.NotificationURI, "dead") {
			sub.ValidityTime = time.Now().Add(-time.Minute)
		}
	}
	register(t, s, amfID, amfArrIn)
	if got := collect(t, ch, 1); got["live"] == nil {
		t.Fatalf("live subscriber not notified: %v", got)
	}
	select {
	case m := <-ch:
		t.Errorf("expired subscription notified: %v", m)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestSubscribeSubscriptionDataRel19(t *testing.T) {
	s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	const body = `{"nfStatusNotificationUri":"https://amf.example:8443/notify","reqNfType":"AMF",` +
		`"validityTime":"2030-01-01T00:00:00Z","requesterFeatures":"1","completeProfileSubscription":false,` +
		`"subscrCond":{"nfType":"SMF"},"vendorExt":{"k":1}}`
	rec := doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", body, "")
	if rec.Code != http.StatusCreated || rec.Result().Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	m := bodyMap(t, rec)
	id, _ := m["subscriptionId"].(string)
	if id == "" || m["validityTime"] != "2030-01-01T00:00:00Z" || m["nrfSupportedFeatures"] != "5" ||
		m["nfStatusNotificationUri"] != "https://amf.example:8443/notify" || m["reqNfType"] != "AMF" {
		t.Errorf("SubscriptionData %s", rec.Body)
	}
	if _, ok := m["requesterFeatures"]; ok {
		t.Error("writeOnly requesterFeatures echoed")
	}
	if _, ok := m["completeProfileSubscription"]; ok {
		t.Error("writeOnly completeProfileSubscription echoed")
	}
	if m["subscrCond"] == nil || m["vendorExt"] == nil {
		t.Errorf("request attributes not echoed: %s", rec.Body)
	}
	if loc := rec.Result().Header.Get("Location"); !strings.HasSuffix(loc, "/nnrf-nfm/v1/subscriptions/"+id) || !strings.HasPrefix(loc, "http") {
		t.Errorf("Location %q", loc)
	}
	// validityTime is stored.
	subs := s.subs.Matching("AMF", "")
	if len(subs) != 1 || subs[0].ValidityTime.Year() != 2030 {
		t.Errorf("stored subscription %+v", subs)
	}
	// No validityTime in the request: defaulted, in the future.
	rec = doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{"nfStatusNotificationUri":"http://x/cb"}`, "")
	vt, err := time.Parse(time.RFC3339, bodyMap(t, rec)["validityTime"].(string))
	if err != nil || !vt.After(time.Now()) {
		t.Errorf("default validityTime %v err %v", vt, err)
	}
	// rel17 keeps the one-attribute body.
	s17, _ := newFeatureNRF(t, profileNamed(t, "rel17"), nil, nil)
	rec = doReq(s17, http.MethodPost, "/nnrf-nfm/v1/subscriptions", `{"nfStatusNotificationUri":"http://x/cb"}`, "")
	if m := bodyMap(t, rec); len(m) != 1 || m["subscriptionId"] == nil {
		t.Errorf("rel17 body %s", rec.Body)
	}
	if !s17.subs.Matching("", "")[0].ValidityTime.IsZero() {
		t.Error("rel17 subscription must not carry a validityTime")
	}
}

func TestProblemDetails400Rel19(t *testing.T) {
	s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	tests := []struct {
		name, body, cause, param string
	}{
		{"no uri", `{"reqNfType":"AMF"}`, "MANDATORY_IE_MISSING", "/nfStatusNotificationUri"},
		{"malformed", `{`, "INVALID_MSG_FORMAT", ""},
		{"bad validityTime", `{"nfStatusNotificationUri":"http://x/cb","validityTime":"tomorrow"}`, "INVALID_MSG_FORMAT", "/validityTime"},
		{"malformed reqPlmnList", `{"nfStatusNotificationUri":"http://x/cb","reqPlmnList":"notAnArray"}`, "INVALID_MSG_FORMAT", "/reqPlmnList"},
		{"wrong attribute type", `{"nfStatusNotificationUri":7}`, "INVALID_MSG_FORMAT", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := doReq(s, http.MethodPost, "/nnrf-nfm/v1/subscriptions", tc.body, "")
			var pd problemBody
			_ = json.Unmarshal(rec.Body.Bytes(), &pd)
			if rec.Code != http.StatusBadRequest || rec.Result().Header.Get("Content-Type") != "application/problem+json" || pd.Cause != tc.cause {
				t.Fatalf("%d %q %s", rec.Code, rec.Result().Header.Get("Content-Type"), rec.Body)
			}
			if tc.param != "" && (len(pd.InvalidParams) != 1 || pd.InvalidParams[0].Param != tc.param) {
				t.Errorf("invalidParams %s", rec.Body)
			}
		})
	}
}

func TestPayloadTooLargeRegisterUpdateRel19(t *testing.T) {
	huge := `{"nfType":"AMF","pad":"` + strings.Repeat("a", 1<<20+10) + `"}`
	s, _ := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	for _, m := range []string{http.MethodPut, http.MethodPatch} {
		rec := doReq(s, m, "/nnrf-nfm/v1/nf-instances/"+amfID, huge, "")
		if rec.Code != http.StatusRequestEntityTooLarge || rec.Result().Header.Get("Content-Type") != "application/problem+json" {
			t.Errorf("%s: %d %.120s", m, rec.Code, rec.Body)
		}
	}
}

func TestSubscriptionStoreKeepsRel19Fields(t *testing.T) {
	st := registry.NewSubscriptionStore()
	id := st.Add(&registry.Subscription{ReqNFType: "AMF", InterPLMN: true, ValidityTime: time.Now()})
	if got := st.Matching("AMF", ""); len(got) != 1 || got[0].SubscriptionID != id || !got[0].InterPLMN {
		t.Errorf("%+v", got)
	}
}

// failStatus answers every notification with a fixed status.
type failStatus struct{ code int }

func (f failStatus) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.code, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
}

func TestNotifySubscriber500LogsFailureRel19(t *testing.T) {
	s, logs := newFeatureNRF(t, profileNamed(t, "rel19"), nil, nil)
	s.httpClient = &http.Client{Transport: failStatus{http.StatusInternalServerError}}
	subscribe(t, s, "broken", ``)
	register(t, s, amfID, `{"nfType":"AMF"}`) // must not panic
	deadline := time.Now().Add(3 * time.Second)
	for {
		out := string(logs.bytes())
		if strings.Contains(out, `"result":"FAILURE"`) && strings.Contains(out, `"status":500`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no result=FAILURE status=500 log line: %s", out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
