package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mockAMF(t *testing.T, name, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/amf/v1/ran/gnbs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func getRAN(t *testing.T, urls ...string) RANGnbsResponse {
	t.Helper()
	h := NewRouter(Deps{AMFMgmtURLs: urls}, http.FS(emptyFS(t)))
	rec := do(t, h, http.MethodGet, "/api/v1/ran/gnbs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp RANGnbsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

const amfBodyTwo = `{"amf":{"name":"amf-1","n2_addr":"0.0.0.0:38412"},"gnbs":[
 {"id":"b","ran_node_name":"gnb-b","state":"DISCONNECTED"},
 {"id":"a","ran_node_name":"gnb-a","state":"NG_READY"},
 {"id":"c","ran_node_name":"gnb-c","state":"SCTP_UP"}]}`

func TestRANGnbs_SortAndTag(t *testing.T) {
	amf := mockAMF(t, "amf-1", amfBodyTwo, 200)
	resp := getRAN(t, amf.URL)
	if len(resp.GNBs) != 3 || len(resp.Sources) != 1 || !resp.Sources[0].OK {
		t.Fatalf("resp = %+v", resp)
	}
	order := []string{"gnb-a", "gnb-c", "gnb-b"} // NG_READY, SCTP_UP, DISCONNECTED
	for i, want := range order {
		if got := resp.GNBs[i]["ran_node_name"]; got != want {
			t.Errorf("gnbs[%d] = %v, want %s", i, got, want)
		}
	}
	amfTag, _ := resp.GNBs[0]["amf"].(map[string]any)
	if amfTag["name"] != "amf-1" || amfTag["url"] != amf.URL {
		t.Errorf("amf tag = %v", amfTag)
	}
	if resp.Sources[0].AMFName != "amf-1" || resp.Sources[0].N2Addr != "0.0.0.0:38412" {
		t.Errorf("source = %+v", resp.Sources[0])
	}
}

func TestRANGnbs_EmptyIsArray(t *testing.T) {
	amf := mockAMF(t, "amf", `{"amf":{"name":"amf"},"gnbs":[]}`, 200)
	h := NewRouter(Deps{AMFMgmtURLs: []string{amf.URL}}, http.FS(emptyFS(t)))
	rec := do(t, h, http.MethodGet, "/api/v1/ran/gnbs", "")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["gnbs"]) != "[]" {
		t.Errorf("gnbs = %s, want []", raw["gnbs"])
	}
}

func TestRANGnbs_OneOfTwoDown(t *testing.T) {
	up := mockAMF(t, "amf-1", amfBodyTwo, 200)
	down := mockAMF(t, "amf-2", "", 503)
	resp := getRAN(t, up.URL, down.URL)
	if len(resp.GNBs) != 3 {
		t.Fatalf("gnbs = %d, want 3 from the healthy AMF", len(resp.GNBs))
	}
	if !resp.Sources[0].OK || resp.Sources[1].OK || resp.Sources[1].Error == "" {
		t.Errorf("sources = %+v", resp.Sources)
	}
}

func TestRANGnbs_AllDownStill200(t *testing.T) {
	down := mockAMF(t, "amf", "", 500)
	resp := getRAN(t, down.URL, "http://127.0.0.1:1")
	if len(resp.GNBs) != 0 || len(resp.Sources) != 2 || resp.Sources[0].OK || resp.Sources[1].OK {
		t.Errorf("resp = %+v", resp)
	}
}

func TestRANGnbs_MalformedUpstream(t *testing.T) {
	bad := mockAMF(t, "amf", "not json", 200)
	resp := getRAN(t, bad.URL)
	if len(resp.GNBs) != 0 || resp.Sources[0].OK || resp.Sources[0].Error == "" {
		t.Errorf("resp = %+v", resp)
	}
}

func TestRANGnbs_FallsBackToAMFBaseURL(t *testing.T) {
	amf := mockAMF(t, "amf", amfBodyTwo, 200)
	h := NewRouter(Deps{AMFBaseURL: amf.URL}, http.FS(emptyFS(t)))
	rec := do(t, h, http.MethodGet, "/api/v1/ran/gnbs", "")
	var resp RANGnbsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.GNBs) != 3 {
		t.Errorf("gnbs = %d, want 3", len(resp.GNBs))
	}
}
