package server

// sm_policy_override_list_test.go — GET /pcf-internal/v1/sm-policy-overrides.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func listOverrides(t *testing.T, s *Server, query string) []map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/pcf-internal/v1/sm-policy-overrides"+query, nil)
	w := httptest.NewRecorder()
	s.handleListQoSOverrides(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) == "null" {
		t.Fatal("body is null, want array")
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func putOverride(t *testing.T, s *Server, supi, body string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/pcf-internal/v1/subscribers/"+supi+"/sm-policy-override", strings.NewReader(body))
	r.SetPathValue("supi", supi)
	w := httptest.NewRecorder()
	s.handleSetQoSOverride(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("put status %d: %s", w.Code, w.Body.String())
	}
}

func TestListQoSOverrides_Empty(t *testing.T) {
	s := newTestPCF(t)
	if got := listOverrides(t, s, ""); len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

func TestListQoSOverrides_SortedAndFiltered(t *testing.T) {
	s := newTestPCF(t)
	putOverride(t, s, "imsi-2", `{"5qi":5,"dnn":"ims"}`)
	putOverride(t, s, "imsi-1", `{"5qi":7}`)
	putOverride(t, s, "imsi-2", `{"5qi":9}`)

	got := listOverrides(t, s, "")
	if len(got) != 3 {
		t.Fatalf("want 3, got %v", got)
	}
	// (imsi-1,""), (imsi-2,""), (imsi-2,"ims")
	want := [][2]string{{"imsi-1", ""}, {"imsi-2", ""}, {"imsi-2", "ims"}}
	for i, w := range want {
		dnn, _ := got[i]["dnn"].(string)
		if got[i]["supi"] != w[0] || dnn != w[1] {
			t.Errorf("entry %d = %v, want %v", i, got[i], w)
		}
	}
	if got[0]["5qi"].(float64) != 7 {
		t.Errorf("5qi = %v", got[0]["5qi"])
	}
	if f := listOverrides(t, s, "?supi=imsi-2"); len(f) != 2 {
		t.Errorf("filter: want 2, got %v", f)
	}
	if f := listOverrides(t, s, "?supi=nope"); len(f) != 0 {
		t.Errorf("filter nope: want 0, got %v", f)
	}
}

func TestListQoSOverrides_MethodAndRoute(t *testing.T) {
	s := newTestPCF(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pcf-internal/v1/sm-policy-overrides", s.handleListQoSOverrides)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/pcf-internal/v1/sm-policy-overrides", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d, want 405", w.Code)
	}
}

func TestListQoSOverrides_ConcurrentWithPut(t *testing.T) {
	s := newTestPCF(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); putOverride(t, s, "imsi-1", `{"5qi":5,"dnn":"x"}`) }()
		go func() { defer wg.Done(); _ = listOverrides(t, s, "") }()
	}
	wg.Wait()
}
