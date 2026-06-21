package server

// am_policy_test.go — AM Policy Association unit tests.
// Ref: TS 29.507 §4.2.2 (Npcf_AMPolicyControl)

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestCreateAMPolicy_HappyPath(t *testing.T) {
	s := newTestPCF(t)

	body := `{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS","plmnId":{"mcc":"001","mnc":"01"}}`
	r := httptest.NewRequest(http.MethodPost, "/npcf-ampolicycontrol/v1/policies",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAMPolicy(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("Location header missing")
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	polAssoID, ok := resp["polAssoId"].(string)
	if !ok || polAssoID == "" {
		t.Fatal("polAssoId missing from response")
	}
	if rfsp, ok := resp["rfsp"].(float64); !ok || rfsp < 1 {
		t.Fatalf("rfsp not present or zero: %v", resp["rfsp"])
	}
	if !strings.Contains(loc, polAssoID) {
		t.Fatalf("Location %q does not contain polAssoId %q", loc, polAssoID)
	}
}

func TestCreateAMPolicy_MissingSUPI(t *testing.T) {
	s := newTestPCF(t)

	r := httptest.NewRequest(http.MethodPost, "/npcf-ampolicycontrol/v1/policies",
		strings.NewReader(`{"accessType":"3GPP_ACCESS"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAMPolicy(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["cause"] != "MANDATORY_IE_MISSING" {
		t.Fatalf("unexpected cause: %v", resp["cause"])
	}
}

func TestCreateAMPolicy_MissingAccessType(t *testing.T) {
	s := newTestPCF(t)

	r := httptest.NewRequest(http.MethodPost, "/npcf-ampolicycontrol/v1/policies",
		strings.NewReader(`{"supi":"imsi-001010000000001"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAMPolicy(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDeleteAMPolicy_HappyPath(t *testing.T) {
	s := newTestPCF(t)

	// Create first
	r := httptest.NewRequest(http.MethodPost, "/npcf-ampolicycontrol/v1/policies",
		strings.NewReader(`{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAMPolicy(w, r)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	polAssoID := resp["polAssoId"].(string)

	// Delete
	r2 := httptest.NewRequest(http.MethodDelete,
		"/npcf-ampolicycontrol/v1/policies/"+polAssoID, nil)
	r2.SetPathValue("polAssoId", polAssoID)
	w2 := httptest.NewRecorder()
	s.handleDeleteAMPolicy(w2, r2)

	if w2.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w2.Code, w2.Body.String())
	}

	// Deleting again gives 404
	r3 := httptest.NewRequest(http.MethodDelete,
		"/npcf-ampolicycontrol/v1/policies/"+polAssoID, nil)
	r3.SetPathValue("polAssoId", polAssoID)
	w3 := httptest.NewRecorder()
	s.handleDeleteAMPolicy(w3, r3)

	if w3.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on second delete, got %d", w3.Code)
	}
}

// setRFSPOverride is a test helper that PUTs a per-subscriber RFSP override.
func setRFSPOverride(t *testing.T, s *Server, supi string, rfsp int) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut,
		"/pcf-internal/v1/subscribers/"+supi+"/am-policy-override",
		strings.NewReader(`{"rfsp":`+itoa(rfsp)+`}`))
	r.SetPathValue("supi", supi)
	w := httptest.NewRecorder()
	s.handleSetRFSPOverride(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("set RFSP override: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

func TestSetRFSPOverride_AppliesToAMPolicy(t *testing.T) {
	s := newTestPCF(t)
	const supi = "imsi-001010000000007"
	setRFSPOverride(t, s, supi, 42)

	// A subsequent AM policy creation for that SUPI must return rfsp=42.
	r := httptest.NewRequest(http.MethodPost, "/npcf-ampolicycontrol/v1/policies",
		strings.NewReader(`{"supi":"`+supi+`","accessType":"3GPP_ACCESS"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAMPolicy(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if rfsp, _ := resp["rfsp"].(float64); rfsp != 42 {
		t.Fatalf("expected rfsp=42 from override, got %v", resp["rfsp"])
	}
}

func TestCreateAMPolicy_DefaultWhenNoOverride(t *testing.T) {
	s := newTestPCF(t)
	r := httptest.NewRequest(http.MethodPost, "/npcf-ampolicycontrol/v1/policies",
		strings.NewReader(`{"supi":"imsi-001010000000099","accessType":"3GPP_ACCESS"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAMPolicy(w, r)
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if rfsp, _ := resp["rfsp"].(float64); rfsp != 1 {
		t.Fatalf("expected default rfsp=1, got %v", resp["rfsp"])
	}
}

func TestRFSPOverride_OutOfRange(t *testing.T) {
	s := newTestPCF(t)
	for _, bad := range []string{`{"rfsp":0}`, `{"rfsp":257}`, `{"rfsp":-5}`} {
		r := httptest.NewRequest(http.MethodPut,
			"/pcf-internal/v1/subscribers/imsi-1/am-policy-override", strings.NewReader(bad))
		r.SetPathValue("supi", "imsi-1")
		w := httptest.NewRecorder()
		s.handleSetRFSPOverride(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d", bad, w.Code)
		}
	}
}

func TestRFSPOverride_GetAndDelete(t *testing.T) {
	s := newTestPCF(t)
	const supi = "imsi-001010000000003"
	setRFSPOverride(t, s, supi, 100)

	// GET returns the value.
	rg := httptest.NewRequest(http.MethodGet,
		"/pcf-internal/v1/subscribers/"+supi+"/am-policy-override", nil)
	rg.SetPathValue("supi", supi)
	wg := httptest.NewRecorder()
	s.handleGetRFSPOverride(wg, rg)
	if wg.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d", wg.Code)
	}
	var got map[string]any
	_ = json.NewDecoder(wg.Body).Decode(&got)
	if rfsp, _ := got["rfsp"].(float64); rfsp != 100 {
		t.Fatalf("GET: expected rfsp=100, got %v", got["rfsp"])
	}

	// DELETE removes it; second DELETE is 404.
	for i, wantCode := range []int{http.StatusNoContent, http.StatusNotFound} {
		rd := httptest.NewRequest(http.MethodDelete,
			"/pcf-internal/v1/subscribers/"+supi+"/am-policy-override", nil)
		rd.SetPathValue("supi", supi)
		wd := httptest.NewRecorder()
		s.handleDeleteRFSPOverride(wd, rd)
		if wd.Code != wantCode {
			t.Fatalf("DELETE #%d: expected %d, got %d", i+1, wantCode, wd.Code)
		}
	}
}
