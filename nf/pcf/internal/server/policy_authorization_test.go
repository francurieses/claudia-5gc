// Package server — Npcf_PolicyAuthorization unit tests.
//
// Tests cover the thin Create + Delete endpoints for app-sessions added to the
// PCF to support the NEF AsSessionWithQoS flow (TS 29.514 §5.2.2.2 / §5.2.2.4).
// Every test uses a fresh Server (newTestPCF) so tests are order-independent.
//
// Ref: TS 29.514 §5.2.2.2 (Create), §5.2.2.4 (Delete)
package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCreateAppSession_HappyPath verifies that a well-formed Create request
// returns 201 Created, a Location header whose tail is a non-empty appSessionId,
// and a JSON body also containing appSessionId.
// Ref: TS 29.514 §5.2.2.2.3.1
func TestCreateAppSession_HappyPath(t *testing.T) {
	s := newTestPCF(t)

	body := `{"ascReqData":{"aspId":"af-test","ueIpv4":"10.60.0.1","qosReference":"qos-gold","dnn":"internet"}}`
	r := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAppSession(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", w.Code, w.Body.String())
	}

	// Location header must end with a non-empty appSessionId.
	loc := w.Header().Get("Location")
	if loc == "" {
		t.Fatal("Location header missing")
	}
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	appSessionID := parts[len(parts)-1]
	if appSessionID == "" {
		t.Fatalf("Location header tail (appSessionId) is empty: %q", loc)
	}
	if !strings.HasSuffix(loc, "/npcf-policyauthorization/v1/app-sessions/"+appSessionID) {
		t.Errorf("Location header unexpected format: %q", loc)
	}

	// Response body must include appSessionId.
	var resp AppSessionContext
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if resp.AppSessionID == "" {
		t.Fatal("appSessionId missing from response body")
	}
	if resp.AppSessionID != appSessionID {
		t.Errorf("body appSessionId %q != Location tail %q", resp.AppSessionID, appSessionID)
	}

	// The session must be stored internally.
	s.appSessionsMu.Lock()
	stored, ok := s.appSessions[appSessionID]
	s.appSessionsMu.Unlock()
	if !ok {
		t.Fatal("app-session not stored in server map after create")
	}
	if stored.AscReqData == nil || stored.AscReqData.UeIpv4 != "10.60.0.1" {
		t.Errorf("stored app-session has wrong ueIpv4: %+v", stored.AscReqData)
	}
}

// TestCreateAppSession_NoAscReqData verifies that omitting the ascReqData
// wrapper returns 400 MANDATORY_IE_MISSING.
// Ref: TS 29.500 §5.2.7.2
func TestCreateAppSession_NoAscReqData(t *testing.T) {
	s := newTestPCF(t)

	r := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions",
		strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAppSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var prob map[string]any
	_ = json.NewDecoder(w.Body).Decode(&prob)
	if prob["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause: got %v want MANDATORY_IE_MISSING", prob["cause"])
	}
}

// TestCreateAppSession_NoUEAddress verifies that an ascReqData with neither
// ueIpv4 nor ueIpv6 returns 400 MANDATORY_IE_MISSING.
// Ref: TS 29.514 §5.6.2.3 — at least one UE address is required.
func TestCreateAppSession_NoUEAddress(t *testing.T) {
	s := newTestPCF(t)

	body := `{"ascReqData":{"aspId":"af-test","qosReference":"qos-gold"}}`
	r := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAppSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var prob map[string]any
	_ = json.NewDecoder(w.Body).Decode(&prob)
	if prob["cause"] != "MANDATORY_IE_MISSING" {
		t.Errorf("cause: got %v want MANDATORY_IE_MISSING", prob["cause"])
	}
}

// TestCreateAppSession_MalformedJSON verifies that malformed JSON returns
// 400 MANDATORY_IE_INCORRECT.
// Ref: TS 29.500 §5.2.7.2
func TestCreateAppSession_MalformedJSON(t *testing.T) {
	s := newTestPCF(t)

	r := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions",
		strings.NewReader(`{not valid json`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAppSession(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var prob map[string]any
	_ = json.NewDecoder(w.Body).Decode(&prob)
	if prob["cause"] != "MANDATORY_IE_INCORRECT" {
		t.Errorf("cause: got %v want MANDATORY_IE_INCORRECT", prob["cause"])
	}
}

// TestDeleteAppSession_HappyPath creates an app-session then deletes it and
// verifies 204 No Content is returned and the session is removed from the store.
// Ref: TS 29.514 §5.2.2.4
func TestDeleteAppSession_HappyPath(t *testing.T) {
	s := newTestPCF(t)

	// Create first.
	body := `{"ascReqData":{"aspId":"af-del","ueIpv4":"10.60.0.2","qosReference":"qos-silver","dnn":"internet"}}`
	rc := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions",
		strings.NewReader(body))
	rc.Header.Set("Content-Type", "application/json")
	wc := httptest.NewRecorder()
	s.handleCreateAppSession(wc, rc)
	if wc.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", wc.Code, wc.Body.String())
	}

	// Extract the appSessionId from the Location header.
	loc := wc.Header().Get("Location")
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	appSessionID := parts[len(parts)-1]

	// Delete.
	rd := httptest.NewRequest(http.MethodDelete,
		"/npcf-policyauthorization/v1/app-sessions/"+appSessionID, nil)
	rd.SetPathValue("appSessionId", appSessionID)
	wd := httptest.NewRecorder()
	s.handleDeleteAppSession(wd, rd)

	if wd.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d: %s", wd.Code, wd.Body.String())
	}

	// Verify the session is gone from the internal map.
	s.appSessionsMu.Lock()
	_, stillPresent := s.appSessions[appSessionID]
	s.appSessionsMu.Unlock()
	if stillPresent {
		t.Error("app-session still in map after delete")
	}
}

// TestDeleteAppSession_NotFound verifies that deleting an unknown appSessionId
// returns 404.
// Ref: TS 29.514 §5.2.2.4
func TestDeleteAppSession_NotFound(t *testing.T) {
	s := newTestPCF(t)

	r := httptest.NewRequest(http.MethodDelete,
		"/npcf-policyauthorization/v1/app-sessions/unknown-session-id", nil)
	r.SetPathValue("appSessionId", "unknown-session-id")
	w := httptest.NewRecorder()
	s.handleDeleteAppSession(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	var prob map[string]any
	_ = json.NewDecoder(w.Body).Decode(&prob)
	if prob["cause"] == nil || prob["cause"] == "" {
		t.Errorf("expected cause in 404 response, got %v", prob)
	}
}

// TestCreateAppSession_IPv6Only verifies that ueIpv6 alone (no ueIpv4) also passes
// the UE-address validation — the endpoint must accept IPv6-only sessions.
// Ref: TS 29.514 §5.6.2.3
func TestCreateAppSession_IPv6Only(t *testing.T) {
	s := newTestPCF(t)

	body := `{"ascReqData":{"aspId":"af-v6","ueIpv6":"2001:db8::1","qosReference":"qos-bronze"}}`
	r := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions",
		strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleCreateAppSession(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("IPv6-only create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

// TestCreateAppSession_TwoSessionsIndependent verifies that two separate Create
// calls produce two independent appSessionIds and both are retrievable from the store.
func TestCreateAppSession_TwoSessionsIndependent(t *testing.T) {
	s := newTestPCF(t)

	ids := make([]string, 2)
	for i := range ids {
		body := `{"ascReqData":{"ueIpv4":"10.60.0.` + strings.Repeat("1", i+1) + `","qosReference":"qos-test"}}`
		r := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions",
			strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.handleCreateAppSession(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("create #%d: expected 201, got %d", i, w.Code)
		}
		loc := w.Header().Get("Location")
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		ids[i] = parts[len(parts)-1]
	}

	if ids[0] == ids[1] {
		t.Errorf("two creates produced the same appSessionId: %q", ids[0])
	}

	s.appSessionsMu.Lock()
	_, ok0 := s.appSessions[ids[0]]
	_, ok1 := s.appSessions[ids[1]]
	s.appSessionsMu.Unlock()
	if !ok0 || !ok1 {
		t.Errorf("not both app-sessions present in store: ids=%v ok0=%v ok1=%v", ids, ok0, ok1)
	}
}
