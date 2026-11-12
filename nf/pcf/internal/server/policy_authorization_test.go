// Package server — Npcf_PolicyAuthorization unit tests.
//
// Tests cover the thin Create + Delete endpoints for app-sessions added to the
// PCF to support the NEF AsSessionWithQoS flow (TS 29.514 §5.2.2.2 / §4.2.4.2).
// Every test uses a fresh Server (newTestPCF) so tests are order-independent.
//
// Ref: TS 29.514 §5.2.2.2 (Create), §4.2.4.2 (Delete)
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

	// AppSessionContext (TS 29.514 §5.6.2.2) has no appSessionId attribute: the
	// id is only in the Location header.
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if _, has := raw["appSessionId"]; has {
		t.Error("response body carries non-schema attribute appSessionId")
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
// Ref: TS 29.514 §4.2.4.2
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
	rd := httptest.NewRequest(http.MethodPost,
		"/npcf-policyauthorization/v1/app-sessions/"+appSessionID+"/delete", nil)
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
// Ref: TS 29.514 §4.2.4.2
func TestDeleteAppSession_NotFound(t *testing.T) {
	s := newTestPCF(t)

	r := httptest.NewRequest(http.MethodPost,
		"/npcf-policyauthorization/v1/app-sessions/unknown-session-id/delete", nil)
	r.SetPathValue("appSessionId", "unknown-session-id")
	w := httptest.NewRecorder()
	s.handleDeleteAppSession(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	var prob map[string]any
	if err := json.NewDecoder(w.Body).Decode(&prob); err != nil {
		t.Fatalf("decode ProblemDetails: %v", err)
	}
	if prob["cause"] != "APPLICATION_SESSION_CONTEXT_NOT_FOUND" {
		t.Errorf("cause: got %v want APPLICATION_SESSION_CONTEXT_NOT_FOUND (TS 29.514 §5.7.3)", prob["cause"])
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

// TestAppSession_QosReferenceBothShapes: REL19-3.5 slice 2. The PCF accepts the
// qosReference at its spec home (medComponents[].qosReference) and as the
// rel17-profile top-level ascReqData member; the 201 echo reproduces the shape
// received (top-level member byte for byte, so a rel17 NEF sees no change).
func TestAppSession_QosReferenceBothShapes(t *testing.T) {
	tests := []struct {
		name, body, wantEcho string
	}{
		{"legacy top-level",
			`{"ascReqData":{"aspId":"af","ueIpv4":"10.60.0.1","qosReference":"q1","dnn":"internet","medComponents":{"1":{"medType":"DATA"}}}}`,
			`{"ascReqData":{"aspId":"af","ueIpv4":"10.60.0.1","qosReference":"q1","dnn":"internet","medComponents":{"1":{"medType":"DATA"}}}}`},
		{"spec medComponents",
			`{"ascReqData":{"aspId":"af","ueIpv4":"10.60.0.1","dnn":"internet","medComponents":{"1":{"medCompN":1,"qosReference":"q1"}}}}`,
			`{"ascReqData":{"aspId":"af","ueIpv4":"10.60.0.1","dnn":"internet","medComponents":{"1":{"medCompN":1,"qosReference":"q1"}}}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestPCF(t)
			r := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, r)
			if w.Code != http.StatusCreated {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if got := strings.TrimSpace(w.Body.String()); got != tc.wantEcho {
				t.Errorf("echo = %s\nwant   %s", got, tc.wantEcho)
			}
			s.appSessionsMu.Lock()
			defer s.appSessionsMu.Unlock()
			for _, c := range s.appSessions {
				if c.AscReqData.QosReference != "q1" {
					t.Errorf("stored QosReference = %q", c.AscReqData.QosReference)
				}
			}
		})
	}
}

// TestAppSession_AuthorizationWithRequiredQoSNegotiated: REL19-3.5 slice 2.
// A rel19 consumer offering feature 17 (AuthorizationWithRequiredQoS, bit 16,
// TS 29.514 §5.8) gets it echoed in ascRespData.suppFeat; a rel17 PCF with no
// offer answers no suppFeat (legacy bytes).
func TestAppSession_AuthorizationWithRequiredQoSNegotiated(t *testing.T) {
	body := `{"ascReqData":{"aspId":"af","ueIpv4":"10.60.0.1","suppFeat":"2010000","medComponents":{"1":{"medCompN":1,"qosReference":"q1"}}}}`
	s, _ := newFeaturePCF(t, profileNamed(t, "rel19"), Catalogs{})
	resp, raw := post(t, s, "/npcf-policyauthorization/v1/app-sessions", body, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		AscRespData struct {
			SuppFeat string `json:"suppFeat"`
		} `json:"ascRespData"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.AscRespData.SuppFeat != "10000" {
		t.Errorf("ascRespData.suppFeat = %q, want 10000 (bit 16 only; ES3XX is not offered by the PCF)", out.AscRespData.SuppFeat)
	}
}

// TestAppSession_QosReferenceTypeError: a non-string qosReference (top-level or
// in a media component) is a schema violation answered 400 (TS 29.500 §5.2.7.2).
func TestAppSession_QosReferenceTypeError(t *testing.T) {
	for name, body := range map[string]string{
		"top-level":     `{"ascReqData":{"ueIpv4":"10.60.0.1","qosReference":5}}`,
		"medComponents": `{"ascReqData":{"ueIpv4":"10.60.0.1","medComponents":{"1":{"qosReference":{"a":1}}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestPCF(t)
			r := httptest.NewRequest(http.MethodPost, "/npcf-policyauthorization/v1/app-sessions", strings.NewReader(body))
			w := httptest.NewRecorder()
			s.httpSrv.Handler.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status %d, want 400: %s", w.Code, w.Body.String())
			}
		})
	}
}
