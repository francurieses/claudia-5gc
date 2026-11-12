package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHTTPPolicyAuthClient_DeleteAppSession verifies the NEF uses the Rel-17
// custom delete operation (POST .../delete) and accepts 200, 204 and 404.
// Ref: TS 29.514 §4.2.4.2, §5.3.3.4.2
func TestHTTPPolicyAuthClient_DeleteAppSession(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		respBody string
		wantErr  bool
		wantMsg  string
	}{
		{"204", http.StatusNoContent, "", false, ""},
		{"200", http.StatusOK, "", false, ""},
		{"404 idempotent", http.StatusNotFound, "", false, ""},
		{"500 with cause", http.StatusInternalServerError, `{"cause":"SYSTEM_FAILURE"}`, true, "SYSTEM_FAILURE"},
		{"500 plain body", http.StatusInternalServerError, "boom", true, "boom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var method, path, body, ctype string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method, path = r.Method, r.URL.Path
				ctype = r.Header.Get("Content-Type")
				b, _ := io.ReadAll(r.Body)
				body = string(b)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.respBody))
			}))
			defer srv.Close()
			c := &HTTPPolicyAuthClient{Client: srv.Client()}
			err := c.DeleteAppSession(t.Context(), srv.URL, "as-1")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if method != http.MethodPost || path != "/npcf-policyauthorization/v1/app-sessions/as-1/delete" {
				t.Errorf("request: %s %s", method, path)
			}
			if body != "" || ctype != "" {
				t.Errorf("want no body and no Content-Type, got body %q Content-Type %q", body, ctype)
			}
			if tc.wantMsg != "" && (err == nil || !strings.Contains(err.Error(), tc.wantMsg)) {
				t.Errorf("error %v does not mention %q", err, tc.wantMsg)
			}
		})
	}
}

// TestHTTPPolicyAuthClient_CreateAppSession_LocationForms proves the
// appSessionId is taken from an absolute {apiRoot} Location (TS 29.501 §4.4.1),
// with trailing slash / query, from the legacy relative form, and falls back
// to the body when Location is absent.
func TestHTTPPolicyAuthClient_CreateAppSession_LocationForms(t *testing.T) {
	for _, tc := range []struct {
		name, loc, body, want string
		wantErr               bool
	}{
		{"absolute", "https://pcf:8006/npcf-policyauthorization/v1/app-sessions/as-abs", "{}", "as-abs", false},
		{"absolute trailing slash", "https://pcf:8006/npcf-policyauthorization/v1/app-sessions/as-ts/", "{}", "as-ts", false},
		{"absolute with query", "https://pcf:8006/npcf-policyauthorization/v1/app-sessions/as-q?a=b/c", "{}", "as-q", false},
		{"relative", "/npcf-policyauthorization/v1/app-sessions/as-rel", "{}", "as-rel", false},
		{"body fallback", "", `{"appSessionId":"as-body"}`, "as-body", false},
		{"wrong collection", "https://pcf:8006/npcf-smpolicycontrol/v1/sm-policies/x", `{"appSessionId":"as-body"}`, "", true},
		{"extra segments", "https://pcf:8006/npcf-policyauthorization/v1/app-sessions/a/b", "{}", "", true},
		{"location without id, body ignored", "https://pcf:8006/npcf-policyauthorization/v1/app-sessions", `{"appSessionId":"as-body"}`, "", true},
		{"no id anywhere", "", "{}", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.loc != "" {
					w.Header().Set("Location", tc.loc)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := &HTTPPolicyAuthClient{Client: srv.Client()}
			got, _, err := c.CreateAppSession(t.Context(), srv.URL, &AppSessionContextReqData{})
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("CreateAppSession = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestHTTPPolicyAuthClient_CreateAppSession_LegacyBodyWarns proves the body
// appSessionId fallback is visible: a Warn with cause=MISSING_LOCATION.
func TestHTTPPolicyAuthClient_CreateAppSession_LegacyBodyWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"appSessionId":"as-body"}`))
	}))
	defer srv.Close()
	var buf strings.Builder
	c := &HTTPPolicyAuthClient{Client: srv.Client(), Logger: slog.New(slog.NewJSONHandler(&buf, nil))}
	if _, _, err := c.CreateAppSession(t.Context(), srv.URL, &AppSessionContextReqData{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"level":"WARN"`, `"cause":"MISSING_LOCATION"`, `"app_session_id":"as-body"`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log %s lacks %s", buf.String(), want)
		}
	}
}
