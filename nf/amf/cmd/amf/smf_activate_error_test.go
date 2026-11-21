package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestActivateSMContextProblemDetails: a non-200 answer becomes a typed error
// carrying the ProblemDetails cause, status kept in the message.
// Ref: TS 24.501 §5.6.1.4.1, TS 29.571 §5.2.4.1
func TestActivateSMContextProblemDetails(t *testing.T) {
	tests := []struct {
		name, ct, body string
		status         int
		wantCause      string
	}{
		{"problem+json cause", "application/problem+json", `{"cause":"UE_IN_NON_LADN_SERVICE_AREA"}`, 403, "UE_IN_NON_LADN_SERVICE_AREA"},
		{"no body", "", "", 500, ""},
		{"non json body", "text/plain", "oops", 502, ""},
		{"malformed json", "application/problem+json", "{", 500, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.ct != "" {
					w.Header().Set("Content-Type", tc.ct)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := &HTTPSMFClient{address: strings.TrimPrefix(srv.URL, "https://"), client: srv.Client()}
			_, err := c.ActivateSMContext(t.Context(), "ref-1")
			if err == nil {
				t.Fatal("expected error")
			}
			var ce interface{ SMFApplicationCause() string }
			if !errors.As(err, &ce) {
				t.Fatalf("error %T not typed", err)
			}
			if ce.SMFApplicationCause() != tc.wantCause {
				t.Errorf("cause = %q, want %q", ce.SMFApplicationCause(), tc.wantCause)
			}
			if !strings.Contains(err.Error(), "status") {
				t.Errorf("status missing from %q", err)
			}
		})
	}
}
