package sbi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// TestUDMCallbacks: the UDM callback endpoints validate the body and answer 204.
func TestUDMCallbacks(t *testing.T) {
	s, mgr := newTestServer(t)
	seedRegisteredUE(mgr, "imsi-001010000000001")
	var deregistered, reasons []string
	s.SetDeregistrationHandler(func(_ context.Context, ue *amfctx.UEContext, reason string) error {
		deregistered = append(deregistered, ue.SUPI)
		reasons = append(reasons, reason)
		return nil
	})
	tests := []struct {
		name, path, body string
		want             int
	}{
		{"dereg ok", UDMDeregCallbackPath + "/imsi-001010000000001", `{"deregReason":"SUBSCRIPTION_WITHDRAWN","accessType":"3GPP_ACCESS"}`, http.StatusNoContent},
		{"dereg unknown ue", UDMDeregCallbackPath + "/imsi-999", `{"deregReason":"SUBSCRIPTION_WITHDRAWN"}`, http.StatusNotFound},
		{"dereg missing reason", UDMDeregCallbackPath + "/imsi-001010000000001", `{}`, http.StatusBadRequest},
		{"dereg not json", UDMDeregCallbackPath + "/imsi-001010000000001", `x`, http.StatusBadRequest},
		{"sdm rel19", UDMSDMCallbackPath, `{"notifyItems":[{"resourceId":"r","changes":[]}],"subscriptionId":"s"}`, http.StatusNoContent},
		{"sdm rel17", UDMSDMCallbackPath, `{"resourceChanges":[{"changeType":"REPLACE","resourcePath":"/x"}]}`, http.StatusNoContent},
		{"sdm empty", UDMSDMCallbackPath, `{}`, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.HTTPHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}
	// The deregReason reaches the handler: it decides whether SM contexts are released.
	if len(reasons) != 1 || reasons[0] != "SUBSCRIPTION_WITHDRAWN" {
		t.Errorf("deregReason passed to the handler = %v, want [SUBSCRIPTION_WITHDRAWN]", reasons)
	}
}

// TestUDMDeregNotifyRunsLocalDeregistration: the notification triggers the wired
// local deregistration for exactly the SUPI of the callback path.
func TestUDMDeregNotifyRunsLocalDeregistration(t *testing.T) {
	s, mgr := newTestServer(t)
	seedRegisteredUE(mgr, "imsi-001010000000001")
	var got []string
	s.SetDeregistrationHandler(func(_ context.Context, ue *amfctx.UEContext, _ string) error {
		got = append(got, ue.SUPI)
		return nil
	})
	rr := httptest.NewRecorder()
	s.HTTPHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, UDMDeregCallbackPath+"/imsi-001010000000001",
		strings.NewReader(`{"deregReason":"SUBSCRIPTION_WITHDRAWN"}`)))
	if rr.Code != http.StatusNoContent || len(got) != 1 || got[0] != "imsi-001010000000001" {
		t.Fatalf("status=%d deregistered=%v", rr.Code, got)
	}
}
