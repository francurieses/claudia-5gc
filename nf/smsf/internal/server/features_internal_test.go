package server

// features_internal_test.go - the negotiated Nsmsf_SMService feature set is
// stored on the UE SMS context (REL19-2.7 slice 3). Ref: TS 29.500 §6.6.2.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/francurieses/claudia-5gc/nf/smsf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

func TestNegotiatedSetStoredOnUEContext(t *testing.T) {
	prof, err := capability.NewProfile(capability.ReleaseConfig{Profile: "rel19"}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.SBI.Address = "127.0.0.1:0"
	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetProfile(prof)
	s.SetCatalog(features.MustCatalog(features.MustImplement(features.NsmsfSMServiceEntries(), 2)...))

	r := httptest.NewRequest(http.MethodPut, "/nsmsf-sms/v2/ue-contexts/imsi-001010000000001",
		strings.NewReader(`{"supi":"imsi-001010000000001","accessType":"3GPP_ACCESS","amfId":"a","supportedFeatures":"ff"}`))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	uectx, ok := s.store.Get("imsi-001010000000001")
	if !ok {
		t.Fatal("no UE SMS context stored")
	}
	if got := uectx.Features.String(); got != "2" || !uectx.Features.Has(2) || uectx.Features.Has(1) {
		t.Errorf("stored features = %q, want 2", got)
	}
}
