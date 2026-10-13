package procedures

// Tests for the runtime-changeable T3512 carried in REGISTRATION ACCEPT
// (IEI 0x5E, GPRS timer 3). Ref: TS 24.501 §8.2.7, §9.11.2.5, §10.2.

import (
	"context"
	"io"
	"log/slog"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/timercfg"
)

func newT3512TestHandler(store *timercfg.Store) *RegistrationHandler {
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, lg)
	h := NewRegistrationHandler(mgr, nil, nil, nil, "nf", "001", "01", lg)
	h.WithTimerStore(store)
	return h
}

func TestT3512RuntimeChangeAndReset(t *testing.T) {
	store := timercfg.New(timercfg.Values{T3512Secs: 60, GuardSecs: 120, ImplicitDetachSecs: 60})
	h := newT3512TestHandler(store)

	tests := []struct {
		name string
		set  func()
		want byte
		secs int
	}{
		{"base", func() {}, 0xA1, 60},
		{"120s is unit 1min value 2", func() { v := store.Effective(); v.T3512Secs = 120; store.Set(v) }, 0xA2, 120},
		{"600s is unit 10min value 1", func() { v := store.Effective(); v.T3512Secs = 600; store.Set(v) }, 0x01, 600},
		{"reset restores base", store.Reset, 0xA1, 60},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.set()
			ue := &amfctx.UEContext{SUPI: "imsi-001010000000001"}
			ra, err := h.BuildRegistrationUpdateAccept(context.Background(), ue)
			if err != nil {
				t.Fatalf("BuildRegistrationUpdateAccept: %v", err)
			}
			if ra.T3512Value == nil || *ra.T3512Value != tc.want {
				t.Fatalf("T3512Value = %v, want 0x%02X", ra.T3512Value, tc.want)
			}
			if got := ue.T3512Sent(); got != tc.secs {
				t.Fatalf("T3512SentSecs = %d, want %d", got, tc.secs)
			}
		})
	}
}

func TestT3512RuntimeNoStoreOmitsIE(t *testing.T) {
	h := newT3512TestHandler(nil)
	ue := &amfctx.UEContext{SUPI: "imsi-001010000000001"}
	ra, err := h.BuildRegistrationUpdateAccept(context.Background(), ue)
	if err != nil {
		t.Fatal(err)
	}
	if ra.T3512Value != nil || ue.T3512Sent() != 0 {
		t.Fatalf("expected no IEI 0x5E and no recorded T3512, got %v / %d", ra.T3512Value, ue.T3512Sent())
	}
}

func TestT3512RuntimeWithT3512Legacy(t *testing.T) {
	h := newT3512TestHandler(nil)
	h.WithT3512(120)
	if h.T3512() != 120 {
		t.Fatalf("T3512() = %d, want 120", h.T3512())
	}
}
